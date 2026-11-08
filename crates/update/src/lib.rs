//! Rule-pack updater shared by the `hexward` command and the desktop app. Downloads public rule packs into the user rules folder.
//!
//! - YARA Forge (https://github.com/YARAHQ/yara-forge): curated, tested community YARA rules.
//!   No key needed. Each rule keeps its author's license; see its `author` and `license_url` meta.
//! - MalwareBazaar (https://bazaar.abuse.ch): SHA-256 hashes of fresh malware samples (CC0).
//!   Needs a free abuse.ch Auth-Key in the HEXWARD_ABUSECH_KEY environment variable. The export
//!   only covers the last 48 hours, so each update adds to a list kept on disk.
//!
//! A new YARA pack only replaces the old one after it compiles. A failed download never
//! leaves you with fewer rules than before.

pub mod app;
pub mod channel;
pub mod cloud;
pub mod online;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use hexward_engine::rules::{BUILTIN_RULES, RuleSet};
use serde::{Deserialize, Serialize};

const USER_AGENT: &str = concat!("hexward-updater/", env!("CARGO_PKG_VERSION"));
const FORGE_FILE: &str = "yara-forge.yar";
const MB_FILE: &str = "malwarebazaar.txt";
const MANIFEST: &str = "packs.json";
/// abuse.ch asks that the recent export is fetched at most every 5 minutes.
const MB_MIN_INTERVAL_SECS: i64 = 5 * 60;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ForgePack {
    /// About 5,000 high-accuracy rules (recommended).
    Core,
    /// More rules, a little more noise.
    Extended,
    /// Everything YARA Forge has, including noisy hunting rules.
    Full,
    /// Don't download YARA rules.
    Off,
}

impl std::str::FromStr for ForgePack {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, String> {
        match s.to_ascii_lowercase().as_str() {
            "core" => Ok(ForgePack::Core),
            "extended" => Ok(ForgePack::Extended),
            "full" => Ok(ForgePack::Full),
            "off" => Ok(ForgePack::Off),
            _ => Err(format!("unknown pack {s}: use core, extended, full or off")),
        }
    }
}

impl ForgePack {
    pub fn name(self) -> &'static str {
        match self {
            ForgePack::Core => "core",
            ForgePack::Extended => "extended",
            ForgePack::Full => "full",
            ForgePack::Off => "off",
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
pub struct Manifest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub yara_forge: Option<ForgeInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub malwarebazaar: Option<BazaarInfo>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ForgeInfo {
    pub pack: ForgePack,
    pub url: String,
    pub updated_at: DateTime<Utc>,
    pub rules: usize,
    pub skipped: usize,
    /// "Creation Date" from the pack header.
    pub created: Option<String>,
    pub forge_version: Option<String>,
    pub sha256: String,
    /// Set when the pack came from Hexward's signed rule channel (its version).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_version: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct BazaarInfo {
    pub updated_at: DateTime<Utc>,
    pub added: usize,
    pub total: usize,
}

#[derive(Serialize)]
pub struct Report {
    pub rules_dir: PathBuf,
    pub yara_forge: Step,
    pub malwarebazaar: Step,
    pub drivers: Step,
    /// Confirmed community submissions from hexward.onurilabs.com.
    pub community: Step,
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum Step {
    Updated { detail: String },
    Skipped { reason: String },
    Failed { reason: String },
}

pub fn rules_dir() -> PathBuf {
    hexward_engine::data_dir().join("rules")
}

pub fn read_manifest(dir: &Path) -> Manifest {
    std::fs::read(dir.join(MANIFEST)).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(180)))
        .user_agent(USER_AGENT)
        .build()
        .into()
}

/// Downloads `url` (at most `limit` bytes). Error text never contains the URL,
/// because the MalwareBazaar URL carries the user's key.
fn download(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>> {
    let mut resp = agent.get(url).call().map_err(|e| match e {
        ureq::Error::StatusCode(401 | 403) => anyhow!("the server refused access (HTTP 401/403). Check the Auth-Key"),
        ureq::Error::StatusCode(code) => anyhow!("the server answered HTTP {code}"),
        ureq::Error::Timeout(_) => anyhow!("the download timed out"),
        ureq::Error::Io(e) => anyhow!("network error: {e}"),
        other => anyhow!("download failed ({})", other.to_string().split(':').next().unwrap_or("error")),
    })?;
    resp.body_mut()
        .with_config()
        .limit(limit)
        .read_to_vec()
        .map_err(|e| anyhow!("download failed while reading: {}", e.to_string().split(':').next().unwrap_or("error")))
}

/// Returns the first entry in the zip whose name ends with `suffix`, decompressed (capped at `limit`).
fn unzip_first(bytes: &[u8], suffix: &str, limit: u64) -> Result<Vec<u8>> {
    let mut zip = zip::ZipArchive::new(std::io::Cursor::new(bytes)).context("the download isn't a valid zip file")?;
    for i in 0..zip.len() {
        let mut f = zip.by_index(i)?;
        let name = f.name().map(|n| n.to_ascii_lowercase()).unwrap_or_default();
        if f.is_file() && name.ends_with(suffix) {
            let mut out = Vec::new();
            (&mut f).take(limit + 1).read_to_end(&mut out)?;
            if out.len() as u64 > limit {
                bail!("{name} is larger than expected");
            }
            return Ok(out);
        }
    }
    bail!("no {suffix} file in the download")
}

/// Pulls `Key: value` from the YARA Forge comment header.
fn header_field(src: &str, key: &str) -> Option<String> {
    src.lines().take(40).find_map(|l| {
        let l = l.trim_start_matches([' ', '*', '/']).trim();
        l.strip_prefix(key).and_then(|r| r.strip_prefix(':')).map(|v| v.trim().to_string())
    })
}

pub fn run(pack: ForgePack, force: bool) -> Result<Report> {
    let dir = rules_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("couldn't create {}", dir.display()))?;
    let mut manifest = read_manifest(&dir);
    let agent = agent();

    // The core pack comes from Hexward's signed, staged channel when it's available; the
    // direct YARA Forge download is the fallback (and the source for the bigger packs).
    let mut channel_note = String::new();
    let from_channel = if pack == ForgePack::Core {
        let current = manifest.yara_forge.as_ref().and_then(|f| f.channel_version.clone());
        match channel::apply(&agent, &dir, FORGE_FILE, current.as_deref()) {
            Ok(channel::Outcome::Installed(i)) => {
                let raw = std::fs::read(dir.join(FORGE_FILE)).unwrap_or_default();
                let src = String::from_utf8_lossy(&raw).into_owned();
                use sha2::Digest;
                manifest.yara_forge = Some(ForgeInfo {
                    pack,
                    url: format!("https://github.com/{}/releases/tag/{}", app::REPO, channel::CHANNEL_TAG),
                    updated_at: Utc::now(),
                    rules: i.rules,
                    skipped: 0,
                    created: header_field(&src, "Creation Date"),
                    forge_version: header_field(&src, "YARA-Forge Version"),
                    sha256: hex::encode(sha2::Sha256::digest(&raw)),
                    channel_version: Some(i.version.clone()),
                });
                Some(Step::Updated { detail: format!("Hexward rule channel {}{}: {} rules, signed and checked for false alarms", i.version, if i.rolled_back { " (rolled back from a withdrawn pack)" } else { "" }, i.rules) })
            }
            Ok(channel::Outcome::UpToDate(v)) => Some(Step::Skipped { reason: format!("already on rule channel pack {v}") }),
            Ok(channel::Outcome::RestoredPrevious) => {
                if let Some(f) = manifest.yara_forge.as_mut() {
                    f.channel_version = None;
                }
                Some(Step::Updated { detail: "the installed pack was withdrawn; the previous pack is back".into() })
            }
            Err(e) => {
                channel_note = format!(" (rule channel: {e:#}; used YARA Forge directly)");
                None
            }
        }
    } else {
        None
    };

    let yara_forge = if let Some(step) = from_channel {
        step
    } else if pack == ForgePack::Off {
        Step::Skipped { reason: "turned off with --yara off".into() }
    } else {
        match update_forge(&agent, &dir, pack) {
            Ok(info) => {
                let detail = format!(
                    "{} pack: {} rules{}{}",
                    pack.name(),
                    info.rules,
                    if info.skipped > 0 { format!(", {} left out (don't compile with YARA-X)", info.skipped) } else { String::new() },
                    info.created.as_deref().map(|c| format!(", built {c}")).unwrap_or_default()
                );
                manifest.yara_forge = Some(info);
                Step::Updated { detail: format!("{detail}{channel_note}") }
            }
            Err(e) => Step::Failed { reason: format!("{e:#}. The previous rules are still in place") },
        }
    };

    let malwarebazaar = match std::env::var("HEXWARD_ABUSECH_KEY").ok().map(|k| k.trim().to_string()).filter(|k| !k.is_empty()) {
        None => Step::Skipped {
            reason: "no Auth-Key. Get a free one at https://auth.abuse.ch, then set HEXWARD_ABUSECH_KEY".into(),
        },
        Some(key) => {
            let recent = manifest
                .malwarebazaar
                .as_ref()
                .is_some_and(|m| (Utc::now() - m.updated_at).num_seconds() < MB_MIN_INTERVAL_SECS);
            if recent && !force {
                Step::Skipped { reason: "updated less than 5 minutes ago (abuse.ch asks for no more than that)".into() }
            } else {
                match update_bazaar(&agent, &dir, &key) {
                    Ok(info) => {
                        let detail = format!("{} new hashes, {} in total", info.added, info.total);
                        manifest.malwarebazaar = Some(info);
                        Step::Updated { detail }
                    }
                    Err(e) => Step::Failed { reason: format!("{e:#}") },
                }
            }
        }
    };

    std::fs::write(dir.join(MANIFEST), serde_json::to_vec_pretty(&manifest)?)?;
    let drivers = match update_drivers(&agent, &dir) {
        Ok(n) => Step::Updated { detail: format!("{n} vulnerable or malicious drivers (LOLDrivers, Microsoft blocklist)") },
        Err(e) => Step::Failed { reason: format!("{e:#}") },
    };
    let community = match cloud::update_community(&dir) {
        Ok(n) => Step::Updated { detail: format!("{n} confirmed community hashes") },
        Err(e) => Step::Failed { reason: format!("{e:#}") },
    };
    Ok(Report { rules_dir: dir, yara_forge, malwarebazaar, drivers, community })
}

/// LOLDrivers and Microsoft's vulnerable driver blocklist → rules/drivers.json.
/// Either source may fail on its own; the file is only replaced when at least one worked.
fn update_drivers(agent: &ureq::Agent, dir: &Path) -> Result<usize> {
    use hexward_engine::drivers::{parse_loldrivers, parse_ms_blocklist};
    let mut all = Vec::new();
    let mut errors = Vec::new();
    match download(agent, "https://www.loldrivers.io/api/drivers.json", 200 * 1024 * 1024) {
        Ok(b) => all.extend(parse_loldrivers(&b)),
        Err(e) => errors.push(format!("LOLDrivers: {e}")),
    }
    match download(agent, "https://aka.ms/VulnerableDriverBlockList", 50 * 1024 * 1024).and_then(|z| unzip_first(&z, "driverpolicy_enforced.xml", 100 * 1024 * 1024).or_else(|_| unzip_first(&z, "sipolicy_enforced.xml", 100 * 1024 * 1024))) {
        Ok(x) => all.extend(parse_ms_blocklist(&String::from_utf8_lossy(&x))),
        Err(e) => errors.push(format!("Microsoft blocklist: {e}")),
    }
    if all.is_empty() {
        bail!("{}", errors.join("; "));
    }
    let tmp = dir.join("drivers.json.new");
    std::fs::write(&tmp, serde_json::to_vec(&all)?)?;
    std::fs::rename(&tmp, dir.join("drivers.json"))?;
    Ok(all.len())
}

fn update_forge(agent: &ureq::Agent, dir: &Path, pack: ForgePack) -> Result<ForgeInfo> {
    let url = format!("https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-{}.zip", pack.name());
    let zip = download(agent, &url, 100 * 1024 * 1024)?;
    let raw = unzip_first(&zip, ".yar", 300 * 1024 * 1024)?;
    let src = String::from_utf8_lossy(&raw).into_owned();
    if !src.contains("YARA-Forge") {
        bail!("the download doesn't look like a YARA Forge pack");
    }

    // Prove it compiles before it replaces anything.
    let set = RuleSet::compile(&[("built-in".into(), BUILTIN_RULES.into()), (FORGE_FILE.into(), src.clone())])
        .context("the new pack didn't compile")?;
    let rules = set.count().saturating_sub(RuleSet::compile(&[("built-in".into(), BUILTIN_RULES.into())])?.count());
    if rules == 0 {
        bail!("the new pack has no usable rules");
    }

    let target = dir.join(FORGE_FILE);
    if target.exists() {
        std::fs::copy(&target, channel::previous_path(dir, FORGE_FILE))?;
    }
    let tmp = dir.join(format!("{FORGE_FILE}.new"));
    std::fs::write(&tmp, &raw)?;
    std::fs::rename(&tmp, dir.join(FORGE_FILE))?;

    use sha2::Digest;
    Ok(ForgeInfo {
        pack,
        url,
        updated_at: Utc::now(),
        rules,
        skipped: set.skipped.len(),
        created: header_field(&src, "Creation Date"),
        forge_version: header_field(&src, "YARA-Forge Version"),
        sha256: hex::encode(sha2::Sha256::digest(&raw)),
        channel_version: None,
    })
}

/// Puts the previous rule pack back (`hexward update --rollback`).
pub fn rollback() -> Result<()> {
    let dir = rules_dir();
    if !channel::restore_previous(&dir, FORGE_FILE)? {
        bail!("there's no previous rule pack to go back to");
    }
    let mut m = read_manifest(&dir);
    if let Some(f) = m.yara_forge.as_mut() {
        f.channel_version = None;
        f.updated_at = Utc::now();
    }
    std::fs::write(dir.join(MANIFEST), serde_json::to_vec_pretty(&m)?)?;
    Ok(())
}

fn update_bazaar(agent: &ureq::Agent, dir: &Path, key: &str) -> Result<BazaarInfo> {
    if !key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        bail!("HEXWARD_ABUSECH_KEY has characters an Auth-Key never contains");
    }
    let url = format!("https://mb-api.abuse.ch/v2/files/exports/{key}/recent.csv");
    let body = download(agent, &url, 200 * 1024 * 1024)?;
    let body = if body.starts_with(b"PK") { unzip_first(&body, ".csv", 500 * 1024 * 1024)? } else { body };
    let fresh = parse_bazaar_csv(&String::from_utf8_lossy(&body));
    if fresh.is_empty() {
        bail!("the export had no hashes in it");
    }

    let path = dir.join(MB_FILE);
    let mut all = load_hash_file(&path);
    let before = all.len();
    for (h, n) in fresh {
        all.entry(h).or_insert(n);
    }
    let added = all.len() - before;
    let mut out = String::from(
        "# MalwareBazaar SHA-256 hashes (https://bazaar.abuse.ch, CC0), collected by `hexward update`.\n# Format: sha256,Detection/Name\n",
    );
    for (h, n) in &all {
        out.push_str(h);
        out.push(',');
        out.push_str(n);
        out.push('\n');
    }
    let tmp = dir.join(format!("{MB_FILE}.new"));
    std::fs::write(&tmp, out)?;
    std::fs::rename(&tmp, &path)?;
    Ok(BazaarInfo { updated_at: Utc::now(), added, total: all.len() })
}

fn load_hash_file(path: &Path) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    if let Ok(text) = std::fs::read_to_string(path) {
        for line in text.lines().filter(|l| !l.starts_with('#')) {
            if let Some((h, n)) = line.split_once(',')
                && h.len() == 64
            {
                map.insert(h.to_ascii_lowercase(), n.trim().to_string());
            }
        }
    }
    map
}

/// Splits one CSV line, honouring double quotes.
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur).trim().to_string()),
            _ => cur.push(c),
        }
    }
    out.push(cur.trim().to_string());
    out
}

/// MalwareBazaar CSV → (sha256, detection name). Column positions come from the header
/// (a `#` comment line naming `sha256_hash`), with the documented order as fallback.
pub fn parse_bazaar_csv(text: &str) -> Vec<(String, String)> {
    let (mut i_hash, mut i_type, mut i_sig) = (1usize, 6usize, 8usize);
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(h) = line.strip_prefix('#') {
            if h.contains("sha256_hash") {
                let cols = csv_fields(h.trim());
                let find = |name: &str| cols.iter().position(|c| c == name);
                i_hash = find("sha256_hash").unwrap_or(i_hash);
                i_type = find("file_type_guess").or(find("file_type")).unwrap_or(i_type);
                i_sig = find("signature").unwrap_or(i_sig);
            }
            continue;
        }
        let f = csv_fields(line);
        let Some(hash) = f.get(i_hash).map(|h| h.to_ascii_lowercase()) else { continue };
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            continue;
        }
        let family: String = f
            .get(i_sig)
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("n/a"))
            .unwrap_or("Generic")
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
            .collect();
        let family = if family.is_empty() { "Generic".to_string() } else { family };
        let platform = match f.get(i_type).map(|t| t.to_ascii_lowercase()).as_deref() {
            Some("exe" | "dll" | "sys" | "msi" | "scr" | "cpl" | "ps1" | "bat" | "cmd" | "vbs" | "js" | "hta" | "lnk") => "Win",
            Some("elf" | "sh") => "Linux",
            Some("apk") => "Android",
            Some("macho" | "dmg") => "Mac",
            _ => "Any",
        };
        out.push((hash, format!("Malware/{platform}.{family}!h")));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bazaar_csv() {
        let csv = "################################################################\n\
# MalwareBazaar recent malware samples (CSV)                   #\n\
################################################################\n\
# \"first_seen_utc\",\"sha256_hash\",\"md5_hash\",\"sha1_hash\",\"reporter\",\"file_name\",\"file_type_guess\",\"mime_type\",\"signature\",\"clamav\",\"vtpercent\",\"imphash\",\"ssdeep\",\"tlsh\"\n\
\"2026-11-08 06:00:01\", \"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\", \"m\", \"s\", \"r\", \"invoice, final.exe\", \"exe\", \"application/x-dosexec\", \"AgentTesla\", \"n/a\", \"n/a\", \"i\", \"d\", \"t\"\n\
\"2026-11-08 06:00:02\", \"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\", \"m\", \"s\", \"r\", \"x\", \"elf\", \"application/x-executable\", \"n/a\", \"n/a\", \"n/a\", \"i\", \"d\", \"t\"\n\
\"bad line\"\n";
        let got = parse_bazaar_csv(csv);
        assert_eq!(
            got,
            [
                ("a".repeat(64), "Malware/Win.AgentTesla!h".to_string()),
                ("b".repeat(64), "Malware/Linux.Generic!h".to_string()),
            ]
        );
    }

    #[test]
    fn reads_forge_header() {
        let src = "/*\n * YARA-Forge YARA Rule Package\n * YARA-Forge Version: 0.9.1\n * Creation Date: 2026-11-03\n */\n";
        assert_eq!(header_field(src, "Creation Date").as_deref(), Some("2026-11-03"));
        assert_eq!(header_field(src, "YARA-Forge Version").as_deref(), Some("0.9.1"));
    }

    #[test]
    fn csv_quotes() {
        assert_eq!(csv_fields(r#""a, b","c""d",e"#), ["a, b", "c\"d", "e"]);
    }
}
