//! Hexward cloud, every part opt-in and off by default (see docs/PRIVACY.md and
//! https://hexward.onurilabs.com/transparency).
//!
//! - **Reputation** ([`lookup`]): only the first 6 hex characters of a file's SHA-256 leave the PC.
//!   The server answers with every known-bad and community-allowed hash starting with them, and the
//!   full hash is compared here, so the server can't tell which file was checked.
//! - **Signer reputation** ([`signers`]): the whole list is downloaded; nothing is sent.
//! - **Reports** ([`send_report`]): a detection, a false alarm or a supply-chain finding. File name
//!   only (never its folder), the hash, the detection, the signer, the app version and a random
//!   install number (the server keeps only a hash of it). Kept 90 days.
//! - **Samples** ([`send_sample`]): the file itself, only when the user clicks "Send to the lab".
//! - **Community hashes** ([`update_community`]): confirmed community submissions, downloaded with
//!   the rule update so every install gets them, cloud switches or not.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const BASE: &str = "https://hexward.onurilabs.com";
/// How many hex characters of the hash are sent: 24 bits, about 16 million buckets.
pub const PREFIX_LEN: usize = 6;
const MAX_SAMPLE: u64 = 32 * 1024 * 1024;
const CACHE_FOR: Duration = Duration::from_secs(3600);
pub const COMMUNITY_FILE: &str = "community.txt";

fn agent(secs: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(secs)))
        .user_agent(concat!("hexward/", env!("CARGO_PKG_VERSION")))
        .http_status_as_error(false)
        .build()
        .into()
}

fn base() -> String {
    // For testing against a local copy of the website (wrangler dev).
    std::env::var("HEXWARD_CLOUD").ok().filter(|s| s.starts_with("http")).unwrap_or_else(|| BASE.into())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reputation {
    /// Known malware: (name, where it's known from).
    Bad { name: String, source: String },
    /// On the community allow list: a confirmed false alarm.
    Allowed { name: String },
    Unknown,
}

/// The SHA-256 prefix that's sent, or None for something that isn't a SHA-256.
pub fn prefix(sha256: &str) -> Option<String> {
    let h = sha256.trim().to_ascii_lowercase();
    (h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())).then(|| h[..PREFIX_LEN].to_string())
}

/// Reads the server's answer for one full hash. Allowed wins over bad: a person confirmed it.
pub fn parse_lookup(sha256: &str, answer: &Value) -> Reputation {
    let h = sha256.trim().to_ascii_lowercase();
    let rows = |k: &str| answer.get(k).and_then(Value::as_array).cloned().unwrap_or_default();
    let cell = |r: &Value, i: usize| r.get(i).and_then(Value::as_str).unwrap_or("").to_string();
    if let Some(r) = rows("allow").iter().find(|r| cell(r, 0) == h) {
        return Reputation::Allowed { name: cell(r, 1) };
    }
    if let Some(r) = rows("bad").iter().find(|r| cell(r, 0) == h) {
        return Reputation::Bad { name: cell(r, 1), source: cell(r, 2) };
    }
    Reputation::Unknown
}

static CACHE: Mutex<Option<HashMap<String, (Instant, Value)>>> = Mutex::new(None);

/// Asks the cloud about one file. Answers are cached for an hour per prefix.
pub fn lookup(sha256: &str) -> Result<Reputation> {
    let Some(p) = prefix(sha256) else { bail!("not a SHA-256") };
    if let Some(v) = CACHE.lock().ok().and_then(|c| c.as_ref().and_then(|m| m.get(&p).filter(|(t, _)| t.elapsed() < CACHE_FOR).map(|(_, v)| v.clone()))) {
        return Ok(parse_lookup(sha256, &v));
    }
    let mut resp = agent(8).get(format!("{}/api/hexward/rep?p={p}", base())).call().context("cloud lookup")?;
    if resp.status() != 200 {
        bail!("cloud lookup answered {}", resp.status());
    }
    let v: Value = serde_json::from_str(&resp.body_mut().with_config().limit(4 * 1024 * 1024).read_to_string()?)?;
    if let Ok(mut c) = CACHE.lock() {
        let m = c.get_or_insert_with(HashMap::new);
        if m.len() > 5000 {
            m.clear();
        }
        m.insert(p, (Instant::now(), v.clone()));
    }
    Ok(parse_lookup(sha256, &v))
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Signer {
    pub signer: String,
    /// "bad" (signs malware) or "trusted".
    pub verdict: String,
    #[serde(default)]
    pub note: Option<String>,
}

/// The signer reputation list.
pub fn signers() -> Result<Vec<Signer>> {
    #[derive(Deserialize)]
    struct List {
        signers: Vec<Signer>,
    }
    let mut resp = agent(15).get(format!("{}/api/hexward/signers", base())).call()?;
    if resp.status() != 200 {
        bail!("signer list answered {}", resp.status());
    }
    Ok(serde_json::from_str::<List>(&resp.body_mut().read_to_string()?)?.signers)
}

static SIGNERS: Mutex<Option<(Instant, Vec<Signer>)>> = Mutex::new(None);

/// What the signer list says about a publisher ("bad" or "trusted"), from a list fetched at most once a day.
pub fn signer_verdict(name: &str) -> Option<String> {
    let mut g = SIGNERS.lock().ok()?;
    if g.as_ref().is_none_or(|(t, _)| t.elapsed() > Duration::from_secs(86400)) {
        // On failure keep the old list (or an empty one) and try again in an hour.
        let list = signers().ok().or_else(|| g.as_ref().map(|(_, l)| l.clone())).unwrap_or_default();
        *g = Some((Instant::now(), list));
    }
    let n = name.trim().to_lowercase();
    g.as_ref()?.1.iter().find(|s| s.signer.trim().to_lowercase() == n).map(|s| s.verdict.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    Detection,
    FalseAlarm,
    SupplyChain,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub kind: Kind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// File name only, or the package (npm:name@version) for a supply-chain report.
    pub name: String,
    pub detection: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
}

/// The body that goes to the server: a file name is cut down to its last part, whatever it was given.
pub fn report_body(r: &Report, install: &str) -> Value {
    let name = if r.kind == Kind::SupplyChain { r.name.clone() } else { r.name.rsplit(['\\', '/']).next().unwrap_or("").to_string() };
    serde_json::json!({
        "kind": r.kind,
        "sha256": r.sha256,
        "name": name,
        "detection": r.detection,
        "signer": r.signer,
        "version": env!("CARGO_PKG_VERSION"),
        "inst": install,
    })
}

pub fn send_report(r: &Report) -> Result<()> {
    let body = report_body(r, &install_id());
    let resp = agent(15).post(format!("{}/api/hexward/report", base())).header("Content-Type", "application/json").send(body.to_string())?;
    if !resp.status().is_success() {
        bail!("report answered {}", resp.status());
    }
    Ok(())
}

/// A random number made once per install, so the same PC isn't counted twice. Not tied to anything.
pub fn install_id() -> String {
    let path = hexward_engine::data_dir().join("install-id");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if s.len() == 32 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            return s.to_string();
        }
    }
    let mut b = [0u8; 16];
    let _ = getrandom::fill(&mut b);
    let id = hex::encode(b);
    let _ = std::fs::create_dir_all(hexward_engine::data_dir());
    let _ = std::fs::write(&path, &id);
    id
}

/// Sends a file to the lab (the same address as the website's "Submit a sample"). Returns the sample id.
pub fn send_sample(file: &Path, note: &str, detection: &str) -> Result<String> {
    let size = std::fs::metadata(file)?.len();
    if size == 0 || size > MAX_SAMPLE {
        bail!("the lab takes files from 1 byte to 32 MB");
    }
    let data = std::fs::read(file)?;
    let name = file.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let enc = |s: &str| s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect::<String>();
    let scan = serde_json::json!({ "from": "hexward-app", "detections": [detection] }).to_string();
    let mut resp = agent(120)
        .post(format!("{}/api/submit", base()))
        .header("x-consent", "yes")
        .header("x-file-name", enc(&name))
        .header("x-note", enc(note))
        .header("x-scan", enc(&scan))
        .header("Content-Type", "application/octet-stream")
        .send(&data[..])?;
    let v: Value = serde_json::from_str(&resp.body_mut().read_to_string().unwrap_or_default()).unwrap_or(Value::Null);
    if !resp.status().is_success() {
        bail!("{}", v.get("error").and_then(Value::as_str).unwrap_or("the lab did not take the file"));
    }
    Ok(v.get("id").and_then(Value::as_str).unwrap_or("").to_string())
}

/// The confirmed community hashes, as lines the hash database reads (`sha256,Name`).
pub fn community_lines(db: &Value) -> Vec<String> {
    db.get("hashes")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|h| {
                    let sha = h.get("sha256")?.as_str()?.to_ascii_lowercase();
                    let name = h.get("name").and_then(Value::as_str).unwrap_or("Malware/Community");
                    (sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit())).then(|| format!("{sha},{}", name.replace([',', '\n', '\r'], " ")))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Downloads the community database into the rules folder. Returns how many hashes it holds.
pub fn update_community(dir: &Path) -> Result<usize> {
    let mut resp = agent(60).get(format!("{}/shared/db/hexward-db.json", base())).call()?;
    if resp.status() != 200 {
        bail!("community database answered {}", resp.status());
    }
    let db: Value = serde_json::from_str(&resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_string()?)?;
    let lines = community_lines(&db);
    let version = db.get("version").and_then(Value::as_str).unwrap_or("?");
    let text = format!("# Hexward community database v{version} ({BASE}), confirmed submissions.\n# Format: sha256,Detection/Name\n{}\n", lines.join("\n"));
    std::fs::write(dir.join(COMMUNITY_FILE), text)?;
    Ok(lines.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const H: &str = "940a2e4e44de86cf81f860ffc06fcac2b1767114f25ad3551be2e4fed8ba24dd";

    #[test]
    fn only_a_short_prefix_is_sent() {
        assert_eq!(prefix(H).as_deref(), Some("940a2e"));
        assert_eq!(prefix(&H.to_uppercase()).as_deref(), Some("940a2e"));
        assert_eq!(prefix("940a2e"), None);
        assert_eq!(prefix(&"z".repeat(64)), None);
    }

    #[test]
    fn full_hash_is_compared_on_the_pc() {
        let other = format!("940a2e{}", "0".repeat(58));
        let answer = serde_json::json!({ "bad": [[other, "Trojan/Win.Other", "feed"], [H, "Test/Any.HashMarker!a", "community"]], "allow": [] });
        assert_eq!(parse_lookup(H, &answer), Reputation::Bad { name: "Test/Any.HashMarker!a".into(), source: "community".into() });
        let answer = serde_json::json!({ "bad": [[other, "Trojan/Win.Other", "feed"]], "allow": [] });
        assert_eq!(parse_lookup(H, &answer), Reputation::Unknown);
        let answer = serde_json::json!({ "bad": [[H, "x", "feed"]], "allow": [[H, "tool.exe"]] });
        assert_eq!(parse_lookup(H, &answer), Reputation::Allowed { name: "tool.exe".into() });
    }

    #[test]
    fn reports_never_carry_a_folder() {
        let r = Report { kind: Kind::FalseAlarm, sha256: Some(H.into()), name: r"C:\Users\me\Desktop\tool.exe".into(), detection: "Suspicious/Win.Packed".into(), signer: None };
        let b = report_body(&r, "0123456789abcdef0123456789abcdef");
        assert_eq!(b["name"], "tool.exe");
        assert_eq!(b["kind"], "false-alarm");
        let r = Report { kind: Kind::SupplyChain, sha256: None, name: "npm:evil@1.0.0".into(), detection: "Known malware".into(), signer: None };
        assert_eq!(report_body(&r, "x")["name"], "npm:evil@1.0.0");
    }

    #[test]
    fn community_hashes_become_hash_lines() {
        let db = serde_json::json!({ "hashes": [{ "sha256": H, "name": "Test/Any.HashMarker!a" }, { "sha256": "nope", "name": "x" }] });
        assert_eq!(community_lines(&db), vec![format!("{H},Test/Any.HashMarker!a")]);
    }
}
