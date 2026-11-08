//! Hexward's own rule channel: signed, staged rule packs with rollback and a kill switch.
//!
//! A GitHub workflow (`.github/workflows/rules.yml`) takes each new YARA Forge core pack, runs
//! it through the false-alarm gate (System32 and Program Files on a clean Windows runner), signs
//! it with the release key, and publishes it to the `rules-channel` release with `channel.json`:
//!
//! - **Staged rollout**: a new pack reaches 5% of installs on day one ("canary"), 25% after a
//!   day, everyone after two. Each install has a random bucket 0–99 and takes the newest pack
//!   whose rollout covers its bucket.
//! - **Kill switch**: a pack listed in `killed` is never installed; installs that have it go
//!   back to the newest good pack, or to their own previous copy.
//! - **Signatures**: `channel.json` and every pack are Ed25519-signed with the same key as app
//!   updates; nothing unsigned or mismatched is installed.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const CHANNEL_TAG: &str = "rules-channel";
const STAGES: [(i64, u8); 3] = [(0, 5), (24, 25), (48, 100)];
const KEEP: usize = 6;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PackEntry {
    /// e.g. "2026.11.08"
    pub version: String,
    /// Asset file name, e.g. "hexward-rules-2026.11.08.yar".
    pub file: String,
    pub sha256: String,
    pub rules: usize,
    pub published: DateTime<Utc>,
    /// Share of installs (0–100) that should take this pack now.
    pub percent: u8,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Channel {
    pub schema: u32,
    pub updated: Option<DateTime<Utc>>,
    /// Newest first.
    pub packs: Vec<PackEntry>,
    /// Versions pulled with the kill switch.
    pub killed: Vec<String>,
}

/// Recomputes rollout percentages by age, adds a new pack, applies a kill. Pure, so the
/// workflow's decisions are testable.
pub fn stage(mut ch: Channel, new: Option<PackEntry>, kill: Option<&str>, now: DateTime<Utc>) -> Channel {
    ch.schema = 1;
    if let Some(k) = kill.map(str::trim).filter(|k| !k.is_empty())
        && !ch.killed.iter().any(|x| x == k)
    {
        ch.killed.push(k.to_string());
    }
    if let Some(p) = new
        && !ch.packs.iter().any(|x| x.version == p.version || x.sha256 == p.sha256)
    {
        ch.packs.insert(0, p);
    }
    ch.packs.sort_by_key(|p| std::cmp::Reverse(p.published));
    for p in &mut ch.packs {
        let age = now - p.published;
        p.percent = STAGES.iter().rev().find(|(h, _)| age >= Duration::hours(*h)).map(|(_, pct)| *pct).unwrap_or(STAGES[0].1);
        if ch.killed.contains(&p.version) {
            p.percent = 0;
        }
    }
    ch.packs.truncate(KEEP);
    ch.updated = Some(now);
    ch
}

/// The pack this install should have: the newest not-killed pack whose rollout covers `bucket`.
/// Older packs stay at 100%, so an install outside a canary keeps the last fully rolled-out one.
pub fn choose(ch: &Channel, bucket: u8) -> Option<&PackEntry> {
    ch.packs.iter().find(|p| !ch.killed.contains(&p.version) && p.percent > bucket)
}

/// This install's rollout bucket, 0–99, from a random id kept in the data folder.
pub fn bucket() -> u8 {
    let path = hexward_engine::data_dir().join("install-id");
    let id = std::fs::read_to_string(&path).ok().filter(|s| s.trim().len() >= 16).unwrap_or_else(|| {
        let mut b = [0u8; 16];
        let _ = getrandom::fill(&mut b);
        let id = hex::encode(b);
        let _ = std::fs::create_dir_all(hexward_engine::data_dir());
        let _ = std::fs::write(&path, &id);
        id
    });
    (Sha256::digest(id.trim().as_bytes())[0] as u16 * 100 / 256) as u8
}

fn base_url() -> String {
    std::env::var("HEXWARD_CHANNEL_URL").unwrap_or_else(|_| format!("https://github.com/{}/releases/download/{CHANNEL_TAG}", crate::app::REPO))
}

fn get(agent: &ureq::Agent, url: &str, limit: u64) -> Result<Vec<u8>> {
    let mut r = agent.get(url).call().map_err(|e| match e {
        ureq::Error::StatusCode(404) => anyhow!("the rule channel isn't published yet"),
        ureq::Error::StatusCode(c) => anyhow!("the rule channel answered HTTP {c}"),
        other => anyhow!("couldn't reach the rule channel ({})", other.to_string().split(':').next().unwrap_or("error")),
    })?;
    r.body_mut().with_config().limit(limit).read_to_vec().map_err(|e| anyhow!("download failed: {e}"))
}

/// Downloads and verifies channel.json.
pub fn fetch(agent: &ureq::Agent) -> Result<Channel> {
    let base = base_url();
    let body = get(agent, &format!("{base}/channel.json"), 1024 * 1024)?;
    let sig = get(agent, &format!("{base}/channel.json.sig"), 4096)?;
    crate::app::verify("channel.json", "channel", &body, &String::from_utf8_lossy(&sig), crate::app::PUBLIC_KEY_HEX).context("the rule channel's signature doesn't match")?;
    let ch: Channel = serde_json::from_slice(&body).context("the rule channel is unreadable")?;
    if ch.schema != 1 {
        bail!("this version of Hexward doesn't understand the rule channel (schema {})", ch.schema);
    }
    Ok(ch)
}

pub struct Installed {
    pub version: String,
    pub rules: usize,
    pub rolled_back: bool,
}

/// What `apply` decided.
pub enum Outcome {
    Installed(Installed),
    UpToDate(String),
    /// The installed pack was killed and nothing better is available: the previous local copy is back.
    RestoredPrevious,
}

/// Brings the local pack in line with the channel. `current` is the installed channel version.
pub fn apply(agent: &ureq::Agent, dir: &Path, forge_file: &str, current: Option<&str>) -> Result<Outcome> {
    let ch = fetch(agent)?;
    let mine = bucket();
    let current_killed = current.is_some_and(|c| ch.killed.iter().any(|k| k == c));
    let Some(pick) = choose(&ch, mine) else {
        if current_killed && restore_previous(dir, forge_file)? {
            return Ok(Outcome::RestoredPrevious);
        }
        bail!("no rule pack is rolled out to this install yet");
    };
    if Some(pick.version.as_str()) == current {
        return Ok(Outcome::UpToDate(pick.version.clone()));
    }
    let base = base_url();
    let data = get(agent, &format!("{base}/{}", pick.file), 300 * 1024 * 1024)?;
    let sig = get(agent, &format!("{base}/{}.sig", pick.file), 4096)?;
    crate::app::verify(&pick.file, &pick.version, &data, &String::from_utf8_lossy(&sig), crate::app::PUBLIC_KEY_HEX).context("the rule pack's signature doesn't match; it was not installed")?;
    if hex::encode(Sha256::digest(&data)) != pick.sha256 {
        bail!("the rule pack doesn't match the channel's checksum; it was not installed");
    }
    let src = String::from_utf8_lossy(&data).into_owned();
    let set = hexward_engine::rules::RuleSet::compile(&[("built-in".into(), hexward_engine::rules::BUILTIN_RULES.into()), (forge_file.into(), src)]).context("the new pack didn't compile")?;
    let target = dir.join(forge_file);
    if target.exists() {
        std::fs::copy(&target, previous_path(dir, forge_file))?;
    }
    let tmp = dir.join(format!("{forge_file}.new"));
    std::fs::write(&tmp, &data)?;
    std::fs::rename(&tmp, &target)?;
    Ok(Outcome::Installed(Installed { version: pick.version.clone(), rules: set.count(), rolled_back: current_killed }))
}

pub fn previous_path(dir: &Path, forge_file: &str) -> PathBuf {
    dir.join(format!("{forge_file}.previous"))
}

/// Puts the previous pack back. Returns false when there's no previous copy.
pub fn restore_previous(dir: &Path, forge_file: &str) -> Result<bool> {
    let prev = previous_path(dir, forge_file);
    if !prev.exists() {
        return Ok(false);
    }
    std::fs::rename(&prev, dir.join(forge_file))?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pack(v: &str, hours_ago: i64, now: DateTime<Utc>) -> PackEntry {
        PackEntry { version: v.into(), file: format!("hexward-rules-{v}.yar"), sha256: format!("sha-{v}"), rules: 5000, published: now - Duration::hours(hours_ago), percent: 0 }
    }

    #[test]
    fn rollout_moves_through_stages() {
        let now = Utc::now();
        let ch = stage(Channel::default(), Some(pack("2026.11.06", 50, now)), None, now);
        let ch = stage(ch, Some(pack("2026.11.07", 30, now)), None, now);
        let ch = stage(ch, Some(pack("2026.11.08", 1, now)), None, now);
        let pct: Vec<u8> = ch.packs.iter().map(|p| p.percent).collect();
        assert_eq!(pct, [5, 25, 100]);
        // Bucket 3 is in the canary; bucket 20 in the 25% wave; bucket 90 gets the fully rolled-out pack.
        assert_eq!(choose(&ch, 3).unwrap().version, "2026.11.08");
        assert_eq!(choose(&ch, 20).unwrap().version, "2026.11.07");
        assert_eq!(choose(&ch, 90).unwrap().version, "2026.11.06");
        // Same pack again (same checksum) isn't added twice.
        let again = stage(ch.clone(), Some(PackEntry { version: "2026.11.09".into(), ..pack("2026.11.08", 0, now) }), None, now);
        assert_eq!(again.packs.len(), 3);
    }

    #[test]
    fn kill_switch_rolls_everyone_back() {
        let now = Utc::now();
        let mut ch = Channel::default();
        for (v, h) in [("a", 100), ("b", 60), ("c", 2)] {
            ch = stage(ch, Some(pack(v, h, now)), None, now);
        }
        assert_eq!(choose(&ch, 0).unwrap().version, "c");
        let ch = stage(ch, None, Some("c"), now);
        let ch = stage(ch, None, Some("b"), now);
        assert_eq!(choose(&ch, 0).unwrap().version, "a", "killed packs are skipped, even for the canary bucket");
        assert!(ch.packs.iter().find(|p| p.version == "c").unwrap().percent == 0);
    }

    #[test]
    fn local_rollback() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("x.yar"), "new").unwrap();
        assert!(!restore_previous(dir.path(), "x.yar").unwrap());
        std::fs::write(previous_path(dir.path(), "x.yar"), "old").unwrap();
        assert!(restore_previous(dir.path(), "x.yar").unwrap());
        assert_eq!(std::fs::read_to_string(dir.path().join("x.yar")).unwrap(), "old");
    }
}
