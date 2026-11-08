//! Files the user trusts. Matched by SHA-256, so a trusted file that later changes
//! (for example, gets infected) is scanned again. Stored locally as JSON.

use std::collections::HashSet;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Allowed {
    pub sha256: String,
    pub path: PathBuf,
    /// The detection that was overruled, kept so the user can see why it was flagged.
    pub detection: String,
    pub added: DateTime<Utc>,
}

fn path() -> PathBuf {
    crate::data_dir().join("allowlist.json")
}

pub fn list() -> Vec<Allowed> {
    std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save(items: &[Allowed]) -> std::io::Result<()> {
    std::fs::create_dir_all(crate::data_dir())?;
    std::fs::write(path(), serde_json::to_vec_pretty(items).map_err(std::io::Error::other)?)
}

pub fn add(sha256: &str, file: PathBuf, detection: &str) -> std::io::Result<()> {
    let mut items = list();
    if !items.iter().any(|a| a.sha256.eq_ignore_ascii_case(sha256)) {
        items.push(Allowed { sha256: sha256.to_ascii_lowercase(), path: file, detection: detection.into(), added: Utc::now() });
    }
    save(&items)
}

pub fn remove(sha256: &str) -> std::io::Result<()> {
    let mut items = list();
    items.retain(|a| !a.sha256.eq_ignore_ascii_case(sha256));
    save(&items)
}

/// The hashes as raw bytes, for fast lookups during a scan.
pub fn hashes() -> HashSet<[u8; 32]> {
    list()
        .iter()
        .filter_map(|a| {
            let mut h = [0u8; 32];
            hex::decode_to_slice(&a.sha256, &mut h).ok().map(|_| h)
        })
        .collect()
}
