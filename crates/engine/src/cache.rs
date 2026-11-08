//! Scan cache: files already found clean by this exact rule set are skipped on later scans.
//!
//! A file's key is a hash of its path, size and last-write time; the whole cache is tied to the
//! engine's fingerprint (rules, hash lists, disabled rules, engine version), so a rule update
//! empties it. Only clean results are cached; anything with a finding is always re-checked.
//! Stored as a compact binary file: "HWC1", the fingerprint, then one u64 per file.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const MAGIC: &[u8; 4] = b"HWC1";
/// Keeps the file small (16 MB) even on very large disks.
const MAX_KEYS: usize = 2_000_000;

pub struct ScanCache {
    path: PathBuf,
    fingerprint: u64,
    known: HashSet<u64>,
    fresh: Mutex<Vec<u64>>,
}

/// FNV-1a: stable across Rust versions and platforms, unlike the std hasher.
pub fn fnv(bytes: &[u8], mut h: u64) -> u64 {
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

pub const FNV_START: u64 = 0xcbf29ce484222325;

impl std::fmt::Debug for ScanCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ScanCache({} files)", self.known.len())
    }
}

impl ScanCache {
    pub fn default_path() -> PathBuf {
        crate::data_dir().join("cache").join("scan.bin")
    }

    /// Opens the cache for an engine fingerprint. A missing, damaged or outdated file gives an empty cache.
    pub fn open(path: impl Into<PathBuf>, fingerprint: u64) -> Self {
        let path = path.into();
        let mut known = HashSet::new();
        if let Ok(bytes) = std::fs::read(&path)
            && bytes.len() >= 12
            && &bytes[..4] == MAGIC
            && u64::from_le_bytes(bytes[4..12].try_into().unwrap_or_default()) == fingerprint
        {
            known.extend(bytes[12..].as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)));
        }
        ScanCache { path, fingerprint, known, fresh: Mutex::new(Vec::new()) }
    }

    pub fn key(path: &Path, meta: &std::fs::Metadata) -> u64 {
        let mut h = fnv(path.to_string_lossy().to_lowercase().as_bytes(), FNV_START);
        h = fnv(&meta.len().to_le_bytes(), h);
        let modified = meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_nanos()).unwrap_or(0);
        fnv(&modified.to_le_bytes(), h)
    }

    pub fn contains(&self, key: u64) -> bool {
        self.known.contains(&key)
    }

    pub fn len(&self) -> usize {
        self.known.len()
    }

    pub fn is_empty(&self) -> bool {
        self.known.is_empty()
    }

    /// Records a file found clean in this scan.
    pub fn insert(&self, key: u64) {
        if let Ok(mut f) = self.fresh.lock() {
            f.push(key);
        }
    }

    /// Writes known + newly clean keys. Best effort: a failed write only costs speed next time.
    pub fn save(&self) -> std::io::Result<()> {
        let fresh = self.fresh.lock().map(|f| f.clone()).unwrap_or_default();
        if fresh.is_empty() {
            return Ok(());
        }
        let mut all: Vec<u64> = self.known.iter().copied().chain(fresh).collect();
        all.sort_unstable();
        all.dedup();
        if all.len() > MAX_KEYS {
            // Keep the newest entries: fresh keys are a better bet than old ones.
            all.drain(..all.len() - MAX_KEYS);
        }
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let mut out = Vec::with_capacity(12 + all.len() * 8);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.fingerprint.to_le_bytes());
        for k in all {
            out.extend_from_slice(&k.to_le_bytes());
        }
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, out)?;
        std::fs::rename(tmp, &self.path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_invalidation() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a.txt");
        std::fs::write(&file, "x").unwrap();
        let key = ScanCache::key(&file, &std::fs::metadata(&file).unwrap());
        let path = dir.path().join("scan.bin");

        let c = ScanCache::open(&path, 7);
        assert!(!c.contains(key));
        c.insert(key);
        c.save().unwrap();
        assert!(ScanCache::open(&path, 7).contains(key));
        assert!(!ScanCache::open(&path, 8).contains(key), "a new rule set empties the cache");

        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(&file, "changed").unwrap();
        let changed = ScanCache::key(&file, &std::fs::metadata(&file).unwrap());
        assert_ne!(key, changed, "editing a file changes its key");
    }

    #[test]
    fn damaged_file_is_an_empty_cache() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan.bin");
        std::fs::write(&path, b"garbage").unwrap();
        assert!(ScanCache::open(&path, 1).is_empty());
    }
}
