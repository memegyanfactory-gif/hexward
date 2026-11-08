//! Ransomware shield (user mode).
//!
//! Three signals, any one of them enough:
//! - **Canary files**: hidden decoy documents in the user's folders. Nobody opens them; if one
//!   changes, is renamed or disappears, something is going through the folder file by file.
//! - **Bursts**: many files renamed to the same new extension, or rewritten with data that looks
//!   random (encrypted), within a few seconds.
//! - **Backup deletion**: `vssadmin delete shadows` and friends (see `chains.rs`), which ransomware
//!   runs first so you can't roll back.
//!
//! The suspect is the unsigned program that wrote the most in the last seconds. Getting files back
//! (file rollback) needs Windows' shadow copies and admin rights, so it isn't part of this shield.

use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Shannon entropy in bits per byte (0–8). Encrypted or compressed data is close to 8.
pub fn entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let n = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / n;
        -p * p.log2()
    }).sum()
}

/// File types that are normally compressed already (high entropy is normal for them).
const PACKED: &[&str] = &["zip", "7z", "rar", "gz", "jpg", "jpeg", "png", "gif", "webp", "mp3", "mp4", "mkv", "avi", "mov", "docx", "xlsx", "pptx", "pdf", "iso", "exe", "dll", "msi", "cab", "heic", "flac", "ogg", "woff2"];

fn ext(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

/// Does a file that was just written look encrypted? Reads its first 64 KB.
pub fn looks_encrypted(path: &Path) -> bool {
    if PACKED.contains(&ext(path).as_str()) {
        return false;
    }
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let mut buf = vec![0u8; 64 * 1024];
    let n = std::io::Read::read(&mut f, &mut buf).unwrap_or(0);
    n >= 4096 && entropy(&buf[..n]) > 7.6
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Modified,
    Renamed,
    Removed,
}

/// A sliding window of file changes in the user's folders.
pub struct BurstWatch {
    window: Duration,
    events: VecDeque<(Instant, PathBuf, Change, bool)>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Alarm {
    pub reason: String,
}

impl BurstWatch {
    pub fn new(window: Duration) -> Self {
        BurstWatch { window, events: VecDeque::new() }
    }

    /// Records a change. `encrypted` = the new content looks random.
    pub fn record(&mut self, at: Instant, path: PathBuf, change: Change, encrypted: bool) {
        self.events.push_back((at, path, change, encrypted));
        while self.events.front().is_some_and(|e| at.duration_since(e.0) > self.window) {
            self.events.pop_front();
        }
        if self.events.len() > 10_000 {
            self.events.pop_front();
        }
    }

    /// Is what happened in the window ransomware-like?
    pub fn check(&self) -> Option<Alarm> {
        let encrypted = self.events.iter().filter(|e| e.3).count();
        if encrypted >= 15 {
            return Some(Alarm { reason: format!("{encrypted} files were rewritten with encrypted-looking data in a few seconds") });
        }
        // Many renames to one new, unusual extension (".locked", ".crypt", ".a1b2c3").
        let mut by_ext: HashMap<String, usize> = HashMap::new();
        for e in self.events.iter().filter(|e| e.2 == Change::Renamed) {
            let x = ext(&e.1);
            if !x.is_empty() && !PACKED.contains(&x.as_str()) && !["tmp", "partial", "crdownload", "part", "bak", "lnk"].contains(&x.as_str()) {
                *by_ext.entry(x).or_default() += 1;
            }
        }
        if let Some((x, n)) = by_ext.into_iter().max_by_key(|(_, n)| *n)
            && n >= 20
        {
            return Some(Alarm { reason: format!("{n} files were renamed to .{x} in a few seconds") });
        }
        None
    }

    pub fn clear(&mut self) {
        self.events.clear();
    }
}

// ---------- canary files ----------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub path: PathBuf,
    pub sha256: String,
}

/// Plausible-looking decoys: a text "document" with random content, named to sort first and last.
fn canary_body(seed: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let mut h = Sha256::digest(seed.as_bytes()).to_vec();
    out.extend_from_slice(b"Hexward ransomware canary. This hidden file is a decoy: if it ever changes, something is encrypting your files. Please leave it in place.\r\n\r\n");
    for _ in 0..200 {
        h = Sha256::digest(&h).to_vec();
        for b in &h {
            out.push(b'a' + (b % 26));
        }
        out.extend_from_slice(b"\r\n");
    }
    out
}

/// Places canaries in the given folders (once), hidden. Returns the list to watch.
pub fn ensure_canaries(folders: &[PathBuf], store: &Path) -> Vec<Canary> {
    let mut list: Vec<Canary> = std::fs::read(store).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    for dir in folders.iter().filter(|d| d.is_dir()) {
        for name in ["!hexward-canary.txt", "~zz-hexward-canary.txt"] {
            let p = dir.join(name);
            if list.iter().any(|c| c.path == p) && p.exists() {
                continue;
            }
            let body = canary_body(&p.to_string_lossy());
            if std::fs::write(&p, &body).is_ok() {
                hide(&p);
                list.retain(|c| c.path != p);
                list.push(Canary { path: p, sha256: hex::encode(Sha256::digest(&body)) });
            }
        }
    }
    if let Some(d) = store.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let _ = std::fs::write(store, serde_json::to_vec_pretty(&list).unwrap_or_default());
    list
}

#[cfg(windows)]
fn hide(p: &Path) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{FILE_ATTRIBUTE_HIDDEN, SetFileAttributesW};
    let w: Vec<u16> = p.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
    // SAFETY: sets attributes on a file we just created.
    unsafe {
        SetFileAttributesW(w.as_ptr(), FILE_ATTRIBUTE_HIDDEN);
    }
}

#[cfg(not(windows))]
fn hide(_p: &Path) {}

/// Which canaries were touched (changed, renamed away or deleted).
pub fn touched(list: &[Canary]) -> Vec<PathBuf> {
    list.iter()
        .filter(|c| match std::fs::read(&c.path) {
            Ok(b) => hex::encode(Sha256::digest(&b)) != c.sha256,
            Err(_) => true,
        })
        .map(|c| c.path.clone())
        .collect()
}

/// The program that wrote the most since the last refresh, ignoring Windows and signed software.
pub fn top_writer(sys: &mut sysinfo::System) -> Option<(u32, String, Option<PathBuf>)> {
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::All, true, sysinfo::ProcessRefreshKind::nothing().with_disk_usage().with_exe(sysinfo::UpdateKind::OnlyIfNotSet));
    let me = std::process::id();
    sys.processes()
        .iter()
        .filter(|(pid, _)| pid.as_u32() != me)
        .filter(|(_, p)| p.disk_usage().written_bytes > 512 * 1024)
        .filter(|(_, p)| !crate::tasks::is_protected(&p.name().to_string_lossy(), p.exe()))
        .filter(|(_, p)| p.exe().is_none_or(|e| !crate::sig::is_signed(e)))
        .max_by_key(|(_, p)| p.disk_usage().written_bytes)
        .map(|(pid, p)| (pid.as_u32(), p.name().to_string_lossy().into_owned(), p.exe().map(Path::to_path_buf)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entropy_tells_text_from_random() {
        assert!(entropy(b"hello hello hello hello hello") < 3.0);
        let mut x = 0x1234_5678u32;
        let rnd: Vec<u8> = (0..65536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        assert!(entropy(&rnd) > 7.9);
    }

    #[test]
    fn bursts_raise_an_alarm_normal_work_does_not() {
        let t = Instant::now();
        let mut w = BurstWatch::new(Duration::from_secs(10));
        for i in 0..30 {
            w.record(t, PathBuf::from(format!(r"C:\Users\x\Documents\file{i}.docx")), Change::Modified, false);
        }
        assert!(w.check().is_none(), "saving many ordinary files is fine");
        for i in 0..25 {
            w.record(t, PathBuf::from(format!(r"C:\Users\x\Documents\file{i}.docx.locked")), Change::Renamed, false);
        }
        assert!(w.check().unwrap().reason.contains(".locked"));
        let mut w = BurstWatch::new(Duration::from_secs(10));
        for i in 0..15 {
            w.record(t, PathBuf::from(format!("f{i}.txt")), Change::Modified, true);
        }
        assert!(w.check().is_some());
        // Old events leave the window.
        let mut w = BurstWatch::new(Duration::from_secs(10));
        for i in 0..14 {
            w.record(t, PathBuf::from(format!("a{i}.txt")), Change::Modified, true);
        }
        w.record(t + Duration::from_secs(30), PathBuf::from("late.txt"), Change::Modified, true);
        assert!(w.check().is_none());
    }

    #[test]
    fn canaries_notice_changes() {
        let dir = tempfile::tempdir().unwrap();
        let store = dir.path().join("canaries.json");
        let list = ensure_canaries(&[dir.path().to_path_buf()], &store);
        assert_eq!(list.len(), 2);
        assert!(touched(&list).is_empty());
        std::fs::write(&list[0].path, b"encrypted!").unwrap();
        std::fs::remove_file(&list[1].path).unwrap();
        assert_eq!(touched(&list).len(), 2);
        // Placing again restores them.
        let again = ensure_canaries(&[dir.path().to_path_buf()], &store);
        assert_eq!(touched(&again).len(), 1, "the changed one is still changed until replaced");
    }

    #[test]
    fn encrypted_looking_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut x = 99u32;
        let rnd: Vec<u8> = (0..20000)
            .map(|_| {
                x = x.wrapping_mul(1664525).wrapping_add(1013904223);
                (x >> 24) as u8
            })
            .collect();
        std::fs::write(dir.path().join("report.txt"), &rnd).unwrap();
        std::fs::write(dir.path().join("photo.jpg"), &rnd).unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"plain words ".repeat(1000)).unwrap();
        assert!(looks_encrypted(&dir.path().join("report.txt")));
        assert!(!looks_encrypted(&dir.path().join("photo.jpg")), "photos are compressed anyway");
        assert!(!looks_encrypted(&dir.path().join("notes.txt")));
    }
}
