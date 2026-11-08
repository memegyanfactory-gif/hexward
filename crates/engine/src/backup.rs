//! Document backups for ransomware rollback, with no admin rights and no shadow copies.
//!
//! Hexward keeps a private copy of the user's documents and photos in
//! `%LOCALAPPDATA%\Hexward\backup`, refreshed in the background when a file changes. A copy is only
//! replaced by a version that still looks like its file type: a .docx that no longer starts with
//! "PK", or a text file that turned into random bytes, is ransomware's work rather than an edit, so
//! it never overwrites the good copy. The copy before that is kept too.
//!
//! After an attack, [`Backup::restore`] puts back every file that was damaged, renamed away or
//! removed since the attack started. Damaged files are kept beside the restored one
//! (`name.hexward-damaged`), never deleted.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// File types that are backed up: documents, spreadsheets, slides, notes and photos.
pub const EXTENSIONS: &[&str] = &[
    "doc", "docx", "docm", "xls", "xlsx", "xlsm", "ppt", "pptx", "odt", "ods", "odp", "rtf", "pdf", "txt", "csv", "md", "json", "xml", "html", "htm", "svg", "jpg", "jpeg", "png", "gif",
    "heic", "tif", "tiff", "bmp", "psd", "epub", "one", "pages", "numbers", "key",
];
/// Bigger files (videos, disk images) are left out: they'd use up the space for everything else.
pub const MAX_FILE: u64 = 20 * 1024 * 1024;
/// Default space the backup may use.
pub const DEFAULT_BUDGET: u64 = 2 * 1024 * 1024 * 1024;
/// A file gone for longer than this is taken out of the backup.
const KEEP_REMOVED: i64 = 30 * 86400;
const DAMAGED_SUFFIX: &str = "hexward-damaged";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Entry {
    pub size: u64,
    /// Modification time of the backed-up version (Unix seconds).
    pub mtime: i64,
    pub sha256: String,
    /// The copy before this one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev: Option<String>,
    /// When the backup first noticed the file was gone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed: Option<i64>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Index {
    files: BTreeMap<String, Entry>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct SyncStats {
    pub files: usize,
    pub saved: usize,
    pub bytes: u64,
    /// Changed files that no longer looked like their type, so they didn't replace the good copy.
    pub refused: Vec<PathBuf>,
    /// The space budget was reached; some files aren't backed up.
    pub full: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Restored,
    /// Dry run: would be restored.
    WouldRestore,
    Failed(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct Restored {
    pub path: PathBuf,
    pub why: &'static str,
    pub outcome: Outcome,
}

pub struct Backup {
    dir: PathBuf,
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn mtime(m: &std::fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn ext_of(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

/// Does this content still look like a file of its type? Encrypted files lose their header.
pub fn intact(ext: &str, data: &[u8]) -> bool {
    if data.is_empty() {
        return true;
    }
    let starts = |m: &[u8]| data.starts_with(m);
    match ext {
        "docx" | "docm" | "xlsx" | "xlsm" | "pptx" | "odt" | "ods" | "odp" | "epub" | "pages" | "numbers" | "key" => starts(b"PK\x03\x04") || starts(b"PK\x05\x06"),
        "doc" | "xls" | "ppt" => starts(&[0xD0, 0xCF, 0x11, 0xE0]),
        "pdf" => data[..data.len().min(1024)].windows(5).any(|w| w == b"%PDF-"),
        "rtf" => starts(b"{\\rtf"),
        "jpg" | "jpeg" => starts(&[0xFF, 0xD8, 0xFF]),
        "png" => starts(&[0x89, b'P', b'N', b'G']),
        "gif" => starts(b"GIF8"),
        "bmp" => starts(b"BM"),
        "tif" | "tiff" => starts(b"II*\0") || starts(b"MM\0*"),
        "psd" => starts(b"8BPS"),
        "heic" => data.len() > 12 && &data[4..8] == b"ftyp",
        "one" => starts(&[0xE4, 0x52, 0x5C, 0x7B]),
        // Text: words and markup are far from random.
        _ => crate::ransom::entropy(&data[..data.len().min(64 * 1024)]) < 6.0,
    }
}

fn skip_dir(name: &str) -> bool {
    name.starts_with('.') || matches!(name.to_ascii_lowercase().as_str(), "node_modules" | "target" | "__pycache__" | "venv" | "$recycle.bin" | "my music" | "my pictures" | "my videos")
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) {
    if depth > 12 || out.len() > 500_000 {
        return;
    }
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        let Ok(ft) = e.file_type() else { continue };
        let p = e.path();
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if !skip_dir(&e.file_name().to_string_lossy()) {
                walk(&p, out, depth + 1);
            }
        } else if ft.is_file() && EXTENSIONS.contains(&ext_of(&p).as_str()) && !e.file_name().to_string_lossy().contains("hexward-canary") {
            out.push(p);
        }
    }
}

impl Backup {
    pub fn open(dir: impl Into<PathBuf>) -> Self {
        Backup { dir: dir.into() }
    }

    pub fn default_dir() -> PathBuf {
        crate::data_dir().join("backup")
    }

    /// The user folders that are backed up: Documents, Desktop and Pictures.
    pub fn default_roots() -> Vec<PathBuf> {
        [dirs::document_dir(), dirs::desktop_dir(), dirs::picture_dir()].into_iter().flatten().filter(|p| p.is_dir()).collect()
    }

    fn index_path(&self) -> PathBuf {
        self.dir.join("index.json")
    }

    fn blob(&self, sha: &str) -> PathBuf {
        self.dir.join("files").join(&sha[..2]).join(sha)
    }

    fn load(&self) -> Index {
        std::fs::read(self.index_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, idx: &Index) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let tmp = self.dir.join("index.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec(idx)?)?;
        std::fs::rename(tmp, self.index_path())
    }

    /// How many files are backed up, and the space they use.
    pub fn usage(&self) -> (usize, u64) {
        let idx = self.load();
        let mut seen = HashSet::new();
        let mut bytes = 0;
        for e in idx.files.values() {
            for sha in std::iter::once(&e.sha256).chain(e.prev.as_ref()) {
                if seen.insert(sha.clone()) {
                    bytes += std::fs::metadata(self.blob(sha)).map(|m| m.len()).unwrap_or(0);
                }
            }
        }
        (idx.files.values().filter(|e| e.removed.is_none()).count(), bytes)
    }

    /// Brings the backup up to date with `roots`. `stop` is asked between files so a shield can
    /// pause it (battery, games, an attack in progress).
    pub fn sync(&self, roots: &[PathBuf], budget: u64, stop: &dyn Fn() -> bool) -> std::io::Result<SyncStats> {
        let mut idx = self.load();
        let mut files = Vec::new();
        for r in roots {
            walk(r, &mut files, 0);
        }
        let mut st = SyncStats { files: files.len(), ..Default::default() };
        let (_, mut used) = self.usage();
        let present: HashSet<String> = files.iter().map(|p| p.to_string_lossy().into_owned()).collect();
        for path in &files {
            if stop() {
                break;
            }
            let Ok(meta) = std::fs::metadata(path) else { continue };
            if meta.len() > MAX_FILE {
                continue;
            }
            let key = path.to_string_lossy().into_owned();
            let mt = mtime(&meta);
            if let Some(e) = idx.files.get_mut(&key) {
                e.removed = None;
                if e.size == meta.len() && e.mtime == mt {
                    continue;
                }
            }
            let mut data = Vec::with_capacity(meta.len() as usize);
            if std::fs::File::open(path).and_then(|mut f| f.read_to_end(&mut data)).is_err() {
                continue; // in use; next time
            }
            if !intact(&ext_of(path), &data) {
                if idx.files.contains_key(&key) {
                    st.refused.push(path.clone());
                }
                continue;
            }
            let sha = hex::encode(Sha256::digest(&data));
            let blob = self.blob(&sha);
            if !blob.exists() {
                if used + data.len() as u64 > budget {
                    st.full = true;
                    continue;
                }
                std::fs::create_dir_all(blob.parent().unwrap_or(&self.dir))?;
                let tmp = blob.with_extension("tmp");
                std::fs::write(&tmp, &data)?;
                std::fs::rename(&tmp, &blob)?;
                used += data.len() as u64;
                st.bytes += data.len() as u64;
            }
            let prev = idx.files.get(&key).filter(|e| e.sha256 != sha).map(|e| e.sha256.clone()).or_else(|| idx.files.get(&key).and_then(|e| e.prev.clone()));
            idx.files.insert(key, Entry { size: meta.len(), mtime: mt, sha256: sha, prev, removed: None });
            st.saved += 1;
        }
        // Files that are gone: remember when they went, forget them after 30 days.
        let t = now();
        let under_roots = |k: &str| roots.iter().any(|r| Path::new(k).starts_with(r));
        idx.files.retain(|k, e| {
            if present.contains(k) || !under_roots(k) {
                return true;
            }
            let since = *e.removed.get_or_insert(t);
            t - since < KEEP_REMOVED
        });
        self.save(&idx)?;
        self.collect_garbage(&idx);
        Ok(st)
    }

    fn collect_garbage(&self, idx: &Index) {
        let keep: HashSet<&str> = idx.files.values().flat_map(|e| std::iter::once(e.sha256.as_str()).chain(e.prev.as_deref())).collect();
        let Ok(rd) = std::fs::read_dir(self.dir.join("files")) else { return };
        for sub in rd.flatten() {
            let Ok(inner) = std::fs::read_dir(sub.path()) else { continue };
            for f in inner.flatten() {
                let name = f.file_name().to_string_lossy().into_owned();
                if !keep.contains(name.as_str()) {
                    let _ = std::fs::remove_file(f.path());
                }
            }
        }
    }

    /// Puts back files damaged, renamed away or removed since `since` (Unix seconds).
    /// A file the user changed normally (it still looks like its type) is left alone.
    pub fn restore(&self, since: i64, dry_run: bool) -> Vec<Restored> {
        let idx = self.load();
        let mut out = Vec::new();
        for (key, e) in &idx.files {
            let path = PathBuf::from(key);
            let why = match std::fs::metadata(&path) {
                Err(_) => match e.removed {
                    Some(t) if t < since => continue, // deleted before the attack
                    _ => "gone (renamed or deleted)",
                },
                Ok(m) => {
                    if mtime(&m) < since || (m.len() == e.size && mtime(&m) == e.mtime) {
                        continue;
                    }
                    let mut head = Vec::new();
                    let _ = std::fs::File::open(&path).and_then(|f| f.take(64 * 1024).read_to_end(&mut head));
                    if intact(&ext_of(&path), &head) {
                        continue; // an ordinary edit
                    }
                    "damaged (no longer a valid file of its type)"
                }
            };
            let blob = self.blob(&e.sha256);
            let outcome = if !blob.exists() {
                Outcome::Failed("the backup copy is missing".into())
            } else if dry_run {
                Outcome::WouldRestore
            } else {
                match put_back(&path, &blob) {
                    Ok(()) => Outcome::Restored,
                    Err(err) => Outcome::Failed(err.to_string()),
                }
            };
            out.push(Restored { path, why, outcome });
        }
        out
    }
}

fn put_back(path: &Path, blob: &Path) -> std::io::Result<()> {
    if path.exists() {
        let mut aside = path.as_os_str().to_owned();
        aside.push(format!(".{DAMAGED_SUFFIX}"));
        std::fs::rename(path, PathBuf::from(aside))?;
    } else if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(blob, path)?;
    Ok(())
}

/// Unix time a number of minutes ago, for "restore what changed in the last N minutes".
pub fn minutes_ago(m: u64) -> i64 {
    now() - Duration::from_secs(m * 60).as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn random(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9u32;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect()
    }

    #[test]
    fn encrypted_versions_dont_look_intact() {
        assert!(intact("txt", b"Meeting notes: bring the slides."));
        assert!(!intact("txt", &random(8192)));
        assert!(intact("docx", b"PK\x03\x04rest"));
        assert!(!intact("docx", &random(4096)));
        assert!(intact("jpg", &[0xFF, 0xD8, 0xFF, 0xE0, 1, 2]));
        assert!(!intact("png", b"not a png"));
        assert!(intact("pdf", b"%PDF-1.7\n..."));
    }

    #[test]
    fn rolls_back_encrypted_and_renamed_files_but_not_edits() {
        let tmp = tempfile::tempdir().unwrap();
        let docs = tmp.path().join("Documents");
        std::fs::create_dir_all(docs.join("sub")).unwrap();
        let a = docs.join("plan.txt");
        let b = docs.join("sub").join("letter.docx");
        let c = docs.join("edit.txt");
        std::fs::write(&a, "The plan, in plain words.").unwrap();
        std::fs::write(&b, b"PK\x03\x04 a real document").unwrap();
        std::fs::write(&c, "first draft").unwrap();
        let bk = Backup::open(tmp.path().join("backup"));
        let roots = vec![docs.clone()];
        let st = bk.sync(&roots, DEFAULT_BUDGET, &|| false).unwrap();
        assert_eq!(st.saved, 3);
        let before = now() - 5;

        // The attack: one file encrypted in place, one renamed and encrypted; one ordinary edit.
        std::thread::sleep(Duration::from_millis(1100));
        std::fs::write(&a, random(8192)).unwrap();
        std::fs::write(docs.join("sub").join("letter.docx.locked"), random(4096)).unwrap();
        std::fs::remove_file(&b).unwrap();
        std::fs::write(&c, "second draft, still words").unwrap();

        // A sync during the attack must not replace the good copies.
        let st = bk.sync(&roots, DEFAULT_BUDGET, &|| false).unwrap();
        assert_eq!(st.refused, vec![a.clone()]);

        let dry = bk.restore(before, true);
        assert_eq!(dry.len(), 2, "{dry:?}");
        assert!(dry.iter().all(|r| r.outcome == Outcome::WouldRestore));

        let done = bk.restore(before, false);
        assert!(done.iter().all(|r| r.outcome == Outcome::Restored), "{done:?}");
        assert_eq!(std::fs::read_to_string(&a).unwrap(), "The plan, in plain words.");
        assert_eq!(std::fs::read(&b).unwrap(), b"PK\x03\x04 a real document");
        assert!(docs.join("plan.txt.hexward-damaged").exists());
        assert_eq!(std::fs::read_to_string(&c).unwrap(), "second draft, still words");
    }

    #[test]
    fn respects_the_space_budget() {
        let tmp = tempfile::tempdir().unwrap();
        let docs = tmp.path().join("d");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("a.txt"), "a".repeat(600)).unwrap();
        std::fs::write(docs.join("b.txt"), "b".repeat(600)).unwrap();
        let bk = Backup::open(tmp.path().join("backup"));
        let st = bk.sync(&[docs], 1000, &|| false).unwrap();
        assert!(st.full);
        assert_eq!(st.saved, 1);
    }
}
