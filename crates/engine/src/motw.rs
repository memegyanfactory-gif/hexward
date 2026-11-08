//! Mark of the Web: the `Zone.Identifier` note Windows attaches to downloaded files. It's what
//! makes SmartScreen, Office's Protected View and "this file came from the internet" warnings
//! appear. Many archive tools drop it when unpacking, which attackers rely on: a script inside a
//! downloaded ZIP runs without any warning once it's extracted.
//!
//! Hexward reads where a file came from, and copies the mark from a downloaded archive onto the
//! programs, scripts and documents extracted from it.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Motw {
    /// 3 = internet, 4 = restricted sites.
    pub zone: u32,
    pub host_url: Option<String>,
    pub referrer_url: Option<String>,
}

fn ads(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(":Zone.Identifier");
    PathBuf::from(s)
}

/// The file's mark of the web, if it has one.
pub fn read(path: &Path) -> Option<Motw> {
    let text = std::fs::read_to_string(ads(path)).ok()?;
    let mut m = Motw::default();
    for line in text.lines() {
        let Some((k, v)) = line.split_once('=') else { continue };
        match k.trim() {
            "ZoneId" => m.zone = v.trim().parse().unwrap_or(0),
            "HostUrl" => m.host_url = Some(v.trim().to_string()).filter(|s| !s.is_empty() && s != "about:internet"),
            "ReferrerUrl" => m.referrer_url = Some(v.trim().to_string()).filter(|s| !s.is_empty()),
            _ => {}
        }
    }
    (m.zone > 0).then_some(m)
}

/// Writes a mark of the web onto a file.
pub fn write(path: &Path, m: &Motw) -> std::io::Result<()> {
    let mut s = format!("[ZoneTransfer]\r\nZoneId={}\r\n", m.zone);
    if let Some(r) = &m.referrer_url {
        s.push_str(&format!("ReferrerUrl={r}\r\n"));
    }
    if let Some(h) = &m.host_url {
        s.push_str(&format!("HostUrl={h}\r\n"));
    }
    std::fs::write(ads(path), s)
}

/// Extracted files worth marking: what Windows would warn about if it came straight from the web.
const RISKY: &[&str] = &[
    "exe", "scr", "com", "pif", "msi", "msix", "appx", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta", "lnk", "url", "reg", "cpl", "dll", "jar", "chm", "iso", "img", "vhd", "vhdx", "doc", "docm", "xls",
    "xlsm", "ppt", "pptm", "rtf", "one", "pdf", "html", "htm", "svg",
];
const ARCHIVES: &[&str] = &["zip", "7z", "rar", "tar", "gz", "tgz", "cab", "iso", "img", "vhd", "vhdx"];

fn ext(p: &Path) -> String {
    p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

fn recent(p: &Path, within: Duration) -> bool {
    std::fs::metadata(p).and_then(|m| m.modified()).ok().and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|age| age <= within)
}

/// The downloaded archive a new, unmarked file was most likely extracted from: an archive with
/// a mark of the web, downloaded in the last day, either next to the file or named like the
/// folder the file is in (`Downloads\invoice.zip` → `Downloads\invoice\…`).
pub fn source_archive(file: &Path) -> Option<(PathBuf, Motw)> {
    let mut dir = file.parent()?;
    for _ in 0..4 {
        let parent = dir.parent();
        let candidates: Vec<PathBuf> = std::fs::read_dir(dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.path())
            .chain(parent.into_iter().flat_map(|p| {
                let stem = dir.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
                std::fs::read_dir(p).into_iter().flatten().flatten().map(|e| e.path()).filter(move |c| c.file_stem().is_some_and(|s| s.to_string_lossy().to_ascii_lowercase() == stem))
            }))
            .filter(|c| c.is_file() && ARCHIVES.contains(&ext(c).as_str()))
            .take(200)
            .collect();
        let mut best: Option<(PathBuf, Motw, SystemTime)> = None;
        for c in candidates {
            if !recent(&c, Duration::from_secs(24 * 3600)) {
                continue;
            }
            if let Some(m) = read(&c).filter(|m| m.zone >= 3) {
                let t = std::fs::metadata(&c).and_then(|m| m.modified()).unwrap_or(SystemTime::UNIX_EPOCH);
                if best.as_ref().is_none_or(|b| t > b.2) {
                    best = Some((c, m, t));
                }
            }
        }
        if let Some((p, m, _)) = best {
            return Some((p, m));
        }
        dir = parent?;
    }
    None
}

/// For a new file without a mark: copies the mark from the archive it came out of.
/// Returns the archive it was copied from.
pub fn propagate(file: &Path) -> Option<PathBuf> {
    if read(file).is_some() || !RISKY.contains(&ext(file).as_str()) || !recent(file, Duration::from_secs(3600)) {
        return None;
    }
    let (archive, m) = source_archive(file)?;
    let mark = Motw { zone: m.zone, host_url: m.host_url.clone(), referrer_url: m.referrer_url.or_else(|| Some(format!("file:///{}", archive.display()))) };
    write(file, &mark).ok()?;
    Some(archive)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn reads_writes_and_propagates() {
        let dir = tempfile::tempdir().unwrap();
        let zip = dir.path().join("invoice.zip");
        std::fs::write(&zip, b"PK\x03\x04").unwrap();
        let mark = Motw { zone: 3, host_url: Some("https://x.invalid/invoice.zip".into()), referrer_url: None };
        if write(&zip, &mark).is_err() {
            return; // not NTFS (no alternate data streams): nothing to test here
        }
        assert_eq!(read(&zip).unwrap().host_url.as_deref(), Some("https://x.invalid/invoice.zip"));
        // Extracted into a folder named after the archive.
        let out = dir.path().join("invoice");
        std::fs::create_dir(&out).unwrap();
        let script = out.join("invoice.js");
        std::fs::write(&script, b"WScript.Echo(1)").unwrap();
        assert_eq!(propagate(&script).as_deref(), Some(zip.as_path()));
        let m = read(&script).unwrap();
        assert_eq!((m.zone, m.host_url.as_deref()), (3, Some("https://x.invalid/invoice.zip")));
        // Plain text isn't marked, and a file already marked is left alone.
        let txt = out.join("readme.txt");
        std::fs::write(&txt, b"hi").unwrap();
        assert!(propagate(&txt).is_none());
        assert!(propagate(&script).is_none());
    }
}
