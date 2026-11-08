//! Cheap checks that need no signatures. They only ever report "suspicious";
//! nothing found here is quarantined unless the user asks for it.

use std::path::Path;

use crate::detect::{Detection, Severity, Source};

/// Extensions Windows will run when double-clicked.
const RUNNABLE: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "wsh", "hta", "msi", "ps1", "lnk", "cpl",
];

/// Extensions people trust as "just a document or picture".
const DOCUMENT: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "jpg", "jpeg", "png", "gif", "bmp", "webp",
    "mp3", "mp4", "mov", "avi", "mkv", "wav", "zip", "rar", "7z",
];

fn ext_lower(name: &str) -> Option<String> {
    let (_, ext) = name.rsplit_once('.')?;
    Some(ext.trim().to_ascii_lowercase())
}

/// Checks on the file name alone.
pub fn name_checks(path: &Path) -> Vec<Detection> {
    let mut out = Vec::new();
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return out;
    };

    // Right-to-left override makes "invoice\u{202E}fdp.exe" display as "invoiceexe.pdf".
    if name.contains('\u{202E}') {
        out.push(Detection::new(
            "Suspicious/Win.RTLO!a",
            Severity::High,
            Source::Heuristic,
            "The file name uses a hidden character that reverses text, a common trick to hide a program's real extension.",
        ));
    }

    let Some(last) = ext_lower(name) else { return out };
    if !RUNNABLE.contains(&last.as_str()) {
        return out;
    }
    let stem = &name[..name.len() - last.len() - 1];

    // "report.pdf.exe"
    if let Some(inner) = ext_lower(stem)
        && DOCUMENT.contains(&inner.as_str())
    {
        out.push(Detection::new(
            "Suspicious/Win.DoubleExt!a",
            Severity::Medium,
            Source::Heuristic,
            format!("A program named to look like a .{inner} file. Windows hides the real .{last} ending by default."),
        ));
    }

    // "photo.jpg            .exe": spaces push the real extension out of view.
    if stem.ends_with("   ") || stem.contains("     ") {
        out.push(Detection::new(
            "Suspicious/Win.PaddedName!a",
            Severity::Medium,
            Source::Heuristic,
            "The file name is padded with spaces to hide that it is a program.",
        ));
    }
    out
}

/// Checks on the file contents.
pub fn content_checks(path: &Path, data: &[u8]) -> Vec<Detection> {
    let mut out = Vec::new();
    if data.len() < 64 || !data.starts_with(b"MZ") {
        return out;
    }
    let Some(ext) = path.file_name().and_then(|n| n.to_str()).and_then(ext_lower) else {
        return out;
    };
    if DOCUMENT.contains(&ext.as_str()) && ext != "zip" && ext != "rar" && ext != "7z" && goblin::pe::PE::parse(data).is_ok() {
        out.push(Detection::new(
            "Suspicious/Win.Masquerade!a",
            Severity::Medium,
            Source::Heuristic,
            format!("This .{ext} file is really a Windows program."),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(path: &str) -> Vec<String> {
        name_checks(Path::new(path)).into_iter().map(|d| d.name).collect()
    }

    #[test]
    fn double_extension() {
        assert_eq!(names(r"C:\Users\sam\Downloads\invoice_2026.pdf.exe"), ["Suspicious/Win.DoubleExt!a"]);
        assert_eq!(names(r"C:\x\holiday.JPG.scr"), ["Suspicious/Win.DoubleExt!a"]);
    }

    #[test]
    fn rtlo_and_padding() {
        assert!(names("invoice\u{202E}fdp.exe").contains(&"Suspicious/Win.RTLO!a".to_string()));
        assert_eq!(names("photo.jpg          .exe"), ["Suspicious/Win.DoubleExt!a", "Suspicious/Win.PaddedName!a"]);
    }

    #[test]
    fn normal_names_are_clean() {
        for n in ["setup.exe", "report.pdf", "app.1.2.3.exe", "my.notes.txt", "Firefox Setup 140.0.exe", "archive.tar.gz", "photo.png"] {
            assert!(names(n).is_empty(), "{n} should be clean");
        }
    }

    #[test]
    fn text_is_not_a_program() {
        assert!(content_checks(Path::new("a.jpg"), b"MZ but really just text that happens to start with MZ and is long enough").is_empty());
    }
}
