//! More file types to look inside: RTF embedded objects, PDF actions/JavaScript/attachments,
//! OneNote attachments, CAB archives, RAR archives (file list and stored files), and raw disk
//! images (VHD, VHDX, IMG, UDF) where programs are carved out of the image bytes.
//!
//! Every reader is bounds-checked and capped by the shared container budget. None of them
//! trusts a length field without checking it against the data that's actually there.

use std::io::Read;

use crate::container::{Budget, Expansion, Note};
use crate::detect::Severity;

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u64le(d: &[u8], o: usize) -> Option<u64> {
    d.get(o..o + 8).map(|b| u64::from_le_bytes(b.try_into().unwrap_or([0; 8])))
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

fn finding(ex: &mut Expansion, name: &str, severity: Severity, text: impl Into<String>) {
    ex.notes.push(Note::Finding { name: name.into(), severity, text: text.into(), entry: None });
}

fn add(b: &mut Budget, ex: &mut Expansion, name: String, data: Vec<u8>) -> bool {
    if data.is_empty() {
        return true;
    }
    b.entries += 1;
    b.bytes += data.len() as u64;
    if b.entries > b.limits.max_entries || b.bytes > b.limits.max_total {
        ex.notes.push(Note::Truncated);
        return false;
    }
    ex.children.push(crate::container::Child { name, data });
    true
}

/// Does this look like a program or script someone would run?
fn runnable_content(d: &[u8]) -> Option<&'static str> {
    if d.starts_with(b"MZ") {
        return Some("a Windows program");
    }
    if d.starts_with(&[0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0]) {
        return Some("a shortcut");
    }
    let head = String::from_utf8_lossy(&d[..d.len().min(4096)]).to_ascii_lowercase();
    for (k, what) in [("<hta:application", "an HTA app"), ("wscript.shell", "a script"), ("createobject(", "a script"), ("powershell", "a script"), ("@echo off", "a batch file"), ("cmd /c", "a batch file"), ("<script", "a script")] {
        if head.contains(k) {
            return Some(what);
        }
    }
    None
}

// ---------- RTF ----------

pub fn is_rtf(d: &[u8]) -> bool {
    d.starts_with(b"{\\rt")
}

/// RTF documents carry embedded OLE objects as hex in `\objdata`. Equation Editor objects are
/// how CVE-2017-11882 and CVE-2018-0802 exploits arrive; packages carry files.
pub fn rtf(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let text = &data[..data.len().min(64 * 1024 * 1024)];
    let mut pos = 0;
    let mut n = 0;
    let auto_update = find(text, b"\\objupdate", 0).is_some();
    if !text.starts_with(b"{\\rtf1") && !text.starts_with(b"{\\rtf") {
        finding(ex, "Suspicious/Rtf.MalformedHeader!a", Severity::Low, "The document's header is deliberately malformed. Word still opens it; scanners that expect a normal header may skip it.");
    }
    while let Some(at) = find(text, b"\\objdata", pos) {
        pos = at + 8;
        n += 1;
        // Collect hex digits up to the end of the group, ignoring whitespace and junk.
        let mut hex = Vec::new();
        let mut depth = 0i32;
        let mut i = pos;
        while i < text.len() {
            let c = text[i];
            match c {
                b'{' => depth += 1,
                b'}' => {
                    if depth == 0 {
                        break;
                    }
                    depth -= 1;
                }
                b'\\' => {
                    // skip a control word
                    i += 1;
                    while i < text.len() && text[i].is_ascii_alphabetic() {
                        i += 1;
                    }
                    while i < text.len() && (text[i].is_ascii_digit() || text[i] == b'-') {
                        i += 1;
                    }
                    continue;
                }
                _ if c.is_ascii_hexdigit() => hex.push(c),
                _ => {}
            }
            i += 1;
        }
        let bytes: Vec<u8> = hex.as_chunks::<2>().0.iter().filter_map(|p| u8::from_str_radix(std::str::from_utf8(p).ok()?, 16).ok()).collect();
        // OLE 1.0 object: version, format, class name, topic, item, native size, native data.
        let class_len = u32le(&bytes, 8).unwrap_or(0) as usize;
        let class = bytes.get(12..12 + class_len.min(256)).map(|c| String::from_utf8_lossy(c).trim_end_matches('\0').to_string()).unwrap_or_default();
        let mut o = 12 + class_len;
        for _ in 0..2 {
            let l = u32le(&bytes, o).unwrap_or(0) as usize;
            o += 4 + l.min(bytes.len());
        }
        let native_len = u32le(&bytes, o).unwrap_or(0) as usize;
        let native = bytes.get(o + 4..(o + 4 + native_len).min(bytes.len())).unwrap_or(&bytes[..]).to_vec();
        let lower = class.to_ascii_lowercase();
        if lower.starts_with("equation") || lower.contains("microsoft equation") {
            finding(ex, "Suspicious/Rtf.EquationEditor!a", Severity::High, format!("The document embeds an Equation Editor object ({class}). That old component is the target of widely used exploits (CVE-2017-11882) that run code when the document opens."));
        } else if auto_update && !class.is_empty() {
            finding(ex, "Suspicious/Rtf.AutoUpdateObject!a", Severity::Medium, format!("The document loads an embedded {class} object automatically when it opens."));
        }
        let payload = if lower == "package" {
            crate::office::parse_ole10native(&native).map(|(name, d)| (format!("{name} (package)"), d)).unwrap_or((format!("object {n}"), native))
        } else {
            (format!("object {n} {}", if class.is_empty() { "data".into() } else { class.clone() }), if native.is_empty() { bytes } else { native })
        };
        if let Some(what) = runnable_content(&payload.1) {
            finding(ex, "Suspicious/Rtf.EmbeddedProgram!a", Severity::Medium, format!("The document carries {what} inside an embedded object."));
        }
        if !add(b, ex, payload.0, payload.1) || n > 100 {
            break;
        }
    }
    true
}

// ---------- PDF ----------

pub fn is_pdf(d: &[u8]) -> bool {
    find(&d[..d.len().min(1024)], b"%PDF-", 0).is_some()
}

/// Undoes `#hh` escapes in names (`/J#61vaScript` → `/JavaScript`).
fn pdf_names(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] == b'#'
            && i + 2 < raw.len()
            && let Ok(v) = u8::from_str_radix(std::str::from_utf8(&raw[i + 1..i + 3]).unwrap_or("zz"), 16)
            && v.is_ascii_alphabetic()
        {
            out.push(v);
            i += 3;
            continue;
        }
        out.push(raw[i]);
        i += 1;
    }
    out
}

/// PDF: what runs when it opens (/OpenAction, /AA, /Launch, JavaScript), and attached files.
pub fn pdf(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut all = pdf_names(data);
    let mut streams: Vec<(String, Vec<u8>)> = Vec::new();
    let mut pos = 0;
    let mut inflated = 0usize;
    while let Some(s) = find(data, b"stream", pos) {
        // The dictionary before the stream says what it is.
        let dict_start = data[..s].windows(2).rposition(|w| w == b"<<").unwrap_or(s.saturating_sub(512));
        let dict = pdf_names(&data[dict_start.max(s.saturating_sub(4096))..s]);
        let mut start = s + 6;
        if data.get(start) == Some(&b'\r') {
            start += 1;
        }
        if data.get(start) == Some(&b'\n') {
            start += 1;
        }
        let Some(end) = find(data, b"endstream", start) else { break };
        pos = end + 9;
        let raw = &data[start..end];
        let mut body = raw.to_vec();
        if find(&dict, b"FlateDecode", 0).is_some() && inflated < 64 * 1024 * 1024 {
            let mut out = Vec::new();
            if flate2::read::ZlibDecoder::new(raw).take(32 * 1024 * 1024).read_to_end(&mut out).is_ok() || !out.is_empty() {
                inflated += out.len();
                body = out;
            }
        }
        all.extend_from_slice(&pdf_names(&body));
        if find(&dict, b"/EmbeddedFile", 0).is_some() {
            streams.push((format!("attachment {}", streams.len() + 1), body));
        } else if find(&dict, b"/JS", 0).is_some() || find(&body[..body.len().min(4096)], b"function", 0).is_some() && find(&all, b"/JavaScript", 0).is_some() {
            streams.push((format!("script {}.js", streams.len() + 1), body));
        }
        if streams.len() > 200 {
            break;
        }
    }
    let has = |k: &[u8]| find(&all, k, 0).is_some();
    let js = has(b"/JavaScript") || has(b"/JS ") || has(b"/JS(") || has(b"/JS<");
    let auto = has(b"/OpenAction") || has(b"/AA");
    if has(b"/Launch") {
        let lower = String::from_utf8_lossy(&all).to_ascii_lowercase();
        let runs = ["cmd.exe", "powershell", "mshta", ".exe", ".bat", ".vbs", ".js"].iter().find(|k| lower.contains(*k));
        finding(
            ex,
            "Suspicious/Pdf.Launch!a",
            if runs.is_some() { Severity::High } else { Severity::Medium },
            match runs {
                Some(r) => format!("The PDF tries to start a program ({r}) when you open or click it."),
                None => "The PDF contains a Launch action, which can start programs on your PC.".into(),
            },
        );
    }
    if js && auto {
        let lower = String::from_utf8_lossy(&all).to_ascii_lowercase();
        let exploit = ["unescape(", "util.printf", "collab.geticon", "spray", "getannots", "media.newplayer", "%u0c0c", "%u9090"].iter().any(|k| lower.contains(k));
        finding(
            ex,
            if exploit { "Suspicious/Pdf.JsExploit!a" } else { "Suspicious/Pdf.AutoJavaScript!a" },
            if exploit { Severity::High } else { Severity::Medium },
            if exploit { "The PDF runs JavaScript when opened, with code patterns used by reader exploits." } else { "The PDF runs JavaScript as soon as it's opened. Ordinary documents rarely need that." },
        );
    }
    for (name, body) in streams {
        if name.starts_with("attachment")
            && let Some(what) = runnable_content(&body)
        {
            finding(ex, "Suspicious/Pdf.EmbeddedProgram!a", Severity::Medium, format!("The PDF has {what} attached to it."));
        }
        if !add(b, ex, name, body) {
            break;
        }
    }
    true
}

// ---------- OneNote ----------

const ONENOTE_SIG: [u8; 16] = [0xE4, 0x52, 0x5C, 0x7B, 0x8C, 0xD8, 0xA7, 0x4D, 0xAE, 0xB1, 0x53, 0x78, 0xD0, 0x29, 0x96, 0xD3];
/// FileDataStoreObject header GUID {BDE316E7-2665-4511-A4C4-8D4D0B7A9EAC}.
const ONENOTE_FILE: [u8; 16] = [0xE7, 0x16, 0xE3, 0xBD, 0x65, 0x26, 0x11, 0x45, 0xA4, 0xC4, 0x8D, 0x4D, 0x0B, 0x7A, 0x9E, 0xAC];

pub fn is_onenote(d: &[u8]) -> bool {
    d.starts_with(&ONENOTE_SIG)
}

/// OneNote attachments (the 2023 wave of Qakbot/IcedID lures hid HTA, BAT and EXE files here).
pub fn onenote(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut pos = 0;
    let mut n = 0;
    while let Some(at) = find(data, &ONENOTE_FILE, pos) {
        pos = at + 16;
        let Some(len) = u64le(data, at + 16) else { break };
        let start = at + 36;
        let end = start.saturating_add(len as usize);
        if len == 0 || end > data.len() {
            continue;
        }
        n += 1;
        let body = data[start..end].to_vec();
        pos = end;
        if let Some(what) = runnable_content(&body) {
            finding(ex, "Suspicious/OneNote.EmbeddedRunnable!a", Severity::High, format!("The notebook has {what} attached, usually hidden under a fake \"double-click to view\" button."));
        }
        if !add(b, ex, format!("attachment {n}"), body) {
            break;
        }
    }
    true
}

// ---------- CAB ----------

pub fn is_cab(d: &[u8]) -> bool {
    d.starts_with(b"MSCF")
}

pub fn cab(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let Ok(mut c) = cab::Cabinet::new(std::io::Cursor::new(data)) else { return false };
    let names: Vec<(String, u64)> = c.folder_entries().flat_map(|f| f.file_entries().map(|e| (e.name().to_string(), e.uncompressed_size() as u64)).collect::<Vec<_>>()).take(5000).collect();
    let packed = data.len() as u64;
    let total: u64 = names.iter().map(|(_, s)| *s).sum();
    if packed > 0 && total / packed.max(1) > b.limits.max_ratio && total > 16 * 1024 * 1024 {
        ex.notes.push(Note::Bomb { entry: "cabinet".into(), ratio: total / packed.max(1) });
        return true;
    }
    for (name, size) in names {
        if size > b.limits.max_total.saturating_sub(b.bytes) {
            ex.notes.push(Note::Truncated);
            break;
        }
        let Ok(mut r) = c.read_file(&name) else { continue };
        let mut v = Vec::new();
        if (&mut r).take(size + 1).read_to_end(&mut v).is_err() {
            continue;
        }
        if !add(b, ex, name, v) {
            break;
        }
    }
    true
}

// ---------- RAR ----------

pub fn is_rar(d: &[u8]) -> bool {
    d.starts_with(b"Rar!\x1a\x07")
}

fn vint(d: &[u8], o: &mut usize) -> Option<u64> {
    let mut v = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *d.get(*o)?;
        *o += 1;
        v |= ((byte & 0x7f) as u64) << shift.min(63);
        if byte & 0x80 == 0 {
            return Some(v);
        }
    }
    None
}

/// RAR: Hexward reads the file list (names are checked) and unpacks stored entries. Compressed
/// entries need the proprietary RAR algorithm, whose license isn't GPL-compatible, so they're
/// listed but not unpacked.
pub fn rar(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut entries: Vec<(String, bool, bool, Option<std::ops::Range<usize>>)> = Vec::new(); // name, encrypted, stored, data
    if data.starts_with(b"Rar!\x1a\x07\x01\x00") {
        // RAR 5
        let mut o = 8;
        while o + 7 < data.len() && entries.len() < 10_000 {
            let start = o;
            o += 4; // CRC32
            let Some(hsize) = vint(data, &mut o) else { break };
            let body = o;
            let Some(htype) = vint(data, &mut o) else { break };
            let Some(hflags) = vint(data, &mut o) else { break };
            let extra = if hflags & 1 != 0 { vint(data, &mut o) } else { Some(0) };
            let dsize = if hflags & 2 != 0 { vint(data, &mut o) } else { Some(0) };
            let (Some(extra), Some(dsize)) = (extra, dsize) else { break };
            let next = body.saturating_add(hsize as usize);
            if next <= start || next > data.len() {
                break;
            }
            if htype == 4 {
                ex.notes.push(Note::Encrypted { entry: "(file names are encrypted)".into() });
                return true;
            }
            if htype == 2 {
                let mut p = o;
                let fflags = vint(data, &mut p).unwrap_or(0);
                let _unp = vint(data, &mut p);
                let _attr = vint(data, &mut p);
                if fflags & 2 != 0 {
                    p += 4;
                }
                if fflags & 4 != 0 {
                    p += 4;
                }
                let comp = vint(data, &mut p).unwrap_or(0);
                let _os = vint(data, &mut p);
                let nlen = vint(data, &mut p).unwrap_or(0) as usize;
                let name = data.get(p..p + nlen).map(|n| String::from_utf8_lossy(n).into_owned()).unwrap_or_default();
                let extra_area = data.get(next.saturating_sub(extra as usize)..next).unwrap_or(&[]);
                // Extra record type 1 = file encryption.
                let encrypted = extra as usize > 0 && { let mut q = 0; vint(extra_area, &mut q).is_some() && vint(extra_area, &mut q) == Some(1) };
                let stored = (comp >> 7) & 7 == 0;
                let range = next..next.saturating_add(dsize as usize);
                entries.push((name, encrypted, stored, (range.end <= data.len()).then_some(range)));
            }
            o = next.saturating_add(dsize as usize);
        }
    } else {
        // RAR 4
        let mut o = 7;
        while o + 7 <= data.len() && entries.len() < 10_000 {
            let htype = data[o + 2];
            let flags = u16le(data, o + 3).unwrap_or(0);
            let hsize = u16le(data, o + 5).unwrap_or(0) as usize;
            if hsize < 7 {
                break;
            }
            let add_size = if flags & 0x8000 != 0 { u32le(data, o + 7).unwrap_or(0) as usize } else { 0 };
            if htype == 0x74 {
                let pack = u32le(data, o + 7).unwrap_or(0) as usize;
                let method = data.get(o + 25).copied().unwrap_or(0);
                let nlen = u16le(data, o + 26).unwrap_or(0) as usize;
                let name_at = o + 32 + if flags & 0x100 != 0 { 8 } else { 0 };
                let name = data.get(name_at..name_at + nlen).map(|n| String::from_utf8_lossy(n.split(|c| *c == 0).next().unwrap_or(n)).into_owned()).unwrap_or_default();
                let range = o + hsize..o + hsize + pack;
                entries.push((name, flags & 0x04 != 0, method == 0x30, (range.end <= data.len()).then_some(range)));
                o += hsize + pack;
            } else {
                o += hsize + add_size;
            }
            if htype == 0x7b {
                break;
            }
        }
    }
    let mut unpacked_any = false;
    for (name, encrypted, stored, range) in &entries {
        if *encrypted {
            ex.notes.push(Note::Encrypted { entry: name.clone() });
        } else if *stored && let Some(r) = range {
            unpacked_any = true;
            if !add(b, ex, name.clone(), data[r.clone()].to_vec()) {
                break;
            }
        } else {
            ex.notes.push(Note::Listed { entry: name.clone() });
        }
    }
    !entries.is_empty() || unpacked_any
}

// ---------- disk images ----------

/// VHD, VHDX, and raw FAT/NTFS/UDF images (.img): containers attackers use to dodge the
/// downloaded-file warning. Hexward doesn't mount file systems; it carves programs and shortcuts
/// out of the raw image, which works because small images store files in one piece.
pub fn disk_image_kind(d: &[u8]) -> Option<&'static str> {
    if d.starts_with(b"vhdxfile") {
        return Some("VHDX");
    }
    if d.starts_with(b"conectix") || (d.len() >= 512 && &d[d.len() - 512..d.len() - 504] == b"conectix") {
        return Some("VHD");
    }
    if d.len() >= 512 && d[510] == 0x55 && d[511] == 0xAA {
        if d.get(3..11) == Some(b"NTFS    ") {
            return Some("NTFS image");
        }
        if d.get(0x36..0x39) == Some(b"FAT") || d.get(0x52..0x55) == Some(b"FAT") {
            return Some("FAT image");
        }
    }
    // UDF: "BEA01"/"NSR0x" volume descriptors from sector 16, without an ISO 9660 one.
    if d.len() > 0x9006 && &d[0x8001..0x8006] == b"BEA01" {
        return Some("UDF image");
    }
    None
}

/// Size of the PE file starting at `at`, from its section table.
fn pe_size(d: &[u8], at: usize) -> Option<usize> {
    let pe = at + u32le(d, at + 0x3c)? as usize;
    if d.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = u16le(d, pe + 6)? as usize;
    let opt = u16le(d, pe + 20)? as usize;
    let table = pe + 24 + opt;
    let mut end = table - at + sections * 40;
    for i in 0..sections.min(96) {
        let s = table + i * 40;
        let raw_size = u32le(d, s + 16)? as usize;
        let raw_ptr = u32le(d, s + 20)? as usize;
        end = end.max(raw_ptr.saturating_add(raw_size));
    }
    (end > 0x200 && end < 512 * 1024 * 1024).then_some(end)
}

pub fn disk_image(data: &[u8], kind: &str, b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut pos = 0;
    let mut found = 0;
    let mut runnables = 0;
    while let Some(at) = find(data, b"MZ", pos) {
        pos = at + 2;
        if at == 0 {
            continue;
        }
        if let Some(size) = pe_size(data, at) {
            let end = (at + size).min(data.len());
            found += 1;
            runnables += 1;
            pos = end;
            if !add(b, ex, format!("carved program {found}.exe"), data[at..end].to_vec()) || found > 64 {
                break;
            }
        }
    }
    let lnk = find(data, &[0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46], 0);
    if let Some(at) = lnk {
        runnables += 1;
        let end = (at + 64 * 1024).min(data.len());
        add(b, ex, "carved shortcut.lnk".into(), data[at..end].to_vec());
    }
    if runnables > 0 && data.len() <= 128 * 1024 * 1024 {
        finding(
            ex,
            "Suspicious/Win.DiskImageDropper!a",
            Severity::Medium,
            format!("A small {kind} disk image holding a program or shortcut. Attackers use disk images to get around Windows' downloaded-file warning."),
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::{Budget, Limits};

    fn run(f: fn(&[u8], &mut Budget, &mut Expansion) -> bool, data: &[u8]) -> Expansion {
        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        f(data, &mut b, &mut ex);
        ex
    }

    fn names(ex: &Expansion) -> Vec<String> {
        ex.notes.iter().filter_map(|n| if let Note::Finding { name, .. } = n { Some(name.clone()) } else { None }).collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn ole1(class: &str, native: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend(0x0501u32.to_le_bytes());
        v.extend(2u32.to_le_bytes());
        v.extend(((class.len() + 1) as u32).to_le_bytes());
        v.extend(class.as_bytes());
        v.push(0);
        v.extend(0u32.to_le_bytes());
        v.extend(0u32.to_le_bytes());
        v.extend((native.len() as u32).to_le_bytes());
        v.extend(native);
        v
    }

    #[test]
    fn rtf_objects() {
        let eq = format!("{{\\rtf1{{\\object\\objemb\\objupdate{{\\*\\objclass Equation.3}}{{\\*\\objdata \n{}\n}}}}}}", hex(&ole1("Equation.3", b"\x1c\x00\x00\x00\x02\x00")));
        let ex = run(rtf, eq.as_bytes());
        assert!(names(&ex).contains(&"Suspicious/Rtf.EquationEditor!a".to_string()));
        assert_eq!(ex.children.len(), 1);
        let mut pkg = Vec::new();
        pkg.extend(2u16.to_le_bytes());
        pkg.extend(b"run.exe\0C:\\run.exe\0");
        pkg.extend(0u32.to_le_bytes());
        pkg.extend(3u32.to_le_bytes());
        pkg.extend(b"tmp");
        let body = b"MZ fake program body";
        pkg.extend((body.len() as u32).to_le_bytes());
        pkg.extend(body);
        let mut native = (pkg.len() as u32).to_le_bytes().to_vec();
        native.extend(&pkg);
        let doc = format!("{{\\rt{{\\object{{\\*\\objdata {}}}}}}}", hex(&ole1("Package", &native)));
        let ex = run(rtf, doc.as_bytes());
        let n = names(&ex);
        assert!(n.contains(&"Suspicious/Rtf.MalformedHeader!a".to_string()) && n.contains(&"Suspicious/Rtf.EmbeddedProgram!a".to_string()), "{n:?}");
    }

    #[test]
    fn pdf_actions_and_attachments() {
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, b"MZ attached program").unwrap();
        let att = z.finish().unwrap();
        let mut pdf_bytes = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj\n2 0 obj << /S /J#61vaScript /JS (app.alert(1)) >> endobj\n3 0 obj << /Type /EmbeddedFile /Filter /FlateDecode >>\nstream\n".to_vec();
        pdf_bytes.extend(&att);
        pdf_bytes.extend(b"\nendstream\nendobj\n%%EOF");
        let ex = run(pdf, &pdf_bytes);
        let n = names(&ex);
        assert!(n.contains(&"Suspicious/Pdf.AutoJavaScript!a".to_string()) && n.contains(&"Suspicious/Pdf.EmbeddedProgram!a".to_string()), "{n:?}");
        assert!(ex.children.iter().any(|c| c.data.starts_with(b"MZ")));
        let plain = run(pdf, b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n%%EOF");
        assert!(names(&plain).is_empty());
    }

    #[test]
    fn onenote_attachments() {
        let mut d = ONENOTE_SIG.to_vec();
        d.extend([0u8; 100]);
        d.extend(ONENOTE_FILE);
        let body = b"<hta:application id=x /><script>var s=1</script>";
        d.extend((body.len() as u64).to_le_bytes());
        d.extend([0u8; 12]);
        d.extend(body);
        d.extend([0u8; 16]);
        let ex = run(onenote, &d);
        assert_eq!(ex.children.len(), 1);
        assert_eq!(names(&ex), ["Suspicious/OneNote.EmbeddedRunnable!a"]);
    }

    #[test]
    fn rar4_lists_and_unpacks_stored() {
        let mut d = b"Rar!\x1a\x07\x00".to_vec();
        d.extend([0x00, 0x00, 0x73, 0x00, 0x00, 0x0d, 0x00, 0, 0, 0, 0, 0, 0]); // archive header
        let body = b"hello stored";
        let name = b"invoice.pdf.exe";
        let hsize = 32 + name.len();
        let mut h = vec![0u8, 0, 0x74];
        h.extend(0u16.to_le_bytes());
        h.extend((hsize as u16).to_le_bytes());
        h.extend((body.len() as u32).to_le_bytes());
        h.extend((body.len() as u32).to_le_bytes());
        h.push(2);
        h.extend([0u8; 4]);
        h.extend([0u8; 4]);
        h.push(29);
        h.push(0x30);
        h.extend((name.len() as u16).to_le_bytes());
        h.extend([0u8; 4]);
        h.extend(name);
        d.extend(h);
        d.extend(body);
        let ex = run(rar, &d);
        assert_eq!(ex.children.len(), 1);
        assert_eq!(ex.children[0].name, "invoice.pdf.exe");
        assert_eq!(ex.children[0].data, body);
    }

    #[test]
    fn disk_image_carves_programs() {
        let mut img = vec![0u8; 4096];
        img[3..11].copy_from_slice(b"NTFS    ");
        img[510] = 0x55;
        img[511] = 0xAA;
        // A minimal PE: MZ, e_lfanew, PE header with one section.
        let mut pe = vec![0u8; 1024];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        let sec = 0x80 + 24 + 0xE0;
        pe[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes());
        img.extend(&pe);
        img.extend(vec![0u8; 2048]);
        assert_eq!(disk_image_kind(&img), Some("NTFS image"));
        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        disk_image(&img, "NTFS image", &mut b, &mut ex);
        assert_eq!(ex.children.len(), 1);
        assert_eq!(ex.children[0].data.len(), 0x400);
        assert_eq!(names(&ex), ["Suspicious/Win.DiskImageDropper!a"]);
    }

    #[test]
    fn garbage_never_panics() {
        let mut seed = 7u32;
        for len in [0usize, 1, 7, 31, 513, 4097] {
            let junk: Vec<u8> = (0..len)
                .map(|_| {
                    seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                    (seed >> 16) as u8
                })
                .collect();
            for prefix in [&b"{\\rtf1\\objdata "[..], b"%PDF-1.7 stream\n", &ONENOTE_SIG, &ONENOTE_FILE, b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00", b"MSCF"] {
                let mut d = prefix.to_vec();
                d.extend(&junk);
                for f in [rtf, pdf, onenote, rar, cab] {
                    run(f, &d);
                }
            }
        }
    }
}
