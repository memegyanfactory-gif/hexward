//! Looks inside containers: ZIP (and everything built on it: Office files, JAR, APK, MSIX),
//! GZIP, TAR, 7z and ISO disk images.
//!
//! Hostile files are the normal case here, so every reader runs inside one budget per
//! top-level file: limited depth, entry count, bytes unpacked and compression ratio.
//! A file that breaks the budget is reported (a zip bomb is itself suspicious), never
//! allowed to exhaust memory or time.

use std::io::{Cursor, Read};

/// Hard limits for one top-level file and everything nested in it.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Containers inside containers: 3 means file.zip › inner.7z › deeper.iso › payload.exe.
    pub max_depth: u32,
    /// Entries looked at across the whole tree.
    pub max_entries: usize,
    /// Largest single inner file that gets scanned.
    pub max_entry: u64,
    /// Total bytes unpacked across the whole tree.
    pub max_total: u64,
    /// Uncompressed:compressed ratio above which an entry counts as a bomb (when it's also big).
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits { max_depth: 3, max_entries: 5_000, max_entry: 64 * 1024 * 1024, max_total: 1024 * 1024 * 1024, max_ratio: 250 }
    }
}

/// Spend-down counters shared by every level of one top-level file.
#[derive(Debug)]
pub struct Budget {
    pub limits: Limits,
    pub entries: usize,
    pub bytes: u64,
}

impl Budget {
    pub fn new(limits: Limits) -> Self {
        Budget { limits, entries: 0, bytes: 0 }
    }
    fn room(&self) -> u64 {
        self.limits.max_total.saturating_sub(self.bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    Gzip,
    Tar,
    SevenZ,
    Iso,
}

impl Format {
    pub fn name(self) -> &'static str {
        match self {
            Format::Zip => "ZIP",
            Format::Gzip => "GZIP",
            Format::Tar => "TAR",
            Format::SevenZ => "7z",
            Format::Iso => "ISO image",
        }
    }
}

/// Decided by content, never by file extension.
pub fn detect(data: &[u8]) -> Option<Format> {
    if data.starts_with(b"PK\x03\x04") || data.starts_with(b"PK\x05\x06") {
        Some(Format::Zip)
    } else if data.starts_with(&[0x1F, 0x8B]) {
        Some(Format::Gzip)
    } else if data.starts_with(&[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C]) {
        Some(Format::SevenZ)
    } else if data.len() > 0x8006 && &data[0x8001..0x8006] == b"CD001" {
        Some(Format::Iso)
    } else if data.len() >= 512 && &data[257..262] == b"ustar" {
        Some(Format::Tar)
    } else {
        None
    }
}

#[derive(Debug)]
pub struct Child {
    pub name: String,
    pub data: Vec<u8>,
}

/// Something about the container worth reporting even if no inner file is bad.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Note {
    /// Unpacks to far more than it holds, or would blow the budget.
    Bomb { entry: String, ratio: u64 },
    /// Password-protected entry; scanners can't see inside.
    Encrypted { entry: String },
    /// Couldn't be opened (damaged, unsupported method). Not suspicious by itself.
    Unreadable,
    /// The budget ran out before every entry was looked at.
    Truncated,
}

#[derive(Debug, Default)]
pub struct Expansion {
    pub children: Vec<Child>,
    pub notes: Vec<Note>,
}

/// Reads up to `limit` bytes; `None` if there was more (so the caller can flag it).
fn read_capped(r: &mut dyn Read, limit: u64) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.take(limit.saturating_add(1)).read_to_end(&mut out).ok()?;
    (out.len() as u64 <= limit).then_some(out)
}

fn accept(b: &mut Budget, ex: &mut Expansion, name: String, data: Vec<u8>) -> bool {
    b.entries += 1;
    b.bytes += data.len() as u64;
    ex.children.push(Child { name, data });
    b.entries < b.limits.max_entries && b.room() > 0
}

/// Unpacks one level. Nested containers are left for the caller to recurse into.
pub fn expand(format: Format, data: &[u8], b: &mut Budget) -> Expansion {
    let mut ex = Expansion::default();
    let ok = match format {
        Format::Zip => zip(data, b, &mut ex),
        Format::Gzip => gzip(data, b, &mut ex),
        Format::Tar => tar(Cursor::new(data), b, &mut ex),
        Format::SevenZ => sevenz(data, b, &mut ex),
        Format::Iso => iso(data, b, &mut ex),
    };
    if !ok && ex.children.is_empty() && ex.notes.is_empty() {
        ex.notes.push(Note::Unreadable);
    }
    if b.entries >= b.limits.max_entries || b.room() == 0 {
        ex.notes.push(Note::Truncated);
    }
    ex
}

fn zip(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let Ok(mut z) = zip::ZipArchive::new(Cursor::new(data)) else { return false };
    for i in 0..z.len() {
        // Look at the header first: nothing is decompressed until it passes the checks.
        let (name, size, packed, encrypted, is_file) = match z.by_index_raw(i) {
            Ok(f) => (f.name().map(|n| n.into_owned()).unwrap_or_default(), f.size(), f.compressed_size(), f.encrypted(), f.is_file()),
            Err(_) => continue,
        };
        if !is_file {
            continue;
        }
        if encrypted {
            ex.notes.push(Note::Encrypted { entry: name });
            continue;
        }
        // Only an extreme ratio makes a bomb; a big file that compresses normally is just skipped.
        let ratio = size / packed.max(1);
        if ratio > b.limits.max_ratio && size > 16 * 1024 * 1024 {
            ex.notes.push(Note::Bomb { entry: name, ratio });
            continue;
        }
        if size > b.limits.max_entry || size > b.room() {
            continue;
        }
        let Ok(mut f) = z.by_index(i) else { continue };
        // Declared sizes can lie, so the read is capped too.
        match read_capped(&mut f, size.min(b.limits.max_entry)) {
            Some(bytes) => {
                if !accept(b, ex, name, bytes) {
                    break;
                }
            }
            // Declared size was a lie (data kept coming): that is a bomb trick.
            None => ex.notes.push(Note::Bomb { entry: name, ratio }),
        }
    }
    true
}

fn gzip(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut dec = flate2::read::GzDecoder::new(data);
    let name = dec.header().and_then(|h| h.filename()).map(|n| String::from_utf8_lossy(n).into_owned()).unwrap_or_else(|| "(gzip content)".into());
    let limit = b.limits.max_entry.min(b.room());
    match read_capped(&mut dec, limit) {
        Some(bytes) => {
            // A .tar.gz: hand the inner tar straight back as one child; the caller recurses.
            accept(b, ex, name, bytes);
            true
        }
        None => {
            // Too big to scan is normal for some files (game and 3D-app data). Only an extreme
            // ratio is a bomb: e.g. 64 MB out of a file under 256 KB.
            let ratio = limit / (data.len() as u64).max(1);
            if ratio > b.limits.max_ratio {
                ex.notes.push(Note::Bomb { entry: name, ratio });
            }
            true
        }
    }
}

fn tar<R: Read>(r: R, b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut archive = tar::Archive::new(r);
    let Ok(entries) = archive.entries() else { return false };
    for entry in entries {
        let Ok(mut e) = entry else { break };
        if !e.header().entry_type().is_file() {
            continue;
        }
        let name = e.path().map(|p| p.display().to_string()).unwrap_or_default();
        let size = e.size();
        if size > b.limits.max_entry || size > b.room() {
            continue;
        }
        if let Some(bytes) = read_capped(&mut e, size)
            && !accept(b, ex, name, bytes)
        {
            break;
        }
    }
    true
}

fn sevenz(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    // A tight decoder memory limit (64 MB) keeps a crafted dictionary size from eating RAM.
    let Ok(mut reader) = sevenz_rust2::ArchiveReader::new_with_memory_limit(Cursor::new(data), sevenz_rust2::Password::empty(), 64 * 1024) else {
        return false;
    };
    let names: Vec<String> = reader.archive().files.iter().filter(|f| f.has_stream()).map(|f| f.name().to_string()).collect();
    let mut stop = false;
    let res = reader.for_each_entries(|entry, r| {
        if stop || entry.is_directory() || !entry.has_stream() {
            return Ok(!stop);
        }
        let name = entry.name().to_string();
        let size = entry.size();
        if size > b.room() {
            ex.notes.push(Note::Bomb { entry: name, ratio: 0 });
            // Drain nothing: skipping solid blocks still requires decoding, so stop here.
            stop = true;
            return Ok(false);
        }
        if size > b.limits.max_entry {
            std::io::copy(&mut r.take(size), &mut std::io::sink())?;
            return Ok(true);
        }
        if let Some(bytes) = read_capped(r, size)
            && !accept(b, ex, name, bytes)
        {
            stop = true;
            return Ok(false);
        }
        Ok(true)
    });
    if let Err(e) = res {
        let msg = e.to_string().to_ascii_lowercase();
        if msg.contains("password") || msg.contains("encrypt") {
            for n in names.into_iter().filter(|n| !ex.children.iter().any(|c| &c.name == n)) {
                ex.notes.push(Note::Encrypted { entry: n });
            }
        } else if ex.children.is_empty() {
            return false;
        }
    }
    true
}

/// Minimal ISO 9660 reader (primary volume, plain names). Written for hostile input:
/// every offset is bounds-checked, each directory is visited once, and the walk is capped.
fn iso(data: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let pvd = 16 * 2048;
    if data.get(pvd) != Some(&1) || data.get(pvd + 1..pvd + 6) != Some(b"CD001") {
        return false;
    }
    let u16le = |at: usize| data.get(at..at + 2).map(|x| u16::from_le_bytes([x[0], x[1]]) as usize);
    let u32le = |at: usize| data.get(at..at + 4).map(|x| u32::from_le_bytes([x[0], x[1], x[2], x[3]]) as usize);
    let Some(block) = u16le(pvd + 128).filter(|b| matches!(b, 512 | 1024 | 2048)) else { return false };
    let root = pvd + 156;
    let (Some(root_lba), Some(root_len)) = (u32le(root + 2), u32le(root + 10)) else { return false };

    let mut queue = vec![(String::new(), root_lba, root_len)];
    let mut seen = std::collections::HashSet::new();
    while let Some((prefix, lba, len)) = queue.pop() {
        if !seen.insert(lba) || seen.len() > 2_000 {
            if seen.len() > 2_000 {
                ex.notes.push(Note::Truncated);
                return true;
            }
            continue;
        }
        let Some(start) = lba.checked_mul(block) else { continue };
        let Some(dir) = data.get(start..start.saturating_add(len.min(16 * 1024 * 1024))) else { continue };
        let mut at = 0;
        while at < dir.len() {
            let rec_len = dir[at] as usize;
            if rec_len == 0 {
                // Records never cross a sector: jump to the next one.
                at = (at / 2048 + 1) * 2048;
                continue;
            }
            let Some(rec) = dir.get(at..at + rec_len) else { break };
            at += rec_len;
            if rec.len() < 34 {
                continue;
            }
            let name_len = rec[32] as usize;
            let Some(raw) = rec.get(33..33 + name_len) else { continue };
            if raw == [0] || raw == [1] {
                continue; // "." and ".."
            }
            let name = String::from_utf8_lossy(raw).split(';').next().unwrap_or("").trim_end_matches('.').to_string();
            let elba = u32::from_le_bytes([rec[2], rec[3], rec[4], rec[5]]) as usize;
            let elen = u32::from_le_bytes([rec[10], rec[11], rec[12], rec[13]]) as usize;
            if rec[25] & 0x02 != 0 {
                queue.push((format!("{prefix}{name}/"), elba, elen));
                continue;
            }
            let size = elen as u64;
            if size > b.limits.max_entry || size > b.room() {
                continue;
            }
            let Some(fstart) = elba.checked_mul(block) else { continue };
            let Some(bytes) = data.get(fstart..fstart.saturating_add(elen)) else { continue };
            if !accept(b, ex, format!("{prefix}{name}"), bytes.to_vec()) {
                return true;
            }
        }
    }
    true
}

#[cfg(test)]
pub(crate) mod tests_support {
    use std::io::{Cursor, Write};

    pub fn zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            for (name, data) in files {
                w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    pub fn make_zip(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut w = zip::ZipWriter::new(&mut buf);
            for (name, data) in files {
                w.start_file(*name, zip::write::SimpleFileOptions::default()).unwrap();
                w.write_all(data).unwrap();
            }
            w.finish().unwrap();
        }
        buf.into_inner()
    }

    #[test]
    fn detects_by_content() {
        assert_eq!(detect(&make_zip(&[("a.txt", b"hi")])), Some(Format::Zip));
        assert_eq!(detect(&[0x1F, 0x8B, 8, 0]), Some(Format::Gzip));
        assert_eq!(detect(b"MZ\x90\x00"), None);
    }

    #[test]
    fn zip_children_and_limits() {
        let z = make_zip(&[("docs/readme.txt", b"hello"), ("bin/tool.exe", b"MZ tool")]);
        let mut b = Budget::new(Limits::default());
        let ex = expand(Format::Zip, &z, &mut b);
        let names: Vec<&str> = ex.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["docs/readme.txt", "bin/tool.exe"]);
        assert!(ex.notes.is_empty());

        let mut tight = Budget::new(Limits { max_entries: 1, ..Limits::default() });
        let ex = expand(Format::Zip, &z, &mut tight);
        assert_eq!(ex.children.len(), 1);
        assert!(ex.notes.contains(&Note::Truncated));
    }

    #[test]
    fn zip_bomb_is_flagged_not_unpacked() {
        let zeros = vec![0u8; 40 * 1024 * 1024];
        let z = make_zip(&[("zeros.bin", &zeros)]);
        assert!(z.len() < 200 * 1024, "compresses hugely: {}", z.len());
        let mut b = Budget::new(Limits::default());
        let ex = expand(Format::Zip, &z, &mut b);
        assert!(ex.children.is_empty());
        assert!(matches!(ex.notes[0], Note::Bomb { .. }));
        assert_eq!(b.bytes, 0, "nothing was unpacked");
    }

    #[test]
    fn big_normal_gzip_is_not_a_bomb() {
        // ~70 MB of varied data compresses only a little: too big to scan, but not a bomb.
        let mut data = Vec::with_capacity(70 * 1024 * 1024);
        let mut x: u32 = 1;
        while data.len() < 70 * 1024 * 1024 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            data.push((x % 64) as u8);
        }
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&data).unwrap();
        let gz = gz.finish().unwrap();
        let mut b = Budget::new(Limits::default());
        let ex = expand(Format::Gzip, &gz, &mut b);
        assert!(ex.children.is_empty() && ex.notes.is_empty(), "{:?}", ex.notes);

        let zeros = vec![0u8; 80 * 1024 * 1024];
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
        gz.write_all(&zeros).unwrap();
        let bomb = gz.finish().unwrap();
        let ex = expand(Format::Gzip, &bomb, &mut Budget::new(Limits::default()));
        assert!(matches!(ex.notes[0], Note::Bomb { .. }));
    }

    #[test]
    fn gzip_and_tar() {
        let mut tar_bytes = Vec::new();
        {
            let mut t = tar::Builder::new(&mut tar_bytes);
            let data = b"echo hi";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_cksum();
            t.append_data(&mut h, "run.sh", &data[..]).unwrap();
            t.finish().unwrap();
        }
        assert_eq!(detect(&tar_bytes), Some(Format::Tar));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&tar_bytes).unwrap();
        let gz = gz.finish().unwrap();
        let mut b = Budget::new(Limits::default());
        let ex = expand(Format::Gzip, &gz, &mut b);
        assert_eq!(detect(&ex.children[0].data), Some(Format::Tar));
        let ex2 = expand(Format::Tar, &ex.children[0].data, &mut b);
        assert_eq!(ex2.children[0].name, "run.sh");
        assert_eq!(ex2.children[0].data, b"echo hi");
    }

    /// Builds a tiny ISO 9660 image: root dir with one subdir and files.
    pub fn make_iso(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut d = vec![0u8; 2048 * 20];
        let rec = |lba: u32, len: u32, dir: bool, name: &[u8]| {
            let mut r = vec![0u8; 33 + name.len() + (1 - name.len() % 2)];
            r[0] = r.len() as u8;
            r[2..6].copy_from_slice(&lba.to_le_bytes());
            r[10..14].copy_from_slice(&len.to_le_bytes());
            r[25] = if dir { 2 } else { 0 };
            r[32] = name.len() as u8;
            r[33..33 + name.len()].copy_from_slice(name);
            r
        };
        let pvd = 16 * 2048;
        d[pvd] = 1;
        d[pvd + 1..pvd + 6].copy_from_slice(b"CD001");
        d[pvd + 128..pvd + 130].copy_from_slice(&2048u16.to_le_bytes());
        let root = rec(18, 2048, true, &[0]);
        d[pvd + 156..pvd + 156 + root.len()].copy_from_slice(&root);
        let mut dir = rec(18, 2048, true, &[0]);
        dir.extend(rec(18, 2048, true, &[1]));
        let mut next_lba = 19u32;
        for (name, data) in files {
            dir.extend(rec(next_lba, data.len() as u32, false, format!("{name};1").as_bytes()));
            let off = next_lba as usize * 2048;
            if d.len() < off + data.len() + 2048 {
                d.resize(off + data.len() + 2048, 0);
            }
            d[off..off + data.len()].copy_from_slice(data);
            next_lba += (data.len() as u32).div_ceil(2048).max(1);
        }
        d[18 * 2048..18 * 2048 + dir.len()].copy_from_slice(&dir);
        d
    }

    #[test]
    fn iso_files_are_listed() {
        let iso = make_iso(&[("INVOICE.LNK", b"shortcut bytes"), ("README.TXT", b"hello")]);
        assert_eq!(detect(&iso), Some(Format::Iso));
        let mut b = Budget::new(Limits::default());
        let ex = expand(Format::Iso, &iso, &mut b);
        let names: Vec<&str> = ex.children.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["INVOICE.LNK", "README.TXT"]);
        assert_eq!(ex.children[1].data, b"hello");
    }

    #[test]
    fn garbage_is_unreadable_not_a_panic() {
        let mut b = Budget::new(Limits::default());
        for f in [Format::Zip, Format::Gzip, Format::Tar, Format::SevenZ, Format::Iso] {
            let mut junk = b"PK\x03\x04".to_vec();
            junk.extend((0..5000u32).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8));
            let _ = expand(f, &junk, &mut b);
        }
    }
}
