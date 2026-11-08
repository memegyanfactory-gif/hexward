//! Programs that carry other files inside them:
//! - NSIS installers: the compressed data block after the program (zlib/deflate, bzip2 or LZMA,
//!   solid or per file) is unpacked into its files
//! - PyInstaller programs: the bundled archive (scripts, libraries, data) is unpacked
//! - UPX-packed programs: the packed code is decompressed (NRV2B/2D/2E, LZMA), so rules see the
//!   real program instead of the packer stub
//! - Inno Setup installers, best effort: the setup header (the [Run] commands and the compiled
//!   [Code] script) and the compressed file chunks ("zlb\x1a", LZMA, LZMA2 or zlib) are
//!   decompressed, and the programs inside are carved out. Inno's exact file table changes with
//!   every version, so files are found by their own headers rather than by name
//!
//! Unpacked data is only scanned, never run. Everything is capped by the container budget.

use std::io::Read;

use crate::container::{Budget, Child, Expansion, Note};

const MAX_OUT: usize = 256 * 1024 * 1024;

fn u16le(d: &[u8], o: usize) -> Option<u16> {
    d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}
fn u32le(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u32be(d: &[u8], o: usize) -> Option<u32> {
    d.get(o..o + 4).map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| p + from)
}

struct Section {
    name: String,
    raw_ptr: usize,
    raw_size: usize,
}

/// Section table and the end of the last section (where installer data is appended).
fn sections(d: &[u8]) -> Option<(Vec<Section>, usize)> {
    let pe = u32le(d, 0x3c)? as usize;
    if d.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let n = u16le(d, pe + 6)? as usize;
    let table = pe + 24 + u16le(d, pe + 20)? as usize;
    let mut out = Vec::new();
    let mut end = 0;
    for i in 0..n.min(96) {
        let s = table + i * 40;
        let name = String::from_utf8_lossy(d.get(s..s + 8)?).trim_end_matches('\0').to_string();
        let raw_size = u32le(d, s + 16)? as usize;
        let raw_ptr = u32le(d, s + 20)? as usize;
        end = end.max(raw_ptr.saturating_add(raw_size));
        out.push(Section { name, raw_ptr, raw_size });
    }
    Some((out, end))
}

const NSIS_MAGIC: &[u8] = b"\xEF\xBE\xAD\xDENullsoftInst";

/// What kind of packed program this is, if any.
pub fn kind(d: &[u8]) -> Option<&'static str> {
    let (secs, end) = sections(d)?;
    if secs.iter().any(|s| s.name.starts_with("UPX")) && find(&d[..d.len().min(0x2000)], b"UPX!", 0).is_some() {
        return Some("UPX-packed program");
    }
    if end < d.len() {
        let overlay = &d[end..];
        if find(&overlay[..overlay.len().min(64 * 1024 * 1024)], NSIS_MAGIC, 0).is_some() {
            return Some("NSIS installer");
        }
    }
    if d.len() > 88 && find(&d[d.len().saturating_sub(4096)..], b"MEI\x0C\x0B\x0A\x0B\x0E", 0).is_some() {
        return Some("PyInstaller program");
    }
    if find(&d[..d.len().min(4 * 1024 * 1024)], b"Inno Setup Setup Data", 0).is_some() || find(&d[..d.len().min(256 * 1024)], b"InnoSetupLdrWindow", 0).is_some() {
        return Some("Inno Setup installer");
    }
    None
}

fn push(b: &mut Budget, ex: &mut Expansion, name: String, data: Vec<u8>) -> bool {
    if data.is_empty() {
        return true;
    }
    b.entries += 1;
    b.bytes += data.len() as u64;
    if b.entries > b.limits.max_entries || b.bytes > b.limits.max_total {
        ex.notes.push(Note::Truncated);
        return false;
    }
    ex.children.push(Child { name, data });
    true
}

pub fn unpack(d: &[u8], k: &str, b: &mut Budget, ex: &mut Expansion) -> bool {
    match k {
        "NSIS installer" => nsis(d, b, ex),
        "PyInstaller program" => pyinstaller(d, b, ex),
        "UPX-packed program" => upx(d, b, ex),
        "Inno Setup installer" => inno(d, b, ex),
        _ => {
            ex.notes.push(Note::Listed { entry: format!("{k} (contents not unpacked)") });
            true
        }
    }
}

// ---------- Inno Setup ----------

/// Most one Inno stream may expand to.
const INNO_CAP: usize = 128 * 1024 * 1024;

fn read_capped(mut r: impl Read, cap: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    while out.len() < cap {
        match r.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
        }
    }
    out
}

/// LZMA as Inno writes it: a properties byte and a 32-bit dictionary size, then the raw stream.
fn lzma1(c: &[u8], cap: usize) -> Option<Vec<u8>> {
    if c.len() < 6 || c[0] >= 225 {
        return None;
    }
    let dict = u32le(c, 1)?.clamp(4096, 1 << 28);
    let mut r = lzma_rust2::LzmaReader::new_with_props(&c[5..], u64::MAX, c[0], dict, None).ok()?;
    r.set_relaxed_end_condition(true);
    let out = read_capped(r, cap);
    (!out.is_empty()).then_some(out)
}

/// LZMA2 as Inno writes it: one dictionary-size byte, then LZMA2 chunks.
fn lzma2(c: &[u8], cap: usize) -> Option<Vec<u8>> {
    let p = *c.first()?;
    if p > 40 {
        return None;
    }
    let dict = if p == 40 { u32::MAX } else { (2 | (p as u32 & 1)) << (p / 2 + 11) };
    let out = read_capped(lzma_rust2::Lzma2Reader::new(&c[1..], dict.min(1 << 28), None), cap);
    (!out.is_empty()).then_some(out)
}

fn zlib(c: &[u8], cap: usize) -> Option<Vec<u8>> {
    let out = read_capped(flate2::read::ZlibDecoder::new(c), cap);
    (!out.is_empty()).then_some(out)
}

/// One compressed chunk of installed files, whatever method it uses.
fn inno_chunk(c: &[u8], cap: usize) -> Option<Vec<u8>> {
    match c.first()? {
        0x78 => zlib(c, cap),
        b'B' if c.starts_with(b"BZh") => Some(read_capped(bzip2::read::BzDecoder::new(c), cap)).filter(|o| !o.is_empty()),
        p if *p <= 40 => lzma2(c, cap).or_else(|| lzma1(c, cap)),
        _ => lzma1(c, cap),
    }
}

/// A setup-header block: CRC, stored size, "compressed" flag, then the data in 4 KB pieces that
/// each start with their own CRC. Returns the data and how many bytes the block took.
fn inno_block(s: &[u8], cap: usize) -> Option<(Vec<u8>, usize)> {
    // Inno 4.0.9 to 6.3 store a 32-bit size; 6.4 and later a 64-bit one.
    for size_len in [4usize, 8] {
        let stored = if size_len == 4 { u32le(s, 4)? as usize } else { u32le(s, 4)? as usize | (u32le(s, 8)? as usize) << 32 };
        let Some(&flag) = s.get(4 + size_len) else { continue };
        let start = 4 + size_len + 1;
        if flag > 1 || stored < 5 || start + stored > s.len() {
            continue;
        }
        let end = start + stored;
        let mut raw = Vec::with_capacity(stored);
        let mut o = start;
        while o + 4 < end {
            let n = (end - o - 4).min(4096);
            raw.extend_from_slice(&s[o + 4..o + 4 + n]);
            o += 4 + n;
        }
        let out = if flag == 1 { lzma1(&raw, cap).or_else(|| zlib(&raw, cap)) } else { Some(raw) };
        if let Some(out) = out {
            return Some((out, end));
        }
    }
    None
}

fn inno(d: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let mut got = false;
    // setup-0: the header (languages, [Run] and [Registry] entries, the compiled [Code] script),
    // then the file location table.
    if let Some(id) = find(&d[..d.len().min(64 * 1024 * 1024)], b"Inno Setup Setup Data (", 0) {
        let mut pos = id + 64;
        for n in 1..=2 {
            let Some((data, used)) = d.get(pos..).and_then(|s| inno_block(s, INNO_CAP)) else { break };
            got = true;
            if !push(b, ex, format!("inno setup header {n}"), data) {
                return true;
            }
            pos += used;
        }
    }
    // setup-1: the files, in chunks that each start with "zlb\x1a".
    let mut from = 0;
    let mut chunks = 0;
    let mut programs = 0;
    while let Some(at) = find(d, b"zlb\x1a", from) {
        from = at + 4;
        let Some(data) = inno_chunk(&d[at + 4..], INNO_CAP).filter(|o| o.len() >= 16) else { continue };
        chunks += 1;
        got = true;
        // Carve the programs out, so each is checked (and hash-matched) on its own.
        let mut pos = 0;
        while let Some(mz) = find(&data, b"MZ", pos) {
            pos = mz + 2;
            if let Some(size) = crate::formats::pe_size(&data, mz) {
                let end = (mz + size).min(data.len());
                programs += 1;
                pos = end;
                if !push(b, ex, format!("inno program {programs}.exe"), data[mz..end].to_vec()) || programs >= 256 {
                    return true;
                }
            }
        }
        if !push(b, ex, format!("inno files {chunks}"), data) || chunks >= 64 {
            return true;
        }
    }
    if !got {
        ex.notes.push(Note::Listed { entry: "Inno Setup installer (this version's data couldn't be unpacked)".into() });
    }
    true
}

// ---------- NSIS ----------

/// Decompresses one NSIS data stream with whatever method it starts with.
fn nsis_decompress(c: &[u8], cap: usize) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let read_all = |mut r: Box<dyn Read + '_>, out: &mut Vec<u8>| {
        let mut buf = [0u8; 64 * 1024];
        while out.len() < cap {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
            }
        }
    };
    if c.first() == Some(&0x5D) && c.len() > 5 {
        // LZMA: props byte, 32-bit dictionary size, then raw LZMA (size unknown).
        let dict = u32le(c, 1)?.clamp(4096, 64 * 1024 * 1024);
        let mut r = lzma_rust2::LzmaReader::new_with_props(&c[5..], u64::MAX, c[0], dict, None).ok()?;
        r.set_relaxed_end_condition(true);
        read_all(Box::new(r), &mut out);
    } else if c.starts_with(b"BZh") || c.starts_with(b"1") {
        read_all(Box::new(bzip2::read::BzDecoder::new(c)), &mut out);
    } else {
        read_all(Box::new(flate2::read::DeflateDecoder::new(c)), &mut out);
    }
    (!out.is_empty()).then_some(out)
}

/// Splits a run of `[u32 length][data]` records.
fn records(blob: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut o = 0;
    while let Some(len) = u32le(blob, o) {
        let len = (len & 0x7FFF_FFFF) as usize;
        let start = o + 4;
        let Some(rec) = blob.get(start..start.saturating_add(len)) else { break };
        out.push(rec.to_vec());
        o = start + len;
        if out.len() > 20_000 {
            break;
        }
    }
    out
}

fn nsis(d: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let Some((_, end)) = sections(d) else { return false };
    let Some(magic) = find(d, NSIS_MAGIC, end) else { return false };
    let first = magic - 4; // flags come first
    let Some(total) = u32le(d, first + 24) else { return false };
    let data = &d[(first + 28).min(d.len())..(first + total as usize).min(d.len())];
    let mut files: Vec<Vec<u8>> = Vec::new();
    // Solid archives start straight with the compressed stream; others with a u32 size whose
    // top bit says "compressed".
    let head = u32le(data, 0).unwrap_or(0);
    let solid = data.first() == Some(&0x5D) || data.starts_with(b"BZh") || (head & 0x8000_0000 == 0 && head as usize + 4 > data.len());
    if solid {
        if let Some(blob) = nsis_decompress(data, MAX_OUT) {
            files = records(&blob);
        }
    } else {
        let mut o = 0;
        while let Some(h) = u32le(data, o) {
            let len = (h & 0x7FFF_FFFF) as usize;
            let Some(block) = data.get(o + 4..o + 4 + len) else { break };
            let body = if h & 0x8000_0000 != 0 { nsis_decompress(block, MAX_OUT / 4).unwrap_or_default() } else { block.to_vec() };
            files.push(body);
            o += 4 + len;
            if files.len() > 20_000 {
                break;
            }
        }
    }
    if files.is_empty() {
        ex.notes.push(Note::Unreadable);
        return true;
    }
    // The first record is the installer script; the rest are the files it installs.
    for (i, f) in files.into_iter().enumerate() {
        let name = if i == 0 { "installer script".to_string() } else { format!("installed file {i}") };
        if !push(b, ex, name, f) {
            break;
        }
    }
    true
}

// ---------- PyInstaller ----------

fn pyinstaller(d: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let tail = d.len().saturating_sub(4096);
    let Some(c) = find(d, b"MEI\x0C\x0B\x0A\x0B\x0E", tail) else { return false };
    let (Some(pkg_len), Some(toc_off), Some(toc_len)) = (u32be(d, c + 8), u32be(d, c + 12), u32be(d, c + 16)) else { return false };
    // The cookie sits at the end of the package (24 bytes for old versions, 88 for 2.1+).
    let cookie_len = if d.get(c + 24..c + 88).is_some_and(|x| x.contains(&b'p')) { 88 } else { 24 };
    let Some(pkg_start) = (c + cookie_len).checked_sub(pkg_len as usize) else { return false };
    let toc = pkg_start + toc_off as usize;
    let mut o = toc;
    let toc_end = toc + toc_len as usize;
    let mut n = 0;
    while o + 18 <= toc_end.min(d.len()) {
        let Some(entry_len) = u32be(d, o).map(|x| x as usize) else { break };
        if entry_len < 18 {
            break;
        }
        let (pos, csize, usize_, flag, typ) = (u32be(d, o + 4).unwrap_or(0) as usize, u32be(d, o + 8).unwrap_or(0) as usize, u32be(d, o + 12).unwrap_or(0) as usize, d[o + 16], d[o + 17]);
        let name = String::from_utf8_lossy(d.get(o + 18..o + entry_len).unwrap_or(&[])).trim_end_matches('\0').to_string();
        o += entry_len;
        // s = script, b = binary, x = data, m/M = modules, z/Z = module archive (left whole).
        let Some(raw) = d.get(pkg_start + pos..pkg_start + pos + csize) else { continue };
        let body = if flag == 1 {
            let mut v = Vec::new();
            let _ = flate2::read::ZlibDecoder::new(raw).take(usize_.min(MAX_OUT) as u64).read_to_end(&mut v);
            v
        } else {
            raw.to_vec()
        };
        let label = match typ {
            b's' => format!("{name}.py (main script)"),
            b'z' | b'Z' => format!("{name} (module archive)"),
            _ => name,
        };
        n += 1;
        if !push(b, ex, label, body) || n > 5000 {
            break;
        }
    }
    n > 0
}

// ---------- UPX ----------

/// The bit reader UPX's NRV decoders share: 32-bit little-endian words, most significant bit first.
struct Bits<'a> {
    src: &'a [u8],
    pos: usize,
    word: u32,
    left: u32,
}

impl Bits<'_> {
    fn bit(&mut self) -> Option<u32> {
        if self.left == 0 {
            self.word = u32le(self.src, self.pos)?;
            self.pos += 4;
            self.left = 32;
        }
        self.left -= 1;
        Some((self.word >> self.left) & 1)
    }
    fn byte(&mut self) -> Option<u8> {
        let b = *self.src.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }
}

fn copy_match(out: &mut Vec<u8>, off: usize, len: usize, cap: usize) -> Option<()> {
    if off == 0 || off > out.len() || out.len() + len > cap {
        return None;
    }
    let start = out.len() - off;
    for i in 0..len {
        let b = out[start + i];
        out.push(b);
    }
    Some(())
}

/// NRV2B, NRV2D and NRV2E (UCL) decoders, 32-bit little-endian bit variant, as UPX uses for PE files.
pub fn nrv(src: &[u8], method: u8, cap: usize) -> Option<Vec<u8>> {
    // Straight from UCL's n2b_d.c / n2d_d.c / n2e_d.c (32-bit little-endian bit buffer).
    let mut b = Bits { src, pos: 0, word: 0, left: 0 };
    let mut out = Vec::with_capacity(cap.min(16 * 1024 * 1024));
    let mut last_off: u32 = 1;
    loop {
        while b.bit()? == 1 {
            out.push(b.byte()?);
            if out.len() > cap {
                return None;
            }
        }
        let mut m_off: u32 = 1;
        if method == b'B' {
            loop {
                m_off = m_off.wrapping_mul(2).wrapping_add(b.bit()?);
                if b.bit()? == 1 {
                    break;
                }
            }
        } else {
            loop {
                m_off = m_off.wrapping_mul(2).wrapping_add(b.bit()?);
                if b.bit()? == 1 {
                    break;
                }
                m_off = (m_off.wrapping_sub(1)).wrapping_mul(2).wrapping_add(b.bit()?);
            }
        }
        let mut m_len: u32;
        if method == b'B' {
            if m_off == 2 {
                m_off = last_off;
            } else {
                m_off = m_off.wrapping_sub(3).wrapping_mul(256).wrapping_add(b.byte()? as u32);
                if m_off == u32::MAX {
                    break;
                }
                m_off = m_off.wrapping_add(1);
                last_off = m_off;
            }
            m_len = b.bit()?;
            m_len = m_len * 2 + b.bit()?;
            if m_len == 0 {
                m_len = 1;
                loop {
                    m_len = m_len.checked_mul(2)? + b.bit()?;
                    if b.bit()? == 1 {
                        break;
                    }
                }
                m_len += 2;
            }
            m_len += (m_off > 0xd00) as u32;
        } else {
            if m_off == 2 {
                m_off = last_off;
                m_len = b.bit()?;
            } else {
                m_off = m_off.wrapping_sub(3).wrapping_mul(256).wrapping_add(b.byte()? as u32);
                if m_off == u32::MAX {
                    break;
                }
                m_len = (m_off ^ u32::MAX) & 1;
                m_off = (m_off >> 1).wrapping_add(1);
                last_off = m_off;
            }
            if method == b'D' {
                m_len = m_len * 2 + b.bit()?;
                if m_len == 0 {
                    m_len = 1;
                    loop {
                        m_len = m_len.checked_mul(2)? + b.bit()?;
                        if b.bit()? == 1 {
                            break;
                        }
                    }
                    m_len += 2;
                }
            } else if m_len != 0 {
                m_len = 1 + b.bit()?;
            } else if b.bit()? == 1 {
                m_len = 3 + b.bit()?;
            } else {
                m_len = 1;
                loop {
                    m_len = m_len.checked_mul(2)? + b.bit()?;
                    if b.bit()? == 1 {
                        break;
                    }
                }
                m_len += 3;
            }
            m_len += (m_off > 0x500) as u32;
        }
        copy_match(&mut out, m_off as usize, m_len as usize + 1, cap)?;
    }
    Some(out)
}

fn upx(d: &[u8], b: &mut Budget, ex: &mut Expansion) -> bool {
    let Some((secs, _)) = sections(d) else { return false };
    let Some(h) = find(&d[..d.len().min(0x2000)], b"UPX!", 0) else { return false };
    // Pack header: magic, version, format, method, level, u_adler, c_adler, u_len, c_len.
    let method = d.get(h + 6).copied().unwrap_or(0);
    let (Some(u_len), Some(c_len)) = (u32le(d, h + 16), u32le(d, h + 20)) else { return false };
    let Some(upx1) = secs.iter().find(|s| s.name == "UPX1") else { return false };
    let start = upx1.raw_ptr;
    let end = (start + (c_len as usize).max(upx1.raw_size)).min(d.len());
    let Some(src) = d.get(start..end) else { return false };
    let cap = (u_len as usize).min(MAX_OUT);
    let out = match method {
        2..=4 => nrv(src, b'B', cap),
        5..=7 => nrv(src, b'D', cap),
        8..=10 => nrv(src, b'E', cap),
        14 => {
            // LZMA: 2-byte UPX header, then 5 props bytes in UPX's own layout; try the raw stream.
            let mut out = Vec::new();
            if let Some(&props) = src.get(2)
                && let Ok(mut r) = lzma_rust2::LzmaReader::new_with_props(src.get(4..).unwrap_or(&[]), u_len as u64, props, 1 << 24, None)
            {
                let _ = (&mut r).take(cap as u64).read_to_end(&mut out);
            }
            (!out.is_empty()).then_some(out)
        }
        _ => None,
    };
    match out {
        Some(o) if !o.is_empty() => {
            push(b, ex, "unpacked program".into(), o);
        }
        _ => ex.notes.push(Note::Listed { entry: format!("UPX method {method} (not unpacked)") }),
    }
    true
}

#[cfg(test)]
mod inno_tests {
    use super::*;
    use crate::container::{Budget, Expansion, Limits};
    use std::io::Write;

    fn zlib_bytes(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    fn tiny_pe(marker: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes()); // one section
        pe[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes()); // optional header size
        let sec = 0x80 + 24 + 0xE0;
        pe[sec..sec + 5].copy_from_slice(b".text");
        pe[sec + 16..sec + 20].copy_from_slice(&0x200u32.to_le_bytes()); // raw size
        pe[sec + 20..sec + 24].copy_from_slice(&0x200u32.to_le_bytes()); // raw pointer
        pe[0x200..0x200 + marker.len()].copy_from_slice(marker);
        pe
    }

    #[test]
    fn unpacks_header_and_file_chunks() {
        // A loader stub, the setup ID and a stored header block, then a zlib file chunk holding a program.
        let mut d = b"MZ fake loader".to_vec();
        d.resize(0x1000, 0);
        let mut id = b"Inno Setup Setup Data (6.2.0)".to_vec();
        id.resize(64, 0);
        d.extend_from_slice(&id);
        let header = b"[Run] powershell -enc AAAA".to_vec();
        let stored = 4 + header.len(); // one piece: CRC + data
        d.extend_from_slice(&0u32.to_le_bytes()); // block CRC
        d.extend_from_slice(&(stored as u32).to_le_bytes());
        d.push(0); // not compressed
        d.extend_from_slice(&0u32.to_le_bytes()); // piece CRC
        d.extend_from_slice(&header);
        d.extend_from_slice(b"padding");
        let payload = [b"readme text ".to_vec(), tiny_pe(b"INNER-PROGRAM-MARKER"), b" trailing".to_vec()].concat();
        d.extend_from_slice(b"zlb\x1a");
        d.extend_from_slice(&zlib_bytes(&payload));

        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        assert!(inno(&d, &mut b, &mut ex));
        let names: Vec<&str> = ex.children.iter().map(|c| c.name.as_str()).collect();
        assert!(names.contains(&"inno setup header 1"), "{names:?}");
        assert_eq!(ex.children.iter().find(|c| c.name == "inno setup header 1").unwrap().data, header);
        let prog = ex.children.iter().find(|c| c.name == "inno program 1.exe").expect("carved program");
        assert!(prog.data.starts_with(b"MZ") && prog.data.windows(20).any(|w| w == b"INNER-PROGRAM-MARKER"));
        assert!(names.contains(&"inno files 1"));
    }

    #[test]
    fn garbage_is_listed_not_unpacked() {
        let d = b"MZ.... InnoSetupLdrWindow ....".to_vec();
        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        assert!(inno(&d, &mut b, &mut ex));
        assert!(ex.children.is_empty());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::container::Limits;

    /// A minimal NRV2B encoder (literals and matches), only for testing the decoder.
    struct Enc {
        out: Vec<u8>,
        word: u32,
        nbits: u32,
        word_at: usize,
    }
    impl Enc {
        fn new() -> Self {
            Enc { out: Vec::new(), word: 0, nbits: 0, word_at: usize::MAX }
        }
        fn bit(&mut self, b: u32) {
            if self.nbits == 0 {
                self.word_at = self.out.len();
                self.out.extend([0; 4]);
                self.word = 0;
            }
            self.word = (self.word << 1) | b;
            self.nbits += 1;
            if self.nbits == 32 {
                self.out[self.word_at..self.word_at + 4].copy_from_slice(&self.word.to_le_bytes());
                self.nbits = 0;
            }
        }
        fn gamma(&mut self, v: u32) {
            // v >= 2, written as NRV2B's interleaved gamma code
            let bits = 32 - v.leading_zeros();
            for i in (0..bits - 1).rev() {
                self.bit((v >> i) & 1);
                self.bit(if i == 0 { 1 } else { 0 });
            }
        }
        fn finish(mut self) -> Vec<u8> {
            if self.nbits > 0 {
                let w = self.word << (32 - self.nbits);
                self.out[self.word_at..self.word_at + 4].copy_from_slice(&w.to_le_bytes());
            }
            self.out
        }
    }

    fn nrv2b_encode(data: &[u8]) -> Vec<u8> {
        let mut e = Enc::new();
        let mut i = 0;
        while i < data.len() {
            // Look back for a match of at least 3 bytes.
            let mut best = (0usize, 0usize);
            for off in 1..=i.min(0xc00) {
                let mut l = 0;
                while i + l < data.len() && data[i + l - off..].first() == data.get(i + l) && l < 200 {
                    l += 1;
                }
                if l > best.1 {
                    best = (off, l);
                }
            }
            if best.1 >= 3 {
                let (off, len) = best;
                e.bit(0);
                let o = off - 1;
                e.gamma((o >> 8) as u32 + 3);
                e.out.push((o & 0xff) as u8);
                let ml = len - 1 - if off > 0xd00 { 1 } else { 0 };
                if ml >= 4 {
                    e.bit(0);
                    e.bit(0);
                    e.gamma(ml as u32 - 2);
                } else {
                    e.bit(((ml >> 1) & 1) as u32);
                    e.bit((ml & 1) as u32);
                }
                i += len;
            } else {
                e.bit(1);
                e.out.push(data[i]);
                i += 1;
            }
        }
        // end marker: offset 0xFFFFFFFF
        e.bit(0);
        e.gamma(0x0100_0002);
        e.out.push(0xff);
        e.finish()
    }

    #[test]
    fn nrv2b_round_trip() {
        let text = b"Hexward unpacks UPX. Hexward unpacks UPX again and again and again, so rules see the real program.".repeat(4);
        let packed = nrv2b_encode(&text);
        assert!(packed.len() < text.len());
        assert_eq!(nrv(&packed, b'B', 1 << 20).as_deref(), Some(&text[..]));
        // Corrupt data fails cleanly.
        assert!(nrv(&packed[..packed.len() / 2], b'B', 1 << 20).is_none());
    }

    fn pe_with_overlay(overlay: &[u8]) -> Vec<u8> {
        let mut pe = vec![0u8; 0x400];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        let s = 0x80 + 24 + 0xE0;
        pe[s..s + 5].copy_from_slice(b".text");
        pe[s + 16..s + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe[s + 20..s + 24].copy_from_slice(&0x200u32.to_le_bytes());
        pe.extend(overlay);
        pe
    }

    #[test]
    fn nsis_non_solid_and_solid() {
        let deflate = |d: &[u8]| {
            let mut e = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
            std::io::Write::write_all(&mut e, d).unwrap();
            e.finish().unwrap()
        };
        // Non-solid: each block [u32 size | 0x80000000][deflate data].
        let mut blocks = Vec::new();
        for f in [&b"installer script with strings"[..], b"MZ the installed program"] {
            let c = deflate(f);
            blocks.extend(((c.len() as u32) | 0x8000_0000).to_le_bytes());
            blocks.extend(c);
        }
        let mut fh = Vec::new();
        fh.extend(0u32.to_le_bytes());
        fh.extend(NSIS_MAGIC);
        fh.extend(100u32.to_le_bytes());
        fh.extend(((28 + blocks.len()) as u32).to_le_bytes());
        fh.extend(&blocks);
        let exe = pe_with_overlay(&fh);
        assert_eq!(kind(&exe), Some("NSIS installer"));
        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        nsis(&exe, &mut b, &mut ex);
        assert_eq!(ex.children.len(), 2);
        assert_eq!(ex.children[1].data, b"MZ the installed program");
    }

    #[test]
    fn pyinstaller_entries() {
        let script = b"print('hi from the bundled script')";
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut z, script).unwrap();
        let comp = z.finish().unwrap();
        let mut pkg = comp.clone();
        let toc_off = pkg.len();
        let name = b"main\0\0";
        let mut entry = Vec::new();
        entry.extend(((18 + name.len()) as u32).to_be_bytes());
        entry.extend(0u32.to_be_bytes());
        entry.extend((comp.len() as u32).to_be_bytes());
        entry.extend((script.len() as u32).to_be_bytes());
        entry.push(1);
        entry.push(b's');
        entry.extend(name);
        pkg.extend(&entry);
        let mut cookie = b"MEI\x0C\x0B\x0A\x0B\x0E".to_vec();
        let pkg_len = pkg.len() + 88;
        cookie.extend((pkg_len as u32).to_be_bytes());
        cookie.extend((toc_off as u32).to_be_bytes());
        cookie.extend((entry.len() as u32).to_be_bytes());
        cookie.extend(312u32.to_be_bytes());
        let mut lib = b"python312.dll".to_vec();
        lib.resize(64, 0);
        cookie.extend(lib);
        pkg.extend(cookie);
        let exe = pe_with_overlay(&pkg);
        assert_eq!(kind(&exe), Some("PyInstaller program"));
        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        assert!(pyinstaller(&exe, &mut b, &mut ex));
        assert_eq!(ex.children[0].name, "main.py (main script)");
        assert_eq!(ex.children[0].data, script);
    }

    #[test]
    fn real_installers_on_this_pc_unpack_without_error() {
        // Whatever NSIS/PyInstaller/UPX programs this PC happens to have: no panics, sane output.
        for dir in [r"C:\Program Files", r"C:\Program Files (x86)"] {
            for e in walkdir::WalkDir::new(dir).max_depth(3).into_iter().flatten().filter(|e| e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("exe"))).take(400) {
                let Ok(meta) = e.metadata() else { continue };
                if meta.len() > 64 * 1024 * 1024 {
                    continue;
                }
                let Ok(d) = std::fs::read(e.path()) else { continue };
                if let Some(k) = kind(&d) {
                    let mut b = Budget::new(Limits::default());
                    let mut ex = Expansion::default();
                    unpack(&d, k, &mut b, &mut ex);
                }
            }
        }
    }
}
