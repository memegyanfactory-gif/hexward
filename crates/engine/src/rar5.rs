//! Decoder for RAR 5 compressed data (WinRAR 5 and later, compression versions 5.0 and 7.0).
//!
//! Written for Hexward from the published description of the format (the RAR 5 technote and the
//! BSD-licensed libarchive reader); no unRAR code is used, because unRAR's licence forbids
//! re-creating the compressor and isn't GPL-compatible. Decompression only.
//!
//! The format: the data is a series of blocks, each with a small header and, when it changes, a
//! set of Huffman tables. Symbols are literals, matches (length + distance, with four recent
//! distances remembered), a "repeat the last match" code, and filters that undo the x86 call
//! (E8/E9), ARM branch and delta transforms after the data is decoded.
//!
//! Hexward decodes whole files into memory, capped by the scan budget, so the dictionary is simply
//! the output so far. Solid archives keep the output and tables from one file to the next.

const NC: usize = 306;
const DC_50: usize = 64;
const DC_70: usize = 80;
const LDC: usize = 16;
const RC: usize = 44;
const BC: usize = 20;
const MAX_FILTER_BLOCK: usize = 0x40_0000;

/// MSB-first bit reader. Reading past the end gives zeros; callers stop at the block end.
struct Bits<'a> {
    d: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn byte(&self, i: usize) -> u64 {
        *self.d.get(i).unwrap_or(&0) as u64
    }
    /// The next 32 bits, without consuming them.
    fn peek32(&self) -> u32 {
        let b = self.pos / 8;
        let v = (self.byte(b) << 32) | (self.byte(b + 1) << 24) | (self.byte(b + 2) << 16) | (self.byte(b + 3) << 8) | self.byte(b + 4);
        ((v >> (8 - (self.pos & 7))) & 0xffff_ffff) as u32
    }
    fn peek16(&self) -> u32 {
        self.peek32() >> 16
    }
    fn skip(&mut self, n: usize) {
        self.pos += n;
    }
    /// Reads `n` bits (1..=16).
    fn get(&mut self, n: usize) -> u32 {
        let v = self.peek16() >> (16 - n);
        self.skip(n);
        v
    }
    fn align(&mut self) {
        self.pos = (self.pos + 7) & !7;
    }
}

/// A canonical Huffman decoder, as RAR builds it (lengths up to 15).
#[derive(Clone, Default)]
struct Huff {
    decode_len: [u32; 16],
    decode_pos: [u32; 16],
    num: Vec<u16>,
}

impl Huff {
    fn new(lengths: &[u8]) -> Huff {
        let mut count = [0u32; 16];
        for &l in lengths {
            count[(l & 15) as usize] += 1;
        }
        count[0] = 0;
        let mut h = Huff { decode_len: [0; 16], decode_pos: [0; 16], num: vec![0; lengths.len()] };
        let mut upper = 0u32;
        for i in 1..16 {
            upper += count[i];
            h.decode_len[i] = upper << (16 - i);
            upper *= 2;
            h.decode_pos[i] = h.decode_pos[i - 1] + count[i - 1];
        }
        let mut next = h.decode_pos;
        for (sym, &l) in lengths.iter().enumerate() {
            let l = (l & 15) as usize;
            if l != 0 {
                if let Some(slot) = h.num.get_mut(next[l] as usize) {
                    *slot = sym as u16;
                }
                next[l] += 1;
            }
        }
        h
    }

    fn decode(&self, inp: &mut Bits) -> usize {
        let field = inp.peek16() & 0xfffe;
        let mut bits = 15;
        for i in 1..15 {
            if field < self.decode_len[i] {
                bits = i;
                break;
            }
        }
        inp.skip(bits);
        let dist = (field.wrapping_sub(self.decode_len[bits - 1])) >> (16 - bits);
        let pos = self.decode_pos[bits].wrapping_add(dist) as usize;
        *self.num.get(pos).unwrap_or(&0) as usize
    }
}

#[derive(Clone)]
struct Tables {
    ld: Huff,
    dd: Huff,
    ldd: Huff,
    rd: Huff,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FilterKind {
    Delta(usize),
    E8,
    E8E9,
    Arm,
}

#[derive(Clone, Copy, Debug)]
struct Filter {
    /// Where it starts in the decoded output (absolute).
    start: usize,
    len: usize,
    kind: FilterKind,
}

struct BlockHeader {
    end_bit: usize,
    last: bool,
    tables: bool,
}

/// Decoder state that carries over between the files of a solid archive.
#[derive(Default)]
pub struct Unpacker {
    out: Vec<u8>,
    tables: Option<Tables>,
    old: [u64; 4],
    last_len: usize,
}

impl Unpacker {
    pub fn new() -> Self {
        Unpacker::default()
    }

    /// Decodes one file's packed data. `version` is the compression version from the file header
    /// (0 = RAR 5.0, 1 = RAR 7.0); `solid` keeps the dictionary and tables from the previous file.
    /// Returns the file's bytes (possibly cut short at `cap`, or where the data turned out broken),
    /// or None when nothing could be decoded.
    pub fn unpack(&mut self, packed: &[u8], unpacked: usize, version: u8, solid: bool, cap: usize) -> Option<Vec<u8>> {
        if !solid {
            *self = Unpacker::default();
        }
        let dc = if version == 0 { DC_50 } else { DC_70 };
        let start = self.out.len();
        let target = start + unpacked.min(cap);
        let mut filters: Vec<Filter> = Vec::new();
        let mut inp = Bits { d: packed, pos: 0 };
        let mut block = read_block_header(&mut inp)?;
        if block.tables {
            self.tables = Some(read_tables(&mut inp, dc)?);
        }
        let t = self.tables.clone()?;
        let mut tables = t;
        while self.out.len() < target {
            if inp.pos >= block.end_bit {
                if block.last {
                    break;
                }
                let Some(b) = read_block_header(&mut inp) else { break };
                block = b;
                if block.tables {
                    let Some(nt) = read_tables(&mut inp, dc) else { break };
                    self.tables = Some(nt.clone());
                    tables = nt;
                }
                continue;
            }
            if inp.pos > packed.len() * 8 {
                break; // ran off the end of truncated data
            }
            let sym = tables.ld.decode(&mut inp);
            if sym < 256 {
                self.out.push(sym as u8);
                continue;
            }
            if sym >= 262 {
                let mut len = slot_to_length(&mut inp, sym - 262);
                let dslot = tables.dd.decode(&mut inp) as u64;
                let mut dist: u64 = 1;
                let dbits: u64;
                if dslot < 4 {
                    dbits = 0;
                    dist += dslot;
                } else {
                    dbits = dslot / 2 - 1;
                    dist += (2 | (dslot & 1)) << dbits;
                }
                if dbits > 0 {
                    if dbits >= 4 {
                        if dbits > 4 {
                            if dbits > 36 {
                                break; // beyond anything Hexward would hold in memory
                            }
                            dist += ((inp.peek32() as u64) >> (36 - dbits)) << 4;
                            inp.skip(dbits as usize - 4);
                        }
                        dist += tables.ldd.decode(&mut inp) as u64;
                    } else {
                        dist += (inp.peek32() >> (32 - dbits)) as u64;
                        inp.skip(dbits as usize);
                    }
                }
                if dist > 0x100 {
                    len += 1;
                    if dist > 0x2000 {
                        len += 1;
                        if dist > 0x40000 {
                            len += 1;
                        }
                    }
                }
                self.old = [dist, self.old[0], self.old[1], self.old[2]];
                self.last_len = len;
                if !self.copy(dist, len, target) {
                    break;
                }
                continue;
            }
            if sym == 256 {
                let Some(f) = read_filter(&mut inp, self.out.len()) else { break };
                if filters.len() < 8192 {
                    filters.push(f);
                }
                continue;
            }
            if sym == 257 {
                if self.last_len != 0 && !self.copy(self.old[0], self.last_len, target) {
                    break;
                }
                continue;
            }
            // 258..=261: one of the four recent distances, then a length.
            let n = sym - 258;
            let dist = self.old[n];
            for i in (1..=n).rev() {
                self.old[i] = self.old[i - 1];
            }
            self.old[0] = dist;
            let lslot = tables.rd.decode(&mut inp);
            let len = slot_to_length(&mut inp, lslot);
            self.last_len = len;
            if !self.copy(dist, len, target) {
                break;
            }
        }
        if self.out.len() <= start {
            return None;
        }
        let end = self.out.len().min(target);
        let mut file = self.out[start..end].to_vec();
        for f in &filters {
            if f.start < start || f.start >= end {
                continue;
            }
            let (a, b) = (f.start - start, (f.start - start + f.len).min(file.len()));
            apply_filter(&mut file[a..b], f.kind, (f.start - start) as u64);
        }
        // Cut short, or too big to keep as history: the next solid file can't be decoded from here.
        if unpacked > cap || self.out.len() > 512 * 1024 * 1024 {
            *self = Unpacker::default();
        }
        Some(file)
    }

    /// Copies a match. False when the distance points before the start of the data (broken input).
    fn copy(&mut self, dist: u64, len: usize, target: usize) -> bool {
        let n = self.out.len();
        if dist == 0 || dist as usize > n {
            return false;
        }
        let from = n - dist as usize;
        let len = len.min(target.saturating_sub(n).max(1));
        if dist as usize >= len {
            self.out.extend_from_within(from..from + len);
        } else {
            for i in 0..len {
                let b = self.out[from + i];
                self.out.push(b);
            }
        }
        true
    }
}

fn slot_to_length(inp: &mut Bits, slot: usize) -> usize {
    let (lbits, mut len) = if slot < 8 { (0, 2 + slot) } else { let lb = slot / 4 - 1; (lb, 2 + ((4 | (slot & 3)) << lb)) };
    if lbits > 0 {
        len += (inp.peek16() >> (16 - lbits)) as usize;
        inp.skip(lbits);
    }
    len
}

fn read_block_header(inp: &mut Bits) -> Option<BlockHeader> {
    inp.align();
    let flags = inp.get(8) as u8;
    let check = inp.get(8) as u8;
    let count = ((flags >> 3) & 3) as usize + 1;
    if count == 4 {
        return None;
    }
    let mut size = 0usize;
    for i in 0..count {
        size |= (inp.get(8) as usize) << (i * 8);
    }
    let sum = 0x5a ^ flags ^ (size as u8) ^ ((size >> 8) as u8) ^ ((size >> 16) as u8);
    if sum != check || size == 0 {
        return None;
    }
    let start = inp.pos / 8;
    Some(BlockHeader { end_bit: (start + size - 1) * 8 + (flags & 7) as usize + 1, last: flags & 0x40 != 0, tables: flags & 0x80 != 0 })
}

fn read_tables(inp: &mut Bits, dc: usize) -> Option<Tables> {
    let mut bl = [0u8; BC];
    let mut i = 0;
    while i < BC {
        let len = inp.get(4) as u8;
        if len == 15 {
            let zeros = inp.get(4) as usize;
            if zeros == 0 {
                bl[i] = 15;
                i += 1;
            } else {
                for _ in 0..zeros + 2 {
                    if i >= BC {
                        break;
                    }
                    bl[i] = 0;
                    i += 1;
                }
            }
        } else {
            bl[i] = len;
            i += 1;
        }
    }
    let bd = Huff::new(&bl);
    let size = NC + dc + LDC + RC;
    let mut t = vec![0u8; size];
    let mut i = 0;
    while i < size {
        let n = bd.decode(inp);
        if n < 16 {
            t[i] = n as u8;
            i += 1;
        } else if n < 18 {
            let count = if n == 16 { inp.get(3) as usize + 3 } else { inp.get(7) as usize + 11 };
            if i == 0 {
                return None;
            }
            for _ in 0..count {
                if i >= size {
                    break;
                }
                t[i] = t[i - 1];
                i += 1;
            }
        } else {
            let count = if n == 18 { inp.get(3) as usize + 3 } else { inp.get(7) as usize + 11 };
            for _ in 0..count {
                if i >= size {
                    break;
                }
                t[i] = 0;
                i += 1;
            }
        }
    }
    Some(Tables { ld: Huff::new(&t[..NC]), dd: Huff::new(&t[NC..NC + dc]), ldd: Huff::new(&t[NC + dc..NC + dc + LDC]), rd: Huff::new(&t[NC + dc + LDC..]) })
}

fn read_filter_number(inp: &mut Bits) -> usize {
    let bytes = inp.get(2) as usize + 1;
    let mut v = 0usize;
    for i in 0..bytes {
        v |= (inp.get(8) as usize) << (i * 8);
    }
    v
}

fn read_filter(inp: &mut Bits, at: usize) -> Option<Filter> {
    let start = read_filter_number(inp);
    let mut len = read_filter_number(inp);
    if len > MAX_FILTER_BLOCK {
        len = 0;
    }
    let kind = match inp.get(3) {
        0 => FilterKind::Delta(inp.get(5) as usize + 1),
        1 => FilterKind::E8,
        2 => FilterKind::E8E9,
        3 => FilterKind::Arm,
        _ => return None,
    };
    Some(Filter { start: at + start, len, kind })
}

/// Undoes a filter in place. `file_offset` is where the block starts within the file.
fn apply_filter(d: &mut [u8], kind: FilterKind, file_offset: u64) {
    match kind {
        FilterKind::E8 | FilterKind::E8E9 => {
            const FILE_SIZE: u32 = 0x100_0000;
            let second = if kind == FilterKind::E8E9 { 0xE9 } else { 0xE8 };
            let mut i = 0;
            while i + 4 < d.len() {
                let c = d[i];
                i += 1;
                if c == 0xE8 || c == second {
                    let offset = ((i as u64 + file_offset) % FILE_SIZE as u64) as u32;
                    let addr = u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]]);
                    let new = if addr & 0x8000_0000 != 0 {
                        (addr.wrapping_add(offset) & 0x8000_0000 == 0).then(|| addr.wrapping_add(FILE_SIZE))
                    } else {
                        (addr.wrapping_sub(FILE_SIZE) & 0x8000_0000 != 0).then(|| addr.wrapping_sub(offset))
                    };
                    if let Some(n) = new {
                        d[i..i + 4].copy_from_slice(&n.to_le_bytes());
                    }
                    i += 4;
                }
            }
        }
        FilterKind::Arm => {
            let mut i = 0;
            while i + 3 < d.len() {
                if d[i + 3] == 0xEB {
                    let mut off = d[i] as u32 | (d[i + 1] as u32) << 8 | (d[i + 2] as u32) << 16;
                    off = off.wrapping_sub(((file_offset + i as u64) / 4) as u32);
                    d[i] = off as u8;
                    d[i + 1] = (off >> 8) as u8;
                    d[i + 2] = (off >> 16) as u8;
                }
                i += 4;
            }
        }
        FilterKind::Delta(channels) => {
            let src = d.to_vec();
            let mut s = 0;
            for ch in 0..channels {
                let mut prev = 0u8;
                let mut p = ch;
                while p < d.len() {
                    prev = prev.wrapping_sub(*src.get(s).unwrap_or(&0));
                    d[p] = prev;
                    s += 1;
                    p += channels;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::container::{Budget, Expansion, Limits};
    use sha2::{Digest, Sha256};

    // Made with WinRAR 7 (`rar a -ma5 -m5`, and `-s` for solid) from generated content: text, x86-like
    // code (decoded through the E8 filter) and 16-bit stereo samples (the delta filter).
    const EXPECTED: [(&str, &str); 3] = [
        ("notes.txt", "a5b3442bf14ec0f4538388d1dfce60628619766ce56ec2c3cccfefeecd2e39fc"),
        ("prog.exe", "ed89d6e3224d4639631360b95ad25c574b439ede8374bff79fb204dfa7adfdc6"),
        ("tone.wav", "ff2415667b0f029ffc216756fc5b056730e8775254a2a6efeafec325fa3ca942"),
    ];

    fn unpack(d: &[u8]) -> Expansion {
        let mut b = Budget::new(Limits::default());
        let mut ex = Expansion::default();
        crate::formats::rar(d, &mut b, &mut ex);
        ex
    }

    #[test]
    fn decodes_winrar_archives_exactly() {
        for archive in [&include_bytes!("../testdata/rar5-plain.rar")[..], &include_bytes!("../testdata/rar5-solid.rar")[..]] {
            let ex = unpack(archive);
            assert!(ex.notes.is_empty(), "{:?}", ex.notes);
            assert_eq!(ex.children.len(), 3);
            for (name, sha) in EXPECTED {
                let c = ex.children.iter().find(|c| c.name == name).expect(name);
                assert_eq!(hex::encode(Sha256::digest(&c.data)), sha, "{name}");
            }
        }
    }

    #[test]
    fn damaged_archives_never_panic() {
        let orig = include_bytes!("../testdata/rar5-solid.rar");
        let mut x: u64 = 0x2545_F491_4F6C_DD1D;
        for i in 0..300 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let mut d = orig.to_vec();
            if i % 2 == 0 {
                let at = 40 + (x as usize) % (d.len() - 40);
                d[at] ^= (x >> 32) as u8 | 1;
            } else {
                d.truncate(8 + (x as usize) % d.len());
            }
            let _ = unpack(&d);
        }
    }
}
