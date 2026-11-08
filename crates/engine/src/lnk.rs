//! Windows shortcuts (.lnk), parsed per Microsoft's [MS-SHLLINK] spec.
//! Shortcuts that quietly launch built-in tools with download or encoded-command arguments
//! are one of the most common ways malware gets started (often inside ISO or ZIP files).

use crate::detect::{Detection, Severity, Source};

/// What a shortcut runs, as far as the file says.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct LnkInfo {
    pub target: String,
    pub arguments: String,
    pub size: usize,
}

const MAGIC: [u8; 20] = [0x4C, 0, 0, 0, 0x01, 0x14, 0x02, 0, 0, 0, 0, 0, 0xC0, 0, 0, 0, 0, 0, 0, 0x46];

fn u16le(d: &[u8], at: usize) -> Option<usize> {
    d.get(at..at.checked_add(2)?).map(|b| u16::from_le_bytes([b[0], b[1]]) as usize)
}

fn u32le(d: &[u8], at: usize) -> Option<usize> {
    d.get(at..at.checked_add(4)?).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize)
}

/// Parses a shortcut. Every offset is bounds-checked; malformed input returns None.
pub fn parse(d: &[u8]) -> Option<LnkInfo> {
    if !d.starts_with(&MAGIC) {
        return None;
    }
    let flags = u32le(d, 0x14)?;
    let unicode = flags & 0x80 != 0;
    let mut at: usize = 0x4C;
    if flags & 0x01 != 0 {
        at = at.checked_add(2 + u16le(d, at)?)?; // LinkTargetIDList
    }
    let mut target = String::new();
    if flags & 0x02 != 0 {
        let info_size = u32le(d, at)?;
        let header_size = u32le(d, at + 4)?;
        let info_flags = u32le(d, at + 8)?;
        if info_flags & 0x01 != 0 {
            if header_size >= 0x24 {
                target = read_utf16z(d, at.checked_add(u32le(d, at + 0x1C)?)?);
            }
            if target.is_empty() {
                target = read_ansiz(d, at.checked_add(u32le(d, at + 0x10)?)?);
            }
        }
        at = at.checked_add(info_size)?;
    }
    // StringData in fixed order: name, relative path, working dir, arguments, icon.
    let mut strings: [String; 5] = Default::default();
    for (i, bit) in [0x04, 0x08, 0x10, 0x20, 0x40].into_iter().enumerate() {
        if flags & bit == 0 {
            continue;
        }
        let count = u16le(d, at)?;
        at += 2;
        let len = if unicode { count * 2 } else { count };
        let raw = d.get(at..at.checked_add(len)?)?;
        strings[i] = if unicode {
            let units: Vec<u16> = raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(raw).into_owned()
        };
        at += len;
    }
    if target.is_empty() {
        target = strings[1].clone();
    }
    Some(LnkInfo { target, arguments: strings[3].clone(), size: d.len() })
}

fn read_utf16z(d: &[u8], at: usize) -> String {
    let mut units = Vec::new();
    let mut i = at;
    while let Some(u) = u16le(d, i) {
        if u == 0 || units.len() > 1024 {
            break;
        }
        units.push(u as u16);
        i += 2;
    }
    String::from_utf16_lossy(&units)
}

fn read_ansiz(d: &[u8], at: usize) -> String {
    let rest = d.get(at..).unwrap_or(&[]);
    let end = rest.iter().take(1024).position(|&b| b == 0).unwrap_or(rest.len().min(1024));
    String::from_utf8_lossy(&rest[..end]).into_owned()
}

/// Built-in Windows programs attackers launch from shortcuts ("living off the land").
const LOLBINS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe", "regsvr32.exe",
    "certutil.exe", "bitsadmin.exe", "msiexec.exe", "forfiles.exe", "conhost.exe", "curl.exe", "schtasks.exe", "wmic.exe",
];

const BAD_ARGS: &[&str] = &[
    "-enc", "-encodedcommand", "frombase64string", "downloadstring", "downloadfile", "invoke-webrequest", "iwr ", "iex",
    "invoke-expression", "http://", "https://", "hidden", "bypass", "start-bitstransfer", "javascript:", "vbscript:",
    "-urlcache", ".hta", "\\\\", "%temp%", "appdata", "net.webclient", "-nop",
];

pub fn checks(data: &[u8]) -> Vec<Detection> {
    let mut out = Vec::new();
    let Some(info) = parse(data) else { return out };
    let exe = info.target.rsplit(['\\', '/']).next().unwrap_or("").to_ascii_lowercase();
    let args = info.arguments.to_ascii_lowercase();
    let lolbin = LOLBINS.contains(&exe.as_str());
    let hits: Vec<&str> = BAD_ARGS.iter().copied().filter(|t| args.contains(t)).collect();
    let padded = info.arguments.contains(&" ".repeat(64));
    if lolbin && (!hits.is_empty() || padded) {
        out.push(Detection::new(
            "Suspicious/Win.LnkDropper!a",
            if hits.len() >= 2 || padded { Severity::High } else { Severity::Medium },
            Source::Heuristic,
            format!(
                "This shortcut runs {exe} with hidden instructions ({}). Shortcuts like this are a common way to download and start malware.",
                if padded { "arguments padded with spaces to hide them".to_string() } else { hits.join(", ") }
            ),
        ));
    } else if info.size > 256 * 1024 {
        out.push(Detection::new(
            "Suspicious/Win.LnkPayload!a",
            Severity::Medium,
            Source::Heuristic,
            "This shortcut is far larger than a shortcut needs to be, which usually means a hidden file is packed inside it.",
        ));
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds a minimal shortcut with a relative path and arguments (Unicode strings).
    pub fn lnk(target: &str, args: &str) -> Vec<u8> {
        let mut d = MAGIC.to_vec();
        d.resize(0x4C, 0);
        d[0x14..0x18].copy_from_slice(&(0x08u32 | 0x20 | 0x80).to_le_bytes());
        for s in [target, args] {
            let units: Vec<u16> = s.encode_utf16().collect();
            d.extend_from_slice(&(units.len() as u16).to_le_bytes());
            for u in units {
                d.extend_from_slice(&u.to_le_bytes());
            }
        }
        d
    }

    #[test]
    fn parses_and_flags_droppers() {
        let bad = lnk(r"..\..\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "-nop -w hidden -enc SQBFAFgA");
        assert!(parse(&bad).unwrap().target.ends_with("powershell.exe"));
        let d = checks(&bad);
        assert_eq!(d[0].name, "Suspicious/Win.LnkDropper!a");
        assert_eq!(d[0].severity, Severity::High);
        let hidden = lnk(r"C:\Windows\System32\cmd.exe", &format!("{}/c start evil", " ".repeat(200)));
        assert_eq!(checks(&hidden)[0].name, "Suspicious/Win.LnkDropper!a");
    }

    #[test]
    fn normal_shortcuts_are_clean() {
        assert!(checks(&lnk(r"C:\Program Files\Mozilla Firefox\firefox.exe", "")).is_empty());
        assert!(checks(&lnk(r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", "")).is_empty());
        assert!(checks(&lnk(r"C:\Windows\System32\notepad.exe", r"C:\notes.txt")).is_empty());
    }

    #[test]
    fn malformed_lnk_is_ignored() {
        let mut bad = lnk("cmd.exe", "-enc AAAA");
        bad.truncate(0x50);
        assert!(checks(&bad).is_empty());
        assert!(parse(&MAGIC).is_none());
    }

    #[cfg(windows)]
    #[test]
    fn real_start_menu_shortcuts_are_clean() {
        // Every shortcut Windows ships in the Start menu must parse without a false alarm.
        let root = std::path::PathBuf::from(std::env::var("ProgramData").unwrap()).join(r"Microsoft\Windows\Start Menu\Programs");
        let mut parsed = 0;
        for e in walkdir::WalkDir::new(root).into_iter().flatten() {
            if e.path().extension().is_some_and(|x| x.eq_ignore_ascii_case("lnk"))
                && let Ok(d) = std::fs::read(e.path())
            {
                if parse(&d).is_some() {
                    parsed += 1;
                }
                assert!(checks(&d).is_empty(), "false alarm on {}", e.path().display());
            }
        }
        assert!(parsed > 5, "parsed {parsed} real shortcuts");
    }
}
