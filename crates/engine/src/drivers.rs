//! Vulnerable and malicious kernel drivers ("bring your own vulnerable driver", BYOVD).
//! Ransomware crews load an old, signed but exploitable driver to switch off security software
//! from the kernel. Two public lists name those drivers:
//! - LOLDrivers (loldrivers.io): file hashes and Authenticode hashes, vulnerable or malicious
//! - Microsoft's vulnerable driver blocklist (the WDAC policy behind "Vulnerable driver blocklist")
//!
//! `hexward update` turns both into `drivers.json` in the rules folder. A match on a *malicious*
//! driver is a confirmed threat; a *vulnerable* one is reported as suspicious, because legitimate
//! (old) software still ships some of them and deleting a driver can break a PC.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::detect::{Detection, Severity, Source};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverEntry {
    pub name: String,
    pub malicious: bool,
    /// "LOLDrivers" or "Microsoft blocklist".
    pub source: String,
    /// File SHA-256, lowercase hex (may be empty).
    #[serde(default)]
    pub sha256: String,
    /// Authenticode SHA-256 (the PE image hash signatures cover), lowercase hex (may be empty).
    #[serde(default)]
    pub auth256: String,
}

#[derive(Default)]
pub struct DriverDb {
    by_file: HashMap<[u8; 32], usize>,
    by_auth: HashMap<[u8; 32], usize>,
    entries: Vec<DriverEntry>,
}

fn hash32(hex_str: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_str.trim(), &mut out).ok()?;
    Some(out)
}

impl DriverDb {
    pub fn from_entries(entries: Vec<DriverEntry>) -> Self {
        let mut db = DriverDb::default();
        for (i, e) in entries.iter().enumerate() {
            if let Some(h) = hash32(&e.sha256) {
                db.by_file.insert(h, i);
            }
            if let Some(h) = hash32(&e.auth256) {
                db.by_auth.insert(h, i);
            }
        }
        db.entries = entries;
        db
    }

    /// Loads `drivers.json` from the first rules folder that has one.
    pub fn load(dirs: &[std::path::PathBuf]) -> Self {
        for d in dirs {
            if let Ok(b) = std::fs::read(d.join("drivers.json"))
                && let Ok(v) = serde_json::from_slice::<Vec<DriverEntry>>(&b)
            {
                return DriverDb::from_entries(v);
            }
        }
        DriverDb::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Checks a file's bytes (any PE; drivers are what the lists contain).
    pub fn check(&self, data: &[u8], file_sha256: &[u8; 32]) -> Option<Detection> {
        if self.entries.is_empty() || !data.starts_with(b"MZ") {
            return None;
        }
        let i = self.by_file.get(file_sha256).copied().or_else(|| authenticode_sha256(data).and_then(|h| self.by_auth.get(&h).copied()))?;
        let e = &self.entries[i];
        Some(if e.malicious {
            Detection::new(format!("Malware/Win.Driver.{}!drv", clean(&e.name)), Severity::High, Source::Hash, format!("A malicious kernel driver ({}) listed by {}. Drivers run inside Windows itself, below every security tool.", e.name, e.source))
        } else {
            Detection::new(
                format!("Vulnerable/Win.Driver.{}!drv", clean(&e.name)),
                Severity::Medium,
                Source::SuspiciousRule,
                format!("A driver with a known security hole ({}, listed by {}). Attackers load drivers like this to switch off antivirus from the kernel. If an app you use needs it, update that app; otherwise remove it.", e.name, e.source),
            )
        })
    }
}

fn clean(name: &str) -> String {
    let n: String = name.trim_end_matches(".sys").chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(40).collect();
    if n.is_empty() { "Unknown".into() } else { n }
}

/// The Authenticode SHA-256 of a PE file: the whole file except the checksum field, the
/// certificate-table directory entry and the certificate table itself.
pub fn authenticode_sha256(d: &[u8]) -> Option<[u8; 32]> {
    let u16le = |o: usize| d.get(o..o + 2).map(|b| u16::from_le_bytes([b[0], b[1]]));
    let u32le = |o: usize| d.get(o..o + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]));
    let pe = u32le(0x3c)? as usize;
    if d.get(pe..pe + 4)? != b"PE\0\0" {
        return None;
    }
    let opt = pe + 24;
    let dirs = match u16le(opt)? {
        0x10b => opt + 96,
        0x20b => opt + 112,
        _ => return None,
    };
    let checksum = opt + 64;
    let cert_dir = dirs + 4 * 8;
    let cert_off = u32le(cert_dir)? as usize;
    let cert_len = u32le(cert_dir + 4)? as usize;
    if cert_dir + 8 > d.len() {
        return None;
    }
    let end = if cert_off > 0 && cert_off <= d.len() { cert_off } else { d.len() };
    let mut h = Sha256::new();
    h.update(&d[..checksum]);
    h.update(&d[checksum + 4..cert_dir]);
    h.update(d.get(cert_dir + 8..end)?);
    if cert_off > 0 && cert_off.saturating_add(cert_len) < d.len() {
        h.update(&d[cert_off + cert_len..]);
    }
    Some(h.finalize().into())
}

/// Parses LOLDrivers' `drivers.json` API export.
pub fn parse_loldrivers(json: &[u8]) -> Vec<DriverEntry> {
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(json) else { return Vec::new() };
    let mut out = Vec::new();
    for d in v.as_array().into_iter().flatten() {
        let malicious = d.get("Category").and_then(|c| c.as_str()).is_some_and(|c| c.to_ascii_lowercase().contains("malicious"));
        let tag = d.get("Tags").and_then(|t| t.as_array()).and_then(|t| t.first()).and_then(|t| t.as_str()).unwrap_or("driver");
        for s in d.get("KnownVulnerableSamples").and_then(|k| k.as_array()).into_iter().flatten() {
            let sha256 = s.get("SHA256").and_then(|x| x.as_str()).unwrap_or("").to_ascii_lowercase();
            let auth256 = s.pointer("/Authentihash/SHA256").and_then(|x| x.as_str()).unwrap_or("").to_ascii_lowercase();
            if sha256.len() != 64 && auth256.len() != 64 {
                continue;
            }
            let name = s.get("Filename").and_then(|x| x.as_str()).filter(|n| !n.is_empty()).unwrap_or(tag).to_string();
            out.push(DriverEntry { name, malicious, source: "LOLDrivers".into(), sha256, auth256 });
        }
    }
    out
}

/// Parses Microsoft's blocklist policy XML: `<Deny ... FriendlyName="x" Hash="..."/>`
/// (SHA-256 Authenticode hashes are the 64-character ones).
pub fn parse_ms_blocklist(xml: &str) -> Vec<DriverEntry> {
    let mut out = Vec::new();
    for part in xml.split("<Deny ").skip(1) {
        let tag = part.split("/>").next().unwrap_or("");
        let attr = |k: &str| tag.split(&format!("{k}=\"")).nth(1).and_then(|r| r.split('"').next()).unwrap_or("").to_string();
        let hash = attr("Hash").to_ascii_lowercase();
        let friendly = attr("FriendlyName");
        // Whole-image SHA-256 only; "Hash Page" entries are per-page hashes.
        if hash.len() != 64 || friendly.contains(" Page ") {
            continue;
        }
        let name = friendly
            .split(['\\', ' '])
            .find(|w| w.to_ascii_lowercase().ends_with(".sys"))
            .map(String::from)
            .unwrap_or_else(|| friendly.split(['\\', ' ']).next().unwrap_or("driver").to_string());
        out.push(DriverEntry { name, malicious: false, source: "Microsoft blocklist".into(), sha256: String::new(), auth256: hash });
    }
    out
}

/// Kernel drivers set to load (services of type 1 or 2) with their files.
#[cfg(windows)]
pub fn installed_drivers() -> Vec<(String, std::path::PathBuf)> {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    let Ok(services) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services") else { return Vec::new() };
    let mut out = Vec::new();
    for name in services.enum_keys().flatten() {
        let Ok(k) = services.open_subkey(&name) else { continue };
        let kind: u32 = k.get_value("Type").unwrap_or(0);
        if kind != 1 && kind != 2 {
            continue;
        }
        let image: String = k.get_value("ImagePath").unwrap_or_default();
        let path = if image.is_empty() {
            std::path::PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into())).join(r"System32\drivers").join(format!("{name}.sys"))
        } else {
            crate::startup::resolve_target(&image).unwrap_or_default()
        };
        out.push((name, path));
    }
    out
}

#[cfg(not(windows))]
pub fn installed_drivers() -> Vec<(String, std::path::PathBuf)> {
    Vec::new()
}

/// Checks one driver file on disk.
pub fn check_file(db: &DriverDb, path: &Path) -> Option<Detection> {
    let data = std::fs::read(path).ok()?;
    let sha: [u8; 32] = Sha256::digest(&data).into();
    db.check(&data, &sha)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticode_hash_ignores_checksum_and_signature() {
        let k = std::fs::read(r"C:\Windows\System32\notepad.exe").unwrap();
        let a = authenticode_sha256(&k).unwrap();
        // Changing the checksum field doesn't change the Authenticode hash; changing code does.
        let pe = u32::from_le_bytes(k[0x3c..0x40].try_into().unwrap()) as usize;
        let mut c = k.clone();
        c[pe + 24 + 64] ^= 0xFF;
        assert_eq!(authenticode_sha256(&c).unwrap(), a);
        let mut m = k.clone();
        let mid = m.len() / 2;
        m[mid] ^= 0xFF;
        assert_ne!(authenticode_sha256(&m).unwrap(), a);
    }

    #[test]
    fn parses_lists_and_matches() {
        let note = std::fs::read(r"C:\Windows\System32\notepad.exe").unwrap();
        let auth = hex::encode(authenticode_sha256(&note).unwrap());
        let lol = format!(r#"[{{"Category":"vulnerable driver","Tags":["RTCore64.sys"],"KnownVulnerableSamples":[{{"Filename":"RTCore64.sys","SHA256":"{}","Authentihash":{{"SHA256":""}}}}]}},{{"Category":"malicious","Tags":["evil.sys"],"KnownVulnerableSamples":[{{"Filename":"evil.sys","SHA256":"","Authentihash":{{"SHA256":"{auth}"}}}}]}}]"#, "ab".repeat(32));
        let entries = parse_loldrivers(lol.as_bytes());
        assert_eq!(entries.len(), 2);
        let ms = r#"<SiPolicy><FileRules><Deny ID="ID_DENY_P" FriendlyName="RTCore64.sys Hash Page Sha256" Hash="EE00000000000000000000000000000000000000000000000000000000000000"/><Deny ID="ID_DENY_X" FriendlyName="\RTCore64.sys Hash Sha256" Hash="CD00000000000000000000000000000000000000000000000000000000000000"/><Deny ID="ID_DENY_Y" FriendlyName="x Hash Sha1" Hash="0000000000000000000000000000000000000000"/></FileRules></SiPolicy>"#;
        let msl = parse_ms_blocklist(ms);
        assert_eq!(msl.len(), 1);
        assert_eq!(msl[0].name, "RTCore64.sys");
        let db = DriverDb::from_entries(entries.into_iter().chain(msl).collect());
        let sha: [u8; 32] = Sha256::digest(&note).into();
        let d = db.check(&note, &sha).unwrap();
        assert_eq!(d.source, Source::Hash, "malicious entry matched by Authenticode hash");
        assert!(db.check(b"MZ other", &[0u8; 32]).is_none());
    }

    #[test]
    fn lists_installed_drivers() {
        assert!(installed_drivers().len() > 20);
    }
}
