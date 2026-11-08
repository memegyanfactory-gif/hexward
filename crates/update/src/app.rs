//! App self-update from GitHub Releases, with Ed25519 signatures.
//!
//! The release pipeline signs each binary with a private key that only GitHub Actions holds.
//! The app accepts an update only if the signature checks out against the public key compiled
//! in below. The signed message binds the file name, the version and the file's SHA-256, so an
//! attacker can't swap in a tampered file or relabel an older signed build as a newer one.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// GitHub repository that publishes releases.
pub const REPO: &str = "memegyanfactory-gif/hexward";
/// Release asset name of the desktop app.
pub const APP_ASSET: &str = "hexward-app.exe";
/// Ed25519 public key that release signatures must match (hex). Its private half lives only in
/// the HEXWARD_SIGNING_KEY secret of the GitHub repository.
pub const PUBLIC_KEY_HEX: &str = "3002353eaa77a15dff2beeac6db21debfd9130f305a6f6237c0d86899c8ce3a7";

#[derive(Debug, Clone, Serialize)]
pub struct AppRelease {
    pub version: String,
    pub notes: String,
    pub page: String,
    exe_url: String,
    sig_url: String,
    pub size: u64,
}

/// "v1.2.3" or "1.2.3" → (1, 2, 3). Pre-release suffixes are ignored.
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches('v');
    let core = s.split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next().flatten().unwrap_or(0), it.next().flatten().unwrap_or(0)))
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    matches!((parse_version(candidate), parse_version(current)), (Some(a), Some(b)) if a > b)
}

/// The exact bytes that get signed.
pub fn signed_message(name: &str, version: &str, data: &[u8]) -> Vec<u8> {
    let version = version.trim().trim_start_matches('v');
    format!("hexward-release-v1|{name}|{version}|{}", hex::encode(Sha256::digest(data))).into_bytes()
}

/// Signs a release file. `secret_hex` is the 32-byte Ed25519 secret key in hex.
pub fn sign(name: &str, version: &str, data: &[u8], secret_hex: &str) -> Result<String> {
    let mut secret = [0u8; 32];
    hex::decode_to_slice(secret_hex.trim(), &mut secret).context("the signing key isn't 64 hex characters")?;
    let key = SigningKey::from_bytes(&secret);
    Ok(hex::encode(key.sign(&signed_message(name, version, data)).to_bytes()))
}

/// Checks a release file against a public key. Errors say what was wrong, never "probably fine".
pub fn verify(name: &str, version: &str, data: &[u8], sig_hex: &str, public_hex: &str) -> Result<()> {
    let mut pk = [0u8; 32];
    hex::decode_to_slice(public_hex.trim(), &mut pk).map_err(|_| anyhow!("this build has no valid update key"))?;
    let key = VerifyingKey::from_bytes(&pk).map_err(|_| anyhow!("this build has no valid update key"))?;
    let mut sig = [0u8; 64];
    hex::decode_to_slice(sig_hex.trim(), &mut sig).map_err(|_| anyhow!("the update's signature file is damaged"))?;
    key.verify_strict(&signed_message(name, version, data), &Signature::from_bytes(&sig))
        .map_err(|_| anyhow!("the update's signature doesn't match. It was not installed"))
}

/// New key pair: (secret hex, public hex).
pub fn keygen() -> Result<(String, String)> {
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).map_err(|e| anyhow!("no secure randomness: {e}"))?;
    let key = SigningKey::from_bytes(&secret);
    Ok((hex::encode(secret), hex::encode(key.verifying_key().to_bytes())))
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(300)))
        .user_agent(concat!("hexward-app/", env!("CARGO_PKG_VERSION")))
        .build()
        .into()
}

/// Asks GitHub for the latest release. `Ok(None)` when there is nothing newer than `current`.
pub fn check(current: &str) -> Result<Option<AppRelease>> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let mut resp = match agent().get(&url).header("Accept", "application/vnd.github+json").call() {
        Ok(r) => r,
        Err(ureq::Error::StatusCode(404)) => return Ok(None), // no releases yet
        Err(ureq::Error::StatusCode(403 | 429)) => bail!("GitHub is rate-limiting update checks. Hexward will try again later"),
        Err(e) => bail!("couldn't reach GitHub ({})", e.to_string().split(':').next().unwrap_or("network error")),
    };
    let body = resp.body_mut().with_config().limit(2 * 1024 * 1024).read_to_string()?;
    let v: serde_json::Value = serde_json::from_str(&body).context("GitHub sent an unexpected answer")?;
    let tag = v["tag_name"].as_str().unwrap_or_default();
    if !is_newer(tag, current) {
        return Ok(None);
    }
    let assets = v["assets"].as_array().cloned().unwrap_or_default();
    let find = |name: &str| assets.iter().find(|a| a["name"].as_str() == Some(name));
    let exe = find(APP_ASSET).ok_or_else(|| anyhow!("release {tag} has no {APP_ASSET}"))?;
    let sig = find(&format!("{APP_ASSET}.sig")).ok_or_else(|| anyhow!("release {tag} isn't signed, so Hexward won't install it"))?;
    Ok(Some(AppRelease {
        version: tag.trim_start_matches('v').to_string(),
        notes: v["body"].as_str().unwrap_or_default().trim().to_string(),
        page: v["html_url"].as_str().unwrap_or_default().to_string(),
        exe_url: exe["browser_download_url"].as_str().unwrap_or_default().to_string(),
        sig_url: sig["browser_download_url"].as_str().unwrap_or_default().to_string(),
        size: exe["size"].as_u64().unwrap_or(0),
    }))
}

/// Downloads one signed file (e.g. `hexward_amsi.dll`) from the latest release and checks its
/// signature. Returns (release version, bytes).
pub fn download_latest_asset(name: &str) -> Result<(String, Vec<u8>)> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let mut resp = agent().get(&url).header("Accept", "application/vnd.github+json").call().map_err(|e| anyhow!("couldn't reach GitHub ({})", e.to_string().split(':').next().unwrap_or("network error")))?;
    let body = resp.body_mut().with_config().limit(2 * 1024 * 1024).read_to_string()?;
    let v: serde_json::Value = serde_json::from_str(&body).context("GitHub sent an unexpected answer")?;
    let version = v["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_string();
    let assets = v["assets"].as_array().cloned().unwrap_or_default();
    let link = |n: &str| assets.iter().find(|a| a["name"].as_str() == Some(n)).and_then(|a| a["browser_download_url"].as_str().map(String::from));
    let file_url = link(name).ok_or_else(|| anyhow!("the latest release has no {name}"))?;
    let sig_url = link(&format!("{name}.sig")).ok_or_else(|| anyhow!("{name} in the latest release isn't signed"))?;
    let a = agent();
    let fetch = |url: &str, limit: u64| -> Result<Vec<u8>> {
        if !url.starts_with("https://github.com/") {
            bail!("the download link doesn't point to GitHub");
        }
        let mut r = a.get(url).call().map_err(|e| anyhow!("download failed ({})", e.to_string().split(':').next().unwrap_or("error")))?;
        let mut out = Vec::new();
        r.body_mut().as_reader().take(limit).read_to_end(&mut out)?;
        Ok(out)
    };
    let data = fetch(&file_url, 64 * 1024 * 1024)?;
    let sig = String::from_utf8(fetch(&sig_url, 4096)?).map_err(|_| anyhow!("the signature file is damaged"))?;
    verify(name, &version, &data, &sig, PUBLIC_KEY_HEX)?;
    Ok((version, data))
}

/// Downloads the new app and checks its signature. Nothing touches the disk before that passes.
pub fn download_verified(rel: &AppRelease) -> Result<Vec<u8>> {
    let a = agent();
    let fetch = |url: &str, limit: u64| -> Result<Vec<u8>> {
        if !url.starts_with("https://github.com/") && !url.starts_with("https://objects.githubusercontent.com/") {
            bail!("the download link doesn't point to GitHub");
        }
        let mut resp = a.get(url).call().map_err(|e| anyhow!("download failed ({})", e.to_string().split(':').next().unwrap_or("error")))?;
        let mut out = Vec::new();
        resp.body_mut().as_reader().take(limit).read_to_end(&mut out)?;
        Ok(out)
    };
    let exe = fetch(&rel.exe_url, 300 * 1024 * 1024)?;
    let sig = String::from_utf8(fetch(&rel.sig_url, 4096)?).map_err(|_| anyhow!("the update's signature file is damaged"))?;
    verify(APP_ASSET, &rel.version, &exe, &sig, PUBLIC_KEY_HEX)?;
    if !exe.starts_with(b"MZ") {
        bail!("the download isn't a Windows program");
    }
    Ok(exe)
}

/// Swaps the program file for `new`. Windows lets a running .exe be renamed, not overwritten,
/// so the old one moves aside to `.old` (deleted on the next start). Rolls back on failure.
pub fn replace_exe(current: &Path, new: &[u8]) -> Result<PathBuf> {
    let staged = current.with_extension("exe.new");
    let old = current.with_extension("exe.old");
    std::fs::write(&staged, new).map_err(|e| permission(e, current))?;
    let _ = std::fs::remove_file(&old);
    if let Err(e) = std::fs::rename(current, &old) {
        let _ = std::fs::remove_file(&staged);
        return Err(permission(e, current));
    }
    if let Err(e) = std::fs::rename(&staged, current) {
        let _ = std::fs::rename(&old, current);
        let _ = std::fs::remove_file(&staged);
        return Err(permission(e, current));
    }
    Ok(old)
}

fn permission(e: std::io::Error, path: &Path) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        anyhow!("Windows won't let Hexward replace {}. Run Hexward as administrator to update", path.display())
    } else {
        anyhow!("couldn't install the update: {e}")
    }
}

/// Removes the previous version left by `replace_exe`. Safe to call on every start.
pub fn cleanup_old(current: &Path) {
    let _ = std::fs::remove_file(current.with_extension("exe.old"));
    let _ = std::fs::remove_file(current.with_extension("exe.new"));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("0.2"), Some((0, 2, 0)));
        assert_eq!(parse_version("1.0.0-beta.1"), Some((1, 0, 0)));
        assert!(is_newer("v0.2.0", "0.1.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("v0.1.0", "0.1.0"));
        assert!(!is_newer("v0.0.9", "0.1.0"));
        assert!(!is_newer("garbage", "0.1.0"));
    }

    #[test]
    fn signatures_bind_file_name_version_and_bytes() {
        let (secret, public) = keygen().unwrap();
        let data = b"MZ pretend program";
        let sig = sign(APP_ASSET, "0.2.0", data, &secret).unwrap();
        verify(APP_ASSET, "v0.2.0", data, &sig, &public).unwrap();
        assert!(verify(APP_ASSET, "0.2.0", b"MZ tampered program", &sig, &public).is_err(), "changed bytes");
        assert!(verify(APP_ASSET, "0.3.0", data, &sig, &public).is_err(), "relabelled version");
        assert!(verify("hexward.exe", "0.2.0", data, &sig, &public).is_err(), "other file");
        let (_, other_public) = keygen().unwrap();
        assert!(verify(APP_ASSET, "0.2.0", data, &sig, &other_public).is_err(), "other key");
        assert!(verify(APP_ASSET, "0.2.0", data, "zz", &public).is_err(), "garbage signature");
    }

    #[test]
    fn replace_and_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hexward-app.exe");
        std::fs::write(&exe, b"MZ old").unwrap();
        let old = replace_exe(&exe, b"MZ new").unwrap();
        assert_eq!(std::fs::read(&exe).unwrap(), b"MZ new");
        assert_eq!(std::fs::read(&old).unwrap(), b"MZ old");
        cleanup_old(&exe);
        assert!(!old.exists());
    }

    #[test]
    fn the_shipped_public_key_is_valid() {
        let mut pk = [0u8; 32];
        hex::decode_to_slice(PUBLIC_KEY_HEX, &mut pk).expect("PUBLIC_KEY_HEX is 64 hex characters");
        VerifyingKey::from_bytes(&pk).expect("PUBLIC_KEY_HEX is a valid Ed25519 key");
    }
}
