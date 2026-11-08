//! Script shield: Hexward's AMSI provider (crates/amsi) hands every script PowerShell, Windows
//! Script Host and Office are about to run to this app over a named pipe. This file is the app's
//! side: the pipe server that judges scripts, and switching the provider on and off (which needs
//! administrator approval once, because AMSI providers are registered machine-wide).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use hexward_engine::Engine;

use crate::shields::ShieldEvent;

pub const DLL: &str = "hexward_amsi.dll";
const CLSID: &str = "{3F8E2B91-6C47-4D2A-B5E8-9A1C7D4F2E63}";
const PIPE: &str = r"\\.\pipe\hexward-amsi";

/// Where the provider lives once installed: under Program Files, so a normal user (or malware
/// running as one) can't replace a DLL that elevated PowerShell will load.
fn install_dir() -> PathBuf {
    PathBuf::from(std::env::var_os("ProgramFiles").unwrap_or_else(|| r"C:\Program Files".into())).join("Hexward")
}

/// Is the provider registered with Windows?
#[cfg(windows)]
pub fn is_registered() -> bool {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;
    RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(format!(r"SOFTWARE\Microsoft\AMSI\Providers\{CLSID}")).is_ok()
}

#[cfg(not(windows))]
pub fn is_registered() -> bool {
    false
}

/// Finds the provider DLL: next to this program, or the signed copy from the latest release.
fn find_dll() -> Result<PathBuf, String> {
    if let Some(local) = std::env::current_exe().ok().and_then(|e| e.parent().map(|d| d.join(DLL))).filter(|p| p.is_file()) {
        return Ok(local);
    }
    let (_, bytes) = hexward_update::app::download_latest_asset(DLL).map_err(|e| format!("{e:#}"))?;
    let tmp = std::env::temp_dir().join(format!("hexward-amsi-{}.dll", std::process::id()));
    std::fs::write(&tmp, bytes).map_err(|e| e.to_string())?;
    Ok(tmp)
}

/// Turns the script shield on or off. Shows Windows' administrator prompt.
pub fn set_enabled(on: bool) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.to_string_lossy().into_owned();
    let code = if on {
        let dll = find_dll()?;
        hexward_engine::startup::run_elevated(&exe, &["--amsi-install", &dll.to_string_lossy()])
    } else {
        hexward_engine::startup::run_elevated(&exe, &["--amsi-uninstall"])
    };
    match code {
        Some(0) => Ok(()),
        None => Err("Windows needs administrator approval for this, and it wasn't given.".into()),
        Some(c) => Err(format!("Windows couldn't register the script shield (code {c}).")),
    }
}

/// `hexward-app --amsi-install <dll>` / `--amsi-uninstall`, run elevated. Returns the exit code.
pub fn helper(args: &[String]) -> Option<i32> {
    let regsvr = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| r"C:\Windows".into()).join(r"System32\regsvr32.exe");
    match args.get(1).map(String::as_str) {
        Some("--amsi-install") => {
            let src = PathBuf::from(args.get(2)?);
            let dir = install_dir();
            let dest = dir.join(DLL);
            let ok = std::fs::create_dir_all(&dir).is_ok()
                // A provider in use can't be overwritten: move it aside first.
                && (!dest.exists() || std::fs::rename(&dest, dir.join(format!("{DLL}.old-{}", std::process::id()))).is_ok() || std::fs::remove_file(&dest).is_ok())
                && std::fs::copy(&src, &dest).is_ok();
            if !ok {
                return Some(2);
            }
            let status = std::process::Command::new(&regsvr).args(["/s"]).arg(&dest).status();
            Some(if status.is_ok_and(|s| s.success()) { 0 } else { 3 })
        }
        Some("--amsi-uninstall") => {
            let dest = install_dir().join(DLL);
            let _ = std::process::Command::new(&regsvr).args(["/u", "/s"]).arg(&dest).status();
            // Still loaded by running PowerShell windows? Then it goes on the next restart.
            if std::fs::remove_file(&dest).is_err() {
                let _ = std::fs::rename(&dest, install_dir().join(format!("{DLL}.removed")));
            }
            Some(0)
        }
        _ => None,
    }
}

fn decode(b: &[u8]) -> Option<(String, &[u8])> {
    if b.get(..4)? != b"HXA1" {
        return None;
    }
    let al = u32::from_le_bytes(b.get(4..8)?.try_into().ok()?) as usize;
    let app = String::from_utf8_lossy(b.get(8..8 + al)?).into_owned();
    let o = 8 + al;
    let cl = u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?) as usize;
    Some((app, b.get(o + 4..o + 4 + cl)?))
}

/// The verdict for one script: Some(reason) to block it.
pub fn judge(engine: &Engine, app: &str, content: &[u8]) -> Option<String> {
    let lower = app.to_ascii_lowercase();
    // PowerShell and WSH hand over UTF-16.
    let text: Vec<u8> = if content.len() >= 4 && content[1] == 0 && content[3] == 0 {
        let units: Vec<u16> = content.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&units).into_bytes()
    } else {
        content.to_vec()
    };
    let ext = if lower.contains("powershell") {
        "ps1"
    } else if lower.contains("jscript") {
        "js"
    } else if lower.contains("vbscript") {
        "vbs"
    } else if lower.contains("vba") || lower.contains("office") {
        "vba"
    } else {
        "txt"
    };
    let mut scanner = engine.rules().scanner();
    let (_, dets) = engine.scan_bytes(&mut scanner, std::path::Path::new(&format!("amsi-script.{ext}")), &text);
    // WSH scripts don't carry the WScript object in the text AMSI sees for each statement,
    // so the script checks also look at it as PowerShell-style text.
    if let Some(d) = dets.iter().find(|d| d.is_confirmed()) {
        return Some(format!("{}: {}", d.name, d.description));
    }
    // Hidden download-and-run (encoded, split, character codes) is never a normal script.
    if let Some(d) = dets.iter().find(|d| d.name.starts_with("Suspicious/Script.DownloadExec") && d.description.contains("hidden with")) {
        return Some(d.description.clone());
    }
    let s = String::from_utf8_lossy(&text);
    if let Some(v) = hexward_engine::behavior::clickfix_score(&s)
        && v.level == hexward_engine::behavior::ClickFixLevel::Block
    {
        return Some(format!("A ClickFix-style command ({})", v.reasons.join(", ")));
    }
    None
}

/// The pipe server. Runs for the app's lifetime; answers "clean" while the shield is off.
#[cfg(windows)]
pub fn serve(engine: Arc<RwLock<Option<Arc<Engine>>>>, on: Arc<AtomicBool>, events: Arc<Mutex<Vec<ShieldEvent>>>) {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_PIPE_CONNECTED, GetLastError, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Storage::FileSystem::{FlushFileBuffers, PIPE_ACCESS_DUPLEX, ReadFile, WriteFile};
    use windows_sys::Win32::System::Pipes::{ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT};
    let name: Vec<u16> = PIPE.encode_utf16().chain(std::iter::once(0)).collect();
    loop {
        // SAFETY: each pipe instance is created, served on its own thread, and closed there.
        let h = unsafe { CreateNamedPipeW(name.as_ptr(), PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES, 64 * 1024, 64 * 1024, 0, std::ptr::null()) };
        if h == INVALID_HANDLE_VALUE {
            std::thread::sleep(std::time::Duration::from_secs(5));
            continue;
        }
        // SAFETY: `h` is a valid pipe handle.
        let connected = unsafe { ConnectNamedPipe(h, std::ptr::null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED };
        if !connected {
            unsafe { CloseHandle(h) };
            continue;
        }
        let (engine, on, events) = (engine.clone(), on.clone(), events.clone());
        let h_addr = h as usize;
        std::thread::spawn(move || {
            let h = h_addr as windows_sys::Win32::Foundation::HANDLE;
            // Read the whole request (header, then the declared content length).
            let mut buf = Vec::new();
            let mut chunk = vec![0u8; 64 * 1024];
            loop {
                let mut n = 0u32;
                // SAFETY: reading into our own buffer from a connected pipe.
                let ok = unsafe { ReadFile(h, chunk.as_mut_ptr(), chunk.len() as u32, &mut n, std::ptr::null_mut()) } != 0;
                buf.extend_from_slice(&chunk[..n as usize]);
                let complete = decode(&buf).is_some();
                if !ok || n == 0 || complete || buf.len() > 9 * 1024 * 1024 {
                    break;
                }
            }
            let mut verdict = 0u8;
            if on.load(Ordering::Relaxed)
                && let Some((app, content)) = decode(&buf)
                && let Some(eng) = engine.read().ok().and_then(|e| e.clone())
                && let Some(reason) = judge(&eng, &app, content)
            {
                verdict = 1;
                let host = app.split('_').next().unwrap_or("A script").to_string();
                if let Ok(mut e) = events.lock() {
                    e.push(ShieldEvent {
                        shield: "Script shield",
                        report: None,
                        title: format!("Blocked a script in {host}"),
                        action: format!("{reason} Hexward stopped it before it ran."),
                        quarantined: false,
                        neutralize: false,
                    });
                }
            }
            let mut written = 0u32;
            // SAFETY: writes one byte to our connected pipe, then closes it.
            unsafe {
                WriteFile(h, &verdict, 1, &mut written, std::ptr::null_mut());
                FlushFileBuffers(h);
                DisconnectNamedPipe(h);
                CloseHandle(h);
            }
        });
    }
}

#[cfg(not(windows))]
pub fn serve(_engine: Arc<RwLock<Option<Arc<Engine>>>>, _on: Arc<AtomicBool>, _events: Arc<Mutex<Vec<ShieldEvent>>>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_requests() {
        let mut r = b"HXA1".to_vec();
        r.extend(3u32.to_le_bytes());
        r.extend(b"app");
        r.extend(2u32.to_le_bytes());
        r.extend(b"hi");
        assert_eq!(decode(&r).map(|(a, c)| (a, c.to_vec())), Some(("app".to_string(), b"hi".to_vec())));
        assert!(decode(&r[..9]).is_none(), "incomplete until the whole content is there");
    }
}
