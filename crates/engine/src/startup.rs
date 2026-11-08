//! Things Windows starts on its own: Run keys, startup folders, Winlogon,
//! scheduled tasks and auto-start services. Phase 1 lists and scans them; it
//! never edits them.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct StartupItem {
    /// Where the entry lives, e.g. `HKCU\...\Run` or `Scheduled task`.
    pub location: String,
    pub name: String,
    /// The raw command as Windows stores it.
    pub command: String,
    /// The program file the command runs, when it could be worked out.
    pub target: Option<PathBuf>,
    /// How Hexward can switch this entry off. None for entries it won't touch
    /// (services, drivers, scheduled tasks, Winlogon).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fix: Option<FixTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FixTarget {
    /// A value under a Run or RunOnce key. `hive` is "HKCU" or "HKLM".
    RegistryValue { hive: String, key: String, value: String },
    /// A file in a Startup folder.
    File { path: PathBuf },
}

/// A startup entry Hexward switched off, with what it needs to switch it back on.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisabledItem {
    pub id: String,
    pub at: DateTime<Utc>,
    pub location: String,
    pub name: String,
    pub command: String,
    pub target: FixTarget,
    /// Registry: the value type ("REG_SZ" or "REG_EXPAND_SZ"). File: where the file was moved.
    pub saved: String,
}

fn disabled_path() -> PathBuf {
    crate::data_dir().join("startup-disabled.json")
}

/// Entries switched off by Hexward, newest first.
pub fn disabled_items() -> Vec<DisabledItem> {
    let mut v: Vec<DisabledItem> = std::fs::read(disabled_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    v.sort_by_key(|d| std::cmp::Reverse(d.at));
    v
}

fn save_disabled(list: &[DisabledItem]) -> Result<(), String> {
    std::fs::create_dir_all(crate::data_dir()).map_err(|e| e.to_string())?;
    let bytes = serde_json::to_vec_pretty(list).map_err(|e| e.to_string())?;
    std::fs::write(disabled_path(), bytes).map_err(|e| e.to_string())
}

fn new_id() -> String {
    let n = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("{:x}", n & 0xFFFF_FFFF_FFFF)
}

fn friendly(e: std::io::Error) -> String {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        "Windows needs administrator rights to change this entry. Run Hexward as administrator and try again.".into()
    } else {
        e.to_string()
    }
}

/// Switches a startup entry off and remembers how to undo it.
/// Registry values are deleted (their data is kept here); files are moved out of the Startup folder.
#[cfg(windows)]
pub fn disable(item: &StartupItem) -> Result<DisabledItem, String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, RegType};
    let Some(fix) = item.fix.clone() else {
        return Err("Hexward can't switch off this kind of entry yet.".into());
    };
    let id = new_id();
    let saved = match &fix {
        FixTarget::RegistryValue { hive, key, value } => {
            let root = winreg::RegKey::predef(if hive == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
            let k = root.open_subkey_with_flags(key, KEY_READ | KEY_SET_VALUE).map_err(friendly)?;
            let raw = k.get_raw_value(value).map_err(friendly)?;
            let kind = match raw.vtype {
                RegType::REG_SZ => "REG_SZ",
                RegType::REG_EXPAND_SZ => "REG_EXPAND_SZ",
                _ => return Err("This entry uses an unusual value type, so Hexward leaves it alone.".into()),
            };
            k.delete_value(value).map_err(friendly)?;
            kind.to_string()
        }
        FixTarget::File { path } => {
            let dir = crate::data_dir().join("StartupDisabled");
            std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "item".into());
            let dest = dir.join(format!("{id}-{name}"));
            std::fs::rename(path, &dest).or_else(|_| std::fs::copy(path, &dest).and_then(|_| std::fs::remove_file(path))).map_err(friendly)?;
            dest.display().to_string()
        }
    };
    let entry = DisabledItem { id, at: Utc::now(), location: item.location.clone(), name: item.name.clone(), command: item.command.clone(), target: fix, saved };
    let mut list = disabled_items();
    list.insert(0, entry.clone());
    save_disabled(&list)?;
    Ok(entry)
}

/// Switches a disabled entry back on exactly as it was.
#[cfg(windows)]
pub fn restore(id: &str) -> Result<DisabledItem, String> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_SET_VALUE, RegType};
    let mut list = disabled_items();
    let pos = list.iter().position(|d| d.id == id).ok_or("That entry isn't in the list any more.")?;
    let item = list[pos].clone();
    match &item.target {
        FixTarget::RegistryValue { hive, key, value } => {
            let root = winreg::RegKey::predef(if hive == "HKLM" { HKEY_LOCAL_MACHINE } else { HKEY_CURRENT_USER });
            let k = root.open_subkey_with_flags(key, KEY_SET_VALUE).map_err(friendly)?;
            let mut bytes: Vec<u8> = item.command.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            bytes.extend_from_slice(&[0, 0]);
            let vtype = if item.saved == "REG_EXPAND_SZ" { RegType::REG_EXPAND_SZ } else { RegType::REG_SZ };
            k.set_raw_value(value, &winreg::RegValue { bytes: bytes.into(), vtype }).map_err(friendly)?;
        }
        FixTarget::File { path } => {
            if path.exists() {
                return Err(format!("{} already exists.", path.display()));
            }
            std::fs::rename(&item.saved, path).map_err(friendly)?;
        }
    }
    list.remove(pos);
    save_disabled(&list)?;
    Ok(item)
}

#[cfg(not(windows))]
pub fn disable(_item: &StartupItem) -> Result<DisabledItem, String> {
    Err("Only supported on Windows.".into())
}

#[cfg(not(windows))]
pub fn restore(_id: &str) -> Result<DisabledItem, String> {
    Err("Only supported on Windows.".into())
}

/// Expands `%VAR%` using the current environment. Unknown variables stay as they are.
pub fn expand_env(s: &str) -> String {
    let mut out = String::new();
    let mut rest = s;
    while let Some(start) = rest.find('%') {
        out.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        match after.find('%') {
            Some(end) => {
                let var = &after[..end];
                match std::env::var(var) {
                    Ok(v) if !var.is_empty() => out.push_str(&v),
                    _ => {
                        out.push('%');
                        out.push_str(var);
                        out.push('%');
                    }
                }
                rest = &after[end + 1..];
            }
            None => {
                out.push_str(&rest[start..]);
                rest = "";
            }
        }
    }
    out.push_str(rest);
    out
}

fn windows_dir() -> PathBuf {
    std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

/// Works out which file a command line runs.
/// Handles quotes, unquoted paths with spaces, `\SystemRoot\`, `\??\`, bare
/// `system32\` service paths, and rundll32 (returns the DLL instead).
pub fn resolve_target(command: &str) -> Option<PathBuf> {
    let cmd = expand_env(command.trim());
    let cmd = cmd.strip_prefix(r"\??\").unwrap_or(&cmd);
    let lower = cmd.to_ascii_lowercase();
    let cmd: String = if lower.starts_with(r"\systemroot\") {
        format!("{}{}", windows_dir().display(), &cmd[r"\systemroot".len()..])
    } else if lower.starts_with(r"system32\") || lower.starts_with(r"syswow64\") {
        format!("{}\\{}", windows_dir().display(), cmd)
    } else {
        cmd.to_string()
    };

    let (first, args) = if let Some(rest) = cmd.strip_prefix('"') {
        let end = rest.find('"')?;
        (rest[..end].to_string(), rest[end + 1..].trim().to_string())
    } else {
        // Try ever-longer prefixes split on spaces: "C:\Program Files\App\app.exe -x".
        let parts: Vec<&str> = cmd.split(' ').collect();
        let mut found = None;
        for i in 1..=parts.len() {
            let candidate = parts[..i].join(" ");
            let p = Path::new(&candidate);
            if p.is_file() || with_exe(p).is_some_and(|q| q.is_file()) {
                found = Some((candidate, parts[i..].join(" ")));
                break;
            }
        }
        found.unwrap_or_else(|| (parts[0].to_string(), parts[1..].join(" ")))
    };

    let mut target = PathBuf::from(&first);
    if !target.is_absolute() {
        // Same order Windows searches: System32, the Windows folder, then PATH.
        let mut dirs = vec![windows_dir().join("System32"), windows_dir()];
        if let Some(path) = std::env::var_os("PATH") {
            dirs.extend(std::env::split_paths(&path));
        }
        if let Some(hit) = dirs
            .iter()
            .map(|d| d.join(&target))
            .find(|c| c.is_file() || with_exe(c).is_some_and(|p| p.is_file()))
        {
            target = hit;
        }
    }
    if target.extension().is_none()
        && let Some(p) = with_exe(&target)
    {
        target = p;
    }

    // rundll32 runs a DLL: that DLL is what matters.
    if target.file_name().is_some_and(|n| n.eq_ignore_ascii_case("rundll32.exe")) {
        let dll = args.trim().trim_matches('"');
        let dll = dll.split(',').next().unwrap_or("").trim().trim_matches('"');
        if !dll.is_empty() {
            return Some(PathBuf::from(dll));
        }
    }
    Some(target)
}

fn with_exe(p: &Path) -> Option<PathBuf> {
    p.extension().is_none().then(|| p.with_extension("exe"))
}

#[cfg(windows)]
pub fn list_startup_items() -> Vec<StartupItem> {
    let mut items = Vec::new();
    registry_items(&mut items);
    folder_items(&mut items);
    task_items(&mut items);
    service_items(&mut items);
    items
}

#[cfg(not(windows))]
pub fn list_startup_items() -> Vec<StartupItem> {
    Vec::new()
}

#[cfg(windows)]
fn push(items: &mut Vec<StartupItem>, location: &str, name: &str, command: &str) -> bool {
    if command.trim().is_empty() {
        return false;
    }
    items.push(StartupItem {
        location: location.to_string(),
        name: name.to_string(),
        command: command.to_string(),
        target: resolve_target(command),
        fix: None,
    });
    true
}

#[cfg(windows)]
fn registry_items(items: &mut Vec<StartupItem>) {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};

    let run_keys = [
        (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_CURRENT_USER, "HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE, "HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        (HKEY_LOCAL_MACHINE, "HKLM", r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"),
    ];
    for (hive, hive_name, path) in run_keys {
        let Ok(key) = RegKey::predef(hive).open_subkey(path) else { continue };
        for (name, _) in key.enum_values().flatten() {
            if let Ok(cmd) = key.get_value::<String, _>(&name)
                && push(items, &format!(r"{hive_name}\{path}"), &name, &cmd)
                && let Some(last) = items.last_mut()
            {
                last.fix = Some(FixTarget::RegistryValue { hive: hive_name.to_string(), key: path.to_string(), value: name.clone() });
            }
        }
    }

    // Winlogon starts these for every sign-in; extra entries after the defaults are a classic hiding spot.
    if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon") {
        for value in ["Shell", "Userinit"] {
            if let Ok(cmd) = key.get_value::<String, _>(value) {
                for part in cmd.split(',').map(str::trim).filter(|p| !p.is_empty()) {
                    push(items, r"HKLM\...\Winlogon", value, part);
                }
            }
        }
    }
}

#[cfg(windows)]
fn folder_items(items: &mut Vec<StartupItem>) {
    let mut folders = Vec::new();
    if let Some(roaming) = dirs::data_dir() {
        folders.push(roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if let Some(pd) = std::env::var_os("ProgramData") {
        folders.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    for folder in folders {
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.file_name().is_some_and(|n| n.eq_ignore_ascii_case("desktop.ini")) {
                continue;
            }
            items.push(StartupItem {
                location: "Startup folder".into(),
                name: e.file_name().to_string_lossy().into_owned(),
                command: p.display().to_string(),
                target: Some(p.clone()),
                fix: Some(FixTarget::File { path: p }),
            });
        }
    }
}

/// Scheduled task definitions are XML files (usually UTF-16) under System32\Tasks.
#[cfg(windows)]
fn task_items(items: &mut Vec<StartupItem>) {
    let root = windows_dir().join(r"System32\Tasks");
    for entry in walkdir::WalkDir::new(&root).into_iter().flatten() {
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(bytes) = std::fs::read(entry.path()) else { continue };
        let xml = decode_text(&bytes);
        let name = entry.path().strip_prefix(&root).unwrap_or(entry.path()).display().to_string();
        let mut rest = xml.as_str();
        while let Some(start) = rest.find("<Command>") {
            let after = &rest[start + 9..];
            let Some(end) = after.find("</Command>") else { break };
            let command = unescape_xml(after[..end].trim());
            let args = after[end..]
                .split("</Exec>")
                .next()
                .and_then(|block| block.split("<Arguments>").nth(1))
                .and_then(|a| a.split("</Arguments>").next())
                .map(unescape_xml)
                .unwrap_or_default();
            let quoted = if command.contains(' ') && !command.starts_with('"') { format!("\"{command}\"") } else { command };
            let full = if args.is_empty() { quoted } else { format!("{quoted} {args}") };
            push(items, "Scheduled task", &name, &full);
            rest = &after[end..];
        }
    }
}

#[cfg(windows)]
fn service_items(items: &mut Vec<StartupItem>) {
    use winreg::RegKey;
    use winreg::enums::HKEY_LOCAL_MACHINE;

    let Ok(services) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey(r"SYSTEM\CurrentControlSet\Services") else {
        return;
    };
    for name in services.enum_keys().flatten() {
        let Ok(svc) = services.open_subkey(&name) else { continue };
        let start: u32 = svc.get_value("Start").unwrap_or(4);
        let kind: u32 = svc.get_value("Type").unwrap_or(0);
        // Auto-start (2) or boot/system (0, 1) programs and drivers.
        if start > 2 || kind == 0 {
            continue;
        }
        if let Ok(image) = svc.get_value::<String, _>("ImagePath") {
            let location = if kind & 0x30 != 0 { "Service" } else { "Driver" };
            push(items, location, &name, &image);
        }
    }
}

fn decode_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xFF, 0xFE]) {
        let u16s: Vec<u16> = bytes[2..].as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
        String::from_utf16_lossy(&u16s)
    } else {
        String::from_utf8_lossy(bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes)).into_owned()
    }
}

fn unescape_xml(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(windows)]
    #[test]
    fn resolves_common_command_shapes() {
        // Windows paths ignore case, so compare lower-cased.
        let r = |cmd: &str| resolve_target(cmd).unwrap().display().to_string().to_lowercase();
        let notepad = windows_dir().join(r"System32\notepad.exe").display().to_string().to_lowercase();
        assert_eq!(r(r#""C:\Windows\System32\notepad.exe" /A file.txt"#), r"c:\windows\system32\notepad.exe");
        assert_eq!(r(r"%SystemRoot%\System32\notepad.exe"), notepad);
        assert_eq!(r(r"\SystemRoot\System32\notepad.exe"), notepad);
        assert_eq!(r(r"system32\notepad.exe"), notepad);
        assert_eq!(r("notepad"), notepad);
        assert_eq!(r("explorer.exe"), windows_dir().join("explorer.exe").display().to_string().to_lowercase());
        assert_eq!(r(r"rundll32.exe C:\Users\sam\AppData\x.dll,Start"), r"c:\users\sam\appdata\x.dll");
        // Windows itself tries "C:\Program.exe" first for an unquoted path with spaces
        // (the "unquoted service path" trick), so that is the file worth checking.
        assert_eq!(r(r"C:\Program Files\Missing App\app.exe --tray"), r"c:\program.exe");
    }

    #[test]
    fn expands_env_and_keeps_unknown() {
        unsafe { std::env::set_var("HEXWARD_T", "X") };
        assert_eq!(expand_env("a%HEXWARD_T%b%NOPE_404%c%"), "aXb%NOPE_404%c%");
    }

    #[test]
    fn decodes_utf16_task_xml() {
        let text = "<Exec><Command>C:\\a.exe</Command><Arguments>-x &quot;y&quot;</Arguments></Exec>";
        let mut bytes = vec![0xFF, 0xFE];
        bytes.extend(text.encode_utf16().flat_map(|u| u.to_le_bytes()));
        assert_eq!(decode_text(&bytes), text);
        assert_eq!(unescape_xml("-x &quot;y&quot;"), "-x \"y\"");
    }
}

#[cfg(all(test, windows))]
mod fix_tests {
    use super::*;

    #[test]
    fn disable_and_restore_registry_value_and_file() {
        use winreg::RegKey;
        use winreg::enums::HKEY_CURRENT_USER;
        let home = tempfile::tempdir().unwrap();
        // SAFETY: only this test reads HEXWARD_HOME through startup's disabled list.
        unsafe { std::env::set_var("HEXWARD_HOME", home.path()) };

        // A throwaway key, never a real Run key.
        let key_path = r"Software\HexwardTest\Run";
        let (k, _) = RegKey::predef(HKEY_CURRENT_USER).create_subkey(key_path).unwrap();
        k.set_value("demo", &r"%SystemRoot%\System32\notepad.exe /x").unwrap();
        let item = StartupItem {
            location: "test".into(),
            name: "demo".into(),
            command: r"%SystemRoot%\System32\notepad.exe /x".into(),
            target: None,
            fix: Some(FixTarget::RegistryValue { hive: "HKCU".into(), key: key_path.into(), value: "demo".into() }),
        };
        let d = disable(&item).unwrap();
        assert!(k.get_value::<String, _>("demo").is_err(), "value removed");
        restore(&d.id).unwrap();
        assert_eq!(k.get_value::<String, _>("demo").unwrap(), r"%SystemRoot%\System32\notepad.exe /x");
        RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(r"Software\HexwardTest").unwrap();

        // A file in a (fake) Startup folder.
        let folder = home.path().join("Startup");
        std::fs::create_dir_all(&folder).unwrap();
        let f = folder.join("updater.lnk");
        std::fs::write(&f, b"shortcut").unwrap();
        let item = StartupItem { location: "Startup folder".into(), name: "updater.lnk".into(), command: f.display().to_string(), target: Some(f.clone()), fix: Some(FixTarget::File { path: f.clone() }) };
        let d = disable(&item).unwrap();
        assert!(!f.exists());
        assert_eq!(disabled_items().len(), 1);
        restore(&d.id).unwrap();
        assert_eq!(std::fs::read(&f).unwrap(), b"shortcut");
        assert!(disabled_items().is_empty());

        // Entries without a fix are refused.
        let item = StartupItem { location: "Service".into(), name: "x".into(), command: "x".into(), target: None, fix: None };
        assert!(disable(&item).is_err());
    }
}
