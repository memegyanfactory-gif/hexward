//! Where to look: quick-scan folders, fixed drives, running programs.

use std::path::PathBuf;

/// Folders where threats usually land or start from. Missing ones are dropped later.
pub fn quick_scan_folders() -> Vec<PathBuf> {
    let mut v = Vec::new();
    v.extend(dirs::download_dir());
    v.extend(dirs::desktop_dir());
    v.push(std::env::temp_dir());
    if let Some(roaming) = dirs::data_dir() {
        v.push(roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"));
    }
    if let Some(pd) = std::env::var_os("ProgramData") {
        v.push(PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"));
    }
    if let Some(public) = std::env::var_os("PUBLIC") {
        v.push(PathBuf::from(public).join("Downloads"));
    }
    v
}

/// Windows itself plus installed programs: where system files live and most software runs from.
pub fn system_folders() -> Vec<PathBuf> {
    let win = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let mut v = vec![win.join("System32"), win.join("SysWOW64"), win.join("Tasks")];
    for var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "ProgramData"] {
        if let Some(p) = std::env::var_os(var) {
            v.push(PathBuf::from(p));
        }
    }
    v.extend(quick_scan_folders());
    v
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Drive {
    pub root: PathBuf,
    pub label: String,
    /// "Local disk", "USB drive", "Network drive", "CD/DVD"
    pub kind: String,
    pub total: u64,
    pub free: u64,
}

/// Every mounted drive with its name and space.
#[cfg(windows)]
pub fn drives() -> Vec<Drive> {
    use windows_sys::Win32::Storage::FileSystem::{GetDiskFreeSpaceExW, GetDriveTypeW, GetVolumeInformationW};
    (b'A'..=b'Z')
        .filter_map(|l| {
            let root = format!("{}:\\", l as char);
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: wide is NUL-terminated and outlives the calls; out-params are valid locals.
            unsafe {
                let kind = match GetDriveTypeW(wide.as_ptr()) {
                    2 => "USB drive",
                    3 => "Local disk",
                    4 => "Network drive",
                    5 => "CD/DVD",
                    _ => return None,
                };
                let mut label = [0u16; 261];
                let ok = GetVolumeInformationW(wide.as_ptr(), label.as_mut_ptr(), label.len() as u32, std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut(), 0);
                if ok == 0 && kind == "CD/DVD" {
                    return None; // empty drive
                }
                let n = label.iter().position(|&c| c == 0).unwrap_or(0);
                let (mut free, mut total) = (0u64, 0u64);
                GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, std::ptr::null_mut());
                Some(Drive { root: PathBuf::from(&root), label: String::from_utf16_lossy(&label[..n]), kind: kind.into(), total, free })
            }
        })
        .collect()
}

#[cfg(not(windows))]
pub fn drives() -> Vec<Drive> {
    vec![Drive { root: PathBuf::from("/"), label: String::new(), kind: "Local disk".into(), total: 0, free: 0 }]
}

/// Program files of everything running now.
pub fn running_programs() -> Vec<PathBuf> {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let Ok(mut sys) = System::new() else { return Vec::new() };
    sys.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing().with_exe(UpdateKind::Always),
    );
    let mut v: Vec<PathBuf> = sys.processes().values().filter_map(|p| p.exe().map(|e| e.to_path_buf())).collect();
    v.sort();
    v.dedup();
    v
}

/// Every fixed (non-removable, non-network) drive root, for a full scan.
#[cfg(windows)]
pub fn fixed_drives() -> Vec<PathBuf> {
    use windows_sys::Win32::Storage::FileSystem::GetDriveTypeW;
    const DRIVE_FIXED: u32 = 3;
    (b'A'..=b'Z')
        .map(|l| format!("{}:\\", l as char))
        .filter(|root| {
            let wide: Vec<u16> = root.encode_utf16().chain(std::iter::once(0)).collect();
            // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that outlives the call.
            unsafe { GetDriveTypeW(wide.as_ptr()) == DRIVE_FIXED }
        })
        .map(PathBuf::from)
        .collect()
}

#[cfg(not(windows))]
pub fn fixed_drives() -> Vec<PathBuf> {
    vec![PathBuf::from("/")]
}
