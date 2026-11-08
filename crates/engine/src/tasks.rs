//! Task manager: running processes grouped the way people think about them.
//!
//! - Apps: programs with a window on screen.
//! - Background: everything else the user started or that runs for them.
//! - Windows: the operating system itself (anything in the Windows folder, core system processes,
//!   and processes Windows won't even show us the path of).
//!
//! Windows processes and security software (Defender, Hexward itself) are protected: Hexward will
//! not end them, and `end()` re-checks that at the moment of the request, whatever the UI sent.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Group {
    Apps,
    Background,
    Windows,
}

#[derive(Debug, Clone, Serialize)]
pub struct Proc {
    pub pid: u32,
    /// What people call it: the program's description ("Google Chrome") or its file name.
    pub name: String,
    pub file: String,
    pub exe: Option<PathBuf>,
    pub window_title: Option<String>,
    /// The Windows service this process runs, when it runs exactly one.
    pub service: Option<String>,
    pub publisher: Option<String>,
    pub group: Group,
    pub protected: bool,
    /// Percent of the whole PC (all cores), 0–100.
    pub cpu: f32,
    pub memory: u64,
    /// Runs from a folder any program can write to (Temp, Downloads, Public): worth a look.
    pub risky_place: bool,
    /// How many processes of the same program were merged into this row.
    pub count: u32,
}

const SYSTEM_NAMES: &[&str] = &[
    "system", "idle", "system idle process", "registry", "memory compression", "secure system", "smss.exe", "csrss.exe", "wininit.exe",
    "services.exe", "lsass.exe", "lsaiso.exe", "winlogon.exe", "svchost.exe", "dwm.exe", "fontdrvhost.exe", "sihost.exe", "ctfmon.exe",
];
const SECURITY_NAMES: &[&str] = &[
    "msmpeng.exe", "nissrv.exe", "mpdefendercoreservice.exe", "securityhealthservice.exe", "securityhealthsystray.exe", "smartscreen.exe",
    "hexward-app.exe", "hexward.exe",
];

fn windows_dir() -> String {
    let w = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
    format!("{}\\", w.trim_end_matches('\\').to_lowercase())
}

/// The protection rule, in one place: used for display and enforced again by `end()`.
pub fn is_protected(file: &str, exe: Option<&Path>) -> bool {
    let f = file.to_lowercase();
    if SYSTEM_NAMES.contains(&f.as_str()) || SECURITY_NAMES.contains(&f.as_str()) {
        return true;
    }
    match exe {
        None => true, // Windows hides the path of its own protected processes
        Some(p) => p.to_string_lossy().to_lowercase().starts_with(&windows_dir()),
    }
}

fn risky(exe: &Path) -> bool {
    let l = exe.to_string_lossy().to_lowercase();
    ["\\appdata\\local\\temp\\", "\\downloads\\", "\\users\\public\\", "\\windows\\temp\\"].iter().any(|p| l.contains(p))
}

/// Windows with a title that are visible and not tool windows: what people call "apps".
#[cfg(windows)]
pub fn windowed_pids() -> HashMap<u32, String> {
    use windows_sys::Win32::Foundation::{HWND, LPARAM};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GW_OWNER, GWL_EXSTYLE, GetWindow, GetWindowLongPtrW, GetWindowTextLengthW, GetWindowTextW, GetWindowThreadProcessId, IsWindowVisible, WS_EX_TOOLWINDOW,
    };
    unsafe extern "system" fn each(hwnd: HWND, lparam: LPARAM) -> windows_sys::core::BOOL {
        // SAFETY: lparam is the &mut HashMap passed below, alive for the whole EnumWindows call.
        unsafe {
            let out = &mut *(lparam as *mut HashMap<u32, String>);
            if IsWindowVisible(hwnd) == 0 || !GetWindow(hwnd, GW_OWNER).is_null() || (GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32) & WS_EX_TOOLWINDOW != 0 {
                return 1;
            }
            let len = GetWindowTextLengthW(hwnd);
            if len <= 0 {
                return 1;
            }
            let mut buf = vec![0u16; len as usize + 1];
            let n = GetWindowTextW(hwnd, buf.as_mut_ptr(), buf.len() as i32);
            let mut pid = 0u32;
            GetWindowThreadProcessId(hwnd, &mut pid);
            out.entry(pid).or_insert_with(|| String::from_utf16_lossy(&buf[..n.max(0) as usize]));
            1
        }
    }
    let mut out: HashMap<u32, String> = HashMap::new();
    // SAFETY: the callback only touches `out` through lparam during this call.
    unsafe { EnumWindows(Some(each), &mut out as *mut _ as LPARAM) };
    out
}

#[cfg(not(windows))]
pub fn windowed_pids() -> HashMap<u32, String> {
    HashMap::new()
}

pub struct TaskList {
    sys: sysinfo::System,
    cores: f32,
    meta: HashMap<PathBuf, (Option<String>, Option<String>)>,
    /// Paths sysinfo couldn't read (services running as SYSTEM), looked up with the lighter
    /// query-limited access right instead.
    paths: HashMap<u32, PathBuf>,
    /// Running services by process id, refreshed every 20 s: the only way a normal user can learn
    /// where a SYSTEM service's program lives.
    services: HashMap<u32, Vec<crate::services::Service>>,
    services_at: Option<std::time::Instant>,
}

fn exe_path(paths: &mut HashMap<u32, PathBuf>, services: &HashMap<u32, Vec<crate::services::Service>>, pid: u32, p: &sysinfo::Process) -> Option<PathBuf> {
    if let Some(e) = p.exe().filter(|e| !e.as_os_str().is_empty()) {
        return Some(e.to_path_buf());
    }
    if let Some(e) = paths.get(&pid) {
        return Some(e.clone());
    }
    let found = crate::behavior::process_path(pid).or_else(|| services.get(&pid).and_then(|v| v.iter().find_map(|s| s.exe.clone())));
    if let Some(e) = &found {
        paths.insert(pid, e.clone());
    }
    found
}

impl TaskList {
    pub fn new() -> Option<Self> {
        let cores = std::thread::available_parallelism().map(|n| n.get() as f32).unwrap_or(1.0);
        Some(TaskList { sys: sysinfo::System::new().ok()?, cores, meta: HashMap::new(), paths: HashMap::new(), services: HashMap::new(), services_at: None })
    }

    /// Refreshes CPU and memory. Call it every second or two; CPU needs two samples.
    pub fn refresh(&mut self) -> Vec<Proc> {
        use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, UpdateKind};
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing().with_cpu().with_memory().with_exe(UpdateKind::OnlyIfNotSet),
        );
        if self.services_at.is_none_or(|t| t.elapsed() > std::time::Duration::from_secs(20)) {
            self.services = crate::services::running();
            self.services_at = Some(std::time::Instant::now());
        }
        let windows = windowed_pids();
        let live: HashSet<u32> = self.sys.processes().keys().map(|p| p.as_u32()).collect();
        self.paths.retain(|pid, _| live.contains(pid));
        let mut rows: Vec<Proc> = Vec::new();
        // Merge processes of the same program within a group (Chrome runs dozens).
        let mut index: HashMap<(String, Group), usize> = HashMap::new();
        for (pid, p) in self.sys.processes() {
            let pid = pid.as_u32();
            let file = p.name().to_string_lossy().into_owned();
            let exe = exe_path(&mut self.paths, &self.services, pid, p);
            let protected = is_protected(&file, exe.as_deref());
            let lower = file.to_lowercase();
            let security = SECURITY_NAMES.contains(&lower.as_str()) && !lower.starts_with("hexward");
            let title = windows.get(&pid).cloned();
            let group = if exe.as_deref().is_none_or(|e| e.to_string_lossy().to_lowercase().starts_with(&windows_dir())) || SYSTEM_NAMES.contains(&lower.as_str()) || security {
                if title.is_some() && file.eq_ignore_ascii_case("explorer.exe") { Group::Apps } else { Group::Windows }
            } else if title.is_some() {
                Group::Apps
            } else {
                Group::Background
            };
            let (publisher, description) = match &exe {
                Some(e) => self.meta.entry(e.clone()).or_insert_with(|| (crate::fileinfo::company(e), crate::fileinfo::description(e))).clone(),
                None => (None, None),
            };
            let service = self.services.get(&pid).filter(|v| v.len() == 1).map(|v| v[0].display.clone());
            let cpu = p.cpu_usage() / self.cores;
            let key = (exe.as_ref().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_else(|| file.to_lowercase()), group);
            if let Some(&i) = index.get(&key) {
                let r = &mut rows[i];
                r.cpu += cpu;
                r.memory += p.memory();
                r.count += 1;
                if r.window_title.is_none() {
                    r.window_title = title;
                }
                continue;
            }
            index.insert(key, rows.len());
            rows.push(Proc {
                pid,
                name: description.clone().filter(|d| d.len() < 60).unwrap_or_else(|| file.clone()),
                file,
                risky_place: exe.as_deref().is_some_and(risky),
                exe,
                window_title: title,
                service,
                publisher,
                group,
                protected,
                cpu,
                memory: p.memory(),
                count: 1,
            });
        }
        rows.sort_by_key(|r| std::cmp::Reverse(r.memory));
        rows
    }

    /// The friendly name of a running process (description or file name).
    pub fn name_of(&mut self, pid: u32) -> Option<String> {
        let p = self.sys.process(sysinfo::Pid::from_u32(pid))?;
        let file = p.name().to_string_lossy().into_owned();
        let desc = p.exe().and_then(|e| self.meta.get(e)).and_then(|m| m.1.clone());
        Some(desc.unwrap_or(file))
    }

    /// (used, total) physical memory in bytes.
    pub fn memory(&mut self) -> (u64, u64) {
        self.sys.refresh_memory();
        (self.sys.used_memory(), self.sys.total_memory())
    }

    /// Every process id belonging to the same program as `pid` (so "End task" ends the whole app).
    pub fn siblings(&self, pid: u32) -> Vec<u32> {
        let Some(p) = self.sys.process(sysinfo::Pid::from_u32(pid)) else { return vec![pid] };
        let Some(exe) = p.exe().map(Path::to_path_buf).filter(|e| !e.as_os_str().is_empty()) else { return vec![pid] };
        self.sys.processes().iter().filter(|(_, q)| q.exe() == Some(exe.as_path())).map(|(id, _)| id.as_u32()).collect()
    }

    /// Ends a program (every process of it). Refuses protected processes, checked here and now.
    pub fn end(&mut self, pid: u32) -> Result<u32, String> {
        let me = std::process::id();
        let Some(p) = self.sys.process(sysinfo::Pid::from_u32(pid)) else { return Err("That program has already closed.".into()) };
        let file = p.name().to_string_lossy().into_owned();
        let exe = exe_path(&mut self.paths, &self.services, pid, p);
        if is_protected(&file, exe.as_deref()) {
            return Err(format!("{file} is part of Windows or your security software, so Hexward won't end it."));
        }
        let mut ended = 0;
        let targets: HashSet<u32> = self.siblings(pid).into_iter().filter(|&p| p != me).collect();
        for t in targets {
            if let Some(q) = self.sys.process(sysinfo::Pid::from_u32(t))
                && q.kill()
            {
                ended += 1;
            }
        }
        if ended == 0 { Err(format!("Windows didn't let Hexward end {file}. It may need administrator rights.")) } else { Ok(ended) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_rule() {
        assert!(is_protected("csrss.exe", None));
        assert!(is_protected("svchost.exe", Some(Path::new(r"C:\Windows\System32\svchost.exe"))));
        assert!(is_protected("anything.exe", Some(Path::new(r"C:\WINDOWS\explorer.exe"))));
        assert!(is_protected("MsMpEng.exe", Some(Path::new(r"C:\ProgramData\Microsoft\Windows Defender\Platform\x\MsMpEng.exe"))));
        assert!(!is_protected("chrome.exe", Some(Path::new(r"C:\Program Files\Google\Chrome\Application\chrome.exe"))));
        assert!(risky(Path::new(r"C:\Users\sam\AppData\Local\Temp\x\setup.exe")));
        assert!(!risky(Path::new(r"C:\Program Files\App\app.exe")));
    }

    #[test]
    fn lists_this_pc_and_refuses_system() {
        let mut t = TaskList::new().unwrap();
        let rows = t.refresh();
        assert!(rows.iter().any(|r| r.group == Group::Windows && r.protected));
        assert!(rows.iter().all(|r| r.cpu >= 0.0 && r.cpu <= 100.5));
        // The protection is enforced in end() itself, not only in the UI.
        let sys_pid = rows.iter().find(|r| r.file.eq_ignore_ascii_case("svchost.exe") || r.file.eq_ignore_ascii_case("csrss.exe")).map(|r| r.pid);
        if let Some(pid) = sys_pid {
            assert!(t.end(pid).is_err());
        }
    }

    #[test]
    fn ends_a_harmless_child_process() {
        // A copy of a tiny Windows program outside the Windows folder, so it's not protected.
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join("hexward-test-sleeper.exe");
        std::fs::copy(r"C:\Windows\System32\PING.EXE", &exe).unwrap();
        let mut child = std::process::Command::new(&exe).args(["-n", "30", "127.0.0.1"]).stdout(std::process::Stdio::null()).spawn().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(300));
        let mut t = TaskList::new().unwrap();
        t.refresh();
        assert!(t.end(child.id()).unwrap() >= 1);
        assert!(child.wait().is_ok());
    }
}
