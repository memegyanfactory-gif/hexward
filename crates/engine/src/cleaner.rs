//! PC cleaner: browser caches, history and cookies, plus Windows junk (temp files, crash dumps,
//! thumbnail cache, recycle bin).
//!
//! Rules that keep it safe:
//! - Only fixed, known locations are ever touched; nothing is searched for by pattern across the disk.
//! - Files in use are skipped, never forced. A running browser is asked to close first.
//! - Temp files from the last 24 hours are kept: an installer may still need them.
//! - Firefox history shares a file with bookmarks, so Hexward never deletes it.
//! - Cookies, history and the recycle bin are off until the user ticks them.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Engine {
    Chromium,
    Firefox,
}

#[derive(Debug, Clone, Serialize)]
pub struct Browser {
    pub id: &'static str,
    pub name: &'static str,
    pub engine: Engine,
    /// The browser's program, for its icon. None if Hexward can't find it.
    pub exe: Option<PathBuf>,
    /// Process name used to tell whether it's running and to ask it to close.
    pub process: &'static str,
    /// Profile folders (Chromium: Default, Profile 1, …; Firefox: each profile).
    pub profiles: Vec<PathBuf>,
    /// Cache root per profile (Chromium keeps it in the profile; Firefox and Opera elsewhere).
    pub cache_roots: Vec<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Target {
    /// Delete everything inside this folder (the folder itself stays).
    DirContents(PathBuf),
    /// Delete files inside this folder older than the given age.
    DirOlderThan(PathBuf, Duration),
    /// Delete this one file.
    File(PathBuf),
    /// Delete files in this folder whose names start with the prefix.
    FilesWithPrefix(PathBuf, &'static str),
    RecycleBin,
}

#[derive(Debug, Clone, Serialize)]
pub struct Item {
    /// Stable id, e.g. "chrome:cache" or "windows:temp".
    pub id: String,
    /// Browser id, or "windows".
    pub group: String,
    pub label: &'static str,
    pub description: &'static str,
    pub default_on: bool,
    /// False when Hexward offers the item but won't clean it (the note says why).
    pub available: bool,
    pub targets: Vec<Target>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Size {
    pub bytes: u64,
    pub files: u64,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct Cleaned {
    pub bytes: u64,
    pub files: u64,
    /// Files that were in use or protected and left alone.
    pub skipped: u64,
}

fn env_dir(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_dir())
}

struct Known {
    id: &'static str,
    name: &'static str,
    process: &'static str,
    /// (env var, path under it) of the user-data folder.
    data: (&'static str, &'static str),
    exes: &'static [(&'static str, &'static str)],
    app_path: &'static str,
}

const CHROMIUM: &[Known] = &[
    Known {
        id: "chrome",
        name: "Google Chrome",
        process: "chrome.exe",
        data: ("LOCALAPPDATA", r"Google\Chrome\User Data"),
        exes: &[("ProgramFiles", r"Google\Chrome\Application\chrome.exe"), ("ProgramFiles(x86)", r"Google\Chrome\Application\chrome.exe"), ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe")],
        app_path: "chrome.exe",
    },
    Known {
        id: "edge",
        name: "Microsoft Edge",
        process: "msedge.exe",
        data: ("LOCALAPPDATA", r"Microsoft\Edge\User Data"),
        exes: &[("ProgramFiles(x86)", r"Microsoft\Edge\Application\msedge.exe"), ("ProgramFiles", r"Microsoft\Edge\Application\msedge.exe")],
        app_path: "msedge.exe",
    },
    Known {
        id: "brave",
        name: "Brave",
        process: "brave.exe",
        data: ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data"),
        exes: &[("ProgramFiles", r"BraveSoftware\Brave-Browser\Application\brave.exe"), ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\Application\brave.exe")],
        app_path: "brave.exe",
    },
    Known {
        id: "vivaldi",
        name: "Vivaldi",
        process: "vivaldi.exe",
        data: ("LOCALAPPDATA", r"Vivaldi\User Data"),
        exes: &[("LOCALAPPDATA", r"Vivaldi\Application\vivaldi.exe"), ("ProgramFiles", r"Vivaldi\Application\vivaldi.exe")],
        app_path: "vivaldi.exe",
    },
    Known {
        id: "yandex",
        name: "Yandex Browser",
        process: "browser.exe",
        data: ("LOCALAPPDATA", r"Yandex\YandexBrowser\User Data"),
        exes: &[("LOCALAPPDATA", r"Yandex\YandexBrowser\Application\browser.exe")],
        app_path: "browser.exe",
    },
    Known {
        id: "opera",
        name: "Opera",
        process: "opera.exe",
        data: ("APPDATA", r"Opera Software\Opera Stable"),
        exes: &[("LOCALAPPDATA", r"Programs\Opera\opera.exe"), ("ProgramFiles", r"Opera\opera.exe")],
        app_path: "opera.exe",
    },
    Known {
        id: "operagx",
        name: "Opera GX",
        process: "opera.exe",
        data: ("APPDATA", r"Opera Software\Opera GX Stable"),
        exes: &[("LOCALAPPDATA", r"Programs\Opera GX\opera.exe"), ("ProgramFiles", r"Opera GX\opera.exe")],
        app_path: "",
    },
];

#[cfg(windows)]
fn app_path(exe: &str) -> Option<PathBuf> {
    use winreg::RegKey;
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    if exe.is_empty() {
        return None;
    }
    for hive in [HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE] {
        if let Ok(k) = RegKey::predef(hive).open_subkey(format!(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe}"))
            && let Ok(v) = k.get_value::<String, _>("")
        {
            let p = PathBuf::from(v.trim_matches('"'));
            if p.is_file() {
                return Some(p);
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn app_path(_exe: &str) -> Option<PathBuf> {
    None
}

/// The file itself, or the newest copy one folder down (Opera keeps `Opera\133.0…\opera.exe`).
fn file_or_versioned(p: PathBuf) -> Option<PathBuf> {
    if p.is_file() {
        return Some(p);
    }
    let (dir, name) = (p.parent()?, p.file_name()?);
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir).ok()?.flatten().map(|e| e.path().join(name)).filter(|c| c.is_file()).collect();
    hits.sort();
    hits.pop()
}

fn find_exe(k: &Known) -> Option<PathBuf> {
    k.exes
        .iter()
        .filter_map(|(var, rel)| std::env::var_os(var).map(|b| PathBuf::from(b).join(rel)))
        .find_map(file_or_versioned)
        .or_else(|| app_path(k.app_path))
}

/// Chromium profile folders: the ones holding a `Preferences` file.
fn chromium_profiles(data: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if data.join("Preferences").is_file() {
        out.push(data.to_path_buf()); // Opera keeps its main profile in the data folder itself
    }
    if let Ok(rd) = std::fs::read_dir(data) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() && p.join("Preferences").is_file() {
                out.push(p);
            }
        }
    }
    out.sort();
    out
}

/// Every supported browser that has data on this PC.
pub fn browsers() -> Vec<Browser> {
    let mut out = Vec::new();
    for k in CHROMIUM {
        let Some(base) = env_dir(k.data.0) else { continue };
        let data = base.join(k.data.1);
        if !data.is_dir() {
            continue;
        }
        let profiles = chromium_profiles(&data);
        if profiles.is_empty() {
            continue;
        }
        // Opera stores its cache under Local AppData, mirroring the Roaming path.
        let mut cache_roots = profiles.clone();
        if k.data.0 == "APPDATA"
            && let (Some(roaming), Some(local)) = (env_dir("APPDATA"), env_dir("LOCALAPPDATA"))
        {
            cache_roots = profiles.iter().filter_map(|p| p.strip_prefix(&roaming).ok().map(|rel| local.join(rel))).chain(profiles.iter().cloned()).collect();
        }
        out.push(Browser { id: k.id, name: k.name, engine: Engine::Chromium, exe: find_exe(k), process: k.process, profiles, cache_roots });
    }
    if let (Some(roaming), Some(local)) = (env_dir("APPDATA"), env_dir("LOCALAPPDATA")) {
        let root = roaming.join(r"Mozilla\Firefox\Profiles");
        let profiles: Vec<PathBuf> = std::fs::read_dir(&root).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.join("prefs.js").is_file()).collect()).unwrap_or_default();
        if !profiles.is_empty() {
            let cache_roots = profiles.iter().filter_map(|p| p.file_name().map(|n| local.join(r"Mozilla\Firefox\Profiles").join(n))).collect();
            let exe = [("ProgramFiles", r"Mozilla Firefox\firefox.exe"), ("ProgramFiles(x86)", r"Mozilla Firefox\firefox.exe")]
                .iter()
                .filter_map(|(v, r)| std::env::var_os(v).map(|b| PathBuf::from(b).join(r)))
                .find(|p| p.is_file())
                .or_else(|| app_path("firefox.exe"));
            out.push(Browser { id: "firefox", name: "Mozilla Firefox", engine: Engine::Firefox, exe, process: "firefox.exe", profiles, cache_roots });
        }
    }
    out
}

const CHROMIUM_CACHE_DIRS: &[&str] = &["Cache", "Code Cache", "GPUCache", r"Service Worker\CacheStorage", r"Service Worker\ScriptCache", "DawnCache", "DawnGraphiteCache", "DawnWebGPUCache", "GrShaderCache", "ShaderCache"];
const CHROMIUM_HISTORY_FILES: &[&str] = &["History", "History-journal", "Visited Links", "Top Sites", "Top Sites-journal", "Shortcuts", "Shortcuts-journal", "Network Action Predictor", "Network Action Predictor-journal"];
const CHROMIUM_COOKIE_FILES: &[&str] = &[r"Network\Cookies", r"Network\Cookies-journal", "Cookies", "Cookies-journal"];

/// The cleanable items for one browser.
pub fn browser_items(b: &Browser) -> Vec<Item> {
    let id = |what: &str| format!("{}:{what}", b.id);
    match b.engine {
        Engine::Chromium => {
            let mut cache: Vec<Target> = Vec::new();
            for root in &b.cache_roots {
                for d in CHROMIUM_CACHE_DIRS {
                    let p = root.join(d);
                    if p.is_dir() && !cache.iter().any(|t| matches!(t, Target::DirContents(q) if p.starts_with(q))) {
                        cache.push(Target::DirContents(p));
                    }
                }
            }
            // Shared shader caches next to the profiles.
            if let Some(data) = b.profiles.first().and_then(|p| p.parent()) {
                for d in ["ShaderCache", "GrShaderCache", "GraphiteDawnCache"] {
                    let p = data.join(d);
                    if p.is_dir() {
                        cache.push(Target::DirContents(p));
                    }
                }
            }
            let files = |names: &[&str]| -> Vec<Target> { b.profiles.iter().flat_map(|p| names.iter().map(move |n| p.join(n))).filter(|p| p.is_file()).map(Target::File).collect() };
            vec![
                Item { id: id("cache"), group: b.id.into(), label: "Cache", description: "Copies of web pages and images. Safe to clear; sites load a little slower the first time.", default_on: true, available: true, targets: cache },
                Item { id: id("history"), group: b.id.into(), label: "History and download list", description: "Sites you visited and the list of downloads. Bookmarks and saved passwords stay.", default_on: false, available: true, targets: files(CHROMIUM_HISTORY_FILES) },
                Item { id: id("cookies"), group: b.id.into(), label: "Cookies", description: "Signs you out of websites. Sites forget your settings.", default_on: false, available: true, targets: files(CHROMIUM_COOKIE_FILES) },
            ]
        }
        Engine::Firefox => {
            let cache = b.cache_roots.iter().flat_map(|r| ["cache2", "startupCache", "thumbnails"].map(|d| r.join(d))).filter(|p| p.is_dir()).map(Target::DirContents).collect();
            let cookies = b.profiles.iter().flat_map(|p| ["cookies.sqlite", "cookies.sqlite-wal", "cookies.sqlite-shm"].map(|n| p.join(n))).filter(|p| p.is_file()).map(Target::File).collect();
            vec![
                Item { id: id("cache"), group: b.id.into(), label: "Cache", description: "Copies of web pages and images. Safe to clear; sites load a little slower the first time.", default_on: true, available: true, targets: cache },
                Item { id: id("history"), group: b.id.into(), label: "History", description: "Firefox keeps history and bookmarks in one file, so Hexward leaves it alone. Clear it in Firefox with Ctrl+Shift+Delete.", default_on: false, available: false, targets: Vec::new() },
                Item { id: id("cookies"), group: b.id.into(), label: "Cookies", description: "Signs you out of websites. Sites forget your settings.", default_on: false, available: true, targets: cookies },
            ]
        }
    }
}

const DAY: Duration = Duration::from_secs(24 * 3600);

/// Windows junk that's always safe to remove.
pub fn windows_items() -> Vec<Item> {
    let local = env_dir("LOCALAPPDATA");
    let windir = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Windows"));
    let program_data = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    let mut temp = vec![Target::DirOlderThan(std::env::temp_dir(), DAY), Target::DirOlderThan(windir.join("Temp"), DAY)];
    temp.dedup_by(|a, b| matches!((a, b), (Target::DirOlderThan(x, _), Target::DirOlderThan(y, _)) if x == y));
    let mut dumps = vec![Target::DirContents(windir.join("Minidump")), Target::DirContents(program_data.join(r"Microsoft\Windows\WER\ReportArchive")), Target::DirContents(program_data.join(r"Microsoft\Windows\WER\ReportQueue"))];
    let mut thumbs = Vec::new();
    let mut shaders = Vec::new();
    if let Some(l) = &local {
        dumps.push(Target::DirContents(l.join("CrashDumps")));
        dumps.push(Target::DirContents(l.join(r"Microsoft\Windows\WER\ReportArchive")));
        dumps.push(Target::DirContents(l.join(r"Microsoft\Windows\WER\ReportQueue")));
        thumbs.push(Target::FilesWithPrefix(l.join(r"Microsoft\Windows\Explorer"), "thumbcache_"));
        for d in ["D3DSCache", r"NVIDIA\DXCache", r"NVIDIA\GLCache", r"AMD\DxCache", r"AMD\DxcCache", r"AMD\VkCache"] {
            shaders.push(Target::DirContents(l.join(d)));
        }
    }
    let keep = |v: Vec<Target>| -> Vec<Target> {
        v.into_iter()
            .filter(|t| match t {
                Target::DirContents(p) | Target::DirOlderThan(p, _) | Target::FilesWithPrefix(p, _) => p.is_dir(),
                Target::File(p) => p.is_file(),
                Target::RecycleBin => true,
            })
            .collect()
    };
    let w = |id: &str, label, description, default_on, targets| Item { id: format!("windows:{id}"), group: "windows".into(), label, description, default_on, available: true, targets };
    vec![
        w("temp", "Temporary files", "Leftovers from installers and apps. Anything from the last 24 hours is kept.", true, keep(temp)),
        w("dumps", "Crash dumps and error reports", "Saved after a program or Windows crashed. Only useful to developers.", true, keep(dumps)),
        w("thumbs", "Thumbnail cache", "Picture previews in File Explorer. Windows makes them again as needed.", true, keep(thumbs)),
        w("shaders", "Graphics shader cache", "Rebuilt by games and apps. Games can stutter briefly the first time after clearing.", false, keep(shaders)),
        w("recycle", "Recycle Bin", "Empties the Recycle Bin. Those files are gone for good.", false, vec![Target::RecycleBin]),
    ]
}

/// Everything the cleaner offers: each browser's items, then Windows'.
pub fn all_items(browsers: &[Browser]) -> Vec<Item> {
    let mut v: Vec<Item> = browsers.iter().flat_map(browser_items).collect();
    v.extend(windows_items());
    v
}

fn old_enough(meta: &std::fs::Metadata, age: Option<Duration>) -> bool {
    let Some(age) = age else { return true };
    let t = meta.modified().ok().max(meta.created().ok());
    t.and_then(|t| SystemTime::now().duration_since(t).ok()).is_some_and(|d| d >= age)
}

fn walk_files(dir: &Path, age: Option<Duration>, mut f: impl FnMut(&Path, u64)) {
    for e in walkdir::WalkDir::new(dir).min_depth(1).follow_links(false).into_iter().flatten() {
        if e.file_type().is_file()
            && let Ok(m) = e.metadata()
            && old_enough(&m, age)
        {
            f(e.path(), m.len());
        }
    }
}

fn prefixed(dir: &Path, prefix: &str) -> Vec<PathBuf> {
    std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.path()).filter(|p| p.is_file() && p.file_name().is_some_and(|n| n.to_string_lossy().to_lowercase().starts_with(prefix))).collect()).unwrap_or_default()
}

/// How much an item would free.
pub fn measure(item: &Item) -> Size {
    let mut s = Size::default();
    let mut bin = (0, 0);
    let mut add = |_: &Path, n: u64| {
        s.bytes += n;
        s.files += 1;
    };
    for t in &item.targets {
        match t {
            Target::DirContents(d) => walk_files(d, None, &mut add),
            Target::DirOlderThan(d, age) => walk_files(d, Some(*age), &mut add),
            Target::File(p) => {
                if let Ok(m) = std::fs::metadata(p) {
                    add(p, m.len());
                }
            }
            Target::FilesWithPrefix(d, pre) => {
                for p in prefixed(d, pre) {
                    if let Ok(m) = std::fs::metadata(&p) {
                        add(&p, m.len());
                    }
                }
            }
            Target::RecycleBin => bin = recycle_bin_size(),
        }
    }
    s.bytes += bin.0;
    s.files += bin.1;
    s
}

fn remove_file(p: &Path, n: u64, c: &mut Cleaned) {
    match std::fs::remove_file(p) {
        Ok(()) => {
            c.bytes += n;
            c.files += 1;
        }
        Err(_) => c.skipped += 1, // in use or protected: left alone
    }
}

/// Removes empty folders under `dir`, deepest first. `dir` itself stays.
fn prune_empty(dir: &Path) {
    let mut dirs: Vec<PathBuf> = walkdir::WalkDir::new(dir).min_depth(1).follow_links(false).into_iter().flatten().filter(|e| e.file_type().is_dir()).map(|e| e.into_path()).collect();
    dirs.sort_by_key(|p| std::cmp::Reverse(p.components().count()));
    for d in dirs {
        let _ = std::fs::remove_dir(d); // only succeeds when empty
    }
}

/// Cleans one item. Files in use are skipped and counted.
pub fn clean(item: &Item) -> Cleaned {
    let mut c = Cleaned::default();
    if !item.available {
        return c;
    }
    for t in &item.targets {
        match t {
            Target::DirContents(d) | Target::DirOlderThan(d, _) => {
                let age = if let Target::DirOlderThan(_, a) = t { Some(*a) } else { None };
                let mut files = Vec::new();
                walk_files(d, age, |p, n| files.push((p.to_path_buf(), n)));
                for (p, n) in files {
                    remove_file(&p, n, &mut c);
                }
                prune_empty(d);
            }
            Target::File(p) => {
                let n = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
                if p.exists() {
                    remove_file(p, n, &mut c);
                }
            }
            Target::FilesWithPrefix(d, pre) => {
                for p in prefixed(d, pre) {
                    let n = std::fs::metadata(&p).map(|m| m.len()).unwrap_or(0);
                    remove_file(&p, n, &mut c);
                }
            }
            Target::RecycleBin => {
                let (b, n) = recycle_bin_size();
                if n > 0 && empty_recycle_bin() {
                    c.bytes += b;
                    c.files += n;
                }
            }
        }
    }
    c
}

#[cfg(windows)]
fn recycle_bin_size() -> (u64, u64) {
    use windows_sys::Win32::UI::Shell::{SHQUERYRBINFO, SHQueryRecycleBinW};
    // SAFETY: the struct's size field is set as the API requires; a null root means all drives.
    unsafe {
        let mut info: SHQUERYRBINFO = std::mem::zeroed();
        info.cbSize = std::mem::size_of::<SHQUERYRBINFO>() as u32;
        if SHQueryRecycleBinW(std::ptr::null(), &mut info) == 0 { (info.i64Size.max(0) as u64, info.i64NumItems.max(0) as u64) } else { (0, 0) }
    }
}

#[cfg(windows)]
fn empty_recycle_bin() -> bool {
    use windows_sys::Win32::UI::Shell::{SHERB_NOCONFIRMATION, SHERB_NOPROGRESSUI, SHERB_NOSOUND, SHEmptyRecycleBinW};
    // SAFETY: no window, all drives; flags only suppress the shell's own dialogs (the app asks first).
    unsafe { SHEmptyRecycleBinW(std::ptr::null_mut(), std::ptr::null(), SHERB_NOCONFIRMATION | SHERB_NOPROGRESSUI | SHERB_NOSOUND) == 0 }
}

#[cfg(not(windows))]
fn recycle_bin_size() -> (u64, u64) {
    (0, 0)
}

#[cfg(not(windows))]
fn empty_recycle_bin() -> bool {
    false
}

/// Is any process with this name running?
pub fn is_running(process: &str) -> bool {
    let Ok(mut sys) = sysinfo::System::new() else { return false };
    sys.refresh_processes_specifics(sysinfo::ProcessesToUpdate::All, true, sysinfo::ProcessRefreshKind::nothing());
    sys.processes().values().any(|p| p.name().to_string_lossy().eq_ignore_ascii_case(process))
}

/// Asks a browser to close the way clicking its X does (no force), then waits up to 8 seconds.
/// Returns true once it's gone.
pub fn close_politely(process: &str) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let _ = std::process::Command::new("taskkill").args(["/IM", process]).creation_flags(CREATE_NO_WINDOW).output();
    }
    for _ in 0..16 {
        if !is_running(process) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn touch(p: &Path, n: usize) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, vec![0u8; n]).unwrap();
    }

    #[test]
    fn cleans_folder_contents_but_keeps_the_folder() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join("Cache");
        touch(&cache.join("a"), 100);
        touch(&cache.join("sub").join("b"), 50);
        let item = Item { id: "t:cache".into(), group: "t".into(), label: "Cache", description: "", default_on: true, available: true, targets: vec![Target::DirContents(cache.clone())] };
        let s = measure(&item);
        assert_eq!((s.bytes, s.files), (150, 2));
        let c = clean(&item);
        assert_eq!((c.bytes, c.files, c.skipped), (150, 2, 0));
        assert!(cache.is_dir());
        assert_eq!(std::fs::read_dir(&cache).unwrap().count(), 0);
    }

    #[test]
    fn recent_temp_files_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        touch(&dir.path().join("fresh.tmp"), 10);
        let item = Item { id: "t:temp".into(), group: "t".into(), label: "Temp", description: "", default_on: true, available: true, targets: vec![Target::DirOlderThan(dir.path().to_path_buf(), DAY)] };
        assert_eq!(measure(&item).files, 0);
        assert_eq!(clean(&item).files, 0);
        assert!(dir.path().join("fresh.tmp").exists());
    }

    #[test]
    fn files_in_use_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("Cookies");
        touch(&p, 10);
        // Hold the file open without delete sharing, like a running browser does.
        #[cfg(windows)]
        let _held = {
            use std::os::windows::fs::OpenOptionsExt;
            std::fs::OpenOptions::new().read(true).share_mode(0).open(&p).unwrap()
        };
        let item = Item { id: "t:cookies".into(), group: "t".into(), label: "Cookies", description: "", default_on: false, available: true, targets: vec![Target::File(p.clone())] };
        let c = clean(&item);
        #[cfg(windows)]
        {
            assert_eq!((c.files, c.skipped), (0, 1));
            assert!(p.exists());
        }
        let _ = c;
    }

    #[test]
    fn chromium_layout_is_understood() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("User Data");
        for prof in ["Default", "Profile 1"] {
            touch(&data.join(prof).join("Preferences"), 2);
            touch(&data.join(prof).join("History"), 300);
            touch(&data.join(prof).join(r"Cache\Cache_Data").join("f_000001"), 1000);
            touch(&data.join(prof).join(r"Network\Cookies"), 40);
            touch(&data.join(prof).join("Bookmarks"), 77);
        }
        touch(&data.join("ShaderCache").join("x"), 5);
        let profiles = chromium_profiles(&data);
        assert_eq!(profiles.len(), 2);
        let b = Browser { id: "chrome", name: "Chrome", engine: Engine::Chromium, exe: None, process: "chrome.exe", cache_roots: profiles.clone(), profiles };
        let items = browser_items(&b);
        let size = |id: &str| measure(items.iter().find(|i| i.id == id).unwrap()).bytes;
        assert_eq!(size("chrome:cache"), 2005);
        assert_eq!(size("chrome:history"), 600);
        assert_eq!(size("chrome:cookies"), 80);
        for i in &items {
            clean(i);
        }
        // Bookmarks and settings are never touched.
        assert!(data.join(r"Default\Bookmarks").exists() && data.join(r"Profile 1\Preferences").exists());
        assert!(!data.join(r"Default\History").exists());
    }

    #[test]
    fn real_pc_lists_items_without_error() {
        let b = browsers();
        let items = all_items(&b);
        assert!(items.iter().any(|i| i.id == "windows:temp"));
        assert!(items.iter().filter(|i| i.group == "windows").count() == 5);
    }
}
