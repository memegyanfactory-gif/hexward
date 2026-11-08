//! Real-time shields, in user mode (no driver, no admin, no paid certificates):
//!
//! - File shield: watches Downloads, Desktop and the Startup folders. A new or changed file is
//!   scanned once it has stopped changing; half-finished downloads are skipped.
//! - Process shield: every program that starts is scanned once per version of its file.
//!
//! Only confirmed threats are acted on automatically (quarantined; their process stopped first).
//! Suspicious files are reported and left alone, so an old game or a home-made tool is never broken.
//! User mode means detection right after a file lands or a program starts, not before; Microsoft
//! Defender keeps doing pre-execution blocking (see docs/STRATEGY.md §0).

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use hexward_engine::{Engine, FileReport, Vault, data_dir};
use notify::Watcher;

pub struct ShieldEvent {
    pub shield: &'static str,
    pub report: FileReport,
    /// What the shield did, in plain words.
    pub action: String,
    /// Whether the file is now in quarantine.
    pub quarantined: bool,
}

#[derive(Default)]
pub struct ShieldStats {
    pub files_checked: AtomicU64,
    pub programs_checked: AtomicU64,
}

pub struct Shields {
    engine: Arc<RwLock<Option<Arc<Engine>>>>,
    events: Arc<Mutex<Vec<ShieldEvent>>>,
    pub file_on: Arc<AtomicBool>,
    pub process_on: Arc<AtomicBool>,
    pub auto_quarantine: Arc<AtomicBool>,
    pub stats: Arc<ShieldStats>,
    pub watched: Vec<PathBuf>,
    _watcher: Option<notify::RecommendedWatcher>,
}

const MAX_SIZE: u64 = 64 * 1024 * 1024;
/// A file must stop changing for this long before it is scanned (downloads finishing, installers writing).
const SETTLE: Duration = Duration::from_millis(1500);

fn watch_list() -> Vec<(PathBuf, notify::RecursiveMode)> {
    use notify::RecursiveMode::{NonRecursive, Recursive};
    let mut v = Vec::new();
    v.extend(dirs::download_dir().map(|p| (p, Recursive)));
    v.extend(dirs::desktop_dir().map(|p| (p, Recursive)));
    if let Some(roaming) = dirs::data_dir() {
        v.push((roaming.join(r"Microsoft\Windows\Start Menu\Programs\Startup"), NonRecursive));
    }
    if let Some(pd) = std::env::var_os("ProgramData") {
        v.push((PathBuf::from(pd).join(r"Microsoft\Windows\Start Menu\Programs\StartUp"), NonRecursive));
    }
    if let Some(public) = std::env::var_os("PUBLIC") {
        v.push((PathBuf::from(public).join("Downloads"), Recursive));
    }
    v.into_iter().filter(|(p, _)| p.is_dir()).collect()
}

/// Browsers and download managers write to these until the download completes, then rename.
fn is_partial(p: &Path) -> bool {
    let e = p.extension().map(|e| e.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    matches!(e.as_str(), "crdownload" | "part" | "partial" | "download" | "opdownload" | "tmp" | "!ut" | "aria2")
}

fn file_key(p: &Path) -> Option<u64> {
    let m = std::fs::metadata(p).ok()?;
    m.is_file().then(|| hexward_engine::cache::ScanCache::key(p, &m))
}

impl Shields {
    pub fn start(file_on: bool, process_on: bool, auto_quarantine: bool) -> Self {
        let engine: Arc<RwLock<Option<Arc<Engine>>>> = Arc::new(RwLock::new(None));
        let events = Arc::new(Mutex::new(Vec::new()));
        let file_on = Arc::new(AtomicBool::new(file_on));
        let process_on = Arc::new(AtomicBool::new(process_on));
        let auto = Arc::new(AtomicBool::new(auto_quarantine));
        let stats = Arc::new(ShieldStats::default());

        // ---- file shield ----
        let pending: Arc<Mutex<HashMap<PathBuf, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
        let own_data = data_dir().to_string_lossy().to_lowercase();
        let watcher = {
            let pending = pending.clone();
            let own = own_data.clone();
            notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                let Ok(ev) = res else { return };
                if !matches!(ev.kind, notify::EventKind::Create(_) | notify::EventKind::Modify(_)) {
                    return;
                }
                if let Ok(mut p) = pending.lock() {
                    for path in ev.paths {
                        if !path.to_string_lossy().to_lowercase().starts_with(&own) && p.len() < 50_000 {
                            p.insert(path, Instant::now());
                        }
                    }
                }
            })
            .ok()
        };
        let mut watcher = watcher;
        let list = watch_list();
        if let Some(w) = watcher.as_mut() {
            for (path, mode) in &list {
                let _ = w.watch(path, *mode);
            }
        }
        {
            let (engine, events, file_on, auto, stats) = (engine.clone(), events.clone(), file_on.clone(), auto.clone(), stats.clone());
            std::thread::Builder::new()
                .name("file-shield".into())
                .spawn(move || {
                    let mut last: HashMap<PathBuf, u64> = HashMap::new();
                    loop {
                        std::thread::sleep(Duration::from_millis(400));
                        let ready: Vec<PathBuf> = {
                            let Ok(mut p) = pending.lock() else { continue };
                            let now = Instant::now();
                            let done: Vec<PathBuf> = p.iter().filter(|(_, t)| now.duration_since(**t) >= SETTLE).map(|(k, _)| k.clone()).collect();
                            for k in &done {
                                p.remove(k);
                            }
                            done
                        };
                        if !file_on.load(Ordering::Relaxed) {
                            continue;
                        }
                        let Some(eng) = engine.read().ok().and_then(|e| e.clone()) else { continue };
                        for path in ready {
                            if is_partial(&path) {
                                continue;
                            }
                            let Some(key) = file_key(&path) else { continue };
                            if last.get(&path) == Some(&key) {
                                continue; // same version already checked
                            }
                            last.insert(path.clone(), key);
                            if last.len() > 100_000 {
                                last.clear();
                            }
                            let mut scanner = eng.rules().scanner();
                            if let Ok(Some(report)) = eng.scan_file(&mut scanner, &path, MAX_SIZE) {
                                stats.files_checked.fetch_add(1, Ordering::Relaxed);
                                if !report.detections.is_empty() {
                                    let ev = act(report, "File shield", auto.load(Ordering::Relaxed), None);
                                    if let Ok(mut e) = events.lock() {
                                        e.push(ev);
                                    }
                                }
                            }
                        }
                    }
                })
                .ok();
        }

        // ---- process shield ----
        {
            let (engine, events, process_on, auto, stats) = (engine.clone(), events.clone(), process_on.clone(), auto.clone(), stats.clone());
            std::thread::Builder::new()
                .name("process-shield".into())
                .spawn(move || {
                    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
                    let Ok(mut sys) = System::new() else { return };
                    let mut seen_pids: HashSet<sysinfo::Pid> = HashSet::new();
                    let mut checked: HashSet<u64> = HashSet::new();
                    let me = std::process::id();
                    loop {
                        std::thread::sleep(Duration::from_secs(2));
                        if !process_on.load(Ordering::Relaxed) {
                            continue;
                        }
                        let Some(eng) = engine.read().ok().and_then(|e| e.clone()) else { continue };
                        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet));
                        let alive: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
                        for (pid, proc_) in sys.processes() {
                            if seen_pids.contains(pid) || pid.as_u32() == me {
                                continue;
                            }
                            let Some(exe) = proc_.exe() else { continue };
                            let Some(key) = file_key(exe) else { continue };
                            if !checked.insert(key) {
                                continue;
                            }
                            let mut scanner = eng.rules().scanner();
                            if let Ok(Some(report)) = eng.scan_file(&mut scanner, exe, MAX_SIZE) {
                                stats.programs_checked.fetch_add(1, Ordering::Relaxed);
                                if !report.detections.is_empty() {
                                    let stop = || proc_.kill();
                                    let ev = act(report, "Process shield", auto.load(Ordering::Relaxed), Some(&stop));
                                    if let Ok(mut e) = events.lock() {
                                        e.push(ev);
                                    }
                                }
                            }
                        }
                        seen_pids = alive;
                        if checked.len() > 50_000 {
                            checked.clear();
                        }
                    }
                })
                .ok();
        }

        Shields {
            engine,
            events,
            file_on,
            process_on,
            auto_quarantine: auto,
            stats,
            watched: list.into_iter().map(|(p, _)| p).collect(),
            _watcher: watcher,
        }
    }

    pub fn set_engine(&self, e: Arc<Engine>) {
        if let Ok(mut g) = self.engine.write() {
            *g = Some(e);
        }
    }

    pub fn drain(&self) -> Vec<ShieldEvent> {
        self.events.lock().map(|mut e| std::mem::take(&mut *e)).unwrap_or_default()
    }
}

/// Decides what happens to a hit. Confirmed + auto: stop the process (if any), then quarantine.
fn act(report: FileReport, shield: &'static str, auto: bool, stop: Option<&dyn Fn() -> bool>) -> ShieldEvent {
    if auto && report.is_confirmed() {
        let stopped = stop.map(|s| s()).unwrap_or(false);
        if stopped {
            std::thread::sleep(Duration::from_millis(300)); // let Windows release the file
        }
        let moved = Vault::open(Vault::default_dir()).and_then(|v| v.quarantine(&report.path, &report.detections[0].name));
        return match moved {
            Ok(_) => ShieldEvent {
                shield,
                action: if stopped { "Stopped it and moved it to quarantine.".into() } else { "Moved it to quarantine automatically.".into() },
                quarantined: true,
                report,
            },
            Err(e) => ShieldEvent { shield, action: format!("Couldn't move it to quarantine: {e}"), quarantined: false, report },
        };
    }
    let action = if report.is_confirmed() {
        "Left in place because automatic quarantine is off. Open Hexward to decide.".to_string()
    } else {
        "Suspicious, not confirmed: left in place. Open Hexward to decide.".to_string()
    };
    ShieldEvent { shield, action, quarantined: false, report }
}

/// Folders the file shield watches, for display.
pub fn describe(watched: &[PathBuf]) -> String {
    let mut names: Vec<String> = Vec::new();
    for n in watched.iter().filter_map(|p| p.file_name()).map(|n| n.to_string_lossy().into_owned()) {
        if !names.iter().any(|x| x.eq_ignore_ascii_case(&n)) {
            names.push(n);
        }
    }
    if names.is_empty() { "no folders".into() } else { names.join(", ") }
}
