//! Real-time shields, in user mode (no driver, no admin, no paid certificates):
//!
//! - File shield: watches Downloads, Desktop and the Startup folders. A new or changed file is
//!   scanned once it has stopped changing; half-finished downloads are skipped.
//! - Process shield: every program that starts is scanned once per version of its file.
//! - ClickFix shield: watches the clipboard for "paste this to verify you're human" commands and
//!   replaces clear-cut ones with a harmless warning; also checks the Win+R history.
//! - Stealer shield: asks Windows (Restart Manager) which processes have browser, chat-app and
//!   wallet secrets open, and flags anything that isn't the app that owns them. Quick reads can
//!   slip between polls; a background service with file-access events closes that gap later.
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
    /// The file involved, when there is one (it becomes a Results row with Quarantine/Delete/Allow).
    pub report: Option<FileReport>,
    /// Headline for alerts without a file (ClickFix).
    pub title: String,
    /// What the shield did, in plain words.
    pub action: String,
    /// Whether the file is now in quarantine.
    pub quarantined: bool,
    /// ClickFix: the UI thread should replace the clipboard with a harmless warning.
    pub neutralize: bool,
}

#[derive(Default)]
pub struct ShieldStats {
    pub files_checked: AtomicU64,
    pub programs_checked: AtomicU64,
    pub copies_checked: AtomicU64,
    pub stores_watched: AtomicU64,
    /// Files extracted from downloads that got their "from the internet" mark back.
    pub files_marked: AtomicU64,
    /// Kernel drivers known (for the new-driver alert).
    pub drivers_known: AtomicU64,
}

pub struct Shields {
    engine: Arc<RwLock<Option<Arc<Engine>>>>,
    events: Arc<Mutex<Vec<ShieldEvent>>>,
    pub file_on: Arc<AtomicBool>,
    pub process_on: Arc<AtomicBool>,
    pub clickfix_on: Arc<AtomicBool>,
    pub stealer_on: Arc<AtomicBool>,
    pub auto_quarantine: Arc<AtomicBool>,
    /// Script shield (AMSI): judge scripts the provider DLL hands over.
    pub script_on: Arc<AtomicBool>,
    /// Ransomware shield (decoy files and encryption bursts).
    pub ransom_on: Arc<AtomicBool>,
    pub stats: Arc<ShieldStats>,
    pub watched: Vec<PathBuf>,
    _watcher: Option<notify::RecommendedWatcher>,
}

const MAX_SIZE: u64 = 64 * 1024 * 1024;

/// Opt-in cloud switches (Settings › Cloud). Both off by default.
pub static CLOUD_REPUTATION: AtomicBool = AtomicBool::new(false);
pub static CLOUD_REPORTS: AtomicBool = AtomicBool::new(false);
/// Document backup for ransomware rollback (Settings › Document backup).
pub static BACKUP_ON: AtomicBool = AtomicBool::new(true);
/// When the ransomware shield last raised an alarm (Unix seconds; 0 = never).
pub static LAST_RANSOM_ALARM: std::sync::atomic::AtomicI64 = std::sync::atomic::AtomicI64::new(0);

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Restores files damaged since shortly before the last ransomware alarm (or the last 2 hours).
pub fn restore_files() -> Vec<hexward_engine::backup::Restored> {
    use hexward_engine::backup::{Backup, minutes_ago};
    let alarm = LAST_RANSOM_ALARM.load(Ordering::Relaxed);
    let since = if alarm > 0 && unix_now() - alarm < 7 * 86400 { alarm - 15 * 60 } else { minutes_ago(120) };
    Backup::open(Backup::default_dir()).restore(since, false)
}

/// Kinds of file worth a cloud lookup when the local engine found nothing: programs and scripts.
fn worth_a_lookup(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "exe" | "dll" | "scr" | "com" | "msi" | "msix" | "appx" | "sys" | "cpl" | "ps1" | "psm1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "hta" | "bat" | "cmd" | "lnk" | "jar" | "iso" | "img" | "vhd" | "vhdx" | "zip" | "rar" | "7z"
    )
}

/// Cloud reputation (opt-in): only the first 6 hex characters of the hash are sent; the full hash is
/// compared here. Known malware the local lists don't have yet becomes a confirmed detection; a
/// suspicious-only verdict on a file the community allow-listed is dropped.
pub fn cloud_judge(report: &mut FileReport) {
    use hexward_engine::{Detection, Severity, Source};
    use hexward_update::cloud::{self, Reputation};
    if !CLOUD_REPUTATION.load(Ordering::Relaxed) {
        return;
    }
    let clean = report.detections.is_empty();
    if clean && !worth_a_lookup(&report.path) {
        return;
    }
    if !clean && report.is_confirmed() {
        return; // already certain; nothing the cloud could change
    }
    match cloud::lookup(&report.sha256) {
        Ok(Reputation::Bad { name, source }) => {
            report.detections.push(Detection::new(
                name,
                Severity::High,
                Source::Hash,
                format!("Hexward's cloud knows this exact file as malware (from {source})."),
            ));
            return;
        }
        Ok(Reputation::Allowed { .. }) => {
            report.detections.clear();
            return;
        }
        _ => {}
    }
    // Signer reputation: certificates known to sign malware (often stolen), and trusted publishers.
    let ext = report.path.extension().and_then(|e| e.to_str()).unwrap_or("").to_ascii_lowercase();
    if matches!(ext.as_str(), "exe" | "dll" | "msi" | "sys" | "scr")
        && let Some(signer) = hexward_engine::sig::signer_name(&report.path)
    {
        report.signed = Some(true);
        match cloud::signer_verdict(&signer).as_deref() {
            Some("bad") => report.detections.push(Detection::new(
                "Malware/Win.BadSigner!cloud",
                Severity::High,
                Source::Rule,
                format!("Signed by \"{signer}\", a certificate Hexward's cloud knows is used to sign malware."),
            )),
            Some("trusted") => report.detections.clear(), // only suspicious finds reach here
            _ => {}
        }
    }
}

/// Detection report (opt-in): file name, hash, detection name, version. Sent in the background.
pub fn cloud_report(report: &FileReport) {
    if !CLOUD_REPORTS.load(Ordering::Relaxed) || report.detections.is_empty() {
        return;
    }
    let r = hexward_update::cloud::Report {
        kind: hexward_update::cloud::Kind::Detection,
        sha256: Some(report.sha256.clone()),
        name: report.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        detection: report.detections[0].name.clone(),
        signer: None,
    };
    std::thread::spawn(move || {
        let _ = hexward_update::cloud::send_report(&r);
    });
}
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
    pub fn start(file_on: bool, process_on: bool, clickfix_on: bool, stealer_on: bool, auto_quarantine: bool, script_on: bool) -> Self {
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
                    hexward_engine::perf::background_thread();
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
                            // Extracted from a downloaded archive without the "from the internet" mark?
                            // Put the mark back, so Windows and Office warn as they should.
                            if hexward_engine::motw::propagate(&path).is_some() {
                                stats.files_marked.fetch_add(1, Ordering::Relaxed);
                            }
                            let mut scanner = eng.rules().scanner();
                            if let Ok(Some(mut report)) = eng.scan_file(&mut scanner, &path, MAX_SIZE) {
                                stats.files_checked.fetch_add(1, Ordering::Relaxed);
                                cloud_judge(&mut report);
                                if !report.detections.is_empty() {
                                    cloud_report(&report);
                                    let origin = hexward_engine::motw::read(&path).and_then(|m| m.host_url.or(m.referrer_url));
                                    let mut ev = act(report, "File shield", auto.load(Ordering::Relaxed), None);
                                    if let Some(o) = origin {
                                        ev.action.push_str(&format!(" It was downloaded from {}.", hexward_engine::audit::snippet(&o, 90)));
                                    }
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
                    hexward_engine::perf::background_thread();
                    let Ok(mut sys) = System::new() else { return };
                    let mut seen_pids: HashSet<sysinfo::Pid> = HashSet::new();
                    let mut checked: HashSet<u64> = HashSet::new();
                    let me = std::process::id();
                    let mut first = true;
                    loop {
                        // Every second: short-lived droppers (mshta, regsvr32) are gone within a few.
                        std::thread::sleep(Duration::from_secs(1));
                        if !process_on.load(Ordering::Relaxed) {
                            continue;
                        }
                        let Some(eng) = engine.read().ok().and_then(|e| e.clone()) else { continue };
                        sys.refresh_processes_specifics(ProcessesToUpdate::All, true, ProcessRefreshKind::nothing().with_exe(UpdateKind::OnlyIfNotSet).with_cmd(UpdateKind::OnlyIfNotSet));
                        let alive: HashSet<sysinfo::Pid> = sys.processes().keys().copied().collect();
                        for (pid, proc_) in sys.processes() {
                            if seen_pids.contains(pid) || pid.as_u32() == me {
                                continue;
                            }
                            // Who started it, and how (skipped on the first pass: those were already running).
                            if !first && let Some(parent) = proc_.parent().and_then(|pp| sys.process(pp)) {
                                let cmd = proc_.cmd().iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>().join(" ");
                                let child = proc_.name().to_string_lossy();
                                if let Some(v) = hexward_engine::chains::judge(&parent.name().to_string_lossy(), &child, &cmd) {
                                    let high = v.severity == hexward_engine::Severity::High;
                                    let stopped = high && auto.load(Ordering::Relaxed) && proc_.kill();
                                    push(
                                        &events,
                                        ShieldEvent {
                                            shield: "Process shield",
                                            report: None,
                                            title: format!("{} started {}", parent.name().to_string_lossy(), child),
                                            action: format!("{}{}", v.reason, if stopped { " Hexward stopped it." } else { " Hexward let it run; end it in Tasks if you didn't expect it." }),
                                            quarantined: false,
                                            neutralize: false,
                                        },
                                    );
                                }
                            }
                            let Some(exe) = proc_.exe() else { continue };
                            let Some(key) = file_key(exe) else { continue };
                            if !checked.insert(key) {
                                continue;
                            }
                            let mut scanner = eng.rules().scanner();
                            if let Ok(Some(mut report)) = eng.scan_file(&mut scanner, exe, MAX_SIZE) {
                                stats.programs_checked.fetch_add(1, Ordering::Relaxed);
                                cloud_judge(&mut report);
                                if !report.detections.is_empty() {
                                    cloud_report(&report);
                                    let stop = || proc_.kill();
                                    let ev = act(report, "Process shield", auto.load(Ordering::Relaxed), Some(&stop));
                                    if let Ok(mut e) = events.lock() {
                                        e.push(ev);
                                    }
                                }
                            }
                        }
                        seen_pids = alive;
                        first = false;
                        if checked.len() > 50_000 {
                            checked.clear();
                        }
                    }
                })
                .ok();
        }

        // ---- script shield: the AMSI provider's pipe ----
        let script_on = Arc::new(AtomicBool::new(script_on));
        {
            let (engine, events, on) = (engine.clone(), events.clone(), script_on.clone());
            std::thread::Builder::new().name("script-shield".into()).spawn(move || crate::amsi::serve(engine, on, events)).ok();
        }

        // ---- ransomware shield: decoy files, encryption bursts ----
        let ransom_on = Arc::new(AtomicBool::new(true));
        {
            let (events, on, auto) = (events.clone(), ransom_on.clone(), auto.clone());
            std::thread::Builder::new()
                .name("ransomware-shield".into())
                .spawn(move || {
                    use hexward_engine::ransom::{BurstWatch, Change, ensure_canaries, looks_encrypted, top_writer, touched};
                    hexward_engine::perf::background_thread();
                    let folders: Vec<PathBuf> = [dirs::document_dir(), dirs::desktop_dir(), dirs::picture_dir(), dirs::audio_dir(), dirs::video_dir()].into_iter().flatten().filter(|p| p.is_dir()).collect();
                    // Development builds don't put decoys in the developer's folders.
                    let dev = std::env::current_exe().map(|e| e.to_string_lossy().to_ascii_lowercase().contains(r"\target\")).unwrap_or(true);
                    let store = data_dir().join("canaries.json");
                    let mut canaries = if dev { Vec::new() } else { ensure_canaries(&folders, &store) };
                    let (tx, rx) = std::sync::mpsc::channel::<(PathBuf, Change)>();
                    let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                        let Ok(ev) = res else { return };
                        use notify::EventKind::{Create, Modify, Remove};
                        use notify::event::ModifyKind;
                        let change = match ev.kind {
                            Modify(ModifyKind::Name(_)) => Change::Renamed,
                            Create(_) | Modify(_) => Change::Modified,
                            Remove(_) => Change::Removed,
                            _ => return,
                        };
                        if let Some(p) = ev.paths.last() {
                            let _ = tx.send((p.clone(), change));
                        }
                    })
                    .ok();
                    if let Some(w) = watcher.as_mut() {
                        for f in &folders {
                            let _ = w.watch(f, notify::RecursiveMode::Recursive);
                        }
                    }
                    let Ok(mut sys) = sysinfo::System::new() else { return };
                    let mut burst = BurstWatch::new(Duration::from_secs(10));
                    let mut quiet_until = Instant::now();
                    loop {
                        std::thread::sleep(Duration::from_secs(1));
                        let writer = top_writer(&mut sys); // keeps disk-usage counters per second
                        let mut checked = 0;
                        while let Ok((path, change)) = rx.try_recv() {
                            if path.file_name().is_some_and(|n| n.to_string_lossy().contains("hexward-canary")) {
                                continue;
                            }
                            let enc = change != Change::Removed && checked < 300 && {
                                checked += 1;
                                looks_encrypted(&path)
                            };
                            burst.record(Instant::now(), path, change, enc);
                        }
                        if !on.load(Ordering::Relaxed) || Instant::now() < quiet_until {
                            continue;
                        }
                        let hit = touched(&canaries);
                        let reason = if !hit.is_empty() {
                            Some(format!("A decoy file Hexward keeps in your folders was changed or removed ({}).", hit[0].display()))
                        } else {
                            burst.check().map(|a| format!("{}.", a.reason))
                        };
                        let Some(reason) = reason else { continue };
                        LAST_RANSOM_ALARM.store(unix_now(), Ordering::Relaxed);
                        let mut action = format!("{reason} That's how ransomware behaves.");
                        match &writer {
                            Some((pid, name, exe)) => {
                                let stopped = auto.load(Ordering::Relaxed) && sysinfo::Pid::from_u32(*pid).as_u32() > 0 && sys.process(sysinfo::Pid::from_u32(*pid)).is_some_and(|p| p.kill());
                                action.push_str(&format!(
                                    " The unsigned program writing the most was {name}{}. {}",
                                    exe.as_ref().map(|e| format!(" ({})", e.display())).unwrap_or_default(),
                                    if stopped { "Hexward stopped it. Scan it, and don't restart it." } else { "End it in Tasks now if you don't recognize it." }
                                ));
                            }
                            None => action.push_str(" No unsigned program was writing heavily; if you're copying or converting lots of files yourself, that's the cause."),
                        }
                        if BACKUP_ON.load(Ordering::Relaxed) {
                            action.push_str(" If files were damaged, Settings › Document backup › Restore puts them back.");
                        }
                        push(&events, ShieldEvent { shield: "Ransomware shield", report: None, title: "Possible ransomware activity".into(), action, quarantined: false, neutralize: false });
                        burst.clear();
                        quiet_until = Instant::now() + Duration::from_secs(60);
                        if !dev {
                            canaries = ensure_canaries(&folders, &store);
                        }
                    }
                })
                .ok();
        }

        // ---- document backup: a private copy of documents and photos, for ransomware rollback ----
        {
            let on = ransom_on.clone();
            std::thread::Builder::new()
                .name("document-backup".into())
                .spawn(move || {
                    use hexward_engine::backup::{Backup, DEFAULT_BUDGET};
                    hexward_engine::perf::background_thread();
                    // Development builds don't copy the developer's documents.
                    if std::env::current_exe().map(|e| e.to_string_lossy().to_ascii_lowercase().contains(r"\target\")).unwrap_or(true) {
                        return;
                    }
                    let may_run = || {
                        BACKUP_ON.load(Ordering::Relaxed)
                            && on.load(Ordering::Relaxed)
                            && unix_now() - LAST_RANSOM_ALARM.load(Ordering::Relaxed) > 6 * 3600 // never during or right after an attack
                            && !hexward_engine::perf::on_battery()
                            && hexward_engine::perf::quiet_reason().is_none()
                    };
                    std::thread::sleep(Duration::from_secs(180));
                    loop {
                        if may_run() {
                            let bk = Backup::open(Backup::default_dir());
                            let _ = bk.sync(&Backup::default_roots(), DEFAULT_BUDGET, &|| !may_run());
                        }
                        std::thread::sleep(Duration::from_secs(30 * 60));
                    }
                })
                .ok();
        }

        // ---- driver watch: alert when a new kernel driver is installed ----
        {
            let (engine, events, process_on, stats) = (engine.clone(), events.clone(), process_on.clone(), stats.clone());
            std::thread::Builder::new()
                .name("driver-watch".into())
                .spawn(move || {
                    hexward_engine::perf::background_thread();
                    let seen_path = data_dir().join("drivers-seen.json");
                    let mut seen: HashSet<String> = std::fs::read(&seen_path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
                    let first_run = seen.is_empty();
                    loop {
                        let Some(eng) = engine.read().ok().and_then(|e| e.clone()) else {
                            std::thread::sleep(Duration::from_secs(5));
                            continue;
                        };
                        if process_on.load(Ordering::Relaxed) {
                            let now = hexward_engine::drivers::installed_drivers();
                            stats.drivers_known.store(now.len() as u64, Ordering::Relaxed);
                            let mut changed = false;
                            for (name, path) in &now {
                                if !seen.insert(name.to_lowercase()) {
                                    continue;
                                }
                                changed = true;
                                if first_run {
                                    continue; // the first look only records what's already there
                                }
                                let mut scanner = eng.rules().scanner();
                                let report = eng.scan_file(&mut scanner, path, MAX_SIZE).ok().flatten();
                                let signed = hexward_engine::sig::is_signed(path);
                                let publisher = hexward_engine::fileinfo::company(path).unwrap_or_else(|| "unknown publisher".into());
                                match report {
                                    Some(r) if !r.detections.is_empty() => push(&events, act(r, "Driver watch", false, None)),
                                    _ => push(
                                        &events,
                                        ShieldEvent {
                                            shield: "Driver watch",
                                            report: None,
                                            title: format!("New kernel driver: {name}"),
                                            action: format!(
                                                "{} ({publisher}, {}). Drivers run inside Windows itself. If you just installed hardware or software that needs it, that's expected.",
                                                path.display(),
                                                if signed { "signed" } else { "NOT signed" }
                                            ),
                                            quarantined: false,
                                            neutralize: false,
                                        },
                                    ),
                                }
                            }
                            if changed && let Ok(b) = serde_json::to_vec(&seen) {
                                let _ = std::fs::create_dir_all(data_dir());
                                let _ = std::fs::write(&seen_path, b);
                            }
                        }
                        std::thread::sleep(Duration::from_secs(60));
                    }
                })
                .ok();
        }

        // ---- ClickFix shield: watch the clipboard for "paste this command" lures ----
        let clickfix_on = Arc::new(AtomicBool::new(clickfix_on));
        {
            let (events, on, stats) = (events.clone(), clickfix_on.clone(), stats.clone());
            std::thread::Builder::new()
                .name("clickfix-shield".into())
                .spawn(move || {
                    let mut last_seq = crate::clipboard::sequence();
                    let mut reported_history: HashSet<String> = HashSet::new();
                    let mut next_history = Instant::now();
                    loop {
                        std::thread::sleep(Duration::from_millis(250));
                        if !on.load(Ordering::Relaxed) {
                            continue;
                        }
                        // Commands already pasted into Win+R earlier (checked every minute).
                        if Instant::now() >= next_history {
                            next_history = Instant::now() + Duration::from_secs(60);
                            for (cmd, v) in hexward_engine::behavior::run_history_hits() {
                                if reported_history.insert(cmd.clone()) {
                                    let short: String = cmd.chars().take(90).collect();
                                    push(&events, ShieldEvent {
                                        shield: "ClickFix shield",
                                        report: None,
                                        title: "A risky command was run from Win+R".into(),
                                        action: format!("Your Run history has a command that {}: \"{short}\". If you didn't type it yourself, run a full scan.", v.reasons.join(", ")),
                                        quarantined: false,
                                        neutralize: false,
                                    });
                                }
                            }
                        }
                        let seq = crate::clipboard::sequence();
                        if seq == last_seq {
                            continue;
                        }
                        last_seq = seq;
                        let Some(text) = crate::clipboard::read_text() else { continue };
                        stats.copies_checked.fetch_add(1, Ordering::Relaxed);
                        if text == crate::clipboard::NEUTRALIZED {
                            continue;
                        }
                        let Some(v) = hexward_engine::behavior::clickfix_score(&text) else { continue };
                        let from = hexward_engine::behavior::process_path(crate::clipboard::foreground_pid())
                            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                            .unwrap_or_else(|| "a window".into());
                        let block = v.level == hexward_engine::behavior::ClickFixLevel::Block;
                        push(&events, ShieldEvent {
                            shield: "ClickFix shield",
                            report: None,
                            title: if block { "Blocked a fake \"verify you're human\" command".into() } else { "The command you copied downloads and runs code".into() },
                            action: if block {
                                format!("Something in {from} copied a command that {}. Hexward replaced it, so pasting it does nothing. Never paste commands a website gives you.", v.reasons.join(", "))
                            } else {
                                format!("Copied from {from}: it {}. Only paste it if you trust where it came from.", v.reasons.join(", "))
                            },
                            quarantined: false,
                            neutralize: block,
                        });
                    }
                })
                .ok();
        }

        // ---- Stealer shield: who has browser, chat and wallet secrets open? ----
        let stealer_on = Arc::new(AtomicBool::new(stealer_on));
        {
            let (engine, events, on, auto, stats) = (engine.clone(), events.clone(), stealer_on.clone(), auto.clone(), stats.clone());
            std::thread::Builder::new()
                .name("stealer-shield".into())
                .spawn(move || {
                    hexward_engine::perf::background_thread();
                    use hexward_engine::behavior::{ALWAYS_OK, credential_stores, process_path, processes_using};
                    let me = std::process::id();
                    let mut stores = credential_stores();
                    let mut refreshed = Instant::now();
                    let mut reported: HashSet<PathBuf> = HashSet::new();
                    loop {
                        std::thread::sleep(Duration::from_millis(1500));
                        if !on.load(Ordering::Relaxed) {
                            continue;
                        }
                        if refreshed.elapsed() > Duration::from_secs(300) {
                            stores = credential_stores();
                            refreshed = Instant::now();
                        }
                        stats.stores_watched.store(stores.len() as u64, Ordering::Relaxed);
                        let Some(eng) = engine.read().ok().and_then(|e| e.clone()) else { continue };
                        // One Restart Manager query per app, so each hit knows whose secrets were opened.
                        let mut apps: Vec<&str> = stores.iter().map(|s| s.app).collect();
                        apps.dedup();
                        for app in apps {
                            let group: Vec<&hexward_engine::behavior::Store> = stores.iter().filter(|s| s.app == app).collect();
                            let files: Vec<PathBuf> = group.iter().map(|s| s.path.clone()).collect();
                            for user in processes_using(&files) {
                                if user.pid == me {
                                    continue;
                                }
                                let Some(exe) = process_path(user.pid) else { continue };
                                let name = exe.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
                                if ALWAYS_OK.contains(&name.as_str()) || group[0].owners.contains(&name.as_str()) || !reported.insert(exe.clone()) {
                                    continue;
                                }
                                push(&events, stealer_event(&eng, &exe, app, user.pid, auto.load(Ordering::Relaxed)));
                            }
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
            clickfix_on,
            stealer_on,
            auto_quarantine: auto,
            script_on,
            ransom_on,
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
        // (events are pushed by the shield threads through push())
        self.events.lock().map(|mut e| std::mem::take(&mut *e)).unwrap_or_default()
    }
}

fn push(events: &Mutex<Vec<ShieldEvent>>, ev: ShieldEvent) {
    if let Ok(mut e) = events.lock() {
        e.push(ev);
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
        let (action, quarantined) = match moved {
            Ok(_) => (if stopped { "Stopped it and moved it to quarantine.".to_string() } else { "Moved it to quarantine automatically.".to_string() }, true),
            Err(e) => (format!("Couldn't move it to quarantine: {e}"), false),
        };
        return file_event(shield, report, action, quarantined);
    }
    let action = if report.is_confirmed() {
        "Left in place because automatic quarantine is off. Open Hexward to decide.".to_string()
    } else {
        "Suspicious, not confirmed: left in place. Open Hexward to decide.".to_string()
    };
    file_event(shield, report, action, false)
}

fn file_event(shield: &'static str, report: FileReport, action: String, quarantined: bool) -> ShieldEvent {
    ShieldEvent { shield, title: String::new(), report: Some(report), action, quarantined, neutralize: false }
}

/// Stealer shield verdict for a process that opened another app's secrets.
fn stealer_event(eng: &Engine, exe: &Path, app: &str, pid: u32, auto: bool) -> ShieldEvent {
    use hexward_engine::{Detection, Severity, Source};
    let signed = hexward_engine::sig::is_signed(exe);
    let lower = exe.to_string_lossy().to_lowercase();
    // Where stealers run from: places any program can write without admin rights.
    let risky_place = ["\\appdata\\local\\temp\\", "\\downloads\\", "\\appdata\\roaming\\", "\\programdata\\", "\\users\\public\\"].iter().any(|p| lower.contains(p));
    let mut scanner = eng.rules().scanner();
    let mut report = eng.scan_file(&mut scanner, exe, MAX_SIZE).ok().flatten().unwrap_or(FileReport {
        path: exe.to_path_buf(),
        size: 0,
        sha256: String::new(),
        detections: Vec::new(),
        signed: Some(signed),
    });
    let name = exe.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    report.detections.insert(
        0,
        Detection::new(
            "Suspicious/Win.StealerBehavior!b",
            if signed { Severity::Medium } else { Severity::High },
            Source::Heuristic,
            format!(
                "{name} opened {app}'s saved passwords, cookies or keys. Only {app} itself should do that{}.",
                if signed { "; it is digitally signed, so it may be a backup or import tool" } else { "; it is not signed, which is how password stealers usually look" }
            ),
        ),
    );
    if auto && !signed && risky_place && !report.sha256.is_empty() {
        let stopped = (|| {
            use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
            let mut sys = System::new().ok()?;
            let pid = Pid::from_u32(pid);
            sys.refresh_processes_specifics(ProcessesToUpdate::Some(&[pid]), true, ProcessRefreshKind::nothing());
            Some(sys.process(pid)?.kill())
        })()
        .unwrap_or(false);
        if stopped {
            std::thread::sleep(Duration::from_millis(300));
        }
        let moved = Vault::open(Vault::default_dir()).and_then(|v| v.quarantine(exe, "Suspicious/Win.StealerBehavior!b"));
        let (action, q) = match moved {
            Ok(_) => (format!("Stopped it and moved it to quarantine (unsigned, running from {}).", exe.parent().map(|p| p.display().to_string()).unwrap_or_default()), true),
            Err(e) => (format!("{}Couldn't quarantine it: {e}", if stopped { "Stopped it. " } else { "" }), false),
        };
        return file_event("Stealer shield", report, action, q);
    }
    file_event("Stealer shield", report, "Left running. Open Hexward to quarantine, delete or allow it.".into(), false)
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
