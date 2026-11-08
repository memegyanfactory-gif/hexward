//! Hexward desktop app (Slint). Heavy work runs on background threads; one 100 ms UI timer
//! pulls progress and results, so the window never waits on a scan.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[allow(dead_code)]
mod art;
mod cleanui;
mod clipboard;
mod icons;
mod shields;
mod taskman;
mod shots;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{Datelike, Days, Local, NaiveDate, Utc};
use hexward_engine::history::{self, Event, EventKind};
use hexward_engine::scan::count_files;
use hexward_engine::startup::{self, StartupItem};
use hexward_engine::{Detection, Engine, FileReport, Progress, ScanOptions, ScanSummary, Severity, Vault, allowlist, data_dir, locations};
use hexward_update::app::{self as appupdate, AppRelease};
use serde::{Deserialize, Serialize};
use slint::{ComponentHandle, Image, Model, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, Timer, TimerMode, VecModel};

slint::include_modules!();

const GRID: usize = 48 * 6;

// ---------- settings ----------

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    dark: bool,
    max_size_mb: u64,
    quarantine_suspicious: bool,
    close_to_tray: bool,
    pack: String,
    told_about_tray: bool,
    file_shield: bool,
    process_shield: bool,
    clickfix_shield: bool,
    stealer_shield: bool,
    auto_quarantine: bool,
    /// Cleaner items the user ticked; None until they first change one (then defaults apply).
    cleaner_ticks: Option<Vec<String>>,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            dark: true,
            max_size_mb: 64,
            quarantine_suspicious: false,
            close_to_tray: true,
            pack: "core".into(),
            told_about_tray: false,
            file_shield: true,
            process_shield: true,
            clickfix_shield: true,
            stealer_shield: true,
            auto_quarantine: true,
            cleaner_ticks: None,
        }
    }
}

fn settings_path() -> PathBuf {
    data_dir().join("app-settings.json")
}

impl Settings {
    fn load() -> Self {
        std::fs::read(settings_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }
    fn save(&self) {
        let _ = std::fs::create_dir_all(data_dir());
        if let Ok(b) = serde_json::to_vec_pretty(self) {
            let _ = std::fs::write(settings_path(), b);
        }
    }
}

// ---------- state ----------

type Slot<T> = Arc<Mutex<Option<T>>>;

fn slot<T>() -> Slot<T> {
    Arc::new(Mutex::new(None))
}

fn take<T>(s: &Slot<T>) -> Option<T> {
    s.lock().ok().and_then(|mut g| g.take())
}

struct ScanJob {
    kind: &'static str,
    progress: Arc<Progress>,
    cancel: Arc<AtomicBool>,
    started: Instant,
    paused_at: Option<Instant>,
    paused_total: Duration,
    result: Slot<ScanSummary>,
    seen_threats: u64,
    threat_cells: Vec<usize>,
    ticks: usize,
}

impl ScanJob {
    fn elapsed(&self) -> Duration {
        let now = self.paused_at.unwrap_or_else(Instant::now);
        now.duration_since(self.started).saturating_sub(self.paused_total)
    }
}

/// Who made a startup program, whether it's signed, how big it is, and its icon.
#[derive(Clone, Default)]
struct StartupMeta {
    publisher: Option<String>,
    signed: bool,
    size: u64,
    icon: Option<(u32, u32, Vec<u8>)>,
}

type StartupResult = Vec<(StartupItem, &'static str, Vec<Detection>, StartupMeta)>;

struct State {
    settings: Settings,
    engine: Option<Arc<Engine>>,
    engine_slot: Slot<Result<Arc<Engine>, String>>,
    reloading: bool,
    scan: Option<ScanJob>,
    reports: Vec<FileReport>,
    threats: Rc<VecModel<ThreatRow>>,
    drives: Rc<VecModel<DriveRow>>,
    folders: Rc<VecModel<SharedString>>,
    startup_items: StartupResult,
    startup_visible: Vec<usize>,
    startup_slot: Slot<StartupResult>,
    startup_fix_slot: Slot<(bool, Result<startup::DisabledItem, String>)>,
    startup_checked_at: Option<chrono::DateTime<Utc>>,
    update_slot: Slot<Result<hexward_update::Report, String>>,
    vault_rows: Rc<VecModel<VaultRow>>,
    toast_until: Option<Instant>,
    flash_until: Option<Instant>,
    release: Option<AppRelease>,
    app_check_slot: Slot<Result<Option<AppRelease>, String>>,
    app_install_slot: Slot<Result<PathBuf, String>>,
    next_app_check: Instant,
    window_visible: bool,
    shields: shields::Shields,
    tasks: taskman::TaskMan,
    cleaner: cleanui::Cleaner,
    /// Message-only window that owns clipboard text Hexward writes (created on the UI thread).
    #[cfg(windows)]
    clip_owner: windows_sys::Win32::Foundation::HWND,
}

// ---------- helpers ----------

pub(crate) fn thousands(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{n} B") } else { format!("{v:.1} {}", U[i]) }
}

fn clock(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 3600 { format!("{}:{:02}:{:02}", s / 3600, (s / 60) % 60, s % 60) } else { format!("{}:{:02}", s / 60, s % 60) }
}

fn when(at: chrono::DateTime<Utc>) -> String {
    let local = at.with_timezone(&Local);
    if local.date_naive() == Local::now().date_naive() { format!("today {}", local.format("%H:%M")) } else { local.format("%b %-d, %H:%M").to_string() }
}

fn kind_label(kind: &str) -> &'static str {
    match kind {
        "system" => "System scan",
        "full" => "Full scan",
        "custom" => "Custom scan",
        _ => "Quick scan",
    }
}

fn hex_view(b: &[u8]) -> String {
    if b.is_empty() {
        return "·· ·· ·· ·· ·· ·· ·· ··
·· ·· ·· ·· ·· ·· ·· ··
················".into();
    }
    let row = |c: &[u8]| c.iter().map(|x| format!("{x:02X}")).collect::<Vec<_>>().join(" ");
    let ascii: String = b.iter().map(|&x| if x.is_ascii_graphic() { x as char } else { '·' }).collect();
    let (a, rest) = b.split_at(b.len().min(8));
    format!("{}
{}
{}", row(a), if rest.is_empty() { "··".to_string() } else { row(rest) }, ascii)
}

fn rule_dirs() -> Vec<PathBuf> {
    let mut v = vec![data_dir().join("rules")];
    if let Some(dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        v.push(dir.join("rules"));
    }
    v
}

fn to_image((w, h, rgba): (u32, u32, Vec<u8>)) -> Image {
    let mut buf = SharedPixelBuffer::<Rgba8Pixel>::new(w, h);
    buf.make_mut_bytes().copy_from_slice(&rgba);
    Image::from_rgba8(buf)
}

fn icon(name: &str) -> Image {
    let rows = art::ICONS.iter().find(|i| i.0 == name).map(|i| i.1).unwrap_or(art::ICONS[0].1);
    to_image(art::render(&rows, 1, |c, _, _| (c == '#').then_some([255, 255, 255, 255])))
}

pub(crate) fn set_assets(ui: &AppWindow) {
    let a = ui.global::<Assets>();
    let mut dots = Vec::new();
    for (y, row) in art::MARK.iter().enumerate() {
        for (x, ch) in row.chars().enumerate() {
            let c = match ch {
                '#' if x < 8 => 0,
                '#' => 1,
                'o' => 2,
                _ => continue,
            };
            dots.push(PixelDot { x: x as i32, y: y as i32, c });
        }
    }
    a.set_mark_pixels(ModelRc::new(VecModel::from(dots)));
    let wm = art::wordmark_rows();
    let rows: Vec<&str> = wm.iter().map(String::as_str).collect();
    a.set_wordmark(to_image(art::render(&rows, 1, |c, _, _| (c == '#').then_some([255, 255, 255, 255]))));
    a.set_i_shield(icon("shield"));
    a.set_i_scan(icon("scan"));
    a.set_i_bug(icon("bug"));
    a.set_i_vault(icon("vault"));
    a.set_i_clock(icon("clock"));
    a.set_i_gear(icon("gear"));
    a.set_i_info(icon("info"));
    a.set_i_folder(icon("folder"));
    a.set_i_file(icon("file"));
    a.set_i_bolt(icon("bolt"));
    a.set_i_update(icon("update"));
    a.set_i_disk(icon("disk"));
    a.set_i_trash(icon("trash"));
    a.set_i_check(icon("check"));
    a.set_i_tasks(icon("tasks"));
    a.set_i_sparkle(icon("sparkle"));
    a.set_i_lock(icon("lock"));
    ui.set_app_icon(to_image(art::render(&art::MARK, 4, art::mark_color(art::MOSS_HI, art::MOSS_LO, Some(art::OXIDE)))));
}

fn toast(st: &mut State, ui: &AppWindow, state: &str, title: &str, text: &str) {
    ui.set_toast_visible(false);
    ui.set_toast_state(state.into());
    ui.set_toast_title(title.into());
    ui.set_toast_text(text.into());
    ui.set_toast_visible(true);
    st.toast_until = Some(Instant::now() + Duration::from_millis(5000));
    if !st.window_visible || state == "alarm" {
        notify(title, text);
    }
}

/// Windows notification (Action Center). Runs on its own thread: showing one can take a moment.
fn notify(title: &str, text: &str) {
    let (t, b) = (title.to_string(), text.to_string());
    std::thread::spawn(move || {
        let _ = notify_rust::Notification::new().appname("Hexward").summary(&t).body(&b).show();
    });
}

fn log(kind: EventKind, title: impl Into<String>, detail: impl Into<String>) {
    history::append(Event::new(kind, title, detail));
}

// ---------- engine ----------

fn load_engine(st: &mut State) {
    let slot = st.engine_slot.clone();
    std::thread::spawn(move || {
        let r = Engine::load(&rule_dirs()).map(Arc::new).map_err(|e| e.to_string());
        if let Ok(mut g) = slot.lock() {
            *g = Some(r);
        }
    });
}

fn has_rule_pack() -> bool {
    hexward_update::read_manifest(&hexward_update::rules_dir()).yara_forge.is_some()
}

// ---------- home / history ----------

pub(crate) fn heat_cells(daily: &BTreeMap<NaiveDate, (u64, u64)>, weeks: u64) -> Vec<i32> {
    let today = Local::now().date_naive();
    let dow = today.weekday().num_days_from_sunday() as u64;
    let last_sat = today + Days::new(6 - dow);
    let start = last_sat - Days::new(weeks * 7 - 1);
    (0..weeks * 7)
        .map(|i| {
            let d = start + Days::new(i);
            if d > today {
                return -1;
            }
            match daily.get(&d) {
                None => 0,
                Some((_, t)) if *t > 0 => 5,
                Some((f, _)) => match f {
                    0 => 0,
                    1..1_000 => 1,
                    1_000..10_000 => 2,
                    10_000..50_000 => 3,
                    _ => 4,
                },
            }
        })
        .collect()
}

fn unhandled_confirmed(st: &State) -> usize {
    st.reports.iter().enumerate().filter(|(i, r)| r.is_confirmed() && st.threats.row_data(*i).is_some_and(|row| !row.done)).count()
}

fn refresh_home(st: &State, ui: &AppWindow) {
    let events = history::load();
    let daily = history::daily(&events);
    let pack = has_rule_pack();
    ui.set_needs_rules(!pack);

    let (state, chip, title, text) = if st.scan.is_some() {
        ("scan", "SCANNING", "Scanning…".to_string(), "Hexward is checking your files. You can keep working.".to_string())
    } else if unhandled_confirmed(st) > 0 {
        let n = unhandled_confirmed(st);
        ("alarm", "THREATS FOUND", "Threats need a decision".to_string(), format!("{n} confirmed {} from your last scan {} waiting. Review them and choose: quarantine, delete or allow.", if n == 1 { "threat" } else { "threats" }, if n == 1 { "is" } else { "are" }))
    } else if !pack {
        ("warn", "RULES NEEDED", "Get the rule pack".to_string(), "Hexward only has its built-in test rules. Download about 5,100 community rules (1.7 MB) to find real threats.".to_string())
    } else if let Some(last) = events.iter().find(|e| e.kind == EventKind::Scan) {
        (
            "safe",
            "ALL CLEAR",
            "No threats waiting".to_string(),
            format!(
                "Last scan {}: {} files checked{}. {}",
                when(last.at),
                thousands(last.files),
                if last.threats > 0 { format!(", {} found and handled", last.threats) } else { ", nothing found".into() },
                if st.settings.file_shield || st.settings.process_shield {
                    "The shields check new downloads and every program that starts."
                } else {
                    "The shields are off, so scan regularly."
                }
            ),
        )
    } else {
        ("warn", "NOT SCANNED YET", "No scan yet".to_string(), "Run a quick scan to check the places threats usually hide. It takes about a minute.".to_string())
    };
    ui.set_home_state(state.into());
    ui.set_home_chip(chip.into());
    ui.set_home_title(title.into());
    ui.set_home_text(text.into());

    let today = Local::now().date_naive();
    let files_today = daily.get(&today).map(|d| d.0).unwrap_or(0);
    let found_30: u64 = daily.range(today - Days::new(30)..).map(|(_, d)| d.1).sum();
    let manifest = hexward_update::read_manifest(&hexward_update::rules_dir());
    let updated = manifest.yara_forge.as_ref().map(|f| when(f.updated_at)).unwrap_or_else(|| "Never".into());
    let rules = st.engine.as_ref().map(|e| thousands(e.rule_count() as u64)).unwrap_or_else(|| "…".into());
    ui.set_home_stats(ModelRc::new(VecModel::from(vec![
        StatItem { label: "CHECKED TODAY".into(), value: thousands(files_today).into() },
        StatItem { label: "FOUND · 30 DAYS".into(), value: thousands(found_30).into() },
        StatItem { label: "RULES".into(), value: rules.clone().into() },
        StatItem { label: "RULES UPDATED".into(), value: updated.into() },
    ])));

    let vault_n = st.vault_rows.row_count();
    let rows = vec![
        StatusRow { name: "On-demand scanner".into(), value: if st.engine.is_some() { "Ready".into() } else { "Loading".into() }, tone: if st.engine.is_some() { "safe".into() } else { "scan".into() } },
        StatusRow { name: "Rule pack".into(), value: if pack { format!("{rules} rules").into() } else { "Not downloaded".into() }, tone: if pack { "safe".into() } else { "warn".into() } },
        StatusRow {
            name: "Startup items".into(),
            value: st.startup_checked_at.map(|t| format!("Checked {}", when(t))).unwrap_or_else(|| "Not checked yet".into()).into(),
            tone: if st.startup_checked_at.is_some() { "safe".into() } else { "off".into() },
        },
        StatusRow { name: "Quarantine".into(), value: format!("{vault_n} {}", if vault_n == 1 { "file" } else { "files" }).into(), tone: "off".into() },
        StatusRow {
            name: "File shield".into(),
            value: if st.settings.file_shield { format!("Watching {}", shields::describe(&st.shields.watched)).into() } else { "Off".into() },
            tone: if st.settings.file_shield { "safe".into() } else { "warn".into() },
        },
        StatusRow {
            name: "Process shield".into(),
            value: if st.settings.process_shield {
                format!("{} programs checked", thousands(st.shields.stats.programs_checked.load(Ordering::Relaxed))).into()
            } else {
                "Off".into()
            },
            tone: if st.settings.process_shield { "safe".into() } else { "warn".into() },
        },
        StatusRow {
            name: "ClickFix shield".into(),
            value: if st.settings.clickfix_shield { format!("{} copies checked", thousands(st.shields.stats.copies_checked.load(Ordering::Relaxed))).into() } else { "Off".into() },
            tone: if st.settings.clickfix_shield { "safe".into() } else { "warn".into() },
        },
        StatusRow {
            name: "Stealer shield".into(),
            value: if st.settings.stealer_shield { format!("Guarding {} secret stores", st.shields.stats.stores_watched.load(Ordering::Relaxed)).into() } else { "Off".into() },
            tone: if st.settings.stealer_shield { "safe".into() } else { "warn".into() },
        },
        StatusRow {
            name: "App".into(),
            value: match &st.release {
                Some(r) => format!("{} ready", r.version).into(),
                None => format!("v{} · up to date", env!("CARGO_PKG_VERSION")).into(),
            },
            tone: if st.release.is_some() { "scan".into() } else { "safe".into() },
        },
    ];
    ui.set_status_rows(ModelRc::new(VecModel::from(rows)));
    ui.set_heat_short(ModelRc::new(VecModel::from(heat_cells(&daily, 26))));
    ui.set_heat_year(ModelRc::new(VecModel::from(heat_cells(&daily, 52))));
}

fn refresh_history(ui: &AppWindow) {
    let events = history::load();
    let rows: Vec<EventRow> = events
        .iter()
        .take(400)
        .map(|e| {
            let (chip, tone) = match e.kind {
                EventKind::Scan if e.threats > 0 => ("SCAN", "alarm"),
                EventKind::Scan => ("SCAN", "safe"),
                EventKind::Quarantine => ("QUARANTINE", "warn"),
                EventKind::Restore => ("RESTORE", "scan"),
                EventKind::Delete => ("DELETE", "off"),
                EventKind::Update => ("UPDATE", "scan"),
                EventKind::StartupFix => ("STARTUP", "oxide"),
                EventKind::EndTask => ("TASK", "warn"),
                EventKind::Clean => ("CLEAN", "safe"),
            };
            EventRow { when: when(e.at).into(), title: e.title.clone().into(), detail: e.detail.clone().into(), chip: chip.into(), tone: tone.into() }
        })
        .collect();
    ui.set_events(ModelRc::new(VecModel::from(rows)));
    ui.set_heat_year(ModelRc::new(VecModel::from(heat_cells(&history::daily(&events), 52))));
}

fn refresh_settings(st: &State, ui: &AppWindow) {
    let m = hexward_update::read_manifest(&hexward_update::rules_dir());
    let rules = match &m.yara_forge {
        Some(f) => format!("{} pack · {} rules · updated {}. From YARA Forge on GitHub.", f.pack.name(), thousands(f.rules as u64), when(f.updated_at)),
        None => "Not downloaded yet. Update to get about 5,100 tested community rules.".into(),
    };
    let key = std::env::var("HEXWARD_ABUSECH_KEY").map(|k| !k.trim().is_empty()).unwrap_or(false);
    let bazaar = match (&m.malwarebazaar, key) {
        (Some(b), _) => format!("{} known-bad hashes, updated {}.", thousands(b.total as u64), when(b.updated_at)),
        (None, true) => "Auth-Key found. The next update downloads the hash list.".into(),
        (None, false) => "Needs a free abuse.ch Auth-Key: create one at auth.abuse.ch, set HEXWARD_ABUSECH_KEY, restart Hexward and update.".into(),
    };
    ui.set_rules_info(rules.into());
    ui.set_bazaar_info(bazaar.into());
    ui.set_data_dir(data_dir().display().to_string().into());
    ui.set_max_size_mb(st.settings.max_size_mb as i32);
    ui.set_quarantine_suspicious(st.settings.quarantine_suspicious);
    ui.set_close_to_tray(st.settings.close_to_tray);
    ui.set_file_shield(st.settings.file_shield);
    ui.set_process_shield(st.settings.process_shield);
    ui.set_auto_quarantine(st.settings.auto_quarantine);
    ui.set_clickfix_shield(st.settings.clickfix_shield);
    ui.set_stealer_shield(st.settings.stealer_shield);
    ui.set_shield_info(format!("Watches {}. New and changed files are checked as soon as they finish writing.", shields::describe(&st.shields.watched)).into());
    ui.set_pack(st.settings.pack.clone().into());
    let allow: Vec<AllowRow> = allowlist::list()
        .into_iter()
        .map(|a| AllowRow {
            sha: a.sha256.clone().into(),
            name: a.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default().into(),
            path: format!("{} · was flagged as {}", a.path.display(), a.detection).into(),
        })
        .collect();
    ui.set_allow_rows(ModelRc::new(VecModel::from(allow)));
}

fn refresh_drives(st: &State) {
    let previous: Vec<(SharedString, bool)> = st.drives.iter().map(|d| (d.root.clone(), d.selected)).collect();
    let rows: Vec<DriveRow> = locations::drives()
        .into_iter()
        .map(|d| {
            let root: SharedString = d.root.display().to_string().trim_end_matches('\\').to_string().into();
            let was = previous.iter().find(|p| p.0 == root).map(|p| p.1);
            let used = d.total.saturating_sub(d.free);
            DriveRow {
                selected: was.unwrap_or(false),
                label: if d.label.is_empty() { d.kind.clone().into() } else { d.label.clone().into() },
                info: format!("{} · {} free of {}", d.kind, bytes(d.free), bytes(d.total)).into(),
                usage: if d.total > 0 { used as f32 / d.total as f32 } else { 0.0 },
                root,
            }
        })
        .collect();
    st.drives.set_vec(rows);
}

// ---------- scanning ----------

fn start_scan(st: &mut State, ui: &AppWindow, kind: &'static str) {
    if st.scan.is_some() {
        return;
    }
    let Some(engine) = st.engine.clone() else { return };
    let custom: Vec<PathBuf> = if kind == "custom" {
        let mut v: Vec<PathBuf> = st.drives.iter().filter(|d| d.selected).map(|d| PathBuf::from(format!("{}\\", d.root))).collect();
        v.extend(st.folders.iter().map(|f| PathBuf::from(f.as_str())));
        if v.is_empty() {
            return toast(st, ui, "warn", "Nothing selected", "Tick a drive or add a folder first.");
        }
        v
    } else {
        Vec::new()
    };
    let progress = Arc::new(Progress::default());
    let cancel = Arc::new(AtomicBool::new(false));
    let result = slot();
    let opts = ScanOptions {
        max_size: st.settings.max_size_mb * 1024 * 1024,
        threads: 0,
        // Never scan Hexward's own data: the rule files would match the rules.
        excludes: vec![data_dir(), Vault::default_dir()],
        cache: Some(Arc::new(hexward_engine::cache::ScanCache::open(hexward_engine::cache::ScanCache::default_path(), engine.fingerprint()))),
    };
    {
        let (progress, cancel, result) = (progress.clone(), cancel.clone(), result.clone());
        std::thread::spawn(move || {
            let with_startup = |mut r: Vec<PathBuf>| {
                r.extend(locations::running_programs());
                r.extend(startup::list_startup_items().into_iter().filter_map(|i| i.target).filter(|t| t.is_file()));
                r
            };
            let roots: Vec<PathBuf> = match kind {
                "system" => with_startup(locations::system_folders()),
                "full" => locations::fixed_drives(),
                "custom" => custom,
                _ => with_startup(locations::quick_scan_folders()),
            };
            {
                let (roots, excludes, progress, cancel) = (roots.clone(), opts.excludes.clone(), progress.clone(), cancel.clone());
                std::thread::spawn(move || count_files(&roots, &excludes, &progress, &cancel));
            }
            let summary = engine.scan_paths(&roots, &opts, &progress, &cancel);
            if let Ok(mut g) = result.lock() {
                *g = Some(summary);
            }
        });
    }

    st.scan = Some(ScanJob {
        kind,
        progress,
        cancel,
        started: Instant::now(),
        paused_at: None,
        paused_total: Duration::ZERO,
        result,
        seen_threats: 0,
        threat_cells: Vec::new(),
        ticks: 0,
    });
    ui.set_scan_kind(kind_label(kind).to_uppercase().into());
    ui.set_scanning(true);
    ui.set_paused(false);
    ui.set_scan_started(true);
    ui.set_scan_threats(0);
    ui.set_scan_fraction(-1.0);
    ui.set_scan_files("0".into());
    ui.set_scan_speed("0".into());
    ui.set_scan_time("0:00".into());
    ui.set_scan_path("Finding files…".into());
    ui.set_scan_bytes(hex_view(&[]).into());
    ui.set_scan_title("Scanning your PC".into());
    ui.set_scan_text("Counting files… You can keep working: Hexward uses spare CPU first.".into());
    ui.set_grid_cells(ModelRc::new(VecModel::from(vec![0; GRID])));
    ui.set_page("scan".into());
    refresh_home(st, ui);
}

fn tick_scan(st: &mut State, ui: &AppWindow) {
    let Some(job) = st.scan.as_mut() else { return };
    if let Some(summary) = take(&job.result) {
        finish_scan(st, ui, summary);
        return;
    }
    job.ticks += 1;
    let p = &job.progress;
    let files = p.files.load(Ordering::Relaxed);
    let found = p.threats.load(Ordering::Relaxed);
    let secs = job.elapsed().as_secs_f64().max(0.001);
    let fraction = p.fraction();
    let lit = fraction.map(|f| ((f * GRID as f32) as usize).min(GRID - 1)).unwrap_or(0);

    if found > job.seen_threats {
        job.seen_threats = found;
        job.threat_cells.push(lit);
        st.flash_until = Some(Instant::now() + Duration::from_millis(900));
        ui.set_flash(true);
    }
    let cursor = if fraction.is_some() { lit } else { (job.ticks * 5) % GRID };
    let cells: Vec<i32> = (0..GRID)
        .map(|i| {
            if job.threat_cells.contains(&i) {
                3
            } else if i == cursor && job.paused_at.is_none() {
                2
            } else if fraction.is_some() && i < lit {
                1
            } else {
                0
            }
        })
        .collect();
    ui.set_grid_cells(ModelRc::new(VecModel::from(cells)));

    ui.set_scan_files(thousands(files).into());
    ui.set_scan_threats(found as i32);
    ui.set_scan_speed(if job.paused_at.is_some() { "0".into() } else { thousands((files as f64 / secs) as u64).into() });
    ui.set_scan_time(clock(job.elapsed()).into());
    if let Ok(cur) = p.current.lock() {
        ui.set_scan_path(cur.display().to_string().into());
    }
    if let Ok(peek) = p.peek.lock() {
        ui.set_scan_bytes(hex_view(&peek).into());
    }
    let total = p.total.load(Ordering::Relaxed);
    if job.paused_at.is_some() {
        ui.set_scan_title("Paused".into());
        ui.set_scan_text("Nothing is being checked. Resume when you're ready.".into());
    } else {
        ui.set_scan_title("Scanning your PC".into());
        match fraction {
            Some(f) => {
                ui.set_scan_fraction(f.min(0.999));
                let left = if f > 0.03 { Duration::from_secs_f64(secs / f as f64 * (1.0 - f as f64)) } else { Duration::ZERO };
                ui.set_scan_text(
                    format!("{} of {} files · {}%{}", thousands(files), thousands(total), (f * 100.0) as u32, if left.as_secs() > 0 { format!(" · about {} left", clock(left)) } else { String::new() }).into(),
                );
            }
            None => {
                ui.set_scan_fraction(-1.0);
                ui.set_scan_text(format!("Counting files… {} found so far, scanning as they're found.", thousands(total)).into());
            }
        }
    }
}

fn row_for(r: &FileReport, selected: bool) -> ThreatRow {
    let d = &r.detections[0];
    let confirmed = r.is_confirmed();
    let chip = if !confirmed {
        "SUSPICIOUS"
    } else {
        match r.top_severity() {
            Some(Severity::High) => "HIGH",
            Some(Severity::Medium) => "MEDIUM",
            _ => "LOW",
        }
    };
    let more = if r.detections.len() > 1 { format!("  +{} more", r.detections.len() - 1) } else { String::new() };
    ThreatRow {
        name: format!("{}{more}", d.name).into(),
        path: r.path.display().to_string().into(),
        description: match &d.inner {
            Some(inner) => format!("Found inside: {inner}. {}", d.description).into(),
            None => d.description.clone().into(),
        },
        chip: chip.into(),
        tone: (if confirmed { "alarm" } else { "warn" }).into(),
        selected,
        done: false,
        confirm_delete: false,
    }
}

fn finish_scan(st: &mut State, ui: &AppWindow, s: ScanSummary) {
    let job = st.scan.take();
    let kind = job.as_ref().map(|j| j.kind).unwrap_or("quick");
    let elapsed = job.as_ref().map(|j| j.elapsed()).unwrap_or_default();
    let found = s.threats.len() as u64;

    let mut ev = Event::new(
        EventKind::Scan,
        format!("{}{}", kind_label(kind), if s.cancelled { " (stopped)" } else { "" }),
        format!("{} files · {} · {} found · {}", thousands(s.files_scanned), bytes(s.bytes_scanned), found, clock(elapsed)),
    );
    ev.files = s.files_scanned;
    ev.threats = found;
    history::append(ev);

    ui.set_scanning(false);
    ui.set_paused(false);
    ui.set_scan_threats(found as i32);
    if !s.cancelled {
        ui.set_scan_fraction(1.0);
        let cells = job.as_ref().map(|j| j.threat_cells.clone()).unwrap_or_default();
        ui.set_grid_cells(ModelRc::new(VecModel::from((0..GRID).map(|i| if cells.contains(&i) { 3 } else { 1 }).collect::<Vec<i32>>())));
    }
    ui.set_scan_files(thousands(s.files_scanned).into());
    ui.set_scan_speed(thousands((s.files_scanned as f64 / elapsed.as_secs_f64().max(0.001)) as u64).into());
    ui.set_scan_time(clock(elapsed).into());
    ui.set_scan_title(
        (if s.cancelled {
            "Scan stopped".to_string()
        } else if found > 0 {
            format!("Scan finished. {found} found")
        } else {
            "Scan finished. Nothing found".to_string()
        })
        .into(),
    );
    let skipped = s.skipped_large + s.unreadable;
    ui.set_scan_text(
        format!(
            "{} files ({}) checked in {}{}.{}",
            thousands(s.files_scanned),
            bytes(s.bytes_scanned),
            clock(elapsed),
            if s.cached > 0 { format!(", {} unchanged since a clean scan", thousands(s.cached)) } else { String::new() },
            if skipped > 0 { format!(" {} skipped (too large, in use or no permission).", thousands(skipped)) } else { String::new() }
        )
        .into(),
    );
    ui.set_scan_path(if found > 0 { "Nothing was changed. Review the results to decide.".into() } else { "Every file checked is clean.".into() });

    st.reports = s.threats.clone();
    let rows: Vec<ThreatRow> = st.reports.iter().map(|r| row_for(r, r.is_confirmed() || st.settings.quarantine_suspicious)).collect();
    st.threats.set_vec(rows);
    update_results_header(st, ui);
    refresh_home(st, ui);

    if found > 0 {
        toast(st, ui, "alarm", &format!("{found} found by the {}", kind_label(kind).to_lowercase()), "Nothing was changed. Open Hexward to choose: quarantine, delete or allow.");
    } else if !s.cancelled {
        toast(st, ui, "safe", "Scan finished", &format!("{} files checked. Nothing found.", thousands(s.files_scanned)));
    }
}

fn update_results_header(st: &State, ui: &AppWindow) {
    let rows: Vec<ThreatRow> = st.threats.iter().collect();
    let open = rows.iter().filter(|r| !r.done).count();
    ui.set_selected_count(rows.iter().filter(|r| r.selected && !r.done).count() as i32);
    ui.set_open_count(open as i32);
    let (title, text) = if rows.is_empty() {
        ("Nothing found".to_string(), "Your last scan found no threats.".to_string())
    } else if open == 0 {
        ("All handled".to_string(), "Everything from this scan has been dealt with.".to_string())
    } else {
        (
            format!("{open} {} need a decision", if open == 1 { "item" } else { "items" }),
            "Quarantine locks a file away (you can restore it). Delete removes it forever. Allow trusts it, for example an old game Hexward got wrong.".to_string(),
        )
    };
    ui.set_results_title(title.into());
    ui.set_results_text(text.into());
}

fn mark_done(st: &State, i: usize, chip: &str, tone: &str) {
    if let Some(mut row) = st.threats.row_data(i) {
        row.done = true;
        row.selected = false;
        row.confirm_delete = false;
        row.chip = chip.into();
        row.tone = tone.into();
        st.threats.set_row_data(i, row);
    }
}

fn quarantine_rows(st: &mut State, ui: &AppWindow, which: &[usize]) {
    let vault = match Vault::open(Vault::default_dir()) {
        Ok(v) => v,
        Err(e) => return toast(st, ui, "alarm", "Quarantine unavailable", &e.to_string()),
    };
    let (mut moved, mut failed) = (0, Vec::new());
    for &i in which {
        let Some(r) = st.reports.get(i).cloned() else { continue };
        match vault.quarantine(&r.path, &r.detections[0].name) {
            Ok(_) => {
                moved += 1;
                mark_done(st, i, "QUARANTINED", "safe");
                log(EventKind::Quarantine, r.detections[0].name.clone(), r.path.display().to_string());
            }
            Err(e) => {
                if let Some(mut row) = st.threats.row_data(i) {
                    row.chip = "NOT MOVED".into();
                    row.description = e.to_string().into();
                    st.threats.set_row_data(i, row);
                }
                failed.push(e.to_string());
            }
        }
    }
    update_results_header(st, ui);
    refresh_vault(st, ui);
    refresh_home(st, ui);
    if !failed.is_empty() {
        toast(st, ui, "warn", &format!("{moved} moved, {} not moved", failed.len()), "A file in use can't be moved. Close the program using it and try again.");
    } else if moved > 0 {
        toast(st, ui, "safe", &format!("{moved} moved to quarantine"), "Encrypted and unable to run. Restore anytime from Quarantine.");
    }
}

fn delete_row(st: &mut State, ui: &AppWindow, i: usize) {
    let Some(r) = st.reports.get(i).cloned() else { return };
    let res = (|| {
        let mut perms = std::fs::metadata(&r.path)?.permissions();
        if perms.readonly() {
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            std::fs::set_permissions(&r.path, perms)?;
        }
        std::fs::remove_file(&r.path)
    })();
    match res {
        Ok(()) => {
            mark_done(st, i, "DELETED", "off");
            log(EventKind::Delete, format!("Deleted {}", r.detections[0].name), r.path.display().to_string());
            toast(st, ui, "off", "Deleted forever", &r.path.display().to_string());
        }
        Err(e) => toast(st, ui, "warn", "Couldn't delete", &format!("{e}. If the file is in use, close the program and try again.")),
    }
    update_results_header(st, ui);
    refresh_home(st, ui);
}

fn allow_row(st: &mut State, ui: &AppWindow, i: usize) {
    let Some(r) = st.reports.get(i).cloned() else { return };
    match allowlist::add(&r.sha256, r.path.clone(), &r.detections[0].name) {
        Ok(()) => {
            if let Some(e) = &st.engine {
                e.reload_allowlist();
            }
            mark_done(st, i, "ALLOWED", "scan");
            toast(st, ui, "scan", "Trusted", &format!("Hexward won't flag {} again. Undo in Settings › Trusted files.", r.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
        }
        Err(e) => toast(st, ui, "warn", "Couldn't save", &e.to_string()),
    }
    update_results_header(st, ui);
    refresh_home(st, ui);
}

fn shield_hit(st: &mut State, ui: &AppWindow, ev: shields::ShieldEvent) {
    #[cfg(windows)]
    if ev.neutralize {
        clipboard::write_text(st.clip_owner, clipboard::NEUTRALIZED);
    }
    let Some(r) = &ev.report else {
        // An alert with no file (ClickFix): history, toast and notification.
        let mut e = Event::new(EventKind::Scan, ev.shield, format!("{} · {}", ev.title, ev.action));
        e.threats = 1;
        history::append(e);
        refresh_home(st, ui);
        toast(st, ui, if ev.neutralize { "alarm" } else { "warn" }, &ev.title, &ev.action);
        return;
    };
    let mut row = row_for(r, !ev.quarantined && r.is_confirmed());
    row.description = format!("{}: {} {}", ev.shield, ev.action, row.description).into();
    if ev.quarantined {
        row.done = true;
        row.selected = false;
        row.chip = "QUARANTINED".into();
        row.tone = "safe".into();
    }
    st.reports.push(r.clone());
    st.threats.push(row);
    let mut e = Event::new(EventKind::Scan, ev.shield, format!("{} · {} · {}", r.detections[0].name, r.path.display(), ev.action));
    e.files = 1;
    e.threats = 1;
    history::append(e);
    update_results_header(st, ui);
    refresh_vault(st, ui);
    refresh_home(st, ui);
    let name = r.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    toast(st, ui, if ev.quarantined { "safe" } else { "alarm" }, &format!("{} found {}", ev.shield, r.detections[0].name), &format!("{name}: {}", ev.action));
}

// ---------- quarantine ----------

fn refresh_vault(st: &State, ui: &AppWindow) {
    let list = Vault::open(Vault::default_dir()).and_then(|v| v.list()).unwrap_or_default();
    let rows: Vec<VaultRow> = list
        .iter()
        .map(|e| VaultRow {
            id: e.id.clone().into(),
            name: e.detection.clone().into(),
            path: e.original_path.display().to_string().into(),
            info: format!("Quarantined {} · {} · id {}", when(e.quarantined_at), bytes(e.size), e.id).into(),
            confirm: false,
        })
        .collect();
    st.vault_rows.set_vec(rows);
    ui.set_vault_rows(ModelRc::from(st.vault_rows.clone()));
}

// ---------- startup ----------

fn show_startup(st: &mut State, ui: &AppWindow) {
    let all = ui.get_startup_show_all();
    let search = ui.get_startup_search().to_lowercase();
    st.startup_visible = st
        .startup_items
        .iter()
        .enumerate()
        .filter(|(_, (item, status, _, meta))| {
            if !search.is_empty() {
                // A search looks through everything, problems or not.
                return [item.name.as_str(), item.command.as_str(), item.location.as_str(), meta.publisher.as_deref().unwrap_or("")].iter().any(|f| f.to_lowercase().contains(&search));
            }
            all || *status == "threat" || (*status == "missing" && item.location != "Driver")
        })
        .map(|(i, _)| i)
        .collect();
    let sort = ui.get_startup_sort().to_string();
    let items = &st.startup_items;
    let rank = |s: &str| match s {
        "threat" => 0,
        "missing" => 1,
        _ => 2,
    };
    match sort.as_str() {
        "Name" => st.startup_visible.sort_by_key(|&i| items[i].0.name.to_lowercase()),
        "Publisher" => st.startup_visible.sort_by_key(|&i| (items[i].3.publisher.is_none(), items[i].3.publisher.clone().unwrap_or_default().to_lowercase(), items[i].0.name.to_lowercase())),
        "Size" => st.startup_visible.sort_by_key(|&i| std::cmp::Reverse(items[i].3.size)),
        _ => st.startup_visible.sort_by_key(|&i| (rank(items[i].1), items[i].0.name.to_lowercase())),
    }
    let rows: Vec<StartupRow> = st
        .startup_visible
        .iter()
        .map(|&i| {
            let (item, status, dets, meta) = &st.startup_items[i];
            let (chip, tone, detail) = match *status {
                "threat" => ("THREAT", "alarm", dets.iter().map(|d| d.name.clone()).collect::<Vec<_>>().join(", ")),
                "missing" => ("MISSING", "warn", "The program this points to no longer exists. Usually a leftover from an uninstalled app.".into()),
                "clean" => ("CLEAN", "safe", String::new()),
                "too large" => ("SKIPPED", "off", "Too large to scan.".into()),
                _ => ("UNREADABLE", "off", "Hexward couldn't read the program file.".into()),
            };
            StartupRow {
                location: item.location.clone().into(),
                name: item.name.clone().into(),
                command: item.command.clone().into(),
                chip: chip.into(),
                tone: tone.into(),
                fixable: item.fix.is_some(),
                detail: detail.into(),
                publisher: match (&meta.publisher, meta.signed) {
                    (Some(p), true) => format!("{p} · signed"),
                    (Some(p), false) => format!("{p} · not signed"),
                    (None, true) => "Signed".into(),
                    (None, false) if item.target.as_ref().is_some_and(|t| t.is_file()) => "Unknown publisher · not signed".into(),
                    _ => String::new(),
                }
                .into(),
                signed: meta.signed,
                size: if meta.size > 0 { bytes(meta.size).into() } else { "".into() },
                has_icon: meta.icon.is_some(),
                icon: meta.icon.clone().map(to_image).unwrap_or_default(),
            }
        })
        .collect();
    ui.set_startup_rows(ModelRc::new(VecModel::from(rows)));
    let n = |s: &str| st.startup_items.iter().filter(|x| x.1 == s).count();
    ui.set_startup_summary(format!("{} items · {} clean · {} threats · {} missing", st.startup_items.len(), n("clean"), n("threat"), n("missing")).into());
    let disabled: Vec<DisabledRow> = startup::disabled_items()
        .into_iter()
        .map(|d| DisabledRow { id: d.id.into(), name: d.name.into(), info: format!("{} · switched off {}", d.location, when(d.at)).into() })
        .collect();
    ui.set_disabled_rows(ModelRc::new(VecModel::from(disabled)));
}

fn check_startup(st: &mut State, ui: &AppWindow) {
    let Some(engine) = st.engine.clone() else { return };
    let out = st.startup_slot.clone();
    ui.set_startup_busy(true);
    std::thread::spawn(move || {
        icons::init_thread();
        let mut scanner = engine.rules().scanner();
        let rows: StartupResult = startup::list_startup_items()
            .into_iter()
            .map(|item| {
                let (status, dets) = match &item.target {
                    Some(t) if t.is_file() => match engine.scan_file(&mut scanner, t, 256 * 1024 * 1024) {
                        Ok(Some(r)) if !r.detections.is_empty() => ("threat", r.detections),
                        Ok(Some(_)) => ("clean", Vec::new()),
                        Ok(None) => ("too large", Vec::new()),
                        Err(_) => ("unreadable", Vec::new()),
                    },
                    _ => ("missing", Vec::new()),
                };
                let meta = match &item.target {
                    Some(t) if t.is_file() => StartupMeta {
                        publisher: hexward_engine::fileinfo::company(t),
                        signed: hexward_engine::sig::has_valid_signature(t),
                        size: std::fs::metadata(t).map(|m| m.len()).unwrap_or(0),
                        icon: icons::file_icon(t),
                    },
                    _ => StartupMeta::default(),
                };
                (item, status, dets, meta)
            })
            .collect();
        if let Ok(mut g) = out.lock() {
            *g = Some(rows);
        }
    });
}

// ---------- rules update ----------

fn update_rules(st: &mut State, ui: &AppWindow) {
    if ui.get_updating() {
        return;
    }
    ui.set_updating(true);
    let pack: hexward_update::ForgePack = st.settings.pack.parse().unwrap_or(hexward_update::ForgePack::Core);
    let out = st.update_slot.clone();
    std::thread::spawn(move || {
        let r = hexward_update::run(pack, false).map_err(|e| format!("{e:#}"));
        if let Ok(mut g) = out.lock() {
            *g = Some(r);
        }
    });
}

fn finish_update(st: &mut State, ui: &AppWindow, r: Result<hexward_update::Report, String>) {
    use hexward_update::Step;
    ui.set_updating(false);
    match r {
        Err(e) => toast(st, ui, "alarm", "Rule update failed", &e),
        Ok(rep) => {
            let mut lines = Vec::new();
            let mut ok = false;
            for (name, step) in [("YARA Forge", &rep.yara_forge), ("MalwareBazaar", &rep.malwarebazaar)] {
                match step {
                    Step::Updated { detail } => {
                        ok = true;
                        lines.push(format!("{name}: {detail}"));
                    }
                    Step::Failed { reason } => lines.push(format!("{name} failed: {reason}")),
                    Step::Skipped { .. } => {}
                }
            }
            log(EventKind::Update, "Rules updated", lines.join(" · "));
            if ok {
                st.reloading = true;
                ui.set_engine_status("Loading new rules…".into());
                load_engine(st);
                toast(st, ui, "scan", "Rules downloaded", "Loading them now. Scans keep running meanwhile.");
            } else {
                toast(st, ui, "warn", "Nothing updated", lines.first().map(String::as_str).unwrap_or("Check your internet connection."));
            }
        }
    }
    refresh_settings(st, ui);
}

// ---------- app self-update ----------

fn check_app_update(st: &mut State, ui: &AppWindow, delay: Duration) {
    ui.set_app_update_status("Checking GitHub for a newer version…".into());
    st.next_app_check = Instant::now() + Duration::from_secs(6 * 3600);
    let out = st.app_check_slot.clone();
    std::thread::spawn(move || {
        std::thread::sleep(delay);
        let r = appupdate::check(env!("CARGO_PKG_VERSION")).map_err(|e| format!("{e:#}"));
        if let Ok(mut g) = out.lock() {
            *g = Some(r);
        }
    });
}

fn install_app_update(st: &mut State, ui: &AppWindow) {
    let Some(rel) = st.release.clone() else { return };
    if ui.get_app_update_busy() {
        return;
    }
    ui.set_app_update_busy(true);
    ui.set_app_update_status(format!("Downloading {} and checking its signature…", rel.version).into());
    let out = st.app_install_slot.clone();
    std::thread::spawn(move || {
        let r = (|| -> anyhow::Result<PathBuf> {
            let exe = std::env::current_exe()?;
            let bytes = appupdate::download_verified(&rel)?;
            appupdate::replace_exe(&exe, &bytes)?;
            Ok(exe)
        })()
        .map_err(|e| format!("{e:#}"));
        if let Ok(mut g) = out.lock() {
            *g = Some(r);
        }
    });
}

// ---------- timer ----------

fn tick(st: &mut State, ui: &AppWindow) {
    if let Some(r) = take(&st.engine_slot) {
        match r {
            Ok(engine) => {
                let n = engine.rule_count() as u64;
                ui.set_rules_count(thousands(n).into());
                ui.set_engine_status(format!("{} rules ready", thousands(n)).into());
                st.shields.set_engine(engine.clone());
                st.engine = Some(engine);
                ui.set_engine_ready(true);
                if st.reloading {
                    toast(st, ui, "safe", "Rules ready", &format!("{} rules loaded.", thousands(n)));
                }
            }
            Err(e) => {
                ui.set_engine_status("Rules failed to load".into());
                toast(st, ui, "alarm", "Rules failed to load", &e);
            }
        }
        st.reloading = false;
        refresh_home(st, ui);
    }
    tick_scan(st, ui);
    taskman::tick(st, ui);
    cleanui::tick(st, ui);
    for ev in st.shields.drain() {
        shield_hit(st, ui, ev);
    }
    if let Some(rows) = take(&st.startup_slot) {
        st.startup_items = rows;
        st.startup_checked_at = Some(Utc::now());
        ui.set_startup_busy(false);
        ui.set_startup_checked(true);
        show_startup(st, ui);
        refresh_home(st, ui);
    }
    if let Some((off, r)) = take(&st.startup_fix_slot) {
        ui.set_startup_busy(false);
        match (off, r) {
            (true, Ok(d)) => {
                st.startup_items.retain(|x| !(x.0.name == d.name && x.0.location == d.location && x.0.command == d.command));
                log(EventKind::StartupFix, format!("Switched off {}", d.name), d.command.clone());
                show_startup(st, ui);
                let how = match d.target {
                    startup::FixTarget::Service { .. } => "won't start with Windows any more; it still runs if an app needs it",
                    _ => "won't start with Windows",
                };
                toast(st, ui, "safe", "Switched off", &format!("{} {how}. Turn it back on anytime.", d.name));
            }
            (false, Ok(d)) => {
                log(EventKind::StartupFix, format!("Turned {} back on", d.name), d.command.clone());
                show_startup(st, ui);
                toast(st, ui, "scan", "Turned back on", &format!("{} will start with Windows again.", d.name));
            }
            (true, Err(e)) => toast(st, ui, "warn", "Couldn't switch it off", &e),
            (false, Err(e)) => toast(st, ui, "warn", "Couldn't turn it back on", &e),
        }
    }
    if let Some(r) = take(&st.update_slot) {
        finish_update(st, ui, r);
    }
    if let Some(r) = take(&st.app_check_slot) {
        match r {
            Ok(Some(rel)) => {
                ui.set_app_update_available(true);
                ui.set_app_update_version(rel.version.clone().into());
                ui.set_app_update_notes(rel.notes.lines().find(|l| !l.trim().is_empty()).unwrap_or("Signed release from GitHub.").trim_start_matches(['#', '-', '*', ' ']).to_string().into());
                ui.set_app_update_status(format!("Version {} is signed and ready. Hexward restarts to finish.", rel.version).into());
                let first = st.release.is_none();
                st.release = Some(rel.clone());
                if first {
                    toast(st, ui, "scan", &format!("Hexward {} is available", rel.version), "Click Update to install it. It's signed and checked first.");
                }
            }
            Ok(None) => ui.set_app_update_status(format!("You have the latest version ({}).", env!("CARGO_PKG_VERSION")).into()),
            Err(e) => ui.set_app_update_status(format!("Couldn't check: {e}").into()),
        }
        refresh_home(st, ui);
    }
    if let Some(r) = take(&st.app_install_slot) {
        ui.set_app_update_busy(false);
        match r {
            Ok(exe) => {
                ui.set_app_update_status("Installed. Restarting…".into());
                let version = st.release.as_ref().map(|r| r.version.clone()).unwrap_or_default();
                if std::process::Command::new(&exe).arg(format!("--updated={version}")).spawn().is_ok() {
                    std::process::exit(0);
                }
                toast(st, ui, "warn", "Update installed", "Restart Hexward to use the new version.");
            }
            Err(e) => {
                ui.set_app_update_status(format!("Not installed: {e}").into());
                toast(st, ui, "alarm", "Update not installed", &e);
            }
        }
    }
    if Instant::now() >= st.next_app_check && !ui.get_app_update_busy() {
        check_app_update(st, ui, Duration::ZERO);
    }
    if st.toast_until.is_some_and(|t| Instant::now() > t) {
        st.toast_until = None;
        ui.set_toast_visible(false);
    }
    if st.flash_until.is_some_and(|t| Instant::now() > t) {
        st.flash_until = None;
        ui.set_flash(false);
    }
}

// ---------- window + tray ----------

fn show_window(ui: &AppWindow, st: &mut State) {
    let _ = ui.show();
    st.window_visible = true;
    use slint::winit_030::WinitWindowAccessor;
    ui.window().with_winit_window(|w| {
        w.set_minimized(false);
        w.focus_window();
    });
}

fn hide_window(ui: &AppWindow, st: &mut State) {
    if st.settings.close_to_tray {
        let _ = ui.hide();
        st.window_visible = false;
        if !st.settings.told_about_tray {
            st.settings.told_about_tray = true;
            st.settings.save();
            notify("Hexward is still running", "It's in the notification area by the clock. Right-click the shield to quit.");
        }
    } else {
        let _ = slint::quit_event_loop();
    }
}

struct Tray {
    _icon: tray_icon::TrayIcon,
    open: tray_icon::menu::MenuId,
    quick: tray_icon::menu::MenuId,
    quit: tray_icon::menu::MenuId,
}

fn make_tray() -> Option<Tray> {
    use tray_icon::menu::{Menu, MenuItem, PredefinedMenuItem};
    let (w, h, rgba) = art::render(&art::MARK, 2, art::mark_color(art::MOSS_HI, art::MOSS_LO, Some(art::OXIDE)));
    let icon = tray_icon::Icon::from_rgba(rgba, w, h).ok()?;
    let menu = Menu::new();
    let open = MenuItem::new("Open Hexward", true, None);
    let quick = MenuItem::new("Quick scan", true, None);
    let quit = MenuItem::new("Quit Hexward", true, None);
    menu.append_items(&[&open, &quick, &PredefinedMenuItem::separator(), &quit]).ok()?;
    let tray = tray_icon::TrayIconBuilder::new().with_icon(icon).with_tooltip("Hexward").with_menu(Box::new(menu)).build().ok()?;
    Some(Tray { _icon: tray, open: open.id().clone(), quick: quick.id().clone(), quit: quit.id().clone() })
}

// ---------- main ----------

fn main() -> Result<(), slint::PlatformError> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--shots") {
        return shots::run(PathBuf::from(args.get(i + 1).cloned().unwrap_or_else(|| "shots".into())));
    }
    if let Ok(exe) = std::env::current_exe() {
        appupdate::cleanup_old(&exe);
    }

    let ui = AppWindow::new()?;
    set_assets(&ui);
    ui.set_version(env!("CARGO_PKG_VERSION").into());

    let settings = Settings::load();
    let settings_shields = (settings.file_shield, settings.process_shield, settings.clickfix_shield, settings.stealer_shield, settings.auto_quarantine);
    ui.global::<Theme>().set_dark(settings.dark);
    let threats = Rc::new(VecModel::<ThreatRow>::default());
    ui.set_threats(ModelRc::from(threats.clone()));
    let vault_rows = Rc::new(VecModel::<VaultRow>::default());
    ui.set_vault_rows(ModelRc::from(vault_rows.clone()));
    let drives = Rc::new(VecModel::<DriveRow>::default());
    ui.set_drives(ModelRc::from(drives.clone()));
    let folders = Rc::new(VecModel::<SharedString>::default());
    ui.set_folders(ModelRc::from(folders.clone()));

    let st = Rc::new(RefCell::new(State {
        settings,
        engine: None,
        engine_slot: slot(),
        reloading: false,
        scan: None,
        reports: Vec::new(),
        threats,
        drives,
        folders,
        startup_items: Vec::new(),
        startup_visible: Vec::new(),
        startup_slot: slot(),
        startup_fix_slot: slot(),
        startup_checked_at: None,
        update_slot: slot(),
        vault_rows,
        toast_until: None,
        flash_until: None,
        release: None,
        app_check_slot: slot(),
        app_install_slot: slot(),
        next_app_check: Instant::now() + Duration::from_secs(6 * 3600),
        window_visible: true,
        shields: shields::Shields::start(settings_shields.0, settings_shields.1, settings_shields.2, settings_shields.3, settings_shields.4),
        tasks: taskman::TaskMan::new(),
        cleaner: cleanui::Cleaner::new(),
        #[cfg(windows)]
        clip_owner: clipboard::owner_window(),
    }));
    {
        let mut s = st.borrow_mut();
        ui.set_tasks(s.tasks.model());
        load_engine(&mut s);
        refresh_vault(&s, &ui);
        refresh_home(&s, &ui);
        refresh_settings(&s, &ui);
        refresh_history(&ui);
        refresh_drives(&s);
        check_app_update(&mut s, &ui, Duration::from_secs(4));
        if let Some(v) = args.iter().find_map(|a| a.strip_prefix("--updated=")) {
            toast(&mut s, &ui, "safe", &format!("Updated to {v}"), "The signed update installed. Welcome to the new version.");
        }
    }

    macro_rules! on {
        ($setter:ident, |$s:ident, $u:ident $(, $a:ident : $t:ty)*| $body:block) => {{
            let st = st.clone();
            let w = ui.as_weak();
            ui.$setter(move |$($a: $t),*| {
                let Some($u) = w.upgrade() else { return };
                let Ok(mut guard) = st.try_borrow_mut() else { return };
                let $s: &mut State = &mut guard;
                $body
            });
        }};
    }

    on!(on_navigate, |s, u, page: SharedString| {
        s.tasks.set_active(page == "tasks");
        match page.as_str() {
            "tasks" => taskman::show(s, &u),
            "cleaner" => cleanui::on_open(s, &u),
            "home" => refresh_home(s, &u),
            "vault" => refresh_vault(s, &u),
            "history" => refresh_history(&u),
            "settings" => refresh_settings(s, &u),
            "scan" => refresh_drives(s),
            "scan-new" => {
                u.set_scan_started(false);
                refresh_drives(s);
            }
            _ => {}
        }
    });
    on!(on_start_scan, |s, u, kind: SharedString| {
        let kind: &'static str = match kind.as_str() {
            "system" => "system",
            "full" => "full",
            "custom" => "custom",
            _ => "quick",
        };
        start_scan(s, &u, kind);
    });
    {
        // The folder picker runs its own message loop, so it opens before the state is borrowed.
        let st = st.clone();
        ui.on_add_folder(move || {
            let picked = rfd::FileDialog::new().set_title("Add a folder or project to scan").pick_folders();
            if let (Some(list), Ok(s)) = (picked, st.try_borrow()) {
                for f in list {
                    let f: SharedString = f.display().to_string().into();
                    if !s.folders.iter().any(|x| x == f) {
                        s.folders.push(f);
                    }
                }
            }
        });
    }
    on!(on_remove_folder, |s, _u, i: i32| {
        if (i as usize) < s.folders.row_count() {
            s.folders.remove(i as usize);
        }
    });
    on!(on_toggle_drive, |s, _u, i: i32| {
        if let Some(mut d) = s.drives.row_data(i as usize) {
            d.selected = !d.selected;
            s.drives.set_row_data(i as usize, d);
        }
    });
    on!(on_pause_scan, |s, u| {
        if let Some(job) = s.scan.as_mut() {
            let now_paused = !job.progress.paused.load(Ordering::Relaxed);
            job.progress.paused.store(now_paused, Ordering::Relaxed);
            if now_paused {
                job.paused_at = Some(Instant::now());
            } else if let Some(t) = job.paused_at.take() {
                job.paused_total += t.elapsed();
            }
            u.set_paused(now_paused);
        }
    });
    on!(on_stop_scan, |s, u| {
        if let Some(job) = s.scan.as_ref() {
            job.progress.paused.store(false, Ordering::Relaxed);
            job.cancel.store(true, Ordering::Relaxed);
            u.set_scan_title("Stopping…".into());
        }
    });
    on!(on_toggle_threat, |s, u, i: i32| {
        if let Some(mut row) = s.threats.row_data(i as usize) {
            row.selected = !row.selected;
            s.threats.set_row_data(i as usize, row);
            update_results_header(s, &u);
        }
    });
    on!(on_quarantine_selected, |s, u| {
        let which: Vec<usize> = s.threats.iter().enumerate().filter(|(_, r)| r.selected && !r.done).map(|(i, _)| i).collect();
        quarantine_rows(s, &u, &which);
    });
    on!(on_quarantine_one, |s, u, i: i32| { quarantine_rows(s, &u, &[i as usize]) });
    on!(on_ask_delete, |s, _u, i: i32| {
        if let Some(mut row) = s.threats.row_data(i as usize) {
            row.confirm_delete = true;
            s.threats.set_row_data(i as usize, row);
        }
    });
    on!(on_cancel_delete, |s, _u, i: i32| {
        if let Some(mut row) = s.threats.row_data(i as usize) {
            row.confirm_delete = false;
            s.threats.set_row_data(i as usize, row);
        }
    });
    on!(on_delete_one, |s, u, i: i32| { delete_row(s, &u, i as usize) });
    on!(on_allow_one, |s, u, i: i32| { allow_row(s, &u, i as usize) });
    on!(on_allow_remove, |s, u, sha: SharedString| {
        if allowlist::remove(&sha).is_ok() {
            if let Some(e) = &s.engine {
                e.reload_allowlist();
            }
            refresh_settings(s, &u);
            toast(s, &u, "scan", "No longer trusted", "Hexward will scan that file again.");
        }
    });
    on!(on_check_startup, |s, u| { check_startup(s, &u) });
    on!(on_startup_changed, |s, u| { show_startup(s, &u) });
    on!(on_set_show_all, |s, u, v: bool| {
        u.set_startup_show_all(v);
        show_startup(s, &u);
    });
    // Switching runs on a worker: tasks and services may wait on a UAC prompt.
    on!(on_disable_startup, |s, u, i: i32| {
        let Some(&idx) = s.startup_visible.get(i as usize) else { return };
        let item = s.startup_items[idx].0.clone();
        u.set_startup_busy(true);
        let out = s.startup_fix_slot.clone();
        std::thread::spawn(move || {
            let r = startup::disable(&item);
            if let Ok(mut g) = out.lock() {
                *g = Some((true, r));
            }
        });
    });
    on!(on_restore_startup, |s, u, id: SharedString| {
        u.set_startup_busy(true);
        let out = s.startup_fix_slot.clone();
        std::thread::spawn(move || {
            let r = startup::restore(&id);
            if let Ok(mut g) = out.lock() {
                *g = Some((false, r));
            }
        });
    });
    on!(on_vault_ask, |s, _u, i: i32| {
        if let Some(mut r) = s.vault_rows.row_data(i as usize) {
            r.confirm = true;
            s.vault_rows.set_row_data(i as usize, r);
        }
    });
    on!(on_vault_cancel, |s, _u, i: i32| {
        if let Some(mut r) = s.vault_rows.row_data(i as usize) {
            r.confirm = false;
            s.vault_rows.set_row_data(i as usize, r);
        }
    });
    on!(on_vault_restore, |s, u, id: SharedString| {
        match Vault::open(Vault::default_dir()).and_then(|v| v.restore(&id, None, false)) {
            Ok(path) => {
                log(EventKind::Restore, "File restored", path.display().to_string());
                refresh_vault(s, &u);
                toast(s, &u, "scan", "File restored", &path.display().to_string());
            }
            Err(e) => toast(s, &u, "warn", "Couldn't restore", &e.to_string()),
        }
    });
    on!(on_vault_delete, |s, u, id: SharedString| {
        match Vault::open(Vault::default_dir()).and_then(|v| v.delete(&id)) {
            Ok(()) => {
                log(EventKind::Delete, "Deleted forever", format!("Quarantine item {id}"));
                refresh_vault(s, &u);
                toast(s, &u, "off", "Deleted forever", "The file is gone.");
            }
            Err(e) => toast(s, &u, "warn", "Couldn't delete", &e.to_string()),
        }
    });
    on!(on_tasks_changed, |s, u| { taskman::show(s, &u) });
    on!(on_task_ask_end, |s, u, pid: i32| { taskman::ask_end(s, &u, pid) });
    on!(on_task_end, |s, u, pid: i32| { taskman::end(s, &u, pid) });
    on!(on_task_scan, |s, u, path: SharedString| { taskman::scan(s, &u, path) });
    on!(on_task_open, |_s, _u, path: SharedString| { taskman::open_location(path) });
    on!(on_cleaner_analyze, |s, u| { cleanui::analyze(s, &u) });
    on!(on_cleaner_toggle, |s, u, id: SharedString| { cleanui::toggle(s, &u, &id) });
    on!(on_cleaner_clean, |s, u| { cleanui::clean(s, &u) });
    on!(on_cleaner_close_browser, |s, u, id: SharedString| { cleanui::close_browser(s, &u, &id) });
    on!(on_update_rules, |s, u| { update_rules(s, &u) });
    on!(on_check_app_update, |s, u| { check_app_update(s, &u, Duration::ZERO) });
    on!(on_install_app_update, |s, u| { install_app_update(s, &u) });
    on!(on_set_dark, |s, u, v: bool| {
        s.settings.dark = v;
        s.settings.save();
        u.global::<Theme>().set_dark(v);
    });
    on!(on_set_max_size, |s, u, v: SharedString| {
        if let Some(n) = v.split_whitespace().next().and_then(|n| n.parse().ok()) {
            s.settings.max_size_mb = n;
            s.settings.save();
            u.set_max_size_mb(n as i32);
        }
    });
    on!(on_set_quarantine_suspicious, |s, u, v: bool| {
        s.settings.quarantine_suspicious = v;
        s.settings.save();
        u.set_quarantine_suspicious(v);
    });
    on!(on_set_file_shield, |s, u, v: bool| {
        s.settings.file_shield = v;
        s.settings.save();
        s.shields.file_on.store(v, Ordering::Relaxed);
        u.set_file_shield(v);
        refresh_home(s, &u);
        toast(s, &u, if v { "safe" } else { "warn" }, if v { "File shield on" } else { "File shield off" }, if v { "New downloads are checked as they arrive." } else { "New downloads won't be checked until you turn it back on." });
    });
    on!(on_set_process_shield, |s, u, v: bool| {
        s.settings.process_shield = v;
        s.settings.save();
        s.shields.process_on.store(v, Ordering::Relaxed);
        u.set_process_shield(v);
        refresh_home(s, &u);
    });
    on!(on_set_clickfix_shield, |s, u, v: bool| {
        s.settings.clickfix_shield = v;
        s.settings.save();
        s.shields.clickfix_on.store(v, Ordering::Relaxed);
        u.set_clickfix_shield(v);
        refresh_home(s, &u);
    });
    on!(on_set_stealer_shield, |s, u, v: bool| {
        s.settings.stealer_shield = v;
        s.settings.save();
        s.shields.stealer_on.store(v, Ordering::Relaxed);
        u.set_stealer_shield(v);
        refresh_home(s, &u);
    });
    on!(on_set_auto_quarantine, |s, u, v: bool| {
        s.settings.auto_quarantine = v;
        s.settings.save();
        s.shields.auto_quarantine.store(v, Ordering::Relaxed);
        u.set_auto_quarantine(v);
    });
    on!(on_set_close_to_tray, |s, u, v: bool| {
        s.settings.close_to_tray = v;
        s.settings.save();
        u.set_close_to_tray(v);
    });
    on!(on_set_pack, |s, u, v: SharedString| {
        s.settings.pack = v.to_string();
        s.settings.save();
        u.set_pack(v);
    });
    on!(on_open_data_dir, |_s, _u| {
        let _ = std::fs::create_dir_all(data_dir());
        let _ = std::process::Command::new("explorer").arg(data_dir()).spawn();
    });

    // Window controls (the system frame is off; these replace it).
    {
        use slint::winit_030::{WinitWindowAccessor, winit::window::ResizeDirection};
        let w = ui.as_weak();
        ui.on_drag_window(move || {
            if let Some(u) = w.upgrade() {
                u.window().with_winit_window(|win| {
                    let _ = win.drag_window();
                });
            }
        });
        let w = ui.as_weak();
        ui.on_resize_window(move |dir| {
            let d = match dir.as_str() {
                "n" => ResizeDirection::North,
                "s" => ResizeDirection::South,
                "e" => ResizeDirection::East,
                "w" => ResizeDirection::West,
                "se" => ResizeDirection::SouthEast,
                "sw" => ResizeDirection::SouthWest,
                _ => return,
            };
            if let Some(u) = w.upgrade() {
                u.window().with_winit_window(|win| {
                    let _ = win.drag_resize_window(d);
                });
            }
        });
        let w = ui.as_weak();
        ui.on_minimize_window(move || {
            if let Some(u) = w.upgrade() {
                u.window().set_minimized(true);
            }
        });
        let w = ui.as_weak();
        ui.on_toggle_maximize(move || {
            if let Some(u) = w.upgrade() {
                let m = !u.window().is_maximized();
                u.window().set_maximized(m);
                u.set_is_max(m);
            }
        });
    }
    on!(on_close_window, |s, u| { hide_window(&u, s) });
    {
        let st = st.clone();
        let w = ui.as_weak();
        ui.window().on_close_requested(move || {
            if let (Some(u), Ok(mut s)) = (w.upgrade(), st.try_borrow_mut()) {
                hide_window(&u, &mut s);
            }
            slint::CloseRequestResponse::KeepWindowShown
        });
    }

    let tray = make_tray();
    let timer = Timer::default();
    {
        let st = st.clone();
        let w = ui.as_weak();
        timer.start(TimerMode::Repeated, Duration::from_millis(100), move || {
            let Some(u) = w.upgrade() else { return };
            let Ok(mut s) = st.try_borrow_mut() else { return };
            if let Some(t) = &tray {
                while let Ok(ev) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                    if ev.id == t.open {
                        show_window(&u, &mut s);
                    } else if ev.id == t.quick {
                        show_window(&u, &mut s);
                        start_scan(&mut s, &u, "quick");
                    } else if ev.id == t.quit {
                        let _ = slint::quit_event_loop();
                    }
                }
                while let Ok(ev) = tray_icon::TrayIconEvent::receiver().try_recv() {
                    if matches!(
                        ev,
                        tray_icon::TrayIconEvent::Click { button: tray_icon::MouseButton::Left, button_state: tray_icon::MouseButtonState::Up, .. }
                            | tray_icon::TrayIconEvent::DoubleClick { .. }
                    ) {
                        show_window(&u, &mut s);
                    }
                }
            }
            tick(&mut s, &u);
        });
    }

    ui.show()?;
    slint::run_event_loop_until_quit()
}
