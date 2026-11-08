//! Task manager screen. A worker thread owns the process list and refreshes it every 1.5 s
//! while the screen is open; it also reads program icons and checks signatures of programs
//! running from risky folders. The UI thread only turns snapshots into rows.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hexward_engine::history::{Event, EventKind};
use hexward_engine::tasks::{Group, Proc, TaskList};
use hexward_engine::{FileReport, sig};
use slint::{Image, Model, ModelRc, SharedString, VecModel};

use crate::{AppWindow, State, TaskRow, bytes, icons, log, toast};

type Pixels = (u32, u32, Vec<u8>);
type MemorySlot = Arc<Mutex<Option<(Vec<hexward_engine::memscan::MemoryFinding>, usize)>>>;
type ScanSlot = Arc<Mutex<Option<(PathBuf, Result<Option<FileReport>, String>)>>>;

struct Snapshot {
    procs: Vec<Proc>,
    icons: Vec<(String, Pixels)>,
    unsigned: HashSet<String>,
    memory: (u64, u64),
}

#[derive(Default)]
struct Shared {
    snapshot: Option<Snapshot>,
    end_requests: Vec<u32>,
    end_results: Vec<(String, Result<u32, String>)>,
}

pub struct TaskMan {
    active: Arc<AtomicBool>,
    shared: Arc<Mutex<Shared>>,
    started: bool,
    icons: HashMap<String, Image>,
    procs: Vec<Proc>,
    unsigned: HashSet<String>,
    memory: (u64, u64),
    rows: Rc<VecModel<TaskRow>>,
    confirm: Option<u32>,
    scan_slot: ScanSlot,
    memory_slot: MemorySlot,
}

fn key(p: &std::path::Path) -> String {
    p.to_string_lossy().to_lowercase()
}

impl TaskMan {
    pub fn new() -> Self {
        TaskMan {
            active: Arc::new(AtomicBool::new(false)),
            shared: Arc::new(Mutex::new(Shared::default())),
            started: false,
            icons: HashMap::new(),
            procs: Vec::new(),
            unsigned: HashSet::new(),
            memory: (0, 0),
            rows: Rc::new(VecModel::default()),
            confirm: None,
            scan_slot: Arc::new(Mutex::new(None)),
            memory_slot: Arc::new(Mutex::new(None)),
        }
    }

    pub fn model(&self) -> ModelRc<TaskRow> {
        ModelRc::from(self.rows.clone())
    }

    /// Called on every page change: the worker only runs while the Tasks screen is open.
    pub fn set_active(&mut self, on: bool) {
        self.active.store(on, Ordering::Relaxed);
        if on && !self.started {
            self.started = true;
            let (active, shared) = (self.active.clone(), self.shared.clone());
            std::thread::Builder::new().name("task-manager".into()).spawn(move || worker(active, shared)).ok();
        }
    }
}

fn worker(active: Arc<AtomicBool>, shared: Arc<Mutex<Shared>>) {
    icons::init_thread();
    let Some(mut list) = TaskList::new() else { return };
    let mut seen_icons: HashSet<String> = HashSet::new();
    let mut signed: HashMap<String, bool> = HashMap::new();
    let mut last = Instant::now() - Duration::from_secs(10);
    loop {
        let ends: Vec<u32> = shared.lock().map(|mut s| std::mem::take(&mut s.end_requests)).unwrap_or_default();
        for pid in &ends {
            let name = list.name_of(*pid).unwrap_or_else(|| format!("process {pid}"));
            let r = list.end(*pid);
            if let Ok(mut s) = shared.lock() {
                s.end_results.push((name, r));
            }
        }
        if active.load(Ordering::Relaxed) && (!ends.is_empty() || last.elapsed() >= Duration::from_millis(1500)) {
            last = Instant::now();
            let procs = list.refresh();
            let mut new_icons = Vec::new();
            let mut unsigned = HashSet::new();
            for p in &procs {
                let Some(exe) = &p.exe else { continue };
                let k = key(exe);
                if seen_icons.insert(k.clone())
                    && let Some(px) = icons::file_icon(exe)
                {
                    new_icons.push((k.clone(), px));
                }
                if p.risky_place && !*signed.entry(k.clone()).or_insert_with(|| sig::is_signed(exe)) {
                    unsigned.insert(k);
                }
            }
            let memory = list.memory();
            if let Ok(mut s) = shared.lock() {
                s.snapshot = Some(Snapshot { procs, icons: new_icons, unsigned, memory });
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn group_name(g: Group) -> &'static str {
    match g {
        Group::Apps => "apps",
        Group::Background => "background",
        Group::Windows => "windows",
    }
}

/// Rebuilds the visible rows from the last snapshot, the chosen group, search and sort.
pub fn show(st: &mut State, ui: &AppWindow) {
    let tm = &st.tasks;
    let group = ui.get_tasks_group().to_string();
    let search = ui.get_tasks_search().to_lowercase();
    let sort = ui.get_tasks_sort().to_string();
    let total_mem = tm.memory.1.max(1);
    let mut list: Vec<&Proc> = tm
        .procs
        .iter()
        .filter(|p| group_name(p.group) == group)
        .filter(|p| {
            search.is_empty()
                || p.name.to_lowercase().contains(&search)
                || p.file.to_lowercase().contains(&search)
                || p.publisher.as_deref().is_some_and(|x| x.to_lowercase().contains(&search))
                || p.window_title.as_deref().is_some_and(|x| x.to_lowercase().contains(&search))
        })
        .collect();
    match sort.as_str() {
        "CPU" => list.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))),
        "Memory" => list.sort_by_key(|p| std::cmp::Reverse(p.memory)),
        _ => list.sort_by_key(|a| a.name.to_lowercase()),
    }
    let rows: Vec<TaskRow> = list
        .iter()
        .map(|p| {
            let k = p.exe.as_deref().map(key).unwrap_or_default();
            let icon = tm.icons.get(&k).cloned();
            let unsigned_risky = tm.unsigned.contains(&k);
            let mut detail = Vec::new();
            if let Some(pb) = &p.publisher {
                detail.push(pb.clone());
            } else if !p.protected {
                detail.push("No publisher".into());
            }
            if let Some(t) = &p.window_title
                && t != &p.name
            {
                detail.push(t.clone());
            }
            if let Some(svc) = &p.service
                && svc != &p.name
            {
                detail.push(format!("Service: {svc}"));
            }
            detail.push(p.file.clone());
            if p.count > 1 {
                detail.push(format!("{} processes", p.count));
            }
            TaskRow {
                pid: p.pid as i32,
                name: p.name.clone().into(),
                detail: detail.join(" · ").into(),
                path: p.exe.as_ref().map(|e| e.display().to_string()).unwrap_or_default().into(),
                has_icon: icon.is_some(),
                icon: icon.unwrap_or_default(),
                cpu: format!("{:.1}%", p.cpu).into(),
                cpu_frac: (p.cpu / 100.0).clamp(0.0, 1.0),
                mem: bytes(p.memory).into(),
                mem_frac: (p.memory as f64 / total_mem as f64 * 4.0).clamp(0.0, 1.0) as f32,
                protected: p.protected,
                risky: unsigned_risky,
                confirm: tm.confirm == Some(p.pid),
            }
        })
        .collect();
    // Update in place when the shape is unchanged, so the list doesn't flicker or lose its scroll.
    if rows.len() == tm.rows.row_count() {
        for (i, r) in rows.into_iter().enumerate() {
            if tm.rows.row_data(i).as_ref() != Some(&r) {
                tm.rows.set_row_data(i, r);
            }
        }
    } else {
        tm.rows.set_vec(rows);
    }
    let count = |g: Group| tm.procs.iter().filter(|p| p.group == g).count() as i32;
    ui.set_tasks_n_apps(count(Group::Apps));
    ui.set_tasks_n_background(count(Group::Background));
    ui.set_tasks_n_windows(count(Group::Windows));
    let cpu: f32 = tm.procs.iter().map(|p| p.cpu).sum();
    ui.set_tasks_cpu(format!("{:.0}%", cpu.min(100.0)).into());
    ui.set_tasks_mem(format!("{} of {}", bytes(tm.memory.0), bytes(tm.memory.1)).into());
    ui.set_tasks_risky(tm.unsigned.len() as i32);
    ui.set_tasks_loading(tm.procs.is_empty());
}

/// Pulls the worker's results; called from the app's 100 ms timer.
pub fn tick(st: &mut State, ui: &AppWindow) {
    let (snapshot, ended) = match st.tasks.shared.lock() {
        Ok(mut s) => (s.snapshot.take(), std::mem::take(&mut s.end_results)),
        Err(_) => return,
    };
    for (name, r) in ended {
        match r {
            Ok(n) => {
                log(EventKind::EndTask, format!("Ended {name}"), if n > 1 { format!("{n} processes") } else { "1 process".into() });
                toast(st, ui, "safe", "Task ended", &format!("{name} was closed."));
            }
            Err(e) => toast(st, ui, "warn", "Couldn't end that task", &e),
        }
    }
    if let Some(s) = snapshot {
        for (k, px) in s.icons {
            st.tasks.icons.insert(k, crate::to_image(px));
        }
        st.tasks.procs = s.procs;
        st.tasks.unsigned = s.unsigned;
        st.tasks.memory = s.memory;
        show(st, ui);
    }
    let scanned = st.tasks.scan_slot.lock().ok().and_then(|mut g| g.take());
    if let Some((path, r)) = scanned {
        ui.set_tasks_scanning(false);
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        match r {
            Ok(Some(rep)) if !rep.detections.is_empty() => {
                let det = rep.detections[0].name.clone();
                st.threats.push(crate::row_for(&rep, rep.is_confirmed()));
                st.reports.push(rep);
                let mut e = Event::new(EventKind::Scan, "Task manager scan", format!("{det} · {}", path.display()));
                e.files = 1;
                e.threats = 1;
                hexward_engine::history::append(e);
                crate::update_results_header(st, ui);
                toast(st, ui, "alarm", &format!("{name}: {det}"), "Open Results to quarantine it. End the task first if it's running.");
            }
            Ok(Some(_)) => {
                let mut e = Event::new(EventKind::Scan, "Task manager scan", format!("{} · clean", path.display()));
                e.files = 1;
                hexward_engine::history::append(e);
                toast(st, ui, "safe", &format!("{name} is clean"), "No known threat in this program.");
            }
            Ok(None) => toast(st, ui, "warn", "Too large to scan", &name),
            Err(e) => toast(st, ui, "warn", "Couldn't scan it", &e),
        }
    }
}

pub fn ask_end(st: &mut State, ui: &AppWindow, pid: i32) {
    st.tasks.confirm = (pid >= 0).then_some(pid as u32);
    show(st, ui);
}

pub fn end(st: &mut State, ui: &AppWindow, pid: i32) {
    st.tasks.confirm = None;
    if let Ok(mut s) = st.tasks.shared.lock() {
        s.end_requests.push(pid as u32);
    }
    show(st, ui);
}

pub fn scan(st: &mut State, ui: &AppWindow, path: SharedString) {
    let Some(engine) = st.engine.clone() else {
        toast(st, ui, "warn", "Rules are still loading", "Try again in a moment.");
        return;
    };
    if path.is_empty() {
        toast(st, ui, "warn", "Can't scan this one", "Windows doesn't show Hexward where this program lives.");
        return;
    }
    ui.set_tasks_scanning(true);
    let out = st.tasks.scan_slot.clone();
    let path = PathBuf::from(path.as_str());
    std::thread::spawn(move || {
        let mut scanner = engine.rules().scanner();
        let r = engine.scan_file(&mut scanner, &path, 512 * 1024 * 1024).map_err(|e| e.to_string());
        if let Ok(mut g) = out.lock() {
            *g = Some((path, r));
        }
    });
}

/// Reads the memory of every running program it may read, on a worker thread.
pub fn scan_memory(st: &mut State, ui: &AppWindow) {
    let Some(engine) = st.engine.clone() else {
        toast(st, ui, "warn", "Rules are still loading", "Try again in a moment.");
        return;
    };
    if ui.get_tasks_memory_busy() {
        return;
    }
    ui.set_tasks_memory_busy(true);
    let out = st.tasks.memory_slot.clone();
    std::thread::spawn(move || {
        hexward_engine::perf::background_thread();
        let r = hexward_engine::memscan::scan_all(&engine);
        if let Ok(mut g) = out.lock() {
            *g = Some(r);
        }
    });
}

/// Called from tick(): turns memory findings into alerts (never into quarantine of the program
/// file: the program itself may be the victim of an injection).
pub fn tick_memory(st: &mut State, ui: &AppWindow) {
    let done = st.tasks.memory_slot.lock().ok().and_then(|mut g| g.take());
    let Some((found, read)) = done else { return };
    ui.set_tasks_memory_busy(false);
    let mut e = Event::new(EventKind::Scan, "Memory scan", format!("{read} programs' memory read · {} found", found.len()));
    e.threats = found.len() as u64;
    hexward_engine::history::append(e);
    if found.is_empty() {
        toast(st, ui, "safe", "Memory looks clean", &format!("Read the memory of {read} running programs. Nothing hiding there."));
        return;
    }
    for f in found {
        let d = &f.detections[0];
        crate::shield_hit(
            st,
            ui,
            crate::shields::ShieldEvent {
                shield: "Memory scan",
                report: None,
                title: format!("{} in the memory of {} (pid {})", d.name, f.name, f.pid),
                action: format!("{} End the program in Tasks; if it's a Windows program, restart the PC and run a full scan.", d.description),
                quarantined: false,
                neutralize: false,
            },
        );
    }
}

pub fn open_location(path: SharedString) {
    if !path.is_empty() {
        let _ = std::process::Command::new("explorer").arg(format!("/select,{path}")).spawn();
    }
}
