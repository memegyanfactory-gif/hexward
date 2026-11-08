//! "Dev & AI" screen: project audit, Hexward Guard and MCP servers, extension inventory.
//! Audits and inventories run on worker threads; this file moves their results into the UI.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use hexward_engine::audit::{self, Level, Options, Report};
use hexward_engine::extensions::{self, Change, Extension};
use hexward_engine::guard::{self, Decision};
use hexward_engine::history::{Event, EventKind};
use hexward_engine::mcp::{self, Status};
use slint::{ModelRc, SharedString, VecModel};

use crate::{AppWindow, AuditRow, ExtRow, GuardRow, McpRow, State, thousands, toast, when};

type Slot<T> = Arc<Mutex<Option<T>>>;
/// Extensions, what changed, and when the previous inventory was taken.
type Inventory = (Vec<Extension>, Vec<Change>, Option<chrono::DateTime<chrono::Utc>>);

#[derive(Default)]
pub struct Dev {
    audit: Slot<Result<(Report, String), String>>,
    exts: Slot<Inventory>,
    root: Option<PathBuf>,
}

impl Dev {
    pub fn new() -> Self {
        Dev::default()
    }
}

fn take<T>(s: &Slot<T>) -> Option<T> {
    s.lock().ok().and_then(|mut g| g.take())
}

fn tone(l: Level) -> &'static str {
    match l {
        Level::High => "alarm",
        Level::Medium => "warn",
        Level::Low => "scan",
        Level::Info => "off",
    }
}

pub fn on_open(st: &mut State, ui: &AppWindow) {
    refresh_agents(st, ui);
}

// ---------- project audit ----------

pub fn pick(ui: &AppWindow) {
    if let Some(p) = rfd::FileDialog::new().set_title("Pick a project folder to audit").pick_folder() {
        ui.set_audit_target(p.display().to_string().into());
    }
}

pub fn run(st: &mut State, ui: &AppWindow) {
    if ui.get_audit_busy() {
        return;
    }
    let target = ui.get_audit_target().trim().to_string();
    if target.is_empty() {
        toast(st, ui, "warn", "Pick a project first", "Choose a folder, or paste a GitHub address.");
        return;
    }
    let (online, history) = (ui.get_audit_online(), ui.get_audit_history());
    ui.set_audit_busy(true);
    ui.set_audit_status(if audit::is_remote(&target) { "Downloading the repository (nothing from it runs)…".into() } else { "Reading the project…".into() });
    let out = st.dev.audit.clone();
    std::thread::spawn(move || {
        let r = (|| -> Result<(Report, String), String> {
            let mut temp = None;
            let root = if audit::is_remote(&target) {
                let dir = std::env::temp_dir().join(format!("hexward-audit-{}-{}", std::process::id(), chrono::Utc::now().timestamp()));
                audit::clone(&target, &dir, if history { 1000 } else { 1 })?;
                temp = Some(dir.clone());
                dir
            } else {
                let p = PathBuf::from(&target);
                if !p.is_dir() {
                    return Err(format!("{target} isn't a folder."));
                }
                p
            };
            let mut report = audit::audit(&root, &Options { history, history_commits: 1000 });
            let mut note = format!("{} files read", thousands(report.files));
            if online {
                let o = hexward_update::online::check(&report);
                note.push_str(&format!(" · {} package versions checked with OSV.dev · {} names checked on npm/PyPI", thousands(o.checked_versions as u64), o.checked_names));
                if !o.errors.is_empty() {
                    note.push_str(&format!(" ({})", o.errors.join("; ")));
                }
                hexward_update::online::apply(&mut report, &o);
            }
            if let Some(t) = temp {
                let _ = std::fs::remove_dir_all(t);
                report.root = PathBuf::new(); // the clone is gone: no "show file" buttons
            }
            Ok((report, note))
        })();
        if let Ok(mut g) = out.lock() {
            *g = Some(r);
        }
    });
}

fn show_report(st: &mut State, ui: &AppWindow, r: &Report, note: &str) {
    let rows: Vec<AuditRow> = r
        .findings
        .iter()
        .filter(|f| ui.get_audit_show_info() || f.level != Level::Info)
        .map(|f| {
            let place = match (f.file.as_str(), f.line) {
                ("", _) => String::new(),
                (file, Some(l)) => format!("{file}:{l}"),
                (file, None) => file.to_string(),
            };
            let abs = if r.root.as_os_str().is_empty() || f.file.is_empty() { String::new() } else { r.root.join(&f.file).display().to_string() };
            AuditRow {
                level: f.level.label().into(),
                tone: tone(f.level).into(),
                category: f.category.label().into(),
                title: f.title.clone().into(),
                place: place.into(),
                detail: f.detail.clone().into(),
                evidence: f.evidence.clone().into(),
                fix: f.fix.clone().into(),
                file: abs.into(),
            }
        })
        .collect();
    ui.set_audit_rows(ModelRc::new(VecModel::from(rows)));
    let (h, m, l) = (r.count(Level::High), r.count(Level::Medium), r.count(Level::Low));
    ui.set_audit_summary(if h + m + l == 0 { format!("Nothing risky found · {note}").into() } else { format!("{h} high · {m} medium · {l} low · {note}").into() });
    ui.set_audit_state(if h > 0 { "alarm".into() } else if m > 0 { "warn".into() } else { "safe".into() });
    ui.set_audit_done(true);
    st.dev.root = Some(r.root.clone());
}

pub fn open_file(path: SharedString) {
    if !path.is_empty() {
        let _ = std::process::Command::new("explorer").arg(format!("/select,{path}")).spawn();
    }
}

// ---------- Guard and MCP ----------

pub fn refresh_agents(st: &mut State, ui: &AppWindow) {
    let installed = guard::claude_settings_path().is_some_and(|p| guard::is_installed(&p));
    ui.set_guard_installed(installed);
    let rows: Vec<GuardRow> = guard::recent(40)
        .into_iter()
        .map(|e| GuardRow {
            when: when(e.at).into(),
            decision: if e.decision == Decision::Deny { "BLOCKED".into() } else { "ASKED".into() },
            tone: if e.decision == Decision::Deny { "alarm".into() } else { "warn".into() },
            subject: audit::snippet(&e.subject, 140).into(),
            reasons: e.reasons.join(" ").into(),
        })
        .collect();
    ui.set_guard_rows(ModelRc::new(VecModel::from(rows)));
    let project = st.dev.root.clone().filter(|p| !p.as_os_str().is_empty());
    let list = mcp::status(project.as_deref());
    ui.set_mcp_waiting(list.iter().filter(|(_, s)| *s != Status::Pinned).count() as i32);
    let rows: Vec<McpRow> = list
        .into_iter()
        .map(|(s, status)| McpRow {
            name: s.name.clone().into(),
            app: s.app.clone().into(),
            summary: audit::snippet(&s.summary(), 120).into(),
            status: match status {
                Status::Pinned => "APPROVED",
                Status::New => "NEW",
                Status::Changed => "CHANGED",
            }
            .into(),
            tone: match status {
                Status::Pinned => "safe",
                Status::New => "warn",
                Status::Changed => "alarm",
            }
            .into(),
            note: if status == Status::Changed {
                "Its command, address, settings or script changed since you approved it. Check what changed before approving again.".into()
            } else if s.unpinned_package {
                "Downloads the newest package version on every start. Pin a version so a takeover can't slip in.".into()
            } else if !s.url.is_empty() {
                "Remote server: what the agent sends it leaves your PC.".into()
            } else {
                "".into()
            },
        })
        .collect();
    ui.set_mcp_rows(ModelRc::new(VecModel::from(rows)));
}

pub fn set_guard(st: &mut State, ui: &AppWindow, on: bool) {
    let Some(path) = guard::claude_settings_path() else { return };
    let r = if on { std::env::current_exe().map_err(|e| e.to_string()).and_then(|exe| guard::install(&path, &exe)) } else { guard::uninstall(&path) };
    match r {
        Ok(()) => {
            crate::log(EventKind::Update, if on { "Hexward Guard turned on for Claude Code" } else { "Hexward Guard turned off for Claude Code" }, path.display().to_string());
            toast(st, ui, "safe", if on { "Guard is on" } else { "Guard is off" }, if on { "Claude Code's commands and file edits are checked first. Restart Claude Code to pick it up." } else { "Claude Code works as before." });
        }
        Err(e) => toast(st, ui, "warn", "Couldn't change Claude Code's settings", &e),
    }
    refresh_agents(st, ui);
}

pub fn approve(st: &mut State, ui: &AppWindow, name: &str) {
    let project = st.dev.root.clone().filter(|p| !p.as_os_str().is_empty());
    let names: Vec<String> = if name.is_empty() { Vec::new() } else { vec![name.to_string()] };
    match mcp::approve(project.as_deref(), &names) {
        Ok(n) => toast(st, ui, "safe", "Approved", &format!("{n} MCP server(s) recorded. Hexward will tell you if any of them changes.")),
        Err(e) => toast(st, ui, "warn", "Couldn't save", &e),
    }
    refresh_agents(st, ui);
}

// ---------- extensions ----------

pub fn refresh_extensions(st: &mut State, ui: &AppWindow) {
    if ui.get_ext_busy() {
        return;
    }
    ui.set_ext_busy(true);
    let out = st.dev.exts.clone();
    std::thread::spawn(move || {
        let list = extensions::inventory();
        let old = extensions::load_snapshot();
        let changes = if old.taken.is_some() { extensions::diff(&old, &extensions::snapshot_of(&list)) } else { Vec::new() };
        let _ = extensions::save_snapshot(&list);
        if let Ok(mut g) = out.lock() {
            *g = Some((list, changes, old.taken));
        }
    });
}

fn show_extensions(ui: &AppWindow, list: &[Extension], changes: &[Change], since: Option<chrono::DateTime<chrono::Utc>>) {
    let change_of = |key: &str| {
        changes.iter().find_map(|c| match c {
            Change::Added { key: k, .. } if k == key => Some("NEW".to_string()),
            Change::Updated { key: k, from, .. } if k == key => Some(format!("UPDATED from {from}")),
            _ => None,
        })
    };
    let mut rows: Vec<ExtRow> = list
        .iter()
        .map(|x| ExtRow {
            app: x.app.clone().into(),
            name: x.name.clone().into(),
            version: x.version.clone().into(),
            id: x.id.clone().into(),
            notes: x.notes.iter().filter(|_| x.level != Some(Level::Info)).cloned().collect::<Vec<_>>().join(" · ").into(),
            level: x.level.filter(|l| *l != Level::Info).map(|l| l.label()).unwrap_or("").into(),
            tone: x.level.map(tone).unwrap_or("off").into(),
            change: change_of(&x.key()).unwrap_or_default().into(),
        })
        .collect();
    for c in changes {
        if let Change::Removed { key, name, version } = c {
            rows.push(ExtRow { app: key.split('|').next().unwrap_or("").into(), name: name.clone().into(), version: version.clone().into(), id: "".into(), notes: "".into(), level: "".into(), tone: "off".into(), change: "REMOVED".into() });
        }
    }
    // Worth-a-look first, then changes, then the rest.
    rows.sort_by_key(|r| (r.level.is_empty(), r.change.is_empty(), r.app.to_string(), r.name.to_lowercase()));
    ui.set_ext_rows(ModelRc::new(VecModel::from(rows)));
    let risky = list.iter().filter(|x| matches!(x.level, Some(Level::High | Level::Medium))).count();
    ui.set_ext_summary(
        format!(
            "{} extensions · {risky} worth a look · {}",
            list.len(),
            match since {
                None => "first inventory saved".to_string(),
                Some(_) if changes.is_empty() => format!("no changes since {}", when(since.unwrap())),
                Some(t) => format!("{} change(s) since {}", changes.len(), when(t)),
            }
        )
        .into(),
    );
    ui.set_ext_loaded(true);
}

pub fn tick(st: &mut State, ui: &AppWindow) {
    if let Some(r) = take(&st.dev.audit) {
        ui.set_audit_busy(false);
        ui.set_audit_status("".into());
        match r {
            Ok((report, note)) => {
                let target = ui.get_audit_target().to_string();
                let mut e = Event::new(EventKind::Scan, "Project audit", format!("{target} · {} high, {} medium", report.count(Level::High), report.count(Level::Medium)));
                e.threats = report.count(Level::High) as u64;
                hexward_engine::history::append(e);
                show_report(st, ui, &report, &note);
                st.dev_report = Some((report, note));
                refresh_agents(st, ui);
            }
            Err(e) => toast(st, ui, "warn", "Couldn't audit it", &e),
        }
    }
    if let Some((list, changes, since)) = take(&st.dev.exts) {
        ui.set_ext_busy(false);
        show_extensions(ui, &list, &changes, since);
    }
}

/// Re-renders the last report (the "show info" switch changed).
pub fn reshow(st: &mut State, ui: &AppWindow) {
    if let Some((r, note)) = st.dev_report.take() {
        show_report(st, ui, &r, &note);
        st.dev_report = Some((r, note));
    }
}
