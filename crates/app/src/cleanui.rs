//! Cleaner screen: finds browsers and Windows junk, shows sizes, cleans what the user ticks.
//! Measuring and cleaning run on worker threads; this file only moves results into the UI.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use hexward_engine::cleaner::{self, Browser, Cleaned, Item, Size};
use hexward_engine::history::EventKind;
use slint::{Image, ModelRc, VecModel};

use crate::{AppWindow, CleanGroup, CleanItemRow, State, bytes, icons, log, thousands, toast};

type Pixels = (u32, u32, Vec<u8>);

struct Analysis {
    browsers: Vec<Browser>,
    items: Vec<Item>,
    sizes: HashMap<String, Size>,
    running: HashSet<String>,
    icons: Vec<(String, Pixels)>,
}

type Slot<T> = Arc<Mutex<Option<T>>>;

#[derive(Default)]
pub struct Cleaner {
    browsers: Vec<Browser>,
    items: Vec<Item>,
    sizes: HashMap<String, Size>,
    running: HashSet<String>,
    icons: HashMap<String, Image>,
    analyzed: bool,
    analysis: Slot<Analysis>,
    cleaned: Slot<(Cleaned, Vec<String>)>,
    closed: Slot<(String, bool)>,
}

impl Cleaner {
    pub fn new() -> Self {
        Cleaner::default()
    }
}

fn ticked(st: &State, item: &Item) -> bool {
    item.available && st.settings.cleaner_ticks.as_ref().map_or(item.default_on, |t| t.iter().any(|x| x == &item.id))
}

pub fn analyze(st: &mut State, ui: &AppWindow) {
    if ui.get_cleaner_busy() {
        return;
    }
    ui.set_cleaner_busy(true);
    ui.set_cleaner_status("Looking for browsers and junk files…".into());
    let out = st.cleaner.analysis.clone();
    std::thread::spawn(move || {
        icons::init_thread();
        let browsers = cleaner::browsers();
        let items = cleaner::all_items(&browsers);
        let sizes = items.iter().map(|i| (i.id.clone(), cleaner::measure(i))).collect();
        let running = browsers.iter().filter(|b| cleaner::is_running(b.process)).map(|b| b.id.to_string()).collect();
        let icons = browsers.iter().filter_map(|b| b.exe.as_deref().and_then(icons::file_icon).map(|px| (b.id.to_string(), px))).collect();
        if let Ok(mut g) = out.lock() {
            *g = Some(Analysis { browsers, items, sizes, running, icons });
        }
    });
}

/// Rebuilds the groups and totals from the last analysis and the user's ticks.
pub fn show(st: &State, ui: &AppWindow) {
    let c = &st.cleaner;
    let mut groups: Vec<CleanGroup> = Vec::new();
    let mut selected = 0u64;
    let mut found = 0u64;
    let mut blocked: Vec<String> = Vec::new();
    let mut ids: Vec<(String, String)> = c.browsers.iter().map(|b| (b.id.to_string(), b.name.to_string())).collect();
    ids.push(("windows".into(), "Windows".into()));
    for (gid, name) in ids {
        let running = c.running.contains(&gid);
        let mut total = 0u64;
        let rows: Vec<CleanItemRow> = c
            .items
            .iter()
            .filter(|i| i.group == gid)
            .map(|i| {
                let s = c.sizes.get(&i.id).copied().unwrap_or_default();
                let on = ticked(st, i);
                total += s.bytes;
                if on && running {
                    // An open browser's items are skipped, so they don't count toward the total.
                    if s.files > 0 && !blocked.contains(&name) {
                        blocked.push(name.clone());
                    }
                } else if on {
                    selected += s.bytes;
                }
                CleanItemRow {
                    id: i.id.clone().into(),
                    label: i.label.into(),
                    description: i.description.into(),
                    size: if !i.available { "kept".into() } else if s.files == 0 { "empty".into() } else { format!("{} · {} files", bytes(s.bytes), thousands(s.files)).into() },
                    checked: on,
                    available: i.available,
                }
            })
            .collect();
        found += total;
        let icon = c.icons.get(&gid).cloned();
        groups.push(CleanGroup {
            id: gid.clone().into(),
            name: name.into(),
            has_icon: icon.is_some(),
            icon: icon.unwrap_or_default(),
            running,
            total: bytes(total).into(),
            items: ModelRc::new(VecModel::from(rows)),
        });
    }
    ui.set_cleaner_groups(ModelRc::new(VecModel::from(groups)));
    ui.set_cleaner_selected(bytes(selected).into());
    ui.set_cleaner_found(bytes(found).into());
    ui.set_cleaner_has_selection(selected > 0);
    ui.set_cleaner_browsers(c.browsers.len() as i32);
    let blocked_text = match blocked.len() {
        0 => String::new(),
        1 => format!("{} is open, so its ticked items will be skipped. Close it to include them.", blocked[0]),
        _ => format!("{} are open, so their ticked items will be skipped. Close them to include them.", blocked.join(" and ")),
    };
    ui.set_cleaner_blocked(blocked_text.into());
    ui.set_cleaner_analyzed(c.analyzed);
}

pub fn toggle(st: &mut State, ui: &AppWindow, id: &str) {
    let mut ticks: Vec<String> = st.cleaner.items.iter().filter(|i| ticked(st, i)).map(|i| i.id.clone()).collect();
    if let Some(p) = ticks.iter().position(|t| t == id) {
        ticks.remove(p);
    } else if st.cleaner.items.iter().any(|i| i.id == id && i.available) {
        ticks.push(id.to_string());
    }
    st.settings.cleaner_ticks = Some(ticks);
    st.settings.save();
    ui.set_cleaner_confirm(false);
    show(st, ui);
}

pub fn clean(st: &mut State, ui: &AppWindow) {
    if ui.get_cleaner_busy() {
        return;
    }
    let running = st.cleaner.running.clone();
    let chosen: Vec<Item> = st.cleaner.items.iter().filter(|i| ticked(st, i)).cloned().collect();
    let (todo, skipped): (Vec<Item>, Vec<Item>) = chosen.into_iter().partition(|i| !running.contains(&i.group));
    let skipped_names: Vec<String> = skipped.iter().map(|i| i.group.clone()).collect::<HashSet<_>>().into_iter().collect();
    ui.set_cleaner_confirm(false);
    ui.set_cleaner_busy(true);
    ui.set_cleaner_status("Cleaning…".into());
    let out = st.cleaner.cleaned.clone();
    std::thread::spawn(move || {
        let mut total = Cleaned::default();
        for i in &todo {
            let c = cleaner::clean(i);
            total.bytes += c.bytes;
            total.files += c.files;
            total.skipped += c.skipped;
        }
        if let Ok(mut g) = out.lock() {
            *g = Some((total, skipped_names));
        }
    });
}

pub fn close_browser(st: &mut State, ui: &AppWindow, id: &str) {
    let Some(b) = st.cleaner.browsers.iter().find(|b| b.id == id) else { return };
    let (process, id) = (b.process, b.id.to_string());
    ui.set_cleaner_status(format!("Asking {} to close…", b.name).into());
    ui.set_cleaner_busy(true);
    let out = st.cleaner.closed.clone();
    std::thread::spawn(move || {
        let ok = cleaner::close_politely(process);
        if let Ok(mut g) = out.lock() {
            *g = Some((id, ok));
        }
    });
}

pub fn tick(st: &mut State, ui: &AppWindow) {
    let a = st.cleaner.analysis.lock().ok().and_then(|mut g| g.take());
    if let Some(a) = a {
        for (id, px) in a.icons {
            st.cleaner.icons.insert(id, crate::to_image(px));
        }
        st.cleaner.browsers = a.browsers;
        st.cleaner.items = a.items;
        st.cleaner.sizes = a.sizes;
        st.cleaner.running = a.running;
        st.cleaner.analyzed = true;
        ui.set_cleaner_busy(false);
        ui.set_cleaner_status("".into());
        show(st, ui);
    }
    let done = st.cleaner.cleaned.lock().ok().and_then(|mut g| g.take());
    if let Some((c, skipped)) = done {
        ui.set_cleaner_busy(false);
        let mut detail = format!("{} files removed", thousands(c.files));
        if c.skipped > 0 {
            detail.push_str(&format!(", {} in use and left alone", thousands(c.skipped)));
        }
        if !skipped.is_empty() {
            let names: Vec<&str> = skipped.iter().filter_map(|g| st.cleaner.browsers.iter().find(|b| b.id == g).map(|b| b.name)).collect();
            detail.push_str(&format!(". Skipped {} because it was open", names.join(" and ")));
        }
        log(EventKind::Clean, format!("Freed {}", bytes(c.bytes)), detail.clone());
        toast(st, ui, "safe", &format!("Freed {}", bytes(c.bytes)), &detail);
        analyze(st, ui);
    }
    let closed = st.cleaner.closed.lock().ok().and_then(|mut g| g.take());
    if let Some((id, ok)) = closed {
        ui.set_cleaner_busy(false);
        ui.set_cleaner_status("".into());
        let name = st.cleaner.browsers.iter().find(|b| b.id == id).map(|b| b.name).unwrap_or("The browser");
        if ok {
            st.cleaner.running.remove(&id);
            toast(st, ui, "safe", &format!("{name} closed"), "Its items can be cleaned now. It reopens your tabs next time.");
        } else {
            toast(st, ui, "warn", &format!("{name} is still open"), "It may be asking about unsaved work. Close it yourself, then try again.");
        }
        show(st, ui);
    }
}

/// Every visit measures again: sizes and open browsers change all the time.
pub fn on_open(st: &mut State, ui: &AppWindow) {
    show(st, ui);
    analyze(st, ui);
}
