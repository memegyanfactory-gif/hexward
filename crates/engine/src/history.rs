//! A small, local activity log: scans, quarantine actions, rule updates, startup fixes.
//! Stored as JSON in the Hexward data folder. Never leaves the PC.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Local, NaiveDate, Utc};
use serde::{Deserialize, Serialize};

const FILE: &str = "history.json";
const KEEP: usize = 5000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Scan,
    Quarantine,
    Restore,
    Delete,
    Update,
    StartupFix,
    EndTask,
    Clean,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub at: DateTime<Utc>,
    pub kind: EventKind,
    pub title: String,
    pub detail: String,
    /// For scans: files checked and threats found.
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub threats: u64,
}

impl Event {
    pub fn new(kind: EventKind, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Event { at: Utc::now(), kind, title: title.into(), detail: detail.into(), files: 0, threats: 0 }
    }
}

fn path() -> PathBuf {
    crate::data_dir().join(FILE)
}

/// Newest first.
pub fn load() -> Vec<Event> {
    let mut v: Vec<Event> = std::fs::read(path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    v.sort_by_key(|e| std::cmp::Reverse(e.at));
    v
}

/// Adds an event. Best effort: a full disk never breaks a scan.
pub fn append(event: Event) {
    let mut v = load();
    v.insert(0, event);
    v.truncate(KEEP);
    let _ = std::fs::create_dir_all(crate::data_dir());
    if let Ok(bytes) = serde_json::to_vec(&v) {
        let tmp = path().with_extension("tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(tmp, path());
        }
    }
}

/// Per local day: (files checked, threats found), for the threat map.
pub fn daily(events: &[Event]) -> BTreeMap<NaiveDate, (u64, u64)> {
    let mut m: BTreeMap<NaiveDate, (u64, u64)> = BTreeMap::new();
    for e in events.iter().filter(|e| e.kind == EventKind::Scan) {
        let day = e.at.with_timezone(&Local).date_naive();
        let entry = m.entry(day).or_default();
        entry.0 += e.files;
        entry.1 += e.threats;
    }
    m
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daily_totals() {
        let mut a = Event::new(EventKind::Scan, "Quick scan", "");
        a.files = 10;
        a.threats = 1;
        let mut b = a.clone();
        b.files = 5;
        b.threats = 0;
        let c = Event::new(EventKind::Restore, "x", "");
        let d = daily(&[a.clone(), b, c]);
        assert_eq!(d.get(&a.at.with_timezone(&Local).date_naive()), Some(&(15, 1)));
    }
}
