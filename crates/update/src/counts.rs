//! "Share anonymous counts" (opt-in, off by default): how many scans, files, threats found, files
//! quarantined and threats blocked by the real-time shields, for "Threats caught so far" on
//! hexward.onurilabs.com. Numbers only: no file names, hashes, paths or install number.
//!
//! The app adds to a small file in the data folder as things happen (so a crash loses nothing),
//! and [`flush`] sends what has piled up since the last report, about once an hour and at exit.
//! A delta is only taken off after the server answers 2xx; network errors, 429 and 5xx keep it
//! for the next try. A 400 means the server will never take that body, so it's dropped.
//!
//! The first time the setting is switched on, the results already recorded in History are added
//! once ([`add_history_once`]); a marker in the same file makes sure that never happens twice.
//!
//! How things are counted (so "caught" and "stopped" on the website don't count anything twice):
//! - `threats`: everything a scan found (the number the app shows), and every threat a shield found and stopped.
//! - `blocked`: threats a real-time shield stopped (quarantined automatically, or a ClickFix
//!   command it replaced). A shield's own quarantine is counted here, not in `quarantined`.
//! - `quarantined`: files the person moved to quarantine from the results.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::Result;
use hexward_engine::history::{Event, EventKind};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const FILE: &str = "counts.json";
/// Roughly how often [`due`] says it's time to send.
pub const EVERY: Duration = Duration::from_secs(3600);
/// Most reports one flush sends (the server takes 30 an hour per network).
const MAX_PER_FLUSH: usize = 10;

/// What the server takes in one report.
pub const CAP: Counts = Counts { scans: 200, files: 5_000_000, threats: 5_000, quarantined: 5_000, blocked: 5_000 };

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Counts {
    pub scans: u64,
    pub files: u64,
    pub threats: u64,
    pub quarantined: u64,
    pub blocked: u64,
}

impl Counts {
    pub fn is_zero(&self) -> bool {
        *self == Counts::default()
    }

    pub fn add(&mut self, o: &Counts) {
        self.scans = self.scans.saturating_add(o.scans);
        self.files = self.files.saturating_add(o.files);
        self.threats = self.threats.saturating_add(o.threats);
        self.quarantined = self.quarantined.saturating_add(o.quarantined);
        self.blocked = self.blocked.saturating_add(o.blocked);
        // Quarantines of threats that were already reported can only ride along with later
        // threats (the server wants quarantined <= threats + blocked in each report). Don't let
        // that leftover grow without end.
        self.quarantined = self.quarantined.min(self.threats.saturating_add(self.blocked).saturating_add(CAP.quarantined));
    }

    pub fn sub(&mut self, o: &Counts) {
        self.scans = self.scans.saturating_sub(o.scans);
        self.files = self.files.saturating_sub(o.files);
        self.threats = self.threats.saturating_sub(o.threats);
        self.quarantined = self.quarantined.saturating_sub(o.quarantined);
        self.blocked = self.blocked.saturating_sub(o.blocked);
    }

    /// The next report to send: each number within the server's cap, quarantined no more than
    /// threats + blocked. None when there's nothing the server would count.
    pub fn next_report(&self) -> Option<Counts> {
        let mut c = Counts {
            scans: self.scans.min(CAP.scans),
            files: self.files.min(CAP.files),
            threats: self.threats.min(CAP.threats),
            quarantined: 0,
            blocked: self.blocked.min(CAP.blocked),
        };
        c.quarantined = self.quarantined.min(CAP.quarantined).min(c.threats + c.blocked);
        (!c.is_zero()).then_some(c)
    }

    /// The JSON body for `/api/hexward/counts`.
    pub fn body(&self) -> Value {
        serde_json::json!({
            "version": env!("CARGO_PKG_VERSION"),
            "scans": self.scans,
            "files": self.files,
            "threats": self.threats,
            "quarantined": self.quarantined,
            "blocked": self.blocked,
        })
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(default)]
struct Saved {
    pending: Counts,
    /// Unix seconds of the last send attempt.
    last_try: i64,
    /// The results already in History were added (once per install, never again).
    history_added: bool,
}

/// What a flush did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Flushed {
    /// Reports the server took (2xx).
    pub sent: usize,
    /// Whether something is still waiting (a failure, or more than one flush sends).
    pub left: bool,
}

/// One file guarded by a lock, so the UI thread can add while a background flush runs.
pub struct Store {
    path: PathBuf,
}

static LOCK: Mutex<()> = Mutex::new(());

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

impl Store {
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Store { path: path.into() }
    }

    fn load(&self) -> Saved {
        std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, s: &Saved) {
        if let Some(dir) = self.path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Ok(b) = serde_json::to_vec(s) {
            let tmp = self.path.with_extension("tmp");
            if std::fs::write(&tmp, b).is_ok() {
                let _ = std::fs::rename(tmp, &self.path);
            }
        }
    }

    fn edit<T>(&self, f: impl FnOnce(&mut Saved) -> T) -> T {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut s = self.load();
        let out = f(&mut s);
        self.save(&s);
        out
    }

    /// Adds to what's waiting to be sent.
    pub fn record(&self, c: Counts) {
        if !c.is_zero() {
            self.edit(|s| s.pending.add(&c));
        }
    }

    pub fn pending(&self) -> Counts {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        self.load().pending
    }

    /// Whether an hour has passed since the last try and something is waiting.
    pub fn due(&self) -> bool {
        let _g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let s = self.load();
        !s.pending.is_zero() && now() - s.last_try >= EVERY.as_secs() as i64
    }

    /// Throws away what's waiting (the setting was switched off).
    /// Keeps the History marker, so switching on again never sends History twice.
    pub fn clear(&self) {
        self.edit(|s| s.pending = Counts::default());
    }

    /// Adds `c` only the first time this is called for this store (the History backfill).
    /// Returns whether it was added.
    pub fn add_once(&self, c: Counts) -> bool {
        self.edit(|s| {
            if s.history_added {
                return false;
            }
            s.history_added = true;
            s.pending.add(&c);
            true
        })
    }

    /// Sends what's waiting with `post` (the body in, the HTTP status out), in as many reports
    /// as the caps need. Each report is taken off only after a 2xx.
    pub fn flush_with(&self, mut post: impl FnMut(&Value) -> Result<u16>) -> Flushed {
        let mut out = Flushed::default();
        self.edit(|s| s.last_try = now());
        for _ in 0..MAX_PER_FLUSH {
            let Some(report) = self.edit(|s| s.pending.next_report()) else { return out };
            match post(&report.body()) {
                Ok(code) if (200..300).contains(&code) => {
                    out.sent += 1;
                    self.edit(|s| s.pending.sub(&report));
                }
                // The server will never take this body; keeping it would block every later report.
                Ok(400) => self.edit(|s| s.pending.sub(&report)),
                // 429, 5xx, or no network: keep it for the next try.
                _ => {
                    out.left = true;
                    return out;
                }
            }
        }
        out.left = self.edit(|s| s.pending.next_report().is_some());
        out
    }
}

fn path_of() -> PathBuf {
    hexward_engine::data_dir().join(FILE)
}

/// Adds to the counts waiting on this PC. The caller checks the setting first.
pub fn record(c: Counts) {
    Store::at(path_of()).record(c);
}

pub fn due() -> bool {
    Store::at(path_of()).due()
}

pub fn clear() {
    Store::at(path_of()).clear();
}

/// Scans the person started (as History titles them; a stopped scan adds " (stopped)").
const SCAN_TITLES: [&str; 6] = ["Quick scan", "Full scan", "System scan", "Custom scan", "Task manager scan", "Memory scan"];
/// What a shield wrote in History when it stopped the threat (quarantined it, replaced a
/// ClickFix command, or ended the program).
const STOPPED: [&str; 3] = ["moved it to quarantine", "hexward replaced it", "hexward stopped it"];

/// The results already recorded in History, as counts: only what History holds, nothing estimated.
/// Project audits are left out (they're findings in code, not threats on this PC).
pub fn history_totals(events: &[Event]) -> Counts {
    let mut c = Counts::default();
    for e in events {
        match e.kind {
            EventKind::Quarantine => c.quarantined += 1,
            EventKind::Scan if e.title == "Project audit" => {}
            EventKind::Scan if SCAN_TITLES.iter().any(|t| e.title.starts_with(t)) => {
                c.scans += 1;
                c.files += e.files;
                c.threats += e.threats;
            }
            // Everything else in History as a scan is a real-time shield's hit.
            EventKind::Scan => {
                c.files += e.files;
                c.threats += e.threats;
                let detail = e.detail.to_lowercase();
                if e.threats > 0 && STOPPED.iter().any(|s| detail.contains(s)) {
                    c.blocked += 1;
                }
            }
            _ => {}
        }
    }
    c
}

/// The first time the setting is switched on: adds what History already holds, exactly once.
pub fn add_history_once() -> bool {
    Store::at(path_of()).add_once(history_totals(&hexward_engine::history::load()))
}

/// Sends what's waiting to hexward.onurilabs.com (or `HEXWARD_CLOUD`, for a local test server).
pub fn flush(timeout: Duration) -> Flushed {
    Store::at(path_of()).flush_to(&crate::cloud::base(), timeout)
}

impl Store {
    /// [`Store::flush_with`] over HTTP to `{base}/api/hexward/counts`.
    pub fn flush_to(&self, base: &str, timeout: Duration) -> Flushed {
        let url = format!("{base}/api/hexward/counts");
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .user_agent(concat!("hexward/", env!("CARGO_PKG_VERSION")))
            .http_status_as_error(false)
            .build()
            .into();
        self.flush_with(|body| Ok(agent.post(&url).header("Content-Type", "application/json").send(body.to_string())?.status().as_u16()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Store) {
        let d = tempfile::tempdir().unwrap();
        let s = Store::at(d.path().join(FILE));
        (d, s)
    }

    fn c(scans: u64, files: u64, threats: u64, quarantined: u64, blocked: u64) -> Counts {
        Counts { scans, files, threats, quarantined, blocked }
    }

    #[test]
    fn adds_up_and_survives_a_restart() {
        let (_d, s) = store();
        s.record(c(1, 100, 2, 0, 0));
        s.record(c(0, 1, 1, 1, 1));
        s.record(Counts::default());
        assert_eq!(Store::at(s.path.clone()).pending(), c(1, 101, 3, 1, 1));
    }

    #[test]
    fn cleared_only_after_a_2xx() {
        let (_d, s) = store();
        s.record(c(1, 50, 1, 1, 0));
        let mut bodies = Vec::new();
        let r = s.flush_with(|b| {
            bodies.push(b.clone());
            Ok(201)
        });
        assert_eq!(r, Flushed { sent: 1, left: false });
        assert_eq!(bodies[0]["files"], 50);
        assert_eq!(bodies[0]["quarantined"], 1);
        assert!(bodies[0]["version"].is_string());
        assert!(s.pending().is_zero());
        // Nothing waiting: nothing is sent.
        assert_eq!(s.flush_with(|_| panic!("sent an empty report")), Flushed::default());
    }

    #[test]
    fn kept_on_429_5xx_and_network_errors() {
        let (_d, s) = store();
        s.record(c(1, 10, 0, 0, 0));
        for answer in [Ok(429), Ok(500), Err(anyhow::anyhow!("offline"))] {
            let mut answer = Some(answer);
            let r = s.flush_with(|_| answer.take().unwrap());
            assert_eq!(r, Flushed { sent: 0, left: true });
            assert_eq!(s.pending(), c(1, 10, 0, 0, 0));
        }
    }

    #[test]
    fn counts_added_during_a_send_are_kept() {
        let (_d, s) = store();
        s.record(c(1, 10, 0, 0, 0));
        let other = Store::at(s.path.clone());
        let mut first = true;
        s.flush_with(|_| {
            if first {
                other.record(c(1, 5, 1, 0, 0));
                first = false;
            }
            Ok(201)
        });
        // The second report carried what was added mid-flush.
        assert!(s.pending().is_zero());
        s.record(c(0, 0, 0, 0, 2));
        let mut seen = None;
        s.flush_with(|_| Err(anyhow::anyhow!("offline")));
        s.flush_with(|b| {
            seen = Some(b["blocked"].as_u64().unwrap());
            Ok(200)
        });
        assert_eq!(seen, Some(2));
    }

    #[test]
    fn a_big_delta_goes_in_several_reports() {
        let (_d, s) = store();
        s.record(c(450, 12_000_000, 7_000, 3_000, 0));
        let mut bodies = Vec::new();
        let r = s.flush_with(|b| {
            bodies.push(b.clone());
            Ok(201)
        });
        assert_eq!(r.sent, 3);
        assert!(!r.left);
        for b in &bodies {
            assert!(b["scans"].as_u64().unwrap() <= CAP.scans);
            assert!(b["files"].as_u64().unwrap() <= CAP.files);
            assert!(b["threats"].as_u64().unwrap() <= CAP.threats);
            assert!(b["quarantined"].as_u64().unwrap() <= b["threats"].as_u64().unwrap() + b["blocked"].as_u64().unwrap());
        }
        let total = |k: &str| bodies.iter().map(|b| b[k].as_u64().unwrap()).sum::<u64>();
        assert_eq!((total("scans"), total("files"), total("threats"), total("quarantined")), (450, 12_000_000, 7_000, 3_000));
        assert!(s.pending().is_zero());
    }

    #[test]
    fn a_failure_midway_keeps_the_rest() {
        let (_d, s) = store();
        s.record(c(0, 0, 12_000, 0, 0));
        let mut n = 0;
        let r = s.flush_with(|_| {
            n += 1;
            Ok(if n == 1 { 201 } else { 429 })
        });
        assert_eq!(r, Flushed { sent: 1, left: true });
        assert_eq!(s.pending().threats, 7_000);
    }

    #[test]
    fn quarantined_never_exceeds_threats_plus_blocked() {
        // Quarantining files a scan found before the last report: the leftover waits.
        let mut p = c(0, 0, 0, 3, 0);
        assert_eq!(p.next_report(), None);
        p.add(&c(0, 0, 1, 0, 1));
        assert_eq!(p.next_report(), Some(c(0, 0, 1, 2, 1)));
        // ...but doesn't grow without end.
        let mut p = Counts::default();
        p.add(&c(0, 0, 0, 1_000_000, 0));
        assert_eq!(p.quarantined, CAP.quarantined);
    }

    fn ev(kind: EventKind, title: &str, detail: &str, files: u64, threats: u64) -> Event {
        let mut e = Event::new(kind, title, detail);
        e.files = files;
        e.threats = threats;
        e
    }

    #[test]
    fn history_becomes_counts_from_what_it_recorded() {
        let h = vec![
            ev(EventKind::Scan, "Full scan", "52,310 files · 3 found", 52_310, 3),
            ev(EventKind::Scan, "Quick scan (stopped)", "", 900, 0),
            ev(EventKind::Scan, "Task manager scan", "x · C:\\a.exe", 1, 1),
            ev(EventKind::Scan, "File shield", "Trojan/X · C:\\b.exe · Moved it to quarantine automatically.", 1, 1),
            ev(EventKind::Scan, "Stealer shield", "S · C:\\c.exe · Couldn't quarantine it: in use", 1, 1),
            ev(EventKind::Scan, "ClickFix shield", "Blocked a fake command · Hexward replaced it, so pasting it does nothing.", 0, 1),
            ev(EventKind::Scan, "Project audit", "repo · 2 high, 0 medium", 0, 2),
            ev(EventKind::Quarantine, "Trojan/X", "C:\\d.exe", 0, 0),
            ev(EventKind::Restore, "x", "", 0, 0),
        ];
        assert_eq!(history_totals(&h), c(3, 53_213, 7, 1, 2));
        assert!(history_totals(&[]).is_zero());
    }

    #[test]
    fn history_is_added_exactly_once() {
        let (_d, s) = store();
        assert!(s.add_once(c(12, 1_000, 30, 5, 2)));
        assert!(!s.add_once(c(12, 1_000, 30, 5, 2)), "a second switch-on adds nothing");
        assert_eq!(s.pending(), c(12, 1_000, 30, 5, 2));
        // Sent, switched off (clears what's waiting), restarted, switched on again: still nothing.
        s.flush_with(|_| Ok(201));
        s.clear();
        let again = Store::at(s.path.clone());
        assert!(!again.add_once(c(12, 1_000, 30, 5, 2)));
        assert!(again.pending().is_zero());
    }

    #[test]
    fn a_big_history_is_split_by_the_caps() {
        let (_d, s) = store();
        s.add_once(c(250, 9_000_000, 35, 18, 3));
        let mut bodies = Vec::new();
        s.flush_with(|b| {
            bodies.push(b.clone());
            Ok(201)
        });
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0]["scans"], 200);
        assert_eq!(bodies[0]["files"], 5_000_000);
        assert_eq!(bodies[1]["files"], 4_000_000);
        assert!(s.pending().is_zero());
    }

    #[test]
    fn a_400_is_dropped_not_retried() {
        let (_d, s) = store();
        s.record(c(1, 1, 0, 0, 0));
        let r = s.flush_with(|_| Ok(400));
        assert_eq!(r, Flushed { sent: 0, left: false });
        assert!(s.pending().is_zero());
    }

    /// A local stand-in for the website: answers each request with the next status and keeps
    /// the (path, body) it got. Never the live endpoint, which keeps totals for good.
    fn mock(statuses: Vec<u16>) -> (String, std::thread::JoinHandle<Vec<(String, Value)>>) {
        use std::io::{BufRead, BufReader, Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let h = std::thread::spawn(move || {
            let mut got = Vec::new();
            for status in statuses {
                let (mut sock, _) = l.accept().unwrap();
                let mut r = BufReader::new(sock.try_clone().unwrap());
                let (mut line, mut len) = (String::new(), 0usize);
                r.read_line(&mut line).unwrap();
                let path = line.split(' ').nth(1).unwrap_or("").to_string();
                loop {
                    let mut h = String::new();
                    r.read_line(&mut h).unwrap();
                    if h.trim().is_empty() {
                        break;
                    }
                    if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                        len = v.trim().parse().unwrap();
                    }
                }
                let mut body = vec![0; len];
                r.read_exact(&mut body).unwrap();
                got.push((path, serde_json::from_slice(&body).unwrap()));
                let answer = if status == 201 { r#"{"ok":true,"counted":true}"# } else { r#"{"error":"Too many reports"}"# };
                write!(sock, "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{answer}", answer.len()).unwrap();
            }
            got
        });
        (base, h)
    }

    #[test]
    fn sends_over_http_to_a_local_mock() {
        let (_d, s) = store();
        s.record(c(1, 300, 7_500, 2, 1));
        let (base, server) = mock(vec![201, 429]);
        let r = s.flush_to(&base, Duration::from_secs(10));
        let got = server.join().unwrap();
        assert_eq!(r, Flushed { sent: 1, left: true });
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].0, "/api/hexward/counts");
        let first = &got[0].1;
        assert_eq!((first["scans"].as_u64(), first["files"].as_u64(), first["threats"].as_u64(), first["quarantined"].as_u64(), first["blocked"].as_u64()), (Some(1), Some(300), Some(5_000), Some(2), Some(1)));
        // The second report was rate limited: what it carried is still waiting.
        assert_eq!(s.pending(), c(0, 0, 2_500, 0, 0));
        // Numbers and the version only.
        let mut keys: Vec<&str> = first.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort();
        assert_eq!(keys, ["blocked", "files", "quarantined", "scans", "threats", "version"]);
    }

    #[test]
    fn due_once_an_hour_with_something_waiting() {
        let (_d, s) = store();
        assert!(!s.due());
        s.record(c(1, 1, 0, 0, 0));
        assert!(s.due());
        s.flush_with(|_| Ok(429));
        assert!(!s.due(), "just tried");
        s.clear();
        assert!(s.pending().is_zero());
    }
}
