//! `hexward`: the command-line scanner.
//!
//! Exit codes: 0 nothing found, 1 threats found, 2 something went wrong.

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use hexward_engine::{Engine, FileReport, Progress, ScanOptions, ScanSummary, Severity, Vault, locations, startup};
use serde::Serialize;

use hexward_update as update;

mod audit_cmd;
mod guard_cmd;

#[derive(Parser)]
#[command(name = "hexward", version, about = "Free, open-source malware scanner. Every byte, warded.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan files and folders. With no paths, runs a quick scan.
    Scan(ScanArgs),
    /// List and scan programs that start with Windows.
    Startup {
        /// Show every item, not only problems.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        rules: RuleArgs,
    },
    /// Manage quarantined files.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Download the latest rule packs (YARA Forge, and MalwareBazaar hashes with an Auth-Key).
    Update {
        /// Which YARA Forge pack to use: core (from Hexward's signed rule channel), extended, full or off.
        #[arg(long, default_value = "core")]
        yara: update::ForgePack,
        /// Ignore the 5-minute wait between MalwareBazaar downloads.
        #[arg(long)]
        force: bool,
        /// Go back to the previous rule pack.
        #[arg(long)]
        rollback: bool,
        #[arg(long)]
        json: bool,
    },
    /// Check a project or repository for supply-chain and AI-agent traps.
    Audit(audit_cmd::AuditArgs),
    /// Hexward Guard: check AI-agent commands, watch MCP servers.
    #[command(subcommand)]
    Guard(guard_cmd::GuardCmd),
    /// List editor and browser extensions, flag risky ones, show what changed.
    Extensions {
        #[arg(long)]
        json: bool,
        /// Don't remember this inventory for the next comparison.
        #[arg(long)]
        no_save: bool,
    },
    /// Show which rules and hash lists are loaded.
    Rules {
        /// List rules that were left out.
        #[arg(long)]
        verbose: bool,
        #[command(flatten)]
        rules: RuleArgs,
    },
}

#[derive(Args)]
struct RuleArgs {
    /// Extra folder of .yar rules and .txt/.csv hash lists. Repeatable.
    #[arg(long = "rules", value_name = "DIR")]
    dirs: Vec<PathBuf>,
}

#[derive(Args)]
struct ScanArgs {
    /// Files or folders to scan.
    paths: Vec<PathBuf>,
    /// Scan every fixed drive.
    #[arg(long, conflicts_with = "paths")]
    full: bool,
    /// Move confirmed threats to quarantine.
    #[arg(long)]
    quarantine: bool,
    /// With --quarantine, also move files only flagged as suspicious.
    #[arg(long, requires = "quarantine")]
    include_suspicious: bool,
    /// Skip files larger than this many MB.
    #[arg(long, default_value_t = 64)]
    max_size_mb: u64,
    /// Worker threads (default: CPU cores, up to 16).
    #[arg(long, default_value_t = 0)]
    threads: usize,
    /// Scan the memory of running programs instead of files.
    #[arg(long, conflicts_with_all = ["paths", "full"])]
    memory: bool,
    /// Scan at background priority so the PC stays responsive.
    #[arg(long)]
    low_priority: bool,
    /// File or folder to skip. Repeatable.
    #[arg(long, value_name = "PATH")]
    exclude: Vec<PathBuf>,
    /// Check every file again, even ones a previous scan found clean.
    #[arg(long)]
    no_cache: bool,
    /// Print the result as JSON.
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    rules: RuleArgs,
}

#[derive(Subcommand)]
enum QuarantineCmd {
    /// List quarantined files.
    List {
        #[arg(long)]
        json: bool,
    },
    /// Put a file back where it was.
    Restore {
        id: String,
        /// Restore to this path instead.
        #[arg(long)]
        to: Option<PathBuf>,
        /// Replace a file that is already there.
        #[arg(long)]
        overwrite: bool,
    },
    /// Delete a quarantined file forever.
    Delete { id: String },
    /// Delete items older than this many days.
    Purge {
        #[arg(long, default_value_t = 30)]
        days: i64,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan(a) => cmd_scan(a),
        Command::Startup { all, json, rules } => cmd_startup(all, json, &rules),
        Command::Quarantine(q) => cmd_quarantine(q).map(|_| false),
        Command::Update { rollback: true, .. } => update::rollback().map(|_| {
            println!("Back on the previous rule pack.");
            false
        }),
        Command::Update { yara, force, json, .. } => cmd_update(yara, force, json).map(|_| false),
        Command::Rules { verbose, rules } => cmd_rules(&rules, verbose).map(|_| false),
        Command::Audit(a) => audit_cmd::run(a),
        // These report their own exit codes (guard check: 0 allow, 1 ask, 2 deny).
        Command::Guard(g) => return coded(guard_cmd::run(g)),
        Command::Extensions { json, no_save } => return coded(guard_cmd::extensions_cmd(json, no_save)),
    };
    match result {
        Ok(false) => ExitCode::from(0),
        Ok(true) => ExitCode::from(1),
        Err(e) => {
            eprintln!("hexward: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn coded(r: Result<u8>) -> ExitCode {
    match r {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("hexward: {e:#}");
            ExitCode::from(3)
        }
    }
}

// ---------- output helpers ----------

struct Style {
    on: bool,
}

impl Style {
    fn stdout() -> Self {
        Style { on: std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none() }
    }
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on { format!("\x1b[{code}m{s}\x1b[0m") } else { s.to_string() }
    }
    fn sev(&self, s: Severity) -> String {
        match s {
            Severity::High => self.paint("1;31", "HIGH  "),
            Severity::Medium => self.paint("33", "MEDIUM"),
            Severity::Low => self.paint("2", "LOW   "),
        }
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn good(&self, s: &str) -> String {
        self.paint("32", s)
    }
}

fn thousands(n: u64) -> String {
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

fn rule_dirs(extra: &RuleArgs) -> Vec<PathBuf> {
    let mut v = vec![hexward_engine::data_dir().join("rules")];
    if let Some(exe_dir) = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)) {
        v.push(exe_dir.join("rules"));
    }
    v.extend(extra.dirs.iter().cloned());
    v
}

fn load_engine(extra: &RuleArgs) -> Result<Engine> {
    Engine::load(&rule_dirs(extra)).context("couldn't load rules")
}

// ---------- scan ----------

#[derive(Serialize)]
struct ScanOutput<'a> {
    kind: &'a str,
    summary: &'a ScanSummary,
    quarantined: Vec<Moved>,
    not_quarantined: Vec<Failed>,
}

#[derive(Serialize)]
struct Moved {
    path: PathBuf,
    id: String,
}

#[derive(Serialize)]
struct Failed {
    path: PathBuf,
    reason: String,
}

fn cmd_scan(a: ScanArgs) -> Result<bool> {
    let st = Style::stdout();
    let engine = load_engine(&a.rules)?;
    if a.memory {
        if !a.json {
            println!("Reading the memory of running programs…");
        }
        let (found, read) = hexward_engine::memscan::scan_all(&engine);
        if a.json {
            let rows: Vec<_> = found.iter().map(|f| serde_json::json!({ "pid": f.pid, "name": f.name, "address": format!("{:#x}", f.address), "detections": f.detections })).collect();
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "programs_read": read, "findings": rows }))?);
        } else {
            for f in &found {
                for d in &f.detections {
                    println!("  {} {}  {}", st.sev(d.severity), d.name, st.dim(&format!("{} (pid {}) at {:#x}", f.name, f.pid, f.address)));
                    println!("          {}", d.description);
                }
            }
            println!("{} programs' memory read{}.", read, if found.is_empty() { ", nothing found" } else { "" });
            println!("{}", st.dim("Programs running as administrator or protected by Windows can only be read from an elevated prompt."));
        }
        return Ok(found.iter().any(|f| f.detections.iter().any(|d| d.is_confirmed())));
    }
    let vault_dir = Vault::default_dir();

    let (kind, roots): (&str, Vec<PathBuf>) = if a.full {
        ("full scan", locations::fixed_drives())
    } else if !a.paths.is_empty() {
        for p in &a.paths {
            if !p.exists() {
                anyhow::bail!("{} doesn't exist", p.display());
            }
        }
        ("custom scan", a.paths.clone())
    } else {
        let mut roots = locations::quick_scan_folders();
        roots.extend(locations::running_programs());
        roots.extend(startup::list_startup_items().into_iter().filter_map(|i| i.target).filter(|t| t.is_file()));
        ("quick scan", roots)
    };

    let mut excludes = a.exclude.clone();
    excludes.push(vault_dir.clone());
    // Never scan Hexward's own data: the rule files would match the rules.
    excludes.push(hexward_engine::data_dir());
    let cache = (!a.no_cache).then(|| std::sync::Arc::new(hexward_engine::cache::ScanCache::open(hexward_engine::cache::ScanCache::default_path(), engine.fingerprint())));
    let opts = ScanOptions { max_size: a.max_size_mb * 1024 * 1024, threads: a.threads, excludes, cache, low_priority: a.low_priority };

    if !a.json {
        println!("{} {} · {}", st.good("hexward"), env!("CARGO_PKG_VERSION"), kind);
        println!(
            "{}",
            st.dim(&format!("Rules: {} YARA {}, {} known-bad {}", thousands(engine.rule_count() as u64), if engine.rule_count() == 1 { "rule" } else { "rules" }, thousands(engine.hash_count() as u64), if engine.hash_count() == 1 { "hash" } else { "hashes" }))
        );
    }

    let progress = Progress::default();
    let cancel = AtomicBool::new(false);
    let done = AtomicBool::new(false);
    let show_progress = !a.json && std::io::stderr().is_terminal();
    let start = Instant::now();

    let summary = std::thread::scope(|s| {
        if show_progress {
            s.spawn(|| {
                let mut err = std::io::stderr();
                while !done.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(200));
                    let files = progress.files.load(Ordering::Relaxed);
                    let rate = files as f64 / start.elapsed().as_secs_f64().max(0.001);
                    let cur = progress.current.lock().map(|p| p.display().to_string()).unwrap_or_default();
                    let cur: String = if cur.chars().count() > 60 {
                        format!("…{}", cur.chars().rev().take(59).collect::<Vec<_>>().into_iter().rev().collect::<String>())
                    } else {
                        cur
                    };
                    let _ = write!(
                        err,
                        "\r\x1b[2K{} files · {} found · {}/s · {}",
                        thousands(files),
                        progress.threats.load(Ordering::Relaxed),
                        thousands(rate as u64),
                        cur
                    );
                    let _ = err.flush();
                }
                let _ = write!(err, "\r\x1b[2K");
            });
        }
        let summary = engine.scan_paths(&roots, &opts, &progress, &cancel);
        done.store(true, Ordering::Relaxed);
        summary
    });

    // Quarantine
    let mut moved = Vec::new();
    let mut failed = Vec::new();
    if a.quarantine && !summary.threats.is_empty() {
        let vault = Vault::open(&vault_dir)?;
        for t in &summary.threats {
            if !t.is_confirmed() && !a.include_suspicious {
                continue;
            }
            let name = &t.detections[0].name;
            match vault.quarantine(&t.path, name) {
                Ok(e) => moved.push(Moved { path: t.path.clone(), id: e.id }),
                Err(e) => failed.push(Failed { path: t.path.clone(), reason: e.to_string() }),
            }
        }
    }

    if a.json {
        let out = ScanOutput { kind, summary: &summary, quarantined: moved, not_quarantined: failed };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(!summary.threats.is_empty());
    }

    let secs = summary.elapsed_ms as f64 / 1000.0;
    println!();
    println!(
        "{} {} files checked ({}) in {:.1} s · {} files/s",
        if summary.cancelled { "Scan stopped." } else { "Scan finished." },
        thousands(summary.files_scanned),
        bytes(summary.bytes_scanned),
        secs,
        thousands((summary.files_scanned as f64 / secs.max(0.001)) as u64)
    );
    if summary.cached > 0 {
        println!("{}", st.dim(&format!("{} of them unchanged since a previous clean scan, so they were skipped (--no-cache checks everything).", thousands(summary.cached))));
    }
    if summary.skipped_large + summary.unreadable > 0 {
        println!(
            "{}",
            st.dim(&format!(
                "Skipped {} files over {} MB and {} that couldn't be read (in use or no permission).",
                thousands(summary.skipped_large),
                a.max_size_mb,
                thousands(summary.unreadable)
            ))
        );
    }
    println!();

    if summary.threats.is_empty() {
        println!("{}", st.good("Nothing found."));
        return Ok(false);
    }

    let confirmed = summary.threats.iter().filter(|t| t.is_confirmed()).count();
    let suspicious = summary.threats.len() - confirmed;
    let mut head = Vec::new();
    if confirmed > 0 {
        head.push(format!("{confirmed} {}", if confirmed == 1 { "threat" } else { "threats" }));
    }
    if suspicious > 0 {
        head.push(format!("{suspicious} suspicious {}", if suspicious == 1 { "file" } else { "files" }));
    }
    println!("{} found", head.join(" and "));
    println!();
    for t in &summary.threats {
        print_report(&st, t);
        if let Some(m) = moved.iter().find(|m| m.path == t.path) {
            println!("          {}", st.good(&format!("Moved to quarantine · id {}", m.id)));
        }
        if let Some(f) = failed.iter().find(|f| f.path == t.path) {
            println!("          {}", st.paint("31", &format!("Not moved: {}", f.reason)));
        }
        println!();
    }
    if !a.quarantine {
        println!("Nothing was changed. Run again with --quarantine to move confirmed threats to quarantine.");
    } else if suspicious > 0 && !a.include_suspicious {
        println!("Suspicious files were left in place. Add --include-suspicious to quarantine them too.");
    }
    Ok(true)
}

fn print_report(st: &Style, t: &FileReport) {
    for (i, d) in t.detections.iter().enumerate() {
        let tag = if d.is_confirmed() { String::new() } else { st.dim("  (suspicious)") };
        if i == 0 {
            println!("  {}  {}{}", st.sev(d.severity), d.name, tag);
            println!("          {}", t.path.display());
            if let Some(inner) = &d.inner {
                println!("          {}", st.dim(&format!("inside: {inner}")));
            }
        } else {
            println!("          also: {}{}{}", d.name, tag, d.inner.as_ref().map(|i| format!("  (inside: {i})")).unwrap_or_default());
        }
    }
    println!("          {}", st.dim(&t.detections[0].description));
}

// ---------- startup ----------

#[derive(Serialize)]
struct StartupRow {
    #[serde(flatten)]
    item: startup::StartupItem,
    status: &'static str,
    detections: Vec<hexward_engine::Detection>,
}

fn cmd_startup(all: bool, json: bool, rules: &RuleArgs) -> Result<bool> {
    let st = Style::stdout();
    let engine = load_engine(rules)?;
    let mut scanner = engine.rules().scanner();
    let items = startup::list_startup_items();

    let mut rows = Vec::new();
    for item in items {
        let (status, detections) = match &item.target {
            Some(t) if t.is_file() => match engine.scan_file(&mut scanner, t, 256 * 1024 * 1024) {
                Ok(Some(r)) if !r.detections.is_empty() => ("threat", r.detections),
                Ok(Some(_)) => ("clean", Vec::new()),
                Ok(None) => ("too large", Vec::new()),
                Err(_) => ("unreadable", Vec::new()),
            },
            _ => ("missing", Vec::new()),
        };
        rows.push(StartupRow { item, status, detections });
    }
    let threats = rows.iter().filter(|r| r.status == "threat").count();

    if json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(threats > 0);
    }

    let count = |s: &str| rows.iter().filter(|r| r.status == s).count();
    println!(
        "{} startup items checked · {} clean · {} threats · {} point to missing files · {} unreadable",
        rows.len(),
        count("clean"),
        threats,
        count("missing"),
        count("unreadable")
    );
    println!();
    for r in &rows {
        let show = all || r.status == "threat" || (r.status == "missing" && r.item.location != "Driver");
        if !show {
            continue;
        }
        let status = match r.status {
            "threat" => st.paint("1;31", "THREAT "),
            "clean" => st.good("clean  "),
            "missing" => st.paint("33", "missing"),
            other => st.dim(&format!("{other:<7}")),
        };
        println!("  {status}  {} · {}", r.item.location, r.item.name);
        println!("           {}", st.dim(&r.item.command));
        for d in &r.detections {
            println!("           {} {}", st.sev(d.severity), d.name);
        }
    }
    if !all {
        println!();
        println!("{}", st.dim("Showing problems only. Add --all to list every item. Missing files are usually leftovers from uninstalled apps."));
    }
    Ok(threats > 0)
}

// ---------- quarantine + rules ----------

fn cmd_quarantine(q: QuarantineCmd) -> Result<()> {
    let vault = Vault::open(Vault::default_dir())?;
    match q {
        QuarantineCmd::List { json } => {
            let list = vault.list()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
            } else if list.is_empty() {
                println!("Quarantine is empty.");
            } else {
                for e in list {
                    println!("{}  {}  {}", e.id, e.quarantined_at.format("%Y-%m-%d %H:%M"), e.detection);
                    println!("                  {} · {}", e.original_path.display(), bytes(e.size));
                }
            }
        }
        QuarantineCmd::Restore { id, to, overwrite } => {
            let path = vault.restore(&id, to.as_deref(), overwrite)?;
            println!("Restored to {}", path.display());
        }
        QuarantineCmd::Delete { id } => {
            vault.delete(&id)?;
            println!("Deleted {id} forever.");
        }
        QuarantineCmd::Purge { days } => {
            let n = vault.purge_older_than(days)?;
            println!("Deleted {n} items older than {days} days.");
        }
    }
    Ok(())
}

fn cmd_rules(extra: &RuleArgs, verbose: bool) -> Result<()> {
    let t = Instant::now();
    let engine = load_engine(extra)?;
    println!("{} YARA {}, {} known-bad {} · loaded in {} ms", thousands(engine.rule_count() as u64), if engine.rule_count() == 1 { "rule" } else { "rules" }, thousands(engine.hash_count() as u64), if engine.hash_count() == 1 { "hash" } else { "hashes" }, t.elapsed().as_millis());
    let skipped = engine.skipped_rules();
    if !skipped.is_empty() {
        println!("{} rules were left out because they don't compile with YARA-X{}", skipped.len(), if verbose { ":" } else { " (--verbose lists them)." });
        if verbose {
            for s in skipped {
                println!("  {s}");
            }
        }
    }
    println!("Built-in rules are always loaded. Extra rules load from:");
    for d in rule_dirs(extra) {
        println!("  {} {}", d.display(), if d.is_dir() { "" } else { "(not there yet)" });
    }
    println!("Quarantine: {}", Vault::default_dir().display());
    Ok(())
}

fn cmd_update(pack: update::ForgePack, force: bool, json: bool) -> Result<()> {
    let st = Style::stdout();
    if !json {
        println!("Updating rule packs…");
    }
    let report = update::run(pack, force)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for (name, step) in [("YARA Forge", &report.yara_forge), ("MalwareBazaar", &report.malwarebazaar), ("Drivers", &report.drivers)] {
            match step {
                update::Step::Updated { detail } => println!("  {}  {name}: {detail}", st.good("updated")),
                update::Step::Skipped { reason } => println!("  {}  {name}: {reason}", st.dim("skipped")),
                update::Step::Failed { reason } => println!("  {}  {name}: {reason}", st.paint("31", "failed ")),
            }
        }
        println!("{}", st.dim(&format!("Rules folder: {}", report.rules_dir.display())));
    }
    if matches!(report.yara_forge, update::Step::Failed { .. }) || matches!(report.malwarebazaar, update::Step::Failed { .. }) {
        anyhow::bail!("some packs didn't update");
    }
    Ok(())
}
