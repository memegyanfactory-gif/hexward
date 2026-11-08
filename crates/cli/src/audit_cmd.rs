//! `hexward audit <folder or repository URL>`: supply-chain and AI-agent audit of a project.

use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Args;
use hexward_engine::audit::{self, Level, Options, Report};
use hexward_update::online;

use crate::Style;

#[derive(Args)]
pub struct AuditArgs {
    /// A project folder, or a git repository address (https://… or git@…). Default: this folder.
    target: Option<String>,
    /// Also ask OSV.dev, npm and PyPI about the dependencies (sends package names and versions only).
    #[arg(long)]
    online: bool,
    /// Skip reading git history for old secrets.
    #[arg(long)]
    no_history: bool,
    /// Most commits to read for old secrets.
    #[arg(long, default_value_t = 1000)]
    commits: usize,
    /// Also show INFO findings.
    #[arg(long)]
    all: bool,
    /// Print the report as JSON.
    #[arg(long)]
    json: bool,
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Runs the audit. Returns true when something HIGH or MEDIUM was found (exit code 1).
pub fn run(a: AuditArgs) -> Result<bool> {
    let target = a.target.unwrap_or_else(|| ".".into());
    let mut _clone = None;
    let root = if audit::is_remote(&target) {
        let dir = std::env::temp_dir().join(format!("hexward-audit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        if !a.json {
            eprintln!("Cloning {target} (nothing from it runs)…");
        }
        if let Err(e) = audit::clone(&target, &dir, if a.no_history { 1 } else { a.commits.min(5000) }) {
            bail!(e);
        }
        _clone = Some(TempDir(dir.clone()));
        dir
    } else {
        let p = PathBuf::from(&target);
        if !p.is_dir() {
            bail!("{} isn't a folder", p.display());
        }
        p.canonicalize().unwrap_or(p)
    };
    let mut report = audit::audit(&root, &Options { history: !a.no_history, history_commits: a.commits });
    let mut online_note = None;
    if a.online {
        let o = online::check(&report);
        online_note = Some(format!(
            "Online: {} package versions checked with OSV.dev, {} names checked on npm/PyPI{}",
            o.checked_versions,
            o.checked_names,
            if o.errors.is_empty() { String::new() } else { format!(" ({})", o.errors.join("; ")) }
        ));
        online::apply(&mut report, &o);
    }
    if a.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print(&report, &target, a.all, online_note.as_deref());
    }
    Ok(report.findings.iter().any(|f| f.level <= Level::Medium))
}

fn print(r: &Report, target: &str, all: bool, online: Option<&str>) {
    let st = Style::stdout();
    let tag = |l: Level| match l {
        Level::High => st.paint("1;31", "HIGH  "),
        Level::Medium => st.paint("33", "MEDIUM"),
        Level::Low => st.paint("2", "LOW   "),
        Level::Info => st.paint("2", "INFO  "),
    };
    println!("Audit of {target}: {} files read", crate::thousands(r.files));
    let shown: Vec<_> = r.findings.iter().filter(|f| all || f.level != Level::Info).collect();
    if shown.is_empty() {
        println!("{}", st.good("Nothing risky found."));
    }
    let mut cat = None;
    for f in &shown {
        if cat != Some(f.category) {
            cat = Some(f.category);
            println!("\n{}", st.paint("1", f.category.label()));
        }
        let place = match (f.file.as_str(), f.line) {
            ("", _) => String::new(),
            (file, Some(l)) => format!("{file}:{l}"),
            (file, None) => file.to_string(),
        };
        println!("  {} {}", tag(f.level), f.title);
        if !place.is_empty() {
            println!("         {}", st.dim(&place));
        }
        println!("         {}", f.detail);
        if !f.evidence.is_empty() {
            println!("         {}", st.dim(&format!("> {}", f.evidence)));
        }
        println!("         Fix: {}", f.fix);
    }
    let hidden = r.findings.len() - shown.len();
    println!(
        "\n{} high · {} medium · {} low{}",
        r.count(Level::High),
        r.count(Level::Medium),
        r.count(Level::Low),
        if hidden > 0 { format!(" · {hidden} info (use --all)") } else { String::new() }
    );
    match online {
        Some(n) => println!("{}", st.dim(n)),
        None => println!("{}", st.dim("Tip: add --online to check dependencies against OSV.dev's malware list (sends package names and versions only).")),
    }
}
