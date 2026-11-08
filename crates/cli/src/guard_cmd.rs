//! `hexward guard …` (AI-agent command checks, MCP pinning) and `hexward extensions`.

use std::io::Read;

use anyhow::{Result, anyhow};
use clap::Subcommand;
use hexward_engine::extensions::{self, Change};
use hexward_engine::guard::{self, Decision};
use hexward_engine::mcp::{self, Status};

use crate::Style;

#[derive(Subcommand)]
pub enum GuardCmd {
    /// Claude Code PreToolUse hook: reads the tool call as JSON on stdin, answers deny/ask or nothing.
    Hook,
    /// Check one command. Exit code: 0 allow, 1 ask, 2 deny.
    Check {
        /// The command line, quoted.
        command: String,
    },
    /// Add Hexward Guard to Claude Code (~/.claude/settings.json). A backup is kept.
    Install,
    /// Remove Hexward Guard from Claude Code.
    Uninstall,
    /// Is Guard installed, and what has it stopped lately?
    Status,
    /// List MCP servers and whether they changed since you approved them.
    Mcp {
        /// Approve these servers as they are now (by name).
        #[arg(long, value_name = "NAME")]
        approve: Vec<String>,
        /// Approve every server as it is now.
        #[arg(long)]
        approve_all: bool,
        #[arg(long)]
        json: bool,
    },
}

/// Returns Ok(exit code).
pub fn run(cmd: GuardCmd) -> Result<u8> {
    let st = Style::stdout();
    match cmd {
        GuardCmd::Hook => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s)?;
            // Never block the agent because of Guard's own problem: unreadable input = no opinion.
            let Ok(input) = serde_json::from_str::<guard::HookInput>(&s) else { return Ok(0) };
            let (verdict, out) = guard::hook(&input);
            guard::log(&input, &verdict);
            if let Some(json) = out {
                println!("{json}");
            }
            Ok(0)
        }
        GuardCmd::Check { command } => {
            let v = guard::check_command(&command);
            let (label, code) = match v.decision {
                Decision::Allow => (st.good("ALLOW"), 0),
                Decision::Ask => (st.paint("33", "ASK"), 1),
                Decision::Deny => (st.paint("1;31", "DENY"), 2),
            };
            println!("{label}");
            for r in &v.reasons {
                println!("  {r}");
            }
            Ok(code)
        }
        GuardCmd::Install => {
            let path = guard::claude_settings_path().ok_or_else(|| anyhow!("can't find your home folder"))?;
            let exe = std::env::current_exe()?;
            guard::install(&path, &exe).map_err(|e| anyhow!(e))?;
            println!("Hexward Guard now checks Claude Code's commands and file edits.\n  {}", st.dim(&path.display().to_string()));
            println!("Restart Claude Code to pick it up. Remove it anytime with: hexward guard uninstall");
            Ok(0)
        }
        GuardCmd::Uninstall => {
            let path = guard::claude_settings_path().ok_or_else(|| anyhow!("can't find your home folder"))?;
            guard::uninstall(&path).map_err(|e| anyhow!(e))?;
            println!("Hexward Guard removed from Claude Code.");
            Ok(0)
        }
        GuardCmd::Status => {
            let installed = guard::claude_settings_path().is_some_and(|p| guard::is_installed(&p));
            println!("Claude Code hook: {}", if installed { st.good("installed") } else { st.dim("not installed (hexward guard install)") });
            let recent = guard::recent(15);
            if recent.is_empty() {
                println!("{}", st.dim("Nothing stopped or questioned yet."));
            }
            for e in recent {
                let d = if e.decision == Decision::Deny { st.paint("1;31", "DENY") } else { st.paint("33", "ASK ") };
                println!("{} {d} {}  {}", e.at.with_timezone(&chrono::Local).format("%b %d %H:%M"), crate_snip(&e.subject), st.dim(&e.reasons.join(" ")));
            }
            Ok(0)
        }
        GuardCmd::Mcp { approve, approve_all, json } => {
            let project = std::env::current_dir().ok();
            if approve_all || !approve.is_empty() {
                let n = mcp::approve(project.as_deref(), if approve_all { &[] } else { &approve }).map_err(|e| anyhow!(e))?;
                println!("Approved {n} MCP server(s). Hexward will tell you if any of them changes.");
                return Ok(0);
            }
            let list = mcp::status(project.as_deref());
            if json {
                println!("{}", serde_json::to_string_pretty(&list)?);
                return Ok(0);
            }
            if list.is_empty() {
                println!("No MCP servers configured.");
            }
            for (s, status) in &list {
                let tag = match status {
                    Status::Pinned => st.good("OK     "),
                    Status::New => st.paint("33", "NEW    "),
                    Status::Changed => st.paint("1;31", "CHANGED"),
                };
                println!("{tag} {}  {}", s.name, st.dim(&format!("[{}]", s.app)));
                println!("        {}", crate_snip(&s.summary()));
                if s.unpinned_package {
                    println!("        {}", st.paint("33", "Runs the newest package version every time; pin a version."));
                }
            }
            let waiting = list.iter().filter(|(_, s)| *s != Status::Pinned).count();
            if waiting > 0 {
                println!("\n{waiting} server(s) need a look. Approve one with --approve <name>, or all with --approve-all.");
            }
            Ok(if list.iter().any(|(_, s)| *s == Status::Changed) { 1 } else { 0 })
        }
    }
}

fn crate_snip(s: &str) -> String {
    hexward_engine::audit::snippet(s, 110)
}

/// `hexward extensions`: inventory, risky ones, and changes since the last run.
pub fn extensions_cmd(json: bool, no_save: bool) -> Result<u8> {
    let st = Style::stdout();
    let list = extensions::inventory();
    let old = extensions::load_snapshot();
    let changes = if old.taken.is_some() { extensions::diff(&old, &extensions::snapshot_of(&list)) } else { Vec::new() };
    if json {
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({ "extensions": list, "changes": changes }))?);
    } else {
        let mut app = String::new();
        for x in &list {
            if x.app != app {
                app = x.app.clone();
                println!("\n{}", st.paint("1", &app));
            }
            let tag = match x.level {
                Some(hexward_engine::audit::Level::High) => st.paint("1;31", "HIGH  "),
                Some(hexward_engine::audit::Level::Medium) => st.paint("33", "MEDIUM"),
                Some(hexward_engine::audit::Level::Low) => st.dim("LOW   "),
                _ => "      ".into(),
            };
            println!("  {tag} {} {}  {}", x.name, st.dim(&x.version), st.dim(&x.id));
            for n in x.notes.iter().filter(|_| x.level != Some(hexward_engine::audit::Level::Info)) {
                println!("         {n}");
            }
        }
        match old.taken {
            None => println!("\n{} extensions. First inventory saved; next time Hexward shows what changed.", list.len()),
            Some(t) if changes.is_empty() => println!("\n{} extensions. No changes since {}.", list.len(), t.with_timezone(&chrono::Local).format("%b %d %H:%M")),
            Some(t) => {
                println!("\nChanges since {}:", t.with_timezone(&chrono::Local).format("%b %d %H:%M"));
                for c in &changes {
                    match c {
                        Change::Added { name, version, key } => println!("  {} {name} {version}  {}", st.paint("33", "ADDED  "), st.dim(key)),
                        Change::Removed { name, version, key } => println!("  {} {name} {version}  {}", st.dim("REMOVED"), st.dim(key)),
                        Change::Updated { name, from, to, key } => println!("  {} {name} {from} → {to}  {}", st.paint("36", "UPDATED"), st.dim(key)),
                    }
                }
            }
        }
    }
    if !no_save {
        extensions::save_snapshot(&list).map_err(|e| anyhow!(e))?;
    }
    Ok(if list.iter().any(|x| x.level == Some(hexward_engine::audit::Level::High)) { 1 } else { 0 })
}
