//! Project audit: looks at a code project (a folder or a cloned repository) for the ways
//! supply-chain and AI-agent attacks get in. It reads files; it never runs anything from the project.
//!
//! Checks, by module:
//! - `install`:  code that runs when dependencies are installed or the project is built
//!   (npm lifecycle scripts, setup.py, custom Python build backends, Cargo build.rs, binding.gyp,
//!   git hooks, git config tricks, submodules)
//! - `agents`:   AI-agent and editor configs (Claude Code hooks and permissions, VS Code
//!   folder-open tasks, MCP servers) and prompt injection in instruction files
//! - `unicode`:  invisible text: Unicode tag characters, bidi controls, zero-width and
//!   variation-selector runs (Trojan Source, GlassWorm, hidden agent instructions)
//! - `actions`:  GitHub Actions: unpinned actions, `pull_request_target` misuse, script injection
//! - `secrets`:  API keys, tokens and private keys in files and in git history
//! - `deps`:     lockfiles: packages from outside the registry, missing integrity, loose versions

pub mod actions;
pub mod agents;
pub mod deps;
pub mod install;
pub mod secrets;
pub mod unicode;

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Level {
    High,
    Medium,
    Low,
    Info,
}

impl Level {
    pub fn label(self) -> &'static str {
        match self {
            Level::High => "HIGH",
            Level::Medium => "MEDIUM",
            Level::Low => "LOW",
            Level::Info => "INFO",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Category {
    InstallCode,
    AgentConfig,
    HiddenText,
    Workflow,
    Secret,
    Dependency,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::InstallCode => "Install-time code",
            Category::AgentConfig => "AI agent and editor config",
            Category::HiddenText => "Hidden text",
            Category::Workflow => "GitHub Actions",
            Category::Secret => "Leaked secrets",
            Category::Dependency => "Dependencies",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable id, e.g. "npm-postinstall-download".
    pub id: &'static str,
    pub level: Level,
    pub category: Category,
    /// Path relative to the project root, with forward slashes.
    pub file: String,
    pub line: Option<usize>,
    pub title: String,
    /// What was found and why it matters, in plain words.
    pub detail: String,
    /// What to do about it.
    pub fix: String,
    /// The offending text, shortened (secrets are masked).
    pub evidence: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Options {
    /// Also read `git log -p` for secrets that were committed and later removed.
    pub history: bool,
    /// Most commits to read from history.
    pub history_commits: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub root: PathBuf,
    pub files: u64,
    pub findings: Vec<Finding>,
    /// Packages found in lockfiles and manifests, for online checks.
    pub packages: Vec<deps::Package>,
    /// Dependencies the project asks for by name (manifests), for the registry check.
    pub direct: Vec<deps::Package>,
}

impl Report {
    pub fn count(&self, level: Level) -> usize {
        self.findings.iter().filter(|f| f.level == level).count()
    }
}

/// A text file handed to every content check.
pub struct TextFile<'a> {
    pub rel: &'a str,
    pub path: &'a Path,
    pub text: &'a str,
}

impl TextFile<'_> {
    pub fn name(&self) -> &str {
        self.rel.rsplit('/').next().unwrap_or(self.rel)
    }
    pub fn ext(&self) -> String {
        self.name().rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
    }
    /// 1-based line number of a byte offset.
    pub fn line_of(&self, offset: usize) -> usize {
        self.text[..offset.min(self.text.len())].bytes().filter(|&b| b == b'\n').count() + 1
    }
}

/// Shortens text for display: one line, at most `n` characters.
pub fn snippet(s: &str, n: usize) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if one.chars().count() > n { format!("{}…", one.chars().take(n).collect::<String>()) } else { one }
}

const SKIP_DIRS: &[&str] = &[".git", "target", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache", ".pytest_cache", ".next", ".turbo", ".cache", ".gradle", ".idea"];
const MAX_TEXT: u64 = 4 * 1024 * 1024;

fn rel_of(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).to_string_lossy().replace('\\', "/")
}

fn looks_binary(bytes: &[u8]) -> bool {
    bytes[..bytes.len().min(8192)].contains(&0)
}

/// Audits a project folder. Reads files only; runs nothing from the project.
pub fn audit(root: &Path, opts: &Options) -> Report {
    let mut report = Report { root: root.to_path_buf(), ..Default::default() };
    let mut walker = walkdir::WalkDir::new(root).follow_links(false).into_iter();
    while let Some(entry) = walker.next() {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if entry.file_type().is_dir() {
            // Claude Code worktrees are copies of this same project.
            let worktree_copy = name == "worktrees" && path.parent().and_then(|p| p.file_name()).is_some_and(|p| p == ".claude");
            if entry.depth() > 0 && (SKIP_DIRS.contains(&name.as_str()) || worktree_copy) {
                walker.skip_current_dir();
            } else if name == "node_modules" {
                // Installed packages: only their manifests matter here (install scripts).
                install::node_modules(root, path, &mut report);
                walker.skip_current_dir();
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() > MAX_TEXT {
            continue;
        }
        let Ok(bytes) = std::fs::read(path) else { continue };
        if looks_binary(&bytes) {
            continue;
        }
        report.files += 1;
        let text = String::from_utf8_lossy(&bytes);
        let rel = rel_of(root, path);
        let f = TextFile { rel: &rel, path, text: &text };
        install::check(&f, &mut report);
        agents::check(&f, &mut report);
        unicode::check(&f, &mut report.findings);
        actions::check(&f, &mut report.findings);
        secrets::check(&f, &mut report.findings);
        deps::check(&f, &mut report);
    }
    install::git_dir(root, &mut report.findings);
    if opts.history {
        secrets::history(root, opts.history_commits.max(1), &mut report.findings);
    }
    report.findings.sort_by(|a, b| a.level.cmp(&b.level).then_with(|| a.file.cmp(&b.file)).then(a.line.cmp(&b.line)));
    report
}

/// Is this a repository address rather than a folder?
pub fn is_remote(target: &str) -> bool {
    let t = target.trim();
    t.starts_with("https://") || t.starts_with("http://") || t.starts_with("git@") || t.starts_with("ssh://") || t.starts_with("git://")
}

/// Clones a repository for auditing without running anything from it: no checkout hooks,
/// no submodules, no fsmonitor, no LFS filters. Keeps the last `depth` commits for the
/// history check.
pub fn clone(url: &str, dest: &Path, depth: usize) -> Result<(), String> {
    if !is_remote(url) || url.starts_with('-') {
        return Err("That doesn't look like a repository address (https://… or git@…).".into());
    }
    let null_hooks = if cfg!(windows) { "NUL" } else { "/dev/null" };
    let out = std::process::Command::new("git")
        .args(["-c", &format!("core.hooksPath={null_hooks}"), "-c", "core.fsmonitor=false", "-c", "filter.lfs.smudge=", "-c", "filter.lfs.process=", "-c", "filter.lfs.required=false", "-c", "protocol.file.allow=never", "-c", "protocol.ext.allow=never"])
        .args(["clone", "--quiet", "--no-recurse-submodules", "--depth"])
        .arg(depth.max(1).to_string())
        .arg("--")
        .arg(url)
        .arg(dest)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_LFS_SKIP_SMUDGE", "1")
        .output()
        .map_err(|_| "Git isn't installed, so Hexward can't download the repository. Install Git, or clone it yourself and audit the folder.".to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        Err(format!("Couldn't clone it: {}", err.lines().find(|l| !l.trim().is_empty()).unwrap_or("git failed").trim_start_matches("fatal: ")))
    }
}

#[cfg(test)]
pub(crate) mod testkit {
    /// Fragments joined at runtime, so the repository never holds a whole attack string.
    pub fn j(parts: &[&str]) -> String {
        parts.concat()
    }

    pub fn project(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (rel, text) in files {
            let p = dir.path().join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        dir
    }

    pub fn ids(r: &super::Report) -> Vec<&'static str> {
        r.findings.iter().map(|f| f.id).collect()
    }
}
