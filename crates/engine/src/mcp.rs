//! MCP server pinning. Every MCP server an AI app is set up to start (Claude Code, Claude
//! Desktop, Cursor, VS Code, Windsurf) gets a fingerprint: its command, arguments, address and
//! environment variable names, plus the hash of the script it runs when that's a local file.
//! The user approves a server once; if anything about it changes later, Hexward says so.
//! That catches a config quietly edited by malware and a local server script that was swapped.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize)]
pub struct Server {
    /// Which app's config it's in, e.g. "Claude Code (user)".
    pub app: String,
    pub config: PathBuf,
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    pub url: String,
    pub env_keys: Vec<String>,
    pub fingerprint: String,
    /// `npx foo` without a version: a new release runs automatically.
    pub unpinned_package: bool,
}

impl Server {
    pub fn key(&self) -> String {
        format!("{}|{}", self.config.display(), self.name)
    }
    /// What it runs, with keys in addresses masked.
    pub fn summary(&self) -> String {
        if !self.url.is_empty() { mask_url(&self.url) } else { format!("{} {}", self.command, self.args.join(" ")).trim().to_string() }
    }
}

/// Hides key-like parts of an address: `https://host/api/mcp/mcp_KNll…`.
pub fn mask_url(url: &str) -> String {
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let parts: Vec<String> = base
        .split('/')
        .map(|seg| {
            let classes = [seg.chars().any(|c| c.is_ascii_digit()), seg.chars().any(|c| c.is_ascii_uppercase()), seg.chars().any(|c| c.is_ascii_lowercase())];
            let mixed = classes.iter().filter(|x| **x).count() >= 2;
            if seg.len() >= 16 && mixed && !seg.contains('.') { format!("{}…", &seg[..seg.char_indices().nth(6).map(|(i, _)| i).unwrap_or(seg.len())]) } else { seg.to_string() }
        })
        .collect();
    if query.is_empty() { parts.join("/") } else { format!("{}?…", parts.join("/")) }
}

/// The package a launcher (npx, bunx, uvx, pipx, `cmd /c npx`, `pnpm dlx`) downloads fresh on
/// every start without a fixed version. None when a version is pinned or it isn't a launcher.
pub fn unpinned_package(command: &str, args: &[&str]) -> Option<String> {
    let mut words: Vec<&str> = std::iter::once(command).chain(args.iter().copied()).collect();
    // `cmd /c npx …`, `pnpm dlx …`: look past the wrapper.
    while let Some(first) = words.first() {
        let raw = first.to_ascii_lowercase();
        let f = if raw.starts_with('/') && raw.len() == 2 { raw.clone() } else { raw.rsplit(['/', '\\']).next().unwrap_or(&raw).trim_end_matches(".exe").trim_end_matches(".cmd").to_string() };
        if matches!(f.as_str(), "cmd" | "/c" | "/k" | "pnpm" | "dlx" | "run") {
            words.remove(0);
            continue;
        }
        if !matches!(f.as_str(), "npx" | "bunx" | "uvx" | "pipx" | "yarn") {
            return None;
        }
        break;
    }
    let pkg = words.iter().skip(1).find(|a| !a.starts_with('-') && **a != "run" && **a != "dlx")?;
    let version = pkg.trim_start_matches('@').split_once('@').map(|(_, v)| v).or_else(|| pkg.split_once("==").map(|(_, v)| v));
    match version {
        Some(v) if !v.is_empty() && !matches!(v, "latest" | "next" | "beta" | "canary" | "*") => None,
        _ => Some(pkg.to_string()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Status {
    /// Approved and unchanged.
    Pinned,
    /// Never approved.
    New,
    /// Approved before, but something about it changed since.
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pin {
    pub fingerprint: String,
    pub summary: String,
    pub approved_at: DateTime<Utc>,
}

fn pins_path() -> PathBuf {
    crate::data_dir().join("mcp-pins.json")
}

pub fn load_pins() -> BTreeMap<String, Pin> {
    std::fs::read(pins_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

fn save_pins(p: &BTreeMap<String, Pin>) -> Result<(), String> {
    std::fs::create_dir_all(crate::data_dir()).map_err(|e| e.to_string())?;
    std::fs::write(pins_path(), serde_json::to_vec_pretty(p).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// Config files to look in: (app label, path).
pub fn config_files(project: Option<&Path>) -> Vec<(String, PathBuf)> {
    let mut v = Vec::new();
    if let Some(h) = dirs::home_dir() {
        v.push(("Claude Code (user)".into(), h.join(".claude.json")));
        v.push(("Cursor".into(), h.join(".cursor").join("mcp.json")));
        v.push(("Windsurf".into(), h.join(".codeium").join("windsurf").join("mcp_config.json")));
    }
    if let Some(a) = dirs::config_dir() {
        v.push(("Claude Desktop".into(), a.join("Claude").join("claude_desktop_config.json")));
        v.push(("VS Code".into(), a.join("Code").join("User").join("mcp.json")));
        v.push(("Cursor".into(), a.join("Cursor").join("User").join("mcp.json")));
    }
    if let Some(p) = project {
        v.push(("Project".into(), p.join(".mcp.json")));
        v.push(("Project (Cursor)".into(), p.join(".cursor").join("mcp.json")));
        v.push(("Project (VS Code)".into(), p.join(".vscode").join("mcp.json")));
    }
    v
}

fn sha256_file(p: &Path) -> Option<String> {
    let meta = std::fs::metadata(p).ok()?;
    if !meta.is_file() || meta.len() > 64 * 1024 * 1024 {
        return None;
    }
    Some(hex::encode(Sha256::digest(std::fs::read(p).ok()?)))
}

fn parse_server(app: &str, config: &Path, name: &str, s: &serde_json::Value) -> Server {
    let command = s.get("command").and_then(|c| c.as_str()).unwrap_or("").to_string();
    let args: Vec<String> = s.get("args").and_then(|a| a.as_array()).into_iter().flatten().filter_map(|a| a.as_str().map(String::from)).collect();
    let url = s.get("url").or_else(|| s.get("serverUrl")).and_then(|u| u.as_str()).unwrap_or("").to_string();
    let mut env_keys: Vec<String> = s.get("env").and_then(|e| e.as_object()).map(|o| o.keys().cloned().collect()).unwrap_or_default();
    env_keys.sort();
    let mut h = Sha256::new();
    h.update(command.as_bytes());
    for a in &args {
        h.update(b"\0");
        h.update(a.as_bytes());
        // A local script the server runs: its contents are part of the fingerprint.
        let p = Path::new(a);
        if p.is_absolute()
            && let Some(fh) = sha256_file(p)
        {
            h.update(fh.as_bytes());
        }
    }
    h.update(b"\0url\0");
    h.update(url.as_bytes());
    for k in &env_keys {
        h.update(b"\0env\0");
        h.update(k.as_bytes());
    }
    if Path::new(&command).is_absolute()
        && let Some(fh) = sha256_file(Path::new(&command))
    {
        h.update(fh.as_bytes());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let unpinned_package = unpinned_package(&command, &arg_refs).is_some();
    Server { app: app.into(), config: config.to_path_buf(), name: name.into(), command, args, url, env_keys, fingerprint: hex::encode(&h.finalize()[..16]), unpinned_package }
}

/// Every MCP server configured on this PC (and in `project`, if given).
pub fn servers(project: Option<&Path>) -> Vec<Server> {
    let mut out = Vec::new();
    for (app, path) in config_files(project) {
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Some(v) = crate::audit::agents::parse_jsonc(&text) else { continue };
        let mut add = |obj: Option<&serde_json::Value>, label: &str| {
            for (name, s) in obj.and_then(|o| o.as_object()).into_iter().flatten() {
                out.push(parse_server(label, &path, name, s));
            }
        };
        add(v.get("mcpServers"), &app);
        add(v.get("servers"), &app);
        add(v.pointer("/mcp/servers"), &app);
        // ~/.claude.json keeps per-project servers too.
        if let Some(projects) = v.get("projects").and_then(|p| p.as_object()) {
            for (proj, pv) in projects {
                let label = format!("Claude Code ({})", Path::new(proj).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| proj.clone()));
                for (name, s) in pv.get("mcpServers").and_then(|o| o.as_object()).into_iter().flatten() {
                    let mut srv = parse_server(&label, &path, name, s);
                    srv.name = format!("{proj} › {name}");
                    out.push(srv);
                }
            }
        }
    }
    out
}

/// Each server with its pin status.
pub fn status(project: Option<&Path>) -> Vec<(Server, Status)> {
    let pins = load_pins();
    servers(project)
        .into_iter()
        .map(|s| {
            let st = match pins.get(&s.key()) {
                Some(p) if p.fingerprint == s.fingerprint => Status::Pinned,
                Some(_) => Status::Changed,
                None => Status::New,
            };
            (s, st)
        })
        .collect()
}

/// Approves servers as they are now. `names` empty = all of them.
pub fn approve(project: Option<&Path>, names: &[String]) -> Result<usize, String> {
    let mut pins = load_pins();
    let mut n = 0;
    for s in servers(project) {
        if names.is_empty() || names.iter().any(|x| x == &s.name || s.name.ends_with(&format!("› {x}"))) {
            pins.insert(s.key(), Pin { fingerprint: s.fingerprint.clone(), summary: s.summary(), approved_at: Utc::now() });
            n += 1;
        }
    }
    save_pins(&pins)?;
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spots_moving_versions() {
        assert_eq!(unpinned_package("npx", &["-y", "some-mcp"]).as_deref(), Some("some-mcp"));
        assert_eq!(unpinned_package("cmd", &["/c", "npx", "-y", "@playwright/mcp@latest"]).as_deref(), Some("@playwright/mcp@latest"));
        assert_eq!(unpinned_package("npx", &["-y", "@playwright/mcp@0.0.41"]), None);
        assert_eq!(unpinned_package("uvx", &["mcp-server-git==0.6.2"]), None);
        assert_eq!(unpinned_package(r"C:\Python\Scripts\uvx.exe", &["windows-mcp", "serve"]).as_deref(), Some("windows-mcp"));
        assert_eq!(unpinned_package("node", &["server.js"]), None);
        assert_eq!(mask_url("https://example.com/api/mcp/mcp_KNllvwXSCzwbZiGs"), "https://example.com/api/mcp/mcp_KN…");
    }

    #[test]
    fn pins_and_notices_changes() {
        let home = tempfile::tempdir().unwrap();
        // SAFETY: test-only; this module reads HEXWARD_HOME through data_dir().
        let _home = crate::TEST_HOME.lock().unwrap_or_else(|e| e.into_inner());
        unsafe { std::env::set_var("HEXWARD_HOME", home.path()) };
        let proj = tempfile::tempdir().unwrap();
        let script = proj.path().join("server.js");
        std::fs::write(&script, "console.log('v1')").unwrap();
        let cfg = serde_json::json!({"mcpServers": {
            "local": {"command": "node", "args": [script.display().to_string()]},
            "remote": {"url": "https://mcp.example.com/sse"},
            "loose": {"command": "npx", "args": ["-y", "some-mcp"]},
        }});
        std::fs::write(proj.path().join(".mcp.json"), cfg.to_string()).unwrap();
        let only_project = |v: Vec<(Server, Status)>| v.into_iter().filter(|(s, _)| s.app == "Project").collect::<Vec<_>>();
        let st = only_project(status(Some(proj.path())));
        assert_eq!(st.len(), 3);
        assert!(st.iter().all(|(_, s)| *s == Status::New));
        assert!(st.iter().any(|(s, _)| s.name == "loose" && s.unpinned_package));
        approve(Some(proj.path()), &[]).unwrap();
        assert!(only_project(status(Some(proj.path()))).iter().all(|(_, s)| *s == Status::Pinned));
        // The local server's script is swapped: Hexward notices.
        std::fs::write(&script, "console.log('evil')").unwrap();
        let st = only_project(status(Some(proj.path())));
        assert_eq!(st.iter().find(|(s, _)| s.name == "local").unwrap().1, Status::Changed);
        assert_eq!(st.iter().find(|(s, _)| s.name == "remote").unwrap().1, Status::Pinned);
    }
}
