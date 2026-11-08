//! Extension inventory: editor extensions (VS Code, Cursor, Windsurf, VSCodium) and browser
//! extensions (Chromium browsers and Firefox). Extensions run with broad access and update
//! themselves silently, so Hexward keeps a snapshot and shows what was added, removed or
//! updated since last time. Editor extensions are also searched for hidden-Unicode payloads
//! (GlassWorm), and browser extensions are rated by the permissions they hold.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::audit::Level;

#[derive(Debug, Clone, Serialize)]
pub struct Extension {
    /// "VS Code", "Cursor", "Google Chrome", …
    pub app: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub publisher: String,
    pub path: PathBuf,
    /// Why it deserves a look (permissions, hidden code); empty when nothing stands out.
    pub notes: Vec<String>,
    pub level: Option<Level>,
}

impl Extension {
    pub fn key(&self) -> String {
        format!("{}|{}", self.app, self.id)
    }
    fn note(&mut self, level: Level, text: impl Into<String>) {
        self.level = Some(self.level.map_or(level, |l| l.min(level)));
        self.notes.push(text.into());
    }
}

fn editor_dirs() -> Vec<(&'static str, PathBuf)> {
    let Some(h) = dirs::home_dir() else { return Vec::new() };
    vec![
        ("VS Code", h.join(".vscode").join("extensions")),
        ("VS Code Insiders", h.join(".vscode-insiders").join("extensions")),
        ("Cursor", h.join(".cursor").join("extensions")),
        ("Windsurf", h.join(".windsurf").join("extensions")),
        ("VSCodium", h.join(".vscode-oss").join("extensions")),
    ]
}

/// Checks an editor extension's main script for invisible payloads.
fn hidden_code(dir: &Path, main: Option<&str>) -> Option<String> {
    let mut files: Vec<PathBuf> = main.map(|m| dir.join(m.trim_start_matches("./"))).into_iter().flat_map(|p| [p.clone(), p.with_extension("js")]).collect();
    files.push(dir.join("extension.js"));
    files.push(dir.join("dist").join("extension.js"));
    files.push(dir.join("out").join("extension.js"));
    for f in files {
        let Ok(meta) = std::fs::metadata(&f) else { continue };
        if !meta.is_file() || meta.len() > 24 * 1024 * 1024 {
            continue;
        }
        let Ok(bytes) = std::fs::read(&f) else { continue };
        let text = String::from_utf8_lossy(&bytes);
        let rel = f.strip_prefix(dir).unwrap_or(&f).to_string_lossy().replace('\\', "/");
        let tf = crate::audit::TextFile { rel: &rel, path: &f, text: &text };
        let mut found = Vec::new();
        crate::audit::unicode::check(&tf, &mut found);
        if let Some(x) = found.into_iter().find(|x| x.level == Level::High) {
            return Some(format!("{} in {rel}", x.title));
        }
        return None;
    }
    None
}

fn editor_extensions(out: &mut Vec<Extension>) {
    for (app, dir) in editor_dirs() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            if e.file_name().to_string_lossy().starts_with('.') {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(p.join("package.json")) else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            let s = |k: &str| v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let (publisher, name) = (s("publisher"), s("name"));
            if name.is_empty() {
                continue;
            }
            let display = s("displayName");
            let mut x = Extension {
                app: app.into(),
                id: format!("{publisher}.{name}").to_lowercase(),
                name: if display.is_empty() || display.starts_with('%') { name.clone() } else { display },
                version: s("version"),
                publisher,
                path: p.clone(),
                notes: Vec::new(),
                level: None,
            };
            if let Some(h) = hidden_code(&p, v.get("main").and_then(|m| m.as_str())) {
                x.note(Level::High, format!("{h}: GlassWorm-style hidden code"));
            }
            if v.get("activationEvents").and_then(|a| a.as_array()).is_some_and(|a| a.iter().any(|e| e.as_str() == Some("*"))) {
                x.note(Level::Info, "Starts with every editor window");
            }
            out.push(x);
        }
    }
}

/// Resolves "__MSG_appName__" from the extension's locale files.
fn chrome_message(dir: &Path, raw: &str, default_locale: &str) -> String {
    let Some(key) = raw.strip_prefix("__MSG_").and_then(|r| r.strip_suffix("__")) else { return raw.to_string() };
    for loc in [default_locale, "en", "en_US"] {
        let Ok(t) = std::fs::read_to_string(dir.join("_locales").join(loc).join("messages.json")) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&t) else { continue };
        if let Some(obj) = v.as_object()
            && let Some((_, m)) = obj.iter().find(|(k, _)| k.eq_ignore_ascii_case(key))
            && let Some(msg) = m.get("message").and_then(|x| x.as_str())
        {
            return msg.to_string();
        }
    }
    key.to_string()
}

fn rate_permissions(x: &mut Extension, perms: &[String]) {
    let has = |p: &str| perms.iter().any(|q| q == p);
    let all_sites = perms.iter().any(|p| p == "<all_urls>" || p == "*://*/*" || p == "http://*/*" || p == "https://*/*" || p == "*://*/");
    for (p, why) in [("debugger", "can control any tab like developer tools"), ("nativeMessaging", "can talk to programs on your PC"), ("proxy", "can reroute all your traffic"), ("management", "can switch other extensions on and off")] {
        if has(p) {
            x.note(Level::Medium, format!("\"{p}\": {why}"));
        }
    }
    if all_sites && (has("cookies") || has("webRequest") || has("webRequestBlocking")) {
        x.note(Level::Medium, "Reads every site you visit, including cookies or network traffic");
    } else if all_sites {
        x.note(Level::Low, "Can read and change every site you visit");
    }
    if has("clipboardRead") {
        x.note(Level::Low, "Can read your clipboard");
    }
}

fn chromium_extensions(out: &mut Vec<Extension>) {
    for b in crate::cleaner::browsers().into_iter().filter(|b| b.engine == crate::cleaner::Engine::Chromium) {
        for profile in &b.profiles {
            let Ok(ids) = std::fs::read_dir(profile.join("Extensions")) else { continue };
            for id in ids.flatten() {
                let id_name = id.file_name().to_string_lossy().to_string();
                if id_name.starts_with('.') || id_name == "Temp" {
                    continue;
                }
                // Newest version folder.
                let mut versions: Vec<PathBuf> = std::fs::read_dir(id.path()).into_iter().flatten().flatten().map(|v| v.path()).filter(|v| v.join("manifest.json").is_file()).collect();
                versions.sort();
                let Some(dir) = versions.pop() else { continue };
                let Ok(text) = std::fs::read_to_string(dir.join("manifest.json")) else { continue };
                let Ok(v) = serde_json::from_str::<serde_json::Value>(text.trim_start_matches('\u{feff}')) else { continue };
                let locale = v.get("default_locale").and_then(|l| l.as_str()).unwrap_or("en");
                let name = chrome_message(&dir, v.get("name").and_then(|n| n.as_str()).unwrap_or(&id_name), locale);
                let profile_name = profile.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let mut x = Extension {
                    app: if b.profiles.len() > 1 { format!("{} ({profile_name})", b.name) } else { b.name.to_string() },
                    id: id_name.clone(),
                    name,
                    version: v.get("version").and_then(|x| x.as_str()).unwrap_or("").into(),
                    publisher: v.get("author").and_then(|a| a.as_str().map(String::from).or_else(|| a.get("email").and_then(|e| e.as_str()).map(String::from))).unwrap_or_default(),
                    path: dir.clone(),
                    notes: Vec::new(),
                    level: None,
                };
                let mut perms: Vec<String> = ["permissions", "host_permissions", "optional_permissions"].iter().flat_map(|k| v.get(*k).and_then(|p| p.as_array()).cloned().unwrap_or_default()).filter_map(|p| p.as_str().map(String::from)).collect();
                for cs in v.get("content_scripts").and_then(|c| c.as_array()).into_iter().flatten() {
                    perms.extend(cs.get("matches").and_then(|m| m.as_array()).into_iter().flatten().filter_map(|m| m.as_str().map(String::from)));
                }
                rate_permissions(&mut x, &perms);
                out.push(x);
            }
        }
    }
}

fn firefox_extensions(out: &mut Vec<Extension>) {
    let Some(b) = crate::cleaner::browsers().into_iter().find(|b| b.engine == crate::cleaner::Engine::Firefox) else { return };
    for profile in &b.profiles {
        let Ok(text) = std::fs::read_to_string(profile.join("extensions.json")) else { continue };
        let Ok(v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        for a in v.get("addons").and_then(|a| a.as_array()).into_iter().flatten() {
            if a.get("type").and_then(|t| t.as_str()) != Some("extension") || a.get("location").and_then(|l| l.as_str()) != Some("app-profile") {
                continue;
            }
            let s = |p: &str| a.pointer(p).and_then(|x| x.as_str()).unwrap_or("").to_string();
            let mut x = Extension { app: "Mozilla Firefox".into(), id: s("/id"), name: s("/defaultLocale/name"), version: s("/version"), publisher: s("/defaultLocale/creator"), path: profile.join("extensions"), notes: Vec::new(), level: None };
            let perms: Vec<String> = ["/userPermissions/permissions", "/userPermissions/origins"].iter().flat_map(|p| a.pointer(p).and_then(|x| x.as_array()).cloned().unwrap_or_default()).filter_map(|p| p.as_str().map(String::from)).collect();
            rate_permissions(&mut x, &perms);
            out.push(x);
        }
    }
}

/// Every editor and browser extension on this PC.
pub fn inventory() -> Vec<Extension> {
    let mut v = Vec::new();
    editor_extensions(&mut v);
    chromium_extensions(&mut v);
    firefox_extensions(&mut v);
    v.sort_by(|a, b| a.app.cmp(&b.app).then(a.name.to_lowercase().cmp(&b.name.to_lowercase())));
    v
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub taken: Option<chrono::DateTime<chrono::Utc>>,
    /// key → (name, version)
    pub items: BTreeMap<String, (String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub enum Change {
    Added { key: String, name: String, version: String },
    Removed { key: String, name: String, version: String },
    Updated { key: String, name: String, from: String, to: String },
}

fn snapshot_path() -> PathBuf {
    crate::data_dir().join("extensions-snapshot.json")
}

pub fn load_snapshot() -> Snapshot {
    std::fs::read(snapshot_path()).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
}

pub fn snapshot_of(list: &[Extension]) -> Snapshot {
    Snapshot { taken: Some(chrono::Utc::now()), items: list.iter().map(|x| (x.key(), (x.name.clone(), x.version.clone()))).collect() }
}

pub fn save_snapshot(list: &[Extension]) -> Result<(), String> {
    std::fs::create_dir_all(crate::data_dir()).map_err(|e| e.to_string())?;
    std::fs::write(snapshot_path(), serde_json::to_vec_pretty(&snapshot_of(list)).map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

/// What changed between two snapshots.
pub fn diff(old: &Snapshot, new: &Snapshot) -> Vec<Change> {
    let mut v = Vec::new();
    for (k, (name, ver)) in &new.items {
        match old.items.get(k) {
            None => v.push(Change::Added { key: k.clone(), name: name.clone(), version: ver.clone() }),
            Some((_, old_ver)) if old_ver != ver => v.push(Change::Updated { key: k.clone(), name: name.clone(), from: old_ver.clone(), to: ver.clone() }),
            _ => {}
        }
    }
    for (k, (name, ver)) in &old.items {
        if !new.items.contains_key(k) {
            v.push(Change::Removed { key: k.clone(), name: name.clone(), version: ver.clone() });
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rates_permissions() {
        let mut x = Extension { app: "t".into(), id: "a".into(), name: "a".into(), version: "1".into(), publisher: String::new(), path: PathBuf::new(), notes: Vec::new(), level: None };
        rate_permissions(&mut x, &["<all_urls>".into(), "cookies".into(), "storage".into()]);
        assert_eq!(x.level, Some(Level::Medium));
        let mut y = Extension { notes: Vec::new(), level: None, ..x.clone() };
        rate_permissions(&mut y, &["storage".into(), "activeTab".into()]);
        assert_eq!(y.level, None);
    }

    #[test]
    fn diffs_snapshots() {
        let mk = |items: &[(&str, &str)]| Snapshot { taken: None, items: items.iter().map(|(k, v)| (k.to_string(), (k.to_string(), v.to_string()))).collect() };
        let changes = diff(&mk(&[("a", "1"), ("b", "1")]), &mk(&[("a", "2"), ("c", "1")]));
        assert!(matches!(&changes[..], [Change::Updated { .. }, Change::Added { .. }, Change::Removed { .. }]), "{changes:?}");
    }

    #[test]
    fn reads_this_pc_without_error() {
        let list = inventory();
        assert!(list.iter().all(|x| !x.id.is_empty()));
    }

    #[test]
    fn finds_hidden_payload_in_editor_extension() {
        let dir = tempfile::tempdir().unwrap();
        let payload: String = std::iter::repeat_n('\u{E0102}', 50).collect();
        std::fs::create_dir_all(dir.path().join("dist")).unwrap();
        std::fs::write(dir.path().join("dist").join("extension.js"), format!("const p='{payload}';")).unwrap();
        assert!(hidden_code(dir.path(), Some("./dist/extension.js")).is_some());
        std::fs::write(dir.path().join("dist").join("extension.js"), "module.exports = {}").unwrap();
        assert!(hidden_code(dir.path(), Some("./dist/extension.js")).is_none());
    }
}
