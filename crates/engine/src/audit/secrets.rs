//! Keys and tokens left in a project, and ones that were committed and later "deleted" but still
//! sit in git history. Stolen tokens are what supply-chain worms are after.

use std::collections::HashSet;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use super::{Category, Finding, Level, TextFile, snippet};

struct Pattern {
    name: &'static str,
    prefix: &'static str,
    /// Characters allowed after the prefix.
    charset: fn(u8) -> bool,
    min: usize,
    max: usize,
    level: Level,
}

fn alnum(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}
fn upper_num(b: u8) -> bool {
    b.is_ascii_uppercase() || b.is_ascii_digit()
}
fn token(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}
fn b64ish(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'
}

const PATTERNS: &[Pattern] = &[
    Pattern { name: "AWS access key", prefix: "AKIA", charset: upper_num, min: 16, max: 16, level: Level::High },
    Pattern { name: "AWS temporary key", prefix: "ASIA", charset: upper_num, min: 16, max: 16, level: Level::Medium },
    Pattern { name: "GitHub token", prefix: "ghp_", charset: alnum, min: 36, max: 36, level: Level::High },
    Pattern { name: "GitHub OAuth token", prefix: "gho_", charset: alnum, min: 36, max: 36, level: Level::High },
    Pattern { name: "GitHub app token", prefix: "ghs_", charset: alnum, min: 36, max: 36, level: Level::High },
    Pattern { name: "GitHub user token", prefix: "ghu_", charset: alnum, min: 36, max: 36, level: Level::High },
    Pattern { name: "GitHub fine-grained token", prefix: "github_pat_", charset: token, min: 70, max: 100, level: Level::High },
    Pattern { name: "GitLab token", prefix: "glpat-", charset: token, min: 20, max: 40, level: Level::High },
    Pattern { name: "npm token", prefix: "npm_", charset: alnum, min: 36, max: 36, level: Level::High },
    Pattern { name: "PyPI token", prefix: "pypi-AgEIcHlwaS5vcmc", charset: token, min: 40, max: 400, level: Level::High },
    Pattern { name: "Anthropic API key", prefix: "sk-ant-", charset: token, min: 40, max: 200, level: Level::High },
    Pattern { name: "OpenAI API key", prefix: "sk-proj-", charset: token, min: 40, max: 300, level: Level::High },
    Pattern { name: "Hugging Face token", prefix: "hf_", charset: alnum, min: 34, max: 40, level: Level::High },
    Pattern { name: "Stripe live key", prefix: "sk_live_", charset: alnum, min: 20, max: 120, level: Level::High },
    Pattern { name: "Stripe restricted key", prefix: "rk_live_", charset: alnum, min: 20, max: 120, level: Level::High },
    Pattern { name: "Slack token", prefix: "xoxb-", charset: token, min: 20, max: 200, level: Level::High },
    Pattern { name: "Slack token", prefix: "xoxp-", charset: token, min: 20, max: 200, level: Level::High },
    Pattern { name: "Google API key", prefix: "AIza", charset: token, min: 35, max: 35, level: Level::Medium },
    Pattern { name: "SendGrid key", prefix: "SG.", charset: b64ish, min: 60, max: 70, level: Level::High },
    Pattern { name: "Slack webhook", prefix: "hooks.slack.com/services/T", charset: |b| alnum(b) || b == b'/', min: 20, max: 80, level: Level::Medium },
    Pattern { name: "Discord webhook", prefix: "discord.com/api/webhooks/", charset: |b| token(b) || b == b'/', min: 30, max: 120, level: Level::Medium },
];

const PLACEHOLDERS: &[&str] = &["EXAMPLE", "example", "XXXX", "xxxx", "your", "YOUR", "0000000000", "1234567890", "abcdef0123", "dummy", "DUMMY", "test", "TEST", "fake", "FAKE", "sample", "<", "${"];

/// A secret found in text: (pattern name, level, byte offset, the secret).
pub fn find(text: &str) -> Vec<(&'static str, Level, usize, String)> {
    let b = text.as_bytes();
    let mut out = Vec::new();
    for p in PATTERNS {
        let mut from = 0;
        while let Some(pos) = text[from..].find(p.prefix) {
            let at = from + pos;
            from = at + p.prefix.len();
            if at > 0 && token(b[at - 1]) && !p.prefix.contains('/') {
                continue; // inside a longer word
            }
            let mut end = from;
            while end < b.len() && (p.charset)(b[end]) && end - from <= p.max {
                end += 1;
            }
            let n = end - from;
            if n < p.min || n > p.max {
                continue;
            }
            let value = &text[at..end];
            if PLACEHOLDERS.iter().any(|x| value[p.prefix.len()..].contains(x)) {
                continue;
            }
            // Real keys aren't one repeated character.
            let body = &value.as_bytes()[p.prefix.len()..];
            if body.iter().collect::<HashSet<_>>().len() < 6 {
                continue;
            }
            out.push((p.name, p.level, at, value.to_string()));
        }
    }
    // The marker must be one unbroken "-----BEGIN <TYPE> PRIVATE KEY-----": a line that only has
    // "BEGIN" somewhere and "PRIVATE KEY-----" further on (a split-up test sample, an END marker)
    // isn't a key.
    if let Some(at) = text.find("-----BEGIN ")
        && let Some(line) = text[at..].lines().next()
        && let Some(kind) = line["-----BEGIN ".len()..].split("-----").next()
        && kind.ends_with("PRIVATE KEY")
        && kind.bytes().all(|b| b.is_ascii_uppercase() || b == b' ')
        && line["-----BEGIN ".len() + kind.len()..].starts_with("-----")
        && !text[at..].contains("ENCRYPTED")
    {
        out.push(("Private key", Level::High, at, line.to_string()));
    }
    out
}

/// Shows enough of a secret to recognize it, never enough to use it.
pub fn mask(s: &str) -> String {
    if s.starts_with("-----BEGIN") {
        return s.to_string();
    }
    let keep = s.char_indices().nth(8).map(|(i, _)| i).unwrap_or(s.len());
    format!("{}…({} chars)", &s[..keep], s.chars().count())
}

const SKIP_NAMES: &[&str] = &["package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Cargo.lock", "poetry.lock", "uv.lock", "composer.lock", "go.sum"];

pub fn check(f: &TextFile, out: &mut Vec<Finding>) {
    if SKIP_NAMES.contains(&f.name()) || f.rel.ends_with(".min.js") {
        return;
    }
    let mut seen = HashSet::new();
    for (name, level, at, value) in find(f.text) {
        if !seen.insert(value.clone()) {
            continue;
        }
        let test_file = f.rel.contains("test") || f.rel.contains("fixture") || f.rel.contains("example");
        out.push(Finding {
            id: "secret",
            level: if test_file { Level::Low } else { level },
            category: Category::Secret,
            file: f.rel.into(),
            line: Some(f.line_of(at)),
            title: format!("{name} in the code"),
            detail: "Anyone who can read this project can use it. Supply-chain worms search projects for exactly these.".into(),
            fix: "Revoke it with the provider and create a new one, then keep it in an environment variable or a secrets manager. Deleting it from the file isn't enough if it was ever committed.".into(),
            evidence: mask(&value),
        });
    }
    // Env files with real-looking values.
    let name = f.name();
    if (name == ".env" || name.starts_with(".env.")) && !["example", "sample", "template", "dist", "defaults"].iter().any(|s| name.ends_with(s)) {
        let filled = f.text.lines().filter(|l| {
            let Some((k, v)) = l.split_once('=') else { return false };
            let k = k.to_ascii_uppercase();
            let v = v.trim().trim_matches(['"', '\'']);
            ["SECRET", "TOKEN", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "PRIVATE"].iter().any(|w| k.contains(w)) && v.len() >= 8 && !PLACEHOLDERS.iter().any(|p| v.contains(p))
        });
        let n = filled.count();
        // Kept out of git by a .gitignore in this folder or above it?
        let ignored = f.path.ancestors().skip(1).take(6).any(|d| {
            std::fs::read_to_string(d.join(".gitignore")).is_ok_and(|g| {
                g.lines().map(str::trim).any(|l| l == name || l == ".env" || l == ".env*" || l == "*.env" || l == ".env.*" || l == ".env*.local" || (l.ends_with('*') && name.starts_with(l.trim_end_matches('*'))))
            })
        });
        if n > 0 && ignored {
            out.push(Finding {
                id: "env-file",
                level: Level::Info,
                category: Category::Secret,
                file: f.rel.into(),
                line: None,
                title: format!("{name} holds {n} secret value(s), kept out of git"),
                detail: ".gitignore keeps it out of commits. Make sure it's also left out of packages and Docker images.".into(),
                fix: "Nothing to do if .npmignore / .dockerignore also exclude it.".into(),
                evidence: String::new(),
            });
        } else if n > 0 {
            out.push(Finding {
                id: "env-file",
                level: Level::Medium,
                category: Category::Secret,
                file: f.rel.into(),
                line: None,
                title: format!("{name} holds {n} secret value(s)"),
                detail: "Env files are often committed or packed into releases by accident.".into(),
                fix: "Make sure it's listed in .gitignore and .npmignore, and was never committed.".into(),
                evidence: String::new(),
            });
        }
    }
}

/// Reads git history for secrets that are no longer in the files. Git runs with every
/// repository-controlled program switched off (fsmonitor, hooks, diff and textconv drivers).
pub fn history(root: &Path, commits: usize, out: &mut Vec<Finding>) {
    if !root.join(".git").exists() {
        return;
    }
    let null_hooks = if cfg!(windows) { "NUL" } else { "/dev/null" };
    // -G makes git itself skip commits whose changes can't contain a key: the full diff of a big
    // repository takes minutes, the filtered one seconds.
    let pickaxe = format!("-G{}", PATTERNS.iter().map(|p| p.prefix.replace('.', "\\.")).chain(["PRIVATE KEY".to_string()]).collect::<Vec<_>>().join("|"));
    let child = Command::new("git")
        .args(["-c", "core.fsmonitor=false", "-c", &format!("core.hooksPath={null_hooks}"), "-c", "diff.external=", "-c", "core.pager=cat", "-C"])
        .arg(root)
        .args(["log", "--all", "-p", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "--unified=0", "--format=@@commit %h %as"])
        .arg(format!("-n{commits}"))
        .arg(&pickaxe)
        .args(["--", ".", ":(exclude)*.lock", ":(exclude)*package-lock.json", ":(exclude)*pnpm-lock.yaml", ":(exclude)*.min.js", ":(exclude)*.map", ":(exclude)*.svg", ":(exclude)dist/", ":(exclude)build/"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return };
    let Some(stdout) = child.stdout.take() else { return };
    // Watchdog: a huge history must not stall the audit.
    let pid = child.id();
    let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let timed_out = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (done, timed_out) = (done.clone(), timed_out.clone());
        std::thread::spawn(move || {
            let start = std::time::Instant::now();
            while start.elapsed() < HISTORY_LIMIT {
                if done.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            timed_out.store(true, std::sync::atomic::Ordering::Relaxed);
            kill_pid(pid);
        });
    }
    let current: HashSet<String> = out.iter().filter(|f| f.category == Category::Secret).map(|f| f.evidence.clone()).collect();
    let mut reported: HashSet<String> = HashSet::new();
    let (mut commit, mut file) = (String::new(), String::new());
    let mut read = 0usize;
    for line in BufReader::new(stdout).split(b'\n').map_while(Result::ok) {
        read += line.len();
        if read > 400 * 1024 * 1024 {
            break;
        }
        let line = String::from_utf8_lossy(&line);
        if let Some(c) = line.strip_prefix("@@commit ") {
            commit = c.to_string();
        } else if let Some(p) = line.strip_prefix("+++ b/") {
            file = p.to_string();
        } else if line.starts_with('+') && !line.starts_with("+++") {
            if SKIP_NAMES.iter().any(|s| file.ends_with(s)) {
                continue;
            }
            for (name, level, _, value) in find(&line[1..]) {
                let masked = mask(&value);
                if current.contains(&masked) || !reported.insert(masked.clone()) {
                    continue;
                }
                out.push(Finding {
                    id: "secret-history",
                    level,
                    category: Category::Secret,
                    file: file.clone(),
                    line: None,
                    title: format!("{name} in git history (commit {})", commit.split(' ').next().unwrap_or("")),
                    detail: format!("Added in commit {commit}. It's not in the files any more, but anyone with a copy of the repository can still read it."),
                    fix: "Revoke it with the provider. Rewriting history doesn't help once it has been pushed or cloned.".into(),
                    evidence: snippet(&masked, 80),
                });
            }
        }
    }
    done.store(true, std::sync::atomic::Ordering::Relaxed);
    let _ = child.kill();
    let _ = child.wait();
    if timed_out.load(std::sync::atomic::Ordering::Relaxed) {
        out.push(Finding {
            id: "history-partial",
            level: Level::Info,
            category: Category::Secret,
            file: String::new(),
            line: None,
            title: format!("Git history check stopped after {} seconds", HISTORY_LIMIT.as_secs()),
            detail: format!("The repository's history is large; the newest commits were checked{}.", if commit.is_empty() { String::new() } else { format!(", back to {commit}") }),
            fix: "Run `hexward audit --commits 200` for a quicker pass, or a dedicated tool for the full history.".into(),
            evidence: String::new(),
        });
    }
}

const HISTORY_LIMIT: std::time::Duration = std::time::Duration::from_secs(90);

fn kill_pid(pid: u32) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let _ = Command::new("taskkill").args(["/PID", &pid.to_string(), "/T", "/F"]).creation_flags(0x0800_0000).output();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill").arg(pid.to_string()).output();
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{j, project};
    use super::super::{Options, audit};
    use super::*;

    fn fake_gh() -> String {
        j(&["gh", "p_", "R7q2Lm9Kd4Vt8Zx1Nc5Bw3Hy6Js0Pf2Ga4Qe"])
    }

    #[test]
    fn finds_and_masks_secrets() {
        let src = format!("const token = \"{}\";\nconst aws = \"{}\";\nconst doc = \"AKIAIOSFODNN7EXAMPLE\";\n", fake_gh(), j(&["AKI", "A4Q7ZK2MT9RLB3XNC"]));
        let key = j(&["-----BEGIN OPENSSH PRIV", "ATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----\n"]);
        let p = project(&[("src/config.js", &src), ("deploy/id_ed25519", &key), (".env", &j(&["API_KEY=", "q8Zr2Lm4Nx7Vb1Kp\n"])), (".env.example", "API_KEY=your-key-here\n")]);
        let r = audit(p.path(), &Options::default());
        let s: Vec<_> = r.findings.iter().filter(|f| f.category == Category::Secret).collect();
        assert!(s.iter().any(|f| f.title.starts_with("GitHub token") && f.evidence.starts_with("ghp_R7q2") && !f.evidence.contains("Pf2Ga4Qe")));
        assert!(s.iter().any(|f| f.title.starts_with("AWS access key")));
        assert!(s.iter().any(|f| f.title.starts_with("Private key")));
        assert!(s.iter().any(|f| f.id == "env-file" && f.file == ".env"));
        assert!(!s.iter().any(|f| f.evidence.contains("EXAMPLE")), "AWS documentation key ignored");
        assert!(!s.iter().any(|f| f.file == ".env.example"));
    }

    #[test]
    fn split_up_key_samples_are_not_keys() {
        // How a test sample looks in source: the marker split in two, "\n" written out, an END marker.
        let line = j(&["let key = j(&[\"-----BEGIN OPENSSH PRIV\", \"ATE KEY-----", "\\nb3BlbnNzaC1rZXktdjEAAAAA\\n-----END OPENSSH PRIVATE KEY-----\\n\"]);"]);
        assert!(find(&line).is_empty(), "{:?}", find(&line));
        let real = j(&["-----BEGIN RSA PRIV", "ATE KEY-----\nMIIEowIBAAKCAQEA\n"]);
        assert_eq!(find(&real).len(), 1);
    }

    #[test]
    fn finds_secrets_removed_from_files_but_kept_in_history() {
        let p = project(&[("app.py", &format!("TOKEN = '{}'\n", fake_gh()))]);
        let git = |args: &[&str]| Command::new("git").args(["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"]).args(args).current_dir(p.path()).output().map(|o| o.status.success()).unwrap_or(false);
        if !git(&["init", "-q"]) {
            return; // no git on this machine
        }
        assert!(git(&["add", "."]) && git(&["commit", "-qm", "add"]));
        std::fs::write(p.path().join("app.py"), "import os\nTOKEN = os.environ['TOKEN']\n").unwrap();
        assert!(git(&["commit", "-qam", "remove"]));
        let r = audit(p.path(), &Options { history: true, history_commits: 50 });
        assert!(r.findings.iter().any(|f| f.id == "secret-history" && f.file == "app.py"), "{:?}", r.findings);
        assert!(!r.findings.iter().any(|f| f.id == "secret"), "not in the files any more");
    }
}
