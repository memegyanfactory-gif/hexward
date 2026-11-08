//! Online checks for a project audit, run only when the user asks:
//! - OSV.dev: is any locked package version known malware (`MAL-` advisories) or vulnerable?
//! - npm and PyPI: does every dependency the project names actually exist? (slopsquatting)
//!
//! What's sent: package names and versions, nothing else. No file contents, no paths.

use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

use hexward_engine::audit::deps::{self, Package};
use hexward_engine::audit::{Level, Report};
use serde_json::{Value, json};

#[derive(Debug, Default)]
pub struct Online {
    pub malicious: Vec<(Package, String, String)>,
    pub vulnerable: Vec<(Package, Vec<String>)>,
    pub missing: Vec<Package>,
    /// (package, level, title, detail) for odd releases of direct dependencies.
    pub anomalies: Vec<(Package, Level, String, String)>,
    pub checked_versions: usize,
    pub checked_names: usize,
    pub errors: Vec<String>,
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(60)))
        .user_agent(concat!("hexward-audit/", env!("CARGO_PKG_VERSION")))
        .http_status_as_error(false)
        .build()
        .into()
}

fn read_json(resp: &mut ureq::http::Response<ureq::Body>) -> Option<Value> {
    let text = resp.body_mut().with_config().limit(64 * 1024 * 1024).read_to_string().ok()?;
    serde_json::from_str(&text).ok()
}

/// Asks OSV about every locked version (deduplicated, in batches of 1,000).
fn osv(agent: &ureq::Agent, packages: &[Package], out: &mut Online) {
    let unique: Vec<&Package> = packages.iter().filter(|p| !p.version.is_empty()).collect::<HashSet<_>>().into_iter().collect();
    out.checked_versions = unique.len();
    let mut mal_ids: Vec<(Package, String)> = Vec::new();
    for chunk in unique.chunks(1000) {
        let queries: Vec<Value> = chunk.iter().map(|p| json!({"package": {"name": p.name, "ecosystem": p.ecosystem}, "version": p.version})).collect();
        let body = json!({ "queries": queries }).to_string();
        let resp = agent.post("https://api.osv.dev/v1/querybatch").header("Content-Type", "application/json").send(body.as_str());
        let Ok(mut resp) = resp else {
            out.errors.push("Couldn't reach OSV.dev".into());
            return;
        };
        if resp.status() != 200 {
            out.errors.push(format!("OSV.dev answered HTTP {}", resp.status().as_u16()));
            return;
        }
        let Some(v) = read_json(&mut resp) else {
            out.errors.push("OSV.dev sent an unreadable answer".into());
            return;
        };
        for (p, r) in chunk.iter().zip(v.get("results").and_then(|r| r.as_array()).into_iter().flatten()) {
            let ids: Vec<String> = r.get("vulns").and_then(|v| v.as_array()).into_iter().flatten().filter_map(|x| x.get("id").and_then(|i| i.as_str()).map(String::from)).collect();
            let (mal, other): (Vec<String>, Vec<String>) = ids.into_iter().partition(|i| i.starts_with("MAL-"));
            for id in mal {
                mal_ids.push(((*p).clone(), id));
            }
            if !other.is_empty() {
                out.vulnerable.push(((*p).clone(), other));
            }
        }
    }
    for (p, id) in mal_ids.into_iter().take(50) {
        let summary = agent
            .get(&format!("https://api.osv.dev/v1/vulns/{id}"))
            .call()
            .ok()
            .and_then(|mut r| read_json(&mut r))
            .and_then(|v| v.get("summary").or_else(|| v.get("details")).and_then(|s| s.as_str()).map(|s| s.chars().take(300).collect()))
            .unwrap_or_else(|| "Malicious code in this package version.".into());
        out.malicious.push((p, id, summary));
    }
}

fn pypi_normalize(name: &str) -> String {
    let mut out = String::new();
    let mut sep = false;
    for c in name.to_lowercase().chars() {
        if matches!(c, '-' | '_' | '.') {
            sep = true;
        } else {
            if sep && !out.is_empty() {
                out.push('-');
            }
            sep = false;
            out.push(c);
        }
    }
    out
}

fn registry_name(p: &Package) -> bool {
    let s = p.version.trim();
    !(s.starts_with("file:") || s.starts_with("link:") || s.starts_with("workspace:") || s.starts_with("git") || s.starts_with("http") || s.starts_with("npm:") || s.contains('/'))
}

/// Checks that each named dependency exists on its registry (HEAD requests, 8 at a time).
fn existence(agent: &ureq::Agent, direct: &[Package], skip_npm: bool, out: &mut Online) {
    let mut names: Vec<&Package> = direct.iter().filter(|p| registry_name(p) && !(skip_npm && p.ecosystem == "npm")).collect::<HashSet<_>>().into_iter().collect();
    names.sort_by(|a, b| a.name.cmp(&b.name));
    names.dedup_by(|a, b| a.name == b.name && a.ecosystem == b.ecosystem);
    names.truncate(300);
    out.checked_names = names.len();
    let missing = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for chunk in names.chunks(names.len().div_ceil(8).max(1)) {
            let missing = &missing;
            s.spawn(move || {
                for p in chunk {
                    let url = match p.ecosystem {
                        "npm" => format!("https://registry.npmjs.org/{}", p.name.replace('/', "%2F")),
                        "PyPI" => format!("https://pypi.org/simple/{}/", pypi_normalize(&p.name)),
                        _ => continue,
                    };
                    if let Ok(r) = agent.head(&url).call()
                        && r.status() == 404
                        && let Ok(mut m) = missing.lock()
                    {
                        m.push((*p).clone());
                    }
                }
            });
        }
    });
    out.missing = missing.into_inner().unwrap_or_default();
}

fn semver(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim_start_matches('v').split(['-', '+']).next()?;
    let mut p = core.split('.').map(|x| x.parse::<u64>().ok());
    Some((p.next()??, p.next().flatten().unwrap_or(0), p.next().flatten().unwrap_or(0)))
}

/// What changed between a locked npm version and the release before it.
#[derive(Debug, Default, Clone)]
pub struct ReleaseFacts {
    pub install_script: bool,
    pub size: u64,
    pub git_head: bool,
}

/// Judges one release against the one before it. Pure, so it's testable without the network.
pub fn release_anomalies(version: &str, prev_version: &str, now: &ReleaseFacts, prev: &ReleaseFacts) -> Vec<(Level, String, String)> {
    let mut v = Vec::new();
    if now.install_script && !prev.install_script {
        v.push((Level::High, format!("{version} added an install script"), format!("{prev_version} had none. A new install script in a patch or minor release is how the chalk/debug and Shai-Hulud takeovers ran their code on install.")));
    }
    if prev.size > 0 && now.size >= prev.size.saturating_mul(10) && now.size > 1024 * 1024 {
        v.push((Level::Medium, format!("{version} is {}× bigger than {prev_version}", now.size / prev.size.max(1)), "A sudden jump in package size can mean bundled binaries or payloads were added.".into()));
    }
    if let (Some(a), Some(b)) = (semver(version), semver(prev_version))
        && (a.0 >= 90 && b.0 < 90 || a.0 >= b.0 + 10)
    {
        v.push((Level::Medium, format!("Version jumped from {prev_version} to {version}"), "Huge version numbers are a dependency-confusion trick: package managers prefer the highest version.".into()));
    }
    if prev.git_head && !now.git_head {
        v.push((Level::Medium, format!("{version} wasn't published from a git commit"), format!("{prev_version} was. Releases pushed straight from a stolen token often skip the project's normal release process.")));
    }
    v
}

fn facts_from(v: &Value) -> ReleaseFacts {
    ReleaseFacts {
        install_script: v.get("hasInstallScript").and_then(|x| x.as_bool()).unwrap_or(false)
            || v.get("scripts").and_then(|s| s.as_object()).is_some_and(|s| ["preinstall", "install", "postinstall"].iter().any(|k| s.contains_key(*k))),
        size: v.pointer("/dist/unpackedSize").and_then(|x| x.as_u64()).unwrap_or(0),
        git_head: v.get("gitHead").and_then(|x| x.as_str()).is_some_and(|s| !s.is_empty()),
    }
}

/// Release anomalies for the project's direct npm dependencies (their locked versions).
fn anomalies(agent: &ureq::Agent, report: &Report, out: &mut Online) {
    let direct: HashSet<&str> = report.direct.iter().filter(|p| p.ecosystem == "npm").map(|p| p.name.as_str()).collect();
    let mut todo: Vec<&Package> = report.packages.iter().filter(|p| p.ecosystem == "npm" && direct.contains(p.name.as_str())).collect::<HashSet<_>>().into_iter().collect();
    todo.sort_by(|a, b| a.name.cmp(&b.name));
    todo.truncate(60);
    let found = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for chunk in todo.chunks(todo.len().div_ceil(6).max(1)) {
            let found = &found;
            s.spawn(move || {
                for p in chunk {
                    let base = format!("https://registry.npmjs.org/{}", p.name.replace('/', "%2F"));
                    let Some(doc) = agent.get(&base).header("Accept", "application/vnd.npm.install-v1+json").call().ok().and_then(|mut r| read_json(&mut r)) else { continue };
                    let Some(versions) = doc.get("versions").and_then(|v| v.as_object()) else { continue };
                    let Some(now_v) = versions.get(&p.version) else { continue };
                    let Some(mine) = semver(&p.version) else { continue };
                    // The newest release before the locked one.
                    let prev = versions.keys().filter_map(|k| semver(k).filter(|s| *s < mine && !k.contains('-')).map(|s| (s, k))).max().map(|(_, k)| k.clone());
                    let Some(prev) = prev else { continue };
                    let mut now = facts_from(now_v);
                    let mut before = facts_from(&versions[&prev]);
                    // gitHead is only in the full per-version documents.
                    let head = |v: &str| agent.get(&format!("{base}/{v}")).call().ok().and_then(|mut r| read_json(&mut r)).map(|d| facts_from(&d).git_head).unwrap_or(false);
                    now.git_head = head(&p.version);
                    before.git_head = head(&prev);
                    for (level, title, detail) in release_anomalies(&p.version, &prev, &now, &before) {
                        if let Ok(mut f) = found.lock() {
                            f.push(((*p).clone(), level, title, detail));
                        }
                    }
                }
            });
        }
    });
    out.anomalies = found.into_inner().unwrap_or_default();
}

/// Runs the online checks for an audit report.
pub fn check(report: &Report) -> Online {
    let agent = agent();
    let mut out = Online::default();
    osv(&agent, &report.packages, &mut out);
    // A project with its own npm registry has private names npm has never seen.
    let private_npm = std::fs::read_to_string(report.root.join(".npmrc")).is_ok_and(|t| t.contains("registry"));
    existence(&agent, &report.direct, private_npm, &mut out);
    anomalies(&agent, report, &mut out);
    out
}

/// Adds the online results to the report as findings.
pub fn apply(report: &mut Report, online: &Online) {
    for (p, id, summary) in &online.malicious {
        let mut f = deps::malicious_finding(p, id, summary);
        f.file = lockfile_for(&report.root, p.ecosystem);
        report.findings.push(f);
    }
    for p in &online.missing {
        let mut f = deps::missing_finding(p);
        if p.name.starts_with('@') {
            f.level = Level::Medium;
            f.detail.push_str(" If this is a private package from your own registry, ignore this.");
        }
        f.file = if p.ecosystem == "npm" { "package.json".into() } else { "requirements.txt".into() };
        report.findings.push(f);
    }
    for (p, level, title, detail) in &online.anomalies {
        let mut f = deps::anomaly_finding(p, title, detail);
        f.level = *level;
        f.file = lockfile_for(&report.root, p.ecosystem);
        report.findings.push(f);
    }
    if !online.vulnerable.is_empty() {
        let examples: Vec<String> = online.vulnerable.iter().take(6).map(|(p, ids)| format!("{} {} ({})", p.name, p.version, ids.first().cloned().unwrap_or_default())).collect();
        report.findings.push(deps::vulnerable_finding(online.vulnerable.len(), &examples.join(", ")));
    }
    report.findings.sort_by(|a, b| a.level.cmp(&b.level).then_with(|| a.file.cmp(&b.file)));
}

fn lockfile_for(root: &Path, eco: &str) -> String {
    let candidates: &[&str] = match eco {
        "npm" => &["package-lock.json", "yarn.lock", "npm-shrinkwrap.json", "node_modules"],
        "PyPI" => &["poetry.lock", "uv.lock", "requirements.txt"],
        _ => &["Cargo.lock"],
    };
    candidates.iter().find(|c| root.join(c).exists()).map(|c| c.to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_odd_releases() {
        let plain = ReleaseFacts { install_script: false, size: 100_000, git_head: true };
        assert!(release_anomalies("1.2.4", "1.2.3", &plain, &plain).is_empty());
        let hijack = ReleaseFacts { install_script: true, size: 4_000_000, git_head: false };
        let found = release_anomalies("1.2.4", "1.2.3", &hijack, &plain);
        assert_eq!(found.len(), 3, "{found:?}");
        assert_eq!(found[0].0, Level::High);
        assert_eq!(release_anomalies("99.0.0", "1.4.0", &plain, &plain).len(), 1);
    }

    #[test]
    fn normalizes_pypi_names() {
        assert_eq!(pypi_normalize("Flask_SQLAlchemy"), "flask-sqlalchemy");
        assert_eq!(pypi_normalize("zope.interface"), "zope-interface");
    }

    /// Talks to the real services; run with `cargo test -- --ignored`.
    #[test]
    #[ignore]
    fn osv_and_registries_answer() {
        let mut r = Report::default();
        r.packages.push(Package { ecosystem: "npm", name: "lodash".into(), version: "4.17.20".into() });
        r.direct.push(Package { ecosystem: "npm", name: "lodash".into(), version: "^4".into() });
        r.direct.push(Package { ecosystem: "npm", name: "hexward-surely-not-a-real-package-x9q".into(), version: "^1".into() });
        let o = check(&r);
        assert!(o.errors.is_empty(), "{:?}", o.errors);
        assert!(o.vulnerable.iter().any(|(p, _)| p.name == "lodash"));
        assert_eq!(o.missing.len(), 1);
    }
}
