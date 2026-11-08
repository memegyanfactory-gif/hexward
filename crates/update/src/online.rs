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

/// Runs the online checks for an audit report.
pub fn check(report: &Report) -> Online {
    let agent = agent();
    let mut out = Online::default();
    osv(&agent, &report.packages, &mut out);
    // A project with its own npm registry has private names npm has never seen.
    let private_npm = std::fs::read_to_string(report.root.join(".npmrc")).is_ok_and(|t| t.contains("registry"));
    existence(&agent, &report.direct, private_npm, &mut out);
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
