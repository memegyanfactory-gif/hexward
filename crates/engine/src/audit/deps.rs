//! Dependencies as lockfiles and manifests describe them. Offline checks here; the online
//! checks (known-malicious versions on OSV, names that don't exist on the registry) live in
//! `hexward-update`, which turns its answers into findings with the helpers below.

use serde::Serialize;

use super::{Category, Finding, Level, Report, TextFile, snippet};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct Package {
    /// OSV ecosystem name: "npm", "PyPI" or "crates.io".
    pub ecosystem: &'static str,
    pub name: String,
    /// Exact version from a lockfile, or the version range from a manifest.
    pub version: String,
}

#[allow(clippy::too_many_arguments)] // every finding names all its parts; a builder would be longer
fn finding(id: &'static str, level: Level, file: &str, line: Option<usize>, title: impl Into<String>, detail: impl Into<String>, fix: &str, evidence: &str) -> Finding {
    Finding { id, level, category: Category::Dependency, file: file.into(), line, title: title.into(), detail: detail.into(), fix: fix.into(), evidence: snippet(evidence, 160) }
}

fn line_of(text: &str, needle: &str) -> Option<usize> {
    text.find(needle).map(|o| text[..o].bytes().filter(|&b| b == b'\n').count() + 1)
}

fn outside_registry(spec: &str) -> bool {
    let s = spec.trim();
    ["git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "http://", "https://"].iter().any(|p| s.starts_with(p)) || (s.contains('/') && !s.starts_with("npm:") && !s.starts_with("file:") && !s.starts_with("link:") && !s.starts_with("workspace:") && !s.starts_with('.') && s.split('/').count() == 2 && !s.contains(' '))
}

pub fn check(f: &TextFile, report: &mut Report) {
    match f.name() {
        "package.json" if !f.rel.contains("node_modules/") => package_json(f, report),
        "package-lock.json" | "npm-shrinkwrap.json" => package_lock(f, report),
        "yarn.lock" => yarn_lock(f, report),
        "Cargo.lock" => toml_lock(f, report, "crates.io"),
        "poetry.lock" | "uv.lock" | "pdm.lock" => toml_lock(f, report, "PyPI"),
        n if n.starts_with("requirements") && n.ends_with(".txt") => requirements(f, report),
        _ => {}
    }
}

fn package_json(f: &TextFile, report: &mut Report) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(f.text) else { return };
    for section in ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"] {
        for (name, spec) in v.get(section).and_then(|d| d.as_object()).into_iter().flatten() {
            let spec = spec.as_str().unwrap_or("");
            if section != "peerDependencies" {
                report.direct.push(Package { ecosystem: "npm", name: name.clone(), version: spec.into() });
            }
            if outside_registry(spec) {
                report.findings.push(finding(
                    "dep-outside-registry",
                    Level::Medium,
                    f.rel,
                    line_of(f.text, &format!("\"{name}\"")),
                    format!("\"{name}\" comes straight from a git repository or URL"),
                    "Code from outside the registry has no published version history or malware scanning, and can change without a new version number.",
                    "Use a published registry version, or pin the git dependency to a commit you've reviewed.",
                    &format!("{name}: {spec}"),
                ));
            } else if matches!(spec.trim(), "*" | "latest" | "" | "x") {
                report.findings.push(finding(
                    "dep-any-version",
                    Level::Low,
                    f.rel,
                    line_of(f.text, &format!("\"{name}\"")),
                    format!("\"{name}\" accepts any version"),
                    "A hijacked new release would be installed automatically.",
                    "Use a version range, and commit the lockfile.",
                    &format!("{name}: {spec}"),
                ));
            }
        }
    }
}

fn package_lock(f: &TextFile, report: &mut Report) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(f.text) else { return };
    let mut odd = 0;
    for (key, p) in v.get("packages").and_then(|p| p.as_object()).into_iter().flatten() {
        let Some(name) = key.rsplit("node_modules/").next().filter(|n| !n.is_empty() && key.contains("node_modules/")) else { continue };
        if p.get("link").and_then(|l| l.as_bool()) == Some(true) {
            continue;
        }
        let version = p.get("version").and_then(|x| x.as_str()).unwrap_or("");
        if !version.is_empty() {
            report.packages.push(Package { ecosystem: "npm", name: name.into(), version: version.into() });
        }
        let resolved = p.get("resolved").and_then(|x| x.as_str()).unwrap_or("");
        if !resolved.is_empty() && !resolved.starts_with("https://registry.npmjs.org/") && !resolved.starts_with("https://registry.yarnpkg.com/") && odd < 25 {
            odd += 1;
            let (level, why) = if resolved.starts_with("https://") && !resolved.contains("github.com") && !resolved.contains("codeload") { (Level::Low, "from a different package registry") } else { (Level::Medium, "from a git repository or plain URL") };
            report.findings.push(finding("lock-outside-registry", level, f.rel, line_of(f.text, resolved), format!("{name} is installed {why}"), "Check that this source is one you expect; attackers point lockfiles at their own copies.", "Re-resolve it from the registry if you didn't choose this source.", resolved));
        }
        if !resolved.is_empty() && p.get("integrity").is_none() && odd < 25 {
            odd += 1;
            report.findings.push(finding("lock-no-integrity", Level::Low, f.rel, line_of(f.text, resolved), format!("{name} has no integrity hash"), "npm can't verify the download matches what was locked.", "Regenerate the lockfile with a current npm.", resolved));
        }
    }
}

fn yarn_lock(f: &TextFile, report: &mut Report) {
    let mut name = String::new();
    for l in f.text.lines() {
        if !l.starts_with(' ') && l.ends_with(':') && !l.starts_with('#') {
            let first = l.trim_end_matches(':').split(", ").next().unwrap_or("").trim_matches('"');
            name = first.rsplit_once('@').map(|(n, _)| n.to_string()).filter(|n| !n.is_empty()).unwrap_or_default();
        } else if let Some(v) = l.trim().strip_prefix("version ") {
            if !name.is_empty() {
                report.packages.push(Package { ecosystem: "npm", name: name.clone(), version: v.trim_matches('"').into() });
            }
        } else if let Some(r) = l.trim().strip_prefix("resolved ") {
            let r = r.trim_matches('"');
            if !r.starts_with("https://registry.yarnpkg.com/") && !r.starts_with("https://registry.npmjs.org/") {
                report.findings.push(finding("lock-outside-registry", Level::Medium, f.rel, line_of(f.text, r), format!("{name} is installed from outside the registry"), "Check that this source is one you expect.", "Re-resolve it from the registry if you didn't choose this source.", r));
            }
        }
    }
}

/// Cargo.lock, poetry.lock, uv.lock: `[[package]]` blocks with name, version, source.
fn toml_lock(f: &TextFile, report: &mut Report, ecosystem: &'static str) {
    let (mut name, mut version) = (String::new(), String::new());
    let flush = |name: &mut String, version: &mut String, report: &mut Report| {
        if !name.is_empty() && !version.is_empty() {
            report.packages.push(Package { ecosystem, name: std::mem::take(name), version: std::mem::take(version) });
        }
        name.clear();
        version.clear();
    };
    for l in f.text.lines() {
        let t = l.trim();
        if t == "[[package]]" {
            flush(&mut name, &mut version, report);
        } else if let Some(v) = t.strip_prefix("name = ") {
            name = v.trim_matches('"').into();
        } else if let Some(v) = t.strip_prefix("version = ") {
            version = v.trim_matches('"').into();
        } else if let Some(src) = t.strip_prefix("source = ")
            && ecosystem == "crates.io"
            && src.contains("git+")
        {
            report.findings.push(finding("lock-git-source", Level::Low, f.rel, line_of(f.text, src), format!("Crate {name} comes from a git repository"), "It isn't checked by crates.io and can change without a new version.", "Prefer a crates.io release, or pin the commit you reviewed.", src));
        }
    }
    flush(&mut name, &mut version, report);
}

fn requirements(f: &TextFile, report: &mut Report) {
    for (i, l) in f.text.lines().enumerate() {
        let t = l.split(" #").next().unwrap_or("").trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if t.starts_with("--extra-index-url") || t.starts_with("--index-url") || t.starts_with("-i ") {
            let extra = t.starts_with("--extra-index-url");
            report.findings.push(finding(
                "pip-index",
                if extra { Level::Medium } else { Level::Low },
                f.rel,
                Some(i + 1),
                if extra { "Extra package index next to PyPI" } else { "Custom package index" },
                if extra { "pip picks the highest version from either index, so anyone can publish your private package's name on PyPI and win (dependency confusion)." } else { "Packages come from this index instead of PyPI." },
                "Use one index, or pin hashes with --require-hashes.",
                t,
            ));
            continue;
        }
        if t.starts_with('-') {
            continue;
        }
        if t.contains("git+") || t.starts_with("http://") || t.starts_with("https://") {
            report.findings.push(finding("dep-outside-registry", Level::Medium, f.rel, Some(i + 1), "Package installed straight from a URL", "It isn't checked by PyPI and can change without a new version.", "Pin a commit you've reviewed, or use a PyPI release.", t));
            continue;
        }
        let name: String = t.chars().take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')).collect();
        if name.is_empty() {
            continue;
        }
        let spec = t[name.len()..].trim();
        if let Some(v) = spec.strip_prefix("==") {
            report.packages.push(Package { ecosystem: "PyPI", name: name.clone(), version: v.split([';', ',', ' ']).next().unwrap_or("").into() });
        }
        report.direct.push(Package { ecosystem: "PyPI", name, version: spec.into() });
    }
}

/// A finding for a package version OSV lists as malicious.
pub fn malicious_finding(p: &Package, id: &str, summary: &str) -> Finding {
    finding(
        "dep-known-malicious",
        Level::High,
        "",
        None,
        format!("{} {} is known malware ({id})", p.name, p.version),
        format!("OSV lists this exact version as malicious: {summary}"),
        "Remove it now. If it was installed, treat this PC's tokens and passwords as stolen: revoke and replace them.",
        &format!("{} {}@{}", p.ecosystem, p.name, p.version),
    )
}

/// A finding for a declared dependency the registry has never heard of.
pub fn missing_finding(p: &Package) -> Finding {
    finding(
        "dep-not-on-registry",
        Level::High,
        "",
        None,
        format!("\"{}\" doesn't exist on {}", p.name, if p.ecosystem == "npm" { "npm" } else { "PyPI" }),
        "The project asks for a package nobody has published. AI assistants invent names like this, and attackers register them to catch the installs (slopsquatting).",
        "Check the name. If it's a typo or invented, fix it before anyone runs an install.",
        &format!("{} {}", p.ecosystem, p.name),
    )
}

/// A summary finding for known (non-malware) vulnerabilities.
pub fn vulnerable_finding(count: usize, examples: &str) -> Finding {
    finding("dep-vulnerable", Level::Low, "", None, format!("{count} dependency versions have known vulnerabilities"), format!("Not malware, but worth updating: {examples}"), "Run your package manager's audit (npm audit, pip-audit, cargo audit) and update.", "")
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{ids, project};
    use super::super::{Options, audit};

    #[test]
    fn reads_lockfiles_and_flags_odd_sources() {
        let pkg = "{\"name\":\"app\",\"dependencies\":{\"left-pad\":\"^1.3.0\",\"evil\":\"github:someone/evil\",\"loose\":\"*\"}}";
        let lock = "{\"lockfileVersion\":3,\"packages\":{\"\":{\"name\":\"app\"},\"node_modules/left-pad\":{\"version\":\"1.3.0\",\"resolved\":\"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz\",\"integrity\":\"sha512-x\"},\"node_modules/evil\":{\"version\":\"1.0.0\",\"resolved\":\"git+ssh://git@github.com/someone/evil.git#abc\"}}}";
        let req = "--extra-index-url https://pkgs.example.com/simple\nrequests==2.31.0\nflask>=2\n";
        let cargo = "[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n\n[[package]]\nname = \"mine\"\nversion = \"0.1.0\"\nsource = \"git+https://github.com/me/mine#abc\"\n";
        let p = project(&[("package.json", pkg), ("package-lock.json", lock), ("requirements.txt", req), ("Cargo.lock", cargo)]);
        let r = audit(p.path(), &Options::default());
        let ids = ids(&r);
        for want in ["dep-outside-registry", "dep-any-version", "lock-outside-registry", "lock-no-integrity", "pip-index", "lock-git-source"] {
            assert!(ids.contains(&want), "missing {want}: {ids:?}");
        }
        let has = |eco: &str, n: &str, v: &str| r.packages.iter().any(|p| p.ecosystem == eco && p.name == n && p.version == v);
        assert!(has("npm", "left-pad", "1.3.0") && has("PyPI", "requests", "2.31.0") && has("crates.io", "serde", "1.0.200"));
        assert!(r.direct.iter().any(|p| p.name == "flask") && r.direct.iter().any(|p| p.name == "left-pad"));
    }
}
