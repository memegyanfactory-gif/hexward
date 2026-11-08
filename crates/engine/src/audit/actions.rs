//! GitHub Actions workflows: the build pipeline is part of the supply chain.
//! - actions pinned to a movable tag can change under you (tj-actions/changed-files, March 2025)
//! - `pull_request_target` with a checkout of the PR runs a stranger's code with your secrets
//! - `${{ github.event... }}` text from issues and PRs pasted into `run:` is shell injection

use super::{Category, Finding, Level, TextFile, snippet};

/// Actions known to have had their tags hijacked.
const COMPROMISED: &[&str] = &["tj-actions/changed-files", "tj-actions/", "reviewdog/action-setup", "reviewdog/"];

const UNTRUSTED: &[&str] = &[
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.head_ref",
    "github.event.commits",
    "github.event.pages",
];

#[allow(clippy::too_many_arguments)] // every finding names all its parts; a builder would be longer
fn finding(id: &'static str, level: Level, f: &TextFile, line: Option<usize>, title: impl Into<String>, detail: &str, fix: &str, evidence: &str) -> Finding {
    Finding { id, level, category: Category::Workflow, file: f.rel.into(), line, title: title.into(), detail: detail.into(), fix: fix.into(), evidence: snippet(evidence, 160) }
}

fn indent(l: &str) -> usize {
    l.len() - l.trim_start().len()
}

pub fn check(f: &TextFile, out: &mut Vec<Finding>) {
    let rel = f.rel.to_ascii_lowercase();
    let workflow = rel.starts_with(".github/workflows/") && (rel.ends_with(".yml") || rel.ends_with(".yaml"));
    let action = f.name() == "action.yml" || f.name() == "action.yaml";
    if !workflow && !action {
        return;
    }
    let lines: Vec<&str> = f.text.lines().collect();
    let mut run_indent: Option<usize> = None;
    for (i, l) in lines.iter().enumerate() {
        let t = l.trim_start();
        let t = t.strip_prefix("- ").unwrap_or(t);
        // Leaving a run: block?
        if let Some(ri) = run_indent
            && !t.is_empty()
            && indent(l) <= ri
        {
            run_indent = None;
        }
        if let Some(v) = t.strip_prefix("uses:") {
            let v = v.trim().trim_matches(['"', '\'']).split(" #").next().unwrap_or("").trim();
            if v.starts_with("./") || v.starts_with("docker://") || v.is_empty() {
                continue;
            }
            let (repo, r#ref) = v.split_once('@').unwrap_or((v, ""));
            let pinned = r#ref.len() == 40 && r#ref.chars().all(|c| c.is_ascii_hexdigit());
            if COMPROMISED.iter().any(|c| repo.starts_with(c)) && !pinned {
                out.push(finding("actions-compromised", Level::High, f, Some(i + 1), format!("{repo} had its tags hijacked"), "Attackers moved this action's version tags to code that dumped CI secrets into build logs.", "Pin a reviewed commit SHA, or replace the action.", v));
            } else if !pinned {
                out.push(finding(
                    "actions-unpinned",
                    Level::Medium,
                    f,
                    Some(i + 1),
                    format!("{repo} is used by tag \"{}\", not a commit", if r#ref.is_empty() { "(none)" } else { r#ref }),
                    "Tags can be moved to new code at any time, and your workflow runs it with your secrets.",
                    "Pin the full 40-character commit SHA and keep the version in a comment.",
                    v,
                ));
            }
            continue;
        }
        if t.starts_with("run:") {
            run_indent = Some(indent(l));
        }
        let in_run = run_indent.is_some();
        if in_run && t.contains("${{") && let Some(u) = UNTRUSTED.iter().find(|u| t.contains(*u)) {
            out.push(finding(
                "actions-script-injection",
                Level::High,
                f,
                Some(i + 1),
                format!("Untrusted text ({u}) pasted into a shell command"),
                "Anyone who can open an issue or PR controls this text, so they can run commands in your workflow, with its token and secrets.",
                "Pass it through an environment variable (env: TITLE: ${{ ... }}) and use \"$TITLE\" in the script.",
                t,
            ));
        }
        if t.starts_with("permissions:") && t.contains("write-all") {
            out.push(finding("actions-write-all", Level::Medium, f, Some(i + 1), "Workflow token can write everything", "If any step is compromised, it can push code, change releases and edit settings.", "Grant only what's needed, e.g. permissions: contents: read.", t));
        }
    }
    if workflow {
        let prt = f.text.contains("pull_request_target");
        let checks_out_pr = ["github.event.pull_request.head.sha", "github.event.pull_request.head.ref", "github.head_ref", "refs/pull/"].iter().any(|s| f.text.contains(s));
        if prt && checks_out_pr {
            let line = f.text.find("pull_request_target").map(|o| f.line_of(o));
            out.push(finding("actions-prt-checkout", Level::High, f, line, "pull_request_target runs code from the pull request", "This trigger runs with your secrets and a write token, and the workflow checks out the PR's own code, so a stranger's PR can steal them.", "Use the pull_request trigger for building PR code, or don't check out the PR head here.", "pull_request_target + PR head checkout"));
        } else if prt {
            let line = f.text.find("pull_request_target").map(|o| f.line_of(o));
            out.push(finding("actions-prt", Level::Low, f, line, "Workflow uses pull_request_target", "It runs with secrets on pull requests from anyone. Safe only if it never runs the PR's code.", "Double-check no step builds or runs PR code.", "pull_request_target"));
        }
        if !f.text.lines().any(|l| l.trim_start().starts_with("permissions:")) {
            out.push(finding("actions-no-permissions", Level::Low, f, None, "Workflow doesn't limit its token", "Without a permissions block the token gets the repository's default, which can include write access.", "Add permissions: contents: read at the top and widen per job.", ""));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::{ids, project};
    use super::super::{Options, audit};

    #[test]
    fn finds_workflow_problems() {
        let wf = "on:\n  pull_request_target:\n  issues:\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - uses: tj-actions/changed-files@v45\n      - uses: actions/cache@0c45773b623bea8c8e75f6c82b208c3cf94ea4f9 # v4\n      - uses: ./local\n      - name: greet\n        run: |\n          echo \"${{ github.event.issue.title }}\"\n      - name: safe\n        env:\n          T: ${{ github.event.issue.title }}\n        run: echo \"$T\"\n";
        let p = project(&[(".github/workflows/ci.yml", wf)]);
        let r = audit(p.path(), &Options::default());
        let ids = ids(&r);
        for want in ["actions-unpinned", "actions-compromised", "actions-prt-checkout", "actions-script-injection", "actions-no-permissions"] {
            assert!(ids.contains(&want), "missing {want}: {ids:?}");
        }
        assert_eq!(r.findings.iter().filter(|f| f.id == "actions-unpinned").count(), 1, "SHA-pinned and local actions are fine");
        assert_eq!(r.findings.iter().filter(|f| f.id == "actions-script-injection").count(), 1, "env: is the safe way");
    }
}
