use std::path::Path;
use std::time::Duration;

use yara_x::{Compiler, MetaValue, Rules, Scanner};

use crate::detect::{Detection, Severity, Source};
use crate::{EngineError, Result};

pub const BUILTIN_RULES: &str = include_str!("../../../rules/hexward.yar");

/// External variables community rules expect (signature-base style). Set per file while scanning.
const GLOBALS: [&str; 4] = ["filename", "filepath", "extension", "owner"];

/// Compiled YARA-X rules. Compile once, share across threads; each thread makes its own scanner.
pub struct RuleSet {
    rules: Rules,
    count: usize,
    /// Rules or files that didn't compile, with the reason. They are left out, not fatal.
    pub skipped: Vec<String>,
}

impl RuleSet {
    /// `sources` is a list of (origin, YARA source). YARA-X keeps every good rule in a
    /// source even when some rules in it fail, so one bad rule doesn't take a pack down;
    /// the failures are listed in `skipped`. Only the first source (built-in) must be clean.
    pub fn compile(sources: &[(String, String)]) -> Result<Self> {
        let mut compiler = Compiler::new();
        for g in GLOBALS {
            compiler.define_global(g, "").map_err(|e| EngineError::Rules(e.to_string()))?;
        }
        let mut skipped = Vec::new();
        for (i, (origin, src)) in sources.iter().enumerate() {
            let before = compiler.errors().len();
            if let Err(e) = compiler.add_source(src.as_str()) {
                if i == 0 {
                    return Err(EngineError::Rules(format!("{origin}: {e}")));
                }
                let errs = &compiler.errors()[before..];
                let errs: Vec<String> = if errs.is_empty() { vec![e.to_string()] } else { errs.iter().map(|e| e.to_string()).collect() };
                skipped.extend(errs.iter().map(|e| format!("{origin}: {}", e.lines().next().unwrap_or(""))));
            }
        }
        let rules = compiler.build();
        let count = rules.iter().count();
        Ok(RuleSet { rules, count, skipped })
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn scanner(&self) -> Scanner<'_> {
        let mut s = Scanner::new(&self.rules);
        s.set_timeout(Duration::from_secs(10));
        s
    }

    /// Runs the rules over `data`, with `path` feeding the filename/extension variables.
    /// A timeout or scan error yields no detections.
    pub fn scan(scanner: &mut Scanner<'_>, path: &Path, data: &[u8]) -> Vec<Detection> {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let ext = path.extension().map(|n| format!(".{}", n.to_string_lossy().to_lowercase())).unwrap_or_default();
        let dir = path.parent().map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
        let _ = scanner.set_global("filename", name.as_str());
        let _ = scanner.set_global("filepath", dir.as_str());
        let _ = scanner.set_global("extension", ext.as_str());

        let Ok(results) = scanner.scan(data) else {
            return Vec::new();
        };
        results.matching_rules().map(|rule| to_detection(rule.identifier(), rule.metadata())).collect()
    }
}

fn to_detection<'a>(identifier: &str, meta: impl Iterator<Item = (&'a str, MetaValue<'a>)>) -> Detection {
    let mut name = None;
    let mut severity = None;
    let mut description = None;
    let mut score = None;
    let mut author = None;
    let mut reference = None;
    for (key, value) in meta {
        match (key, value) {
            ("name", MetaValue::String(v)) => name = Some(v.to_string()),
            ("severity", MetaValue::String(v)) => severity = Some(Severity::parse(v)),
            ("description", MetaValue::String(v)) => description = Some(v.to_string()),
            ("author", MetaValue::String(v)) => author = Some(v.to_string()),
            ("reference", MetaValue::String(v)) if reference.is_none() => reference = Some(v.to_string()),
            ("score", MetaValue::Integer(v)) => score = Some(v),
            ("score", MetaValue::String(v)) => score = v.trim().parse().ok(),
            _ => {}
        }
    }

    // Our own rules carry `name` and `severity`. Community rules carry a 0-100 `score`
    // (signature-base convention: 40-60 suspicious, 70+ likely bad, 80+ malware).
    let kind = kind_of(identifier);
    // Malpedia "_Auto" rules are machine-generated from code bytes and can match shared library code.
    let auto_generated = identifier.starts_with("MALPEDIA_") && identifier.ends_with("_Auto");
    let weak = matches!(kind, "Suspicious" | "HackTool" | "PUP") || auto_generated || score.is_some_and(|s| s < 75);
    let severity = severity.unwrap_or(match score {
        Some(s) if s >= 80 => Severity::High,
        Some(s) if s >= 70 => Severity::Medium,
        Some(_) => Severity::Low,
        None => Severity::Medium,
    });
    let source = if name.is_none() && weak { Source::SuspiciousRule } else { Source::Rule };
    let mut d = Detection::new(
        name.unwrap_or_else(|| format!("{kind}/Any.{identifier}!y")),
        severity,
        source,
        description.unwrap_or_else(|| format!("Matched the rule {identifier}.")),
    );
    d.rule = Some(identifier.to_string());
    d.author = author;
    d.reference = reference;
    d
}

/// Guesses the threat type from community naming conventions (MAL_, HKTL_, SUSP_, ...).
fn kind_of(identifier: &str) -> &'static str {
    let up = identifier.to_ascii_uppercase();
    let has = |t: &str| up.split('_').any(|p| p == t);
    if has("SUSP") || has("SUSPICIOUS") || has("INDICATOR") || has("GEN") && has("SUSP") {
        "Suspicious"
    } else if has("HKTL") || has("HACKTOOL") || has("PENTEST") || has("RT") {
        "HackTool"
    } else if has("PUA") || has("PUP") || has("ADWARE") {
        "PUP"
    } else if up.contains("RANSOM") {
        "Ransom"
    } else if has("WEBSHELL") || up.contains("WEBSHELL") {
        "Webshell"
    } else if has("EXPL") || has("EXPLOIT") || has("CVE") || up.contains("_CVE_") {
        "Exploit"
    } else if has("APT") {
        "APT"
    } else {
        "Malware"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(rs: &RuleSet, path: &str, data: &[u8]) -> Vec<(String, Source)> {
        let mut s = rs.scanner();
        RuleSet::scan(&mut s, Path::new(path), data).into_iter().map(|d| (d.name, d.source)).collect()
    }

    #[test]
    fn bad_rule_is_skipped_good_ones_kept() {
        let pack = r#"
import "pe"
rule MAL_Good_One { meta: score = 85 description = "good" strings: $a = "AAAA-1111" condition: $a }
rule Broken_Rule { condition: no_such_module.thing == 1 }
private rule Helper { strings: $h = "HELP-ME" condition: $h }
rule SUSP_Uses_Helper { meta: score = 60 condition: Helper }
"#;
        let rs = RuleSet::compile(&[("built-in".into(), BUILTIN_RULES.into()), ("pack.yar".into(), pack.into())]).unwrap();
        assert_eq!(rs.skipped.len(), 1, "{:?}", rs.skipped);
        assert!(rs.skipped[0].contains("no_such_module"), "{:?}", rs.skipped);
        assert_eq!(names(&rs, "a.bin", b"xx AAAA-1111 xx"), [("Malware/Any.MAL_Good_One!y".to_string(), Source::Rule)]);
        assert_eq!(names(&rs, "a.bin", b"HELP-ME"), [("Suspicious/Any.SUSP_Uses_Helper!y".to_string(), Source::SuspiciousRule)]);
    }

    #[test]
    fn filename_variables_are_set() {
        let pack = r#"rule HKTL_By_Name { meta: score = 80 condition: filename == "mimi.exe" and extension == ".exe" }"#;
        let rs = RuleSet::compile(&[("built-in".into(), BUILTIN_RULES.into()), ("p".into(), pack.into())]).unwrap();
        assert_eq!(names(&rs, r"C:\t\mimi.exe", b"x"), [("HackTool/Any.HKTL_By_Name!y".to_string(), Source::SuspiciousRule)]);
        assert!(names(&rs, r"C:\t\other.exe", b"x").is_empty());
    }

    #[test]
    fn kinds() {
        assert_eq!(kind_of("SIGNATURE_BASE_MAL_Emotet_Jan21"), "Malware");
        assert_eq!(kind_of("ELASTIC_Windows_Ransomware_Lockbit_89E64044"), "Ransom");
        assert_eq!(kind_of("SIGNATURE_BASE_HKTL_Mimikatz"), "HackTool");
        assert_eq!(kind_of("SIGNATURE_BASE_SUSP_LNK_Big"), "Suspicious");
        assert_eq!(kind_of("R3C0NST_Exploit_Outlook_CVE_2023_23397"), "Exploit");
        let d = to_detection("MALPEDIA_Win_Example_Auto", std::iter::empty());
        assert_eq!(d.source, Source::SuspiciousRule, "auto-generated rules are never confirmed on their own");
    }
}
