use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn parse(s: &str) -> Severity {
        match s.to_ascii_lowercase().as_str() {
            "high" | "critical" => Severity::High,
            "low" | "info" => Severity::Low,
            _ => Severity::Medium,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        })
    }
}

/// Which layer found it. Heuristics and low-confidence rules are "suspicious",
/// the rest are confirmed matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Hash,
    Rule,
    /// A rule that hunts for suspicious traits or dual-use tools rather than known malware.
    SuspiciousRule,
    Eicar,
    Heuristic,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Type/Platform.Family!variant, for example `Ransom/Win64.Locker!b`.
    pub name: String,
    pub severity: Severity,
    pub source: Source,
    /// One plain sentence.
    pub description: String,
    /// For rule hits: the rule's identifier, so anyone can look it up.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// For hits inside an archive or disk image: where, e.g. `docs › invoice.pdf.exe`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inner: Option<String>,
}

impl Detection {
    pub fn new(name: impl Into<String>, severity: Severity, source: Source, description: impl Into<String>) -> Self {
        Detection { name: name.into(), severity, source, description: description.into(), rule: None, author: None, reference: None, inner: None }
    }

    /// Confirmed matches (hash, rule, EICAR) may be quarantined automatically.
    /// Suspicious hits are only reported unless the user opts in.
    pub fn is_confirmed(&self) -> bool {
        !matches!(self.source, Source::Heuristic | Source::SuspiciousRule)
    }
}
