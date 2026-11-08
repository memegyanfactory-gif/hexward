//! Hexward scanning engine.
//!
//! Layers, cheapest first:
//! 1. file-name tricks (double extensions, right-to-left override, padding)
//! 2. SHA-256 hash list
//! 3. the EICAR test file
//! 4. YARA-X rules
//! 5. content checks (Windows programs disguised as documents or images)

pub mod allowlist;
pub mod backup;
pub mod audit;
pub mod behavior;
pub mod cache;
pub mod chains;
pub mod cleaner;
pub mod container;
pub mod deobf;
pub mod detect;
pub mod drivers;
pub mod fileinfo;
pub mod formats;
pub mod guard;
pub mod eicar;
pub mod extensions;
pub mod hashdb;
pub mod heuristics;
pub mod installers;
pub mod history;
pub mod lnk;
pub mod mcp;
pub mod memscan;
pub mod motw;
pub mod locations;
pub mod office;
pub mod perf;
pub mod ransom;
pub mod rules;
pub mod scan;
pub mod scripts;
pub mod sig;
pub mod services;
pub mod startup;
pub mod tasks;
pub mod vault;

pub use detect::{Detection, Severity, Source};
pub use scan::{Engine, FileReport, Progress, ScanOptions, ScanSummary};
pub use vault::{Vault, VaultEntry};

use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("rules didn't compile: {0}")]
    Rules(String),
    #[error("quarantine: {0}")]
    Vault(String),
}

pub type Result<T> = std::result::Result<T, EngineError>;

/// Where Hexward keeps its data (quarantine, user rules).
/// `HEXWARD_HOME` overrides it, which keeps tests away from the real vault.
pub fn data_dir() -> PathBuf {
    if let Some(home) = std::env::var_os("HEXWARD_HOME") {
        return PathBuf::from(home);
    }
    dirs::data_local_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("Hexward")
}

/// Tests that point HEXWARD_HOME at a temporary folder hold this, so they don't race.
#[cfg(test)]
pub(crate) static TEST_HOME: std::sync::Mutex<()> = std::sync::Mutex::new(());
