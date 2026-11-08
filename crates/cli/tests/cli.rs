//! End-to-end: run the real binary on a folder of harmless test files.

use std::path::Path;
use std::process::Command;

fn hexward(home: &Path) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_hexward"));
    c.env("HEXWARD_HOME", home).env("NO_COLOR", "1");
    c
}

#[test]
fn scan_quarantine_restore() {
    let home = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let t = target.path();
    std::fs::write(t.join("clean.txt"), "hello").unwrap();
    std::fs::write(t.join("marker.bin"), "HEXWARD-HARMLESS-TEST-MARKER-7f3a9c").unwrap();
    std::fs::write(t.join("invoice.pdf.exe"), "not really a program").unwrap();

    // Report only: exit 1, nothing moved.
    let out = hexward(home.path()).args(["scan", "--json"]).arg(t).output().unwrap();
    assert_eq!(out.status.code(), Some(1), "{}", String::from_utf8_lossy(&out.stderr));
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["summary"]["files_scanned"], 3);
    assert_eq!(v["summary"]["threats"].as_array().unwrap().len(), 2);
    assert!(t.join("marker.bin").exists());

    // Quarantine: the confirmed hit moves, the suspicious one stays.
    let out = hexward(home.path()).args(["scan", "--quarantine", "--json"]).arg(t).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let moved = v["quarantined"].as_array().unwrap();
    assert_eq!(moved.len(), 1);
    assert!(!t.join("marker.bin").exists());
    assert!(t.join("invoice.pdf.exe").exists());
    let id = moved[0]["id"].as_str().unwrap().to_string();

    // A second scan no longer sees it, and the vault isn't scanned.
    let out = hexward(home.path()).args(["scan", "--json"]).arg(t).arg(home.path()).output().unwrap();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["summary"]["threats"].as_array().unwrap().len(), 1);

    // Restore puts it back.
    let out = hexward(home.path()).args(["quarantine", "restore", &id]).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read(t.join("marker.bin")).unwrap(), b"HEXWARD-HARMLESS-TEST-MARKER-7f3a9c");

    // Clean folder: exit 0.
    std::fs::remove_file(t.join("marker.bin")).unwrap();
    std::fs::remove_file(t.join("invoice.pdf.exe")).unwrap();
    let out = hexward(home.path()).arg("scan").arg(t).output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("Nothing found."));
}

#[test]
fn missing_path_is_an_error() {
    let home = tempfile::tempdir().unwrap();
    let out = hexward(home.path()).args(["scan", r"Z:\definitely\not\here"]).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}
