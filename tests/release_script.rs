#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Command;

fn publisher_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/publish-release.sh")
}

#[test]
fn publisher_script_has_valid_bash_syntax() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(publisher_path())
        .status()
        .expect("check publisher syntax");

    assert!(status.success());
}

#[test]
fn publisher_requires_exactly_one_version() {
    let output = Command::new(publisher_path())
        .output()
        .expect("run publisher without version");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
}

#[test]
fn publisher_rejects_invalid_version_before_repository_changes() {
    let output = Command::new(publisher_path())
        .arg("0.11.0")
        .output()
        .expect("run publisher with invalid version");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected vX.Y.Z"));
}
