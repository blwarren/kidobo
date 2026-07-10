#![cfg(unix)]

use std::fs::File;
use std::io::Read;
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
fn publisher_resolves_lockfile_before_staging_release_update() {
    const MAX_PUBLISHER_SCRIPT_BYTES: u64 = 64 * 1024;

    let file = File::open(publisher_path()).expect("open publisher script");
    assert!(
        file.metadata().expect("read publisher metadata").len() <= MAX_PUBLISHER_SCRIPT_BYTES,
        "publisher script exceeds test read limit"
    );
    let mut script = String::new();
    file.take(MAX_PUBLISHER_SCRIPT_BYTES)
        .read_to_string(&mut script)
        .expect("read publisher script");
    let lockfile_refresh = script
        .find("cargo update --package kidobo --precise \"${release_version}\"")
        .expect("publisher must update the package version in Cargo.lock");
    let release_staging = script
        .find("git add Cargo.toml Cargo.lock")
        .expect("publisher must stage the release update");

    assert!(
        lockfile_refresh < release_staging,
        "Cargo.lock must be resolved before it is staged"
    );
    for unsuitable_command in [
        "cargo metadata --no-deps",
        "cargo metadata --format-version 1",
    ] {
        assert!(
            !script.contains(unsuitable_command),
            "metadata resolution either leaves the package stale or refreshes dependencies"
        );
    }
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
        .arg("release-0.11.0")
        .output()
        .expect("run publisher with invalid version");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected X.Y.Z or vX.Y.Z"));
}
