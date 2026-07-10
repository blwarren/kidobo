#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

use tempfile::TempDir;

fn installer_path() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts/install.sh")
        .display()
        .to_string()
}

fn write_executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod");
}

#[test]
fn installer_runs_when_read_from_standard_input() {
    let installer = fs::File::open(installer_path()).expect("open installer");
    let output = Command::new("bash")
        .arg("-s")
        .arg("--")
        .arg("--help")
        .stdin(Stdio::from(installer))
        .output()
        .expect("run installer from stdin");

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("BASH_SOURCE"));
}

#[test]
fn installer_entrypoint_does_not_depend_on_bash_source() {
    const MAX_INSTALLER_BYTES: u64 = 1024 * 1024;
    let installer_file = fs::File::open(installer_path()).expect("open installer");
    let mut installer = String::new();
    installer_file
        .take(MAX_INSTALLER_BYTES + 1)
        .read_to_string(&mut installer)
        .expect("read installer");

    assert!(installer.len() as u64 <= MAX_INSTALLER_BYTES);
    assert!(!installer.contains("BASH_SOURCE"));
}

#[test]
fn run_init_after_install_propagates_target_failure_status() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    write_executable(
        &install_dir.join("kidobo"),
        "#!/usr/bin/env bash\nexit 23\n",
    );
    let init_log = temp.path().join("init.log");

    let status = Command::new("bash")
        .arg("-c")
        .arg("source \"$INSTALLER\"; sudo() { \"$@\"; }; run_init_after_install \"$INIT_LOG\"")
        .env("INSTALLER", installer_path())
        .env("INIT_LOG", &init_log)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(23));
}

#[test]
fn uninstall_preserves_artifacts_when_fallback_cleanup_fails() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let install_dir = temp.path().join("bin");
    let binary = install_dir.join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 1\n");
    fs::create_dir_all(root.join("config")).expect("mkdir config");
    fs::write(root.join("config/config.toml"), "preserve").expect("write config");

    let status = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             run_flush_best_effort() { return 1; }; \
             cleanup_firewall_chain_family() { return 1; }; \
             cleanup_default_ipsets() { return 0; }; \
             uninstall_artifacts",
        )
        .env("INSTALLER", installer_path())
        .env("KIDOBO_ROOT", &root)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
    assert!(binary.exists());
    assert!(root.join("config/config.toml").exists());
}

#[test]
fn uninstall_removes_scoped_artifacts_after_successful_flush() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let install_dir = temp.path().join("bin");
    let binary = install_dir.join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 0\n");
    for directory in ["config", "data", "cache", "systemd/system"] {
        fs::create_dir_all(root.join(directory)).expect("mkdir artifact");
    }

    let status = Command::new("bash")
        .arg("-c")
        .arg("source \"$INSTALLER\"; run_flush_best_effort() { return 0; }; uninstall_artifacts")
        .env("INSTALLER", installer_path())
        .env("KIDOBO_ROOT", &root)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .status()
        .expect("run bash");

    assert!(status.success());
    assert!(!binary.exists());
    assert!(!root.join("config").exists());
    assert!(!root.join("data").exists());
    assert!(!root.join("cache").exists());
}

#[test]
fn known_init_reset_failure_recovery_propagates_success() {
    let temp = TempDir::new().expect("tempdir");
    let init_log = temp.path().join("init.log");
    fs::write(
        &init_log,
        "systemctl reset-failed kidobo-sync.service\nUnit kidobo-sync.service not loaded\n",
    )
    .expect("write log");

    let status = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             run_with_init_privileges() { return 0; }; \
             recover_known_init_systemd_reset_failed_case \"$INIT_LOG\"",
        )
        .env("INSTALLER", installer_path())
        .env("INIT_LOG", &init_log)
        .env_remove("KIDOBO_ROOT")
        .status()
        .expect("run bash");

    assert!(status.success());
}

#[test]
fn known_init_reset_failure_recovery_propagates_command_failure() {
    let temp = TempDir::new().expect("tempdir");
    let init_log = temp.path().join("init.log");
    fs::write(
        &init_log,
        "systemctl reset-failed kidobo-sync.service\nUnit kidobo-sync.service not loaded\n",
    )
    .expect("write log");

    let status = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             run_with_init_privileges() { return 1; }; \
             recover_known_init_systemd_reset_failed_case \"$INIT_LOG\"",
        )
        .env("INSTALLER", installer_path())
        .env("INIT_LOG", &init_log)
        .env_remove("KIDOBO_ROOT")
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
}
