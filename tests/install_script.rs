#![cfg(unix)]

use std::fmt::Write as _;
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use sha2::{Digest, Sha256};
use tempfile::TempDir;

const TEST_VERSION: &str = "v9.8.7";
const FIXTURE_FILE_READ_LIMIT: usize = 16 * 1024 * 1024;

fn read_bytes_with_limit(path: &Path, limit: usize) -> Vec<u8> {
    let file = fs::File::open(path).expect("open bounded fixture file");
    assert!(
        file.metadata().expect("fixture metadata").len()
            <= u64::try_from(limit).expect("read limit fits u64"),
        "fixture exceeds {limit} byte read limit: {}",
        path.display()
    );
    let mut bytes = Vec::new();
    file.take(u64::try_from(limit).expect("read limit fits u64"))
        .read_to_end(&mut bytes)
        .expect("read bounded fixture file");
    bytes
}

fn read_to_string_with_limit(path: &Path, limit: usize) -> String {
    String::from_utf8(read_bytes_with_limit(path, limit)).expect("fixture is UTF-8")
}

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

fn path_with_prefix(path: &Path) -> String {
    match std::env::var("PATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", path.display()),
        _ => path.display().to_string(),
    }
}

fn prepare_release_fixture(temp: &TempDir, binary_script: &str) -> PathBuf {
    let release_dir = temp.path().join("release");
    let archive_root = temp
        .path()
        .join(format!("kidobo-{TEST_VERSION}-linux-x86_64"));
    fs::create_dir_all(&release_dir).expect("mkdir release");
    write_executable(&archive_root.join("kidobo"), binary_script);

    let archive_name = format!("kidobo-{TEST_VERSION}-linux-x86_64.tar.gz");
    let archive = release_dir.join(&archive_name);
    let status = Command::new("tar")
        .args(["-czf"])
        .arg(&archive)
        .arg("-C")
        .arg(temp.path())
        .arg(archive_root.file_name().expect("archive root name"))
        .status()
        .expect("create release archive");
    assert!(status.success());
    write_checksum_file(&release_dir, &archive_name);

    let fake_bin = temp.path().join("fake-bin");
    write_executable(
        &fake_bin.join("curl"),
        r#"#!/usr/bin/env bash
set -euo pipefail
if [[ "${KIDOBO_TEST_CURL_FAIL:-0}" == "1" ]]; then
  exit 22
fi
output=""
url=""
while [[ $# -gt 0 ]]; do
  if [[ "$1" == "-o" ]]; then
    output="$2"
    shift 2
    continue
  fi
  url="$1"
  shift
done
cp "${KIDOBO_TEST_RELEASE_DIR}/${url##*/}" "${output}"
"#,
    );
    release_dir
}

fn write_checksum_file(release_dir: &Path, archive_name: &str) {
    let archive = read_bytes_with_limit(&release_dir.join(archive_name), FIXTURE_FILE_READ_LIMIT);
    let mut checksum = String::with_capacity(64);
    for byte in Sha256::digest(&archive) {
        let _write_result = write!(&mut checksum, "{byte:02x}");
    }
    fs::write(
        release_dir.join("SHA256SUMS"),
        format!("{checksum}  {archive_name}\n"),
    )
    .expect("write checksums");
}

fn installer_command(temp: &TempDir, release_dir: &Path, install_dir: &Path) -> Command {
    let mut command = Command::new(installer_path());
    command
        .args(["--version", TEST_VERSION])
        .env("KIDOBO_INSTALL_DIR", install_dir)
        .env("KIDOBO_TEST_RELEASE_DIR", release_dir)
        .env("PATH", path_with_prefix(&temp.path().join("fake-bin")));
    command
}

fn install_old_binary(install_dir: &Path) -> Vec<u8> {
    let old_binary = install_dir.join("kidobo");
    write_executable(&old_binary, "#!/usr/bin/env bash\nprintf 'kidobo old\\n'\n");
    read_bytes_with_limit(&old_binary, FIXTURE_FILE_READ_LIMIT)
}

fn assert_old_binary_and_no_staging_files(install_dir: &Path, expected: &[u8]) {
    assert_eq!(
        read_bytes_with_limit(&install_dir.join("kidobo"), FIXTURE_FILE_READ_LIMIT),
        expected
    );
    let names = fs::read_dir(install_dir)
        .expect("read install dir")
        .map(|entry| {
            entry
                .expect("install entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(names, vec!["kidobo"]);
}

fn write_cleanup_fakes(temp: &TempDir) -> PathBuf {
    let fake_bin = temp.path().join("cleanup-bin");
    let command_script = r#"#!/usr/bin/env bash
set -euo pipefail
name="${0##*/}"
printf '%s %s\n' "${name}" "$*" >> "${KIDOBO_TEST_CLEANUP_LOG}"
if [[ "${name}" == "iptables" || "${name}" == "ip6tables" ]]; then
  args=" $* "
  if [[ "${args}" == *" -D INPUT "* ]]; then
    echo "Bad rule (does a matching rule exist in that chain?)." >&2
    exit 1
  fi
  if [[ "${KIDOBO_TEST_FAIL_CLEANUP:-}" == "${name}" && "${args}" == *" -F "* ]]; then
    echo "injected cleanup failure" >&2
    exit 42
  fi
fi
exit 0
"#;
    for binary in ["iptables", "ip6tables", "ipset"] {
        write_executable(&fake_bin.join(binary), command_script);
    }
    write_executable(
        &fake_bin.join("sudo"),
        "#!/usr/bin/env bash\nset -euo pipefail\n[[ \"${1:-}\" == \"-n\" ]]\nshift\nexec \"$@\"\n",
    );
    fake_bin
}

#[test]
fn installer_validates_checksum_and_installs_the_verified_binary() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    fs::create_dir_all(&install_dir).expect("mkdir install");
    let release_dir = prepare_release_fixture(
        &temp,
        "#!/usr/bin/env bash\n[[ \"${1:-}\" == \"--version\" ]]\nprintf 'kidobo 9.8.7\\n'\n",
    );

    let output = installer_command(&temp, &release_dir, &install_dir)
        .output()
        .expect("run installer");

    assert!(
        output.status.success(),
        "installer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let installed_version = Command::new(install_dir.join("kidobo"))
        .arg("--version")
        .output()
        .expect("run installed binary");
    assert!(installed_version.status.success());
    assert_eq!(installed_version.stdout, b"kidobo 9.8.7\n");
}

#[test]
fn installer_rejects_wrong_missing_and_ambiguous_checksums_without_replacement() {
    for checksum_case in ["wrong", "missing", "ambiguous"] {
        let temp = TempDir::new().expect("tempdir");
        let install_dir = temp.path().join("bin");
        fs::create_dir_all(&install_dir).expect("mkdir install");
        let old_binary = install_old_binary(&install_dir);
        let release_dir =
            prepare_release_fixture(&temp, "#!/usr/bin/env bash\nprintf 'kidobo 9.8.7\\n'\n");
        let checksum_path = release_dir.join("SHA256SUMS");
        let valid = read_to_string_with_limit(&checksum_path, FIXTURE_FILE_READ_LIMIT);
        match checksum_case {
            "wrong" => fs::write(
                &checksum_path,
                format!(
                    "{}  kidobo-{TEST_VERSION}-linux-x86_64.tar.gz\n",
                    "0".repeat(64)
                ),
            )
            .expect("write wrong checksum"),
            "missing" => fs::write(&checksum_path, "unrelated  other.tar.gz\n")
                .expect("write missing checksum"),
            "ambiguous" => fs::write(&checksum_path, format!("{valid}{valid}"))
                .expect("write ambiguous checksum"),
            _ => unreachable!(),
        }

        let output = installer_command(&temp, &release_dir, &install_dir)
            .output()
            .expect("run installer");

        assert!(
            !output.status.success(),
            "{checksum_case} checksum succeeded"
        );
        assert_old_binary_and_no_staging_files(&install_dir, &old_binary);
    }
}

#[test]
fn installer_download_failure_preserves_the_existing_binary() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    fs::create_dir_all(&install_dir).expect("mkdir install");
    let old_binary = install_old_binary(&install_dir);
    let release_dir =
        prepare_release_fixture(&temp, "#!/usr/bin/env bash\nprintf 'kidobo 9.8.7\\n'\n");

    let output = installer_command(&temp, &release_dir, &install_dir)
        .env("KIDOBO_TEST_CURL_FAIL", "1")
        .output()
        .expect("run installer");

    assert!(!output.status.success());
    assert_old_binary_and_no_staging_files(&install_dir, &old_binary);
}

#[test]
fn installer_extract_failure_preserves_the_existing_binary() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    fs::create_dir_all(&install_dir).expect("mkdir install");
    let old_binary = install_old_binary(&install_dir);
    let release_dir =
        prepare_release_fixture(&temp, "#!/usr/bin/env bash\nprintf 'kidobo 9.8.7\\n'\n");
    let archive_name = format!("kidobo-{TEST_VERSION}-linux-x86_64.tar.gz");
    fs::write(release_dir.join(&archive_name), "not an archive").expect("corrupt archive");
    write_checksum_file(&release_dir, &archive_name);

    let output = installer_command(&temp, &release_dir, &install_dir)
        .output()
        .expect("run installer");

    assert!(!output.status.success());
    assert_old_binary_and_no_staging_files(&install_dir, &old_binary);
}

#[test]
fn installer_staging_failure_preserves_the_existing_binary() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    fs::create_dir_all(&install_dir).expect("mkdir install");
    let old_binary = install_old_binary(&install_dir);
    let release_dir =
        prepare_release_fixture(&temp, "#!/usr/bin/env bash\nprintf 'kidobo 9.8.7\\n'\n");
    write_executable(
        &temp.path().join("fake-bin/install"),
        "#!/usr/bin/env bash\nexit 41\n",
    );
    write_executable(
        &temp.path().join("fake-bin/sudo"),
        "#!/usr/bin/env bash\nexit 42\n",
    );

    let output = installer_command(&temp, &release_dir, &install_dir)
        .output()
        .expect("run installer");

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to stage kidobo for installation")
    );
    assert_old_binary_and_no_staging_files(&install_dir, &old_binary);
}

#[test]
fn installer_version_verification_failure_preserves_the_existing_binary() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    fs::create_dir_all(&install_dir).expect("mkdir install");
    let old_binary = install_old_binary(&install_dir);
    let release_dir =
        prepare_release_fixture(&temp, "#!/usr/bin/env bash\nprintf 'kidobo 1.0.0\\n'\n");

    let output = installer_command(&temp, &release_dir, &install_dir)
        .output()
        .expect("run installer");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unexpected version"));
    assert_old_binary_and_no_staging_files(&install_dir, &old_binary);
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
fn custom_root_init_uses_direct_path_without_sudo() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    let root = temp.path().join("root with spaces");
    let observed_root = temp.path().join("observed-root");
    let sudo_marker = temp.path().join("sudo-called");
    write_executable(
        &install_dir.join("kidobo"),
        "#!/usr/bin/env bash\nset -euo pipefail\n[[ \"${1:-}\" == \"init\" ]]\nprintf '%s' \"${KIDOBO_ROOT-}\" > \"${KIDOBO_TEST_OBSERVED_ROOT}\"\n",
    );
    let init_log = temp.path().join("init.log");

    let status = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             sudo() { : > \"$SUDO_MARKER\"; return 99; }; \
             run_init_after_install \"$INIT_LOG\"",
        )
        .env("INSTALLER", installer_path())
        .env("INIT_LOG", &init_log)
        .env("SUDO_MARKER", &sudo_marker)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .env("KIDOBO_ROOT", &root)
        .env("KIDOBO_TEST_OBSERVED_ROOT", &observed_root)
        .status()
        .expect("run bash");

    assert!(status.success());
    assert_eq!(
        read_to_string_with_limit(&observed_root, FIXTURE_FILE_READ_LIMIT),
        root.display().to_string()
    );
    assert!(!sudo_marker.exists());
}

#[test]
fn custom_root_init_preserves_exact_value_through_sudo_env() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    let root = temp.path().join("root with spaces");
    let observed_root = temp.path().join("observed-root");
    write_executable(
        &install_dir.join("kidobo"),
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"${KIDOBO_TEST_ELEVATED:-0}\" != \"1\" ]]; then exit 23; fi\n[[ \"${1:-}\" == \"init\" ]]\nprintf '%s' \"${KIDOBO_ROOT-}\" > \"${KIDOBO_TEST_OBSERVED_ROOT}\"\n",
    );
    let init_log = temp.path().join("init.log");

    let status = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             sudo() { env -i PATH=\"$PATH\" KIDOBO_TEST_ELEVATED=1 KIDOBO_TEST_OBSERVED_ROOT=\"$KIDOBO_TEST_OBSERVED_ROOT\" \"$@\"; }; \
             run_init_after_install \"$INIT_LOG\"",
        )
        .env("INSTALLER", installer_path())
        .env("INIT_LOG", &init_log)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .env("KIDOBO_ROOT", &root)
        .env("KIDOBO_TEST_OBSERVED_ROOT", &observed_root)
        .status()
        .expect("run bash");

    assert!(status.success());
    assert_eq!(
        read_to_string_with_limit(&observed_root, FIXTURE_FILE_READ_LIMIT),
        root.display().to_string()
    );
}

#[test]
fn custom_root_init_rejects_explicit_empty_value_before_execution() {
    let temp = TempDir::new().expect("tempdir");
    let install_dir = temp.path().join("bin");
    let marker = temp.path().join("target-called");
    write_executable(
        &install_dir.join("kidobo"),
        "#!/usr/bin/env bash\n: > \"${KIDOBO_TEST_MARKER}\"\n",
    );

    let status = Command::new("bash")
        .arg("-c")
        .arg("source \"$INSTALLER\"; run_init_after_install \"$INIT_LOG\"")
        .env("INSTALLER", installer_path())
        .env("INIT_LOG", temp.path().join("init.log"))
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .env("KIDOBO_ROOT", "")
        .env("KIDOBO_TEST_MARKER", &marker)
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
    assert!(!marker.exists());
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
fn uninstall_canonicalizes_scoped_root_without_touching_siblings() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let root_alias = root.join("unused").join("..");
    let sibling = temp.path().join("keep");
    let install_dir = temp.path().join("bin");
    let binary = install_dir.join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 0\n");
    for directory in ["config", "data", "cache", "systemd/system"] {
        fs::create_dir_all(root.join(directory)).expect("mkdir artifact");
    }
    fs::create_dir_all(&sibling).expect("mkdir sibling");
    fs::write(sibling.join("sentinel"), "preserve").expect("write sentinel");

    let status = Command::new("bash")
        .arg("-c")
        .arg("source \"$INSTALLER\"; run_flush_best_effort() { return 0; }; uninstall_artifacts")
        .env("INSTALLER", installer_path())
        .env("KIDOBO_ROOT", &root_alias)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .status()
        .expect("run bash");

    assert!(status.success());
    assert!(!binary.exists());
    assert!(!root.join("config").exists());
    assert!(!root.join("data").exists());
    assert!(!root.join("cache").exists());
    assert_eq!(
        read_to_string_with_limit(&sibling.join("sentinel"), FIXTURE_FILE_READ_LIMIT),
        "preserve"
    );
}

#[test]
fn uninstall_rejects_root_aliases_before_cleanup() {
    let temp = TempDir::new().expect("tempdir");
    let root_symlink = temp.path().join("root-alias");
    std::os::unix::fs::symlink("/", &root_symlink).expect("symlink to root");
    let cleanup_marker = temp.path().join("cleanup-started");

    let roots = [
        "/.".to_string(),
        "//".to_string(),
        "/tmp/..".to_string(),
        root_symlink.display().to_string(),
    ];

    for root in roots {
        let _remove_result = fs::remove_file(&cleanup_marker);
        let status = Command::new("bash")
            .arg("-c")
            .arg(
                "source \"$INSTALLER\"; \
                 run_flush_best_effort() { : > \"$CLEANUP_MARKER\"; return 0; }; \
                 remove_path() { : > \"$CLEANUP_MARKER\"; }; \
                 uninstall_artifacts",
            )
            .env("INSTALLER", installer_path())
            .env("CLEANUP_MARKER", &cleanup_marker)
            .env("KIDOBO_ROOT", &root)
            .env("KIDOBO_INSTALL_DIR", temp.path().join("bin"))
            .status()
            .expect("run bash");

        assert_eq!(status.code(), Some(1), "root alias was accepted: {root}");
        assert!(
            !cleanup_marker.exists(),
            "cleanup began for rejected root alias: {root}"
        );
    }
}

#[test]
fn uninstall_rejects_explicit_empty_root_before_cleanup() {
    let temp = TempDir::new().expect("tempdir");
    let cleanup_marker = temp.path().join("cleanup-started");

    let status = Command::new("bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             run_flush_best_effort() { : > \"$CLEANUP_MARKER\"; return 0; }; \
             remove_path() { : > \"$CLEANUP_MARKER\"; }; \
             uninstall_artifacts",
        )
        .env("INSTALLER", installer_path())
        .env("CLEANUP_MARKER", &cleanup_marker)
        .env("KIDOBO_ROOT", "")
        .env("KIDOBO_INSTALL_DIR", temp.path().join("bin"))
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
    assert!(!cleanup_marker.exists());
}

#[test]
fn uninstall_rejects_override_when_realpath_is_unavailable() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = temp.path().join("fake-bin");
    fs::create_dir_all(&fake_bin).expect("create fake bin");
    std::os::unix::fs::symlink("/usr/bin/rm", fake_bin.join("rm")).expect("link rm");
    let cleanup_marker = temp.path().join("cleanup-started");

    let status = Command::new("/bin/bash")
        .arg("-c")
        .arg(
            "source \"$INSTALLER\"; \
             run_flush_best_effort() { : > \"$CLEANUP_MARKER\"; return 0; }; \
             remove_path() { : > \"$CLEANUP_MARKER\"; }; \
             uninstall_artifacts",
        )
        .env("INSTALLER", installer_path())
        .env("CLEANUP_MARKER", &cleanup_marker)
        .env("KIDOBO_ROOT", temp.path().join("root"))
        .env("KIDOBO_INSTALL_DIR", temp.path().join("bin"))
        .env("PATH", &fake_bin)
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
    assert!(!cleanup_marker.exists());
}

#[test]
fn failed_config_aware_uninstall_attempts_default_cleanup_but_preserves_artifacts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let install_dir = temp.path().join("bin");
    let binary = install_dir.join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 1\n");
    for directory in ["config", "data", "cache", "systemd/system"] {
        fs::create_dir_all(root.join(directory)).expect("mkdir artifact");
    }
    for artifact in [
        "config/config.toml",
        "data/blocklist.txt",
        "cache/remote.cache",
        "systemd/system/kidobo-sync.service",
        "systemd/system/kidobo-sync.timer",
    ] {
        fs::write(root.join(artifact), "preserve").expect("write artifact");
    }
    let cleanup_log = temp.path().join("cleanup.log");
    let fake_bin = write_cleanup_fakes(&temp);

    let status = Command::new("bash")
        .arg("-c")
        .arg("source \"$INSTALLER\"; uninstall_artifacts")
        .env("INSTALLER", installer_path())
        .env("KIDOBO_ROOT", &root)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .env("KIDOBO_TEST_CLEANUP_LOG", &cleanup_log)
        .env("PATH", path_with_prefix(&fake_bin))
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
    let transcript = read_to_string_with_limit(&cleanup_log, FIXTURE_FILE_READ_LIMIT);
    for expected in [
        "iptables -w 5 -D INPUT -j kidobo-input-stage",
        "iptables -w 5 -D INPUT -j kidobo-input",
        "iptables -w 5 -F kidobo-input-stage",
        "iptables -w 5 -X kidobo-input-stage",
        "iptables -w 5 -F kidobo-input",
        "iptables -w 5 -X kidobo-input",
        "ip6tables -w 5 -D INPUT -j kidobo-input-stage",
        "ip6tables -w 5 -D INPUT -j kidobo-input",
        "ip6tables -w 5 -F kidobo-input-stage",
        "ip6tables -w 5 -X kidobo-input-stage",
        "ip6tables -w 5 -F kidobo-input",
        "ip6tables -w 5 -X kidobo-input",
        "ipset destroy kidobo",
        "ipset destroy kidobo-v6",
    ] {
        assert!(
            transcript.contains(expected),
            "missing `{expected}` in: {transcript}"
        );
    }
    assert!(binary.exists());
    assert!(root.join("config").exists());
    assert!(root.join("data").exists());
    assert!(root.join("cache").exists());
    assert!(root.join("systemd/system").exists());
    for artifact in [
        "config/config.toml",
        "data/blocklist.txt",
        "cache/remote.cache",
        "systemd/system/kidobo-sync.service",
        "systemd/system/kidobo-sync.timer",
    ] {
        assert!(root.join(artifact).exists(), "removed {artifact}");
    }
}

#[test]
fn uninstall_real_fallback_failure_preserves_all_runtime_artifacts() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    let install_dir = temp.path().join("bin");
    let binary = install_dir.join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 1\n");
    for directory in ["config", "data", "cache", "systemd/system"] {
        fs::create_dir_all(root.join(directory)).expect("mkdir artifact");
    }
    fs::write(root.join("config/config.toml"), "preserve").expect("write config");
    let cleanup_log = temp.path().join("cleanup.log");
    let fake_bin = write_cleanup_fakes(&temp);

    let status = Command::new("bash")
        .arg("-c")
        .arg("source \"$INSTALLER\"; uninstall_artifacts")
        .env("INSTALLER", installer_path())
        .env("KIDOBO_ROOT", &root)
        .env("KIDOBO_INSTALL_DIR", &install_dir)
        .env("KIDOBO_TEST_CLEANUP_LOG", &cleanup_log)
        .env("KIDOBO_TEST_FAIL_CLEANUP", "ip6tables")
        .env("PATH", path_with_prefix(&fake_bin))
        .status()
        .expect("run bash");

    assert_eq!(status.code(), Some(1));
    let transcript = read_to_string_with_limit(&cleanup_log, FIXTURE_FILE_READ_LIMIT);
    assert!(transcript.contains("iptables -w 5 -F kidobo-input"));
    assert!(transcript.contains("ip6tables -w 5 -F kidobo-input"));
    assert!(transcript.contains("ipset destroy kidobo"));
    assert!(transcript.contains("ipset destroy kidobo-v6"));
    assert!(binary.exists());
    assert!(root.join("config/config.toml").exists());
    assert!(root.join("data").exists());
    assert!(root.join("cache").exists());
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
