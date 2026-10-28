#![cfg(unix)]

#[path = "support/release_fixture.rs"]
mod release_fixture;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use release_fixture::{
    CommandFixture, FIXTURE_LOG_READ_LIMIT, RELEASE_TAG, RELEASE_VERSION,
    REPOSITORY_LOCAL_GIT_ENV_VARS, ReleaseFixture, assert_success, path_with_prefix,
    publisher_path, read_to_string_with_limit, run_git_at, run_with_confirmation, write_executable,
};
use tempfile::TempDir;

const PRERELEASE_VERSION: &str = "0.12.0-rc.1";
const PRERELEASE_TAG: &str = "v0.12.0-rc.1";

fn compatibility_script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-release-compat.sh")
}

impl ReleaseFixture {
    fn git_success(&self, args: &[&str], context: &str) {
        assert_success(&self.git(args), context);
    }

    fn branch(&self) -> String {
        let output = self.git(&["branch", "--show-current"]);
        assert_success(&output, "read branch");
        String::from_utf8(output.stdout)
            .expect("UTF-8 branch")
            .trim()
            .to_string()
    }

    fn run_publisher(&self, confirmation: &str) -> Output {
        self.run_publisher_for(RELEASE_VERSION, confirmation)
    }

    fn run_publisher_for(&self, version: &str, confirmation: &str) -> Output {
        run_with_confirmation(&mut self.publisher_command_for(version), confirmation)
    }

    fn run_after_validation<F>(&self, action: F) -> Output
    where
        F: FnOnce(),
    {
        let ready = self
            .repo
            .parent()
            .expect("fixture parent")
            .join("validation-ready");
        let mut child = self
            .publisher_command()
            .env("KIDOBO_TEST_READY_MARKER", &ready)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn publisher");
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "publisher did not reach the final validation gate"
            );
            thread::sleep(Duration::from_millis(10));
        }
        action();
        child
            .stdin
            .take()
            .expect("publisher stdin")
            .write_all(b"y\n")
            .expect("confirm release");
        child.wait_with_output().expect("wait for publisher")
    }

    fn advance_origin_main(&self, clone_name: &str) {
        let clone = self.repo.parent().expect("fixture parent").join(clone_name);
        assert_success(
            &run_git_at(
                self.repo.parent().expect("fixture parent"),
                &[
                    "clone",
                    "--quiet",
                    "--branch",
                    "main",
                    self.remote.to_str().expect("remote path"),
                    clone.to_str().expect("clone path"),
                ],
            ),
            "clone origin",
        );
        assert_success(
            &run_git_at(&clone, &["config", "user.name", "Remote Test"]),
            "configure clone name",
        );
        assert_success(
            &run_git_at(&clone, &["config", "user.email", "remote@example.test"]),
            "configure clone email",
        );
        fs::write(clone.join("remote-change"), clone_name).expect("write remote change");
        assert_success(&run_git_at(&clone, &["add", "."]), "stage remote change");
        assert_success(
            &run_git_at(&clone, &["commit", "-m", "Advance remote"]),
            "commit remote change",
        );
        assert_success(
            &run_git_at(&clone, &["push", "origin", "main"]),
            "push remote change",
        );
    }
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
fn release_compatibility_script_has_valid_bash_syntax() {
    let status = Command::new("bash")
        .arg("-n")
        .arg(compatibility_script_path())
        .status()
        .expect("check compatibility script syntax");
    assert!(status.success());
}

#[test]
fn release_compatibility_gate_checks_both_container_baselines() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = temp.path().join("fake-bin");
    let docker_log = temp.path().join("docker.log");
    let binary = temp.path().join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 0\n");
    write_executable(
        &fake_bin.join("readelf"),
        "#!/usr/bin/env bash\nset -euo pipefail\nexit 0\n",
    );
    write_executable(
        &fake_bin.join("docker"),
        r#"#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "${KIDOBO_TEST_DOCKER_LOG}"
if [[ " $* " == *" lookup 203.0.113.7 --format tsv "* ]]; then
  printf '203.0.113.7\tinternal:blocklist\t203.0.113.0/24\n'
fi
"#,
    );

    let output = Command::new(compatibility_script_path())
        .arg(&binary)
        .env("PATH", path_with_prefix(&fake_bin))
        .env("KIDOBO_TEST_DOCKER_LOG", &docker_log)
        .output()
        .expect("run compatibility gate");

    assert_success(&output, "release compatibility gate");
    let log = read_to_string_with_limit(&docker_log, FIXTURE_LOG_READ_LIMIT);
    assert_eq!(log.lines().count(), 6);
    assert!(log.contains("debian:11-slim"));
    assert!(log.contains("alpine:3.22"));
    assert!(log.contains("--network none"));
    assert!(log.contains("--read-only"));
}

#[test]
fn release_compatibility_gate_rejects_an_elf_interpreter() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = temp.path().join("fake-bin");
    let binary = temp.path().join("kidobo");
    write_executable(&binary, "#!/usr/bin/env bash\nexit 0\n");
    write_executable(
        &fake_bin.join("readelf"),
        "#!/usr/bin/env bash\nset -euo pipefail\nif [[ \"$1\" == \"-l\" ]]; then echo 'Requesting program interpreter'; fi\n",
    );
    write_executable(&fake_bin.join("docker"), "#!/usr/bin/env bash\nexit 99\n");

    let output = Command::new(compatibility_script_path())
        .arg(&binary)
        .env("PATH", path_with_prefix(&fake_bin))
        .output()
        .expect("run compatibility gate");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ELF interpreter"));
}

#[test]
fn publisher_fixture_clears_repository_local_git_environment() {
    let fixture = ReleaseFixture::new();
    let command = fixture.publisher_command();
    let environment = command.get_envs().collect::<Vec<_>>();

    for variable in REPOSITORY_LOCAL_GIT_ENV_VARS {
        assert!(
            environment
                .iter()
                .any(|(key, value)| { key == &std::ffi::OsStr::new(variable) && value.is_none() }),
            "publisher command did not clear {variable}"
        );
    }
}

#[test]
fn publisher_requires_exactly_one_version() {
    for args in [vec![], vec![RELEASE_VERSION, RELEASE_VERSION]] {
        let output = Command::new(publisher_path())
            .args(&args)
            .output()
            .expect("reject missing or extra arguments");
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("Usage:"));
    }
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

#[test]
fn publisher_requires_github_cli() {
    let output = Command::new("/usr/bin/bash")
        .arg(publisher_path())
        .arg(RELEASE_VERSION)
        .env("PATH", "/missing")
        .output()
        .expect("run publisher without GitHub CLI");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing required command: gh"));
}

#[test]
fn publisher_requires_github_authentication_before_repository_changes() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_FAIL_GH_AUTH", "1")
        .output()
        .expect("run publisher without GitHub authentication");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("gh auth login"));
    assert!(!fixture.git_log.exists());
}

#[test]
fn publisher_rejects_a_github_repository_that_does_not_match_origin() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_GITHUB_REPOSITORY", "someone/else")
        .output()
        .expect("run publisher with mismatched GitHub repository");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match origin"));
    assert!(!fixture.tag_exists());
}

#[test]
fn publisher_rejects_non_x86_64_hosts_before_repository_changes() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_UNAME_MACHINE", "aarch64")
        .output()
        .expect("run publisher on unsupported architecture");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Linux x86_64 host"));
    assert!(!fixture.git_log.exists());
}

#[test]
fn publisher_rejects_a_dirty_worktree_before_switching_or_fetching() {
    let fixture = ReleaseFixture::new();
    fs::write(fixture.repo.join("dirty"), "dirty").expect("dirty worktree");

    let output = fixture.run_publisher("n\n");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("requires a clean worktree"));
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    assert!(!log.contains("switch main"));
    assert!(!log.contains("fetch --quiet"));
}

#[test]
fn publisher_rejects_an_existing_github_release() {
    let fixture = ReleaseFixture::new();
    let output = fixture
        .publisher_command()
        .env("KIDOBO_TEST_EXISTING_RELEASE", "1")
        .output()
        .expect("run publisher with existing GitHub release");

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("GitHub release already exists"));
    assert!(!fixture.tag_exists());
}

#[test]
fn publisher_cancel_restores_the_original_branch_and_leaves_no_release_state() {
    let fixture = ReleaseFixture::new();
    fixture.git_success(&["switch", "-c", "feature"], "create feature branch");
    let original_head = fixture.head();

    let output = fixture.run_publisher("n\n");

    assert!(output.status.success());
    assert_eq!(fixture.branch(), "feature");
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
    assert!(!fixture.artifact_root(RELEASE_TAG).exists());
    assert_eq!(fixture.git(&["status", "--porcelain"]).stdout.len(), 0);
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    assert!(log.contains("switch main"));
    assert!(log.contains("switch --quiet feature"));
}

#[test]
fn publisher_rejects_behind_and_diverged_main() {
    for scenario in ["behind", "diverged"] {
        let fixture = ReleaseFixture::new();
        let base = fixture.head();
        fs::write(fixture.repo.join("remote-source"), scenario).expect("write remote source");
        fixture.git_success(&["add", "."], "stage remote source");
        fixture.git_success(&["commit", "-m", "Remote source"], "commit remote source");
        fixture.git_success(&["push", "origin", "main"], "push remote source");
        fixture.git_success(&["reset", "--hard", &base], "reset local main");
        if scenario == "diverged" {
            fs::write(fixture.repo.join("local-source"), scenario).expect("write local source");
            fixture.git_success(&["add", "."], "stage local source");
            fixture.git_success(&["commit", "-m", "Local source"], "commit local source");
        }

        let output = fixture.run_publisher("n\n");

        assert_eq!(
            output.status.code(),
            Some(1),
            "{scenario} main was accepted"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("must not be behind or diverged"));
        assert!(!fixture.tag_exists());
    }
}

#[test]
fn publisher_rejects_existing_local_and_remote_tags() {
    for location in ["local", "remote"] {
        let fixture = ReleaseFixture::new();
        fixture.git_success(&["tag", RELEASE_TAG], "create release tag");
        if location == "remote" {
            fixture.git_success(&["push", "origin", RELEASE_TAG], "push release tag");
            fixture.git_success(&["tag", "--delete", RELEASE_TAG], "delete local tag");
        }

        let output = fixture.run_publisher("n\n");

        assert_eq!(output.status.code(), Some(1), "{location} tag was accepted");
        assert!(String::from_utf8_lossy(&output.stderr).contains("tag already exists"));
    }
}

#[test]
fn publisher_rolls_back_the_tag_when_original_worktree_changes() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();
    let output = fixture.run_after_validation(|| {
        fs::write(fixture.repo.join("external-change"), "preserve").expect("external change");
    });

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("worktree changed"));
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
    assert!(fixture.repo.join("external-change").exists());
}

#[test]
fn publisher_rolls_back_the_tag_when_origin_changes_during_validation() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();
    let output = fixture.run_after_validation(|| fixture.advance_origin_main("late-origin"));

    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("origin/main changed"));
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());
}

#[test]
fn publisher_packages_the_validated_candidate_from_each_target_directory() {
    for target_directory in [
        None,
        Some("target/custom"),
        Some("target/custom with spaces"),
        Some("absolute"),
    ] {
        let fixture = ReleaseFixture::new();
        let mut command = fixture.publisher_command();
        if let Some(directory) = target_directory {
            let path = if directory == "absolute" {
                fixture.temp.path().join("absolute build with spaces")
            } else {
                PathBuf::from(directory)
            };
            command.env("CARGO_TARGET_DIR", path);
        }
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn fixture publisher");
        child
            .stdin
            .take()
            .expect("stdin")
            .write_all(b"y\n")
            .expect("confirm fixture publication");
        let output = child.wait_with_output().expect("wait publisher");
        assert_success(&output, &format!("target directory {target_directory:?}"));
        let archive = fixture
            .artifact_root(RELEASE_TAG)
            .join(format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz"));
        let packaged = Command::new("tar")
            .arg("-xOzf")
            .arg(archive)
            .arg(format!("kidobo-{RELEASE_TAG}-linux-x86_64/kidobo"))
            .output()
            .expect("read packaged binary");
        assert_success(&packaged, "extract candidate");
        assert_eq!(
            packaged.stdout,
            read_to_string_with_limit(
                &fixture.gh_release_dir.join("validated-candidate"),
                FIXTURE_LOG_READ_LIMIT,
            )
            .into_bytes()
        );
    }
}

#[test]
fn publisher_atomically_pushes_then_verifies_and_publishes_local_artifacts() {
    let fixture = ReleaseFixture::new();
    let original_head = fixture.head();

    let output = fixture.run_publisher("y\n");

    assert_success(&output, "publish fixture release");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("is ready to publish"));
    let release_head = fixture.head();
    assert_ne!(release_head, original_head);
    assert!(fixture.tag_exists());
    assert!(fixture.remote_tag_exists(RELEASE_TAG));
    let log = read_to_string_with_limit(&fixture.git_log, FIXTURE_LOG_READ_LIMIT);
    let expected_push = format!(
        "-c core.hooksPath=/dev/null push --atomic origin {release_head}:refs/heads/main refs/tags/{RELEASE_TAG}:refs/tags/{RELEASE_TAG}"
    );
    assert!(
        log.lines().any(|line| line == expected_push),
        "missing exact atomic push `{expected_push}` in: {log}"
    );
    let remote_main = run_git_at(&fixture.remote, &["rev-parse", "refs/heads/main"]);
    assert_success(&remote_main, "read remote main");
    assert_eq!(
        String::from_utf8(remote_main.stdout)
            .expect("UTF-8 remote main")
            .trim(),
        release_head
    );

    let artifact_root = fixture.artifact_root(RELEASE_TAG);
    let archive_name = format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz");
    let archive = artifact_root.join(&archive_name);
    assert!(archive.is_file());
    assert!(artifact_root.join("SHA256SUMS").is_file());
    assert!(artifact_root.join("release-notes.md").is_file());
    let checksum = Command::new("sha256sum")
        .args(["--check", "SHA256SUMS"])
        .current_dir(&artifact_root)
        .output()
        .expect("verify retained release checksum");
    assert_success(&checksum, "verify retained release checksum");
    let listing = Command::new("tar")
        .args(["-tzf", archive.to_str().expect("archive path")])
        .output()
        .expect("list retained release archive");
    assert_success(&listing, "list retained release archive");
    let mut entries = String::from_utf8(listing.stdout)
        .expect("UTF-8 archive listing")
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(
        entries,
        [
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/"),
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/LICENSE"),
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/README.md"),
            format!("kidobo-{RELEASE_TAG}-linux-x86_64/kidobo"),
        ]
    );

    let gh_log = read_to_string_with_limit(&fixture.gh_log, FIXTURE_LOG_READ_LIMIT);
    let create = gh_log
        .lines()
        .find(|line| line.starts_with("release create "))
        .expect("draft release creation");
    assert!(create.contains("--draft"));
    assert!(create.contains("--verify-tag"));
    assert!(!create.contains("--prerelease"));
    let edit = gh_log
        .lines()
        .find(|line| line.starts_with("release edit "))
        .expect("release publication");
    assert!(edit.contains("--draft=false"));
    assert!(edit.contains("--latest"));

    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    let exercise_position = events
        .find("just exercise-release\n")
        .expect("release binary exercise event");
    let compatibility_position = events
        .find("just release-compat\n")
        .expect("release compatibility event");
    let push_position = events
        .find("git -c core.hooksPath=/dev/null push --atomic ")
        .expect("atomic push event");
    let create_position = events
        .find("gh release create ")
        .expect("draft creation event");
    let download_position = events
        .find("gh release download ")
        .expect("asset download event");
    let edit_position = events
        .find("gh release edit ")
        .expect("draft publication event");
    assert!(exercise_position < compatibility_position);
    assert!(compatibility_position < push_position);
    assert!(push_position < create_position);
    assert!(create_position < download_position);
    assert!(download_position < edit_position);
    assert!(fixture.gh_release_dir.join("published").is_file());
}

#[test]
fn publisher_marks_suffixed_versions_as_prereleases_without_changing_latest() {
    let fixture = ReleaseFixture::new();

    let output = fixture.run_publisher_for(PRERELEASE_VERSION, "y\n");

    assert!(
        output.status.success(),
        "publisher failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(fixture.local_tag_exists(PRERELEASE_TAG));
    assert!(fixture.remote_tag_exists(PRERELEASE_TAG));
    let gh_log = read_to_string_with_limit(&fixture.gh_log, FIXTURE_LOG_READ_LIMIT);
    let create = gh_log
        .lines()
        .find(|line| line.starts_with("release create "))
        .expect("prerelease draft creation");
    assert!(create.contains("--prerelease"));
    let edit = gh_log
        .lines()
        .find(|line| line.starts_with("release edit "))
        .expect("prerelease publication");
    assert!(edit.contains("--draft=false"));
    assert!(!edit.contains("--latest"));
}

#[test]
fn publisher_retains_recovery_state_after_post_push_failures() {
    for (failure_variable, failure_value, expected_status) in [
        ("KIDOBO_TEST_FAIL_GH_CREATE", "1", 41),
        ("KIDOBO_TEST_FAIL_GH_DOWNLOAD", "1", 42),
        ("KIDOBO_TEST_CORRUPT_DOWNLOAD", "1", 1),
        ("KIDOBO_TEST_BINARY_VERSION", "9.9.9", 1),
        ("KIDOBO_TEST_FAIL_GH_EDIT", "1", 43),
    ] {
        let fixture = ReleaseFixture::new();
        let output = fixture
            .publisher_command()
            .env(failure_variable, failure_value)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                child
                    .stdin
                    .take()
                    .expect("publisher stdin")
                    .write_all(b"y\n")?;
                child.wait_with_output()
            })
            .expect("run publisher with post-push failure");

        assert_eq!(
            output.status.code(),
            Some(expected_status),
            "unexpected status for {failure_variable}: stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(fixture.tag_exists());
        assert!(fixture.remote_tag_exists(RELEASE_TAG));
        assert!(fixture.artifact_root(RELEASE_TAG).is_dir());
        assert!(!fixture.gh_release_dir.join("published").exists());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("Local recovery artifacts were retained"));
        assert!(stderr.contains("gh release upload"));
        assert!(stderr.contains("gh release download"));
        assert!(stderr.contains("gh release edit"));

        let gh_log = read_to_string_with_limit(&fixture.gh_log, FIXTURE_LOG_READ_LIMIT);
        if failure_variable != "KIDOBO_TEST_FAIL_GH_EDIT" {
            assert!(
                !gh_log.lines().any(|line| line.starts_with("release edit ")),
                "failed validation must not attempt publication: {failure_variable}"
            );
        }
    }
}

#[test]
fn publisher_preserves_preexisting_artifact_directories() {
    let fixture = ReleaseFixture::new();
    let artifact_root = fixture.artifact_root(RELEASE_TAG);
    fs::create_dir_all(&artifact_root).expect("create prior artifacts");
    let prior = artifact_root.join("prior-candidate");
    fs::write(&prior, "retained evidence").expect("write prior artifact");
    let output = fixture
        .publisher_command()
        .output()
        .expect("reject existing artifacts");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("preserve it elsewhere"));
    assert_eq!(
        read_to_string_with_limit(&prior, FIXTURE_LOG_READ_LIMIT),
        "retained evidence"
    );
    assert!(!fixture.tag_exists());
}

#[test]
fn publisher_rejects_unknown_options_before_running_tools() {
    let fixture = CommandFixture::new();
    let output = fixture
        .publisher_command()
        .arg("--unknown-option")
        .output()
        .expect("reject misspelled option");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown option: --unknown-option"));
    assert!(!fixture.event_log.exists());
}

#[test]
fn publisher_runs_explicit_gates_without_repeating_git_hooks() {
    let fixture = ReleaseFixture::new();
    let hooks = fixture.temp.path().join("hooks");
    for hook in ["pre-commit", "pre-push"] {
        write_executable(&hooks.join(hook), "#!/bin/bash\nexit 91\n");
    }
    assert_success(
        &run_git_at(
            &fixture.repo,
            &[
                "config",
                "core.hooksPath",
                hooks.to_str().expect("hook path"),
            ],
        ),
        "configure hooks that reject unvalidated ordinary Git operations",
    );
    assert_success(
        &fixture.run_publisher("y\n"),
        "publish already validated candidate",
    );
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    for gate in [
        "_release-ci-without-e2e",
        "release-notes-check",
        "_release-coverage-without-e2e",
        "_release-rustdoc-without-e2e",
        "exercise-release",
        "release-compat",
    ] {
        assert_eq!(
            events.matches(&format!("just {gate}\n")).count(),
            1,
            "{gate}"
        );
    }
    assert_eq!(
        run_git_at(
            &fixture.repo,
            &["commit", "--allow-empty", "-m", "ordinary commit"]
        )
        .status
        .code(),
        Some(1)
    );
}

#[test]
fn publisher_rejects_candidate_changes_after_validation() {
    let fixture = ReleaseFixture::new();
    let output = fixture.run_after_validation(|| {
        let worktrees = run_git_at(&fixture.repo, &["worktree", "list", "--porcelain"]);
        assert_success(&worktrees, "list candidate worktree");
        let listing = String::from_utf8(worktrees.stdout).expect("worktree paths");
        let candidate = listing
            .lines()
            .filter_map(|line| line.strip_prefix("worktree "))
            .map(PathBuf::from)
            .find(|path| path != &fixture.repo)
            .expect("candidate worktree");
        fs::write(candidate.join("LICENSE"), "changed after validation\n")
            .expect("change candidate");
        assert_success(
            &run_git_at(&candidate, &["add", "LICENSE"]),
            "restage changed candidate",
        );
    });
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("validation produced uncommitted changes")
            || stderr.contains("validated candidate changed"),
        "{stderr}"
    );
    assert!(!fixture.tag_exists());
    assert!(!fixture.remote_tag_exists(RELEASE_TAG));
}

#[test]
fn publisher_rejects_artifact_changes_while_awaiting_confirmation() {
    for name in [
        format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz"),
        "SHA256SUMS".to_owned(),
        "release-notes.md".to_owned(),
    ] {
        let fixture = ReleaseFixture::new();
        let output = fixture.run_after_validation(|| {
            let path = fixture.artifact_root(RELEASE_TAG).join(&name);
            fs::OpenOptions::new()
                .append(true)
                .open(path)
                .expect("open validated artifact")
                .write_all(b"changed after validation\n")
                .expect("change validated artifact");
        });
        assert_eq!(output.status.code(), Some(1), "{name}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("validated candidate changed"),
            "{name}"
        );
        assert!(!fixture.tag_exists());
        assert!(!fixture.remote_tag_exists(RELEASE_TAG));
        assert!(!fixture.artifact_root(RELEASE_TAG).exists());
    }
}
