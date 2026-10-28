#![cfg(unix)]

#[path = "support/release_fixture.rs"]
mod release_fixture;

use std::fs;
use std::path::Path;
use std::process::Command;

use release_fixture::{
    CommandFixture, FIXTURE_LOG_READ_LIMIT, RELEASE_TAG, RELEASE_VERSION, ReleaseFixture,
    assert_success, path_with_prefix, read_to_string_with_limit, run_with_confirmation,
    write_executable,
};

fn e2e_fixture() -> ReleaseFixture {
    let fixture = ReleaseFixture::new();
    for tool in ["incus", "genisoimage"] {
        write_executable(&fixture.fake_bin.join(tool), "#!/bin/bash\nexit 0\n");
    }
    fs::rename(
        fixture.fake_bin.join("just"),
        fixture.fake_bin.join("just-base"),
    )
    .expect("retain neutral release recipes");
    write_executable(
        &fixture.fake_bin.join("just"),
        r#"#!/usr/bin/env bash
set -euo pipefail
"${0%/*}/just-base" "$@"
if [[ "$1" == "e2e-artifact" ]]; then
  [[ "${KIDOBO_E2E_RESULTS_DIR}" == "${KIDOBO_TEST_REPO_ROOT}/target/e2e" ]] || exit 46
  mkdir -p "${KIDOBO_E2E_RESULTS_DIR}"
  cp "$2" "${KIDOBO_E2E_RESULTS_DIR}/frozen-candidate.tar.gz"
  if [[ "${KIDOBO_TEST_FAIL_E2E:-0}" == "1" ]]; then exit 45; fi
  if [[ "${KIDOBO_TEST_MUTATE_ARCHIVE:-0}" == "1" ]]; then printf corrupt >> "$2"; fi
fi
"#,
    );
    fixture
}

fn publisher_command(fixture: &ReleaseFixture) -> Command {
    fixture.command_with_options(RELEASE_VERSION, &[])
}

#[test]
fn distro_gate_failure_or_artifact_changes_prevent_publication() {
    for variable in ["KIDOBO_TEST_FAIL_E2E", "KIDOBO_TEST_MUTATE_ARCHIVE"] {
        let fixture = e2e_fixture();
        let output = publisher_command(&fixture)
            .env(variable, "1")
            .output()
            .expect("run failing distro gate");
        assert!(
            !output.status.success(),
            "{variable} must block publication"
        );
        assert!(!fixture.tag_exists());
        assert!(!fixture.artifact_root(RELEASE_TAG).exists());
        assert!(
            fixture
                .repo
                .join("target/e2e/frozen-candidate.tar.gz")
                .is_file()
        );
        let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
        assert!(events.contains("just e2e-artifact "));
        assert!(!events.contains("git -c core.hooksPath=/dev/null push --atomic "));
        assert!(!events.contains("gh release create "));
    }
}

#[test]
fn publisher_reruns_all_gates_after_a_failed_matrix() {
    let fixture = e2e_fixture();
    let original_head = fixture.head();
    let first = publisher_command(&fixture)
        .env("KIDOBO_TEST_FAIL_E2E", "1")
        .output()
        .expect("fail the first matrix");
    assert_eq!(first.status.code(), Some(45));
    assert!(!fixture.artifact_root(RELEASE_TAG).exists());
    assert!(
        fixture
            .repo
            .join("target/e2e/frozen-candidate.tar.gz")
            .is_file()
    );
    assert_eq!(fixture.head(), original_head);
    assert!(!fixture.tag_exists());

    let second = run_with_confirmation(&mut publisher_command(&fixture), "y\n");
    assert_success(&second, "publish a fresh candidate");
    let stdout = String::from_utf8_lossy(&second.stdout);
    assert!(stdout.contains("running required distro lifecycle matrix"));
    assert!(stdout.contains("PASSED (required targets; advisory coverage separate)"));
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    for gate in [
        "ci",
        "coverage",
        "release-notes-check",
        "rustdoc",
        "exercise-release",
        "release-compat",
    ] {
        assert_eq!(
            events.matches(&format!("just {gate}\n")).count(),
            2,
            "{gate}"
        );
    }
    assert_eq!(
        events
            .lines()
            .filter(|line| line.starts_with("just e2e-artifact "))
            .count(),
        2
    );
    assert!(
        !fixture
            .artifact_root(RELEASE_TAG)
            .join("candidate.txt")
            .exists()
    );
    let compatibility = events
        .rfind("just release-compat\n")
        .expect("compatibility gate");
    let matrix = events
        .rfind("just e2e-artifact ")
        .expect("required matrix gate");
    let push = events
        .find("git -c core.hooksPath=/dev/null push --atomic ")
        .expect("atomic push");
    assert!(compatibility < matrix && matrix < push);
    assert!(fixture.gh_release_dir.join("published").is_file());
}

#[test]
fn publisher_rejects_removed_options_before_tools() {
    for options in [
        vec!["--resume-e2e", "run-123-456"],
        vec!["--refresh-e2e-images"],
        vec!["--skip-e2e", "--resume-e2e", "run-123-456"],
        vec!["--skip-e2e", "--skip-e2e"],
        vec!["--skip-e2e", "extra"],
    ] {
        let fixture = CommandFixture::new();
        let output = fixture
            .publisher_command()
            .args(&options)
            .output()
            .expect("reject removed options");
        assert_eq!(output.status.code(), Some(2), "{options:?}");
        assert!(!fixture.event_log.exists());
    }
}

#[test]
fn publisher_can_skip_e2e_without_vm_tools_and_keeps_other_gates() {
    let fixture = e2e_fixture();
    for tool in [
        "incus",
        "tmux",
        "genisoimage",
        "mkisofs",
        "curl",
        "gpg",
        "qemu-img",
    ] {
        write_executable(
            &fixture.fake_bin.join(tool),
            "#!/bin/bash\nprintf 'unexpected E2E tool: %s\\n' \"$0\" >> \"$KIDOBO_TEST_EVENT_LOG\"\nexit 99\n",
        );
    }
    let no_vm_tools = fixture.temp.path().join("no-vm-tools.sh");
    fs::write(
        &no_vm_tools,
        r#"
command() {
  if [[ "$1" == -v ]]; then
    case "$2" in incus|tmux|genisoimage|mkisofs|curl|gpg|qemu-img) return 1 ;; esac
  fi
  builtin command "$@"
}
"#,
    )
    .expect("hide VM tools independently of the host PATH");
    let default = publisher_command(&fixture)
        .env("BASH_ENV", &no_vm_tools)
        .output()
        .expect("check default VM prerequisites");
    assert_eq!(default.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&default.stderr).contains("missing required command: incus"));

    let output = run_with_confirmation(
        fixture
            .publisher_command()
            .env("BASH_ENV", &no_vm_tools)
            .env("KIDOBO_TEST_FAIL_E2E", "1"),
        "y\n",
    );
    assert_success(
        &output,
        "publish without VM prerequisites or matrix execution",
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let notice =
        "E2E validation skipped (--skip-e2e): harness checks, image operations, and VM matrix";
    let first_notice = stdout.find(notice).expect("initial skipped-gate notice");
    assert!(first_notice < stdout.find("running local CI").expect("local CI"));
    let last_notice = stdout
        .rfind(notice)
        .expect("confirmation skipped-gate notice");
    assert!(
        last_notice
            > stdout
                .find("is ready to publish")
                .expect("publication review")
    );
    let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
    assert!(!events.contains("just e2e-artifact "));
    assert!(!events.contains("unexpected E2E tool:"));
    for gate in ["ci", "coverage", "rustdoc"] {
        assert!(!events.contains(&format!("just {gate}\n")));
    }
    for gate in [
        "_release-ci-without-e2e",
        "release-notes-check",
        "_release-coverage-without-e2e",
        "_release-rustdoc-without-e2e",
        "exercise-release",
        "release-compat",
    ] {
        assert!(events.contains(&format!("just {gate}\n")), "missing {gate}");
    }
    assert!(events.contains("gh release download "));
    assert!(fixture.gh_release_dir.join("published").exists());
}

#[test]
fn skipping_e2e_still_blocks_publication_on_other_gate_failures() {
    for gate in [
        "_release-ci-without-e2e",
        "_release-coverage-without-e2e",
        "_release-rustdoc-without-e2e",
        "release-notes-check",
        "exercise-release",
        "release-compat",
    ] {
        let fixture = e2e_fixture();
        let output = fixture
            .publisher_command()
            .env("KIDOBO_TEST_FAIL_GATE", gate)
            .output()
            .expect("exercise retained gate failure");
        assert_eq!(output.status.code(), Some(44), "{gate}");
        assert!(!fixture.tag_exists());
        assert!(!fixture.remote_tag_exists(RELEASE_TAG));
        let events = read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT);
        assert!(!events.contains("git -c core.hooksPath=/dev/null push --atomic "));
        assert!(!events.contains("gh release create "));
    }
}

#[test]
fn candidate_recipe_runs_an_existing_archive_without_building_or_packaging() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        "#!/bin/bash\n[[ \"$1\" == run ]] || exit 91\nprintf '%s\\n' \"$@\"\n",
    );
    write_executable(
        &fixture.repo.join("scripts/package-release.sh"),
        "#!/bin/bash\nprintf unexpected-package > \"$KIDOBO_TEST_EVENT_LOG\"\nexit 92\n",
    );
    for options in [
        vec![
            "--archive".to_owned(),
            "/tmp/existing candidate.tar.gz".to_owned(),
            "--tag".to_owned(),
            RELEASE_TAG.to_owned(),
        ],
        vec![
            "--archive=/tmp/existing candidate.tar.gz".to_owned(),
            format!("--tag={RELEASE_TAG}"),
        ],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .arg("_e2e")
            .args(&options)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .env("KIDOBO_TEST_EVENT_LOG", &fixture.event_log)
            .output()
            .expect("forward an existing archive without a build");
        assert_success(&output, "run the prebuilt candidate recipe");
        assert_eq!(
            String::from_utf8(output.stdout).expect("UTF-8 candidate arguments"),
            format!(
                "run\n--locked\n-p\nkidobo-e2e\n--\nrun\n{}\n",
                options.join("\n")
            )
        );
        assert!(
            !fixture.event_log.exists(),
            "prebuilt archives must not be repackaged"
        );
    }
}

#[test]
fn candidate_recipe_still_builds_and_packages_when_no_archive_is_supplied() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        r#"#!/bin/bash
set -euo pipefail
printf 'cargo %s\n' "$1" >> "$KIDOBO_TEST_EVENT_LOG"
case "$1" in
  build)
    binary="$CARGO_TARGET_DIR/x86_64-unknown-linux-musl/release/kidobo"
    mkdir -p "${binary%/*}"
    printf '#!/bin/bash\nprintf '\''kidobo %s\\n'\''\n' "$KIDOBO_TEST_BINARY_VERSION" > "$binary"
    chmod 0755 "$binary"
    ;;
  run) printf '%s\n' "$@" ;;
  *) exit 91 ;;
esac
"#,
    );
    write_executable(
        &fixture.repo.join("scripts/package-release.sh"),
        r#"#!/bin/bash
set -euo pipefail
[[ -x "$1" && "$2" == "v$KIDOBO_TEST_BINARY_VERSION" && -d "$3" ]]
printf 'package %s\n' "$2" >> "$KIDOBO_TEST_EVENT_LOG"
: > "$3/kidobo-$2-linux-x86_64.tar.gz"
"#,
    );
    let output = Command::new("just")
        .arg("--justfile")
        .arg(&justfile)
        .args(["_e2e", "--keep-failed"])
        .env("PATH", path_with_prefix(&fixture.fake_bin))
        .env("CARGO_TARGET_DIR", fixture.repo.join("custom build target"))
        .env("KIDOBO_TEST_EVENT_LOG", &fixture.event_log)
        .env("KIDOBO_TEST_BINARY_VERSION", RELEASE_VERSION)
        .output()
        .expect("build and package a candidate with inert tools");
    assert_success(&output, "build the normal candidate recipe");
    assert_eq!(
        read_to_string_with_limit(&fixture.event_log, FIXTURE_LOG_READ_LIMIT),
        format!("cargo build\npackage {RELEASE_TAG}\ncargo run\n")
    );
    let arguments = String::from_utf8(output.stdout).expect("UTF-8 candidate arguments");
    let arguments = arguments.lines().collect::<Vec<_>>();
    let archive = arguments
        .windows(2)
        .find(|pair| pair[0] == "--archive")
        .expect("packaged archive argument")[1];
    assert!(fixture.repo.join(archive).is_file());
    assert!(archive.ends_with(&format!("kidobo-{RELEASE_TAG}-linux-x86_64.tar.gz")));
    assert_eq!(
        &arguments[arguments.len() - 3..],
        &["--tag", RELEASE_TAG, "--keep-failed"]
    );
    assert!(!arguments.contains(&"--required-only"));
}

#[test]
fn publication_recipe_forwards_the_skip_option_as_an_argument() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipes into isolated repository");
    write_executable(
        &fixture.repo.join("scripts/publish-release.sh"),
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n",
    );
    let output = Command::new("just")
        .arg("--justfile")
        .arg(&justfile)
        .args(["publish-release", RELEASE_VERSION, "--skip-e2e"])
        .output()
        .expect("exercise recipe with an inert publisher");
    assert_success(&output, "forward publisher arguments");
    assert_eq!(
        String::from_utf8(output.stdout).expect("forwarded arguments"),
        format!("{RELEASE_VERSION}\n--skip-e2e\n")
    );
}

#[test]
fn artifact_recipe_preserves_arguments_and_rejects_extra_options() {
    let fixture = CommandFixture::new();
    let justfile = fixture.repo.join("Justfile");
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("Justfile"),
        &justfile,
    )
    .expect("copy recipe into isolated repository");
    write_executable(
        &fixture.fake_bin.join("cargo"),
        "#!/bin/bash\nprintf '%s\\n' \"$@\"\n",
    );
    let output = Command::new("just")
        .arg("--justfile")
        .arg(&justfile)
        .env("PATH", path_with_prefix(&fixture.fake_bin))
        .args([
            "e2e-artifact",
            "/tmp/candidate with spaces.tar.gz",
            RELEASE_TAG,
        ])
        .output()
        .expect("forward exact archive and tag");
    assert_success(&output, "forward artifact arguments");
    assert_eq!(
        String::from_utf8(output.stdout).expect("UTF-8 arguments"),
        format!(
            "run\n--locked\n-p\nkidobo-e2e\n--\nrun\n--required-only\n--archive\n/tmp/candidate with spaces.tar.gz\n--tag\n{RELEASE_TAG}\n"
        )
    );
    for options in [
        vec!["--distro", "debian-12"],
        vec!["--resume", "run-123-456"],
        vec!["--refresh-images"],
    ] {
        let output = Command::new("just")
            .arg("--justfile")
            .arg(&justfile)
            .env("PATH", path_with_prefix(&fixture.fake_bin))
            .args(["e2e-artifact", "/tmp/candidate.tar.gz", RELEASE_TAG])
            .args(&options)
            .output()
            .expect("reject extra artifact arguments");
        assert!(!output.status.success(), "{options:?}");
        assert_eq!(output.stdout, [] as [u8; 0]);
    }
    let output = Command::new("just")
        .arg("--justfile")
        .arg(&justfile)
        .args(["e2e-resume", "run-123-456"])
        .output()
        .expect("reject removed recipe");
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not contain recipe"));
}
