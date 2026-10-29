#![cfg(unix)]

use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

const FIXTURE_LOG_READ_LIMIT: usize = 4 * 1024;

fn script_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn write_executable(path: &Path, contents: &str) {
    fs::create_dir_all(path.parent().expect("parent")).expect("create executable parent");
    fs::write(path, contents).expect("write executable");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod executable");
}

fn path_with_prefix(path: &Path) -> String {
    match std::env::var("PATH") {
        Ok(existing) if !existing.is_empty() => format!("{}:{existing}", path.display()),
        _ => path.display().to_string(),
    }
}

fn read_to_string_with_limit(path: &Path, limit: usize) -> String {
    let file = fs::File::open(path).expect("open bounded fixture file");
    assert!(
        file.metadata().expect("fixture metadata").len()
            <= u64::try_from(limit).expect("read limit fits u64"),
        "fixture exceeds {limit} byte read limit: {}",
        path.display()
    );
    let mut contents = String::new();
    file.take(u64::try_from(limit).expect("read limit fits u64"))
        .read_to_string(&mut contents)
        .expect("read bounded UTF-8 fixture file");
    contents
}

fn write_lookup_build_fixture(root: &Path) -> PathBuf {
    let fake_bin = root.join("bin");
    write_executable(
        &root.join("lookup-fixture"),
        r#"#!/bin/bash
set -euo pipefail
[[ "$1" == lookup && "$2" == --file && "$4" == --format ]]
[[ "$(wc -l < "$3")" -eq 4 ]]
[[ "$(wc -l < "${KIDOBO_ROOT}/data/blocklist.txt")" -eq 4 ]]
printf '%s\n' "$5" >> "$KIDOBO_TEST_LOOKUP_LOG"
printf 'fixture result\n'
"#,
    );
    write_executable(
        &fake_bin.join("cargo"),
        r#"#!/bin/bash
set -euo pipefail
printf '%s\n' "$*" >> "$KIDOBO_TEST_CARGO_LOG"
case "$*" in
  'build --release --locked --bin kidobo')
    mkdir -p "${CARGO_TARGET_DIR:-target}/release"
    cp "$KIDOBO_TEST_LOOKUP_FIXTURE" "${CARGO_TARGET_DIR:-target}/release/kidobo"
    ;;
  'bench --bench core_perf -- --baseline main')
    mkdir -p "${CARGO_TARGET_DIR:-target}/criterion/fixture/new"
    printf '{"mean":{"point_estimate":100}}' > "${CARGO_TARGET_DIR:-target}/criterion/fixture/new/estimates.json"
    ;;
  *) exit 2 ;;
esac
"#,
    );
    fake_bin
}

#[test]
fn benchmark_runner_compares_then_saves_in_separate_invocations() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = temp.path().join("bin");
    let cargo_log = temp.path().join("cargo.log");
    write_executable(
        &fake_bin.join("cargo"),
        "#!/usr/bin/env bash\nset -euo pipefail\nprintf '%s\\n' \"$*\" >> \"${KIDOBO_TEST_CARGO_LOG}\"\n",
    );

    let status = Command::new(script_path("scripts/perf/run-benchmarks.sh"))
        .args(["main", "candidate"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("PATH", path_with_prefix(&fake_bin))
        .env("KIDOBO_TEST_CARGO_LOG", &cargo_log)
        .status()
        .expect("run benchmark helper");

    assert!(status.success());
    assert_eq!(
        read_to_string_with_limit(&cargo_log, FIXTURE_LOG_READ_LIMIT),
        "bench --bench core_perf -- --baseline main\nbench --bench core_perf -- --save-baseline candidate\n"
    );
}

#[test]
fn regression_checker_requires_fresh_complete_comparisons() {
    for scenario in [
        "complete",
        "missing",
        "stale",
        "malformed",
        "invalid-mean",
        "wrong-field",
        "slow",
    ] {
        let temp = TempDir::new().expect("tempdir");
        let target = temp.path().join("custom-target");
        for case in ["first", "second"] {
            let directory = target.join("criterion").join(case).join("main");
            fs::create_dir_all(&directory).expect("baseline directory");
            fs::write(
                directory.join("estimates.json"),
                r#"{"mean":{"point_estimate":100}}"#,
            )
            .expect("baseline");
            if scenario == "stale" {
                let old = directory.parent().expect("case").join("new");
                fs::create_dir_all(&old).expect("stale directory");
                fs::write(
                    old.join("estimates.json"),
                    r#"{"mean":{"point_estimate":100}}"#,
                )
                .expect("stale estimates");
            }
        }
        let fake_bin = temp.path().join("bin");
        write_executable(
            &fake_bin.join("cargo"),
            r#"#!/bin/bash
set -euo pipefail
[[ "$*" == 'bench --bench core_perf -- --baseline main' ]]
mkdir -p "$CARGO_TARGET_DIR/criterion/first/new"
mean=105
[[ "$KIDOBO_TEST_SCENARIO" != slow ]] || mean=125
if [[ "$KIDOBO_TEST_SCENARIO" == malformed ]]; then
  printf 'garbage "point_estimate":105' > "$CARGO_TARGET_DIR/criterion/first/new/estimates.json"
elif [[ "$KIDOBO_TEST_SCENARIO" == invalid-mean ]]; then
  printf '{"mean":{"point_estimate":0}}' > "$CARGO_TARGET_DIR/criterion/first/new/estimates.json"
elif [[ "$KIDOBO_TEST_SCENARIO" == wrong-field ]]; then
  printf '{"median":{"point_estimate":105}}' > "$CARGO_TARGET_DIR/criterion/first/new/estimates.json"
else
  printf '{"mean":{"point_estimate":%s}}' "$mean" > "$CARGO_TARGET_DIR/criterion/first/new/estimates.json"
fi
if [[ "$KIDOBO_TEST_SCENARIO" != missing && "$KIDOBO_TEST_SCENARIO" != stale ]]; then
  mkdir -p "$CARGO_TARGET_DIR/criterion/second/new"
  printf '{"mean":{"point_estimate":105}}' > "$CARGO_TARGET_DIR/criterion/second/new/estimates.json"
fi
"#,
        );
        let output = Command::new(script_path("scripts/perf/check-regressions.sh"))
            .args(["--skip-rss-probe"])
            .current_dir(temp.path())
            .env("CARGO_TARGET_DIR", &target)
            .env("KIDOBO_TEST_SCENARIO", scenario)
            .env("PATH", path_with_prefix(&fake_bin))
            .output()
            .expect("check isolated estimates");
        assert_eq!(
            output.status.success(),
            scenario == "complete",
            "{scenario}: {} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if matches!(scenario, "missing" | "stale") {
            assert!(String::from_utf8_lossy(&output.stderr).contains("missing current results"));
        }
    }
}

#[test]
fn lookup_probe_builds_fixture_without_running_init_and_measures_both_formats() {
    let temp = TempDir::new().expect("tempdir");
    let fake_binary = temp.path().join("override binary");
    write_executable(
        &fake_binary,
        r#"#!/usr/bin/env bash
set -euo pipefail
[[ "$1" == "lookup" ]]
[[ "$2" == "--file" ]]
[[ "$4" == "--format" ]]
[[ -f "${KIDOBO_ROOT}/config/config.toml" ]]
[[ -f "${KIDOBO_ROOT}/data/blocklist.txt" ]]
[[ "$(wc -l < "$3")" -eq 4 ]]
[[ "$(wc -l < "${KIDOBO_ROOT}/data/blocklist.txt")" -eq 4 ]]
case "$5" in
  human)
    printf 'human-one\nhuman-two\n'
    ;;
  tsv)
    printf 'tsv-one\ntsv-two\ntsv-summary\n'
    ;;
  *)
    exit 2
    ;;
esac
"#,
    );

    let fake_bin = temp.path().join("bin");
    write_executable(&fake_bin.join("cargo"), "#!/bin/bash\nexit 99\n");
    let output = Command::new(script_path("scripts/perf/measure-lookup-rss.sh"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("PATH", path_with_prefix(&fake_bin))
        .env("CARGO_TARGET_DIR", temp.path().join("unused target"))
        .env("KIDOBO_PERF_BINARY", &fake_binary)
        .env_remove("KIDOBO_PERF_CPU_CORE")
        .env_remove("KIDOBO_PERF_MEM_LIMIT_KIB")
        .env("KIDOBO_PERF_BLOCKS", "4")
        .env("KIDOBO_PERF_TARGETS", "4")
        .output()
        .expect("run lookup probe");

    assert!(
        output.status.success(),
        "probe failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 probe output");
    for expected in [
        "blocklist_entries=4",
        "target_entries=4",
        "human_output_lines=2",
        "human_elapsed_s=",
        "human_max_rss_kib=",
        "tsv_output_lines=3",
        "tsv_elapsed_s=",
        "tsv_max_rss_kib=",
    ] {
        assert!(stdout.contains(expected), "missing {expected:?}: {stdout}");
    }
}

#[test]
fn lookup_probe_runs_binary_from_cargo_target_directory() {
    for target_kind in ["default", "relative", "absolute"] {
        let temp = TempDir::new().expect("tempdir");
        let fake_bin = write_lookup_build_fixture(temp.path());
        let cargo_log = temp.path().join("cargo.log");
        let lookup_log = temp.path().join("lookup.log");
        let mut command = Command::new(script_path("scripts/perf/measure-lookup-rss.sh"));
        command
            .current_dir(temp.path())
            .env("PATH", path_with_prefix(&fake_bin))
            .env_remove("KIDOBO_PERF_BINARY")
            .env_remove("CARGO_TARGET_DIR")
            .env_remove("KIDOBO_PERF_CPU_CORE")
            .env_remove("KIDOBO_PERF_MEM_LIMIT_KIB")
            .env("KIDOBO_PERF_BLOCKS", "4")
            .env("KIDOBO_PERF_TARGETS", "4")
            .env("KIDOBO_TEST_CARGO_LOG", &cargo_log)
            .env("KIDOBO_TEST_LOOKUP_LOG", &lookup_log)
            .env(
                "KIDOBO_TEST_LOOKUP_FIXTURE",
                temp.path().join("lookup-fixture"),
            );
        if target_kind != "default" {
            let target = if target_kind == "relative" {
                PathBuf::from("relative target")
            } else {
                temp.path().join("absolute target")
            };
            command.env("CARGO_TARGET_DIR", target);
            write_executable(
                &temp.path().join("target/release/kidobo"),
                "#!/bin/bash\nexit 98\n",
            );
        }
        let output = command.output().expect("run lookup probe with fake Cargo");
        assert!(
            output.status.success(),
            "{target_kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            read_to_string_with_limit(&cargo_log, FIXTURE_LOG_READ_LIMIT),
            "build --release --locked --bin kidobo\n"
        );
        assert_eq!(
            read_to_string_with_limit(&lookup_log, FIXTURE_LOG_READ_LIMIT),
            "human\ntsv\n"
        );
    }
}

#[test]
fn regression_checker_runs_rss_probe_from_custom_target_directory() {
    let temp = TempDir::new().expect("tempdir");
    let fake_bin = write_lookup_build_fixture(temp.path());
    let target = temp.path().join("custom target");
    let baseline = target.join("criterion/fixture/main");
    fs::create_dir_all(&baseline).expect("baseline directory");
    fs::write(
        baseline.join("estimates.json"),
        r#"{"mean":{"point_estimate":100}}"#,
    )
    .expect("baseline estimates");
    std::os::unix::fs::symlink(script_path("scripts"), temp.path().join("scripts"))
        .expect("link performance scripts");
    write_executable(
        &temp.path().join("target/release/kidobo"),
        "#!/bin/bash\nexit 98\n",
    );
    let cargo_log = temp.path().join("cargo.log");
    let lookup_log = temp.path().join("lookup.log");
    let output = Command::new(script_path("scripts/perf/check-regressions.sh"))
        .current_dir(temp.path())
        .env("PATH", path_with_prefix(&fake_bin))
        .env("CARGO_TARGET_DIR", target)
        .env_remove("KIDOBO_PERF_BINARY")
        .env_remove("KIDOBO_PERF_CPU_CORE")
        .env_remove("KIDOBO_PERF_MEM_LIMIT_KIB")
        .env("KIDOBO_PERF_BLOCKS", "4")
        .env("KIDOBO_PERF_TARGETS", "4")
        .env("KIDOBO_TEST_CARGO_LOG", &cargo_log)
        .env("KIDOBO_TEST_LOOKUP_LOG", &lookup_log)
        .env(
            "KIDOBO_TEST_LOOKUP_FIXTURE",
            temp.path().join("lookup-fixture"),
        )
        .output()
        .expect("run regression checker with RSS probe");
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        read_to_string_with_limit(&cargo_log, FIXTURE_LOG_READ_LIMIT),
        "bench --bench core_perf -- --baseline main\nbuild --release --locked --bin kidobo\n"
    );
    assert_eq!(
        read_to_string_with_limit(&lookup_log, FIXTURE_LOG_READ_LIMIT),
        "human\ntsv\n"
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("no regressions"));
}
