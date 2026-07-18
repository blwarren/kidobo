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
fn lookup_probe_builds_fixture_without_running_init_and_measures_both_formats() {
    let temp = TempDir::new().expect("tempdir");
    let fake_binary = temp.path().join("kidobo");
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

    let output = Command::new(script_path("scripts/perf/measure-lookup-rss.sh"))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .env("KIDOBO_PERF_BINARY", &fake_binary)
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
