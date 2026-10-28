use std::fmt::Write as _;
use std::process::{Command, Output};

fn reporting_header() -> String {
    format!(
        "set -euo pipefail\nexec 9>&2\nBASH_XTRACEFD=9\nPS4='+ TRACE ${{BASH_SOURCE:-main}}:${{LINENO}}:${{FUNCNAME[0]:-main}}: '\nset -x\ne2e_checks=()\ne2e_failure_reason='command failed or guest interrupted before assertion completion'\n{}\ntrap 'e2e_report_exit \"$?\"' EXIT\n",
        include_str!("../../../scripts/e2e/lib/reporting.sh")
    )
}

fn fixture(body: &str) -> Output {
    Command::new("bash")
        .env(
            "E2E_CHECK_MANIFEST",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../../scripts/e2e/checks.json"),
        )
        .args(["-c", &format!("{}\n{body}", reporting_header())])
        .output()
        .expect("run guest reporting with shell builtins only")
}

#[test]
fn lifecycle_helper_modules_source_without_running_guest_commands() {
    use super::tests::TestDir;

    let temp = TestDir::new();
    let modules = [
        include_str!("../../../scripts/e2e/lib/reporting.sh"),
        include_str!("../../../scripts/e2e/lib/fixtures.sh"),
        include_str!("../../../scripts/e2e/lib/network.sh"),
        include_str!("../../../scripts/e2e/lib/runtime.sh"),
        include_str!("../../../scripts/e2e/lib/upgrade.sh"),
    ];
    let paths = modules
        .iter()
        .enumerate()
        .map(|(index, module)| {
            let path = temp.path().join(format!("helper-{index}.sh"));
            std::fs::write(&path, module).expect("write source fixture");
            path
        })
        .collect::<Vec<_>>();
    let mut script = String::from(
        "set -euo pipefail\nROOT=$1\nPATH=/nonexistent\ncommand_not_found_handle() { printf '%s\\n' \"$1\" > \"$ROOT/unexpected-command\"; return 127; }\nshopt -s nullglob\nbefore=(\"$ROOT\"/*)\nflags=$-\ntrap_before=$(trap -p EXIT)\n",
    );
    for path in &paths {
        writeln!(script, "source '{}'", path.display()).expect("append source path");
    }
    script.push_str(
        "after=(\"$ROOT\"/*)\n[[ \"${before[*]}\" == \"${after[*]}\" && \"$flags\" == \"$-\" && \"$trap_before\" == \"$(trap -p EXIT)\" && ! -e \"$ROOT/unexpected-command\" ]]\ndeclare -F e2e_check_start fixture_curl setup_namespace run_after_reboot_phase run_upgrade_phase >/dev/null\n",
    );
    let output = Command::new("bash")
        .args(["-c", &script, "source-helper-check"])
        .arg(temp.path())
        .output()
        .expect("source helper definitions in an inert shell");
    assert!(output.status.success(), "{output:?}");
    assert!(
        output.stdout.is_empty(),
        "source printed guest output: {output:?}"
    );
    assert!(
        output.stderr.is_empty(),
        "source wrote guest diagnostics: {output:?}"
    );
}

#[test]
fn guest_trace_does_not_contaminate_captured_output_or_diagnostics() {
    let output = fixture(
        r#"
value=$(printf clean 2>/dev/null)
[[ "$value" == clean ]]
captured=$( { printf diagnostic >&2; } 2>&1)
[[ "$captured" == diagnostic ]]
e2e_check_start sample 'captured values stay clean'
e2e_check_pass 'both exact string comparisons succeeded'
"#,
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert_eq!(output.stdout, b"");
    assert!(stderr.contains("TRACE main:"));
    assert!(stderr.contains("E2E_CHECK\tsample\tPASS\t"));
}

#[test]
fn guest_checks_reject_infrastructure_errors_and_require_drop_evidence() {
    use super::tests::TestDir;
    let probe = include_str!("../../../scripts/e2e/lib/network.sh");
    for (status, outcome, expectation, before, after, success) in [
        (0, "allowed", "allowed", 0, 0, true),
        (10, "connect-timeout", "blocked", 2, 3, true),
        (10, "connect-timeout", "blocked", 2, 2, false),
        (20, "infrastructure-error", "blocked", 2, 3, false),
        (127, "infrastructure-error", "blocked", 2, 3, false),
        (0, "allowed", "blocked", 2, 3, false),
        (10, "connect-timeout", "allowed", 0, 0, false),
    ] {
        let temp = TestDir::new();
        let observation = temp.path().join("probe.json");
        std::fs::write(
            &observation,
            format!(r#"{{"address":"198.18.77.1","source":"198.18.77.2","outcome":"{outcome}"}}"#),
        )
        .expect("probe fixture");
        std::fs::write(
            observation.with_extension("json.status"),
            status.to_string(),
        )
        .expect("exit fixture");
        let output = fixture(&format!(
            "TEST_NS=fake TRAFFIC_PORT=123\nfail() {{ exit 1; }}\n{}\ne2e_check_start outer expectation\nprobe_observation IPv4 198.18.77.1 198.18.77.2 {expectation} '{}' {before} {after}\ne2e_check_pass completed\n",
            probe,
            observation.display()
        ));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.success(), success, "{stderr}");
        let markers: Vec<_> = stderr
            .lines()
            .filter(|line| line.starts_with("E2E_CHECK\t"))
            .collect();
        assert_eq!(
            markers.iter().any(|line| line.contains("\tPASS\t")),
            success
        );
        assert_eq!(
            markers.iter().any(|line| line.contains("\tFAIL\t")),
            !success
        );
    }
}

#[test]
fn guest_plans_later_checks_without_claiming_they_ran() {
    for mode in ["candidate", "published"] {
        let output = fixture(&format!(
            "e2e_plan_checks start {mode}\ne2e_check_start 'installation and initialization' expectation\nexit 7\n"
        ));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let markers: Vec<_> = stderr
            .lines()
            .filter(|line| line.starts_with("E2E_CHECK\t"))
            .collect();
        assert_eq!(output.status.code(), Some(7));
        assert!(
            markers
                .iter()
                .any(|line| line.starts_with("E2E_CHECK\tinstallation and initialization\tFAIL\t"))
        );
        assert!(markers.iter().any(|line| {
            line.starts_with("E2E_CHECK\tHTTP sync and repeated firewall activation\tPLAN\t")
        }));
        assert!(!markers.iter().any(|line| line.contains("\tPASS\t")));
        assert_eq!(
            markers.iter().any(|line| line
                .starts_with("E2E_CHECK\tIPv6 capacity failure preserves both families\tPLAN\t")),
            mode == "candidate"
        );
    }
}

#[test]
fn guest_timer_deferral_replaces_existing_triggers_before_restart() {
    use super::tests::{TestDir, executable};

    let temp = TestDir::new();
    let dropin = temp.path().join("kidobo-sync.timer.d/e2e.conf");
    let reloaded = temp.path().join("reloaded.conf");
    let helper = include_str!("../../../scripts/e2e/lib/runtime.sh").replace(
        "/run/systemd/system/kidobo-sync.timer.d/e2e.conf",
        dropin.to_str().expect("temporary drop-in path"),
    );
    let bin = temp.path().join("bin");
    std::fs::create_dir(&bin).expect("fake systemd command directory");
    executable(
        &bin.join("systemctl"),
        r#"#!/bin/bash
set -eu
case "$1" in
  daemon-reload) cp "$DROPIN" "$RELOADED" ;;
  is-active) exit 0 ;;
  restart) cmp -s "$DROPIN" "$RELOADED"; printf restarted ;;
  *) exit 90 ;;
esac
"#,
    );
    let output = Command::new("bash")
        .args([
            "-c",
            &format!(
                "set -eu\n{}\n{helper}\ndefer_timer_until_configuration_is_ready",
                reporting_header()
            ),
        ])
        .env("PATH", format!("{}:/usr/bin:/bin", bin.display()))
        .env("DROPIN", &dropin)
        .env("RELOADED", &reloaded)
        .output()
        .expect("exercise deferral with fake systemctl");
    assert!(output.status.success(), "{output:?}");
    assert_eq!(output.stdout, b"restarted");

    // systemd.timer(5): empty assignments clear all accumulated timer expressions.
    let mut triggers = vec!["OnBootSec=2min", "OnUnitActiveSec=1h"];
    let config = super::read_text(&reloaded).expect("configuration loaded before restart");
    for line in config.lines().filter(|line| line.starts_with("On")) {
        if line.ends_with('=') {
            triggers.clear();
        } else {
            triggers.push(line);
        }
    }
    assert_eq!(triggers, ["OnActiveSec=1h"]);
}
