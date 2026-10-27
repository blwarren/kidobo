use std::process::{Command, Output};

fn reporting_header() -> &'static str {
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    &script[..script
        .find("readonly ROOT=")
        .expect("guest reporting header")]
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
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = script
        .find("probe_observation() {")
        .expect("probe observation helper");
    let end = script[start..]
        .find("\nprobe_pair() {")
        .expect("probe observation end")
        + start;
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
            &script[start..end],
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
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = script
        .find("defer_timer_until_configuration_is_ready() {")
        .expect("timer deferral helper");
    let end = script[start..]
        .find("\nrestore_boot_timer() {")
        .map(|offset| start + offset)
        .expect("end of timer deferral");
    let helper = script[start..end].replace(
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
            &format!("set -eu\n{helper}\ndefer_timer_until_configuration_is_ready"),
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
