use std::process::{Command, Output};

fn reporting_header() -> &'static str {
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    &script[..script
        .find("readonly ROOT=")
        .expect("guest reporting header")]
}

fn fixture(body: &str) -> Output {
    Command::new("bash")
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
fn guest_checks_report_expected_probe_failures_and_abort_mismatches() {
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    let start = script.find("probe() {").expect("probe helper");
    let end = script[start..]
        .find("\nwrite_config() {")
        .expect("probe end")
        + start;
    for (status, expectation, success) in [
        (0, "allowed", true),
        (1, "blocked", true),
        (0, "blocked", false),
        (1, "allowed", false),
    ] {
        let output = fixture(&format!(
            "TEST_NS=fake TRAFFIC_PORT=123 ROOT=/unused\n\
             fail() {{ exit 1; }}\n\
             ip() {{ return {status}; }}\n\
             {}\n\
             e2e_check_start outer expectation\n\
             probe IPv4 198.18.77.1 {expectation}\n\
             e2e_check_pass completed\n",
            &script[start..end]
        ));
        let stderr = String::from_utf8_lossy(&output.stderr);
        let markers: Vec<_> = stderr
            .lines()
            .filter(|line| line.starts_with("E2E_CHECK\t"))
            .collect();
        assert_eq!(output.status.success(), success, "{stderr}");
        assert_eq!(
            markers.iter().any(|line| line.contains("\tPASS\t")),
            success
        );
        assert_eq!(
            markers.iter().any(|line| line.contains("\tFAIL\t")),
            !success
        );
        if !success {
            assert!(
                markers
                    .iter()
                    .any(|line| line.starts_with("E2E_CHECK\touter\tFAIL\t"))
            );
        }
        assert_eq!(output.stdout, b"");
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
