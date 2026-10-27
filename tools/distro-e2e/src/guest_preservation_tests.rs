use super::{read_text, tests::TestDir};
use std::fs;
use std::process::Command;

fn lifecycle_function(start: &str, end: &str) -> String {
    let script = include_str!("../../../scripts/e2e/lifecycle.sh");
    let offset = script
        .find(&format!("\n{start}"))
        .expect("lifecycle function")
        + 1;
    let length = script[offset..].find(end).expect("next function");
    script[offset..offset + length]
        .replace("/usr/local/bin/kidobo", "${TARGET}")
        .replace("/var/lib/kidobo/temporary-bans.toml", "${TEMPORARY}")
}

#[test]
fn failed_uninstall_observes_enforcement_before_any_repair() {
    let function = lifecycle_function(
        "test_uninstall_failure_preserves_runtime() {",
        "\nfinish_phase() {",
    );
    for damages_enforcement in [false, true] {
        let temp = TestDir::new();
        let root = temp.path();
        for name in ["config", "blocklist", "firewall"] {
            fs::write(root.join(name), "retained").expect("preserved fixture");
        }
        super::tests::executable(&root.join("kidobo"), "#!/bin/sh\nexit 0\n");
        super::tests::executable(
            &root.join("installer"),
            "#!/bin/bash\nprintf 'uninstall\\n' >> \"$EVENTS\"\nif [[ \"$DAMAGE\" == true ]]; then printf changed > \"$FIREWALL\"; fi\nprintf 'unknown_key\\n' >&2\nexit 1\n",
        );
        let output = Command::new("bash")
            .args([
                "-c",
                &format!(
                    r#"
set -euo pipefail
exec 9>&2
STATE=$ROOT CONFIG=$ROOT/config BLOCKLIST=$ROOT/blocklist TARGET=$ROOT/kidobo
installer=$ROOT/installer V4_HOST=198.18.77.1 V6_HOST=fd42::1 SET4=set4 SET6=set6
e2e_check_start() {{ :; }}
e2e_check_pass() {{ :; }}
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
defer_timer_until_configuration_is_ready() {{ :; }}
wait_for_sync_service_idle() {{ :; }}
restore_boot_timer() {{ :; }}
systemctl() {{ return 0; }}
ipset() {{ return 0; }}
sets_snapshot() {{ cat "$FIREWALL"; }}
probe_pair() {{
  [[ $(cat "$FIREWALL") == retained ]]
  printf 'probe IPv4\nprobe IPv6\n' >> "$EVENTS"
}}
sync_and_assert() {{ printf 'repair\n' >> "$EVENTS"; printf retained > "$FIREWALL"; }}
{function}
test_uninstall_failure_preserves_runtime
"#
                ),
            ])
            .env("ROOT", root)
            .env("FIREWALL", root.join("firewall"))
            .env("EVENTS", root.join("events"))
            .env("DAMAGE", damages_enforcement.to_string())
            .output()
            .expect("exercise failed uninstall with inert commands");
        let events = read_text(&root.join("events")).expect("uninstall observations");
        if damages_enforcement {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("failed uninstall changed live firewall enforcement")
            );
            assert_eq!(events, "uninstall\n");
        } else {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(events, "uninstall\nprobe IPv4\nprobe IPv6\nrepair\n");
        }
    }
}

#[test]
fn candidate_reinstall_checks_nonempty_temporary_state_lookup_and_enforcement() {
    let function = lifecycle_function(
        "test_candidate_temporary_reinstall() {",
        "\nupgrade_phase() {",
    );
    for scenario in ["preserved", "lost-file", "lost-lookup", "lost-enforcement"] {
        let temp = TestDir::new();
        let root = temp.path();
        let output = Command::new("bash")
            .args(["-c", &format!(r#"
set -euo pipefail
exec 9>&2
STATE=$ROOT TEMPORARY=$ROOT/temporary SET4=set4
e2e_check_start() {{ :; }}
e2e_check_pass() {{ :; }}
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
assert_target_version() {{ :; }}
assert_installed_binary() {{ :; }}
kidobo() {{
 case "$1" in
  ban) printf 'version = 1\n[[ips]]\ncidr = "203.0.113.79/32"\nexpires_at = 4102444800\n' > "$TEMPORARY" ;;
  lookup) [[ "$SCENARIO" == lost-lookup ]] || printf '203.0.113.79\ttemporary:blocklist\t203.0.113.79/32\n'; return 0 ;;
  *) exit 90 ;;
 esac
}}
install_target() {{ if [[ "$SCENARIO" == lost-file ]]; then printf 'version = 1\n' > "$TEMPORARY"; fi; }}
sync_and_assert() {{ if [[ "$SCENARIO" != lost-enforcement ]]; then printf enforced > "$ROOT/membership"; fi; }}
ipset() {{ [[ "$1" == test && "$2" == set4 && "$3" == 203.0.113.79 && -f "$ROOT/membership" ]]; }}
{function}
test_candidate_temporary_reinstall
"#)])
            .env("ROOT", root)
            .env("SCENARIO", scenario)
            .output()
            .expect("exercise reinstall with inert commands");
        if scenario == "preserved" {
            assert!(output.status.success(), "{output:?}");
            assert!(
                read_text(&root.join("temporary"))
                    .expect("temporary state")
                    .contains("203.0.113.79/32")
            );
        } else {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
            let expected = match scenario {
                "lost-file" => "candidate reinstall changed nonempty temporary state",
                "lost-lookup" => "candidate reinstall lost the active temporary lookup",
                "lost-enforcement" => "reinstalled candidate did not enforce temporary ban",
                _ => unreachable!(),
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{scenario}: {output:?}"
            );
        }
    }
}
