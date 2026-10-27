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
            "#!/bin/bash\nprintf 'uninstall\\n' >> \"$EVENTS\"\nif [[ \"$DAMAGE\" == true ]]; then printf changed > \"$FIREWALL\"; fi\nexit 1\n",
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
probe() {{
  [[ $(cat "$FIREWALL") == retained ]]
  printf 'probe %s\n' "$1" >> "$EVENTS"
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
fn upgrade_checks_a_nonempty_temporary_ban_through_lookup_and_enforcement() {
    let function = lifecycle_function("upgrade_phase() {", "\nassert_enforcement_absent() {");
    for scenario in ["preserved", "lost-file", "lost-lookup", "lost-enforcement"] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir(root.join("baseline")).expect("baseline fixture");
        for name in ["config", "blocklist", "temporary", "baseline/SHA256SUMS"] {
            fs::write(root.join(name), "initial").expect("source fixture");
        }
        fs::write(root.join("baseline-tag"), "v0.14.3").expect("baseline tag");
        super::tests::executable(
            &root.join("baseline/installer.sh"),
            "#!/bin/bash\nprintf baseline > \"$ROOT/version\"\n",
        );
        super::tests::executable(&root.join("installer"), "#!/bin/sh\nexit 0\n");
        let output = Command::new("bash")
            .args(["-c", &format!(r#"
set -euo pipefail
exec 9>&2
STATE=$ROOT BASELINE=$ROOT/baseline CONFIG=$ROOT/config BLOCKLIST=$ROOT/blocklist
TEMPORARY=$ROOT/temporary installer=$ROOT/installer mode=candidate tag=v0.15.0 SET4=set4
V4_HOST=198.18.77.1 V6_HOST=fd42::1 HTTP_PORT=39472
e2e_check_start() {{ :; }}
e2e_check_pass() {{ :; }}
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
start_source_fixture() {{ :; }}
fixture_curl() {{ :; }}
defer_timer_until_configuration_is_ready() {{ :; }}
wait_for_sync_service_idle() {{ :; }}
assert_installed_binary() {{ :; }}
assert_systemd_units() {{ :; }}
setup_namespace() {{ :; }}
capture_namespace_and_cleanup() {{ :; }}
start_traffic_servers() {{ :; }}
restore_boot_timer() {{ :; }}
probe() {{ :; }}
assert_target_version() {{ [[ $(cat "$ROOT/version") == candidate ]]; }}
kidobo() {{
  case "$1" in
    ban)
      [[ "$2" == 203.0.113.79 && "$3" == --for && "$4" == 1d ]]
      printf 'version = 1\n[[ips]]\ncidr = "203.0.113.79/32"\nexpires_at = 4102444800\n' > "$TEMPORARY"
      ;;
    --version) printf 'kidobo 0.14.3\n' ;;
    lookup)
      [[ "$SCENARIO" == lost-lookup ]] || printf '203.0.113.79\ttemporary:blocklist\t203.0.113.79/32\n'
      return 0 ;;
    doctor) : ;;
    *) exit 90 ;;
  esac
}}
run_baseline_enforcement_check() {{ grep -Fq 'cidr = "203.0.113.79/32"' "$4"; }}
install_target() {{
  printf candidate > "$ROOT/version"
  if [[ "$SCENARIO" == lost-file ]]; then printf 'version = 1\n' > "$TEMPORARY"; fi
}}
sync_and_assert() {{
  if [[ "$SCENARIO" != lost-enforcement ]]; then printf '203.0.113.79\n' > "$ROOT/membership"; fi
}}
ipset() {{ [[ "$1" == test && "$2" == set4 && "$3" == 203.0.113.79 && -f "$ROOT/membership" ]]; }}
{function}
upgrade_phase
"#)])
            .env("ROOT", root)
            .env("SCENARIO", scenario)
            .output()
            .expect("exercise upgrade with inert commands");
        if scenario == "preserved" {
            assert!(output.status.success(), "{output:?}");
            let state = read_text(&root.join("temporary")).expect("upgraded temporary state");
            assert!(state.contains("cidr = \"203.0.113.79/32\""));
            assert!(state.contains("expires_at = 4102444800"));
        } else {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
            let expected = match scenario {
                "lost-file" => "binary upgrade changed temporary-ban data",
                "lost-lookup" => "binary upgrade lost the active temporary ban from offline lookup",
                "lost-enforcement" => "upgraded sync did not enforce the preserved temporary ban",
                _ => unreachable!(),
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{scenario}: {output:?}"
            );
        }
    }
}
