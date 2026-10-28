use super::{read_text, tests::TestDir};
use std::fs;
use std::process::Command;

#[test]
fn failed_uninstall_observes_enforcement_before_any_repair() {
    let function = include_str!("../../../scripts/e2e/lib/runtime.sh")
        .replace("/usr/local/bin/kidobo", "${TARGET}")
        .replace("/var/lib/kidobo/temporary-bans.toml", "${TEMPORARY}");
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
{function}
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
    let function = include_str!("../../../scripts/e2e/lib/upgrade.sh")
        .replace("/var/lib/kidobo/temporary-bans.toml", "${TEMPORARY}");
    for scenario in ["preserved", "lost-file", "lost-lookup", "lost-enforcement"] {
        let temp = TestDir::new();
        let root = temp.path();
        let output = Command::new("bash")
            .args(["-c", &format!(r#"
set -euo pipefail
exec 9>&2
STATE=$ROOT TEMPORARY=$ROOT/temporary SET4=set4
{function}
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

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "One inert lifecycle fixture verifies snapshot ordering and each preserved artifact"
)]
fn upgrade_preservation_compares_post_sync_state_and_rejects_installer_changes() {
    let function = include_str!("../../../scripts/e2e/lib/upgrade.sh")
        .replace("/usr/local/bin/kidobo", "${TARGET}")
        .replace("/var/lib/kidobo/temporary-bans.toml", "${TEMPORARY}")
        .replace("/var/cache/kidobo/remote", "\"$ROOT/cache/remote\"");
    for scenario in [
        "preserved",
        "legacy",
        "config",
        "blocklist",
        "cache",
        "temporary",
    ] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir_all(root.join("baseline/kidobo-v0.14.2-linux-x86_64"))
            .expect("archive tree");
        fs::create_dir_all(root.join("cache/remote")).expect("cache tree");
        fs::write(root.join("kidobo"), "frozen old binary bytes").expect("binary");
        fs::write(
            root.join("baseline/kidobo-v0.14.2-linux-x86_64/kidobo"),
            "frozen old binary bytes",
        )
        .expect("archive binary");
        fs::write(root.join("baseline-tag"), "v0.14.2\n").expect("baseline tag");
        fs::write(root.join("config"), "baseline configuration\n").expect("config");
        fs::write(root.join("blocklist"), "# baseline header\n").expect("blocklist");
        super::tests::executable(&root.join("baseline/installer.sh"), "#!/bin/sh\nexit 0\n");
        let output = Command::new("bash")
            .args(["-c", &format!(r#"
set -euo pipefail
exec 9>&2
STATE=$ROOT CONFIG=$ROOT/config BLOCKLIST=$ROOT/blocklist TARGET=$ROOT/kidobo TEMPORARY=$ROOT/temporary
BASELINE=$ROOT/baseline RELEASE=$ROOT/release HTTP_PORT=12345 SOURCE_PORT=12346
installer=$BASELINE/installer.sh mode=candidate tag=v0.14.3
V4_PEER=198.18.77.2 V6_PEER=fd42::2 SET4=set4 SET6=set6
{function}
tar -czf "$BASELINE/kidobo-v0.14.2-linux-x86_64.tar.gz" -C "$BASELINE" kidobo-v0.14.2-linux-x86_64
(cd "$BASELINE"; sha256sum kidobo-v0.14.2-linux-x86_64.tar.gz > SHA256SUMS)
e2e_check_start() {{ :; }}
e2e_check_pass() {{ :; }}
fail() {{ echo "$*" >&2; exit 1; }}
start_source_fixture() {{ :; }}
serve_dir() {{ :; }}
defer_timer_until_configuration_is_ready() {{ :; }}
wait_for_sync_service_idle() {{ :; }}
clear_timer_deferral() {{ :; }}
install_frozen_baseline() {{ :; }}
assert_installed_binary() {{ :; }}
assert_systemd_units() {{ :; }}
configure_baseline_sources() {{ :; }}
setup_namespace() {{ :; }}
capture_namespace_and_cleanup() {{ :; }}
start_traffic_servers() {{ :; }}
assert_remote_lookup() {{ :; }}
stop_fixture() {{ :; }}
assert_target_version() {{ :; }}
sync_and_assert() {{ :; }}
ipset() {{ :; }}
probe_pair() {{ :; }}
test_candidate_temporary_reinstall() {{ :; }}
restore_boot_timer() {{ :; }}
kidobo() {{
  case "$1" in
    --version) echo 'kidobo v0.14.2' | sed 's/kidobo v/kidobo /' ;;
    ban)
      if [[ "$2" == --help ]]; then [[ "$SCENARIO" == legacy ]] || echo '  --for DURATION'; return 0
      elif [[ "${{3:-}}" == --for ]]; then echo 'old temporary state' > "$TEMPORARY"
      else printf '%s\n' "$2" >> "$BLOCKLIST"; fi ;;
    lookup) printf '203.0.113.79\ttemporary:blocklist\t203.0.113.79/32\n' ;;
    init|doctor) : ;;
    *) exit 90 ;;
  esac
}}
run_baseline_enforcement_check() {{
  cmp -s "$2" "$CONFIG"
  cmp -s "$3" "$BLOCKLIST"
  [[ "$4" == - ]] || cmp -s "$4" "$TEMPORARY"
  printf '# baseline header\n\n198.18.77.2/32\nfd42::2/128\n' > "$BLOCKLIST"
  echo 'cache written by old sync' > "$ROOT/cache/remote/data"
}}
install_target() {{
  case "$SCENARIO" in
    config) echo changed >> "$CONFIG" ;;
    blocklist) echo changed >> "$BLOCKLIST" ;;
    cache) echo changed >> "$ROOT/cache/remote/data" ;;
    temporary) echo changed >> "$TEMPORARY" ;;
  esac
}}
run_upgrade_phase
"#)])
            .env("ROOT", root)
            .env("SCENARIO", scenario)
            .output()
            .expect("exercise upgrade with inert lifecycle operations");
        if matches!(scenario, "preserved" | "legacy") {
            assert!(output.status.success(), "{scenario}: {output:?}");
            assert_eq!(
                read_text(&root.join("upgrade-blocklist.txt")).expect("installer snapshot"),
                "# baseline header\n\n198.18.77.2/32\nfd42::2/128\n"
            );
            assert_eq!(
                read_text(&root.join("baseline-before-sync-blocklist.txt"))
                    .expect("baseline failure snapshot"),
                "# baseline header\n198.18.77.2\nfd42::2\n"
            );
        } else {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
            let expected = match scenario {
                "config" => "binary upgrade changed baseline-generated config",
                "blocklist" => "binary upgrade changed baseline-generated blocklist",
                "cache" => "binary upgrade changed old remote-cache bytes",
                "temporary" => "binary upgrade changed baseline temporary data",
                _ => unreachable!(),
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{scenario}: {output:?}"
            );
        }
    }
}
