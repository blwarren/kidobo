//! Guest preparation regressions use extracted helpers and inert command boundaries.
use super::{read_text, tests::TestDir};
use std::fs;
use std::process::{Command, Output};

fn helper(first: &str, next: &str) -> String {
    let source = include_str!("../../../scripts/e2e/provision.sh");
    let start = source.find(&format!("\n{first}() {{")).expect("helper") + 1;
    let end = source[start..]
        .find(&format!("\n{next}() {{"))
        .expect("next helper")
        + start;
    source[start..end].to_owned()
}

fn run(root: &std::path::Path, body: &str) -> Output {
    Command::new("bash")
        .args(["-c", body])
        .env("FIXTURE_ROOT", root)
        .output()
        .expect("run isolated preparation helper")
}

#[test]
fn running_kernel_capabilities_are_required_regardless_of_installed_version() {
    for (failure, expected) in [
        ("", ""),
        ("ip_set", "required module ip_set cannot be loaded"),
        ("xt_set", "required module xt_set cannot be loaded"),
        (
            "ip_set_hash_net",
            "required module ip_set_hash_net cannot be loaded",
        ),
        ("iptables", "default IPv4 iptables backend is unavailable"),
        ("ip6tables", "default IPv6 iptables backend is unavailable"),
    ] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::write(root.join("packages.txt"), "kernel-core=6.12.0-new\n")
            .expect("newer installed kernel inventory");
        let body = format!(
            r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
uname() {{ printf '6.12.0-old\n'; }}
probe() {{ printf '%s\n' "$1" >> "$PREPARED/probes"; [[ "$1" != '{failure}' ]]; }}
modprobe() {{ probe "$1"; }}
iptables() {{ probe iptables; }}
ip6tables() {{ probe ip6tables; }}
{}
verify_running_kernel
"#,
            helper("verify_running_kernel", "finish_selinux")
        );
        let output = run(root, &body);
        assert_eq!(output.status.success(), failure.is_empty(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("running_kernel=6.12.0-old"));
        let probes = read_text(&root.join("probes")).expect("capability probes");
        if failure.is_empty() {
            assert_eq!(
                probes,
                "ip_set\nxt_set\nip_set_hash_net\niptables\nip6tables\n"
            );
        } else {
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{output:?}"
            );
            assert_eq!(probes.lines().last(), Some(failure));
        }
        assert!(!root.join("expected-kernel").exists());
        assert!(!root.join("expected-initramfs").exists());
    }
}

#[test]
fn fresh_preparation_leaves_kernel_selection_to_the_distribution() {
    let temp = TestDir::new();
    let source = include_str!("../../../scripts/e2e/provision.sh")
        .split_once("\nif [[ \"${BASH_SOURCE[0]}\"")
        .expect("script entrypoint")
        .0
        .replace("/opt/kidobo-e2e", "${FIXTURE_ROOT}");
    let body = format!(
        r#"
set -euo pipefail
{source}
require_guest() {{ :; }}
wait_for_network() {{ :; }}
install_dependencies() {{ printf 'dependencies\n' >> "$FIXTURE_ROOT/events"; }}
upgrade_operating_system() {{ printf 'upgrade\n' >> "$FIXTURE_ROOT/events"; }}
record_packages() {{ printf 'kernel-core=6.12.0-new\n' > "$2"; }}
uname() {{ printf '6.12.0-old\n'; }}
grubby() {{ fail 'unexpected boot selection'; }}
update-grub() {{ fail 'unexpected GRUB generation'; }}
grub2-mkconfig() {{ fail 'unexpected GRUB generation'; }}
update-initramfs() {{ fail 'unexpected initramfs generation'; }}
dracut() {{ fail 'unexpected initramfs generation'; }}
provision_main --prepare dnf image-default kmod
"#
    );
    let output = run(temp.path(), &body);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        read_text(&temp.path().join("events")).expect("provisioning events"),
        "dependencies\nupgrade\n"
    );
    assert_eq!(
        read_text(&temp.path().join("prepared/selinux-requested")).expect("security policy"),
        "image-default\n"
    );
    assert!(!temp.path().join("prepared/expected-kernel").exists());
    assert!(!temp.path().join("prepared/expected-initramfs").exists());
    assert!(
        read_text(&temp.path().join("state/provision.txt"))
            .expect("observed kernel")
            .contains("kernel=6.12.0-old")
    );
}

#[test]
fn rpm_dependencies_keep_module_packages_and_only_need_grubby_for_selinux() {
    for selinux in ["image-default", "enforcing"] {
        let temp = TestDir::new();
        let body = format!(
            r#"
set -euo pipefail
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
dnf() {{ printf '%s\n' "$@" > "$FIXTURE_ROOT/packages"; }}
command() {{ [[ "$1" == -v ]]; }}
{}
install_dependencies dnf {selinux} kmod kernel-modules-extra
"#,
            helper("install_dependencies", "run_upgrade")
        );
        let output = run(temp.path(), &body);
        assert!(output.status.success(), "{output:?}");
        let packages = read_text(&temp.path().join("packages")).expect("requested packages");
        assert!(!packages.lines().any(|package| package == "kernel"));
        assert!(
            packages
                .lines()
                .any(|package| package == "kernel-modules-extra")
        );
        assert_eq!(
            packages.lines().any(|package| package == "grubby"),
            selinux == "enforcing"
        );
    }
}

#[test]
fn disabled_selinux_is_prepared_for_permissive_relabel_before_enforcement() {
    let temp = TestDir::new();
    let root = temp.path();
    let config = root.join("selinux-config");
    fs::write(&config, "SELINUX=disabled\nSELINUXTYPE=targeted\n").expect("security config");
    let function = helper("prepare_selinux", "verify_running_kernel")
        .replace("/etc/selinux/config", "${FIXTURE_ROOT}/selinux-config")
        .replace("/etc/systemd/system", "${FIXTURE_ROOT}/units");
    let body = format!(
        r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
prepare_agent_selinux() {{ printf 'agent labels prepared\n' >> "$PREPARED/events"; }}
systemctl() {{ printf 'systemctl %s\n' "$*" >> "$PREPARED/events"; }}
getenforce() {{ printf 'Disabled\n'; }}
grubby() {{ printf 'grubby %s\n' "$*" >> "$PREPARED/events"; }}
fixfiles() {{ printf 'fixfiles %s\n' "$*" >> "$PREPARED/events"; }}
setenforce() {{ printf 'unexpected enforcement\n' >> "$PREPARED/events"; exit 99; }}
{function}
prepare_selinux dnf-epel enforcing
"#
    );
    let output = run(root, &body);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        read_text(&root.join("relabel-scheduled")).expect("relabel flag"),
        "1\n"
    );
    assert!(
        read_text(&config)
            .expect("config")
            .contains("SELINUX=permissive")
    );
    let events = read_text(&root.join("events")).expect("events");
    assert!(events.contains("--args selinux=1 enforcing=0"));
    assert!(events.contains("fixfiles -F onboot"));
    assert!(!events.contains("unexpected enforcement"));
}

#[test]
fn selinux_enforcement_waits_for_relabel_and_verifies_the_transition() {
    for scenario in ["complete", "incomplete", "disabled", "denied"] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::write(root.join("selinux-requested"), "enforcing\n").expect("security requirement");
        fs::write(root.join("selinux-config"), "SELINUX=permissive\n").expect("security config");
        let initial = if scenario == "disabled" {
            "Disabled"
        } else {
            "Permissive"
        };
        fs::write(root.join("mode"), initial).expect("runtime mode");
        if scenario == "incomplete" {
            fs::write(root.join("autorelabel"), "-F\n").expect("unfinished relabel");
        }
        let function = helper("enable_selinux", "prepared_boot_status")
            .replace("/.autorelabel", "${FIXTURE_ROOT}/autorelabel")
            .replace("/etc/selinux/config", "${FIXTURE_ROOT}/selinux-config");
        let body = format!(
            r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
systemctl() {{ [[ "$*" != 'is-active --quiet selinux-autorelabel.service' ]]; }}
ls() {{ :; }}
stat() {{ printf 'system_u:object_r:bin_t:s0\n'; }}
sleep() {{ SECONDS=$((SECONDS + 901)); }}
getenforce() {{ cat "$PREPARED/mode"; }}
setenforce() {{
  printf 'setenforce %s\n' "$*" >> "$PREPARED/events"
  if [[ '{scenario}' != denied ]]; then printf Enforcing > "$PREPARED/mode"; fi
}}
grubby() {{ printf 'grubby %s\n' "$*" >> "$PREPARED/events"; }}
{function}
enable_selinux
"#
        );
        let output = run(root, &body);
        if scenario == "complete" {
            assert!(output.status.success(), "{output:?}");
            assert!(
                read_text(&root.join("selinux-config"))
                    .expect("config")
                    .contains("SELINUX=enforcing")
            );
            let events = read_text(&root.join("events")).expect("events");
            assert!(events.starts_with("setenforce 1\n"));
            assert!(events.contains("--remove-args enforcing=0 selinux=0"));
        } else {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
            let expected = match scenario {
                "incomplete" => "relabeling has not completed",
                "disabled" => "policy did not load",
                "denied" => "did not enter enforcing mode",
                _ => unreachable!(),
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{scenario}: {output:?}"
            );
            assert!(
                !read_text(&root.join("selinux-config"))
                    .expect("config")
                    .contains("SELINUX=enforcing")
            );
        }
    }
}

#[test]
fn relabel_boot_probe_rejects_intermediate_boot_and_reports_both_identities() {
    for scenario in [
        "not-started",
        "relabel-boot",
        "marker",
        "active",
        "complete",
    ] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::write(root.join("relabel-scheduled"), "1\n").expect("scheduled");
        fs::write(root.join("boot-id"), "final-boot\n").expect("boot");
        if scenario != "not-started" {
            fs::write(
                root.join("relabel-boot-id"),
                if scenario == "relabel-boot" {
                    "final-boot\n"
                } else {
                    "relabel-boot\n"
                },
            )
            .expect("relabel boot");
        }
        if scenario == "marker" {
            fs::write(root.join("autorelabel"), "-F").expect("marker");
        }
        let function = helper("prepared_boot_status", "assert_pristine")
            .replace("/proc/sys/kernel/random/boot_id", "${FIXTURE_ROOT}/boot-id")
            .replace("/.autorelabel", "${FIXTURE_ROOT}/autorelabel");
        let output = run(
            root,
            &format!(
                r"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
systemctl() {{ [[ '{scenario}' == active ]]; }}
{function}
prepared_boot_status
"
            ),
        );
        assert_eq!(
            output.status.code(),
            Some(if scenario == "complete" { 0 } else { 75 }),
            "{scenario}: {output:?}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("current=final-boot relabel="));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            if scenario == "complete" {
                "final-boot\n"
            } else {
                ""
            }
        );
    }
}

#[test]
fn agent_label_dropin_preserves_vendor_setup_and_rejects_unknown_layout() {
    for known in [true, false] {
        let temp = TestDir::new();
        let root = temp.path();
        let function = helper("prepare_agent_selinux", "prepare_selinux")
            .replace("/etc/systemd/system", "${FIXTURE_ROOT}/units");
        let output = run(
            root,
            &format!(
                r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
systemctl() {{
  if [[ "$1" == show ]]; then
    if [[ '{known}' == true ]]; then printf '{{ path=/run/incus_agent/incus-agent ; }}\n'; else printf '{{ path=/unknown ; }}\n'; fi
  fi
}}
chcon() {{ :; }}
ls() {{ :; }}
ps() {{ :; }}
{function}
prepare_agent_selinux
"#
            ),
        );
        let dropin = root.join("units/incus-agent.service.d/kidobo-e2e-selinux.conf");
        if known {
            assert!(output.status.success(), "{output:?}");
            assert_eq!(
                read_text(&dropin).expect("drop-in"),
                "[Service]\nExecStartPre=/usr/bin/chcon -t bin_t /run/incus_agent/incus-agent\n"
            );
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("unsupported Incus agent executable")
            );
            assert!(!dropin.exists());
        }
    }
}

#[test]
fn enforcement_admission_requires_durable_success_and_enforcing_state() {
    for (status, mode, success) in [
        ("0", "Enforcing", true),
        ("", "Enforcing", false),
        ("17", "Enforcing", false),
        ("0", "Permissive", false),
    ] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::write(root.join("selinux-requested"), "enforcing").expect("requested");
        fs::write(root.join("enforcement.status"), status).expect("status");
        let function = helper("finish_selinux", "enable_selinux")
            .replace("/.autorelabel", "${FIXTURE_ROOT}/autorelabel");
        let output = run(
            root,
            &format!(
                r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
systemctl() {{ return 1; }}
getenforce() {{ printf '%s\n' '{mode}'; }}
{function}
finish_selinux
"#
            ),
        );
        assert_eq!(
            output.status.success(),
            success,
            "status={status} mode={mode}: {output:?}"
        );
    }
}

#[test]
fn detached_enforcement_launch_and_worker_persist_outcome_without_agent_lifetime() {
    for mode in ["launch", "success", "failure"] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir(root.join("prepared")).expect("prepared");
        fs::write(root.join("prepared/selinux-requested"), "enforcing").expect("requested");
        let script = include_str!("../../../scripts/e2e/provision.sh").replace(
            "readonly BASE=/opt/kidobo-e2e PREPARED=/opt/kidobo-e2e/prepared",
            "readonly BASE=\"$FIXTURE_ROOT\" PREPARED=\"$FIXTURE_ROOT/prepared\"",
        );
        fs::write(root.join("provision.sh"), script).expect("script");
        let output = run(
            root,
            &format!(
                r#"
set -euo pipefail
source "$FIXTURE_ROOT/provision.sh"
require_guest() {{ :; }}
systemd-run() {{ printf '%s\n' "$*" > "$FIXTURE_ROOT/job"; }}
enable_selinux() {{ [[ '{mode}' != launch ]] || exit 99; if [[ '{mode}' == failure ]]; then return 17; fi; }}
if [[ '{mode}' == launch ]]; then provision_main --start-enforcement; else provision_main --enforce-selinux; fi
"#
            ),
        );
        if mode == "launch" {
            assert!(output.status.success(), "{output:?}");
            let job = read_text(&root.join("job")).expect("job invocation");
            assert!(job.contains("--no-block --property=Type=oneshot"));
            assert!(job.contains("--property=TimeoutStartSec=120"));
            assert!(job.contains("--property=StandardOutput=journal"));
            assert!(job.contains("--property=StandardError=journal"));
            assert!(!job.contains("append:"));
            assert!(!job.contains("RuntimeMaxSec"));
            assert!(job.ends_with("provision.sh --enforce-selinux\n"));
            assert!(!root.join("prepared/enforcement.status").exists());
        } else {
            let expected = if mode == "success" { 0 } else { 17 };
            assert_eq!(output.status.code(), Some(expected), "{output:?}");
            assert_eq!(
                read_text(&root.join("prepared/enforcement.status")).expect("durable status"),
                format!("{expected}\n")
            );
        }
    }
}

#[test]
fn enforcement_probe_reports_terminal_unit_failure_without_waiting_for_a_marker() {
    for (active, expected) in [
        ("activating", "pending\n"),
        ("active", "pending\n"),
        (
            "failed",
            "failed unit=failed result=exit-code status=209; completion marker missing\n",
        ),
        (
            "inactive",
            "failed unit=inactive result=exit-code status=209; completion marker missing\n",
        ),
    ] {
        let temp = TestDir::new();
        fs::create_dir(temp.path().join("prepared")).expect("prepared");
        let script = include_str!("../../../scripts/e2e/provision.sh").replace(
            "readonly BASE=/opt/kidobo-e2e PREPARED=/opt/kidobo-e2e/prepared",
            "readonly BASE=\"$FIXTURE_ROOT\" PREPARED=\"$FIXTURE_ROOT/prepared\"",
        );
        fs::write(temp.path().join("provision.sh"), script).expect("script");
        let output = run(
            temp.path(),
            &format!(
                r#"
set -euo pipefail
source "$FIXTURE_ROOT/provision.sh"
require_guest() {{ :; }}
systemctl() {{
  case "$*" in
    *--property=ActiveState*) printf '%s\n' '{active}' ;;
    *--property=Result*) printf 'exit-code\n' ;;
    *--property=ExecMainStatus*) printf '209\n' ;;
    *) exit 99 ;;
  esac
}}
provision_main --enforcement-status
"#
            ),
        );
        assert!(output.status.success(), "{output:?}");
        assert_eq!(String::from_utf8_lossy(&output.stdout), expected);
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("E2E_CHECK\tprepared enforcement status observed\tPASS")
        );
    }
}

#[test]
fn vendor_bootstrap_assertion_requires_durable_success_active_agent_and_selinux() {
    for (status, active, selinux, success) in [
        ("0", true, "Enforcing", true),
        ("", true, "Enforcing", false),
        ("1", true, "Enforcing", false),
        ("0", false, "Enforcing", false),
        ("0", true, "Permissive", false),
    ] {
        let temp = TestDir::new();
        fs::write(temp.path().join("bootstrap.status"), status).expect("status");
        let script = include_str!("../../../scripts/e2e/provision.sh").replace(
            "/var/log/kidobo-image-bootstrap.status",
            "${FIXTURE_ROOT}/bootstrap.status",
        );
        fs::write(temp.path().join("provision.sh"), script).expect("script");
        let output = run(
            temp.path(),
            &format!(
                r#"
set -euo pipefail
source "$FIXTURE_ROOT/provision.sh"
require_guest() {{ :; }}
systemctl() {{ [[ '{active}' == true ]]; }}
getenforce() {{ printf '%s\n' '{selinux}'; }}
provision_main --check-bootstrap
"#
            ),
        );
        assert_eq!(output.status.success(), success, "{output:?}");
        let expected = if success { "PASS" } else { "FAIL" };
        assert!(String::from_utf8_lossy(&output.stderr).contains(&format!(
            "E2E_CHECK\tvendor image agent bootstrap\t{expected}"
        )));
    }
}

#[test]
fn vendor_bootstrap_installs_agent_and_cleans_the_mount_on_failure() {
    for (scenario, expected_status) in [("success", 0), ("installer", 17), ("layout", 1)] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir(root.join("agent")).expect("agent config disk mount");
        fs::write(
            root.join("agent/install.sh"),
            if scenario == "installer" {
                "exit 17\n"
            } else {
                "exit 0\n"
            },
        )
        .expect("inert installer");
        let script = include_str!("../../../scripts/e2e/bootstrap.sh")
            .replace("/mnt/incus-agent", "${FIXTURE_ROOT}/agent")
            .replace(
                "/var/log/kidobo-image-bootstrap",
                "${FIXTURE_ROOT}/bootstrap",
            )
            .replace("/etc/systemd/system", "${FIXTURE_ROOT}/units");
        fs::write(root.join("bootstrap.sh"), script).expect("isolated script");
        let output = run(
            root,
            &format!(
                r#"
set -euo pipefail
systemd-detect-virt() {{ [[ "$*" == --vm ]]; }}
mount() {{ printf 'mount %s\n' "$*" >> "$FIXTURE_ROOT/events"; }}
umount() {{ printf 'umount\n' >> "$FIXTURE_ROOT/events"; }}
systemctl() {{
  printf 'systemctl %s\n' "$*" >> "$FIXTURE_ROOT/events"
  if [[ "$1" == show ]]; then
    if [[ '{scenario}' == layout ]]; then printf '{{ path=/unknown ; }}\n'; else printf '{{ path=/run/incus_agent/incus-agent ; }}\n'; fi
  fi
}}
getenforce() {{ printf 'Enforcing\n'; }}
source "$FIXTURE_ROOT/bootstrap.sh"
"#
            ),
        );
        assert_eq!(output.status.code(), Some(expected_status), "{output:?}");
        assert_eq!(
            read_text(&root.join("bootstrap.status")).expect("durable bootstrap status"),
            format!("{expected_status}\n")
        );
        let events = read_text(&root.join("events")).expect("bootstrap events");
        assert!(events.starts_with("mount -o ro /dev/disk/by-label/incus-agent "));
        assert_eq!(events.lines().filter(|line| *line == "umount").count(), 1);
        if scenario == "success" {
            assert!(events.contains("systemctl start incus-agent.service"));
            assert_eq!(
                read_text(&root.join("units/incus-agent.service.d/kidobo-e2e-selinux.conf"))
                    .expect("bounded agent accommodation"),
                "[Service]\nExecStartPre=/usr/bin/chcon -t bin_t /run/incus_agent/incus-agent\n"
            );
        } else {
            assert!(!events.contains("systemctl start"));
        }
    }
}

#[test]
fn pristine_image_rejects_existing_or_dangling_kidobo_artifacts() {
    for dangling in [false, true] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir_all(root.join("usr/local/bin")).expect("binary directory");
        let artifact = root.join("usr/local/bin/kidobo");
        if dangling {
            std::os::unix::fs::symlink("/does-not-exist", &artifact).expect("dangling artifact");
        } else {
            fs::write(&artifact, "candidate").expect("candidate artifact");
        }
        let function = helper("assert_pristine", "write_environment")
            .replace("/usr/", "${FIXTURE_ROOT}/usr/")
            .replace("/etc/", "${FIXTURE_ROOT}/etc/")
            .replace("/var/", "${FIXTURE_ROOT}/var/");
        let body = format!(
            "set -euo pipefail\nfail() {{ printf '%s\\n' \"$*\" >&2; exit 1; }}\n{function}\nassert_pristine\n"
        );
        let output = run(root, &body);
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("contains Kidobo state"));
    }
}

#[test]
fn preparation_upgrade_reuses_metadata_and_accepts_only_zypper_reboot_statuses() {
    for (family, manager, accepted) in [
        ("apt", "apt-get <-y> <full-upgrade>", false),
        ("dnf", "dnf <-y> <upgrade>", false),
        ("dnf-epel", "dnf <-y> <upgrade>", false),
        (
            "zypper",
            "zypper <--no-refresh> <--non-interactive> <update>",
            true,
        ),
    ] {
        for status in [0, 102, 103, 7] {
            let temp = TestDir::new();
            let root = temp.path();
            fs::write(root.join("provision.txt"), "family=test\n").expect("metadata");
            let functions = helper("run_upgrade", "prepare_agent_selinux");
            let body = format!(
                r#"
set -euo pipefail
exec 9>&2
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
package_manager() {{
  printf '%s' "$1" >> "$PREPARED/events"
  shift
  for argument in "$@"; do printf ' <%s>' "$argument" >> "$PREPARED/events"; done
  printf '\n' >> "$PREPARED/events"
  return {status}
}}
apt-get() {{ package_manager apt-get "$@"; }}
dnf() {{ package_manager dnf "$@"; }}
zypper() {{ package_manager zypper "$@"; }}
record_packages() {{ printf 'inventory\n' >> "$PREPARED/events"; printf 'pkg=1\n' > "$2"; }}
{functions}
upgrade_operating_system {family}
"#
            );
            let output = run(root, &body);
            let events = read_text(&root.join("events")).expect("package events");
            let succeeds = status == 0 || (accepted && matches!(status, 102 | 103));
            assert!(events.starts_with(&format!("{manager}\n")));
            if succeeds {
                assert!(output.status.success(), "{family} {status}: {output:?}");
                assert_eq!(events, format!("{manager}\ninventory\n"));
                assert!(
                    read_text(&root.join("provision.txt"))
                        .expect("completed metadata")
                        .contains("os_upgrade_completed_utc=")
                );
            } else {
                assert_eq!(output.status.code(), Some(status));
                assert_eq!(events, format!("{manager}\n"));
                assert!(!root.join("packages.txt").exists());
                assert!(
                    !read_text(&root.join("provision.txt"))
                        .expect("failed metadata")
                        .contains("os_upgrade_completed_utc=")
                );
            }
        }
    }
}
