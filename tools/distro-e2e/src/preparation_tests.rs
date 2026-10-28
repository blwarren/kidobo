//! Guest preparation regressions use extracted helpers and inert command boundaries.
use super::{read_text, tests::TestDir};
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
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

fn digest(bytes: &[u8]) -> String {
    let mut text = String::new();
    for byte in Sha256::digest(bytes) {
        write!(text, "{byte:02x}").expect("format test digest");
    }
    text
}

#[test]
fn kernel_mismatch_fails_before_loading_modules_or_touching_firewalls() {
    let temp = TestDir::new();
    let root = temp.path();
    fs::write(root.join("expected-kernel"), "6.12.0-new\n").expect("expected kernel");
    fs::write(root.join("expected-initramfs"), "/unused\n").expect("initramfs");
    let body = format!(
        r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
uname() {{ printf '6.12.0-old\n'; }}
capture_boot_diagnostics() {{ printf captured > "$PREPARED/diagnostic"; }}
verify_kernel_artifacts() {{ printf called >> "$PREPARED/side-effects"; }}
modprobe() {{ printf called >> "$PREPARED/side-effects"; }}
iptables() {{ printf called >> "$PREPARED/side-effects"; }}
ip6tables() {{ printf called >> "$PREPARED/side-effects"; }}
{}
verify_running_kernel
"#,
        helper("verify_running_kernel", "finish_selinux")
    );
    let output = run(root, &body);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("does not match intended kernel"));
    assert_eq!(
        read_text(&root.join("diagnostic")).expect("diagnostics"),
        "captured"
    );
    assert!(!root.join("side-effects").exists());
}

#[test]
fn intended_kernel_requires_all_module_files_before_selection_qualifies() {
    for missing in ["", "xt_set"] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir_all(root.join("boot")).expect("boot");
        fs::create_dir_all(root.join("lib/modules/6.12.0-new")).expect("modules");
        fs::write(root.join("boot/vmlinuz-6.12.0-new"), "kernel").expect("kernel");
        fs::write(root.join("boot/initramfs"), "initramfs").expect("initramfs");
        for module in ["ip_set", "xt_set", "ip_set_hash_net"] {
            if module != missing {
                fs::write(
                    root.join(format!("lib/modules/6.12.0-new/{module}.ko")),
                    "module",
                )
                .expect("module");
            }
        }
        let function = helper("verify_kernel_artifacts", "select_boot_kernel")
            .replace("/boot/", "${FIXTURE_ROOT}/boot/")
            .replace("/lib/modules/", "${FIXTURE_ROOT}/lib/modules/");
        let body = format!(
            r#"
set -euo pipefail
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
modinfo() {{ printf '%s/lib/modules/%s/%s.ko\n' "$FIXTURE_ROOT" "$2" "$4"; }}
{function}
verify_kernel_artifacts 6.12.0-new "$FIXTURE_ROOT/boot/initramfs"
"#
        );
        let output = run(root, &body);
        if missing.is_empty() {
            assert!(output.status.success(), "{output:?}");
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("module file is missing"));
        }
    }
}

#[test]
fn rpm_boot_default_must_match_the_selected_kernel() {
    for agrees in [true, false] {
        let temp = TestDir::new();
        let root = temp.path();
        fs::create_dir(root.join("boot")).expect("boot");
        fs::write(root.join("boot/initramfs-6.12.0-new.img"), "initramfs").expect("initramfs");
        let function = helper("select_boot_kernel", "prepare_selinux")
            .replace("/boot/", "${FIXTURE_ROOT}/boot/");
        let default = if agrees { "new" } else { "old" };
        let body = format!(
            r#"
set -euo pipefail
PREPARED=$FIXTURE_ROOT
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
grubby() {{
  if [[ "$1" == --default-kernel ]]; then printf '%s/boot/vmlinuz-6.12.0-{default}\n' "$FIXTURE_ROOT";
  else printf '%s\n' "$*" >> "$PREPARED/events"; fi
}}
verify_kernel_artifacts() {{ printf 'artifacts %s\n' "$1" >> "$PREPARED/events"; }}
{function}
select_boot_kernel dnf 6.12.0-new
"#
        );
        let output = run(root, &body);
        let events = read_text(&root.join("events")).expect("boot selection events");
        assert!(events.contains("--set-default"));
        if agrees {
            assert!(output.status.success(), "{output:?}");
            assert!(events.contains("artifacts 6.12.0-new"));
            assert_eq!(
                read_text(&root.join("expected-kernel")).expect("selected kernel"),
                "6.12.0-new\n"
            );
        } else {
            assert_eq!(output.status.code(), Some(1));
            assert!(
                String::from_utf8_lossy(&output.stderr)
                    .contains("did not select the intended kernel")
            );
            assert!(!root.join("expected-kernel").exists());
            assert!(!events.contains("artifacts"));
        }
    }
}

#[test]
fn latest_installed_kernel_ignores_apt_meta_packages_and_uses_version_order() {
    let temp = TestDir::new();
    let function = helper("installed_kernel", "verify_kernel_artifacts");
    let body = format!(
        r"
set -euo pipefail
fail() {{ exit 1; }}
dpkg-query() {{ printf 'installed linux-image-6.1.0-9-amd64\ninstalled linux-image-6.1.0-10-amd64\ninstalled linux-image-amd64\nconfig-files linux-image-6.1.0-99-amd64\n'; }}
rpm() {{ printf '6.12.0-211.9.el10.x86_64\n6.12.0-211.10.el10.x86_64\n'; }}
{function}
installed_kernel apt
installed_kernel dnf
"
    );
    let output = run(temp.path(), &body);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        b"6.1.0-10-amd64\n6.12.0-211.10.el10.x86_64\n"
    );
}

#[test]
fn disabled_selinux_is_prepared_for_permissive_relabel_before_enforcement() {
    let temp = TestDir::new();
    let root = temp.path();
    let config = root.join("selinux-config");
    fs::write(&config, "SELINUX=disabled\nSELINUXTYPE=targeted\n").expect("security config");
    let function = helper("prepare_selinux", "capture_boot_diagnostics")
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
fn sanitization_keeps_preparation_provenance_and_removes_instance_artifacts() {
    let temp = TestDir::new();
    let root = temp.path();
    for directory in [
        "base/prepared",
        "base/state",
        "base/release",
        "etc/ssh",
        "var/lib/dbus",
        "var/lib/dhcp",
        "var/lib/NetworkManager",
    ] {
        fs::create_dir_all(root.join(directory)).expect("fixture directory");
    }
    for (path, contents) in [
        ("base/prepared/manifest.json", "retained provenance"),
        ("base/provision.sh", "retained script"),
        ("base/state/old-run", "old application evidence"),
        ("base/release/candidate", "candidate"),
        ("etc/machine-id", "old identity"),
        ("var/lib/dbus/machine-id", "old identity"),
        ("etc/ssh/ssh_host_rsa_key", "old host key"),
        ("var/lib/dhcp/eth0.leases", "old lease"),
    ] {
        fs::write(root.join(path), contents).expect("fixture file");
    }
    let function = helper("sanitize_image", "admit_clone")
        .replace("/etc/", "${FIXTURE_ROOT}/etc/")
        .replace("/var/lib/", "${FIXTURE_ROOT}/var/lib/");
    let body = format!(
        r#"
set -euo pipefail
BASE=$FIXTURE_ROOT/base PREPARED=$FIXTURE_ROOT/base/prepared
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
assert_pristine() {{ :; }}
cloud-init() {{ printf '%s\n' "$*" > "$FIXTURE_ROOT/cloud-init-events"; }}
{function}
sanitize_image
"#
    );
    let output = run(root, &body);
    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        read_text(&root.join("base/prepared/manifest.json")).expect("provenance"),
        "retained provenance"
    );
    assert_eq!(
        read_text(&root.join("base/provision.sh")).expect("script"),
        "retained script"
    );
    assert_eq!(
        read_text(&root.join("etc/machine-id")).expect("machine id"),
        ""
    );
    assert!(!root.join("base/state").exists());
    assert!(!root.join("base/release").exists());
    assert!(!root.join("var/lib/dbus/machine-id").exists());
    assert!(!root.join("etc/ssh/ssh_host_rsa_key").exists());
    assert!(!root.join("var/lib/dhcp/eth0.leases").exists());
    assert_eq!(
        read_text(&root.join("cloud-init-events")).expect("cloud-init sanitation"),
        "clean --logs\n"
    );
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
#[expect(
    clippy::too_many_lines,
    reason = "One isolated clone fixture exercises independent admission failures against the same provenance"
)]
fn clone_admission_checks_identity_inventory_script_backends_and_security() {
    let kernel = read_text(std::path::Path::new("/proc/sys/kernel/osrelease"))
        .expect("read kernel identity");
    for scenario in [
        "valid",
        "same-id",
        "fresh",
        "corrupt-packages",
        "changed-packages",
        "corrupt-script",
        "backend-drift",
        "security-drift",
    ] {
        let temp = TestDir::new();
        let root = temp.path();
        for directory in ["base/prepared", "bin", "etc"] {
            fs::create_dir_all(root.join(directory)).expect("admission directory");
        }
        let machine_id = if matches!(scenario, "same-id" | "fresh") {
            "a".repeat(32)
        } else {
            "b".repeat(32)
        };
        fs::write(root.join("etc/machine-id"), machine_id).expect("clone machine ID");
        fs::write(root.join("boot-id"), "clone-boot\n").expect("clone boot ID");
        fs::write(
            root.join("base/provision.sh"),
            if scenario == "corrupt-script" {
                "changed"
            } else {
                "script"
            },
        )
        .expect("prepared script");
        fs::write(root.join("base/prepared/provision.txt"), "family=dnf\n").expect("metadata");
        fs::write(
            root.join("base/prepared/selinux-requested"),
            "image-default\n",
        )
        .expect("requested mode");
        fs::write(
            root.join("base/prepared/packages.txt"),
            if scenario == "corrupt-packages" {
                "changed\n"
            } else {
                "pkg=1\n"
            },
        )
        .expect("prepared inventory");
        let version4 = if scenario == "backend-drift" {
            "iptables v1.8.11 (nf_tables)"
        } else {
            "iptables v1.8.11 (legacy)"
        };
        for (command, output) in [
            ("iptables", version4),
            ("ip6tables", "ip6tables v1.8.11 (legacy)"),
            (
                "getenforce",
                if scenario == "security-drift" {
                    "Permissive"
                } else {
                    "Enforcing"
                },
            ),
        ] {
            super::tests::executable(
                &root.join("bin").join(command),
                &format!("#!/bin/sh\nprintf '%s\\n' '{output}'\n"),
            );
        }
        let manifest = serde_json::json!({
            "format": 1,
            "prepared_at_unix": 1,
            "source_machine_id": "a".repeat(32),
            "source_boot_id": "source-boot",
            "expected_kernel": kernel.trim(),
            "packages_sha256": digest(b"pkg=1\n"),
            "provision_sha256": digest(b"script"),
            "iptables_backend": "iptables v1.8.11 (legacy)",
            "ip6tables_backend": "ip6tables v1.8.11 (legacy)",
            "selinux_actual": "Enforcing",
        });
        fs::write(
            root.join("base/prepared/manifest.json"),
            serde_json::to_vec(&manifest).expect("manifest JSON"),
        )
        .expect("manifest");
        let function = helper("admit_clone", "provision_main")
            .replace(
                "/etc/machine-id",
                root.join("etc/machine-id")
                    .to_str()
                    .expect("machine ID path"),
            )
            .replace(
                "/proc/sys/kernel/random/boot_id",
                root.join("boot-id").to_str().expect("boot ID path"),
            )
            .replace(
                "/opt/kidobo-e2e/provision.sh",
                root.join("base/provision.sh")
                    .to_str()
                    .expect("provision path"),
            );
        let inventory = if scenario == "changed-packages" {
            "pkg=2"
        } else {
            "pkg=1"
        };
        let fresh = scenario == "fresh";
        let body = format!(
            r#"
set -euo pipefail
PATH="$FIXTURE_ROOT/bin:/usr/bin:/bin"
BASE=$FIXTURE_ROOT/base PREPARED=$FIXTURE_ROOT/base/prepared
fail() {{ printf '%s\n' "$*" >&2; exit 1; }}
assert_pristine() {{ :; }}
verify_running_kernel() {{ :; }}
wait_for_network() {{ :; }}
record_packages() {{ printf '{inventory}\n' > "$2"; }}
{function}
admit_clone {fresh}
"#
        );
        let output = run(root, &body);
        if matches!(scenario, "valid" | "fresh") {
            assert!(output.status.success(), "{scenario}: {output:?}");
            let admission: serde_json::Value = serde_json::from_str(
                &read_text(&root.join("base/prepared/admission.json")).expect("admission evidence"),
            )
            .expect("admission JSON");
            assert_eq!(admission["fresh_same_instance"], fresh);
            assert_eq!(admission["boot_id"], "clone-boot");
            assert_eq!(admission["selinux"], "Enforcing");
            assert_eq!(
                read_text(&root.join("base/state/packages.txt")).expect("runtime inventory"),
                "pkg=1\n"
            );
        } else {
            assert_eq!(output.status.code(), Some(1), "{scenario}: {output:?}");
            let expected = match scenario {
                "same-id" => "new valid machine ID",
                "corrupt-packages" => "inventory does not match provenance",
                "changed-packages" => "packages changed after preparation",
                "corrupt-script" => "script does not match provenance",
                "backend-drift" => "firewall backends changed after preparation",
                "security-drift" => "SELinux state changed after preparation",
                _ => unreachable!(),
            };
            assert!(
                String::from_utf8_lossy(&output.stderr).contains(expected),
                "{scenario}: {output:?}"
            );
            assert!(!root.join("base/state").exists());
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
        let function = helper("assert_pristine", "write_manifest")
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
            let functions = helper("run_upgrade", "installed_kernel");
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
