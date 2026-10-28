//! Bounded guest snapshots and agent-independent host diagnostics.
use crate::{Result, Runner, read_text, strings};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const LOG_LIMIT: u64 = 1024 * 1024;
const VM_CONSOLE_UNSUPPORTED: &str = "Error: Instance is not container type\n";

const PRE_REBOOT_SNAPSHOT: &str = r#"set -uo pipefail
capture_failed=0
attempt() {
    "$@" || { status=$?; printf 'WARNING: snapshot command failed (%s): %s\n' "$status" "$*" >&2; capture_failed=1; }
}
printf '%s\n' '=== pre-reboot snapshot ===' '=== running kernel ==='
attempt uname -a
printf '%s\n' '=== boot ID ==='
attempt cat /proc/sys/kernel/random/boot_id
printf '%s\n' '=== kernel command line ==='
attempt cat /proc/cmdline
printf '%s\n' '=== relabel scheduled ==='
attempt cat /opt/kidobo-e2e/prepared/relabel-scheduled
optional() {
    if command -v "$1" >/dev/null 2>&1; then attempt "$@"
    else printf 'WARNING: unavailable tool: %s\n' "$1"; fi
}
read_file() {
    if [[ -e "$1" || -L "$1" ]]; then
        printf '\n=== %s ===\n' "$1"
        attempt cat "$1"
    else printf 'WARNING: absent file: %s\n' "$1"; fi
}
shopt -s nullglob
for file in /etc/os-release /etc/kernel/cmdline /etc/default/grub /etc/default/grub.d/* \
    /etc/grub2.cfg /etc/grub2-efi.cfg /boot/grub/grub.cfg /boot/grub2/grub.cfg \
    /boot/loader/loader.conf /boot/loader/entries/*.conf \
    /etc/selinux/config /.autorelabel /sys/fs/selinux/enforce \
    /opt/kidobo-e2e/prepared/relabel-boot-id; do
    read_file "$file"
done
for directory in /boot/grub /boot/grub2 /boot/efi/EFI; do
    if [[ -d "$directory" ]]; then
        if ! listing=$(find "$directory" -maxdepth 4 -type f \( -name grub.cfg -o -name grubenv \)); then
            printf 'WARNING: cannot list boot diagnostics: %s\n' "$directory" >&2
            capture_failed=1
        fi
        while IFS= read -r file; do
            [[ -n "$file" ]] || continue
            read_file "$file"
            if [[ "$file" == */grubenv ]]; then
                if command -v grub2-editenv >/dev/null 2>&1; then attempt grub2-editenv "$file" list
                elif command -v grub-editenv >/dev/null 2>&1; then attempt grub-editenv "$file" list; fi
            fi
        done <<< "$listing"
    fi
done
printf '\n%s\n' '=== boot selection ==='
optional grubby --default-kernel
optional grubby --info=ALL
printf '\n%s\n' '=== SELinux state ==='
optional getenforce
optional sestatus
printf '\n%s\n' '=== agent and relabel units and configuration ==='
if command -v systemctl >/dev/null 2>&1; then
    for unit in incus-agent.service incus-agent-setup.service lxd-agent.service selinux-autorelabel.service kidobo-e2e-enforce.service; do
        if load=$(systemctl show "$unit" --property=LoadState --value); then
            load_status=0
        else load_status=$?; fi
        printf '%s LoadState=%s\n' "$unit" "$load"
        [[ "$load" != not-found ]] || continue
        if (( load_status != 0 )); then
            printf 'WARNING: systemd diagnostic query failed (%s): %s\n' "$load_status" "$unit" >&2
            capture_failed=1
            continue
        fi
        attempt systemctl cat "$unit"
        attempt systemctl show "$unit" --property=ActiveState,SubState,FragmentPath,DropInPaths,ExecStart,ExecStartPre
    done
else printf '%s\n' 'WARNING: unavailable tool: systemctl'; fi
printf '\n%s\n' '=== agent executable and configuration labels ==='
for directory in /run/incus_agent /run/lxd_agent /var/lib/incus-agent /var/lib/lxd-agent; do
    if [[ -d "$directory" ]]; then
        attempt ls -ldZ "$directory"
        attempt find "$directory" -maxdepth 2 -type f -exec ls -lZ -- '{}' +
    fi
done
for file in /usr/bin/incus-agent /usr/sbin/incus-agent /usr/bin/lxd-agent; do
    if [[ -e "$file" || -L "$file" ]]; then attempt ls -lZ -- "$file"; fi
done
printf '\n%s\n' '=== recent agent and relabel journal ==='
optional journalctl -b --no-pager -n 250 -u incus-agent.service -u incus-agent-setup.service -u lxd-agent.service -u selinux-autorelabel.service -u kidobo-e2e-enforce.service
exit "$capture_failed"
"#;

pub(super) fn pre_reboot(runner: &mut Runner, vm: &str, target: &Path) -> Result<Option<String>> {
    runner.verify(vm)?;
    let directory = target.join("pre-reboot");
    let outcome = (|| -> Result<()> {
        fs::create_dir_all(&directory)?;
        capture(
            runner,
            &strings(&[
                "--project",
                &runner.project,
                "exec",
                vm,
                "--mode=non-interactive",
                "--",
                "bash",
                "-c",
                PRE_REBOOT_SNAPSHOT,
            ]),
            &directory.join("snapshot.log"),
        )
    })();
    runner.report.ensure_healthy()?;
    Ok(outcome
        .err()
        .map(|error| format!("pre-reboot snapshot: {error}")))
}

pub(super) fn vendor_guest(runner: &mut Runner, vm: &str, target: &Path) -> Result<Option<String>> {
    runner.verify(vm)?;
    let script = r#"set -uo pipefail
failed=0
attempt() {
    "$@" || { status=$?; printf 'WARNING: vendor diagnostic capture failed (%s): %s\n' "$status" "$*" >&2; failed=1; }
}
for file in /var/log/kidobo-image-bootstrap.log /var/log/kidobo-image-bootstrap.status; do
    printf '\n=== %s ===\n' "$file"
    attempt cat "$file"
done
printf '\n%s\n' '=== cloud-init completion ==='
cloud-init status --long
status=$?
if [[ "$status" != 0 && "$status" != 2 ]]; then
    printf 'WARNING: cloud-init diagnostic command failed (%s)\n' "$status" >&2
    failed=1
fi
printf '\n%s\n' '=== bootstrap and enforcement journals ==='
attempt journalctl -b --no-pager -n 250 -u cloud-final.service -u incus-agent.service -u kidobo-e2e-enforce.service
exit "$failed"
"#;
    let outcome = (|| -> Result<()> {
        fs::create_dir_all(target)?;
        capture(
            runner,
            &strings(&[
                "--project",
                &runner.project,
                "exec",
                vm,
                "--mode=non-interactive",
                "--",
                "bash",
                "-c",
                script,
            ]),
            &target.join("vendor-guest-diagnostics.log"),
        )
    })();
    runner.report.ensure_healthy()?;
    Ok(outcome
        .err()
        .map(|error| format!("vendor guest diagnostics: {error}")))
}

#[derive(Default, serde::Serialize)]
pub(super) struct Diagnostics {
    pub(super) errors: Vec<String>,
    pub(super) warnings: Vec<String>,
}

pub(super) fn collect(runner: &mut Runner, vm: &str, target: &Path) -> Diagnostics {
    let mut diagnostics = Diagnostics::default();
    if let Err(error) = runner.verify(vm) {
        diagnostics
            .errors
            .push(format!("host diagnostics ownership: {error}"));
        return diagnostics;
    }
    let directory = target.join("host-diagnostics");
    if let Err(error) = fs::create_dir_all(&directory) {
        diagnostics
            .warnings
            .push(format!("host diagnostics directory: {error}"));
        return diagnostics;
    }
    let console = strings(&["--project", &runner.project, "console", vm, "--show-log"]);
    let console_log = directory.join("console.log");
    if let Err(error) = capture(runner, &console, &console_log) {
        match record_unsupported_console(&console_log) {
            Ok(true) => {
                let warning = format!(
                    "{vm}: Incus does not support saved serial-console logs for VMs; QEMU logs are collected separately"
                );
                if let Err(error) = runner.report.emit(&format!("WARNING: {warning}")) {
                    diagnostics
                        .errors
                        .push(format!("serial-console warning: {error}"));
                }
                diagnostics.warnings.push(warning);
            }
            Ok(false) => diagnostics
                .warnings
                .push(format!("serial console: {error}")),
            Err(classification) => diagnostics.warnings.push(format!(
                "serial console: {error}; classify capture: {classification}"
            )),
        }
    }
    let prefix = format!("/1.0/instances/{vm}/logs");
    let listing = directory.join("available-logs.json");
    let available = (|| -> Result<Value> {
        capture(
            runner,
            &strings(&["query", &format!("{prefix}?project={}", runner.project)]),
            &listing,
        )?;
        Ok(serde_json::from_str(&read_text(&listing)?)?)
    })();
    let logs = match available {
        Ok(value) => value.get("metadata").cloned().unwrap_or(value),
        Err(error) => {
            diagnostics
                .warnings
                .push(format!("runtime log listing: {error}"));
            // qemu.log is the standard VM log; still attempt it if listing failed.
            json!([format!("{prefix}/qemu.log")])
        }
    };
    if let Some(logs) = logs.as_array() {
        if !logs
            .iter()
            .any(|entry| entry == &format!("{prefix}/qemu.log"))
        {
            diagnostics
                .warnings
                .push("runtime qemu.log is not advertised by Incus".into());
        }
        // Do not follow arbitrary server-provided URLs or retrieve exec output.
        for name in ["qemu.log", "qemu.early.log"] {
            let path = format!("{prefix}/{name}");
            if logs.iter().any(|entry| entry == &path) {
                let args = strings(&[
                    "query",
                    "--raw",
                    &format!("{path}?project={}", runner.project),
                ]);
                if let Err(error) = capture(runner, &args, &directory.join(name)) {
                    diagnostics
                        .warnings
                        .push(format!("runtime {name}: {error}"));
                }
            }
        }
    } else {
        diagnostics
            .warnings
            .push("runtime log listing is not an array".into());
    }
    if runner.report.failed() {
        diagnostics
            .errors
            .push("could not retain authoritative diagnostic command report".into());
    }
    diagnostics
}

fn record_unsupported_console(destination: &Path) -> Result<bool> {
    let sidecar = destination.with_extension("capture.json");
    let mut metadata: Value = serde_json::from_str(&read_text(&sidecar)?)?;
    if metadata["exit_status"] != json!([1, 0])
        || metadata["truncated"] != false
        || read_text(destination)? != VM_CONSOLE_UNSUPPORTED
    {
        return Ok(false);
    }
    // This exception is reached only after verifying an owned virtual machine.
    // Retain the failed command's raw status and response for compatibility evidence.
    metadata["status"] = json!("unsupported");
    metadata["unsupported_reason"] =
        json!("Incus server restricts saved console logs to containers");
    fs::write(sidecar, serde_json::to_vec_pretty(&metadata)?)?;
    Ok(true)
}

fn capture(runner: &mut Runner, args: &[String], destination: &Path) -> Result<()> {
    capture_with_timeout(runner, args, destination, 30)
}

fn capture_with_timeout(
    runner: &mut Runner,
    args: &[String],
    destination: &Path,
    seconds: u64,
) -> Result<()> {
    // Head bounds storage even for continuously producing commands. Disable its
    // buffering so a timeout or cancellation retains even short partial output.
    let script = r#"destination=$1
limit=$2
shift 2
"$@" 2>&1 | stdbuf -o0 head -c "$limit" > "$destination"
statuses=("${PIPESTATUS[@]}")
printf '%s %s\n' "${statuses[0]}" "${statuses[1]}"
"#;
    let mut command = strings(&[
        "-c",
        script,
        "kidobo-host-diagnostics",
        &destination.to_string_lossy(),
        &(LOG_LIMIT + 1).to_string(),
        &runner.incus_program.to_string_lossy(),
    ]);
    command.extend_from_slice(args);
    fs::File::create(destination)?;
    let outcome = runner.command("bash", &command, seconds);
    let bytes = fs::metadata(destination)?.len();
    let truncated = bytes > LOG_LIMIT;
    if truncated {
        fs::OpenOptions::new()
            .write(true)
            .open(destination)?
            .set_len(LOG_LIMIT)?;
    }
    let mut command_status = None;
    let result = outcome.and_then(|text| {
        let statuses = text
            .split_whitespace()
            .map(str::parse::<i32>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        command_status = Some(statuses.clone());
        match statuses.as_slice() {
            [0 | 141, 0] if truncated => {
                Err(format!("diagnostic capture truncated at {LOG_LIMIT} bytes").into())
            }
            [0, 0] => Ok(()),
            [child, sink] => Err(format!("log command exit={child}, capture exit={sink}").into()),
            _ => Err("invalid diagnostic capture status".into()),
        }
    });
    fs::write(
        destination.with_extension("capture.json"),
        serde_json::to_vec_pretty(&json!({
            "arguments":args, "bytes":bytes.min(LOG_LIMIT), "truncated":truncated,
            "exit_status":command_status,
            "status":if result.is_ok() { "captured" } else { "failed" },
            "error":result.as_ref().err().map(ToString::to_string)
        }))?,
    )?;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TestDir, executable, runner_with_incus};
    use std::io::Read;

    #[test]
    fn pre_reboot_snapshot_refuses_unowned_guests_before_reading() {
        let temp = TestDir::new();
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            r#"#!/bin/bash
if [[ "$3" == list ]]; then
    printf '%s\n' '[{"name":"vm-foreign","type":"virtual-machine","config":{"user.kidobo-e2e":"someone-else"}}]'
else
    touch "$(dirname "$0")/unexpected-read"
    exit 99
fi
"#,
        );
        let mut runner = runner_with_incus(temp.path(), &program);
        assert!(
            pre_reboot(&mut runner, "vm-foreign", temp.path())
                .expect_err("ownership rejection")
                .to_string()
                .contains("unowned")
        );
        assert!(!temp.path().join("unexpected-read").exists());
        assert!(!temp.path().join("pre-reboot").exists());
    }

    #[test]
    fn pre_reboot_guest_reads_continue_after_missing_files_and_failed_tools() {
        let temp = TestDir::new();
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).expect("fake guest tools");
        for tool in ["uname", "cat", "find", "ls"] {
            std::os::unix::fs::symlink(format!("/usr/bin/{tool}"), bin.join(tool))
                .expect("read-only guest utility");
        }
        let mut script = PRE_REBOOT_SNAPSHOT.to_owned();
        for prefix in [
            "/opt/",
            "/proc/",
            "/etc/",
            "/sys/fs/",
            "/boot/",
            "/run/",
            "/var/",
            "/usr/",
            "/.autorelabel",
        ] {
            script = script.replace(prefix, &format!("{}{prefix}", temp.path().display()));
        }
        for (path, text) in [
            ("proc/sys/kernel/random/boot_id", "fixture-boot\n"),
            ("proc/cmdline", "fixture-command-line\n"),
            ("opt/kidobo-e2e/prepared/relabel-scheduled", "1\n"),
        ] {
            let path = temp.path().join(path);
            fs::create_dir_all(path.parent().expect("fixture parent")).expect("guest directories");
            fs::write(path, text).expect("guest identity");
        }
        let run = || {
            std::process::Command::new("/bin/bash")
                .args(["-c", &script])
                .env("PATH", &bin)
                .output()
                .expect("inert guest reads")
        };
        let output = run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = String::from_utf8(output.stdout).expect("snapshot text");
        assert!(output.contains("fixture-boot"));
        assert!(!output.contains("expected-kernel"));
        assert!(!output.contains("expected-initramfs"));
        assert!(output.contains("unavailable tool: grubby"));
        assert!(output.contains("unavailable tool: systemctl"));
        executable(
            &bin.join("systemctl"),
            "#!/bin/bash\nprintf 'not-found\\n'\nexit 4\n",
        );
        let output = run();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("lxd-agent.service LoadState=not-found")
        );
        executable(
            &bin.join("systemctl"),
            "#!/bin/bash\nprintf 'systemd query failed\\n' >&2\nexit 19\n",
        );
        let output = run();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("systemd query failed"));
        fs::remove_file(bin.join("systemctl")).expect("remove optional systemctl");
        executable(
            &bin.join("getenforce"),
            "#!/bin/bash\necho 'SELinux read failed' >&2\nexit 17\n",
        );
        let output = run();
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("SELinux read failed"));
        fs::remove_file(bin.join("getenforce")).expect("remove optional tool");
        fs::create_dir_all(temp.path().join("etc")).expect("guest etc");
        std::os::unix::fs::symlink("missing-grub", temp.path().join("etc/grub2.cfg"))
            .expect("dangling diagnostic symlink");
        let output = run();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("WARNING: snapshot command failed")
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("=== recent agent and relabel journal ===")
        );
    }

    #[test]
    fn bounded_capture_retains_partial_output_and_sidecar_after_timeout_or_cancellation() {
        for cancelled in [false, true] {
            let temp = TestDir::new();
            let program = temp.path().join("fake-incus");
            executable(
                &program,
                "#!/bin/bash\nprintf 'partial boot evidence\\n'\nsleep 60\n",
            );
            let mut runner = runner_with_incus(temp.path(), &program);
            let log = temp.path().join("snapshot.log");
            let cancellation = std::sync::Arc::clone(&runner.cancelled);
            let observed_log = log.clone();
            let watcher = cancelled.then(|| {
                std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                    while fs::metadata(&observed_log).map_or(true, |value| value.len() == 0)
                        && std::time::Instant::now() < deadline
                    {
                        std::thread::sleep(std::time::Duration::from_millis(5));
                    }
                    cancellation.store(true, std::sync::atomic::Ordering::Relaxed);
                })
            });
            let error = capture_with_timeout(&mut runner, &strings(&["exec", "vm"]), &log, 1)
                .expect_err("incomplete snapshot fails")
                .to_string();
            if let Some(watcher) = watcher {
                watcher.join().expect("cancel watcher");
            }
            let expected = if cancelled {
                "interrupted"
            } else {
                "timed out"
            };
            assert!(error.contains(expected), "{error}");
            assert_eq!(
                read_text(&log).expect("partial snapshot"),
                "partial boot evidence\n"
            );
            let metadata: Value = serde_json::from_str(
                &read_text(&log.with_extension("capture.json")).expect("sidecar"),
            )
            .expect("JSON");
            assert_eq!(metadata["status"], "failed");
            assert_eq!(metadata["exit_status"], Value::Null);
            assert_eq!(metadata["truncated"], false);
            assert!(
                metadata["error"]
                    .as_str()
                    .expect("capture reason")
                    .contains(expected)
            );
        }
    }

    #[test]
    fn host_logs_are_not_read_for_an_unowned_guest() {
        let temp = TestDir::new();
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            r#"#!/bin/bash
if [[ "$3" == list ]]; then
    printf '%s\n' '[{"name":"vm-foreign","type":"virtual-machine","config":{"user.kidobo-e2e":"someone-else"}}]'
else
    touch "$(dirname "$0")/unexpected-read"
    exit 99
fi
"#,
        );
        let mut runner = runner_with_incus(temp.path(), &program);
        let diagnostics = collect(&mut runner, "vm-foreign", temp.path());
        assert_eq!(diagnostics.errors.len(), 1);
        assert!(diagnostics.errors[0].contains("unowned"));
        assert_eq!(diagnostics.warnings, Vec::<String>::new());
        assert!(!temp.path().join("unexpected-read").exists());
        assert!(!temp.path().join("host-diagnostics").exists());
    }

    #[test]
    fn oversized_pre_reboot_stderr_is_bounded_and_marked_as_truncated() {
        let temp = TestDir::new();
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            r#"#!/bin/bash
if [[ "$3" == list ]]; then
    printf '%s\n' '[{"name":"vm-owned","type":"virtual-machine","config":{"user.kidobo-e2e":"kidobo-e2e-v1"}}]'
else
    [[ "$3" == exec && "$4" == vm-owned ]] || exit 99
    head -c 2097152 /dev/zero | tr '\000' '\377' >&2
fi
"#,
        );
        let mut runner = runner_with_incus(temp.path(), &program);
        let target = temp.path().join("target with spaces");
        assert!(
            pre_reboot(&mut runner, "vm-owned", &target)
                .expect("capture result")
                .expect("truncation warning")
                .contains("truncated")
        );
        let log = target.join("pre-reboot/snapshot.log");
        assert_eq!(fs::metadata(&log).expect("log metadata").len(), LOG_LIMIT);
        let mut bytes = [0; 4];
        fs::File::open(&log)
            .expect("binary log")
            .read_exact(&mut bytes)
            .expect("binary bytes");
        assert_eq!(bytes, [255; 4]);
        let metadata: Value = serde_json::from_str(
            &read_text(&log.with_extension("capture.json")).expect("capture metadata"),
        )
        .expect("JSON");
        assert_eq!(metadata["truncated"], true);
        assert!(
            metadata["error"]
                .as_str()
                .expect("truncation warning")
                .contains("truncated")
        );
    }

    #[test]
    fn failed_log_commands_keep_their_output_and_status() {
        let temp = TestDir::new();
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            "#!/bin/bash\necho 'partial output'\necho 'failure detail' >&2\nexit 23\n",
        );
        let mut runner = runner_with_incus(temp.path(), &program);
        let log = temp.path().join("qemu.log");
        let error = capture(&mut runner, &strings(&["query", "--raw", "/log"]), &log)
            .expect_err("producer failed")
            .to_string();
        assert_eq!(error, "log command exit=23, capture exit=0");
        assert_eq!(
            read_text(&log).expect("partial log"),
            "partial output\nfailure detail\n"
        );
        let metadata: Value = serde_json::from_str(
            &read_text(&log.with_extension("capture.json")).expect("capture metadata"),
        )
        .expect("JSON");
        assert_eq!(metadata["error"], error);
        assert_eq!(metadata["truncated"], false);
    }

    fn compatible_runner(temp: &TestDir, console: &str, status: i32, logs: &str) -> Runner {
        fs::write(temp.path().join("console-response"), console).expect("console response");
        fs::write(temp.path().join("console-exit"), status.to_string()).expect("console exit");
        fs::write(temp.path().join("log-mode"), logs).expect("runtime log mode");
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            r#"#!/bin/bash
set -eu
cd "$(dirname "$0")"
if [[ "$1" == --project ]]; then
    [[ "$2" == test-project ]]
    shift 2
fi
case "$1" in
    list) printf '%s\n' '[{"name":"vm-owned","type":"virtual-machine","config":{"user.kidobo-e2e":"kidobo-e2e-v1"}}]' ;;
    console) cat console-response >&2; exit "$(cat console-exit)" ;;
    query)
        case "${@: -1}" in
            '/1.0/instances/vm-owned/logs?project=test-project')
                if [[ "$(cat log-mode)" == missing ]]; then printf '[]\n'
                else printf '%s\n' '["/1.0/instances/vm-owned/logs/qemu.log"]'; fi ;;
            '/1.0/instances/vm-owned/logs/qemu.log?project=test-project')
                if [[ "$(cat log-mode)" == failure ]]; then echo 'Error: Permission denied' >&2; exit 1; fi
                echo 'QEMU boot evidence' ;;
            *) exit 99 ;;
        esac ;;
    *) exit 99 ;;
esac
"#,
        );
        runner_with_incus(temp.path(), &program)
    }

    #[test]
    fn supported_console_and_runtime_logs_are_captured() {
        let temp = TestDir::new();
        let mut runner = compatible_runner(&temp, "serial evidence\n", 0, "available");
        let diagnostics = collect(&mut runner, "vm-owned", temp.path());
        assert_eq!(diagnostics.errors, Vec::<String>::new());
        assert_eq!(diagnostics.warnings, Vec::<String>::new());
        let host = temp.path().join("host-diagnostics");
        assert_eq!(
            read_text(&host.join("console.log")).expect("console"),
            "serial evidence\n"
        );
        assert_eq!(
            read_text(&host.join("qemu.log")).expect("runtime"),
            "QEMU boot evidence\n"
        );
        let sidecar: Value =
            serde_json::from_str(&read_text(&host.join("console.capture.json")).expect("sidecar"))
                .expect("JSON");
        assert_eq!(sidecar["status"], "captured");
        assert_eq!(sidecar["exit_status"], json!([0, 0]));
    }

    #[test]
    fn exact_unsupported_vm_console_is_a_warning_with_raw_failure_preserved() {
        let temp = TestDir::new();
        let mut runner = compatible_runner(&temp, VM_CONSOLE_UNSUPPORTED, 1, "available");
        let diagnostics = collect(&mut runner, "vm-owned", temp.path());
        assert_eq!(diagnostics.errors, Vec::<String>::new());
        assert_eq!(diagnostics.warnings.len(), 1);
        assert!(
            diagnostics.warnings[0].contains("does not support saved serial-console logs for VMs")
        );
        let host = temp.path().join("host-diagnostics");
        assert_eq!(
            read_text(&host.join("console.log")).expect("raw response"),
            VM_CONSOLE_UNSUPPORTED
        );
        let sidecar: Value =
            serde_json::from_str(&read_text(&host.join("console.capture.json")).expect("sidecar"))
                .expect("JSON");
        assert_eq!(sidecar["status"], "unsupported");
        assert_eq!(sidecar["exit_status"], json!([1, 0]));
        assert_eq!(sidecar["error"], "log command exit=1, capture exit=0");
        assert_eq!(
            sidecar["unsupported_reason"],
            "Incus server restricts saved console logs to containers"
        );
        assert!(
            read_text(&temp.path().join("transcript.log"))
                .expect("transcript")
                .contains("WARNING: vm-owned:")
        );
    }

    #[test]
    fn other_console_failures_are_not_compatibility_exceptions() {
        for (response, status) in [
            (VM_CONSOLE_UNSUPPORTED, 2),
            ("Error: Permission denied\n", 1),
            (
                "Error: Instance is not container type\nadditional failure\n",
                1,
            ),
        ] {
            let temp = TestDir::new();
            let mut runner = compatible_runner(&temp, response, status, "available");
            let diagnostics = collect(&mut runner, "vm-owned", temp.path());
            assert_eq!(diagnostics.errors, Vec::<String>::new());
            assert_eq!(diagnostics.warnings.len(), 1);
            assert!(diagnostics.warnings[0].starts_with("serial console:"));
        }
    }

    #[test]
    fn missing_or_failed_runtime_logs_are_warnings_with_other_captures_preserved() {
        for (mode, expected) in [
            ("missing", "not advertised"),
            ("failure", "runtime qemu.log"),
        ] {
            let temp = TestDir::new();
            let mut runner = compatible_runner(&temp, VM_CONSOLE_UNSUPPORTED, 1, mode);
            let diagnostics = collect(&mut runner, "vm-owned", temp.path());
            assert_eq!(diagnostics.warnings.len(), 2);
            assert_eq!(diagnostics.errors, Vec::<String>::new());
            assert!(diagnostics.warnings[1].contains(expected));
        }
    }

    #[test]
    fn incomplete_capture_status_cannot_be_classified_as_unsupported() {
        let temp = TestDir::new();
        let path = temp.path().join("console.log");
        fs::write(&path, VM_CONSOLE_UNSUPPORTED).expect("partial response");
        for metadata in [
            json!({"exit_status":null,"truncated":false,"error":"timed out"}),
            json!({"exit_status":[1,0],"truncated":true,"error":"truncated capture"}),
            json!({"exit_status":[1,1],"truncated":false,"error":"capture failed"}),
        ] {
            fs::write(
                path.with_extension("capture.json"),
                serde_json::to_vec(&metadata).expect("JSON"),
            )
            .expect("capture status");
            assert!(!record_unsupported_console(&path).expect("classification"));
        }
    }
}
