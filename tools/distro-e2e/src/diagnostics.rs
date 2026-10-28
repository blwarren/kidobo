//! Agent-independent evidence captured before guest restart or deletion.
use crate::{Result, Runner, read_text, strings};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const LOG_LIMIT: u64 = 1024 * 1024;
const VM_CONSOLE_UNSUPPORTED: &str = "Error: Instance is not container type\n";

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
            .errors
            .push(format!("host diagnostics directory: {error}"));
        return diagnostics;
    }
    let console = strings(&["--project", &runner.project, "console", vm, "--show-log"]);
    let console_log = directory.join("console.log");
    if let Err(error) = capture(runner, &console, &console_log) {
        match record_unsupported_console(&console_log) {
            Ok(true) => {
                let warning = format!(
                    "{vm}: Incus does not support saved serial-console logs for VMs; qemu.log remains required"
                );
                if let Err(error) = runner.report.emit(&format!("WARNING: {warning}")) {
                    diagnostics
                        .errors
                        .push(format!("serial-console warning: {error}"));
                }
                diagnostics.warnings.push(warning);
            }
            Ok(false) => diagnostics.errors.push(format!("serial console: {error}")),
            Err(classification) => diagnostics.errors.push(format!(
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
                .errors
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
                .errors
                .push("required runtime qemu.log is not advertised by Incus".into());
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
                    diagnostics.errors.push(format!("runtime {name}: {error}"));
                }
            }
        }
    } else {
        diagnostics
            .errors
            .push("runtime log listing is not an array".into());
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
    // Head bounds storage even for continuously producing commands. Keep stderr in
    // the artifact so failed API requests retain their explanation as well.
    let script = r#"destination=$1
limit=$2
shift 2
"$@" 2>&1 | head -c "$limit" > "$destination"
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
    let outcome = runner.command("bash", &command, 30);
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
            [0, 0] => Ok(()),
            [141, 0] if truncated => Ok(()),
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
    fn oversized_binary_stderr_is_bounded_and_marked_as_truncated() {
        let temp = TestDir::new();
        let program = temp.path().join("fake-incus");
        executable(
            &program,
            "#!/bin/bash\nhead -c 2097152 /dev/zero | tr '\\000' '\\377' >&2\n",
        );
        let mut runner = runner_with_incus(temp.path(), &program);
        let log = temp.path().join("console with spaces.log");
        capture(
            &mut runner,
            &strings(&["console", "fixture", "--show-log"]),
            &log,
        )
        .expect("bounded capture");
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
        assert_eq!(metadata["error"], Value::Null);
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
    fn supported_console_and_required_runtime_logs_are_captured() {
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
            assert_eq!(diagnostics.errors.len(), 1);
            assert!(diagnostics.errors[0].starts_with("serial console:"));
            assert_eq!(diagnostics.warnings, Vec::<String>::new());
        }
    }

    #[test]
    fn unsupported_console_does_not_excuse_missing_or_failed_runtime_logs() {
        for (mode, expected) in [
            ("missing", "not advertised"),
            ("failure", "runtime qemu.log"),
        ] {
            let temp = TestDir::new();
            let mut runner = compatible_runner(&temp, VM_CONSOLE_UNSUPPORTED, 1, mode);
            let diagnostics = collect(&mut runner, "vm-owned", temp.path());
            assert_eq!(diagnostics.warnings.len(), 1);
            assert_eq!(diagnostics.errors.len(), 1);
            assert!(diagnostics.errors[0].contains(expected));
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
