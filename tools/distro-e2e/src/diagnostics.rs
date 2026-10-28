//! Agent-independent evidence captured before guest restart or deletion.
use crate::{Result, Runner, read_text, strings};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

const LOG_LIMIT: u64 = 1024 * 1024;

pub(super) fn collect(runner: &mut Runner, vm: &str, target: &Path) -> Vec<String> {
    let mut errors = Vec::new();
    if let Err(error) = runner.verify(vm) {
        return vec![format!("host diagnostics ownership: {error}")];
    }
    let directory = target.join("host-diagnostics");
    if let Err(error) = fs::create_dir_all(&directory) {
        return vec![format!("host diagnostics directory: {error}")];
    }
    let console = strings(&["--project", &runner.project, "console", vm, "--show-log"]);
    if let Err(error) = capture(runner, &console, &directory.join("console.log")) {
        errors.push(format!("serial console: {error}"));
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
            errors.push(format!("runtime log listing: {error}"));
            // qemu.log is the standard VM log; still attempt it if listing failed.
            json!([format!("{prefix}/qemu.log")])
        }
    };
    if let Some(logs) = logs.as_array() {
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
                    errors.push(format!("runtime {name}: {error}"));
                }
            }
        }
    } else {
        errors.push("runtime log listing is not an array".into());
    }
    errors
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
        let errors = collect(&mut runner, "vm-foreign", temp.path());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("unowned"));
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
}
