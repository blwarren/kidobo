//! Shared command execution helpers.

use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use crate::command_runner::{CommandResult, ProcessStatus};

/// Renders a command and its arguments for bounded operator diagnostics.
pub fn display_command<S: AsRef<str>>(command: &str, args: &[S]) -> String {
    if args.is_empty() {
        command.to_string()
    } else {
        let rendered_args = args.iter().map(AsRef::as_ref).collect::<Vec<_>>().join(" ");
        format!("{command} {rendered_args}")
    }
}

#[must_use]
/// Finds the first regular executable file named `binary` in an explicit native `PATH` value.
pub fn find_executable_in_path(binary: &str, path: Option<OsString>) -> Option<PathBuf> {
    let path = path?;
    env::split_paths(&path)
        .map(|directory| directory.join(binary))
        .find(|candidate| is_executable_file(candidate))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };

    if !metadata.is_file() {
        return false;
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        metadata.permissions().mode() & 0o111 != 0
    }

    #[cfg(not(unix))]
    {
        true
    }
}

/// Returns a successful command result or maps its unsuccessful status to `E`.
///
/// # Errors
///
/// Returns the error produced by `build_error` when the command status is unsuccessful.
pub fn ensure_command_succeeded<E, F>(
    result: CommandResult,
    command: &str,
    args: &[&str],
    build_error: F,
) -> Result<CommandResult, E>
where
    F: FnOnce(String, ProcessStatus, String) -> E,
{
    if result.status.success() {
        return Ok(result);
    }

    Err(build_error(
        display_command(command, args),
        result.status,
        result.stderr,
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    use tempfile::TempDir;

    use super::{display_command, ensure_command_succeeded, find_executable_in_path};
    use crate::command_runner::CommandResult;

    #[test]
    fn display_command_renders_command_and_args() {
        assert_eq!(display_command("ipset", &[] as &[&str]), "ipset");
        assert_eq!(
            display_command("iptables", &["-A", "INPUT", "-j", "DROP"]),
            "iptables -A INPUT -j DROP"
        );
        assert_eq!(
            display_command(
                "sudo",
                &[
                    "ipset".to_string(),
                    "list".to_string(),
                    "kidobo".to_string()
                ]
            ),
            "sudo ipset list kidobo"
        );
    }

    #[test]
    fn ensure_command_succeeded_passes_success_through() {
        let result = CommandResult {
            status: crate::command_runner::ProcessStatus::Exited(0),
            stdout: "ok".to_string(),
            stderr: String::new(),
        };
        let output = ensure_command_succeeded(result, "ipset", &["list"], |_, _, _| ())
            .expect("success should pass through");
        assert_eq!(output.stdout, "ok");
    }

    #[cfg(unix)]
    #[test]
    fn find_executable_in_path_returns_executable_candidate() {
        let temp = TempDir::new().expect("tempdir");
        let executable = temp.path().join("bgpq4");
        fs::write(&executable, "#!/bin/sh\n").expect("write executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("chmod");

        let path = std::env::join_paths([temp.path()]).expect("PATH");
        assert_eq!(
            find_executable_in_path("bgpq4", Some(path)),
            Some(executable)
        );
    }

    #[cfg(unix)]
    #[test]
    fn find_executable_in_path_skips_non_executable_files() {
        let temp = TempDir::new().expect("tempdir");
        let executable = temp.path().join("ipset");
        fs::write(&executable, "not executable").expect("write file");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o644)).expect("chmod");

        let path = std::env::join_paths([temp.path()]).expect("PATH");
        assert_eq!(find_executable_in_path("ipset", Some(path)), None);
    }
}
