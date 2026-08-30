//! Filesystem and systemd implementation of init provisioning.

use std::fs;
use std::path::{Path, PathBuf};

use kidobo_app::AppError;
use kidobo_app::init::{
    InitProvisioner, KIDOBO_SYNC_SERVICE_FILE, KIDOBO_SYNC_TIMER_FILE, ProvisionState,
};

use crate::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner, SystemCommandExecutor,
};
use crate::limited_io::write_string_atomic;

/// Command boundary used for systemd initialization.
pub trait InitCommandRunner {
    /// Runs one noninteractive system command.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRunnerError`] when bounded command execution fails.
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> InitCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

/// Filesystem provisioner with an injected runner for live systemd operations.
#[derive(Debug)]
pub struct FileInitProvisioner<R> {
    runner: R,
}

impl<R> FileInitProvisioner<R> {
    #[must_use]
    /// Creates an initialization provisioner around the supplied command runner.
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl Default for FileInitProvisioner<SudoCommandRunner<SystemCommandExecutor>> {
    fn default() -> Self {
        Self::new(SudoCommandRunner::default())
    }
}

/// Production initialization provisioner using noninteractive bounded sudo commands.
pub type SystemInitProvisioner = FileInitProvisioner<SudoCommandRunner<SystemCommandExecutor>>;

impl<R: InitCommandRunner> InitProvisioner for FileInitProvisioner<R> {
    fn resolve_installed_executable(&self, candidates: &[PathBuf]) -> Result<PathBuf, AppError> {
        candidates
            .iter()
            .find(|candidate| candidate.is_file())
            .cloned()
            .ok_or_else(|| AppError::InitBinaryPathUnavailable {
                candidates: candidates
                    .iter()
                    .map(|candidate| candidate.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", "),
            })
    }

    fn ensure_dir(&self, path: &Path) -> Result<ProvisionState, AppError> {
        let existed = path.exists();
        fs::create_dir_all(path).map_err(|error| AppError::InitIo {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        Ok(if existed {
            ProvisionState::Preserved
        } else {
            ProvisionState::Created
        })
    }

    fn ensure_file(&self, path: &Path, contents: &str) -> Result<ProvisionState, AppError> {
        if path.exists() {
            if !path.is_file() {
                return Err(AppError::InitIo {
                    path: path.to_path_buf(),
                    reason: "path exists but is not a file".to_string(),
                });
            }
            return Ok(ProvisionState::Preserved);
        }
        if let Some(parent) = path.parent() {
            self.ensure_dir(parent)?;
        }
        write_string_atomic(path, contents).map_err(|error| AppError::InitIo {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })?;
        Ok(ProvisionState::Created)
    }

    fn enable_systemd_timer(&self) -> Result<(), AppError> {
        for arguments in [
            vec!["daemon-reload"],
            vec!["reset-failed", KIDOBO_SYNC_SERVICE_FILE],
            vec!["enable", "--now", KIDOBO_SYNC_TIMER_FILE],
        ] {
            run_required_systemd_command(&self.runner, &arguments)?;
        }
        Ok(())
    }
}

fn run_required_systemd_command(
    runner: &dyn InitCommandRunner,
    arguments: &[&str],
) -> Result<(), AppError> {
    let command = format!("systemctl {}", arguments.join(" "));
    let result = runner
        .run("systemctl", arguments)
        .map_err(|error| AppError::InitSystemd {
            command: command.clone(),
            reason: error.to_string(),
        })?;
    if result.status.success() {
        return Ok(());
    }
    let stderr = result.stderr.trim();
    let stdout = result.stdout.trim();
    let reason = if !stderr.is_empty() {
        format!("status={:?} stderr={stderr}", result.status)
    } else if !stdout.is_empty() {
        format!("status={:?} stdout={stdout}", result.status)
    } else {
        format!("status={:?}", result.status)
    };
    Err(AppError::InitSystemd { command, reason })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use kidobo_app::init::{InitProvisioner, ProvisionState};
    use tempfile::TempDir;

    use super::{FileInitProvisioner, InitCommandRunner};
    use crate::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};

    struct Runner {
        calls: RefCell<Vec<Vec<String>>>,
        fail_at: Option<usize>,
    }
    impl InitCommandRunner for Runner {
        fn run(&self, _command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            self.calls
                .borrow_mut()
                .push(args.iter().map(|value| (*value).to_string()).collect());
            if self.fail_at == Some(self.calls.borrow().len()) {
                return Ok(CommandResult {
                    status: ProcessStatus::Exited(9),
                    stdout: String::new(),
                    stderr: "injected systemd failure".to_string(),
                });
            }
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: String::new(),
                stderr: String::new(),
            })
        }
    }

    #[test]
    fn preserves_existing_file_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        fs::write(&path, "custom bytes\n").expect("write");
        let provisioner = FileInitProvisioner::new(Runner {
            calls: RefCell::new(Vec::new()),
            fail_at: None,
        });

        let state = provisioner
            .ensure_file(&path, "replacement")
            .expect("ensure");

        assert_eq!(state, ProvisionState::Preserved);
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&path, 1024).expect("read"),
            "custom bytes\n"
        );
    }

    #[test]
    fn systemd_enablement_uses_expected_command_sequence() {
        let provisioner = FileInitProvisioner::new(Runner {
            calls: RefCell::new(Vec::new()),
            fail_at: None,
        });
        provisioner.enable_systemd_timer().expect("enable");
        assert_eq!(
            *provisioner.runner.calls.borrow(),
            [
                vec!["daemon-reload"],
                vec!["reset-failed", "kidobo-sync.service"],
                vec!["enable", "--now", "kidobo-sync.timer"],
            ]
        );
    }

    #[test]
    fn systemd_enablement_maps_nonzero_exit_to_application_error() {
        let provisioner = FileInitProvisioner::new(Runner {
            calls: RefCell::new(Vec::new()),
            fail_at: Some(1),
        });

        let error = provisioner
            .enable_systemd_timer()
            .expect_err("daemon-reload failure must stop init");

        assert_eq!(provisioner.runner.calls.borrow().len(), 1);
        assert!(error.to_string().contains("systemctl daemon-reload"));
        assert!(error.to_string().contains("injected systemd failure"));
    }
}
