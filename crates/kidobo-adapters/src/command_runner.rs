//! Bounded subprocess execution adapter.

use std::io::Read;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use thiserror::Error;

#[cfg(unix)]
use nix::sys::signal::{Signal, killpg};
#[cfg(unix)]
use nix::unistd::Pid;

use crate::command_common::display_command;
use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use std::os::fd::AsFd;

/// Default upper bound for one external command.
pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const PRODUCTION_COMMAND_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
#[cfg(not(test))]
const DEFAULT_COMMAND_OUTPUT_LIMIT: usize = PRODUCTION_COMMAND_OUTPUT_LIMIT;
#[cfg(test)]
const DEFAULT_COMMAND_OUTPUT_LIMIT: usize = 1024 * 1024;

/// Program, arguments, and time bound for one subprocess execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    /// Program name or path.
    pub program: String,
    /// Arguments passed without shell interpretation.
    pub args: Vec<String>,
    /// Maximum execution duration.
    pub timeout: Duration,
}

/// Bounded subprocess status and lossy UTF-8 output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    /// Portable process termination state.
    pub status: ProcessStatus,
    /// Bounded standard output.
    pub stdout: String,
    /// Bounded standard error.
    pub stderr: String,
}

/// Portable process termination state used by command adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    /// Process exited normally with this code.
    Exited(i32),
    #[cfg(unix)]
    /// Process terminated after receiving this signal number.
    Signaled(i32),
    /// Platform status was neither a normal exit nor a recognized Unix signal.
    Other,
}

impl ProcessStatus {
    #[must_use]
    /// Returns the normal exit code, if available.
    pub fn code(self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(code),
            #[cfg(unix)]
            Self::Signaled(_) => None,
            Self::Other => None,
        }
    }

    #[must_use]
    /// Returns true only for a normal zero exit.
    pub fn success(self) -> bool {
        matches!(self, Self::Exited(0))
    }

    fn from_exit_status(status: ExitStatus) -> Self {
        if let Some(code) = status.code() {
            return Self::Exited(code);
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;

            if let Some(signal) = status.signal() {
                return Self::Signaled(signal);
            }
        }

        Self::Other
    }
}

/// Failure while starting, supervising, or collecting a bounded subprocess.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandRunnerError {
    /// The operating system refused to start the process.
    #[error("failed to spawn command `{command}`: {reason}")]
    Spawn {
        /// Rendered command.
        command: String,
        /// Operating-system diagnostic.
        reason: String,
    },

    /// Process status polling failed.
    #[error("failed to poll command `{command}`: {reason}")]
    Poll {
        /// Rendered command.
        command: String,
        /// Operating-system diagnostic.
        reason: String,
    },

    /// Bounded output collection failed.
    #[error("failed to read output for command `{command}`: {reason}")]
    Output {
        /// Rendered command.
        command: String,
        /// Pipe, size-bound, or reader diagnostic.
        reason: String,
    },

    /// The process exceeded its deadline and was terminated.
    #[error("command `{command}` timed out after {timeout_ms} ms")]
    Timeout {
        /// Rendered command.
        command: String,
        /// Configured timeout in milliseconds.
        timeout_ms: u64,
    },
}

/// Executes bounded subprocess requests without a shell.
pub trait CommandExecutor {
    /// Executes one bounded command request.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRunnerError`] when spawning, polling, output collection, or the timeout
    /// boundary fails.
    fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError>;
}

/// Production executor using operating-system subprocess APIs.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
        let command = display_command(&request.program, &request.args);
        let mut child_command = Command::new(&request.program);
        child_command
            .args(&request.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            child_command.process_group(0);
        }

        let mut child = child_command
            .spawn()
            .map_err(|err| CommandRunnerError::Spawn {
                command: command.clone(),
                reason: err.to_string(),
            })?;

        let result = collect_output(&mut child, request, &command);
        if result.is_err() {
            terminate_child_process_tree(&mut child);
        }
        result
    }
}

fn collect_output(
    child: &mut Child,
    request: &CommandRequest,
    command: &str,
) -> Result<CommandResult, CommandRunnerError> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| CommandRunnerError::Output {
            command: command.to_string(),
            reason: "stdout pipe was not available".to_string(),
        })?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| CommandRunnerError::Output {
            command: command.to_string(),
            reason: "stderr pipe was not available".to_string(),
        })?;

    let output_error = |error: std::io::Error| CommandRunnerError::Output {
        command: command.to_string(),
        reason: error.to_string(),
    };
    set_nonblocking(&stdout).map_err(output_error)?;
    set_nonblocking(&stderr).map_err(output_error)?;
    let mut stdout_bytes = Vec::new();
    let mut stderr_bytes = Vec::new();
    let mut stdout_eof = false;
    let mut stderr_eof = false;
    let mut status = None;
    let started = Instant::now();
    loop {
        let remaining = request.timeout.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            return Err(CommandRunnerError::Timeout {
                command: command.to_string(),
                timeout_ms: duration_millis_u64(request.timeout),
            });
        }
        if status.is_none() {
            status = child.try_wait().map_err(|error| CommandRunnerError::Poll {
                command: command.to_string(),
                reason: error.to_string(),
            })?;
        }
        if !stdout_eof {
            stdout_eof = drain_output(&mut stdout, &mut stdout_bytes).map_err(output_error)?;
        }
        if !stderr_eof {
            stderr_eof = drain_output(&mut stderr, &mut stderr_bytes).map_err(output_error)?;
        }
        if let Some(status) = status.filter(|_| stdout_eof && stderr_eof) {
            return Ok(CommandResult {
                status: ProcessStatus::from_exit_status(status),
                stdout: String::from_utf8_lossy(&stdout_bytes).into_owned(),
                stderr: String::from_utf8_lossy(&stderr_bytes).into_owned(),
            });
        }
        let mut pipes = Vec::with_capacity(2);
        if !stdout_eof {
            pipes.push(PollFd::new(stdout.as_fd(), PollFlags::POLLIN));
        }
        if !stderr_eof {
            pipes.push(PollFd::new(stderr.as_fd(), PollFlags::POLLIN));
        }
        let wait_ms = u16::try_from(remaining.as_millis().min(10)).unwrap_or(10);
        match poll(&mut pipes, wait_ms) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(output_error(error.into())),
        }
    }
}

fn set_nonblocking(pipe: &impl AsFd) -> std::io::Result<()> {
    let flags = OFlag::from_bits_retain(fcntl(pipe, FcntlArg::F_GETFL)?);
    fcntl(pipe, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK))?;
    Ok(())
}

// Read one chunk per stream so continuously writable stdout cannot starve stderr or the deadline.
fn drain_output(pipe: &mut impl Read, contents: &mut Vec<u8>) -> std::io::Result<bool> {
    let mut buffer = [0; 8192];
    match pipe.read(&mut buffer) {
        Ok(0) => Ok(true),
        Ok(count) => {
            if count > DEFAULT_COMMAND_OUTPUT_LIMIT.saturating_sub(contents.len()) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("command output exceeds {DEFAULT_COMMAND_OUTPUT_LIMIT} byte limit"),
                ));
            }
            let bytes = buffer
                .get(..count)
                .ok_or_else(|| std::io::Error::other("pipe read exceeded buffer length"))?;
            contents.extend_from_slice(bytes);
            Ok(false)
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

fn terminate_child_process_tree(child: &mut Child) {
    #[cfg(unix)]
    if let Ok(raw_pid) = i32::try_from(child.id()) {
        let _group_kill_result = killpg(Pid::from_raw(raw_pid), Signal::SIGKILL);
    }

    let _direct_kill_result = child.kill();
    let _wait_result = child.wait();
}

/// Command runner that prepends noninteractive `sudo -n` to every request.
#[derive(Debug)]
pub struct SudoCommandRunner<E: CommandExecutor> {
    executor: E,
    default_timeout: Duration,
}

impl<E: CommandExecutor> SudoCommandRunner<E> {
    /// Wraps an executor with the specified default command timeout.
    pub fn new(executor: E, default_timeout: Duration) -> Self {
        Self {
            executor,
            default_timeout,
        }
    }

    /// Runs one command through noninteractive sudo using the default timeout.
    ///
    /// # Errors
    ///
    /// Returns the wrapped executor's [`CommandRunnerError`].
    pub fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.run_with_timeout(command, args, self.default_timeout)
    }

    /// Runs one command through noninteractive sudo using an explicit timeout.
    ///
    /// # Errors
    ///
    /// Returns the wrapped executor's [`CommandRunnerError`].
    pub fn run_with_timeout(
        &self,
        command: &str,
        args: &[&str],
        timeout: Duration,
    ) -> Result<CommandResult, CommandRunnerError> {
        let mut sudo_args = Vec::with_capacity(args.len() + 2);
        sudo_args.push("-n".to_string());
        sudo_args.push(command.to_string());
        sudo_args.extend(args.iter().map(|value| (*value).to_string()));

        let request = CommandRequest {
            program: "sudo".to_string(),
            args: sudo_args,
            timeout,
        };

        self.executor.execute(&request)
    }
}

impl Default for SudoCommandRunner<SystemCommandExecutor> {
    fn default() -> Self {
        Self::new(SystemCommandExecutor, DEFAULT_COMMAND_TIMEOUT)
    }
}

fn duration_millis_u64(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::{
        CommandExecutor, CommandRequest, CommandResult, CommandRunnerError,
        DEFAULT_COMMAND_TIMEOUT, ProcessStatus, SudoCommandRunner, SystemCommandExecutor,
        duration_millis_u64,
    };

    struct MockExecutor {
        requests: RefCell<Vec<CommandRequest>>,
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
    }

    impl MockExecutor {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                requests: RefCell::new(Vec::new()),
                responses: RefCell::new(VecDeque::from(responses)),
            }
        }

        fn requests(&self) -> Vec<CommandRequest> {
            self.requests.borrow().clone()
        }
    }

    impl CommandExecutor for MockExecutor {
        fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
            self.requests.borrow_mut().push(request.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    #[test]
    fn duration_millis_preserves_nontrivial_values() {
        assert_eq!(duration_millis_u64(Duration::from_millis(1_234)), 1_234);
    }

    #[test]
    fn wraps_commands_with_sudo_n_and_captures_output() {
        let executor = MockExecutor::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: "ok".to_string(),
            stderr: String::new(),
        })]);
        let runner = SudoCommandRunner::new(executor, Duration::from_secs(5));

        let result = runner
            .run("ipset", &["list", "kidobo"])
            .expect("command result");
        assert_eq!(result.status.code(), Some(0));
        assert_eq!(result.stdout, "ok");
        assert_eq!(result.stderr, "");

        let requests = runner.executor.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].program, "sudo");
        assert_eq!(requests[0].args, vec!["-n", "ipset", "list", "kidobo"]);
        assert_eq!(requests[0].timeout, Duration::from_secs(5));
    }

    #[test]
    fn custom_timeout_overrides_default() {
        let executor = MockExecutor::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        })]);
        let runner = SudoCommandRunner::new(executor, Duration::from_secs(30));

        let _ = runner
            .run_with_timeout("iptables", &["-S"], Duration::from_secs(2))
            .expect("command result");

        let requests = runner.executor.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].timeout, Duration::from_secs(2));
    }

    #[test]
    fn normalized_error_mapping_is_preserved() {
        let error = CommandRunnerError::Timeout {
            command: "sudo -n ipset list kidobo".to_string(),
            timeout_ms: 1_000,
        };

        let executor = MockExecutor::new(vec![Err(error.clone())]);
        let runner = SudoCommandRunner::new(executor, Duration::from_secs(1));

        let returned = runner
            .run("ipset", &["list", "kidobo"])
            .expect_err("must fail");
        assert_eq!(returned, error);
    }

    #[test]
    fn default_runner_uses_default_timeout() {
        let runner: SudoCommandRunner<SystemCommandExecutor> = SudoCommandRunner::default();
        assert_eq!(runner.default_timeout, DEFAULT_COMMAND_TIMEOUT);
    }

    #[test]
    fn production_command_output_limit_is_16_mib() {
        assert_eq!(super::PRODUCTION_COMMAND_OUTPUT_LIMIT, 16 * 1024 * 1024);
    }

    #[cfg(unix)]
    fn run_system_shell(script: &str) -> Result<CommandResult, CommandRunnerError> {
        let executor = SystemCommandExecutor;
        executor.execute(&CommandRequest {
            program: "sh".to_string(),
            args: vec!["-c".to_string(), script.to_string()],
            timeout: Duration::from_secs(10),
        })
    }

    #[cfg(unix)]
    #[test]
    fn system_executor_drains_large_stdout_without_timeout() {
        let result = run_system_shell("yes kidobo | head -n 70000")
            .expect("command should succeed without pipe blocking");
        assert!(result.status.success());
        assert!(result.stdout.len() > 64 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn system_executor_drains_large_stderr_without_timeout() {
        let result = run_system_shell("yes kidobo | head -n 70000 1>&2")
            .expect("command should succeed without pipe blocking");
        assert!(result.status.success());
        assert!(result.stderr.len() > 64 * 1024);
    }

    #[cfg(unix)]
    #[test]
    fn system_executor_rejects_oversized_output() {
        let err = run_system_shell(&format!(
            "yes kidobo | head -c {}",
            super::DEFAULT_COMMAND_OUTPUT_LIMIT + 1
        ))
        .expect_err("oversized command output must fail");

        match err {
            CommandRunnerError::Output { reason, .. } => {
                assert!(reason.contains("command output exceeds"));
            }
            _ => panic!("expected output error"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn system_executor_reports_spawn_errors_with_command_context() {
        let executor = SystemCommandExecutor;
        let err = executor
            .execute(&CommandRequest {
                program: "kidobo-definitely-missing-command-for-tests".to_string(),
                args: Vec::new(),
                timeout: Duration::from_secs(1),
            })
            .expect_err("missing binary must fail to spawn");

        match err {
            CommandRunnerError::Spawn { command, .. } => {
                assert_eq!(command, "kidobo-definitely-missing-command-for-tests");
            }
            _ => panic!("expected spawn error"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn deadline_includes_pipes_inherited_after_the_child_exits() {
        for script in [
            "sleep 2 2>/dev/null & exit 0",
            "sleep 2 >/dev/null & exit 0",
        ] {
            let started = std::time::Instant::now();
            let result = SystemCommandExecutor.execute(&CommandRequest {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), script.to_string()],
                timeout: Duration::from_millis(100),
            });
            assert!(
                matches!(
                    result,
                    Err(CommandRunnerError::Timeout {
                        timeout_ms: 100,
                        ..
                    })
                ),
                "{result:?}"
            );
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "pipe collection outlived its deadline"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn both_output_streams_are_drained_before_returning() {
        let result =
            run_system_shell("(yes out | head -n 20000) & (yes err | head -n 20000 >&2) & wait")
                .expect("output");
        assert!(result.status.success());
        assert_eq!(result.stdout.lines().count(), 20000);
        assert_eq!(result.stderr.lines().count(), 20000);
    }

    #[cfg(unix)]
    #[test]
    fn system_executor_reports_timeouts() {
        let executor = SystemCommandExecutor;
        let err = executor
            .execute(&CommandRequest {
                program: "sh".to_string(),
                args: vec!["-c".to_string(), "sleep 1".to_string()],
                timeout: Duration::from_millis(1),
            })
            .expect_err("sleep command should time out");

        match err {
            CommandRunnerError::Timeout {
                command,
                timeout_ms,
            } => {
                assert!(command.contains("sh -c sleep 1"));
                assert_eq!(timeout_ms, 1);
            }
            _ => panic!("expected timeout error"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn system_executor_timeout_terminates_descendant_processes() {
        let temp = TempDir::new().expect("tempdir");
        let marker = temp.path().join("descendant-finished");
        let executor = SystemCommandExecutor;
        let started = std::time::Instant::now();
        let err = executor
            .execute(&CommandRequest {
                program: "sh".to_string(),
                args: vec![
                    "-c".to_string(),
                    "(sleep 1; touch \"$1\") & wait".to_string(),
                    "sh".to_string(),
                    marker.display().to_string(),
                ],
                timeout: Duration::from_millis(20),
            })
            .expect_err("process tree must time out");

        assert!(matches!(err, CommandRunnerError::Timeout { .. }));
        assert!(
            started.elapsed() < Duration::from_millis(750),
            "timeout waited for the descendant process"
        );
        std::thread::sleep(Duration::from_millis(1_100));
        assert!(
            !marker.exists(),
            "descendant survived the process-group kill"
        );
    }
}
