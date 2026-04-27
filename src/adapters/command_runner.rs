use std::io::{self, Read};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;

use crate::adapters::command_common::display_command;

pub const DEFAULT_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
#[cfg(not(test))]
const DEFAULT_COMMAND_OUTPUT_LIMIT: usize = 16 * 1024 * 1024;
#[cfg(test)]
const DEFAULT_COMMAND_OUTPUT_LIMIT: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandRequest {
    pub program: String,
    pub args: Vec<String>,
    pub timeout: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandResult {
    pub status: ProcessStatus,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessStatus {
    Exited(i32),
    #[cfg(unix)]
    Signaled(i32),
    Other,
}

impl ProcessStatus {
    pub fn code(self) -> Option<i32> {
        match self {
            Self::Exited(code) => Some(code),
            #[cfg(unix)]
            Self::Signaled(_) => None,
            Self::Other => None,
        }
    }

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

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommandRunnerError {
    #[error("failed to spawn command `{command}`: {reason}")]
    Spawn { command: String, reason: String },

    #[error("failed to poll command `{command}`: {reason}")]
    Poll { command: String, reason: String },

    #[error("failed to read output for command `{command}`: {reason}")]
    Output { command: String, reason: String },

    #[error("command `{command}` timed out after {timeout_ms} ms")]
    Timeout { command: String, timeout_ms: u64 },
}

pub trait CommandExecutor {
    fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemCommandExecutor;

impl CommandExecutor for SystemCommandExecutor {
    fn execute(&self, request: &CommandRequest) -> Result<CommandResult, CommandRunnerError> {
        let command = display_command(&request.program, &request.args);
        let mut child = Command::new(&request.program)
            .args(&request.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| CommandRunnerError::Spawn {
                command: command.clone(),
                reason: err.to_string(),
            })?;

        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| CommandRunnerError::Output {
                command: command.clone(),
                reason: "stdout pipe was not available".to_string(),
            })?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| CommandRunnerError::Output {
                command: command.clone(),
                reason: "stderr pipe was not available".to_string(),
            })?;

        let stdout_reader = spawn_output_reader(stdout);
        let stderr_reader = spawn_output_reader(stderr);

        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    let stdout = join_output_reader(stdout_reader, &command)?;
                    let stderr = join_output_reader(stderr_reader, &command)?;

                    return Ok(CommandResult {
                        status: ProcessStatus::from_exit_status(status),
                        stdout: String::from_utf8_lossy(&stdout).to_string(),
                        stderr: String::from_utf8_lossy(&stderr).to_string(),
                    });
                }
                Ok(None) => {
                    if started.elapsed() >= request.timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        best_effort_join_output_reader(stdout_reader);
                        best_effort_join_output_reader(stderr_reader);

                        return Err(CommandRunnerError::Timeout {
                            command,
                            timeout_ms: duration_millis_u64(request.timeout),
                        });
                    }

                    thread::sleep(Duration::from_millis(10));
                }
                Err(err) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    best_effort_join_output_reader(stdout_reader);
                    best_effort_join_output_reader(stderr_reader);

                    return Err(CommandRunnerError::Poll {
                        command,
                        reason: err.to_string(),
                    });
                }
            }
        }
    }
}

fn spawn_output_reader<R>(mut reader: R) -> thread::JoinHandle<std::io::Result<Vec<u8>>>
where
    R: Read + Send + 'static,
{
    thread::spawn(move || read_to_end_with_limit(&mut reader, DEFAULT_COMMAND_OUTPUT_LIMIT))
}

fn read_to_end_with_limit(reader: &mut impl Read, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];

    loop {
        let read = reader.read(&mut chunk)?;
        if read == 0 {
            break;
        }

        if bytes
            .len()
            .checked_add(read)
            .is_none_or(|next| next > max_bytes)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("command output exceeds {max_bytes} byte limit"),
            ));
        }

        let Some(slice) = chunk.get(..read) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "output reader returned an invalid chunk size",
            ));
        };
        bytes.extend_from_slice(slice);
    }

    Ok(bytes)
}

fn join_output_reader(
    handle: thread::JoinHandle<std::io::Result<Vec<u8>>>,
    command: &str,
) -> Result<Vec<u8>, CommandRunnerError> {
    let result = handle.join().map_err(|_| CommandRunnerError::Output {
        command: command.to_string(),
        reason: "output reader thread panicked".to_string(),
    })?;

    result.map_err(|err| CommandRunnerError::Output {
        command: command.to_string(),
        reason: err.to_string(),
    })
}

fn best_effort_join_output_reader(handle: thread::JoinHandle<std::io::Result<Vec<u8>>>) {
    let _ = handle.join();
}

#[derive(Debug)]
pub struct SudoCommandRunner<E: CommandExecutor> {
    executor: E,
    default_timeout: Duration,
}

impl<E: CommandExecutor> SudoCommandRunner<E> {
    pub fn new(executor: E, default_timeout: Duration) -> Self {
        Self {
            executor,
            default_timeout,
        }
    }

    pub fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.run_with_timeout(command, args, self.default_timeout)
    }

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

    use super::{
        CommandExecutor, CommandRequest, CommandResult, CommandRunnerError,
        DEFAULT_COMMAND_TIMEOUT, ProcessStatus, SudoCommandRunner, SystemCommandExecutor,
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
}
