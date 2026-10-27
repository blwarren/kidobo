use std::env;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdout, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, poll};
use nix::pty::{Winsize, openpty};
use tempfile::TempDir;

const OUTPUT_LIMIT: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Clone, Copy)]
pub enum OutputDestination {
    Terminal,
    Pipe,
}

pub struct Fixture {
    directory: TempDir,
}

impl Fixture {
    pub fn new(config: &str, blocklist: &str) -> Self {
        let directory = TempDir::new().expect("terminal fixture");
        for path in ["config", "data", "cache/remote", "bin"] {
            fs::create_dir_all(directory.path().join(path)).expect("fixture directory");
        }
        fs::write(directory.path().join("config/config.toml"), config).expect("fixture config");
        fs::write(directory.path().join("data/blocklist.txt"), blocklist)
            .expect("fixture blocklist");
        fs::write(
            directory.path().join("data/temporary-bans.toml"),
            "version = 1\n",
        )
        .expect("fixture temporary bans");
        fs::write(directory.path().join("cache/sync.lock"), "").expect("fixture lock");
        let fixture = Self { directory };
        fixture.write_tool("sudo", "[ \"$1\" = '-n' ] || exit 91\nshift\nexec \"$@\"\n");
        fixture.write_tool(
            "ipset",
            "[ \"$*\" = 'list -name' ] || exit 92\nprintf 'kidobo\\nkidobo-v6\\n'\n",
        );
        for binary in ["iptables", "ip6tables"] {
            fixture.write_tool(binary, "[ \"$*\" = '-S' ] || exit 93\nexit 0\n");
        }
        for binary in ["bgpq4", "systemctl"] {
            fixture.write_tool(binary, "exit 94\n");
        }
        fixture
    }

    pub fn root(&self) -> &Path {
        self.directory.path()
    }

    pub fn write_tool(&self, binary: &str, body: &str) {
        let path = self.root().join("bin").join(binary);
        fs::write(
            &path,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"{binary} $*\" >> \"$KIDOBO_TEST_TOOL_LOG\"\n{body}"
            ),
        )
        .expect("fake command");
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("fake command mode");
    }

    pub fn spawn(
        &self,
        arguments: &[&str],
        width: u16,
        destination: OutputDestination,
        environment: &[(&str, &str)],
    ) -> PtyCommand {
        let binary = env::var_os("KIDOBO_TEST_BINARY").map_or_else(
            || PathBuf::from(env!("CARGO_BIN_EXE_kidobo")),
            PathBuf::from,
        );
        let mut command = Command::new(binary);
        command
            .args(arguments)
            .current_dir(self.root())
            .env_clear()
            // Keep instrumentation output outside the state whose immutability is tested.
            .envs(std::env::var_os("LLVM_PROFILE_FILE").map(|value| ("LLVM_PROFILE_FILE", value)))
            .env("KIDOBO_ROOT", self.root())
            .env("PATH", self.root().join("bin"))
            .env("KIDOBO_TEST_TOOL_LOG", self.root().join("tool.log"))
            .env("TERM", "xterm")
            .env("LANG", "C.UTF-8")
            .envs(environment.iter().copied());
        PtyCommand::spawn(command, width, destination)
    }

    pub fn tool_log(&self) -> String {
        match File::open(self.root().join("tool.log")) {
            Ok(file) => {
                let mut contents = String::new();
                file.take(u64::try_from(OUTPUT_LIMIT).expect("output limit fits u64"))
                    .read_to_string(&mut contents)
                    .expect("tool log");
                contents
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => String::new(),
            Err(error) => panic!("tool log: {error}"),
        }
    }
}

#[derive(Debug)]
pub struct CapturedOutput {
    pub status: ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

pub struct PtyCommand {
    child: Child,
    master: File,
    stdout_pipe: Option<ChildStdout>,
    stderr_pipe: Option<ChildStderr>,
    destination: OutputDestination,
    command: String,
}

impl PtyCommand {
    fn spawn(mut command: Command, width: u16, destination: OutputDestination) -> Self {
        let terminal = openpty(
            Some(&Winsize {
                ws_row: 40,
                ws_col: width,
                ws_xpixel: 0,
                ws_ypixel: 0,
            }),
            None,
        )
        .expect("create pseudoterminal");
        for descriptor in [&terminal.master, &terminal.slave] {
            fcntl(descriptor, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .expect("terminal close-on-exec");
        }
        let slave = File::from(terminal.slave);
        let master = File::from(terminal.master);
        command
            .stdin(Stdio::from(slave.try_clone().expect("terminal stdin")))
            .stderr(Stdio::piped());
        match destination {
            OutputDestination::Terminal => {
                command.stdout(Stdio::from(slave.try_clone().expect("terminal stdout")));
            }
            OutputDestination::Pipe => {
                command.stdout(Stdio::piped());
            }
        }
        let diagnostic = format!("{command:?}");
        let mut child = command.spawn().expect("spawn terminal Kidobo");
        // Command retains its configured descriptors for possible reuse. Closing both copies
        // here lets the master observe EOF after the child closes its terminal handles.
        drop(command);
        drop(slave);
        set_nonblocking(&master);
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        if let Some(stdout) = &stdout_pipe {
            set_nonblocking(stdout);
        }
        if let Some(stderr) = &stderr_pipe {
            set_nonblocking(stderr);
        }
        Self {
            child,
            master,
            stdout_pipe,
            stderr_pipe,
            destination,
            command: diagnostic,
        }
    }

    pub fn wait(mut self) -> CapturedOutput {
        self.collect(&[])
    }

    #[allow(dead_code, reason = "Used by single-prompt integration test binaries.")]
    pub fn respond_after(mut self, prompt: &str, response: &str) -> CapturedOutput {
        self.collect(&[(prompt, response)])
    }

    #[allow(
        dead_code,
        reason = "Used by the multi-prompt setup integration test binary."
    )]
    pub fn respond_to_all(mut self, interactions: &[(&str, &str)]) -> CapturedOutput {
        self.collect(interactions)
    }

    fn collect(&mut self, interactions: &[(&str, &str)]) -> CapturedOutput {
        let deadline = Instant::now() + DEADLINE;
        let mut terminal = Vec::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut terminal_open = true;
        let mut status = None;
        let mut interaction_index = 0;
        let mut terminal_cursor = 0;
        let mut stdout_cursor = 0;
        let mut stderr_cursor = 0;
        loop {
            assert!(
                Instant::now() < deadline,
                "terminal command timed out: {}\nstdout={}\nterminal={}\nstderr={}",
                self.command,
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&terminal),
                String::from_utf8_lossy(&stderr)
            );
            {
                let mut descriptors = Vec::new();
                if terminal_open {
                    descriptors.push(PollFd::new(self.master.as_fd(), PollFlags::POLLIN));
                }
                if let Some(pipe) = &self.stdout_pipe {
                    descriptors.push(PollFd::new(pipe.as_fd(), PollFlags::POLLIN));
                }
                if let Some(pipe) = &self.stderr_pipe {
                    descriptors.push(PollFd::new(pipe.as_fd(), PollFlags::POLLIN));
                }
                poll(&mut descriptors, 20_u16).expect("poll child output");
            }
            if terminal_open {
                terminal_open = drain(&mut self.master, &mut terminal, true);
            }
            if let Some(pipe) = &mut self.stdout_pipe
                && !drain(pipe, &mut stdout, false)
            {
                self.stdout_pipe = None;
            }
            if let Some(pipe) = &mut self.stderr_pipe
                && !drain(pipe, &mut stderr, false)
            {
                self.stderr_pipe = None;
            }
            if let Some((prompt, response)) = interactions.get(interaction_index) {
                let terminal_tail = &terminal[terminal_cursor..];
                let stdout_tail = &stdout[stdout_cursor..];
                let stderr_tail = &stderr[stderr_cursor..];
                if [terminal_tail, stdout_tail, stderr_tail]
                    .iter()
                    .any(|bytes| String::from_utf8_lossy(bytes).contains(prompt))
                {
                    self.master
                        .write_all(response.as_bytes())
                        .expect("terminal response");
                    interaction_index += 1;
                    terminal_cursor = terminal.len();
                    stdout_cursor = stdout.len();
                    stderr_cursor = stderr.len();
                }
            }
            if status.is_none() {
                status = self.child.try_wait().expect("inspect child status");
            }
            if let Some(status) = status
                && !terminal_open
                && self.stdout_pipe.is_none()
                && self.stderr_pipe.is_none()
            {
                assert_eq!(
                    interaction_index,
                    interactions.len(),
                    "command ended before the expected prompt"
                );
                let stdout = match self.destination {
                    OutputDestination::Terminal => {
                        // A PTY's default ONLCR maps newlines to CRLF. Normalize that transport
                        // detail only; pipe output is retained exactly.
                        String::from_utf8(terminal)
                            .expect("UTF-8 terminal stdout")
                            .replace("\r\n", "\n")
                    }
                    OutputDestination::Pipe => {
                        String::from_utf8(stdout).expect("UTF-8 pipe stdout")
                    }
                };
                return CapturedOutput {
                    status,
                    stdout,
                    stderr: String::from_utf8(stderr).expect("UTF-8 stderr"),
                };
            }
        }
    }
}

impl Drop for PtyCommand {
    fn drop(&mut self) {
        let _kill_result = self.child.kill();
        let _wait_result = self.child.wait();
    }
}

fn set_nonblocking(descriptor: &impl AsFd) {
    let current = fcntl(descriptor, FcntlArg::F_GETFL).expect("descriptor flags");
    fcntl(
        descriptor,
        FcntlArg::F_SETFL(OFlag::from_bits_truncate(current) | OFlag::O_NONBLOCK),
    )
    .expect("nonblocking descriptor");
}

fn drain(reader: &mut impl Read, output: &mut Vec<u8>, terminal: bool) -> bool {
    let mut buffer = [0_u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return false,
            Ok(count) => {
                assert!(
                    output.len() + count <= OUTPUT_LIMIT,
                    "terminal output exceeded limit"
                );
                output.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return true,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if terminal && error.raw_os_error() == Some(nix::libc::EIO) => return false,
            Err(error) => panic!("read terminal command output: {error}"),
        }
    }
}
