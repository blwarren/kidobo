use std::env;
use std::fs::{self, File};
use std::io::{self, Read};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::TempDir;

#[path = "pty.rs"]
mod pty;
pub use pty::{OutputDestination, PtyCommand};

const OUTPUT_LIMIT: usize = 1024 * 1024;

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
