//! Filesystem and firewall implementation of the flush application port.

use std::fs;
use std::path::Path;

use kidobo_app::flush::{FirewallFamily as AppFirewallFamily, FlushBackend};

use crate::command_runner::{SudoCommandRunner, SystemCommandExecutor};
use crate::ipset::{IpsetCommandRunner, is_missing_set_result};
use crate::iptables::{FirewallCommandRunner, FirewallFamily, cleanup_firewall_wiring};

/// Flush backend using injected firewall and ipset command runners.
#[derive(Debug)]
pub struct CommandFlushBackend<R> {
    runner: R,
}

impl<R> CommandFlushBackend<R> {
    #[must_use]
    /// Creates a flush backend around the supplied runner.
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl Default for CommandFlushBackend<SudoCommandRunner<SystemCommandExecutor>> {
    fn default() -> Self {
        Self::new(SudoCommandRunner::default())
    }
}

/// Production flush backend using noninteractive bounded sudo commands.
pub type SystemFlushBackend = CommandFlushBackend<SudoCommandRunner<SystemCommandExecutor>>;

impl<R> FlushBackend for CommandFlushBackend<R>
where
    R: FirewallCommandRunner + IpsetCommandRunner,
{
    fn cleanup_firewall(&self, family: AppFirewallFamily) -> Result<(), String> {
        let family = match family {
            AppFirewallFamily::Ipv4 => FirewallFamily::Ipv4,
            AppFirewallFamily::Ipv6 => FirewallFamily::Ipv6,
        };
        cleanup_firewall_wiring(&self.runner, family)
            .map_err(|error| format!("firewall cleanup failed for {family:?}: {error}"))
    }

    fn destroy_ipset(&self, set_name: &str) -> Result<(), String> {
        let args = ["destroy", set_name];
        let rendered = crate::command_common::display_command("ipset", &args);
        match IpsetCommandRunner::run(&self.runner, "ipset", &args) {
            Ok(result) if result.status.success() || is_missing_set_result(&result) => Ok(()),
            Ok(result) => Err(format!(
                "{rendered} failed (status={:?} stderr={})",
                result.status, result.stderr
            )),
            Err(error) => Err(format!("{rendered} execution failed ({error})")),
        }
    }

    fn clear_remote_cache(&self, path: &Path) -> std::io::Result<()> {
        clear_remote_cache_dir(path)
    }
}

fn clear_remote_cache_dir(remote_cache_dir: &Path) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let parent = pin_cache_parent(remote_cache_dir)?;
        let name = remote_cache_dir.file_name().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "remote cache must have a child directory name",
            )
        })?;
        clear_pinned_cache_dir(&parent, name)
    }
    #[cfg(not(unix))]
    clear_cache_path(remote_cache_dir)
}

#[cfg(unix)]
fn pin_cache_parent(remote_cache_dir: &Path) -> std::io::Result<fs::File> {
    crate::private_fs::open_parent_directory(remote_cache_dir)
}

#[cfg(unix)]
fn clear_pinned_cache_dir(parent: &fs::File, name: &std::ffi::OsStr) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    // The live directory descriptor stays pinned if an attacker renames its pathname.
    let path = std::path::PathBuf::from(format!("/dev/fd/{}", parent.as_raw_fd())).join(name);
    remove_cache_path(&path)?;
    crate::private_fs::ensure_private_dir_at(parent, name).map(|_| ())
}

#[cfg(not(unix))]
fn clear_cache_path(remote_cache_dir: &Path) -> std::io::Result<()> {
    remove_cache_path(remote_cache_dir)?;
    crate::private_fs::ensure_private_dir(remote_cache_dir).map(|_| ())
}

fn remove_cache_path(remote_cache_dir: &Path) -> std::io::Result<()> {
    match fs::remove_dir_all(remote_cache_dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use kidobo_app::flush::FlushBackend;
    use tempfile::TempDir;

    use super::{CommandFlushBackend, clear_remote_cache_dir};
    use crate::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::ipset::IpsetCommandRunner;
    use crate::iptables::FirewallCommandRunner;

    struct Runner {
        outcome: RefCell<Option<Result<CommandResult, CommandRunnerError>>>,
        calls: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl IpsetCommandRunner for Runner {
        fn run_os(
            &self,
            command: &str,
            args: &[&std::ffi::OsStr],
        ) -> Result<CommandResult, CommandRunnerError> {
            self.calls.borrow_mut().push((
                command.to_string(),
                args.iter()
                    .map(|arg| arg.to_string_lossy().into_owned())
                    .collect(),
            ));
            self.outcome.borrow_mut().take().expect("outcome")
        }
    }

    impl FirewallCommandRunner for Runner {
        fn run(&self, _command: &str, _args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            unreachable!("firewall commands are outside these ipset tests")
        }
    }

    fn backend_with_outcome(
        outcome: Result<CommandResult, CommandRunnerError>,
    ) -> CommandFlushBackend<Runner> {
        CommandFlushBackend::new(Runner {
            outcome: RefCell::new(Some(outcome)),
            calls: RefCell::new(Vec::new()),
        })
    }

    fn assert_destroy_call(backend: &CommandFlushBackend<Runner>, set_name: &str) {
        assert_eq!(
            backend.runner.calls.borrow().as_slice(),
            [(
                "ipset".to_string(),
                vec!["destroy".to_string(), set_name.to_string()]
            )]
        );
    }

    #[test]
    fn clears_and_recreates_remote_cache_directory() {
        let temp = TempDir::new().expect("tempdir");
        let cache = temp.path().join("remote");
        fs::create_dir_all(&cache).expect("mkdir");
        fs::write(cache.join("old.iplist"), "old").expect("write");

        clear_remote_cache_dir(&cache).expect("clear");

        assert!(cache.is_dir());
        assert_eq!(fs::read_dir(cache).expect("read dir").count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn cache_cleanup_rejects_a_symlinked_parent_without_deleting_outside_files() {
        let temp = TempDir::new().expect("tempdir");
        let outside = temp.path().join("outside");
        fs::create_dir_all(outside.join("remote")).expect("outside cache");
        fs::write(outside.join("remote/sentinel"), "preserve").expect("outside sentinel");
        let parent = temp.path().join("cache");
        std::os::unix::fs::symlink(&outside, &parent).expect("cache parent symlink");
        let backend = backend_with_outcome(Ok(CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        }));
        let error = backend
            .clear_remote_cache(&parent.join("remote"))
            .expect_err("symlinked cache parent must fail closed");
        assert!(error.raw_os_error().is_some());
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&outside.join("remote/sentinel"), 1024)
                .expect("outside survived"),
            "preserve"
        );
        assert_eq!(backend.runner.calls.borrow().len(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn cache_cleanup_uses_the_pinned_parent_after_path_replacement() {
        let temp = TempDir::new().expect("tempdir");
        let parent = temp.path().join("cache");
        let outside = temp.path().join("outside");
        for directory in [&parent, &outside] {
            fs::create_dir_all(directory.join("remote")).expect("cache directory");
            fs::write(directory.join("remote/sentinel"), "preserve").expect("cache sentinel");
        }
        let descriptor = super::pin_cache_parent(&parent.join("remote")).expect("pin parent");
        let moved = temp.path().join("moved-cache");
        fs::rename(&parent, &moved).expect("move pinned parent");
        std::os::unix::fs::symlink(&outside, &parent).expect("replace parent");
        super::clear_pinned_cache_dir(&descriptor, std::ffi::OsStr::new("remote"))
            .expect("clear pinned cache");
        assert!(!moved.join("remote/sentinel").exists());
        assert!(moved.join("remote").is_dir());
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&outside.join("remote/sentinel"), 1024)
                .expect("outside survived"),
            "preserve"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cache_cleanup_unlinks_a_final_symlink_without_following_its_target() {
        let temp = TempDir::new().expect("tempdir");
        let outside = temp.path().join("outside");
        fs::create_dir(&outside).expect("outside directory");
        fs::write(outside.join("sentinel"), "preserve").expect("outside sentinel");
        let remote = temp.path().join("remote");
        std::os::unix::fs::symlink(&outside, &remote).expect("remote symlink");
        clear_remote_cache_dir(&remote).expect("unlink remote symlink");
        assert!(!remote.is_symlink());
        assert!(remote.is_dir());
        assert_eq!(
            crate::limited_io::read_to_string_with_limit(&outside.join("sentinel"), 1024)
                .expect("outside survived"),
            "preserve"
        );
    }

    #[test]
    fn successful_ipset_cleanup_records_exact_command() {
        let backend = backend_with_outcome(Ok(CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        }));

        backend.destroy_ipset("kidobo").expect("success");

        assert_destroy_call(&backend, "kidobo");
    }

    #[test]
    fn missing_ipset_is_an_idempotent_success_and_records_exact_command() {
        let backend = backend_with_outcome(Ok(CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "The set with the given name does not exist".to_string(),
        }));

        backend.destroy_ipset("kidobo").expect("missing is success");

        assert_destroy_call(&backend, "kidobo");
    }

    #[test]
    fn unrelated_ipset_failure_preserves_status_stderr_and_command() {
        let backend = backend_with_outcome(Ok(CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "busy".to_string(),
        }));

        let error = backend.destroy_ipset("kidobo").expect_err("must fail");
        assert_eq!(
            error,
            "ipset destroy kidobo failed (status=Exited(1) stderr=busy)"
        );
        assert_destroy_call(&backend, "kidobo");
    }

    #[cfg(unix)]
    #[test]
    fn signaled_ipset_failure_preserves_status_and_command() {
        let backend = backend_with_outcome(Ok(CommandResult {
            status: ProcessStatus::Signaled(9),
            stdout: String::new(),
            stderr: "terminated".to_string(),
        }));

        let error = backend
            .destroy_ipset("kidobo")
            .expect_err("signal must fail");
        assert_eq!(
            error,
            "ipset destroy kidobo failed (status=Signaled(9) stderr=terminated)"
        );
        assert_destroy_call(&backend, "kidobo");
    }

    #[test]
    fn runner_error_preserves_execution_diagnostic_and_command() {
        let error = CommandRunnerError::Spawn {
            command: "ipset destroy kidobo".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "missing binary"),
        };
        let backend = backend_with_outcome(Err(error));

        let error = backend
            .destroy_ipset("kidobo")
            .expect_err("runner error must fail");
        assert_eq!(
            error,
            "ipset destroy kidobo execution failed (failed to spawn command `ipset destroy kidobo`: missing binary)"
        );
        assert_destroy_call(&backend, "kidobo");
    }
}
