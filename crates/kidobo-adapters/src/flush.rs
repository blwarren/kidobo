//! Filesystem and firewall implementation of the flush application port.

use std::fs;
use std::path::Path;

use kidobo_app::flush::{FirewallFamily as AppFirewallFamily, FlushBackend};

use crate::command_common::display_command;
use crate::command_runner::{
    CommandResult, CommandRunnerError, SudoCommandRunner, SystemCommandExecutor,
};
use crate::ipset::IpsetCommandRunner;
use crate::iptables::{FirewallCommandRunner, FirewallFamily, cleanup_firewall_wiring};

#[derive(Debug)]
pub struct CommandFlushBackend<R> {
    runner: R,
}

impl<R> CommandFlushBackend<R> {
    #[must_use]
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl Default for CommandFlushBackend<SudoCommandRunner<SystemCommandExecutor>> {
    fn default() -> Self {
        Self::new(SudoCommandRunner::default())
    }
}

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
        run_cleanup_command("ipset", &["destroy", set_name], |command, args| {
            IpsetCommandRunner::run(&self.runner, command, args)
        })
    }

    fn clear_remote_cache(&self, path: &Path) -> Result<(), String> {
        clear_remote_cache_dir(path).map_err(|error| error.to_string())
    }
}

fn run_cleanup_command<F>(command: &str, args: &[&str], run: F) -> Result<(), String>
where
    F: FnOnce(&str, &[&str]) -> Result<CommandResult, CommandRunnerError>,
{
    let rendered = display_command(command, args);
    match run(command, args) {
        Ok(result) if result.status.success() || is_missing_ipset_result(&result) => Ok(()),
        Ok(result) => Err(format!(
            "{rendered} failed (status={:?} stderr={})",
            result.status, result.stderr
        )),
        Err(error) => Err(format!("{rendered} execution failed ({error})")),
    }
}

fn is_missing_ipset_result(result: &CommandResult) -> bool {
    result.status.code() == Some(1)
        && result
            .stderr
            .to_ascii_lowercase()
            .contains("does not exist")
}

fn clear_remote_cache_dir(remote_cache_dir: &Path) -> Result<(), std::io::Error> {
    if remote_cache_dir.exists() {
        fs::remove_dir_all(remote_cache_dir)?;
    }
    fs::create_dir_all(remote_cache_dir)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::fs;

    use kidobo_app::flush::FlushBackend;
    use tempfile::TempDir;

    use super::{CommandFlushBackend, clear_remote_cache_dir, run_cleanup_command};
    use crate::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::ipset::IpsetCommandRunner;
    use crate::iptables::FirewallCommandRunner;

    struct Runner {
        response: RefCell<Option<CommandResult>>,
    }

    impl IpsetCommandRunner for Runner {
        fn run(&self, _command: &str, _args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.response.borrow_mut().take().expect("response"))
        }
    }

    impl FirewallCommandRunner for Runner {
        fn run(&self, _command: &str, _args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.response.borrow_mut().take().expect("response"))
        }
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

    #[test]
    fn missing_ipset_is_an_idempotent_success() {
        let result = CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "The set with the given name does not exist".to_string(),
        };

        run_cleanup_command("ipset", &["destroy", "kidobo"], |_command, _args| {
            Ok(result)
        })
        .expect("missing is success");
    }

    #[test]
    fn backend_maps_failed_ipset_cleanup_to_existing_diagnostic() {
        let backend = CommandFlushBackend::new(Runner {
            response: RefCell::new(Some(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "busy".to_string(),
            })),
        });

        let error = backend.destroy_ipset("kidobo").expect_err("must fail");
        assert!(error.contains("ipset destroy kidobo failed"));
        assert!(error.contains("busy"));
    }
}
