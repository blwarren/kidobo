use std::fs;
use std::path::Path;

use crate::adapters::command_common::display_command;
use crate::adapters::command_runner::{CommandResult, CommandRunnerError, SudoCommandRunner};
use crate::adapters::config::load_config_from_file;
use crate::adapters::ipset::IpsetCommandRunner;
use crate::adapters::iptables::{FirewallCommandRunner, FirewallFamily, cleanup_firewall_wiring};
use crate::adapters::lock::acquire_non_blocking;
use crate::adapters::path::{PathResolutionInput, resolve_paths, resolve_paths_without_config};
use crate::core::config::Config;
use crate::error::KidoboError;

pub fn run_flush_command(cache_only: bool) -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = if cache_only {
        resolve_paths_without_config(&path_input)?
    } else {
        resolve_paths(&path_input)?
    };

    let _lock = acquire_non_blocking(&paths.lock_file)?;

    if cache_only {
        clear_remote_cache_dir(&paths.remote_cache_dir)?;
        return Ok(());
    }

    let config = load_config_from_file(&paths.config_file)?;
    let sudo_runner = SudoCommandRunner::default();
    run_flush_with_runner(&config, &sudo_runner, &sudo_runner, &paths.remote_cache_dir)
}

pub(crate) fn run_flush_with_runner(
    config: &Config,
    firewall_runner: &dyn FirewallCommandRunner,
    ipset_runner: &dyn IpsetCommandRunner,
    remote_cache_dir: &Path,
) -> Result<(), KidoboError> {
    let mut failures = Vec::new();
    cleanup_firewall_family(firewall_runner, FirewallFamily::Ipv4, &mut failures);
    cleanup_firewall_family(firewall_runner, FirewallFamily::Ipv6, &mut failures);

    destroy_ipset(ipset_runner, &config.ipset.set_name, &mut failures);
    if config.ipset.set_name_v6 != config.ipset.set_name {
        destroy_ipset(ipset_runner, &config.ipset.set_name_v6, &mut failures);
    }

    if let Err(err) = clear_remote_cache_dir(remote_cache_dir) {
        failures.push(err.to_string());
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(KidoboError::FlushIncomplete {
            failures: failures.len(),
            details: failures.join("; "),
        })
    }
}

fn cleanup_firewall_family(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    failures: &mut Vec<String>,
) {
    if let Err(err) = cleanup_firewall_wiring(runner, family) {
        failures.push(format!("firewall cleanup failed for {family:?}: {err}"));
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
        Err(err) => Err(format!("{rendered} execution failed ({err})")),
    }
}

fn destroy_ipset(runner: &dyn IpsetCommandRunner, set_name: &str, failures: &mut Vec<String>) {
    if let Err(err) = run_cleanup_command("ipset", &["destroy", set_name], |command, args| {
        runner.run(command, args)
    }) {
        failures.push(err);
    }
}

fn is_missing_ipset_result(result: &CommandResult) -> bool {
    result.status.code() == Some(1)
        && result
            .stderr
            .to_ascii_lowercase()
            .contains("does not exist")
}

fn clear_remote_cache_dir(remote_cache_dir: &Path) -> Result<(), KidoboError> {
    if remote_cache_dir.exists() {
        fs::remove_dir_all(remote_cache_dir).map_err(|err| KidoboError::FlushCacheIo {
            path: remote_cache_dir.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    fs::create_dir_all(remote_cache_dir).map_err(|err| KidoboError::FlushCacheIo {
        path: remote_cache_dir.to_path_buf(),
        reason: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::Path;

    use super::{clear_remote_cache_dir, run_cleanup_command, run_flush_with_runner};
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::adapters::ipset::IpsetCommandRunner;
    use crate::adapters::iptables::FirewallCommandRunner;
    use crate::core::config::{
        AsnCacheStaleAfterSecs, AsnConfig, Config, FirewallAction, HashsizePow2, IpsetConfig,
        MaxElem, RemoteConfig, RemoteTimeoutSecs, SafeConfig,
    };
    use tempfile::TempDir;

    struct MockRunner {
        invocations: RefCell<Vec<(String, Vec<String>)>>,
        jump_budget: RefCell<BTreeMap<String, usize>>,
        fail_cleanup: bool,
    }

    impl MockRunner {
        fn new(ipv4_jump_count: usize, ipv6_jump_count: usize, fail_cleanup: bool) -> Self {
            let mut jump_budget = BTreeMap::new();
            jump_budget.insert("iptables".to_string(), ipv4_jump_count);
            jump_budget.insert("ip6tables".to_string(), ipv6_jump_count);

            Self {
                invocations: RefCell::new(Vec::new()),
                jump_budget: RefCell::new(jump_budget),
                fail_cleanup,
            }
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.invocations.borrow().clone()
        }

        fn run_impl(&self, command: &str, args: &[&str]) -> CommandResult {
            self.invocations.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));

            let effective_args = if args.starts_with(&["-w", "5"]) {
                &args[2..]
            } else {
                args
            };

            if effective_args == ["-D", "INPUT", "-j", "kidobo-input"] {
                let mut budget = self.jump_budget.borrow_mut();
                let remaining = budget.get_mut(command).expect("jump budget");
                if *remaining > 0 {
                    *remaining -= 1;
                    return success();
                }

                return CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
                };
            }

            if self.fail_cleanup
                && ((command == "iptables" || command == "ip6tables")
                    && (effective_args.first() == Some(&"-F")
                        || effective_args.first() == Some(&"-X"))
                    || (command == "ipset" && effective_args.first() == Some(&"destroy")))
            {
                return CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "not found".to_string(),
                };
            }

            success()
        }
    }

    impl IpsetCommandRunner for MockRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run_impl(command, args))
        }
    }

    impl FirewallCommandRunner for MockRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run_impl(command, args))
        }
    }

    fn success() -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn test_config(enable_ipv6: bool) -> Config {
        Config {
            ipset: IpsetConfig {
                set_name: "kidobo".to_string(),
                set_name_v6: "kidobo-v6".to_string(),
                enable_ipv6,
                chain_action: FirewallAction::Drop,
                set_type: "hash:net".to_string(),
                hashsize: HashsizePow2::new(65536).expect("valid hashsize"),
                maxelem: MaxElem::new(500000).expect("valid maxelem"),
                timeout: 0,
            },
            safe: SafeConfig {
                ips: Vec::new(),
                include_github_meta: false,
                github_meta_url: "https://api.github.com/meta".to_string(),
                github_meta_categories: None,
            },
            remote: RemoteConfig {
                urls: Vec::new(),
                timeout_secs: RemoteTimeoutSecs::new(30).expect("valid timeout"),
            },
            asn: AsnConfig {
                banned: Vec::new(),
                cache_stale_after_secs: AsnCacheStaleAfterSecs::new(86_400).expect("valid stale"),
            },
        }
    }

    #[test]
    fn flush_attempts_all_cleanup_steps_with_ipv6_enabled() {
        let config = test_config(true);
        let runner = MockRunner::new(2, 1, false);
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote cache");

        run_flush_with_runner(&config, &runner, &runner, &remote_cache_dir).expect("flush");

        let invocations = runner.invocations();

        let v4_jump_deletes = invocations
            .iter()
            .filter(|(cmd, args)| {
                cmd == "iptables" && args == &["-w", "5", "-D", "INPUT", "-j", "kidobo-input"]
            })
            .count();
        assert_eq!(v4_jump_deletes, 3);

        let v6_jump_deletes = invocations
            .iter()
            .filter(|(cmd, args)| {
                cmd == "ip6tables" && args == &["-w", "5", "-D", "INPUT", "-j", "kidobo-input"]
            })
            .count();
        assert_eq!(v6_jump_deletes, 2);

        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "iptables" && args == &["-w", "5", "-F", "kidobo-input"])
        );
        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "iptables" && args == &["-w", "5", "-X", "kidobo-input"])
        );
        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "ip6tables" && args == &["-w", "5", "-F", "kidobo-input"])
        );
        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "ip6tables" && args == &["-w", "5", "-X", "kidobo-input"])
        );
        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "ipset" && args == &["destroy", "kidobo"])
        );
        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "ipset" && args == &["destroy", "kidobo-v6"])
        );
        assert!(remote_cache_dir.exists());
    }

    #[test]
    fn flush_attempts_ipv6_cleanup_when_disabled_to_remove_stale_artifacts() {
        let config = test_config(false);
        let runner = MockRunner::new(1, 99, false);
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote cache");

        run_flush_with_runner(&config, &runner, &runner, &remote_cache_dir).expect("flush");

        let invocations = runner.invocations();
        assert!(invocations.iter().any(|(cmd, _)| cmd == "ip6tables"));
        assert!(
            invocations
                .iter()
                .any(|(cmd, args)| cmd == "ipset" && args == &["destroy", "kidobo-v6"])
        );
    }

    #[test]
    fn flush_is_idempotent_under_missing_artifacts() {
        let config = test_config(true);
        let runner = MockRunner::new(0, 0, false);
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote cache");

        run_flush_with_runner(&config, &runner, &runner, &remote_cache_dir).expect("first flush");
        run_flush_with_runner(&config, &runner, &runner, &remote_cache_dir).expect("second flush");

        let invocations = runner.invocations();
        let destroy_calls = invocations
            .iter()
            .filter(|(cmd, args)| cmd == "ipset" && args.first() == Some(&"destroy".to_string()))
            .count();

        assert_eq!(
            destroy_calls, 4,
            "two sets destroyed per run across two runs"
        );
    }

    #[test]
    fn flush_clears_remote_cache_even_when_command_cleanup_fails() {
        let config = test_config(true);
        let runner = MockRunner::new(1, 1, true);
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(remote_cache_dir.join("nested")).expect("mkdir nested");
        fs::write(remote_cache_dir.join("one.iplist"), "10.0.0.0/24").expect("write iplist");
        fs::write(remote_cache_dir.join("nested/two.raw"), "raw").expect("write raw");

        let err = run_flush_with_runner(&config, &runner, &runner, &remote_cache_dir)
            .expect_err("cleanup failures must be reported");
        match err {
            crate::error::KidoboError::FlushIncomplete { failures, details } => {
                assert_eq!(failures, 4);
                for expected in [
                    "Ipv4",
                    "Ipv6",
                    "ipset destroy kidobo",
                    "ipset destroy kidobo-v6",
                ] {
                    assert!(
                        details.contains(expected),
                        "missing `{expected}` in: {details}"
                    );
                }
            }
            _ => panic!("expected FlushIncomplete"),
        }

        assert!(remote_cache_dir.exists());
        let entries = fs::read_dir(&remote_cache_dir)
            .expect("read dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect entries");
        assert!(entries.is_empty());
    }

    #[test]
    fn clear_remote_cache_dir_removes_existing_cached_files() {
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote");
        fs::write(remote_cache_dir.join("one.iplist"), "10.0.0.0/24").expect("write iplist");
        fs::create_dir_all(remote_cache_dir.join("nested")).expect("mkdir nested");
        fs::write(remote_cache_dir.join("nested/two.raw"), "raw").expect("write raw");

        clear_remote_cache_dir(&remote_cache_dir).expect("clear cache");

        assert!(remote_cache_dir.exists());
        let entries = fs::read_dir(&remote_cache_dir)
            .expect("read dir")
            .collect::<Result<Vec<_>, _>>()
            .expect("collect entries");
        assert!(entries.is_empty());
    }

    #[test]
    fn clear_remote_cache_dir_creates_missing_directory() {
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        assert!(!Path::new(&remote_cache_dir).exists());

        clear_remote_cache_dir(&remote_cache_dir).expect("clear cache");

        assert!(remote_cache_dir.exists());
    }

    #[test]
    fn missing_ipset_is_an_idempotent_cleanup_success() {
        let result = run_cleanup_command("ipset", &["destroy", "kidobo"], |_, _| {
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "The set with the given name does not exist".to_string(),
            })
        });

        result.expect("missing ipset should be treated as successful cleanup");
    }
}
