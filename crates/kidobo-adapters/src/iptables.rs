//! Fail-closed iptables adapter.

use thiserror::Error;

use crate::command_common::{display_command, ensure_command_succeeded};
use crate::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, ProcessStatus, SudoCommandRunner,
};

pub const KIDOBO_CHAIN_NAME: &str = "kidobo-input";
const XTABLES_LOCK_WAIT_SECS: &str = "5";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAction {
    Drop,
    Reject,
}

impl ChainAction {
    fn as_target(self) -> &'static str {
        match self {
            Self::Drop => "DROP",
            Self::Reject => "REJECT",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallFamily {
    Ipv4,
    Ipv6,
}

impl FirewallFamily {
    fn binary(self) -> &'static str {
        match self {
            Self::Ipv4 => "iptables",
            Self::Ipv6 => "ip6tables",
        }
    }
}

#[derive(Debug, Error)]
pub enum FirewallError {
    #[error("firewall command execution failed: {source}")]
    CommandExecution {
        #[from]
        source: CommandRunnerError,
    },

    #[error("firewall command failed `{command}` with status {status:?}: {stderr}")]
    CommandFailed {
        command: String,
        status: ProcessStatus,
        stderr: String,
    },
}

pub trait FirewallCommandRunner {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> FirewallCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

pub fn chain_exists(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<bool, FirewallError> {
    let binary = family.binary();
    let args = with_lock_wait(&["-S", chain_name]);
    let result = runner.run(binary, &args)?;
    if result.status.success() {
        return Ok(true);
    }

    if is_missing_chain_result(&result) {
        return Ok(false);
    }

    Err(FirewallError::CommandFailed {
        command: display_command(binary, &args),
        status: result.status,
        stderr: result.stderr,
    })
}

pub fn ensure_firewall_wiring(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    set_name: &str,
    chain_action: ChainAction,
) -> Result<(), FirewallError> {
    ensure_chain_exists(runner, family, KIDOBO_CHAIN_NAME)?;
    replace_chain_rule_fail_closed(
        runner,
        family,
        KIDOBO_CHAIN_NAME,
        set_name,
        chain_action.as_target(),
    )?;
    normalize_input_jump_fail_closed(runner, family, KIDOBO_CHAIN_NAME)?;
    Ok(())
}

pub fn ensure_firewall_wiring_for_families(
    runner: &dyn FirewallCommandRunner,
    set_name_v4: &str,
    set_name_v6: &str,
    enable_ipv6: bool,
    chain_action: ChainAction,
) -> Result<(), FirewallError> {
    ensure_firewall_wiring(runner, FirewallFamily::Ipv4, set_name_v4, chain_action)?;

    if enable_ipv6 {
        ensure_firewall_wiring(runner, FirewallFamily::Ipv6, set_name_v6, chain_action)?;
    }

    Ok(())
}

pub fn ensure_firewall_artifacts_for_families(
    runner: &dyn FirewallCommandRunner,
    enable_ipv6: bool,
) -> Result<(), FirewallError> {
    ensure_chain_exists(runner, FirewallFamily::Ipv4, KIDOBO_CHAIN_NAME)?;
    if enable_ipv6 {
        ensure_chain_exists(runner, FirewallFamily::Ipv6, KIDOBO_CHAIN_NAME)?;
    }
    Ok(())
}

pub fn cleanup_firewall_wiring(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
) -> Result<(), FirewallError> {
    let jump_result = remove_all_input_jumps_for_chain(runner, family, KIDOBO_CHAIN_NAME);
    let flush_result =
        run_checked_allow_missing_chain(runner, family.binary(), &["-F", KIDOBO_CHAIN_NAME]);
    let delete_result =
        run_checked_allow_missing_chain(runner, family.binary(), &["-X", KIDOBO_CHAIN_NAME]);

    jump_result?;
    flush_result?;
    delete_result
}

fn ensure_chain_exists(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    if chain_exists(runner, family, chain_name)? {
        return Ok(());
    }

    run_checked(runner, family.binary(), &["-N", chain_name]).map(|_| ())
}

pub fn remove_all_input_jumps_for_chain(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();

    loop {
        let args = with_lock_wait(&["-D", "INPUT", "-j", chain_name]);
        let result = runner.run(binary, &args)?;
        if result.status.success() {
            continue;
        }

        if is_missing_rule_result(&result) {
            break;
        }

        return Err(FirewallError::CommandFailed {
            command: display_command(binary, &args),
            status: result.status,
            stderr: result.stderr,
        });
    }

    Ok(())
}

fn normalize_input_jump_fail_closed(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();
    let current = run_checked(runner, binary, &["-S", "INPUT"])?;
    let old_positions = exact_jump_positions(&current.stdout, chain_name);

    run_checked(runner, binary, &["-I", "INPUT", "1", "-j", chain_name])?;

    for old_position in old_positions.into_iter().rev() {
        let shifted_position = (old_position + 1).to_string();
        run_checked(runner, binary, &["-D", "INPUT", &shifted_position])?;
    }

    Ok(())
}

fn replace_chain_rule_fail_closed(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
    set_name: &str,
    target: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();
    let current = run_checked(runner, binary, &["-S", chain_name])?;
    let old_rule_count = chain_rule_count(&current.stdout, chain_name);
    run_checked(
        runner,
        binary,
        &[
            "-A",
            chain_name,
            "-m",
            "set",
            "--match-set",
            set_name,
            "src",
            "-j",
            target,
        ],
    )?;

    for _ in 0..old_rule_count {
        run_checked(runner, binary, &["-D", chain_name, "1"])?;
    }

    Ok(())
}

fn chain_rule_count(stdout: &str, chain_name: &str) -> usize {
    let prefix = format!("-A {chain_name} ");
    stdout
        .lines()
        .filter(|line| line.starts_with(&prefix))
        .count()
}

fn exact_jump_positions(stdout: &str, chain_name: &str) -> Vec<usize> {
    let expected = format!("-A INPUT -j {chain_name}");
    stdout
        .lines()
        .filter(|line| line.starts_with("-A INPUT "))
        .enumerate()
        .filter_map(|(idx, line)| (line.trim() == expected).then_some(idx + 1))
        .collect()
}

fn with_lock_wait<'a>(args: &[&'a str]) -> Vec<&'a str> {
    let mut waited = Vec::with_capacity(args.len() + 2);
    waited.push("-w");
    waited.push(XTABLES_LOCK_WAIT_SECS);
    waited.extend_from_slice(args);
    waited
}

fn run_checked(
    runner: &dyn FirewallCommandRunner,
    command: &str,
    args: &[&str],
) -> Result<CommandResult, FirewallError> {
    let waited_args = with_lock_wait(args);
    let result = runner.run(command, &waited_args)?;
    ensure_command_succeeded(result, command, &waited_args, |rendered, status, stderr| {
        FirewallError::CommandFailed {
            command: rendered,
            status,
            stderr,
        }
    })
}

fn run_checked_allow_missing_chain(
    runner: &dyn FirewallCommandRunner,
    command: &str,
    args: &[&str],
) -> Result<(), FirewallError> {
    let waited_args = with_lock_wait(args);
    let result = runner.run(command, &waited_args)?;
    if result.status.success() || is_missing_chain_result(&result) {
        return Ok(());
    }

    Err(FirewallError::CommandFailed {
        command: display_command(command, &waited_args),
        status: result.status,
        stderr: result.stderr,
    })
}

fn is_missing_chain_result(result: &CommandResult) -> bool {
    result.status.code() == Some(1)
        && result
            .stderr
            .to_ascii_lowercase()
            .contains("no chain/target/match by that name")
}

fn is_missing_rule_result(result: &CommandResult) -> bool {
    result.status.code() == Some(1) && result.stderr.to_ascii_lowercase().contains("bad rule")
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use super::{
        ChainAction, FirewallCommandRunner, FirewallError, FirewallFamily, KIDOBO_CHAIN_NAME,
        chain_exists, cleanup_firewall_wiring, ensure_firewall_wiring,
        ensure_firewall_wiring_for_families, remove_all_input_jumps_for_chain,
    };
    use crate::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};

    struct MockRunner {
        responses: RefCell<VecDeque<Result<CommandResult, CommandRunnerError>>>,
        invocations: RefCell<Vec<(String, Vec<String>)>>,
    }

    impl MockRunner {
        fn new(responses: Vec<Result<CommandResult, CommandRunnerError>>) -> Self {
            Self {
                responses: RefCell::new(VecDeque::from(responses)),
                invocations: RefCell::new(Vec::new()),
            }
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.invocations.borrow().clone()
        }
    }

    impl FirewallCommandRunner for MockRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            self.invocations.borrow_mut().push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    fn ok(status: i32) -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(status),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn chain_exists_maps_missing_chain_to_false() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "iptables: No chain/target/match by that name.".to_string(),
        })]);

        let exists =
            chain_exists(&runner, FirewallFamily::Ipv4, KIDOBO_CHAIN_NAME).expect("exists");
        assert!(!exists);
        assert_eq!(
            runner.invocations()[0].1,
            vec!["-w", "5", "-S", KIDOBO_CHAIN_NAME]
        );
    }

    #[test]
    fn firewall_family_selects_exact_binary() {
        assert_eq!(FirewallFamily::Ipv4.binary(), "iptables");
        assert_eq!(FirewallFamily::Ipv6.binary(), "ip6tables");
    }

    #[test]
    fn jump_cleanup_propagates_nonmissing_delete_failure() {
        let runner = MockRunner::new(vec![Ok(CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "permission denied".to_string(),
        })]);

        let err =
            remove_all_input_jumps_for_chain(&runner, FirewallFamily::Ipv4, KIDOBO_CHAIN_NAME)
                .expect_err("nonmissing delete failure");

        assert!(matches!(err, FirewallError::CommandFailed { .. }));
        assert_eq!(runner.invocations().len(), 1);
    }

    #[test]
    fn ensures_chain_rule_before_input_jump_without_flushing() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "No chain/target/match by that name".to_string(),
            }),
            Ok(ok(0)), // -N chain
            Ok(ok(0)), // -S empty chain
            Ok(ok(0)), // -A chain drop rule
            Ok(ok(0)), // -S INPUT
            Ok(ok(0)), // -I INPUT 1 -j chain
        ]);

        ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(invocations[0].0, "iptables");
        assert_eq!(invocations[0].1, vec!["-w", "5", "-S", KIDOBO_CHAIN_NAME]);
        assert_eq!(invocations[1].1, vec!["-w", "5", "-N", KIDOBO_CHAIN_NAME]);
        assert_eq!(invocations[2].1, vec!["-w", "5", "-S", KIDOBO_CHAIN_NAME]);
        assert_eq!(
            invocations[3].1,
            vec![
                "-w",
                "5",
                "-A",
                KIDOBO_CHAIN_NAME,
                "-m",
                "set",
                "--match-set",
                "kidobo-set",
                "src",
                "-j",
                "DROP",
            ]
        );
        assert_eq!(invocations[4].1, vec!["-w", "5", "-S", "INPUT"]);
        assert_eq!(
            invocations[5].1,
            vec!["-w", "5", "-I", "INPUT", "1", "-j", KIDOBO_CHAIN_NAME]
        );
        assert!(
            invocations
                .iter()
                .all(|(_, args)| !args.contains(&"-F".to_string()))
        );
    }

    #[test]
    fn removes_old_input_jumps_only_after_reinserting() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "-N kidobo-input\n-A kidobo-input -j DROP\n".to_string(),
                stderr: String::new(),
            }), // -S chain exists
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "-N kidobo-input\n-A kidobo-input -j DROP\n".to_string(),
                stderr: String::new(),
            }), // -S chain rules
            Ok(ok(0)), // append desired
            Ok(ok(0)), // delete old chain rule
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: format!(
                    "-A INPUT -j {KIDOBO_CHAIN_NAME}\n-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j {KIDOBO_CHAIN_NAME}\n"
                ),
                stderr: String::new(),
            }), // -S INPUT
            Ok(ok(0)), // insert new jump
            Ok(ok(0)), // delete old jump at shifted position 4
            Ok(ok(0)), // delete old jump at shifted position 2
        ]);

        ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(
            invocations[5].1,
            vec!["-w", "5", "-I", "INPUT", "1", "-j", KIDOBO_CHAIN_NAME]
        );
        assert_eq!(invocations[6].1, vec!["-w", "5", "-D", "INPUT", "4"]);
        assert_eq!(invocations[7].1, vec!["-w", "5", "-D", "INPUT", "2"]);
    }

    #[test]
    fn append_failure_leaves_old_chain_rule_and_input_jump_untouched() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "-N kidobo-input\n-A kidobo-input -j DROP\n".to_string(),
                stderr: String::new(),
            }), // chain exists
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "-N kidobo-input\n-A kidobo-input -j DROP\n".to_string(),
                stderr: String::new(),
            }), // query rules
            Ok(CommandResult {
                status: ProcessStatus::Exited(2),
                stdout: String::new(),
                stderr: "append failed".to_string(),
            }), // append fails
        ]);

        let err = ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect_err("wiring must fail");

        assert!(matches!(err, FirewallError::CommandFailed { .. }));
        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 3);
        assert!(
            invocations
                .iter()
                .all(|(_, args)| !args.contains(&"-D".to_string()))
        );
        assert!(
            invocations
                .iter()
                .all(|(_, args)| !args.contains(&"-I".to_string()))
        );
    }

    #[test]
    fn old_rule_delete_failure_leaves_new_rule_in_place() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "-A kidobo-input -j DROP\n".to_string(),
                stderr: String::new(),
            }), // chain exists
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: "-A kidobo-input -j DROP\n".to_string(),
                stderr: String::new(),
            }), // query rules
            Ok(ok(0)), // append desired
            Ok(CommandResult {
                status: ProcessStatus::Exited(2),
                stdout: String::new(),
                stderr: "delete failed".to_string(),
            }), // delete old fails
        ]);

        let err = ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect_err("wiring must fail");

        assert!(matches!(err, FirewallError::CommandFailed { .. }));
        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 4);
        assert!(invocations[2].1.contains(&"-A".to_string()));
        assert_eq!(
            invocations[3].1,
            vec!["-w", "5", "-D", KIDOBO_CHAIN_NAME, "1"]
        );
    }

    #[test]
    fn supports_ipv6_parallel_wiring() {
        let runner = MockRunner::new((0..10).map(|_| Ok(ok(0))).collect());

        ensure_firewall_wiring_for_families(
            &runner,
            "kidobo-v4",
            "kidobo-v6",
            true,
            ChainAction::Drop,
        )
        .expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(invocations[0].0, "iptables");
        assert_eq!(invocations[5].0, "ip6tables");
    }

    #[test]
    fn supports_reject_target_rule() {
        let runner = MockRunner::new((0..5).map(|_| Ok(ok(0))).collect());

        ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Reject,
        )
        .expect("wiring");

        let invocations = runner.invocations();
        assert_eq!(
            invocations[2].1,
            vec![
                "-w",
                "5",
                "-A",
                KIDOBO_CHAIN_NAME,
                "-m",
                "set",
                "--match-set",
                "kidobo-set",
                "src",
                "-j",
                "REJECT",
            ]
        );
    }

    #[test]
    fn input_jump_insert_failure_does_not_delete_existing_jump() {
        let runner = MockRunner::new(vec![
            Ok(ok(0)),
            Ok(ok(0)),
            Ok(ok(0)),
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: format!("-A INPUT -j {KIDOBO_CHAIN_NAME}\n"),
                stderr: String::new(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(2),
                stdout: String::new(),
                stderr: "insert failed".to_string(),
            }),
        ]);

        let err = ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect_err("insert must fail");

        assert!(matches!(err, FirewallError::CommandFailed { .. }));
        let invocations = runner.invocations();
        assert_eq!(invocations.len(), 5);
        assert!(
            invocations
                .iter()
                .all(|(_, args)| { args.as_slice() != ["-w", "5", "-D", "INPUT", "2"] })
        );
    }

    #[test]
    fn cleanup_firewall_wiring_removes_jumps_and_deletes_chain() {
        let runner = MockRunner::new(vec![
            Ok(ok(0)), // first -D INPUT -j chain
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
            }),
            Ok(ok(0)), // -F chain
            Ok(ok(0)), // -X chain
        ]);

        cleanup_firewall_wiring(&runner, FirewallFamily::Ipv6).expect("cleanup");

        let invocations = runner.invocations();
        assert_eq!(
            invocations,
            vec![
                (
                    "ip6tables".to_string(),
                    vec![
                        "-w".to_string(),
                        "5".to_string(),
                        "-D".to_string(),
                        "INPUT".to_string(),
                        "-j".to_string(),
                        KIDOBO_CHAIN_NAME.to_string()
                    ]
                ),
                (
                    "ip6tables".to_string(),
                    vec![
                        "-w".to_string(),
                        "5".to_string(),
                        "-D".to_string(),
                        "INPUT".to_string(),
                        "-j".to_string(),
                        KIDOBO_CHAIN_NAME.to_string()
                    ]
                ),
                (
                    "ip6tables".to_string(),
                    vec![
                        "-w".to_string(),
                        "5".to_string(),
                        "-F".to_string(),
                        KIDOBO_CHAIN_NAME.to_string()
                    ]
                ),
                (
                    "ip6tables".to_string(),
                    vec![
                        "-w".to_string(),
                        "5".to_string(),
                        "-X".to_string(),
                        KIDOBO_CHAIN_NAME.to_string()
                    ]
                ),
            ]
        );
    }

    #[test]
    fn cleanup_firewall_wiring_treats_missing_chain_as_success() {
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "No chain/target/match by that name".to_string(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "No chain/target/match by that name".to_string(),
            }),
        ]);

        cleanup_firewall_wiring(&runner, FirewallFamily::Ipv6).expect("cleanup");
    }
}
