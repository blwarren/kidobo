//! Fail-closed iptables adapter.

use thiserror::Error;

use crate::command_common::{display_command, ensure_command_succeeded};
use crate::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, ProcessStatus, SudoCommandRunner,
};

/// Stable Kidobo-owned enforcement chain name.
pub const KIDOBO_CHAIN_NAME: &str = "kidobo-input";
const KIDOBO_STAGING_CHAIN_NAME: &str = "kidobo-input-stage";
const XTABLES_LOCK_WAIT_SECS: &str = "5";

/// Firewall verdict used by the Kidobo-owned chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainAction {
    /// Silently discard matching packets.
    Drop,
    /// Reject matching packets.
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

/// Firewall command family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallFamily {
    /// IPv4 through `iptables`.
    Ipv4,
    /// IPv6 through `ip6tables`.
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

/// Failure while inspecting, activating, normalizing, or cleaning firewall wiring.
#[derive(Debug, Error)]
pub enum FirewallError {
    /// Bounded command execution failed.
    #[error("firewall command execution failed: {source}")]
    CommandExecution {
        /// Underlying command-runner failure.
        #[from]
        source: CommandRunnerError,
    },

    /// A firewall command returned an unsuccessful status.
    #[error("firewall command failed `{command}` with status {status:?}: {stderr}")]
    CommandFailed {
        /// Rendered command.
        command: String,
        /// Process termination state.
        status: ProcessStatus,
        /// Bounded standard error.
        stderr: String,
    },

    /// Final INPUT wiring violated the exact one-stable-jump invariant.
    #[error(
        "firewall INPUT wiring validation failed for {family:?}: stable={stable_positions:?}, staging={staging_positions:?}"
    )]
    UnexpectedInputWiring {
        /// Affected firewall family.
        family: FirewallFamily,
        /// One-based INPUT positions jumping to the stable chain.
        stable_positions: Vec<usize>,
        /// One-based INPUT positions jumping to the transient staging chain.
        staging_positions: Vec<usize>,
    },
}

/// Command boundary used by fail-closed firewall operations.
pub trait FirewallCommandRunner {
    /// Runs one bounded iptables-family command.
    ///
    /// # Errors
    ///
    /// Returns [`CommandRunnerError`] when command execution fails.
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> FirewallCommandRunner for SudoCommandRunner<E> {
    fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        SudoCommandRunner::run(self, command, args)
    }
}

/// Checks whether a named chain exists for one address family.
///
/// # Errors
///
/// Returns [`FirewallError`] when the inspection command cannot execute or fails for a reason
/// other than a missing chain.
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

/// Establishes and normalizes fail-closed wiring for one family.
///
/// # Errors
///
/// Returns [`FirewallError`] when the chain, set-match action, or position-one input jump cannot be
/// established or normalized.
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

/// Establishes IPv4 and optionally IPv6 managed firewall wiring.
///
/// # Errors
///
/// Returns the first [`FirewallError`] encountered while wiring an enabled family.
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

/// Ensures managed chains exist without activating new input jumps.
///
/// # Errors
///
/// Returns the first [`FirewallError`] encountered while preparing an enabled family.
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

/// Removes every managed input jump, then flushes and deletes the managed chain.
///
/// # Errors
///
/// Returns [`FirewallError`] when any required cleanup command fails for a reason other than an
/// already-missing rule or chain.
pub fn cleanup_firewall_wiring(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
) -> Result<(), FirewallError> {
    let staging_jump_result =
        remove_all_input_jumps_for_chain(runner, family, KIDOBO_STAGING_CHAIN_NAME);
    let stable_jump_result = remove_all_input_jumps_for_chain(runner, family, KIDOBO_CHAIN_NAME);
    let staging_flush_result = run_checked_allow_missing_chain(
        runner,
        family.binary(),
        &["-F", KIDOBO_STAGING_CHAIN_NAME],
    );
    let staging_delete_result = run_checked_allow_missing_chain(
        runner,
        family.binary(),
        &["-X", KIDOBO_STAGING_CHAIN_NAME],
    );
    let stable_flush_result =
        run_checked_allow_missing_chain(runner, family.binary(), &["-F", KIDOBO_CHAIN_NAME]);
    let stable_delete_result =
        run_checked_allow_missing_chain(runner, family.binary(), &["-X", KIDOBO_CHAIN_NAME]);

    staging_jump_result?;
    stable_jump_result?;
    staging_flush_result?;
    staging_delete_result?;
    stable_flush_result?;
    stable_delete_result
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

/// Repeatedly inspects and removes exact input jumps to a named chain until none remain.
///
/// # Errors
///
/// Returns [`FirewallError`] when inspection or deletion fails.
pub fn remove_all_input_jumps_for_chain(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();

    loop {
        let input = run_checked(runner, binary, &["-S", "INPUT"])?;
        if exact_jump_positions(&input.stdout, chain_name).is_empty() {
            return Ok(());
        }

        let args = with_lock_wait(&["-D", "INPUT", "-j", chain_name]);
        let result = runner.run(binary, &args)?;
        if result.status.success() {
            continue;
        }

        return Err(FirewallError::CommandFailed {
            command: display_command(binary, &args),
            status: result.status,
            stderr: result.stderr,
        });
    }
}

fn normalize_input_jump_fail_closed(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();
    ensure_chain_exists(runner, family, KIDOBO_STAGING_CHAIN_NAME)?;
    replace_chain_jump_fail_closed(runner, family, KIDOBO_STAGING_CHAIN_NAME, chain_name)?;

    run_checked(
        runner,
        binary,
        &["-I", "INPUT", "1", "-j", KIDOBO_STAGING_CHAIN_NAME],
    )?;
    remove_all_input_jumps_for_chain(runner, family, chain_name)?;
    run_checked(runner, binary, &["-I", "INPUT", "1", "-j", chain_name])?;
    remove_all_input_jumps_for_chain(runner, family, KIDOBO_STAGING_CHAIN_NAME)?;
    run_checked_allow_missing_chain(runner, binary, &["-F", KIDOBO_STAGING_CHAIN_NAME])?;
    run_checked_allow_missing_chain(runner, binary, &["-X", KIDOBO_STAGING_CHAIN_NAME])?;

    let final_input = run_checked(runner, binary, &["-S", "INPUT"])?;
    let stable_positions = exact_jump_positions(&final_input.stdout, chain_name);
    let staging_positions = exact_jump_positions(&final_input.stdout, KIDOBO_STAGING_CHAIN_NAME);
    if stable_positions != [1] || !staging_positions.is_empty() {
        return Err(FirewallError::UnexpectedInputWiring {
            family,
            stable_positions,
            staging_positions,
        });
    }
    Ok(())
}

fn replace_chain_jump_fail_closed(
    runner: &dyn FirewallCommandRunner,
    family: FirewallFamily,
    chain_name: &str,
    target_chain: &str,
) -> Result<(), FirewallError> {
    let binary = family.binary();
    let current = run_checked(runner, binary, &["-S", chain_name])?;
    let old_rule_count = chain_rule_count(&current.stdout, chain_name);
    run_checked(runner, binary, &["-A", chain_name, "-j", target_chain])?;
    for _ in 0..old_rule_count {
        run_checked(runner, binary, &["-D", chain_name, "1"])?;
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

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};

    use super::{
        ChainAction, FirewallCommandRunner, FirewallError, FirewallFamily, KIDOBO_CHAIN_NAME,
        KIDOBO_STAGING_CHAIN_NAME, chain_exists, cleanup_firewall_wiring, ensure_firewall_wiring,
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

    #[derive(Default)]
    struct FirewallTable {
        chains: BTreeMap<String, Vec<String>>,
        input_rules: Vec<String>,
    }

    #[derive(Default)]
    enum UnrelatedInjection {
        #[default]
        Disabled,
        Armed,
        Done,
    }

    // Keep shared INPUT order and owned-chain targets as state so injected failures can detect a
    // fail-open window; an invocation-only fake cannot prove that enforcement remains reachable.
    #[derive(Default)]
    struct StatefulControl {
        tables: BTreeMap<String, FirewallTable>,
        invocations: Vec<(String, Vec<String>)>,
        unrelated_injection: UnrelatedInjection,
        fail_stage_activation: bool,
        fail_post_stage_command: Option<usize>,
        stage_active: bool,
        post_stage_commands: usize,
    }

    #[derive(Default)]
    struct StatefulRunner {
        control: RefCell<StatefulControl>,
    }

    impl StatefulRunner {
        fn with_existing_wiring(stable_jump_count: usize) -> Self {
            let runner = Self::default();
            let mut control = runner.control.borrow_mut();
            let table = control.tables.entry("iptables".to_string()).or_default();
            table.chains.insert(
                KIDOBO_CHAIN_NAME.to_string(),
                vec!["-m set --match-set old-set src -j DROP".to_string()],
            );
            table.input_rules.extend(std::iter::repeat_n(
                format!("-j {KIDOBO_CHAIN_NAME}"),
                stable_jump_count,
            ));
            drop(control);
            runner
        }

        fn invocations(&self) -> Vec<(String, Vec<String>)> {
            self.control.borrow().invocations.clone()
        }

        fn input_rules(&self, binary: &str) -> Vec<String> {
            self.control
                .borrow()
                .tables
                .get(binary)
                .map_or_else(Vec::new, |table| table.input_rules.clone())
        }

        fn chain_rules(&self, binary: &str, chain_name: &str) -> Vec<String> {
            self.control
                .borrow()
                .tables
                .get(binary)
                .and_then(|table| table.chains.get(chain_name))
                .cloned()
                .unwrap_or_default()
        }

        fn set_inject_unrelated_on_stable_delete(&self) {
            self.control.borrow_mut().unrelated_injection = UnrelatedInjection::Armed;
        }

        fn set_fail_stage_activation(&self) {
            self.control.borrow_mut().fail_stage_activation = true;
        }

        fn set_fail_post_stage_command(&self, command_number: usize) {
            self.control.borrow_mut().fail_post_stage_command = Some(command_number);
        }

        fn enforcement_active(&self, binary: &str) -> bool {
            let control = self.control.borrow();
            let Some(table) = control.tables.get(binary) else {
                return false;
            };
            let stable_ready = table
                .chains
                .get(KIDOBO_CHAIN_NAME)
                .is_some_and(|rules| !rules.is_empty());
            let stable_active = table
                .input_rules
                .iter()
                .any(|rule| rule == &format!("-j {KIDOBO_CHAIN_NAME}"));
            let staging_active = table
                .input_rules
                .iter()
                .any(|rule| rule == &format!("-j {KIDOBO_STAGING_CHAIN_NAME}"))
                && table
                    .chains
                    .get(KIDOBO_STAGING_CHAIN_NAME)
                    .is_some_and(|rules| rules == &[format!("-j {KIDOBO_CHAIN_NAME}")]);
            stable_ready && (stable_active || staging_active)
        }
    }

    impl FirewallCommandRunner for StatefulRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            let mut control = self.control.borrow_mut();
            control.invocations.push((
                command.to_string(),
                args.iter().map(|value| (*value).to_string()).collect(),
            ));
            let operation = args.get(2..).expect("xtables wait prefix");
            let activates_stage =
                operation == ["-I", "INPUT", "1", "-j", KIDOBO_STAGING_CHAIN_NAME];
            if activates_stage && control.fail_stage_activation {
                return Ok(command_failure("injected stage activation failure"));
            }
            if control.stage_active {
                control.post_stage_commands += 1;
                if control.fail_post_stage_command == Some(control.post_stage_commands) {
                    return Ok(command_failure("injected post-stage failure"));
                }
            }

            let should_inject = matches!(control.unrelated_injection, UnrelatedInjection::Armed)
                && operation == ["-D", "INPUT", "-j", KIDOBO_CHAIN_NAME];
            if should_inject {
                control
                    .tables
                    .entry(command.to_string())
                    .or_default()
                    .input_rules
                    .insert(0, "-p tcp --dport 22 -j ACCEPT".to_string());
                control.unrelated_injection = UnrelatedInjection::Done;
            }

            let result = apply_stateful_operation(&mut control, command, operation);
            if activates_stage && result.status.success() {
                control.stage_active = true;
            }
            Ok(result)
        }
    }

    fn apply_stateful_operation(
        control: &mut StatefulControl,
        command: &str,
        operation: &[&str],
    ) -> CommandResult {
        let table = control.tables.entry(command.to_string()).or_default();
        match operation {
            ["-S", "INPUT"] => CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: render_rules("INPUT", &table.input_rules),
                stderr: String::new(),
            },
            ["-S", chain_name] => {
                table
                    .chains
                    .get(*chain_name)
                    .map_or_else(missing_chain, |rules| CommandResult {
                        status: ProcessStatus::Exited(0),
                        stdout: render_rules(chain_name, rules),
                        stderr: String::new(),
                    })
            }
            ["-N", chain_name] => {
                table.chains.entry((*chain_name).to_string()).or_default();
                ok(0)
            }
            ["-A", chain_name, rule @ ..] => {
                table
                    .chains
                    .entry((*chain_name).to_string())
                    .or_default()
                    .push(rule.join(" "));
                ok(0)
            }
            ["-I", "INPUT", "1", "-j", chain_name] => {
                table.input_rules.insert(0, format!("-j {chain_name}"));
                ok(0)
            }
            ["-D", "INPUT", "-j", chain_name] => {
                if !table.chains.contains_key(*chain_name) {
                    return missing_target_chain(chain_name);
                }
                let expected = format!("-j {chain_name}");
                table
                    .input_rules
                    .iter()
                    .position(|rule| rule == &expected)
                    .map_or_else(missing_rule, |position| {
                        table.input_rules.remove(position);
                        ok(0)
                    })
            }
            ["-D", chain_name, "1"] => table
                .chains
                .get_mut(*chain_name)
                .filter(|rules| !rules.is_empty())
                .map_or_else(missing_rule, |rules| {
                    rules.remove(0);
                    ok(0)
                }),
            ["-F", chain_name] => {
                table
                    .chains
                    .get_mut(*chain_name)
                    .map_or_else(missing_chain, |rules| {
                        rules.clear();
                        ok(0)
                    })
            }
            ["-X", chain_name] => {
                if table.chains.get(*chain_name).is_some_and(Vec::is_empty) {
                    table.chains.remove(*chain_name);
                    ok(0)
                } else {
                    missing_chain()
                }
            }
            _ => command_failure("unexpected test command"),
        }
    }

    fn render_rules(chain_name: &str, rules: &[String]) -> String {
        use std::fmt::Write;

        let mut output = String::new();
        for rule in rules {
            let _write_result = writeln!(&mut output, "-A {chain_name} {rule}");
        }
        output
    }

    fn command_failure(stderr: &str) -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(2),
            stdout: String::new(),
            stderr: stderr.to_string(),
        }
    }

    fn missing_chain() -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "No chain/target/match by that name".to_string(),
        }
    }

    fn missing_rule() -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(1),
            stdout: String::new(),
            stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
        }
    }

    fn missing_target_chain(chain_name: &str) -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(2),
            stdout: String::new(),
            stderr: format!("iptables v1.8.10 (nf_tables): Chain '{chain_name}' does not exist"),
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
        let runner = MockRunner::new(vec![
            Ok(CommandResult {
                status: ProcessStatus::Exited(0),
                stdout: format!("-A INPUT -j {KIDOBO_CHAIN_NAME}\n"),
                stderr: String::new(),
            }),
            Ok(CommandResult {
                status: ProcessStatus::Exited(1),
                stdout: String::new(),
                stderr: "permission denied".to_string(),
            }),
        ]);

        let err =
            remove_all_input_jumps_for_chain(&runner, FirewallFamily::Ipv4, KIDOBO_CHAIN_NAME)
                .expect_err("nonmissing delete failure");

        assert!(matches!(err, FirewallError::CommandFailed { .. }));
        assert_eq!(runner.invocations().len(), 2);
        assert_eq!(
            runner.invocations()[1].1,
            vec!["-w", "5", "-D", "INPUT", "-j", KIDOBO_CHAIN_NAME]
        );
    }

    #[test]
    fn ensures_chain_rule_before_input_jump_without_flushing() {
        let runner = StatefulRunner::default();

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
        let first_input_insert = invocations
            .iter()
            .position(|(_, args)| args.get(2).is_some_and(|arg| arg == "-I"))
            .expect("INPUT insertion");
        assert!(first_input_insert > 3);
        assert_eq!(
            runner.input_rules("iptables"),
            [format!("-j {KIDOBO_CHAIN_NAME}")]
        );
        assert_eq!(
            runner.chain_rules("iptables", KIDOBO_CHAIN_NAME),
            ["-m set --match-set kidobo-set src -j DROP"]
        );
        assert!(
            runner
                .chain_rules("iptables", KIDOBO_STAGING_CHAIN_NAME)
                .is_empty()
        );
        assert!(
            invocations
                .iter()
                .all(|(_, args)| args.as_slice() != ["-w", "5", "-F", KIDOBO_CHAIN_NAME])
        );
    }

    #[test]
    fn removes_old_input_jumps_only_after_reinserting() {
        let runner = StatefulRunner::with_existing_wiring(2);
        runner.set_inject_unrelated_on_stable_delete();

        ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect("wiring");

        assert_eq!(
            runner.input_rules("iptables"),
            [
                format!("-j {KIDOBO_CHAIN_NAME}"),
                "-p tcp --dport 22 -j ACCEPT".to_string()
            ]
        );
        assert!(runner.enforcement_active("iptables"));
    }

    #[test]
    fn input_jump_normalization_never_uses_numeric_deletion() {
        let runner = StatefulRunner::with_existing_wiring(2);

        ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect("wiring");

        let invocations = runner.invocations();
        assert!(invocations.iter().all(|(_, args)| {
            !(args.get(2).is_some_and(|arg| arg == "-D")
                && args.get(3).is_some_and(|arg| arg == "INPUT")
                && args.get(4).is_some_and(|arg| arg.parse::<usize>().is_ok()))
        }));
        assert!(invocations.iter().any(|(_, args)| {
            args.as_slice() == ["-w", "5", "-D", "INPUT", "-j", KIDOBO_CHAIN_NAME]
        }));
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
        let runner = StatefulRunner::default();

        ensure_firewall_wiring_for_families(
            &runner,
            "kidobo-v4",
            "kidobo-v6",
            true,
            ChainAction::Drop,
        )
        .expect("wiring");

        let invocations = runner.invocations();
        assert!(invocations.iter().any(|(binary, _)| binary == "iptables"));
        assert!(invocations.iter().any(|(binary, _)| binary == "ip6tables"));
        assert!(runner.enforcement_active("iptables"));
        assert!(runner.enforcement_active("ip6tables"));
    }

    #[test]
    fn supports_reject_target_rule() {
        let runner = StatefulRunner::default();

        ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Reject,
        )
        .expect("wiring");

        assert_eq!(
            runner.chain_rules("iptables", KIDOBO_CHAIN_NAME),
            ["-m set --match-set kidobo-set src -j REJECT"]
        );
    }

    #[test]
    fn input_jump_insert_failure_does_not_delete_existing_jump() {
        let runner = StatefulRunner::with_existing_wiring(1);
        runner.set_fail_stage_activation();

        let err = ensure_firewall_wiring(
            &runner,
            FirewallFamily::Ipv4,
            "kidobo-set",
            ChainAction::Drop,
        )
        .expect_err("insert must fail");

        assert!(matches!(err, FirewallError::CommandFailed { .. }));
        assert_eq!(
            runner.input_rules("iptables"),
            [format!("-j {KIDOBO_CHAIN_NAME}")]
        );
        assert!(runner.enforcement_active("iptables"));
    }

    #[test]
    fn every_post_activation_failure_keeps_an_enforcement_path() {
        // Exercise every command after the staging jump becomes active, including the probes that
        // confirm deletion and the final state inspection.
        for command_number in 1..=8 {
            let runner = StatefulRunner::with_existing_wiring(1);
            runner.set_fail_post_stage_command(command_number);

            let error = ensure_firewall_wiring(
                &runner,
                FirewallFamily::Ipv4,
                "kidobo-set",
                ChainAction::Drop,
            )
            .expect_err("injected failure must be reported");

            assert!(matches!(error, FirewallError::CommandFailed { .. }));
            assert!(
                runner.enforcement_active("iptables"),
                "lost enforcement after post-stage command {command_number}: {:?}",
                runner.input_rules("iptables")
            );
        }
    }

    #[test]
    fn cleanup_firewall_wiring_removes_jumps_and_deletes_chain() {
        let runner = StatefulRunner::with_existing_wiring(1);
        {
            let mut control = runner.control.borrow_mut();
            let mut table = control.tables.remove("iptables").expect("table");
            table.chains.insert(
                KIDOBO_STAGING_CHAIN_NAME.to_string(),
                vec![format!("-j {KIDOBO_CHAIN_NAME}")],
            );
            table
                .input_rules
                .insert(0, format!("-j {KIDOBO_STAGING_CHAIN_NAME}"));
            control.tables.insert("ip6tables".to_string(), table);
        }

        cleanup_firewall_wiring(&runner, FirewallFamily::Ipv6).expect("cleanup");

        assert!(runner.input_rules("ip6tables").is_empty());
        assert!(
            runner
                .chain_rules("ip6tables", KIDOBO_STAGING_CHAIN_NAME)
                .is_empty()
        );
        assert!(
            runner
                .chain_rules("ip6tables", KIDOBO_CHAIN_NAME)
                .is_empty()
        );
    }

    #[test]
    fn cleanup_firewall_wiring_treats_missing_chain_as_success() {
        let runner = StatefulRunner::default();

        cleanup_firewall_wiring(&runner, FirewallFamily::Ipv6).expect("cleanup");
        assert!(
            runner.invocations().iter().all(|(_, args)| {
                args.get(2..4) != Some(&["-D".to_string(), "INPUT".to_string()])
            })
        );
    }
}
