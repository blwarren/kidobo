use crate::adapters::command_common::display_command;
use crate::adapters::command_runner::{
    CommandExecutor, CommandResult, CommandRunnerError, SudoCommandRunner,
};

use super::checks::{BinaryAvailability, Ipv6Mode, ipv6_skip_reason};
use super::report::{DoctorCheck, fail_check, ok_check, skip_check};

const SUDO_PROBE_CHECKS: [(&str, &str, &[&str]); 2] = [
    ("sudo_probe_ipset", "ipset", &["list"]),
    ("sudo_probe_iptables", "iptables", &["-S"]),
];

pub(super) trait SudoProbeRunner {
    fn run_probe(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError>;
}

impl<E: CommandExecutor> SudoProbeRunner for SudoCommandRunner<E> {
    fn run_probe(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
        self.run(command, args)
    }
}

pub(super) fn push_sudo_probe_checks(
    checks: &mut Vec<DoctorCheck>,
    ipv6_mode: Ipv6Mode,
    binary_available: &BinaryAvailability,
    runner: &dyn SudoProbeRunner,
) {
    let sudo_available = *binary_available.get("sudo").unwrap_or(&false);

    for &(check_name, binary, args) in &SUDO_PROBE_CHECKS {
        checks.push(sudo_probe_check(
            check_name,
            binary,
            args,
            sudo_available,
            binary_available,
            runner,
        ));
    }

    let ipv6_probe = if let Some(reason) = ipv6_skip_reason(ipv6_mode) {
        skip_check("sudo_probe_ip6tables", reason)
    } else {
        sudo_probe_check(
            "sudo_probe_ip6tables",
            "ip6tables",
            &["-S"],
            sudo_available,
            binary_available,
            runner,
        )
    };
    checks.push(ipv6_probe);
}

fn sudo_probe_check(
    check_name: &'static str,
    binary: &str,
    args: &[&str],
    sudo_available: bool,
    binary_available: &BinaryAvailability,
    runner: &dyn SudoProbeRunner,
) -> DoctorCheck {
    if !sudo_available {
        return skip_check(check_name, "sudo binary is unavailable");
    }

    if !binary_available.get(binary).copied().unwrap_or(false) {
        return skip_check(check_name, format!("{binary} binary is unavailable"));
    }

    let command = display_command(binary, args);
    match runner.run_probe(binary, args) {
        Ok(result) if result.status.success() => {
            ok_check(check_name, format!("sudo -n {command} succeeded"))
        }
        Ok(result) => fail_check(
            check_name,
            format!(
                "sudo -n {command} failed with status {:?}: {}",
                result.status,
                stderr_detail(&result.stderr)
            ),
        ),
        Err(err) => fail_check(
            check_name,
            format!("sudo -n {command} execution failed: {err}"),
        ),
    }
}

fn stderr_detail(stderr: &str) -> String {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        "no stderr".to_string()
    } else {
        trimmed.to_string()
    }
}
