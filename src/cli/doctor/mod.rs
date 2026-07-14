mod checks;
mod probes;
mod report;

#[cfg(test)]
mod tests;

use log::info;

use crate::adapters::command_runner::SudoCommandRunner;
use crate::adapters::path::PathResolutionInput;
use crate::error::KidoboError;

use self::checks::{
    SystemBinaryLocator, collect_binary_checks, collect_doctor_context, push_path_checks,
};
use self::probes::push_sudo_probe_checks;
pub(crate) use self::report::{DoctorCheckStatus, DoctorOverall, DoctorReport};

#[allow(
    clippy::print_stdout,
    reason = "CLI command writes its report to standard output"
)]
pub fn run_doctor_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let binary_locator = SystemBinaryLocator;
    let sudo_runner = SudoCommandRunner::default();

    let report = build_doctor_report(&path_input, &binary_locator, &sudo_runner);
    let json = serde_json::to_string_pretty(&report).map_err(|err| {
        KidoboError::DoctorReportSerialize {
            reason: err.to_string(),
        }
    })?;

    println!("{json}");
    let failed_count = report
        .checks
        .iter()
        .filter(|check| check.status == DoctorCheckStatus::Fail)
        .count();
    let skipped_count = report
        .checks
        .iter()
        .filter(|check| check.status == DoctorCheckStatus::Skip)
        .count();
    let overall = match report.overall {
        DoctorOverall::Ok => "OK",
        DoctorOverall::Fail => "FAIL",
    };
    info!(
        "doctor summary: overall={} checks_total={} checks_failed={} checks_skipped={}",
        overall,
        report.checks.len(),
        failed_count,
        skipped_count
    );

    if report.overall == DoctorOverall::Ok {
        Ok(())
    } else {
        Err(KidoboError::DoctorFailed)
    }
}

fn build_doctor_report(
    path_input: &PathResolutionInput,
    binary_locator: &dyn checks::BinaryLocator,
    sudo_probe_runner: &dyn probes::SudoProbeRunner,
) -> DoctorReport {
    let mut checks = Vec::new();
    let context = collect_doctor_context(path_input, &mut checks);
    let binary_available = collect_binary_checks(&mut checks, binary_locator, context.ipv6_mode);
    push_path_checks(&mut checks, &context.paths_result);
    push_sudo_probe_checks(
        &mut checks,
        context.ipv6_mode,
        &binary_available,
        sudo_probe_runner,
    );

    DoctorReport::from_checks(checks)
}
