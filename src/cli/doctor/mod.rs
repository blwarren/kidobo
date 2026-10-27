use log::info;

use crate::cli::CliIo;
use crate::cli::args::ReportFormat;
use crate::cli::presentation::{Presentation, Status};
use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::doctor::SystemDoctorProbe;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::temporary_bans::FileTemporaryBanRepository;
use kidobo_app::doctor::{
    self, DoctorCheckStatus, DoctorDependencies, DoctorOverall, DoctorReport,
};

pub fn run_doctor_command(
    format: Option<ReportFormat>,
    io: &mut CliIo<'_>,
) -> Result<(), KidoboError> {
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let probes = SystemDoctorProbe::default();
    let temporary_bans = FileTemporaryBanRepository;
    let report = doctor::execute(
        &path_resolution_input_from_process(None),
        &DoctorDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &paths,
            configs: &configs,
            temporary_bans: &temporary_bans,
            probes: &probes,
        },
    )?;
    let format = format.unwrap_or(if io.stdout_is_terminal && !io.under_systemd {
        ReportFormat::Human
    } else {
        ReportFormat::Json
    });
    match format {
        ReportFormat::Json => writeln!(io.stdout, "{}", render_report(&report)?)?,
        ReportFormat::Human => render_human(&report, io)?,
    }

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

fn render_human(report: &DoctorReport, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let view = io.presentation();
    view.heading(io.stdout, "Kidobo doctor")?;
    for (heading, prefix) in [
        ("Configuration", "config_"),
        ("Required tools", "binary_"),
        ("Local files and cache", "file_"),
        ("Cache access", "cache_"),
        ("Firewall permissions", "sudo_"),
    ] {
        let checks = report
            .checks
            .iter()
            .filter(|check| check.name.starts_with(prefix))
            .collect::<Vec<_>>();
        if checks.is_empty() {
            continue;
        }
        view.heading(io.stdout, heading)?;
        for check in checks {
            render_check(&view, check, io.stdout)?;
        }
    }
    for check in &report.checks {
        if !["config_", "binary_", "file_", "cache_", "sudo_"]
            .iter()
            .any(|prefix| check.name.starts_with(prefix))
        {
            render_check(&view, check, io.stdout)?;
        }
    }
    let failed = report
        .checks
        .iter()
        .filter(|check| check.status == DoctorCheckStatus::Fail)
        .count();
    let skipped = report
        .checks
        .iter()
        .filter(|check| check.status == DoctorCheckStatus::Skip)
        .count();
    view.heading(io.stdout, "Summary")?;
    view.paragraph(
        io.stdout,
        &format!(
            "{} checks: {} passed, {failed} failed, {skipped} skipped.",
            report.checks.len(),
            report.checks.len() - failed - skipped
        ),
    )?;
    view.next(
        io.stdout,
        if failed == 0 {
            "sudo kidobo sync"
        } else {
            "correct the reported issues, then rerun kidobo doctor"
        },
    )?;
    Ok(())
}

fn render_check(
    view: &Presentation,
    check: &kidobo_app::doctor::DoctorCheck,
    out: &mut dyn std::io::Write,
) -> Result<(), KidoboError> {
    let status = match check.status {
        DoctorCheckStatus::Ok => Status::Pass,
        DoctorCheckStatus::Fail => Status::Fail,
        DoctorCheckStatus::Skip => Status::Skip,
    };
    view.status(out, status, &check.name.replace('_', " "), &check.detail)?;
    if check.status == DoctorCheckStatus::Fail {
        let remedy = if check.name.starts_with("config_") {
            "Correct the reported configuration path or error; sudo kidobo init creates missing configuration."
        } else if check.name.starts_with("binary_") {
            "Install the named tool using your distribution's package manager, then rerun doctor."
        } else if check.name.starts_with("sudo_") {
            "Retry sudo kidobo doctor; check privilege configuration if the probe still fails."
        } else {
            "Inspect the reported path and permissions; sudo kidobo init creates missing files without replacing existing files."
        };
        view.paragraph(out, remedy)?;
    }
    Ok(())
}

fn render_report(report: &DoctorReport) -> Result<String, KidoboError> {
    serde_json::to_string_pretty(report).map_err(|error| KidoboError::DoctorReportSerialize {
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use kidobo_app::doctor::{DoctorCheck, DoctorCheckStatus, DoctorOverall, DoctorReport};

    use super::render_report;

    #[test]
    fn report_renderer_preserves_machine_readable_shape() {
        let rendered = render_report(&DoctorReport {
            overall: DoctorOverall::Fail,
            checks: vec![DoctorCheck {
                name: "binary_ipset".to_string(),
                status: DoctorCheckStatus::Skip,
                detail: "unavailable".to_string(),
            }],
        })
        .expect("render");
        assert_eq!(
            rendered,
            "{\n  \"overall\": \"FAIL\",\n  \"checks\": [\n    {\n      \"name\": \"binary_ipset\",\n      \"status\": \"SKIP\",\n      \"detail\": \"unavailable\"\n    }\n  ]\n}"
        );
    }
}
