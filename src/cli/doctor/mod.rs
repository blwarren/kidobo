use std::collections::BTreeSet;

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
    if format == ReportFormat::Json || !io.stdout_is_terminal || io.under_systemd {
        info!(
            "doctor summary: overall={} checks_total={} checks_failed={} checks_skipped={}",
            overall,
            report.checks.len(),
            failed_count,
            skipped_count
        );
    }
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
            "{} {}: {} passed, {failed} failed, {skipped} skipped.",
            report.checks.len(),
            if report.checks.len() == 1 {
                "check"
            } else {
                "checks"
            },
            report.checks.len() - failed - skipped
        ),
    )?;
    let remedies = report
        .checks
        .iter()
        .filter(|check| check.status == DoctorCheckStatus::Fail)
        .map(|check| remedy(&check.name))
        .collect::<BTreeSet<_>>();
    for remedy in remedies {
        view.paragraph(io.stdout, remedy)?;
    }
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
    Ok(())
}

fn remedy(name: &str) -> &'static str {
    if name.starts_with("config_") {
        "Correct the reported configuration path or error; sudo kidobo init creates missing configuration."
    } else if name.starts_with("binary_") {
        "Install the missing tools using your distribution's package manager, then rerun doctor."
    } else if name.starts_with("sudo_") {
        "Retry sudo kidobo doctor; check privilege configuration if the probe still fails."
    } else {
        "Inspect the reported path and permissions; sudo kidobo init creates missing files without replacing existing files."
    }
}

fn render_report(report: &DoctorReport) -> Result<String, KidoboError> {
    serde_json::to_string_pretty(report).map_err(|error| KidoboError::DoctorReportSerialize {
        reason: error.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use kidobo_app::doctor::{DoctorCheck, DoctorCheckStatus, DoctorOverall, DoctorReport};

    use super::{render_human, render_report};
    use crate::cli::{CliIo, PromptInput};
    use crate::error::KidoboError;

    struct NoInput;

    impl PromptInput for NoInput {
        fn read_response(&mut self) -> Result<String, KidoboError> {
            panic!("doctor must not prompt")
        }
    }

    fn human_output(checks: Vec<DoctorCheck>) -> String {
        let mut stdout = Vec::new();
        render_human(
            &DoctorReport {
                overall: DoctorOverall::Fail,
                checks,
            },
            &mut CliIo {
                input: &mut NoInput,
                stdout: &mut stdout,
                stderr: &mut Vec::new(),
                stdin_is_terminal: false,
                stdout_is_terminal: false,
                stderr_is_terminal: false,
                terminal_width: 120,
                term_dumb: false,
                under_systemd: false,
                no_color: true,
            },
        )
        .expect("human doctor report");
        String::from_utf8(stdout).expect("UTF-8 doctor output")
    }

    #[test]
    fn human_report_lists_failures_and_prints_each_remedy_once() {
        let output = human_output(
            ["binary_ipset", "binary_iptables"]
                .into_iter()
                .map(|name| DoctorCheck {
                    name: name.into(),
                    status: DoctorCheckStatus::Fail,
                    detail: format!("missing {name}"),
                })
                .collect(),
        );
        assert_eq!(output.matches("[FAIL]").count(), 2);
        assert!(output.contains("missing binary_ipset"));
        assert!(output.contains("missing binary_iptables"));
        assert_eq!(output.matches("Install the missing tools").count(), 1);
        assert!(output.contains("2 checks: 0 passed, 2 failed, 0 skipped."));
    }

    #[test]
    fn successful_human_reports_use_count_appropriate_nouns_without_navigation() {
        for (count, noun) in [(0, "checks"), (1, "check"), (2, "checks")] {
            let output = human_output(
                (0..count)
                    .map(|index| DoctorCheck {
                        name: format!("binary_tool_{index}"),
                        status: DoctorCheckStatus::Ok,
                        detail: "available".into(),
                    })
                    .collect(),
            );
            assert!(output.contains(&format!(
                "{count} {noun}: {count} passed, 0 failed, 0 skipped."
            )));
            assert!(!output.contains("Next:"));
            assert!(!output.contains("Install the missing tools"));
        }
    }

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
