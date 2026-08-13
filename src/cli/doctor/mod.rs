use log::info;

use crate::cli::CliIo;
use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::doctor::SystemDoctorProbe;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_app::doctor::{
    self, DoctorCheckStatus, DoctorDependencies, DoctorOverall, DoctorReport,
};

pub fn run_doctor_command(io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let probes = SystemDoctorProbe::default();
    let report = doctor::execute(
        &path_resolution_input_from_process(None),
        &DoctorDependencies {
            paths: &paths,
            configs: &configs,
            probes: &probes,
        },
    );
    let json = render_report(&report)?;
    writeln!(io.stdout, "{json}").map_err(|error| KidoboError::CliIo {
        reason: error.to_string(),
    })?;

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
