use std::net::IpAddr;

use crate::cli::CliIo;
use crate::cli::args::ReportFormat;
use crate::cli::presentation::{Presentation, Status, redact_urls};
use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::inspection::{SystemLiveProbe, SystemSavedBanCountReader};
use kidobo_adapters::lookup_sources::build_offline_lookup_registry;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::target_file::LookupTargetFileReader;
use kidobo_adapters::temporary_bans::{FileTemporaryBanRepository, SystemClock};
use kidobo_app::inspection::{
    self, CheckDependencies, CheckRequest, CheckVerdict, FamilyInspection, OfflineMatch,
    StatusDependencies, Verification,
};
use kidobo_app::lookup::{self, LookupDependencies, LookupInput, LookupRequest};

pub fn status(format: ReportFormat, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let mut report = inspection::status(
        &path_resolution_input_from_process(None),
        &StatusDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            configs: &FileConfigRepository,
            saved_counts: &SystemSavedBanCountReader,
            clock: &SystemClock,
            live_probe: &SystemLiveProbe::default(),
        },
    )?;
    report.configuration_detail = redact_urls(&report.configuration_detail);
    redact_family(&mut report.ipv4);
    redact_family(&mut report.ipv6);
    report.timer.detail = redact_urls(&report.timer.detail);
    for notice in report
        .notices
        .iter_mut()
        .chain(&mut report.saved_bans.notices)
    {
        *notice = redact_urls(notice);
    }
    if format == ReportFormat::Json {
        serde_json::to_writer_pretty(&mut *io.stdout, &report)?;
        writeln!(io.stdout)?;
        return Ok(());
    }
    let view = io.presentation();
    view.heading(io.stdout, &format!("Kidobo {}", env!("CARGO_PKG_VERSION")))?;
    if report.initialized == Some(false) {
        view.paragraph(io.stdout, "Welcome. Kidobo manages incoming IP/CIDR blocks through one-shot synchronization. Create and review your configuration to begin.")?;
        view.next(io.stdout, "sudo kidobo setup")?;
    }
    view.status(
        io.stdout,
        status_label(report.configuration),
        "Configuration",
        &report.configuration_detail,
    )?;
    render_family(view, io.stdout, &report.ipv4)?;
    render_family(view, io.stdout, &report.ipv6)?;
    if report.ipv4.enforcement == Verification::Unknown
        || report.ipv6.enforcement == Verification::Unknown
    {
        for family in [&report.ipv4, &report.ipv6] {
            if family.enforcement == Verification::Unknown {
                for evidence in family.evidence.iter().take(2) {
                    view.paragraph(io.stdout, evidence)?;
                }
            }
        }
        view.next(io.stdout, "sudo kidobo status if permissions prevent verification; kidobo doctor for prerequisites")?;
    }
    let counts = &report.saved_bans;
    view.key_values(
        io.stdout,
        &[
            ("Configured feeds", &count(report.configured_feeds)),
            ("Local IP/CIDR bans", &count(counts.permanent_ip_cidrs)),
            ("Permanent ASN bans", &count(counts.permanent_asns)),
            (
                "Temporary IP/CIDRs",
                &format!(
                    "{} saved, {} active",
                    count(counts.temporary_ip_cidrs),
                    count(counts.active_temporary_ip_cidrs)
                ),
            ),
            (
                "Temporary ASNs",
                &format!(
                    "{} saved, {} active",
                    count(counts.temporary_asns),
                    count(counts.active_temporary_asns)
                ),
            ),
            ("Sync timer", &report.timer.detail),
            ("Last successful sync", "Not recorded"),
        ],
    )?;
    for notice in report.notices.iter().chain(&counts.notices) {
        view.paragraph(io.stdout, notice)?;
    }
    view.paragraph(io.stdout, "Saved bans may await sync. Unknown means unable to verify; it never establishes an unblocked host.")?;
    view.next(io.stdout, "kidobo help; sudo kidobo check IP; kidobo bans")?;
    Ok(())
}

fn count(value: Option<usize>) -> String {
    value.map_or_else(|| "Unknown".to_string(), |value| value.to_string())
}

fn status_label(value: Verification) -> Status {
    match value {
        Verification::Verified => Status::Pass,
        Verification::Absent => Status::Warn,
        Verification::Unknown => Status::Unknown,
    }
}

fn render_family(
    view: Presentation,
    output: &mut dyn std::io::Write,
    family: &FamilyInspection,
) -> Result<(), KidoboError> {
    let enabled =
        family.configured_enabled.map_or(
            "Unknown",
            |enabled| if enabled { "enabled" } else { "disabled" },
        );
    view.status(
        output,
        status_label(family.enforcement),
        &format!("{} managed enforcement", family.family.to_uppercase()),
        &format!(
            "{} Live kernel entries: {}. Configuration: {enabled}.",
            family.detail,
            count(family.entries)
        ),
    )?;
    Ok(())
}

fn redact_family(family: &mut FamilyInspection) {
    family.detail = redact_urls(&family.detail);
    for evidence in &mut family.evidence {
        *evidence = redact_urls(evidence);
    }
}

pub fn check(ip: IpAddr, format: ReportFormat, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let mut report = inspection::check(
        &CheckRequest {
            paths: path_resolution_input_from_process(None),
            target: ip,
        },
        &CheckDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            configs: &FileConfigRepository,
            live_probe: &SystemLiveProbe::default(),
        },
    )?;
    match offline_evidence(ip) {
        Ok((matches, notices)) => {
            report.offline_matches = matches;
            report.offline_notices = notices;
        }
        Err(error) => {
            if matches!(
                error,
                KidoboError::Interrupted
                    | KidoboError::Application {
                        source: kidobo_app::AppError::Interrupted
                    }
            ) {
                return Err(error);
            }
            report
                .offline_notices
                .push(format!("Offline evidence unavailable: {error}"));
        }
    }
    redact_family(&mut report.family);
    for entry in &mut report.offline_matches {
        entry.source = redact_urls(&entry.source);
        entry.entry = redact_urls(&entry.entry);
    }
    for notice in report.notices.iter_mut().chain(&mut report.offline_notices) {
        *notice = redact_urls(notice);
    }
    if format == ReportFormat::Json {
        serde_json::to_writer_pretty(&mut *io.stdout, &report)?;
        writeln!(io.stdout)?;
    } else {
        let view = io.presentation();
        let (label, result) = match report.verdict {
            CheckVerdict::Blocked => ("BLOCKED BY KIDOBO", Status::Pass),
            CheckVerdict::NotBlocked => ("NOT BLOCKED BY KIDOBO", Status::Pass),
            CheckVerdict::Unknown => ("UNKNOWN", Status::Unknown),
        };
        view.heading(io.stdout, "Live managed enforcement")?;
        view.status(io.stdout, result, label, &report.target)?;
        render_family(view, io.stdout, &report.family)?;
        for notice in report.family.evidence.iter().chain(&report.notices) {
            view.paragraph(io.stdout, notice)?;
        }
        view.paragraph(
            io.stdout,
            "This assessment covers Kidobo's managed incoming blocking path only.",
        )?;
        view.heading(io.stdout, "Offline source evidence")?;
        view.paragraph(io.stdout, "Saved/cached overlaps may be stale and do not establish enforcement. Safelists can exempt addresses; remote or ASN sources can keep blocking an address after local unban.")?;
        let rows = report
            .offline_matches
            .iter()
            .map(|entry| vec![entry.source.clone(), entry.entry.clone()])
            .collect::<Vec<_>>();
        if rows.is_empty() {
            view.paragraph(io.stdout, "No readable offline source matches.")?;
        } else {
            view.table(io.stdout, &["Source", "Matched entry"], &rows)?;
        }
        for notice in &report.offline_notices {
            view.paragraph(io.stdout, notice)?;
        }
        if report.verdict == CheckVerdict::Unknown {
            view.next(io.stdout, &format!("sudo kidobo check {ip}; kidobo doctor"))?;
        }
    }
    if report.verdict == CheckVerdict::Unknown {
        Err(KidoboError::CheckUnknown)
    } else {
        Ok(())
    }
}

fn offline_evidence(ip: IpAddr) -> Result<(Vec<OfflineMatch>, Vec<String>), KidoboError> {
    let mut matches = Vec::new();
    let sources = build_offline_lookup_registry()?;
    let outcome = lookup::execute(
        &LookupRequest {
            paths: path_resolution_input_from_process(None),
            input: LookupInput::Single(ip.to_string()),
        },
        &LookupDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            configs: &FileConfigRepository,
            target_files: &LookupTargetFileReader,
            sources: &sources,
            clock: &SystemClock,
            temporary_bans: &FileTemporaryBanRepository,
        },
        |_, entries| {
            matches.extend(entries.iter().map(|entry| OfflineMatch {
                source: entry.source_label.to_string(),
                entry: entry.source_line.clone(),
            }));
            Ok::<(), KidoboError>(())
        },
    )?;
    Ok((
        matches,
        outcome
            .notices
            .into_iter()
            .map(|notice| notice.message)
            .collect(),
    ))
}
