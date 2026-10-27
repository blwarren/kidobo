use std::io::Write;
use std::time::{Duration, Instant};

use crate::cli::CliIo;
use crate::cli::presentation::{Presentation, Status};
use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::lock::ReadOnlyFileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::preview_sources::build_preview_source_registry;
use kidobo_adapters::temporary_bans::{FileTemporaryBanRepository, SystemClock};
use kidobo_app::preview::{self, PreviewDependencies, PreviewRequest};
use kidobo_app::source::{NoticeLevel, SourceProvenance};

pub fn run(allow_network: bool, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let started = Instant::now();
    let view = io.presentation();
    let sources = build_preview_source_registry(env!("CARGO_PKG_VERSION"))?;
    if io.stdout_is_terminal && io.stderr_is_terminal && !io.under_systemd {
        view.paragraph(
            io.stderr,
            if allow_network {
                "... Read and plan sources; network reads are explicitly permitted"
            } else {
                "... Read and plan saved sources and validated caches offline"
            },
        )?;
    }
    let result = preview::execute(
        &PreviewRequest {
            paths: path_resolution_input_from_process(None),
            allow_network,
        },
        &PreviewDependencies {
            cancellation: &super::interrupt::SigintCancellation,
            paths: &SystemPathResolver,
            configs: &FileConfigRepository,
            locks: &ReadOnlyFileLockManager,
            clock: &SystemClock,
            temporary_bans: &FileTemporaryBanRepository,
            sources: &sources,
        },
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(source) => {
            if matches!(&source, kidobo_app::AppError::Lock { .. }) {
                let _result = view.next(io.stderr, "ensure setup has created the existing lock, retry with sudo if needed, and wait for any active mutation to finish; preview never creates lock state");
            }
            return Err(source.into());
        }
    };
    render(&outcome, view, io.stdout, started.elapsed())
}

fn render(
    outcome: &preview::PreviewOutcome,
    view: Presentation,
    output: &mut dyn Write,
    elapsed: Duration,
) -> Result<(), KidoboError> {
    view.heading(
        output,
        if outcome.allow_network {
            "Sync preview: network reads permitted"
        } else {
            "Sync preview: offline"
        },
    )?;
    view.table(
        output,
        &["Family", "Proposed CIDRs", "Kernel entries"],
        &[
            vec![
                "IPv4".into(),
                outcome.entries.ipv4_networks.to_string(),
                outcome.entries.ipv4.len().to_string(),
            ],
            vec![
                if outcome.enable_ipv6 {
                    "IPv6"
                } else {
                    "IPv6 (disabled)"
                }
                .into(),
                outcome.entries.ipv6_networks.to_string(),
                outcome.entries.ipv6.len().to_string(),
            ],
        ],
    )?;
    view.status(
        output,
        Status::Pass,
        "Capacity preflight",
        "Every enabled family's proposed kernel entries fit its configured capacity.",
    )?;
    view.heading(output, "Source evidence")?;
    let rows = outcome
        .sources
        .iter()
        .flat_map(|source| {
            source.observations.iter().map(|observation| {
                vec![
                    observation.label.clone(),
                    provenance_label(observation.provenance).to_string(),
                ]
            })
        })
        .collect::<Vec<_>>();
    view.table(output, &["Source", "Data origin"], &rows)?;
    for notice in &outcome.notices {
        let status = match notice.level {
            NoticeLevel::Info => Status::Skip,
            NoticeLevel::Warning => Status::Warn,
        };
        view.status(output, status, "Preview notice", &notice.message)?;
    }
    view.status(output, Status::Unknown, "Exact live delta unavailable", "Live set members are not enumerated by this preview. Proposed counts do not establish added/removed CIDRs or current packet enforcement; use status and check for live observations.")?;
    view.paragraph(output, "No source/config/temporary-ban files, cache generations/manifests, firewall sets/rules, or systemd state were written. Preview does not test cache persistence or guarantee that a later sync will succeed. Inputs may change before the real sync.")?;
    view.paragraph(
        output,
        &format!("Preview completed in {:.2}s.", elapsed.as_secs_f64()),
    )?;
    if !outcome.allow_network {
        view.next(
            output,
            "sudo kidobo sync --dry-run --allow-network to permit fresh reads without saving",
        )?;
    }
    view.next(output, "sudo kidobo sync to perform the actual update")?;
    Ok(())
}

fn provenance_label(source: SourceProvenance) -> &'static str {
    match source {
        SourceProvenance::Local => "Saved source",
        SourceProvenance::Network => "Fresh network read",
        SourceProvenance::Cache => "Validated cache",
        SourceProvenance::FallbackCache => "Fallback cache",
        SourceProvenance::Unavailable => "Unavailable",
        SourceProvenance::Disabled => "Disabled",
    }
}
