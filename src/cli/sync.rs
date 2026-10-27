use std::cell::RefCell;
use std::io::Write;
use std::time::{Duration, Instant};

use log::info;

use crate::cli::CliIo;
use crate::cli::presentation::{Presentation, Status};

use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::enforcement::SystemEnforcementBackend;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::sync_observer::LoggingSyncObserver;
use kidobo_adapters::sync_sources::build_sync_source_registry;
use kidobo_adapters::temporary_bans::{FileTemporaryBanRepository, SystemClock};
use kidobo_app::sync::{self, AddressFamily, SyncDependencies, SyncEvent, SyncObserver};

pub fn run_sync_command(timer: bool, io: &mut CliIo<'_>) -> Result<(), KidoboError> {
    let started = Instant::now();
    let view = io.presentation();
    let human = io.interactive();
    let progress = human && io.stderr_is_terminal;
    let request = path_resolution_input_from_process(None);
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let locks = FileLockManager;
    let sources = build_sync_source_registry(env!("CARGO_PKG_VERSION"))?;
    let enforcement = SystemEnforcementBackend::default();
    let observer = CliSyncObserver {
        logs: LoggingSyncObserver::new(timer),
        output: RefCell::new(&mut *io.stderr),
        view: Presentation::new(io.terminal_width, progress && !io.no_color && !io.term_dumb),
        progress,
        state: RefCell::new(SyncProgress::default()),
    };
    let result = sync::execute(
        &request,
        &SyncDependencies {
            cancellation: &crate::cli::interrupt::SigintCancellation,
            paths: &paths,
            configs: &configs,
            locks: &locks,
            clock: &SystemClock,
            temporary_bans: &FileTemporaryBanRepository,
            sources: &sources,
            enforcement: &enforcement,
            observer: &observer,
        },
    );
    let outcome = match result {
        Ok(outcome) => outcome,
        Err(error) => {
            if human {
                let state = observer.state.borrow();
                let _render_result = render_failure(view, io.stdout, &state);
            }
            return Err(error.into());
        }
    };
    if human {
        render_summary(view, io.stdout, &outcome, started.elapsed())?;
    }
    if crate::cli::interrupt::was_interrupted() {
        info!("sync enforcement completed after SIGINT");
        return Err(KidoboError::Interrupted);
    }
    observer.stage_completed("sync_pipeline_complete");

    log_summary(&outcome);
    Ok(())
}

fn render_failure(
    view: Presentation,
    output: &mut dyn Write,
    progress: &SyncProgress,
) -> std::io::Result<()> {
    view.status(
        output,
        Status::Fail,
        "Sync incomplete",
        &progress.failure_summary(),
    )?;
    view.status(
        output,
        Status::Unknown,
        "Live enforcement",
        "Inspect current managed state before retrying.",
    )?;
    view.next(
        output,
        "kidobo status; correct the error, then sudo kidobo sync",
    )
}

fn render_summary(
    view: Presentation,
    output: &mut dyn Write,
    outcome: &sync::SyncOutcome,
    elapsed: Duration,
) -> Result<(), KidoboError> {
    let observations = outcome
        .sources
        .iter()
        .flat_map(|source| &source.observations)
        .collect::<Vec<_>>();
    let loaded = observations
        .iter()
        .filter(|source| source.provenance.is_loaded())
        .count();
    let degraded = observations
        .iter()
        .filter(|source| source.provenance.is_degraded())
        .count();
    view.heading(output, "Synchronization complete")?;
    view.table(
        output,
        &["Family", "Networks/CIDRs", "Kernel entries"],
        &[
            vec![
                "IPv4".into(),
                outcome.ipv4_entries.to_string(),
                outcome.ipv4_kernel_entries.to_string(),
            ],
            vec![
                "IPv6".into(),
                outcome.ipv6_entries.to_string(),
                outcome.ipv6_kernel_entries.to_string(),
            ],
        ],
    )?;
    view.paragraph(
        output,
        &format!(
            "Sources: {loaded} loaded, {degraded} degraded. Elapsed: {:.2}s.",
            elapsed.as_secs_f64()
        ),
    )?;
    if degraded > 0 {
        view.status(
            output,
            Status::Warn,
            "Degraded source coverage",
            "Review the source warnings above; fallback or unavailable data was encountered.",
        )?;
    }
    view.next(output, "kidobo status")?;
    Ok(())
}

fn log_summary(outcome: &sync::SyncOutcome) {
    let source_count = |id: &str| {
        outcome
            .sources
            .iter()
            .find(|source| source.id == id)
            .map_or(0, |source| source.entries)
    };
    info!(
        "sync source counts: internal={} temporary={} remote={} asn={} safelist={}",
        source_count("local-blocklist"),
        source_count("temporary-blocklist"),
        source_count("remote-feeds"),
        source_count("asn-bans"),
        source_count("config-safelist") + source_count("github-metadata")
    );
    info!(
        "sync final ipset counts: ipv4={} ipv6={}",
        outcome.ipv4_entries, outcome.ipv6_entries
    );
    info!(
        "sync completed: ipv4_entries={} ipv6_entries={}",
        outcome.ipv4_entries, outcome.ipv6_entries
    );
}

#[derive(Default)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "independent facts record confirmed partial enforcement progress"
)]
struct SyncProgress {
    enforcement_started: bool,
    ipv4_replaced: bool,
    ipv6_replaced: bool,
    wired: bool,
}

impl SyncProgress {
    fn failure_summary(&self) -> String {
        if !self.enforcement_started {
            return "No set replacement was started. Source/cache preparation may have changed local state.".into();
        }
        format!(
            "Enforcement started; partial application is possible. Confirmed replacements: IPv4={}, IPv6={}; managed wiring activated={}. The failed operation may also have changed state.",
            self.ipv4_replaced, self.ipv6_replaced, self.wired
        )
    }
}

struct CliSyncObserver<'a> {
    logs: LoggingSyncObserver,
    output: RefCell<&'a mut dyn Write>,
    view: Presentation,
    progress: bool,
    state: RefCell<SyncProgress>,
}

impl SyncObserver for CliSyncObserver<'_> {
    fn stage_completed(&self, stage: &'static str) {
        self.logs.stage_completed(stage);
    }
    fn notice(&self, notice: &kidobo_app::source::Notice) {
        self.logs.notice(notice);
    }
    fn event(&self, event: SyncEvent) {
        let mut progress_state = self.state.borrow_mut();
        match event {
            SyncEvent::EnforcementStarted => progress_state.enforcement_started = true,
            SyncEvent::FamilyReplaced(AddressFamily::Ipv4) => progress_state.ipv4_replaced = true,
            SyncEvent::FamilyReplaced(AddressFamily::Ipv6) => progress_state.ipv6_replaced = true,
            SyncEvent::WiringActivated => progress_state.wired = true,
            SyncEvent::StageStarted(stage) if self.progress => {
                // Presentation failure cannot interrupt the protected enforcement section.
                let _result = self.view.paragraph(
                    &mut **self.output.borrow_mut(),
                    &format!("... {}", stage.label()),
                );
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SyncProgress;
    #[test]
    fn failed_replacement_does_not_claim_rollback() {
        let before = SyncProgress::default().failure_summary();
        assert!(before.contains("No set replacement was started"));
        let after = SyncProgress {
            enforcement_started: true,
            ipv6_replaced: true,
            ..SyncProgress::default()
        }
        .failure_summary();
        assert!(after.contains("partial application is possible"));
        assert!(after.contains("IPv4=false, IPv6=true"));
    }
}
