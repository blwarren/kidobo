use log::info;

use crate::error::KidoboError;
use kidobo_adapters::config::FileConfigRepository;
use kidobo_adapters::enforcement::SystemEnforcementBackend;
use kidobo_adapters::lock::FileLockManager;
use kidobo_adapters::path::{SystemPathResolver, path_resolution_input_from_process};
use kidobo_adapters::sync_observer::LoggingSyncObserver;
use kidobo_adapters::sync_sources::build_sync_source_registry;
use kidobo_app::sync::{self, SyncDependencies, SyncObserver};

pub fn run_sync_command(timer: bool) -> Result<(), KidoboError> {
    let request = path_resolution_input_from_process(None);
    let paths = SystemPathResolver;
    let configs = FileConfigRepository;
    let locks = FileLockManager;
    let sources = build_sync_source_registry(env!("CARGO_PKG_VERSION"))?;
    let enforcement = SystemEnforcementBackend::default();
    let observer = LoggingSyncObserver::new(timer);
    let outcome = sync::execute(
        &request,
        &SyncDependencies {
            paths: &paths,
            configs: &configs,
            locks: &locks,
            sources: &sources,
            enforcement: &enforcement,
            observer: &observer,
        },
    )?;
    observer.stage_completed("sync_pipeline_complete");

    let source_count = |id: &str| {
        outcome
            .sources
            .iter()
            .find(|source| source.id == id)
            .map_or(0, |source| source.entries)
    };
    info!(
        "sync source counts: internal={} remote={} asn={} safelist={}",
        source_count("local-blocklist"),
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

    Ok(())
}
