//! Read-only sync planning through data-only source ports and a non-creating shared lock.

use std::collections::BTreeSet;
use std::path::Path;

use kidobo_core::network::CanonicalCidr;
use kidobo_core::sync::compute_effective_blocklists;
pub use kidobo_core::temporary_bans::TemporaryBans;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{Cancellation, ConfigRepository, LockGuard, PathResolver};
use crate::source::{
    Notice, SourceFailureDisposition, SourceObservation, SourceProvenance, SourceRole,
    SyncSourceBatch, SyncSourceContext, SyncSourceDescriptor, classify_source_failure,
};
use crate::sync::{
    EnforcementPlan, ExternalSafelistSelection, PreparedSyncEntries, SourceSummary,
    prepare_sync_entries, select_external_safelist,
};
use crate::temporary_bans::{Clock, kernel_timeout_notice};

/// Literal source data accepted by preview; no persistence or promotion handles are present.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreviewSourceLoad {
    /// Preferred validated source batch.
    pub primary: SyncSourceBatch,
    /// Optional compatible cache batch for external-safelist admission fallback.
    pub fallback: Option<SyncSourceBatch>,
    /// Typed provenance for each configured feed, ASN, or local source.
    pub observations: Vec<SourceObservation>,
}

impl PreviewSourceLoad {
    #[must_use]
    /// Wraps one batch without an admission fallback or explicit per-source observations.
    pub fn ready(primary: SyncSourceBatch) -> Self {
        Self {
            primary,
            fallback: None,
            observations: Vec::new(),
        }
    }
}

/// Immutable source inputs and explicit permission for non-persisting network reads.
pub struct PreviewSourceContext<'a> {
    /// The same immutable paths, configuration, temporary snapshot, and cutoff used by sync sources.
    pub sync: SyncSourceContext<'a>,
    /// Whether providers may fetch or resolve fresh data into bounded memory.
    pub allow_network: bool,
}

/// A source which can return only data and cannot return pending cache work.
pub trait PreviewSourceProvider: Send + Sync {
    /// Stable identity, contribution role, and normal source failure policy.
    fn descriptor(&self) -> SyncSourceDescriptor;

    /// Reads a batch without normalization writes, cache staging, repair, or promotion.
    ///
    /// # Errors
    ///
    /// Returns required-source, read, admission-budget, or cancellation failures.
    fn load(&self, context: &PreviewSourceContext<'_>) -> Result<PreviewSourceLoad, AppError>;
}

/// Ordered, uniquely identified collection of explicitly read-only source providers.
#[derive(Default)]
pub struct PreviewSourceRegistry {
    providers: Vec<Box<dyn PreviewSourceProvider>>,
    ids: BTreeSet<&'static str>,
}

impl PreviewSourceRegistry {
    #[must_use]
    /// Creates an empty read-only source registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a source without any normal sync or cache-promotion capability.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::DuplicateSourceProvider`] for a duplicate stable identity.
    pub fn register(
        &mut self,
        provider: impl PreviewSourceProvider + 'static,
    ) -> Result<(), AppError> {
        let id = provider.descriptor().id;
        if !self.ids.insert(id) {
            return Err(AppError::DuplicateSourceProvider { provider: id });
        }
        self.providers.push(Box::new(provider));
        Ok(())
    }

    #[must_use]
    /// Returns descriptors in source evaluation order.
    pub fn descriptors(&self) -> Vec<SyncSourceDescriptor> {
        self.providers
            .iter()
            .map(|provider| provider.descriptor())
            .collect()
    }
}

/// Loads temporary state without exposing a save or pruning capability to preview.
pub trait TemporaryBanReader {
    /// Reads and validates saved state; a missing file is empty.
    ///
    /// # Errors
    ///
    /// Returns bounded read or validation failures.
    fn load(&self, path: &Path) -> Result<TemporaryBans, AppError>;
}

/// Coordinates with mutations using only an existing regular lock file.
pub trait SharedLockManager {
    /// Acquires a nonblocking shared lock without creating files or changing permissions.
    ///
    /// # Errors
    ///
    /// Returns missing/inaccessible lock, contention, or operating-system failures.
    fn acquire_existing(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError>;
}

/// One read-only synchronization preview.
pub struct PreviewRequest {
    /// Existing native runtime path inputs.
    pub paths: PathResolutionInput,
    /// Explicit permission for non-persisting network reads; false means offline only.
    pub allow_network: bool,
}

/// Capabilities required for preview; no writable repository or enforcement backend is available.
pub struct PreviewDependencies<'a> {
    /// Cooperative cancellation between read operations.
    pub cancellation: &'a dyn Cancellation,
    /// Existing runtime path-resolution policy.
    pub paths: &'a dyn PathResolver,
    /// Validated read-only configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Non-creating shared lock acquisition.
    pub locks: &'a dyn SharedLockManager,
    /// One cutoff sampled while holding the shared process lock.
    pub clock: &'a dyn Clock,
    /// Read-only temporary state, without save or prune methods.
    pub temporary_bans: &'a dyn TemporaryBanReader,
    /// Separately registered data-only sources.
    pub sources: &'a PreviewSourceRegistry,
}

/// Validated proposed network data; it does not guarantee a subsequent sync or cache write succeeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreviewOutcome {
    /// Family-separated kernel representation and minimal network counts.
    pub entries: PreparedSyncEntries,
    /// Whether IPv6 was enabled in the configuration read under the shared lock.
    pub enable_ipv6: bool,
    /// Source load and admission summaries in registry order.
    pub sources: Vec<SourceSummary>,
    /// Degradation, admission, and kernel-timeout warnings.
    pub notices: Vec<Notice>,
    /// Whether this preview permitted fresh non-persisting reads.
    pub allow_network: bool,
}

struct LoadedSources {
    candidates: Vec<CanonicalCidr>,
    safelist: Vec<CanonicalCidr>,
    external_safelists: Vec<ExternalSafelist>,
    summaries: Vec<SourceSummary>,
    notices: Vec<Notice>,
}

struct ExternalSafelist {
    provider: &'static str,
    primary: SyncSourceBatch,
    fallback: Option<SyncSourceBatch>,
    summary_index: usize,
}

/// Builds a safe source plan without preparing artifacts, persisting data, or enforcing rules.
///
/// # Errors
///
/// Returns missing configuration/lock, required-source failures, hard source budgets, capacity
/// preflight failures, or cancellation. Optional source failures remain explicit notices.
pub fn execute(
    request: &PreviewRequest,
    dependencies: &PreviewDependencies<'_>,
) -> Result<PreviewOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let _lock = dependencies.locks.acquire_existing(&paths.lock_file)?;
    dependencies.cancellation.check()?;
    let cutoff = dependencies.clock.now_unix_secs()?;
    let config = dependencies.configs.load(&paths.config_file)?;
    dependencies.cancellation.check()?;
    let temporary_bans = dependencies
        .temporary_bans
        .load(&paths.temporary_bans_file())?;
    let context = PreviewSourceContext {
        sync: SyncSourceContext {
            cancellation: dependencies.cancellation,
            paths: &paths,
            config: &config,
            env: &request.paths.env,
            temporary_bans: &temporary_bans,
            cutoff,
        },
        allow_network: request.allow_network,
    };
    let LoadedSources {
        mut candidates,
        mut safelist,
        external_safelists,
        mut summaries,
        mut notices,
    } = load_sources(dependencies.sources, &context)?;
    if config.ipset.timeout != 0
        && (!temporary_bans.active_ips(cutoff).is_empty()
            || !temporary_bans.active_asns(cutoff).is_empty())
    {
        notices.push(kernel_timeout_notice());
    }
    dependencies.cancellation.check()?;
    candidates.sort_unstable();
    candidates.dedup();
    safelist.sort_unstable();
    safelist.dedup();
    admit_external_safelists(
        &candidates,
        &mut safelist,
        external_safelists,
        config.ipset.enable_ipv6,
        &mut summaries,
        &mut notices,
        dependencies.cancellation,
    )?;
    let effective = compute_effective_blocklists(&candidates, &safelist, config.ipset.enable_ipv6);
    let plan = EnforcementPlan::from_config(&config);
    let entries = prepare_sync_entries(&effective, &plan)?;
    dependencies.cancellation.check()?;
    Ok(PreviewOutcome {
        entries,
        enable_ipv6: config.ipset.enable_ipv6,
        sources: summaries,
        notices,
        allow_network: request.allow_network,
    })
}

fn load_sources(
    registry: &PreviewSourceRegistry,
    context: &PreviewSourceContext<'_>,
) -> Result<LoadedSources, AppError> {
    let mut loaded = LoadedSources {
        candidates: Vec::new(),
        safelist: Vec::new(),
        external_safelists: Vec::new(),
        summaries: Vec::new(),
        notices: Vec::new(),
    };
    for provider in &registry.providers {
        context.sync.cancellation.check()?;
        let descriptor = provider.descriptor();
        match provider.load(context) {
            Ok(batch) => {
                let PreviewSourceLoad {
                    primary,
                    fallback,
                    mut observations,
                } = batch;
                if observations.is_empty() {
                    observations.push(SourceObservation {
                        label: descriptor.id.to_string(),
                        provenance: SourceProvenance::Local,
                    });
                }
                loaded.notices.extend(primary.notices.iter().cloned());
                let entries = primary.networks.len();
                match descriptor.role {
                    SourceRole::Candidate => loaded.candidates.extend(primary.networks),
                    SourceRole::Safelist => loaded.safelist.extend(primary.networks),
                    SourceRole::ExternalSafelist => {
                        loaded.external_safelists.push(ExternalSafelist {
                            provider: descriptor.id,
                            primary,
                            fallback,
                            summary_index: loaded.summaries.len(),
                        });
                    }
                }
                loaded.summaries.push(SourceSummary {
                    id: descriptor.id,
                    role: descriptor.role,
                    entries,
                    loaded: true,
                    observations,
                });
            }
            Err(error)
                if classify_source_failure(descriptor.failure_policy, &error)
                    == SourceFailureDisposition::Degraded =>
            {
                loaded.notices.push(Notice::warning(format!(
                    "source provider `{}` failed softly: {error}",
                    descriptor.id
                )));
                loaded.summaries.push(SourceSummary {
                    id: descriptor.id,
                    role: descriptor.role,
                    entries: 0,
                    loaded: false,
                    observations: vec![SourceObservation {
                        label: descriptor.id.to_string(),
                        provenance: SourceProvenance::Unavailable,
                    }],
                });
            }
            Err(error) => return Err(error),
        }
    }
    Ok(loaded)
}

fn admit_external_safelists(
    candidates: &[CanonicalCidr],
    safelist: &mut Vec<CanonicalCidr>,
    external_safelists: Vec<ExternalSafelist>,
    enable_ipv6: bool,
    summaries: &mut [SourceSummary],
    notices: &mut Vec<Notice>,
    cancellation: &dyn Cancellation,
) -> Result<(), AppError> {
    let baseline = compute_effective_blocklists(candidates, safelist, enable_ipv6);
    for external in external_safelists {
        cancellation.check()?;
        let selection = select_external_safelist(
            candidates,
            safelist,
            &external.primary.networks,
            external
                .fallback
                .as_ref()
                .map(|batch| batch.networks.as_slice()),
            enable_ipv6,
            &baseline,
        );
        if selection == ExternalSafelistSelection::Primary {
            safelist.extend(external.primary.networks);
            continue;
        }
        notices.push(Notice::warning(format!("externally controlled safelist `{}` was rejected because it would empty an enabled address family", external.provider)));
        if let Some(fallback) = external
            .fallback
            .filter(|_| selection == ExternalSafelistSelection::Fallback)
        {
            notices.extend(fallback.notices);
            safelist.extend(fallback.networks.iter().copied());
            if let Some(summary) = summaries.get_mut(external.summary_index) {
                summary.entries = fallback.networks.len();
                for observation in &mut summary.observations {
                    observation.provenance = SourceProvenance::FallbackCache;
                }
            }
        } else {
            notices.push(Notice::warning(format!("externally controlled safelist `{}` has no admissible fallback; using only operator-controlled safelist entries", external.provider)));
            if let Some(summary) = summaries.get_mut(external.summary_index) {
                summary.entries = 0;
                summary.loaded = false;
                for observation in &mut summary.observations {
                    observation.provenance = SourceProvenance::Unavailable;
                }
            }
        }
    }
    safelist.sort_unstable();
    safelist.dedup();
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use kidobo_core::config::Config;
    use kidobo_core::network::parse_ip_cidr_strict;

    use super::*;
    use crate::paths::ResolvedPaths;
    use crate::source::FailurePolicy;

    type Events = Arc<Mutex<Vec<String>>>;

    fn record(events: &Events, event: &str) {
        events.lock().expect("events").push(event.to_string());
    }
    fn cidr(input: &str) -> CanonicalCidr {
        parse_ip_cidr_strict(input).expect("CIDR")
    }
    fn config(ipv6: bool, maxelem: u32) -> Config {
        Config::from_toml_str(&format!(
            "[ipset]\nset_name='kidobo'\nenable_ipv6={ipv6}\nmaxelem={maxelem}\n"
        ))
        .expect("config")
    }

    struct Paths(Events);
    impl PathResolver for Paths {
        fn resolve(
            &self,
            _: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Required);
            record(&self.0, "paths");
            let root = PathBuf::from("/preview-fixture");
            Ok(ResolvedPaths {
                root_override: Some(root.clone()),
                config_dir: root.join("config"),
                config_file: root.join("config/config.toml"),
                data_dir: root.join("data"),
                blocklist_file: root.join("data/blocklist.txt"),
                cache_dir: root.join("cache"),
                remote_cache_dir: root.join("cache/remote"),
                lock_file: root.join("cache/lock"),
            })
        }
    }

    struct Configs {
        events: Events,
        config: Config,
    }
    impl ConfigRepository for Configs {
        fn load(&self, _: &Path) -> Result<Config, AppError> {
            record(&self.events, "config");
            Ok(self.config.clone())
        }
    }

    struct Locks {
        events: Events,
        fail: bool,
    }
    struct Guard(Events);
    impl LockGuard for Guard {}
    impl Drop for Guard {
        fn drop(&mut self) {
            record(&self.0, "unlock");
        }
    }
    impl SharedLockManager for Locks {
        fn acquire_existing(&self, _: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            record(&self.events, "lock");
            if self.fail {
                return Err(AppError::Lock {
                    source: Box::new(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                });
            }
            Ok(Box::new(Guard(Arc::clone(&self.events))))
        }
    }

    struct ClockFixture {
        events: Events,
        now: AtomicU64,
        calls: AtomicUsize,
    }
    impl Clock for ClockFixture {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            record(&self.events, "clock");
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.now.load(Ordering::SeqCst))
        }
    }

    struct Temporary {
        events: Events,
        state: TemporaryBans,
    }
    impl TemporaryBanReader for Temporary {
        fn load(&self, _: &Path) -> Result<TemporaryBans, AppError> {
            record(&self.events, "temporary");
            Ok(self.state.clone())
        }
    }

    struct Fixture {
        events: Events,
        configs: Configs,
        locks: Locks,
        clock: Arc<ClockFixture>,
        temporary: Temporary,
        cancelled: Arc<AtomicBool>,
    }

    impl Fixture {
        fn new(config: Config) -> Self {
            let events = Events::default();
            Self {
                configs: Configs {
                    events: Arc::clone(&events),
                    config,
                },
                locks: Locks {
                    events: Arc::clone(&events),
                    fail: false,
                },
                clock: Arc::new(ClockFixture {
                    events: Arc::clone(&events),
                    now: AtomicU64::new(100),
                    calls: AtomicUsize::new(0),
                }),
                temporary: Temporary {
                    events: Arc::clone(&events),
                    state: TemporaryBans::default(),
                },
                cancelled: Arc::new(AtomicBool::new(false)),
                events,
            }
        }

        fn execute(
            &self,
            sources: &PreviewSourceRegistry,
            allow_network: bool,
        ) -> Result<PreviewOutcome, AppError> {
            execute(
                &PreviewRequest {
                    paths: PathResolutionInput {
                        explicit_config_path: None,
                        temp_dir: PathBuf::from("/tmp"),
                        env: std::collections::BTreeMap::new(),
                    },
                    allow_network,
                },
                &PreviewDependencies {
                    cancellation: self.cancelled.as_ref(),
                    paths: &Paths(Arc::clone(&self.events)),
                    configs: &self.configs,
                    locks: &self.locks,
                    clock: self.clock.as_ref(),
                    temporary_bans: &self.temporary,
                    sources,
                },
            )
        }
    }

    #[derive(Clone, Copy)]
    enum Failure {
        None,
        OptionalRead,
        RequiredAsn,
        Aggregate,
        Budget,
        Staging,
        Interrupted,
    }

    struct Source {
        descriptor: SyncSourceDescriptor,
        events: Events,
        primary: Vec<CanonicalCidr>,
        fallback: Option<Vec<CanonicalCidr>>,
        failure: Failure,
        expected_network: bool,
        temporary: bool,
        advance_clock: Option<Arc<ClockFixture>>,
        cancel_after: Option<Arc<AtomicBool>>,
    }

    impl PreviewSourceProvider for Source {
        fn descriptor(&self) -> SyncSourceDescriptor {
            self.descriptor
        }
        fn load(&self, context: &PreviewSourceContext<'_>) -> Result<PreviewSourceLoad, AppError> {
            record(&self.events, &format!("source:{}", self.descriptor.id));
            assert_eq!(context.allow_network, self.expected_network);
            assert_eq!(context.sync.cutoff, 100);
            let error = || {
                Box::new(std::io::Error::other("injected source failure"))
                    as Box<dyn std::error::Error + Send + Sync>
            };
            match self.failure {
                Failure::None => {}
                Failure::OptionalRead => {
                    return Err(AppError::Source {
                        provider: self.descriptor.id,
                        source: error(),
                    });
                }
                Failure::RequiredAsn => return Err(AppError::Asn { source: error() }),
                Failure::Aggregate => {
                    return Err(AppError::SourceAggregateBudgetExceeded {
                        entries: 8193,
                        limit: 8192,
                    });
                }
                Failure::Budget => {
                    return Err(AppError::PreviewSourceBudget {
                        provider: self.descriptor.id,
                        reason: "normalized response exceeds the supported cache representation"
                            .to_string(),
                    });
                }
                Failure::Staging => {
                    return Err(AppError::CacheStaging {
                        provider: self.descriptor.id,
                        source: error(),
                    });
                }
                Failure::Interrupted => return Err(AppError::Interrupted),
            }
            let networks = if self.temporary {
                context.sync.temporary_bans.active_ips(context.sync.cutoff)
            } else {
                self.primary.clone()
            };
            if let Some(clock) = &self.advance_clock {
                clock.now.store(1000, Ordering::SeqCst);
            }
            if let Some(cancelled) = &self.cancel_after {
                cancelled.store(true, Ordering::SeqCst);
            }
            Ok(PreviewSourceLoad {
                primary: SyncSourceBatch {
                    networks,
                    notices: Vec::new(),
                },
                fallback: self.fallback.as_ref().map(|networks| SyncSourceBatch {
                    networks: networks.clone(),
                    notices: vec![Notice::info("selected compatible fallback")],
                }),
                observations: vec![SourceObservation {
                    label: self.descriptor.id.to_string(),
                    provenance: SourceProvenance::Network,
                }],
            })
        }
    }

    fn source(
        fixture: &Fixture,
        id: &'static str,
        role: SourceRole,
        policy: FailurePolicy,
        networks: &[&str],
    ) -> Source {
        Source {
            descriptor: SyncSourceDescriptor {
                id,
                role,
                failure_policy: policy,
            },
            events: Arc::clone(&fixture.events),
            primary: networks.iter().map(|input| cidr(input)).collect(),
            fallback: None,
            failure: Failure::None,
            expected_network: false,
            temporary: false,
            advance_clock: None,
            cancel_after: None,
        }
    }

    #[test]
    fn ordered_sources_are_read_under_the_existing_lock_and_plan_counts_distinguish_kernel_entries()
    {
        let fixture = Fixture::new(config(true, 10));
        let mut registry = PreviewSourceRegistry::new();
        registry
            .register(source(
                &fixture,
                "local",
                SourceRole::Candidate,
                FailurePolicy::Required,
                &["0.0.0.0/0", "::/0"],
            ))
            .expect("local");
        registry
            .register(source(
                &fixture,
                "safe",
                SourceRole::Safelist,
                FailurePolicy::Required,
                &[],
            ))
            .expect("safe");
        let outcome = fixture.execute(&registry, false).expect("preview");
        assert_eq!(
            (outcome.entries.ipv4_networks, outcome.entries.ipv6_networks),
            (1, 1)
        );
        assert_eq!(
            outcome.entries.ipv4,
            [cidr("0.0.0.0/1"), cidr("128.0.0.0/1")]
        );
        assert_eq!(outcome.entries.ipv6, [cidr("::/1"), cidr("8000::/1")]);
        assert_eq!(
            *fixture.events.lock().expect("events"),
            [
                "paths",
                "lock",
                "clock",
                "config",
                "temporary",
                "source:local",
                "source:safe",
                "unlock"
            ]
        );
    }

    #[test]
    fn both_family_capacities_use_expanded_entries_and_disabled_ipv6_is_excluded() {
        for (ipv6, networks, failed_family) in [
            (true, vec!["0.0.0.0/0"], Some("ipv4")),
            (true, vec!["::/0"], Some("ipv6")),
            (false, vec!["::/0"], None),
        ] {
            let fixture = Fixture::new(config(ipv6, 1));
            let mut registry = PreviewSourceRegistry::new();
            registry
                .register(source(
                    &fixture,
                    "local",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    &networks,
                ))
                .expect("source");
            let result = fixture.execute(&registry, false);
            if let Some(expected) = failed_family {
                assert!(
                    matches!(result, Err(AppError::IpsetCapacityExceeded { family, entries: 2, .. }) if family == expected)
                );
            } else {
                let outcome = result.expect("disabled family ignored");
                assert_eq!(outcome.entries.ipv6, Vec::<CanonicalCidr>::new());
            }
            assert_eq!(
                fixture
                    .events
                    .lock()
                    .expect("events")
                    .last()
                    .map(String::as_str),
                Some("unlock")
            );
        }
    }

    #[test]
    fn external_safelist_uses_the_shared_primary_fallback_and_unavailable_choices() {
        for (primary, fallback, expected, provenance) in [
            (
                vec!["192.0.2.0/25"],
                None,
                "192.0.2.128/25",
                SourceProvenance::Network,
            ),
            (
                vec!["192.0.2.0/24"],
                Some(vec!["192.0.2.0/25"]),
                "192.0.2.128/25",
                SourceProvenance::FallbackCache,
            ),
            (
                vec!["192.0.2.0/24"],
                Some(vec!["192.0.2.0/24"]),
                "192.0.2.0/24",
                SourceProvenance::Unavailable,
            ),
        ] {
            let fixture = Fixture::new(config(false, 10));
            let mut registry = PreviewSourceRegistry::new();
            registry
                .register(source(
                    &fixture,
                    "local",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    &["192.0.2.0/24"],
                ))
                .expect("local");
            let mut external = source(
                &fixture,
                "external",
                SourceRole::ExternalSafelist,
                FailurePolicy::BestEffort,
                &primary,
            );
            external.fallback =
                fallback.map(|networks| networks.iter().map(|network| cidr(network)).collect());
            registry.register(external).expect("external");
            let outcome = fixture.execute(&registry, false).expect("preview");
            assert_eq!(outcome.entries.ipv4, [cidr(expected)]);
            let observation = outcome
                .sources
                .iter()
                .find(|source| source.id == "external")
                .expect("external summary");
            assert_eq!(
                observation
                    .observations
                    .first()
                    .expect("provenance")
                    .provenance,
                provenance
            );
            assert_eq!(
                observation.loaded,
                provenance != SourceProvenance::Unavailable
            );
            if provenance == SourceProvenance::FallbackCache {
                assert!(
                    outcome
                        .notices
                        .iter()
                        .any(|notice| notice.message == "selected compatible fallback")
                );
            }
        }
    }

    #[test]
    fn required_sources_and_hard_budgets_fail_while_optional_reads_degrade() {
        for (failure, policy, succeeds) in [
            (Failure::OptionalRead, FailurePolicy::BestEffort, true),
            (Failure::OptionalRead, FailurePolicy::Required, false),
            (Failure::RequiredAsn, FailurePolicy::Required, false),
            (Failure::Aggregate, FailurePolicy::BestEffort, false),
            (Failure::Budget, FailurePolicy::BestEffort, false),
            (Failure::Staging, FailurePolicy::BestEffort, false),
            (Failure::Interrupted, FailurePolicy::BestEffort, false),
        ] {
            let fixture = Fixture::new(config(true, 10));
            let mut registry = PreviewSourceRegistry::new();
            let mut failing = source(&fixture, "source", SourceRole::Candidate, policy, &[]);
            failing.failure = failure;
            registry.register(failing).expect("source");
            match fixture.execute(&registry, false) {
                Ok(outcome) => {
                    assert!(succeeds);
                    assert!(!outcome.sources.first().expect("source summary").loaded);
                    assert!(
                        outcome
                            .notices
                            .iter()
                            .any(|notice| notice.message.contains("failed softly"))
                    );
                }
                Err(error) => {
                    assert!(!succeeds);
                    match failure {
                        Failure::Budget => {
                            assert!(matches!(error, AppError::PreviewSourceBudget { .. }));
                        }
                        Failure::Aggregate => assert!(matches!(
                            error,
                            AppError::SourceAggregateBudgetExceeded { .. }
                        )),
                        Failure::RequiredAsn => assert!(matches!(error, AppError::Asn { .. })),
                        Failure::Interrupted => assert!(matches!(error, AppError::Interrupted)),
                        Failure::Staging => assert!(matches!(error, AppError::CacheStaging { .. })),
                        _ => assert!(matches!(error, AppError::Source { .. })),
                    }
                }
            }
        }
    }

    #[test]
    fn one_cutoff_keeps_snapshot_active_entries_and_never_prunes_saved_temporary_records() {
        let mut fixture = Fixture::new(config(true, 10));
        fixture.temporary.state.ips.insert(cidr("203.0.113.7"), 101);
        fixture.temporary.state.ips.insert(cidr("203.0.113.8"), 100);
        let saved = fixture.temporary.state.clone();
        let mut registry = PreviewSourceRegistry::new();
        let mut temporary = source(
            &fixture,
            "temporary",
            SourceRole::Candidate,
            FailurePolicy::Required,
            &[],
        );
        temporary.temporary = true;
        temporary.advance_clock = Some(Arc::clone(&fixture.clock));
        registry.register(temporary).expect("temporary");
        registry
            .register(source(
                &fixture,
                "later",
                SourceRole::Candidate,
                FailurePolicy::Required,
                &[],
            ))
            .expect("later");
        let outcome = fixture.execute(&registry, false).expect("preview");
        assert_eq!(outcome.entries.ipv4, [cidr("203.0.113.7")]);
        assert_eq!(fixture.clock.calls.load(Ordering::SeqCst), 1);
        assert_eq!(fixture.temporary.state, saved);
    }

    #[test]
    fn cancellation_and_lock_failures_stop_later_reads_and_release_acquired_locks() {
        let fixture = Fixture::new(config(true, 10));
        let mut registry = PreviewSourceRegistry::new();
        let mut first = source(
            &fixture,
            "first",
            SourceRole::Candidate,
            FailurePolicy::Required,
            &[],
        );
        first.cancel_after = Some(Arc::clone(&fixture.cancelled));
        registry.register(first).expect("first");
        registry
            .register(source(
                &fixture,
                "never",
                SourceRole::Candidate,
                FailurePolicy::Required,
                &[],
            ))
            .expect("never");
        assert!(matches!(
            fixture.execute(&registry, false),
            Err(AppError::Interrupted)
        ));
        assert_eq!(
            *fixture.events.lock().expect("events"),
            [
                "paths",
                "lock",
                "clock",
                "config",
                "temporary",
                "source:first",
                "unlock"
            ]
        );
        let mut locked = Fixture::new(config(true, 10));
        locked.locks.fail = true;
        assert!(matches!(
            locked.execute(&PreviewSourceRegistry::new(), false),
            Err(AppError::Lock { .. })
        ));
        assert_eq!(*locked.events.lock().expect("events"), ["paths", "lock"]);
    }

    #[test]
    fn registry_rejects_duplicates_and_network_permission_is_explicitly_forwarded() {
        let fixture = Fixture::new(config(true, 10));
        let mut registry = PreviewSourceRegistry::new();
        let mut online = source(
            &fixture,
            "online",
            SourceRole::Candidate,
            FailurePolicy::Required,
            &[],
        );
        online.expected_network = true;
        registry.register(online).expect("source");
        assert!(matches!(
            registry.register(source(
                &fixture,
                "online",
                SourceRole::Candidate,
                FailurePolicy::Required,
                &[]
            )),
            Err(AppError::DuplicateSourceProvider { provider: "online" })
        ));
        assert_eq!(registry.descriptors().len(), 1);
        assert!(
            fixture
                .execute(&registry, true)
                .expect("online preview")
                .allow_network
        );
    }
}
