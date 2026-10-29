//! Ordered, fail-closed synchronization workflow and its enforcement port.

pub use kidobo_core::AddressFamily;
use kidobo_core::config::{Config, FirewallAction};
use kidobo_core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};
use kidobo_core::sync::compute_effective_blocklists;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::source::{
    Notice, SourceFailureDisposition, SourceRole, SyncSourceContext, SyncSourceRegistry,
    classify_source_failure,
};
use crate::source::{
    PendingCachePromotion, SourceObservation, SourceProvenance, SyncSourceBatch, SyncSourceLoad,
};
use crate::temporary_bans::{Clock, TemporaryBanRepository, kernel_timeout_notice};

/// Validated kernel-set parameters for one address family.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSetSpec {
    /// Address family owned by the set.
    pub family: AddressFamily,
    /// Compatibility-sensitive kernel set name.
    pub set_name: String,
    /// Kernel set type.
    pub set_type: String,
    /// Initial kernel hash table size.
    pub hashsize: u32,
    /// Maximum permitted entries.
    pub maxelem: u32,
    /// Kernel entry timeout; zero disables expiry.
    pub timeout: u32,
}

/// Complete family-separated firewall and ipset enforcement plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnforcementPlan {
    /// IPv4 managed-set specification.
    pub ipv4: ManagedSetSpec,
    /// IPv6 managed-set specification, used only when enabled.
    pub ipv6: ManagedSetSpec,
    /// Whether IPv6 artifacts should be enforced rather than cleaned up.
    pub enable_ipv6: bool,
    /// Firewall verdict used by each managed chain rule.
    pub chain_action: FirewallAction,
}

impl EnforcementPlan {
    #[must_use]
    /// Builds an enforcement plan from validated configuration.
    pub fn from_config(config: &Config) -> Self {
        Self {
            ipv4: ManagedSetSpec {
                family: AddressFamily::Ipv4,
                set_name: config.ipset.set_name.clone(),
                set_type: config.ipset.set_type.clone(),
                hashsize: config.ipset.hashsize.get(),
                maxelem: config.ipset.maxelem.get(),
                timeout: config.ipset.timeout,
            },
            ipv6: ManagedSetSpec {
                family: AddressFamily::Ipv6,
                set_name: config.ipset.set_name_v6.clone(),
                set_type: config.ipset.set_type.clone(),
                hashsize: config.ipset.hashsize.get(),
                maxelem: config.ipset.maxelem.get(),
                timeout: config.ipset.timeout,
            },
            enable_ipv6: config.ipset.enable_ipv6,
            chain_action: config.ipset.chain_action,
        }
    }
}

/// Side-effect boundary for atomic set replacement and fail-closed firewall wiring.
pub trait EnforcementBackend {
    /// Ensures inactive managed sets and chains exist without enabling new wiring.
    ///
    /// # Errors
    ///
    /// Returns an error when any required firewall or ipset artifact cannot be prepared.
    fn ensure_artifacts(&self, plan: &EnforcementPlan) -> Result<(), AppError>;

    /// Atomically replaces one managed set with the supplied family-specific entries.
    ///
    /// # Errors
    ///
    /// Returns an error when the temporary set cannot be created, restored, swapped, or cleaned
    /// up according to the backend contract.
    fn replace_set(&self, spec: &ManagedSetSpec, entries: &[CanonicalCidr])
    -> Result<(), AppError>;

    /// Activates and normalizes firewall wiring for the prepared sets.
    ///
    /// # Errors
    ///
    /// Returns an error when fail-closed wiring cannot be established or normalized.
    fn activate(&self, plan: &EnforcementPlan) -> Result<(), AppError>;

    /// Best-effort removal of managed IPv6 artifacts when IPv6 is disabled.
    ///
    /// All scoped cleanup steps must be attempted; incomplete steps are returned as notices.
    fn cleanup_disabled_ipv6(&self, plan: &EnforcementPlan) -> Vec<Notice>;
}

/// Named synchronization stages with stable journal markers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncStage {
    /// Resolve configured runtime paths.
    ResolvePaths,
    /// Read and validate configuration.
    LoadConfig,
    /// Acquire the exclusive process lock.
    AcquireLock,
    /// Prepare inactive managed firewall artifacts.
    PrepareArtifacts,
    /// Load candidate and safelist providers.
    LoadSources,
    /// Admit safelists and compute effective family-separated CIDRs.
    ComputeBlocklists,
    /// Promote validated source cache selections.
    PromoteCaches,
    /// Replace the managed IPv6 set.
    ApplyIpv6,
    /// Replace the managed IPv4 set.
    ApplyIpv4,
    /// Activate and normalize managed wiring and clean disabled-family artifacts.
    ActivateFirewall,
}

impl SyncStage {
    #[must_use]
    /// Returns the existing timing/logging identifier for the stage.
    pub fn marker(self) -> &'static str {
        match self {
            Self::ResolvePaths => "resolve_paths",
            Self::LoadConfig => "load_config",
            Self::AcquireLock => "acquire_lock",
            Self::PrepareArtifacts => "ensure_ipset_artifacts",
            Self::LoadSources => "load_sources",
            Self::ComputeBlocklists => "compute_effective_blocklists",
            Self::PromoteCaches => "promote_source_caches",
            Self::ApplyIpv6 => "apply_ipv6_ipset",
            Self::ApplyIpv4 => "apply_ipv4_ipset",
            Self::ActivateFirewall => "ensure_firewall_wiring",
        }
    }

    #[must_use]
    /// Returns a concise operator-facing description.
    pub fn label(self) -> &'static str {
        match self {
            Self::ResolvePaths => "Resolve paths",
            Self::LoadConfig => "Read configuration",
            Self::AcquireLock => "Acquire sync lock",
            Self::PrepareArtifacts => "Prepare managed sets and chains",
            Self::LoadSources => "Load blocklists and safelists",
            Self::ComputeBlocklists => "Compute effective networks",
            Self::PromoteCaches => "Select validated caches",
            Self::ApplyIpv6 => "Replace IPv6 set",
            Self::ApplyIpv4 => "Replace IPv4 set",
            Self::ActivateFirewall => "Activate managed firewall wiring",
        }
    }
}

/// Truthful workflow observations; callbacks cannot change execution or error policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncEvent {
    /// A named operation is about to start and may still fail.
    StageStarted(SyncStage),
    /// A named operation completed successfully.
    StageCompleted(SyncStage),
    /// Enforcement is entering its protected, non-cancellable section.
    EnforcementStarted,
    /// One family replacement returned successfully.
    FamilyReplaced(AddressFamily),
    /// Managed firewall activation returned successfully.
    WiringActivated,
    /// Cleanup of artifacts for disabled IPv6 is beginning.
    DisabledIpv6CleanupStarted,
    /// Every scoped disabled-IPv6 cleanup attempt finished; notices describe failures.
    DisabledIpv6CleanupCompleted,
}

/// Observer for stable workflow stage markers and operator notices.
pub trait SyncObserver {
    /// Records completion of a named ordered synchronization stage.
    fn stage_completed(&self, stage: &'static str);

    /// Records a notice without changing workflow error policy.
    fn notice(&self, notice: &Notice);

    /// Receives typed progress without adding cancellation or failure boundaries.
    fn event(&self, _event: SyncEvent) {}
}

fn start_stage(observer: &dyn SyncObserver, stage: SyncStage) {
    observer.event(SyncEvent::StageStarted(stage));
}

fn complete_stage(observer: &dyn SyncObserver, stage: SyncStage) {
    observer.event(SyncEvent::StageCompleted(stage));
    observer.stage_completed(stage.marker());
}

/// Outcome summary for one registered synchronization source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceSummary {
    /// Stable provider identifier.
    pub id: &'static str,
    /// Candidate or safelist role.
    pub role: SourceRole,
    /// Number of networks loaded, or zero after a best-effort failure.
    pub entries: usize,
    /// Whether the provider produced a usable batch.
    pub loaded: bool,
    /// Evidence for each contributing feed, ASN, or local provider.
    pub observations: Vec<SourceObservation>,
}

/// Successful synchronization result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Number of effective IPv4 CIDRs before kernel-specific /0 expansion.
    pub ipv4_entries: usize,
    /// Number of effective IPv6 CIDRs before kernel-specific /0 expansion.
    pub ipv6_entries: usize,
    /// Number of IPv4 kernel entries after /0 expansion.
    pub ipv4_kernel_entries: usize,
    /// Number of IPv6 kernel entries after /0 expansion.
    pub ipv6_kernel_entries: usize,
    /// Per-provider load summaries in registry order.
    pub sources: Vec<SourceSummary>,
}

/// Data-only kernel representation and network counts after shared capacity preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedSyncEntries {
    /// IPv4 kernel entries; a minimal /0 is represented by two /1 entries.
    pub ipv4: Vec<CanonicalCidr>,
    /// IPv6 kernel entries, empty when IPv6 is disabled.
    pub ipv6: Vec<CanonicalCidr>,
    /// Minimal effective IPv4 network count before kernel-specific expansion.
    pub ipv4_networks: usize,
    /// Minimal effective IPv6 network count before kernel-specific expansion.
    pub ipv6_networks: usize,
}

/// Ports and registries required by the synchronization workflow.
pub struct SyncDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Nonblocking process lock manager.
    pub locks: &'a dyn LockManager,
    /// Time source for one consistent expiry decision per sync.
    pub clock: &'a dyn Clock,
    /// Persistent operator-managed temporary bans.
    pub temporary_bans: &'a dyn TemporaryBanRepository,
    /// Ordered source registry.
    pub sources: &'a SyncSourceRegistry,
    /// Atomic set and fail-closed firewall backend.
    pub enforcement: &'a dyn EnforcementBackend,
    /// Workflow event observer.
    pub observer: &'a dyn SyncObserver,
}

struct LoadedSources {
    candidates: Vec<CanonicalCidr>,
    safelist: Vec<CanonicalCidr>,
    external_safelists: Vec<LoadedExternalSafelist>,
    pending_promotions: Vec<PendingPromotion>,
    summaries: Vec<SourceSummary>,
}

struct LoadedExternalSafelist {
    provider: &'static str,
    primary: SyncSourceBatch,
    fallback: Option<SyncSourceBatch>,
    pending_promotions: Vec<Box<dyn PendingCachePromotion>>,
    summary_index: usize,
    fallback_failure: Option<AppError>,
}

struct PendingPromotion {
    provider: &'static str,
    promotion: Box<dyn PendingCachePromotion>,
}

/// Runs one complete fail-closed synchronization.
///
/// # Errors
///
/// Returns an error when required paths, configuration, locking, sources, capacity preflight,
/// atomic set replacement, or firewall activation fails. Best-effort source and disabled-family
/// cleanup failures are reported as notices instead.
pub fn execute(
    request: &PathResolutionInput,
    dependencies: &SyncDependencies<'_>,
) -> Result<SyncOutcome, AppError> {
    dependencies.cancellation.check()?;
    start_stage(dependencies.observer, SyncStage::ResolvePaths);
    let paths = dependencies
        .paths
        .resolve(request, ConfigRequirement::Required)?;
    complete_stage(dependencies.observer, SyncStage::ResolvePaths);
    dependencies.cancellation.check()?;

    start_stage(dependencies.observer, SyncStage::LoadConfig);
    dependencies.configs.load(&paths.config_file)?;
    complete_stage(dependencies.observer, SyncStage::LoadConfig);
    dependencies.cancellation.check()?;

    start_stage(dependencies.observer, SyncStage::AcquireLock);
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    complete_stage(dependencies.observer, SyncStage::AcquireLock);
    let cutoff = dependencies.clock.now_unix_secs()?;
    dependencies.cancellation.check()?;

    // A source-editing command may have published a new configuration before lock acquisition.
    let config = dependencies.configs.load(&paths.config_file)?;
    dependencies.cancellation.check()?;
    let temporary_path = paths.temporary_bans_file();
    let mut temporary_bans = dependencies.temporary_bans.load(&temporary_path)?;
    if config.ipset.timeout != 0
        && (!temporary_bans.active_ips(cutoff).is_empty()
            || !temporary_bans.active_asns(cutoff).is_empty())
    {
        dependencies.observer.notice(&kernel_timeout_notice());
    }

    let enforcement_plan = EnforcementPlan::from_config(&config);
    start_stage(dependencies.observer, SyncStage::PrepareArtifacts);
    dependencies
        .enforcement
        .ensure_artifacts(&enforcement_plan)?;
    complete_stage(dependencies.observer, SyncStage::PrepareArtifacts);

    let source_context = SyncSourceContext {
        cancellation: dependencies.cancellation,
        paths: &paths,
        config: &config,
        env: &request.env,
        temporary_bans: &temporary_bans,
        cutoff,
    };
    start_stage(dependencies.observer, SyncStage::LoadSources);
    let LoadedSources {
        mut candidates,
        mut safelist,
        external_safelists,
        mut pending_promotions,
        mut summaries,
    } = load_sources(dependencies.sources, &source_context, dependencies.observer)?;
    complete_stage(dependencies.observer, SyncStage::LoadSources);
    dependencies.cancellation.check()?;

    start_stage(dependencies.observer, SyncStage::ComputeBlocklists);
    candidates.sort_unstable();
    candidates.dedup();
    safelist.sort_unstable();
    safelist.dedup();
    admit_external_safelists(
        &candidates,
        &mut safelist,
        external_safelists,
        enforcement_plan.enable_ipv6,
        &mut pending_promotions,
        &mut summaries,
        dependencies.observer,
    )?;
    let effective =
        compute_effective_blocklists(&candidates, &safelist, enforcement_plan.enable_ipv6);
    complete_stage(dependencies.observer, SyncStage::ComputeBlocklists);

    let entries = prepare_sync_entries(&effective, &enforcement_plan)?;

    dependencies.cancellation.check()?;
    promote_pending_caches(
        pending_promotions,
        dependencies.observer,
        dependencies.cancellation,
    )?;
    dependencies.cancellation.check()?;

    apply_enforcement(
        &enforcement_plan,
        &entries.ipv4,
        &entries.ipv6,
        dependencies,
    )?;

    if temporary_bans.prune_expired(cutoff)
        && let Err(error) = dependencies
            .temporary_bans
            .save(&temporary_path, &temporary_bans)
    {
        dependencies.observer.notice(&Notice::warning(format!(
            "sync enforcement completed but expired temporary ban cleanup failed; expired records remain inactive: {error}"
        )));
    }

    Ok(SyncOutcome {
        ipv4_entries: effective.ipv4.len(),
        ipv6_entries: effective.ipv6.len(),
        ipv4_kernel_entries: entries.ipv4.len(),
        ipv6_kernel_entries: entries.ipv6.len(),
        sources: summaries,
    })
}

pub(crate) fn prepare_sync_entries(
    effective: &kidobo_core::sync::EffectiveBlocklists,
    plan: &EnforcementPlan,
) -> Result<PreparedSyncEntries, AppError> {
    let ipv4 = prepare_enforcement_entries(effective.ipv4.iter().copied().map(CanonicalCidr::V4));
    let ipv6 = prepare_enforcement_entries(effective.ipv6.iter().copied().map(CanonicalCidr::V6));
    if plan.enable_ipv6 {
        ensure_within_capacity(&plan.ipv6, ipv6.len())?;
    }
    ensure_within_capacity(&plan.ipv4, ipv4.len())?;
    Ok(PreparedSyncEntries {
        ipv4,
        ipv6,
        ipv4_networks: effective.ipv4.len(),
        ipv6_networks: effective.ipv6.len(),
    })
}

// hash:net cannot represent /0. Keep the core result minimal and use the same
// expanded entries for capacity preflight and replacement.
#[expect(clippy::expect_used, reason = "constant /1 prefixes are always valid")]
fn prepare_enforcement_entries(
    entries: impl IntoIterator<Item = CanonicalCidr>,
) -> Vec<CanonicalCidr> {
    entries
        .into_iter()
        .flat_map(|entry| match entry {
            CanonicalCidr::V4(cidr) if cidr.prefix() == 0 => [
                Some(CanonicalCidr::V4(
                    Ipv4Cidr::new(0_u32.into(), 1).expect("valid /1"),
                )),
                Some(CanonicalCidr::V4(
                    Ipv4Cidr::new((1_u32 << 31).into(), 1).expect("valid /1"),
                )),
            ],
            CanonicalCidr::V6(cidr) if cidr.prefix() == 0 => [
                Some(CanonicalCidr::V6(
                    Ipv6Cidr::new(0_u128.into(), 1).expect("valid /1"),
                )),
                Some(CanonicalCidr::V6(
                    Ipv6Cidr::new((1_u128 << 127).into(), 1).expect("valid /1"),
                )),
            ],
            _ => [Some(entry), None],
        })
        .flatten()
        .collect()
}

// Finish enforcement once the first replacement starts, including wiring and cleanup.
fn apply_enforcement(
    enforcement_plan: &EnforcementPlan,
    ipv4_entries: &[CanonicalCidr],
    ipv6_entries: &[CanonicalCidr],
    dependencies: &SyncDependencies<'_>,
) -> Result<(), AppError> {
    dependencies.observer.event(SyncEvent::EnforcementStarted);
    if enforcement_plan.enable_ipv6 {
        start_stage(dependencies.observer, SyncStage::ApplyIpv6);
        dependencies
            .enforcement
            .replace_set(&enforcement_plan.ipv6, ipv6_entries)?;
        dependencies
            .observer
            .event(SyncEvent::FamilyReplaced(AddressFamily::Ipv6));
        complete_stage(dependencies.observer, SyncStage::ApplyIpv6);
    }
    start_stage(dependencies.observer, SyncStage::ApplyIpv4);
    dependencies
        .enforcement
        .replace_set(&enforcement_plan.ipv4, ipv4_entries)?;
    dependencies
        .observer
        .event(SyncEvent::FamilyReplaced(AddressFamily::Ipv4));
    complete_stage(dependencies.observer, SyncStage::ApplyIpv4);

    start_stage(dependencies.observer, SyncStage::ActivateFirewall);
    dependencies.enforcement.activate(enforcement_plan)?;
    dependencies.observer.event(SyncEvent::WiringActivated);
    if !enforcement_plan.enable_ipv6 {
        dependencies
            .observer
            .event(SyncEvent::DisabledIpv6CleanupStarted);
        for notice in dependencies
            .enforcement
            .cleanup_disabled_ipv6(enforcement_plan)
        {
            dependencies.observer.notice(&notice);
        }
        dependencies
            .observer
            .event(SyncEvent::DisabledIpv6CleanupCompleted);
    }
    complete_stage(dependencies.observer, SyncStage::ActivateFirewall);

    Ok(())
}

fn load_sources(
    registry: &SyncSourceRegistry,
    context: &SyncSourceContext<'_>,
    observer: &dyn SyncObserver,
) -> Result<LoadedSources, AppError> {
    let mut candidates = Vec::new();
    let mut safelist = Vec::new();
    let mut external_safelists = Vec::new();
    let mut pending_promotions = Vec::new();
    let mut summaries = Vec::new();

    for provider in registry.providers() {
        context.cancellation.check()?;
        let descriptor = provider.descriptor();
        match provider.load(context) {
            Ok(loaded) => {
                let SyncSourceLoad {
                    primary,
                    fallback,
                    pending_promotions: loaded_promotions,
                    fallback_failure,
                    mut observations,
                } = loaded;
                if observations.is_empty() {
                    observations.push(SourceObservation {
                        label: descriptor.id.to_string(),
                        provenance: SourceProvenance::Local,
                    });
                }
                let entry_count = primary.networks.len();
                let summary_index = summaries.len();
                for notice in &primary.notices {
                    observer.notice(notice);
                }
                match descriptor.role {
                    SourceRole::Candidate => {
                        candidates.extend(primary.networks);
                        pending_promotions.extend(loaded_promotions.into_iter().map(|promotion| {
                            PendingPromotion {
                                provider: descriptor.id,
                                promotion,
                            }
                        }));
                    }
                    SourceRole::Safelist => {
                        safelist.extend(primary.networks);
                        pending_promotions.extend(loaded_promotions.into_iter().map(|promotion| {
                            PendingPromotion {
                                provider: descriptor.id,
                                promotion,
                            }
                        }));
                    }
                    SourceRole::ExternalSafelist => {
                        external_safelists.push(LoadedExternalSafelist {
                            provider: descriptor.id,
                            primary,
                            fallback,
                            pending_promotions: loaded_promotions,
                            summary_index,
                            fallback_failure,
                        });
                    }
                }
                summaries.push(SourceSummary {
                    id: descriptor.id,
                    role: descriptor.role,
                    entries: entry_count,
                    loaded: true,
                    observations,
                });
            }
            Err(error)
                if classify_source_failure(descriptor.failure_policy, &error)
                    == SourceFailureDisposition::Degraded =>
            {
                observer.notice(&Notice::warning(format!(
                    "source provider `{}` failed softly: {error}",
                    descriptor.id
                )));
                summaries.push(SourceSummary {
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

    Ok(LoadedSources {
        candidates,
        safelist,
        external_safelists,
        pending_promotions,
        summaries,
    })
}

fn promote_pending_caches(
    pending_promotions: Vec<PendingPromotion>,
    observer: &dyn SyncObserver,
    cancellation: &dyn crate::ports::Cancellation,
) -> Result<(), AppError> {
    start_stage(observer, SyncStage::PromoteCaches);
    for pending in pending_promotions {
        cancellation.check()?;
        pending
            .promotion
            .promote()
            .map_err(|source| AppError::CachePromotion {
                provider: pending.provider,
                source,
            })?;
    }
    complete_stage(observer, SyncStage::PromoteCaches);
    Ok(())
}

fn admit_external_safelists(
    candidates: &[CanonicalCidr],
    safelist: &mut Vec<CanonicalCidr>,
    external_safelists: Vec<LoadedExternalSafelist>,
    enable_ipv6: bool,
    pending_promotions: &mut Vec<PendingPromotion>,
    summaries: &mut [SourceSummary],
    observer: &dyn SyncObserver,
) -> Result<(), AppError> {
    let baseline = compute_effective_blocklists(candidates, safelist, enable_ipv6);

    for external in external_safelists {
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
            safelist.extend(external.primary.networks.iter().copied());
            pending_promotions.extend(external.pending_promotions.into_iter().map(|promotion| {
                PendingPromotion {
                    provider: external.provider,
                    promotion,
                }
            }));
            continue;
        }

        observer.notice(&Notice::warning(format!(
            "externally controlled safelist `{}` was rejected because it would empty an enabled address family",
            external.provider
        )));
        if let Some(fallback) = external
            .fallback
            .filter(|_| selection == ExternalSafelistSelection::Fallback)
        {
            for notice in &fallback.notices {
                observer.notice(notice);
            }
            safelist.extend(fallback.networks.iter().copied());
            if let Some(summary) = summaries.get_mut(external.summary_index) {
                summary.entries = fallback.networks.len();
                for observation in &mut summary.observations {
                    observation.provenance = SourceProvenance::FallbackCache;
                }
            }
        } else {
            if let Some(error) = external.fallback_failure {
                return Err(error);
            }
            observer.notice(&Notice::warning(format!(
                "externally controlled safelist `{}` has no admissible fallback; using only operator-controlled safelist entries",
                external.provider
            )));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExternalSafelistSelection {
    Primary,
    Fallback,
    Unavailable,
}

pub(crate) fn select_external_safelist(
    candidates: &[CanonicalCidr],
    operator_and_admitted_safelist: &[CanonicalCidr],
    primary: &[CanonicalCidr],
    fallback: Option<&[CanonicalCidr]>,
    enable_ipv6: bool,
    baseline: &kidobo_core::sync::EffectiveBlocklists,
) -> ExternalSafelistSelection {
    if external_safelist_preserves_baseline(
        candidates,
        operator_and_admitted_safelist,
        primary,
        enable_ipv6,
        baseline,
    ) {
        ExternalSafelistSelection::Primary
    } else if fallback.is_some_and(|fallback| {
        external_safelist_preserves_baseline(
            candidates,
            operator_and_admitted_safelist,
            fallback,
            enable_ipv6,
            baseline,
        )
    }) {
        ExternalSafelistSelection::Fallback
    } else {
        ExternalSafelistSelection::Unavailable
    }
}

fn external_safelist_preserves_baseline(
    candidates: &[CanonicalCidr],
    operator_safelist: &[CanonicalCidr],
    external_safelist: &[CanonicalCidr],
    enable_ipv6: bool,
    baseline: &kidobo_core::sync::EffectiveBlocklists,
) -> bool {
    let mut combined = Vec::with_capacity(operator_safelist.len() + external_safelist.len());
    combined.extend_from_slice(operator_safelist);
    combined.extend_from_slice(external_safelist);
    combined.sort_unstable();
    combined.dedup();
    let admitted = compute_effective_blocklists(candidates, &combined, enable_ipv6);

    (baseline.ipv4.is_empty() || !admitted.ipv4.is_empty())
        && (!enable_ipv6 || baseline.ipv6.is_empty() || !admitted.ipv6.is_empty())
}

fn ensure_within_capacity(spec: &ManagedSetSpec, entries: usize) -> Result<(), AppError> {
    if entries <= usize::try_from(spec.maxelem).unwrap_or(usize::MAX) {
        return Ok(());
    }

    let family = match spec.family {
        AddressFamily::Ipv4 => "ipv4",
        AddressFamily::Ipv6 => "ipv6",
    };
    Err(AppError::IpsetCapacityExceeded {
        family,
        set_name: spec.set_name.clone(),
        entries,
        maxelem: spec.maxelem,
    })
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};

    use kidobo_core::AddressFamily;
    use kidobo_core::config::Config;
    use kidobo_core::network::{CanonicalCidr, parse_ip_cidr_token};
    use kidobo_core::temporary_bans::TemporaryBans;

    use super::{
        EnforcementBackend, EnforcementPlan, ManagedSetSpec, SyncDependencies, SyncEvent,
        SyncObserver, SyncStage, execute,
    };
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, LockGuard, LockManager, PathResolver};
    use crate::source::{
        FailurePolicy, Notice, PendingCachePromotion, SourceRole, SyncSourceBatch,
        SyncSourceContext, SyncSourceDescriptor, SyncSourceLoad, SyncSourceProvider,
        SyncSourceRegistry,
    };
    use crate::temporary_bans::{Clock, TemporaryBanRepository};

    type Ledger = Arc<Mutex<Vec<String>>>;

    fn record(ledger: &Ledger, event: impl Into<String>) {
        ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(event.into());
    }

    fn events(ledger: &Ledger) -> Vec<String> {
        ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn cidr(value: &str) -> CanonicalCidr {
        parse_ip_cidr_token(value).expect("valid CIDR")
    }

    fn config(enable_ipv6: bool, maxelem: u32) -> Config {
        Config::from_toml_str(&format!(
            "[ipset]\nset_name = 'kidobo'\nenable_ipv6 = {enable_ipv6}\nmaxelem = {maxelem}\n"
        ))
        .expect("valid config")
    }

    fn test_paths() -> ResolvedPaths {
        let root = PathBuf::from("/test-root");
        ResolvedPaths {
            root_override: Some(root.clone()),
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        }
    }

    fn request() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: std::collections::BTreeMap::new(),
        }
    }

    struct FakePaths {
        ledger: Ledger,
        paths: ResolvedPaths,
    }

    impl PathResolver for FakePaths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            assert_eq!(requirement, ConfigRequirement::Required);
            record(&self.ledger, "paths");
            Ok(self.paths.clone())
        }
    }

    struct FakeConfigs {
        ledger: Ledger,
        config: Config,
    }

    impl ConfigRepository for FakeConfigs {
        fn load(&self, _path: &Path) -> Result<Config, AppError> {
            record(&self.ledger, "config");
            Ok(self.config.clone())
        }
    }

    struct FakeLockGuard(Ledger);

    impl LockGuard for FakeLockGuard {}

    impl Drop for FakeLockGuard {
        fn drop(&mut self) {
            record(&self.0, "unlock");
        }
    }

    struct FakeLocks(Ledger);

    impl LockManager for FakeLocks {
        fn acquire(&self, _path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            record(&self.0, "lock");
            Ok(Box::new(FakeLockGuard(Arc::clone(&self.0))))
        }
    }

    struct FakeSource {
        ledger: Ledger,
        descriptor: SyncSourceDescriptor,
        networks: Vec<CanonicalCidr>,
        fail: bool,
    }

    impl SyncSourceProvider for FakeSource {
        fn descriptor(&self) -> SyncSourceDescriptor {
            self.descriptor
        }

        fn load(&self, _context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
            record(&self.ledger, format!("source:{}", self.descriptor.id));
            if self.fail {
                return Err(AppError::Source {
                    provider: self.descriptor.id,
                    source: Box::new(std::io::Error::other("injected failure")),
                });
            }
            Ok(SyncSourceLoad::ready(SyncSourceBatch {
                networks: self.networks.clone(),
                notices: Vec::new(),
            }))
        }
    }

    struct FakeEnforcement {
        ledger: Ledger,
        fail_at: Option<&'static str>,
        replacements: Mutex<Vec<(AddressFamily, Vec<CanonicalCidr>)>>,
    }

    struct RecordingPromotion {
        ledger: Ledger,
        fail: bool,
    }

    impl PendingCachePromotion for RecordingPromotion {
        fn promote(self: Box<Self>) -> std::io::Result<()> {
            record(&self.ledger, "promote");
            if self.fail {
                Err(std::io::Error::other("injected promotion failure"))
            } else {
                Ok(())
            }
        }
    }

    struct DeferredSource {
        ledger: Ledger,
        descriptor: SyncSourceDescriptor,
        primary: Vec<CanonicalCidr>,
        fallback: Option<Vec<CanonicalCidr>>,
        fail_promotion: bool,
    }

    impl SyncSourceProvider for DeferredSource {
        fn descriptor(&self) -> SyncSourceDescriptor {
            self.descriptor
        }

        fn load(&self, _context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
            record(&self.ledger, format!("source:{}", self.descriptor.id));
            Ok(SyncSourceLoad {
                fallback_failure: None,
                primary: SyncSourceBatch {
                    networks: self.primary.clone(),
                    notices: Vec::new(),
                },
                fallback: self.fallback.as_ref().map(|networks| SyncSourceBatch {
                    networks: networks.clone(),
                    notices: Vec::new(),
                }),
                pending_promotions: vec![Box::new(RecordingPromotion {
                    ledger: Arc::clone(&self.ledger),
                    fail: self.fail_promotion,
                })],
                observations: Vec::new(),
            })
        }
    }

    impl EnforcementBackend for FakeEnforcement {
        fn ensure_artifacts(&self, _plan: &EnforcementPlan) -> Result<(), AppError> {
            record(&self.ledger, "ensure");
            self.result_for("ensure")
        }

        fn replace_set(
            &self,
            spec: &ManagedSetSpec,
            entries: &[CanonicalCidr],
        ) -> Result<(), AppError> {
            let event = match spec.family {
                AddressFamily::Ipv4 => "replace-v4",
                AddressFamily::Ipv6 => "replace-v6",
            };
            record(&self.ledger, event);
            self.replacements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push((spec.family, entries.to_vec()));
            self.result_for(event)
        }

        fn activate(&self, _plan: &EnforcementPlan) -> Result<(), AppError> {
            record(&self.ledger, "activate");
            self.result_for("activate")
        }

        fn cleanup_disabled_ipv6(&self, _plan: &EnforcementPlan) -> Vec<Notice> {
            record(&self.ledger, "cleanup-v6");
            vec![Notice::warning("cleanup notice")]
        }
    }

    impl FakeEnforcement {
        fn result_for(&self, stage: &'static str) -> Result<(), AppError> {
            if self.fail_at == Some(stage) {
                Err(AppError::Ipset {
                    source: Box::new(std::io::Error::other(format!("injected {stage} failure"))),
                })
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct RecordingObserver {
        stages: Mutex<Vec<&'static str>>,
        notices: Mutex<Vec<String>>,
        events: Mutex<Vec<SyncEvent>>,
        cancel_at: Option<&'static str>,
        cancelled: std::sync::atomic::AtomicBool,
    }

    impl crate::ports::Cancellation for RecordingObserver {
        fn is_cancelled(&self) -> bool {
            self.cancelled.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SyncObserver for RecordingObserver {
        fn stage_completed(&self, stage: &'static str) {
            if self.cancel_at == Some(stage) {
                self.cancelled
                    .store(true, std::sync::atomic::Ordering::SeqCst);
            }
            self.stages
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(stage);
        }

        fn notice(&self, notice: &Notice) {
            self.notices
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(notice.message.clone());
        }

        fn event(&self, event: SyncEvent) {
            self.events.lock().expect("events").push(event);
        }
    }

    fn registry(ledger: &Ledger, providers: Vec<FakeSource>) -> SyncSourceRegistry {
        let mut registry = SyncSourceRegistry::new();
        for provider in providers {
            assert!(Arc::ptr_eq(&provider.ledger, ledger));
            registry.register(provider).expect("unique provider");
        }
        registry
    }

    fn provider(
        ledger: &Ledger,
        id: &'static str,
        role: SourceRole,
        policy: FailurePolicy,
        networks: Vec<CanonicalCidr>,
    ) -> FakeSource {
        FakeSource {
            ledger: Arc::clone(ledger),
            descriptor: SyncSourceDescriptor {
                id,
                role,
                failure_policy: policy,
            },
            networks,
            fail: false,
        }
    }

    fn execute_with(
        ledger: &Ledger,
        config: Config,
        sources: &SyncSourceRegistry,
        enforcement: &FakeEnforcement,
        observer: &RecordingObserver,
    ) -> Result<super::SyncOutcome, AppError> {
        execute_with_temporary(
            ledger,
            config,
            sources,
            enforcement,
            observer,
            &TemporaryState::default(),
        )
    }

    #[test]
    fn progress_never_claims_a_failed_family_replacement_or_wiring_completed() {
        for (fail_at, expected_families, wiring) in [
            (Some("replace-v6"), Vec::new(), false),
            (Some("replace-v4"), vec![AddressFamily::Ipv6], false),
            (
                Some("activate"),
                vec![AddressFamily::Ipv6, AddressFamily::Ipv4],
                false,
            ),
            (None, vec![AddressFamily::Ipv6, AddressFamily::Ipv4], true),
        ] {
            let ledger = Ledger::default();
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at,
                replacements: Mutex::new(Vec::new()),
            };
            let observer = RecordingObserver::default();
            let result = execute_with(
                &ledger,
                config(true, 10),
                &SyncSourceRegistry::new(),
                &enforcement,
                &observer,
            );
            if fail_at.is_some() {
                assert!(matches!(result, Err(AppError::Ipset { .. })));
            } else {
                result.expect("sync");
            }
            let observations = observer.events.lock().expect("events");
            assert!(observations.contains(&SyncEvent::EnforcementStarted));
            let completed = observations
                .iter()
                .filter_map(|event| match event {
                    SyncEvent::FamilyReplaced(family) => Some(*family),
                    _ => None,
                })
                .collect::<Vec<_>>();
            assert_eq!(completed, expected_families);
            assert_eq!(observations.contains(&SyncEvent::WiringActivated), wiring);
            assert_eq!(
                observations.contains(&SyncEvent::StageCompleted(SyncStage::ActivateFirewall)),
                wiring
            );
            assert_eq!(events(&ledger).last().map(String::as_str), Some("unlock"));
        }
    }

    #[test]
    fn kernel_entry_counts_distinguish_zero_prefix_expansion_from_network_counts() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("0.0.0.0/0"), cidr("::/0")],
            )],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let outcome = execute_with(
            &ledger,
            config(true, 10),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect("sync");
        assert_eq!((outcome.ipv4_entries, outcome.ipv6_entries), (1, 1));
        assert_eq!(
            (outcome.ipv4_kernel_entries, outcome.ipv6_kernel_entries),
            (2, 2)
        );
    }

    #[derive(Default)]
    struct TemporaryState {
        state: Mutex<TemporaryBans>,
        cutoff: std::sync::atomic::AtomicU64,
        ledger: Option<Ledger>,
        fail_load: bool,
        fail_save: bool,
    }

    impl Clock for TemporaryState {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            if let Some(ledger) = &self.ledger {
                record(ledger, "clock");
            }
            Ok(self
                .cutoff
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst))
        }
    }

    impl TemporaryBanRepository for TemporaryState {
        fn load(&self, path: &Path) -> Result<TemporaryBans, AppError> {
            assert_eq!(path, test_paths().temporary_bans_file());
            if let Some(ledger) = &self.ledger {
                record(ledger, "load-temporary");
            }
            if self.fail_load {
                return Err(AppError::Source {
                    provider: "temporary-bans",
                    source: Box::new(std::io::Error::other("invalid temporary state")),
                });
            }
            Ok(self.state.lock().expect("temporary state").clone())
        }

        fn save(&self, path: &Path, state: &TemporaryBans) -> Result<(), AppError> {
            assert_eq!(path, test_paths().temporary_bans_file());
            if let Some(ledger) = &self.ledger {
                record(ledger, "save-temporary");
            }
            if self.fail_save {
                return Err(AppError::Source {
                    provider: "temporary-bans",
                    source: Box::new(std::io::Error::other("temporary write failure")),
                });
            }
            *self.state.lock().expect("temporary state") = state.clone();
            Ok(())
        }
    }

    struct TemporarySource;

    impl SyncSourceProvider for TemporarySource {
        fn descriptor(&self) -> SyncSourceDescriptor {
            SyncSourceDescriptor {
                id: "temporary-blocklist",
                role: SourceRole::Candidate,
                failure_policy: FailurePolicy::Required,
            }
        }

        fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
            Ok(SyncSourceLoad::ready(SyncSourceBatch {
                networks: context.temporary_bans.active_ips(context.cutoff),
                notices: Vec::new(),
            }))
        }
    }

    fn execute_with_temporary(
        ledger: &Ledger,
        config: Config,
        sources: &SyncSourceRegistry,
        enforcement: &FakeEnforcement,
        observer: &RecordingObserver,
        temporary: &TemporaryState,
    ) -> Result<super::SyncOutcome, AppError> {
        let paths = FakePaths {
            ledger: Arc::clone(ledger),
            paths: test_paths(),
        };
        let configs = FakeConfigs {
            ledger: Arc::clone(ledger),
            config,
        };
        let locks = FakeLocks(Arc::clone(ledger));
        execute(
            &request(),
            &SyncDependencies {
                cancellation: observer,
                paths: &paths,
                configs: &configs,
                locks: &locks,
                clock: temporary,
                temporary_bans: temporary,
                sources,
                enforcement,
                observer,
            },
        )
    }

    struct ConfigChangingAtLock {
        ledger: Ledger,
        contents: Mutex<String>,
        replacement: String,
    }

    impl ConfigRepository for ConfigChangingAtLock {
        fn load(&self, _path: &Path) -> Result<Config, AppError> {
            record(&self.ledger, "config");
            Config::from_toml_str(&self.contents.lock().expect("config contents"))
                .map_err(AppError::from)
        }
    }

    impl LockManager for ConfigChangingAtLock {
        fn acquire(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            *self.contents.lock().expect("config contents") = self.replacement.clone();
            record(&self.ledger, "publish-config");
            FakeLocks(Arc::clone(&self.ledger)).acquire(path)
        }
    }

    impl ConfigChangingAtLock {
        fn execute(
            &self,
            sources: &SyncSourceRegistry,
            enforcement: &FakeEnforcement,
        ) -> Result<super::SyncOutcome, AppError> {
            let observer = RecordingObserver::default();
            let temporary = TemporaryState {
                ledger: Some(Arc::clone(&self.ledger)),
                ..TemporaryState::default()
            };
            execute(
                &request(),
                &SyncDependencies {
                    cancellation: &observer,
                    paths: &FakePaths {
                        ledger: Arc::clone(&self.ledger),
                        paths: test_paths(),
                    },
                    configs: self,
                    locks: self,
                    clock: &temporary,
                    temporary_bans: &temporary,
                    sources,
                    enforcement,
                    observer: &observer,
                },
            )
        }
    }

    #[test]
    fn config_revision_published_before_lock_controls_enforcement() {
        struct ConfigSafelist;

        impl SyncSourceProvider for ConfigSafelist {
            fn descriptor(&self) -> SyncSourceDescriptor {
                SyncSourceDescriptor {
                    id: "config-safelist",
                    role: SourceRole::Safelist,
                    failure_policy: FailurePolicy::Required,
                }
            }

            fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
                Ok(SyncSourceLoad::ready(SyncSourceBatch {
                    networks: context.config.safe.ips.clone(),
                    notices: Vec::new(),
                }))
            }
        }

        let ledger = Ledger::default();
        let original = "[ipset]\nset_name='kidobo'\nenable_ipv6=false\n";
        let config = ConfigChangingAtLock {
            ledger: Arc::clone(&ledger),
            contents: Mutex::new(original.to_string()),
            replacement: format!("{original}[safe]\nips=['203.0.113.7']\n"),
        };
        let mut sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "local",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("203.0.113.7"), cidr("198.51.100.9")],
            )],
        );
        sources.register(ConfigSafelist).expect("safelist source");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };

        config.execute(&sources, &enforcement).expect("sync");

        assert_eq!(
            *enforcement.replacements.lock().expect("replacements"),
            [(AddressFamily::Ipv4, vec![cidr("198.51.100.9")])]
        );
        assert_eq!(events(&ledger).last().map(String::as_str), Some("unlock"));
    }

    #[test]
    fn invalid_config_revision_stops_before_source_cache_or_firewall_work() {
        for initially_valid in [false, true] {
            let ledger = Ledger::default();
            let config = ConfigChangingAtLock {
                ledger: Arc::clone(&ledger),
                contents: Mutex::new(if initially_valid {
                    "[ipset]\nset_name='kidobo'\n".to_string()
                } else {
                    "invalid TOML".to_string()
                }),
                replacement: "invalid TOML".to_string(),
            };
            let mut sources = SyncSourceRegistry::new();
            sources
                .register(DeferredSource {
                    ledger: Arc::clone(&ledger),
                    descriptor: SyncSourceDescriptor {
                        id: "remote",
                        role: SourceRole::Candidate,
                        failure_policy: FailurePolicy::Required,
                    },
                    primary: vec![cidr("203.0.113.7")],
                    fallback: None,
                    fail_promotion: false,
                })
                .expect("remote source");
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };

            let error = config
                .execute(&sources, &enforcement)
                .expect_err("invalid configuration must stop sync");

            assert!(matches!(error, AppError::ConfigParse { .. }));
            let expected = if initially_valid {
                vec![
                    "paths",
                    "config",
                    "publish-config",
                    "lock",
                    "clock",
                    "config",
                    "unlock",
                ]
            } else {
                vec!["paths", "config"]
            };
            assert_eq!(events(&ledger), expected);
            assert!(
                enforcement
                    .replacements
                    .lock()
                    .expect("replacements")
                    .is_empty()
            );
        }
    }

    #[test]
    fn temporary_bans_expire_at_one_cutoff_without_renewal_and_preserve_other_sources() {
        let ledger = Ledger::default();
        let temporary = TemporaryState {
            state: Mutex::new(TemporaryBans {
                ips: [(cidr("198.51.100.0/24"), 100), (cidr("2001:db8::/64"), 101)].into(),
                asns: [(64512, 100)].into(),
            }),
            cutoff: std::sync::atomic::AtomicU64::new(99),
            ledger: Some(Arc::clone(&ledger)),
            ..TemporaryState::default()
        };
        let mut sources = registry(
            &ledger,
            vec![
                provider(
                    &ledger,
                    "permanent",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    vec![cidr("198.51.100.0/25")],
                ),
                provider(
                    &ledger,
                    "safe",
                    SourceRole::Safelist,
                    FailurePolicy::Required,
                    vec![cidr("198.51.100.64/26")],
                ),
            ],
        );
        sources.register(TemporarySource).expect("temporary source");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let observer = RecordingObserver::default();

        for (cutoff, expected_v4, expected_v6) in [
            (
                99,
                vec![cidr("198.51.100.0/26"), cidr("198.51.100.128/25")],
                vec![cidr("2001:db8::/64")],
            ),
            (
                100,
                vec![cidr("198.51.100.0/26")],
                vec![cidr("2001:db8::/64")],
            ),
            (101, vec![cidr("198.51.100.0/26")], Vec::new()),
        ] {
            ledger.lock().expect("ledger").clear();
            enforcement
                .replacements
                .lock()
                .expect("replacements")
                .clear();
            let outcome = execute_with_temporary(
                &ledger,
                config(true, 100),
                &sources,
                &enforcement,
                &observer,
                &temporary,
            )
            .expect("sync");
            assert_eq!(
                (outcome.ipv4_entries, outcome.ipv6_entries),
                (expected_v4.len(), expected_v6.len())
            );
            assert_eq!(
                *enforcement.replacements.lock().expect("replacements"),
                [
                    (AddressFamily::Ipv6, expected_v6),
                    (AddressFamily::Ipv4, expected_v4)
                ]
            );
            assert_temporary_snapshot_order(&ledger, cutoff != 99);
            let state = temporary.state.lock().expect("temporary state");
            assert_eq!(
                state.ips.get(&cidr("2001:db8::/64")),
                (cutoff < 101).then_some(&101)
            );
            assert_eq!(state.asns.get(&64512), (cutoff < 100).then_some(&100));
        }
    }

    fn assert_temporary_snapshot_order(ledger: &Ledger, pruned: bool) {
        let actual = events(ledger);
        assert_eq!(
            &actual[..7],
            [
                "paths",
                "config",
                "lock",
                "clock",
                "config",
                "load-temporary",
                "ensure"
            ]
        );
        assert_eq!(actual.iter().filter(|event| *event == "clock").count(), 1);
        assert_eq!(
            actual
                .iter()
                .filter(|event| *event == "load-temporary")
                .count(),
            1
        );
        if pruned {
            assert_eq!(
                &actual[actual.len() - 3..],
                ["activate", "save-temporary", "unlock"]
            );
        } else {
            assert!(!actual.iter().any(|event| event == "save-temporary"));
        }
    }

    #[test]
    fn temporary_state_failure_stops_sync_before_artifact_mutation() {
        let ledger = Ledger::default();
        let temporary = TemporaryState {
            fail_load: true,
            ledger: Some(Arc::clone(&ledger)),
            ..TemporaryState::default()
        };
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let error = execute_with_temporary(
            &ledger,
            config(true, 100),
            &SyncSourceRegistry::new(),
            &enforcement,
            &RecordingObserver::default(),
            &temporary,
        )
        .expect_err("invalid state");
        assert!(error.to_string().contains("invalid temporary state"));
        assert_eq!(
            events(&ledger),
            [
                "paths",
                "config",
                "lock",
                "clock",
                "config",
                "load-temporary",
                "unlock"
            ]
        );
    }

    #[test]
    fn failed_enforcement_never_prunes_and_cleanup_failure_is_soft() {
        for fail_at in [Some("replace-v4"), Some("activate"), None] {
            let ledger = Ledger::default();
            let temporary = TemporaryState {
                state: Mutex::new(TemporaryBans {
                    ips: [(cidr("198.51.100.0/24"), 100)].into(),
                    asns: [(64512, 100)].into(),
                }),
                cutoff: std::sync::atomic::AtomicU64::new(100),
                ledger: Some(Arc::clone(&ledger)),
                fail_save: true,
                ..TemporaryState::default()
            };
            let mut sources = SyncSourceRegistry::new();
            sources.register(TemporarySource).expect("temporary source");
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at,
                replacements: Mutex::new(Vec::new()),
            };
            let observer = RecordingObserver::default();
            let result = execute_with_temporary(
                &ledger,
                config(true, 100),
                &sources,
                &enforcement,
                &observer,
                &temporary,
            );
            let actual = events(&ledger);
            if fail_at.is_some() {
                assert!(result.is_err());
                assert!(!actual.iter().any(|event| event == "save-temporary"));
            } else {
                assert_eq!(result.expect("cleanup is soft").ipv4_entries, 0);
                assert_eq!(
                    &actual[actual.len() - 3..],
                    ["activate", "save-temporary", "unlock"]
                );
                assert!(
                    observer
                        .notices
                        .lock()
                        .expect("notices")
                        .iter()
                        .any(|notice| notice.contains("expired temporary ban cleanup failed"))
                );
            }
            assert_eq!(
                temporary.state.lock().expect("unchanged state").ips[&cidr("198.51.100.0/24")],
                100
            );
            assert!(
                enforcement
                    .replacements
                    .lock()
                    .expect("replacements")
                    .iter()
                    .all(|(_, entries)| entries.is_empty())
            );
        }
    }

    #[test]
    fn temporary_candidates_are_subject_to_both_family_capacity_checks() {
        let ledger = Ledger::default();
        let temporary = TemporaryState {
            state: Mutex::new(TemporaryBans {
                ips: [
                    (cidr("192.0.2.0/24"), 100),
                    (cidr("198.51.100.0/24"), 100),
                    (cidr("2001:db8::/64"), 100),
                ]
                .into(),
                asns: std::collections::BTreeMap::default(),
            }),
            ..TemporaryState::default()
        };
        let mut sources = SyncSourceRegistry::new();
        sources.register(TemporarySource).expect("temporary source");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let error = execute_with_temporary(
            &ledger,
            config(true, 1),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
            &temporary,
        )
        .expect_err("capacity");
        assert!(matches!(
            error,
            AppError::IpsetCapacityExceeded {
                family: "ipv4",
                entries: 2,
                ..
            }
        ));
        assert!(
            enforcement
                .replacements
                .lock()
                .expect("replacements")
                .is_empty()
        );
    }

    #[test]
    fn nonzero_kernel_timeout_warns_for_active_temporary_ip_or_asn_bans_only() {
        for (ip_expiry, asn_expiry, timeout, warns) in [
            (101, 100, 30, true),
            (100, 101, 30, true),
            (100, 100, 30, false),
            (101, 101, 0, false),
        ] {
            let ledger = Ledger::default();
            let temporary = TemporaryState {
                state: Mutex::new(TemporaryBans {
                    ips: [(cidr("198.51.100.0/24"), ip_expiry)].into(),
                    asns: [(64512, asn_expiry)].into(),
                }),
                cutoff: std::sync::atomic::AtomicU64::new(100),
                ..TemporaryState::default()
            };
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };
            let observer = RecordingObserver::default();
            let mut config = config(true, 100);
            config.ipset.timeout = timeout;
            execute_with_temporary(
                &ledger,
                config,
                &SyncSourceRegistry::new(),
                &enforcement,
                &observer,
                &temporary,
            )
            .expect("sync");
            assert_eq!(
                observer
                    .notices
                    .lock()
                    .expect("notices")
                    .iter()
                    .any(|notice| notice.contains("kernel entries can expire independently")),
                warns
            );
        }
    }

    #[test]
    fn cancellation_stops_before_replacement_but_finishes_started_enforcement() {
        for (stage, finishes) in [
            ("load_sources", false),
            ("compute_effective_blocklists", false),
            ("promote_source_caches", false),
            ("apply_ipv6_ipset", true),
        ] {
            let ledger = Ledger::default();
            let sources = registry(
                &ledger,
                vec![provider(
                    &ledger,
                    "local",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    vec![cidr("203.0.113.0/24"), cidr("2001:db8::/64")],
                )],
            );
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };
            let observer = RecordingObserver {
                cancel_at: Some(stage),
                ..RecordingObserver::default()
            };
            let result = execute_with(
                &ledger,
                config(true, 100),
                &sources,
                &enforcement,
                &observer,
            );
            let replacements = enforcement.replacements.lock().expect("replacements");
            if finishes {
                let outcome = result.expect("finish enforcement");
                assert_eq!((outcome.ipv4_entries, outcome.ipv6_entries), (1, 1));
                assert_eq!(
                    replacements
                        .iter()
                        .map(|(family, _)| *family)
                        .collect::<Vec<_>>(),
                    [AddressFamily::Ipv6, AddressFamily::Ipv4]
                );
                assert!(
                    ledger
                        .lock()
                        .expect("ledger")
                        .iter()
                        .any(|event| event == "activate")
                );
            } else {
                assert!(matches!(result, Err(AppError::Interrupted)));
                assert_eq!(replacements.len(), 0);
                assert!(
                    !ledger
                        .lock()
                        .expect("ledger")
                        .iter()
                        .any(|event| event == "activate")
                );
            }
            assert_eq!(
                ledger.lock().expect("ledger").last().map(String::as_str),
                Some("unlock")
            );
        }
    }

    #[test]
    fn staging_failure_requires_a_usable_fallback_even_for_best_effort_sources() {
        struct FailedRefresh(Option<Vec<CanonicalCidr>>);
        impl SyncSourceProvider for FailedRefresh {
            fn descriptor(&self) -> SyncSourceDescriptor {
                SyncSourceDescriptor {
                    id: "external",
                    role: SourceRole::ExternalSafelist,
                    failure_policy: FailurePolicy::BestEffort,
                }
            }
            fn load(&self, _: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
                let failure = AppError::CacheStaging {
                    provider: "external",
                    source: Box::new(std::io::Error::other("injected disk failure")),
                };
                let Some(networks) = &self.0 else {
                    return Err(failure);
                };
                Ok(SyncSourceLoad {
                    primary: SyncSourceBatch {
                        networks: networks.clone(),
                        notices: Vec::new(),
                    },
                    fallback_failure: Some(failure),
                    ..SyncSourceLoad::default()
                })
            }
        }
        for (fallback, succeeds) in [
            (None, false),
            (Some(vec![cidr("192.0.2.0/24")]), false),
            (Some(Vec::new()), true),
            (Some(vec![cidr("192.0.2.0/25")]), true),
        ] {
            let ledger = Ledger::default();
            let mut sources = registry(
                &ledger,
                vec![provider(
                    &ledger,
                    "local",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    vec![cidr("192.0.2.0/24")],
                )],
            );
            sources.register(FailedRefresh(fallback)).expect("source");
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };
            let result = execute_with(
                &ledger,
                config(false, 10),
                &sources,
                &enforcement,
                &RecordingObserver::default(),
            );
            if succeeds {
                assert_eq!(result.expect("fallback").ipv4_entries, 1);
            } else {
                assert!(matches!(result, Err(AppError::CacheStaging { .. })));
                assert_eq!(
                    enforcement.replacements.lock().expect("replacements").len(),
                    0
                );
                assert!(!events(&ledger).iter().any(|event| event == "activate"));
            }
        }
    }

    #[test]
    fn preserves_required_sync_order_and_family_separation() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![
                provider(
                    &ledger,
                    "candidate",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    vec![cidr("198.51.100.0/24"), cidr("2001:db8::/64")],
                ),
                provider(
                    &ledger,
                    "safelist",
                    SourceRole::Safelist,
                    FailurePolicy::Required,
                    vec![cidr("198.51.100.128/25")],
                ),
            ],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let observer = RecordingObserver::default();

        let outcome = execute_with(
            &ledger,
            config(true, 100),
            &sources,
            &enforcement,
            &observer,
        )
        .expect("sync");

        assert_eq!(outcome.ipv4_entries, 1);
        assert_eq!(outcome.ipv6_entries, 1);
        let replacements = enforcement.replacements.lock().expect("replacements");
        assert_eq!(
            replacements[0],
            (AddressFamily::Ipv6, vec![cidr("2001:db8::/64")])
        );
        assert_eq!(
            replacements[1],
            (AddressFamily::Ipv4, vec![cidr("198.51.100.0/25")])
        );
        drop(replacements);
        assert_eq!(
            events(&ledger),
            [
                "paths",
                "config",
                "lock",
                "config",
                "ensure",
                "source:candidate",
                "source:safelist",
                "replace-v6",
                "replace-v4",
                "activate",
                "unlock",
            ]
        );
    }

    #[test]
    fn validates_ipv4_capacity_before_replacing_ipv6() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![
                    cidr("192.0.2.0/24"),
                    cidr("198.51.100.0/24"),
                    cidr("2001:db8::/64"),
                ],
            )],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let error = execute_with(
            &ledger,
            config(true, 1),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("capacity must fail");

        assert!(matches!(
            error,
            AppError::IpsetCapacityExceeded { family: "ipv4", .. }
        ));
        assert!(
            !events(&ledger)
                .iter()
                .any(|event| event.starts_with("replace"))
        );
    }

    #[test]
    fn required_source_failure_prevents_all_later_side_effects() {
        let ledger = Ledger::default();
        let mut failing = provider(
            &ledger,
            "required",
            SourceRole::Candidate,
            FailurePolicy::Required,
            Vec::new(),
        );
        failing.fail = true;
        let sources = registry(&ledger, vec![failing]);
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };

        execute_with(
            &ledger,
            config(true, 100),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("required source must fail");

        assert_eq!(
            events(&ledger),
            [
                "paths",
                "config",
                "lock",
                "config",
                "ensure",
                "source:required",
                "unlock"
            ]
        );
    }

    #[test]
    fn best_effort_source_failure_is_reported_and_sync_continues() {
        let ledger = Ledger::default();
        let mut failing = provider(
            &ledger,
            "optional",
            SourceRole::Candidate,
            FailurePolicy::BestEffort,
            Vec::new(),
        );
        failing.fail = true;
        let sources = registry(&ledger, vec![failing]);
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let observer = RecordingObserver::default();

        let outcome = execute_with(
            &ledger,
            config(false, 100),
            &sources,
            &enforcement,
            &observer,
        )
        .expect("soft failure");

        assert!(!outcome.sources[0].loaded);
        assert!(
            observer
                .notices
                .lock()
                .expect("notices")
                .iter()
                .any(|notice| notice.contains("failed softly"))
        );
        assert!(events(&ledger).contains(&"activate".to_string()));
        assert!(events(&ledger).contains(&"cleanup-v6".to_string()));
    }

    #[test]
    fn failed_ipv6_replace_prevents_ipv4_and_firewall_mutation() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("192.0.2.0/24"), cidr("2001:db8::/64")],
            )],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: Some("replace-v6"),
            replacements: Mutex::new(Vec::new()),
        };

        execute_with(
            &ledger,
            config(true, 100),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("replace must fail");

        let events = events(&ledger);
        assert!(events.contains(&"replace-v6".to_string()));
        assert!(!events.contains(&"replace-v4".to_string()));
        assert!(!events.contains(&"activate".to_string()));
    }

    #[test]
    fn validates_ipv6_capacity_before_any_replacement() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![
                    cidr("192.0.2.0/24"),
                    cidr("2001:db8::/64"),
                    cidr("2001:db8:1::/64"),
                ],
            )],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let error = execute_with(
            &ledger,
            config(true, 1),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("capacity must fail");

        assert!(matches!(
            error,
            AppError::IpsetCapacityExceeded { family: "ipv6", .. }
        ));
        assert!(
            !events(&ledger)
                .iter()
                .any(|event| event.starts_with("replace"))
        );
    }

    #[test]
    fn full_family_safelists_are_carved_before_enforcement_preparation() {
        for erase in [false, true] {
            let ledger = Ledger::default();
            let sources = registry(
                &ledger,
                vec![
                    provider(
                        &ledger,
                        "candidate",
                        SourceRole::Candidate,
                        FailurePolicy::Required,
                        vec![cidr("0.0.0.0/0"), cidr("::/0")],
                    ),
                    provider(
                        &ledger,
                        "safe",
                        SourceRole::Safelist,
                        FailurePolicy::Required,
                        if erase {
                            vec![cidr("0.0.0.0/0"), cidr("::/0")]
                        } else {
                            vec![cidr("128.0.0.0/1"), cidr("8000::/1")]
                        },
                    ),
                ],
            );
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };
            let outcome = execute_with(
                &ledger,
                config(true, 1),
                &sources,
                &enforcement,
                &RecordingObserver::default(),
            )
            .expect("carved sets fit");
            assert_eq!(
                (outcome.ipv4_entries, outcome.ipv6_entries),
                if erase { (0, 0) } else { (1, 1) }
            );
            assert_eq!(
                *enforcement.replacements.lock().expect("replacements"),
                vec![
                    (
                        AddressFamily::Ipv6,
                        if erase { vec![] } else { vec![cidr("::/1")] }
                    ),
                    (
                        AddressFamily::Ipv4,
                        if erase {
                            vec![]
                        } else {
                            vec![cidr("0.0.0.0/1")]
                        }
                    ),
                ]
            );
        }
    }

    #[test]
    fn full_family_networks_expand_only_for_enforcement() {
        for enable_ipv6 in [false, true] {
            let ledger = Ledger::default();
            let sources = registry(
                &ledger,
                vec![provider(
                    &ledger,
                    "candidate",
                    SourceRole::Candidate,
                    FailurePolicy::Required,
                    vec![
                        cidr("0.0.0.0/1"),
                        cidr("128.0.0.0/1"),
                        cidr("::/1"),
                        cidr("8000::/1"),
                    ],
                )],
            );
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };
            let outcome = execute_with(
                &ledger,
                config(enable_ipv6, 2),
                &sources,
                &enforcement,
                &RecordingObserver::default(),
            )
            .expect("expanded sets fit");
            assert_eq!(
                (outcome.ipv4_entries, outcome.ipv6_entries),
                (1, usize::from(enable_ipv6))
            );
            let mut expected = Vec::new();
            if enable_ipv6 {
                expected.push((AddressFamily::Ipv6, vec![cidr("::/1"), cidr("8000::/1")]));
            }
            expected.push((
                AddressFamily::Ipv4,
                vec![cidr("0.0.0.0/1"), cidr("128.0.0.0/1")],
            ));
            assert_eq!(
                *enforcement.replacements.lock().expect("replacements"),
                expected
            );
        }
    }

    #[test]
    fn expanded_capacity_rejection_precedes_promotion_and_both_replacements() {
        for (family, networks) in [
            (
                "ipv4",
                vec![
                    cidr("0.0.0.0/1"),
                    cidr("128.0.0.0/1"),
                    cidr("2001:db8::/64"),
                ],
            ),
            (
                "ipv6",
                vec![cidr("192.0.2.0/24"), cidr("::/1"), cidr("8000::/1")],
            ),
        ] {
            let ledger = Ledger::default();
            let mut sources = SyncSourceRegistry::new();
            sources
                .register(DeferredSource {
                    ledger: Arc::clone(&ledger),
                    descriptor: SyncSourceDescriptor {
                        id: "deferred",
                        role: SourceRole::Candidate,
                        failure_policy: FailurePolicy::Required,
                    },
                    primary: networks,
                    fallback: None,
                    fail_promotion: false,
                })
                .expect("source");
            let enforcement = FakeEnforcement {
                ledger: Arc::clone(&ledger),
                fail_at: None,
                replacements: Mutex::new(Vec::new()),
            };
            let error = execute_with(
                &ledger,
                config(true, 1),
                &sources,
                &enforcement,
                &RecordingObserver::default(),
            )
            .expect_err("expanded capacity");
            assert!(matches!(error, AppError::IpsetCapacityExceeded {
                family: actual, entries: 2, maxelem: 1, ..
            } if actual == family));
            assert!(!events(&ledger).iter().any(|event| event == "promote"
                || event.starts_with("replace")
                || event == "activate"));
            assert_eq!(
                enforcement.replacements.lock().expect("replacements").len(),
                0
            );
        }
    }

    #[test]
    fn capacity_equal_to_limit_is_allowed_for_both_families() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("192.0.2.0/24"), cidr("2001:db8::/64")],
            )],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let outcome = execute_with(
            &ledger,
            config(true, 1),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect("equal capacity");
        assert_eq!((outcome.ipv4_entries, outcome.ipv6_entries), (1, 1));
    }

    #[test]
    fn failed_ipv4_replace_after_ipv6_still_prevents_activation() {
        let ledger = Ledger::default();
        let sources = registry(
            &ledger,
            vec![provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("192.0.2.0/24"), cidr("2001:db8::/64")],
            )],
        );
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: Some("replace-v4"),
            replacements: Mutex::new(Vec::new()),
        };
        execute_with(
            &ledger,
            config(true, 100),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("replace must fail");
        let events = events(&ledger);
        assert!(events.contains(&"replace-v6".to_string()));
        assert!(events.contains(&"replace-v4".to_string()));
        assert!(!events.contains(&"activate".to_string()));
    }

    #[test]
    fn capacity_rejection_drops_staged_cache_before_enforcement() {
        let ledger = Ledger::default();
        let mut sources = SyncSourceRegistry::new();
        sources
            .register(DeferredSource {
                ledger: Arc::clone(&ledger),
                descriptor: SyncSourceDescriptor {
                    id: "deferred-candidate",
                    role: SourceRole::Candidate,
                    failure_policy: FailurePolicy::Required,
                },
                primary: vec![cidr("192.0.2.0/24"), cidr("198.51.100.0/24")],
                fallback: None,
                fail_promotion: false,
            })
            .expect("register source");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };

        let error = execute_with(
            &ledger,
            config(false, 1),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("capacity must reject the staged source");

        assert!(matches!(error, AppError::IpsetCapacityExceeded { .. }));
        assert!(!events(&ledger).iter().any(|event| event == "promote"));
        assert_eq!(
            enforcement.replacements.lock().expect("replacements").len(),
            0
        );
    }

    #[test]
    fn cache_promotion_failure_precedes_both_family_replacements() {
        let ledger = Ledger::default();
        let mut sources = SyncSourceRegistry::new();
        sources
            .register(DeferredSource {
                ledger: Arc::clone(&ledger),
                descriptor: SyncSourceDescriptor {
                    id: "deferred-candidate",
                    role: SourceRole::Candidate,
                    failure_policy: FailurePolicy::Required,
                },
                primary: vec![cidr("192.0.2.0/24"), cidr("2001:db8::/64")],
                fallback: None,
                fail_promotion: true,
            })
            .expect("register source");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };

        let error = execute_with(
            &ledger,
            config(true, 10),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect_err("promotion must fail");

        assert!(matches!(error, AppError::CachePromotion { .. }));
        assert!(events(&ledger).iter().any(|event| event == "promote"));
        assert_eq!(
            enforcement.replacements.lock().expect("replacements").len(),
            0
        );
    }

    #[test]
    fn external_safelist_uses_admissible_fallback_when_primary_empties_family() {
        let ledger = Ledger::default();
        let mut sources = SyncSourceRegistry::new();
        sources
            .register(provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("192.0.2.0/24")],
            ))
            .expect("register candidate");
        sources
            .register(DeferredSource {
                ledger: Arc::clone(&ledger),
                descriptor: SyncSourceDescriptor {
                    id: "external",
                    role: SourceRole::ExternalSafelist,
                    failure_policy: FailurePolicy::BestEffort,
                },
                primary: vec![cidr("192.0.2.0/24")],
                fallback: Some(vec![cidr("192.0.2.0/25")]),
                fail_promotion: false,
            })
            .expect("register external safelist");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };
        let observer = RecordingObserver::default();

        let outcome = execute_with(
            &ledger,
            config(false, 10),
            &sources,
            &enforcement,
            &observer,
        )
        .expect("fallback should be admitted");

        assert_eq!(outcome.ipv4_entries, 1);
        assert_eq!(outcome.sources[1].entries, 1);
        assert_eq!(
            enforcement
                .replacements
                .lock()
                .expect("replacements")
                .as_slice(),
            &[(AddressFamily::Ipv4, vec![cidr("192.0.2.128/25")])]
        );
        assert!(!events(&ledger).iter().any(|event| event == "promote"));
        assert!(
            observer
                .notices
                .lock()
                .expect("notices")
                .iter()
                .any(|notice| notice.contains("would empty"))
        );
    }

    #[test]
    fn admitted_external_safelist_promotes_before_replacement() {
        let ledger = Ledger::default();
        let mut sources = SyncSourceRegistry::new();
        sources
            .register(provider(
                &ledger,
                "candidate",
                SourceRole::Candidate,
                FailurePolicy::Required,
                vec![cidr("192.0.2.0/24")],
            ))
            .expect("register candidate");
        sources
            .register(DeferredSource {
                ledger: Arc::clone(&ledger),
                descriptor: SyncSourceDescriptor {
                    id: "external",
                    role: SourceRole::ExternalSafelist,
                    failure_policy: FailurePolicy::BestEffort,
                },
                primary: vec![cidr("192.0.2.0/25")],
                fallback: None,
                fail_promotion: false,
            })
            .expect("register external safelist");
        let enforcement = FakeEnforcement {
            ledger: Arc::clone(&ledger),
            fail_at: None,
            replacements: Mutex::new(Vec::new()),
        };

        execute_with(
            &ledger,
            config(false, 10),
            &sources,
            &enforcement,
            &RecordingObserver::default(),
        )
        .expect("sync");

        assert_eq!(
            enforcement
                .replacements
                .lock()
                .expect("replacements")
                .as_slice(),
            &[(AddressFamily::Ipv4, vec![cidr("192.0.2.128/25")])]
        );
        let ledger = events(&ledger);
        let promotion = ledger
            .iter()
            .position(|event| event == "promote")
            .expect("promotion");
        let replacement = ledger
            .iter()
            .position(|event| event == "replace-v4")
            .expect("replacement");
        assert!(promotion < replacement);
    }

    #[test]
    #[expect(
        clippy::too_many_lines,
        reason = "compare complete normal and preview workflows across shared admission decisions"
    )]
    fn preview_and_normal_sync_use_identical_effective_kernel_entries() {
        #[derive(Clone)]
        struct ParitySource {
            descriptor: SyncSourceDescriptor,
            primary: Vec<CanonicalCidr>,
            fallback: Option<Vec<CanonicalCidr>>,
            ledger: Ledger,
        }
        impl ParitySource {
            fn data(&self) -> crate::preview::PreviewSourceLoad {
                record(&self.ledger, format!("source:{}", self.descriptor.id));
                crate::preview::PreviewSourceLoad {
                    primary: SyncSourceBatch {
                        networks: self.primary.clone(),
                        notices: Vec::new(),
                    },
                    fallback: self.fallback.as_ref().map(|networks| SyncSourceBatch {
                        networks: networks.clone(),
                        notices: Vec::new(),
                    }),
                    observations: Vec::new(),
                }
            }
        }
        impl SyncSourceProvider for ParitySource {
            fn descriptor(&self) -> SyncSourceDescriptor {
                self.descriptor
            }
            fn load(&self, _: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
                let data = self.data();
                Ok(SyncSourceLoad {
                    primary: data.primary,
                    fallback: data.fallback,
                    observations: data.observations,
                    pending_promotions: if self.descriptor.role == SourceRole::ExternalSafelist {
                        vec![Box::new(RecordingPromotion {
                            ledger: Arc::clone(&self.ledger),
                            fail: false,
                        })]
                    } else {
                        Vec::new()
                    },
                    fallback_failure: None,
                })
            }
        }
        impl crate::preview::PreviewSourceProvider for ParitySource {
            fn descriptor(&self) -> SyncSourceDescriptor {
                self.descriptor
            }
            fn load(
                &self,
                _: &crate::preview::PreviewSourceContext<'_>,
            ) -> Result<crate::preview::PreviewSourceLoad, AppError> {
                Ok(self.data())
            }
        }
        struct ReadLock(FakeLocks);
        impl crate::preview::SharedLockManager for ReadLock {
            fn acquire_existing(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
                self.0.acquire(path)
            }
        }
        struct ReadTemporary(TemporaryState);
        impl crate::preview::TemporaryBanReader for ReadTemporary {
            fn load(&self, path: &Path) -> Result<TemporaryBans, AppError> {
                self.0.load(path)
            }
        }

        for enable_ipv6 in [false, true] {
            for (primary, fallback) in [
                (vec![cidr("192.0.2.0/25")], None),
                (vec![cidr("192.0.2.0/24")], Some(vec![cidr("192.0.2.0/25")])),
                (vec![cidr("192.0.2.0/24")], Some(vec![cidr("192.0.2.0/24")])),
                (vec![cidr("2001:db8::/64")], Some(Vec::new())),
            ] {
                let ledger = Ledger::default();
                let sources = [
                    ParitySource {
                        descriptor: SyncSourceDescriptor {
                            id: "local",
                            role: SourceRole::Candidate,
                            failure_policy: FailurePolicy::Required,
                        },
                        primary: vec![cidr("192.0.2.0/24"), cidr("2001:db8::/64")],
                        fallback: None,
                        ledger: Arc::clone(&ledger),
                    },
                    ParitySource {
                        descriptor: SyncSourceDescriptor {
                            id: "safe",
                            role: SourceRole::Safelist,
                            failure_policy: FailurePolicy::Required,
                        },
                        primary: vec![cidr("192.0.2.0/26"), cidr("2001:db8::/66")],
                        fallback: None,
                        ledger: Arc::clone(&ledger),
                    },
                    ParitySource {
                        descriptor: SyncSourceDescriptor {
                            id: "external",
                            role: SourceRole::ExternalSafelist,
                            failure_policy: FailurePolicy::BestEffort,
                        },
                        primary,
                        fallback,
                        ledger: Arc::clone(&ledger),
                    },
                ];
                let mut normal_sources = SyncSourceRegistry::new();
                let mut preview_sources = crate::preview::PreviewSourceRegistry::new();
                for source in sources {
                    normal_sources
                        .register(source.clone())
                        .expect("normal source");
                    preview_sources.register(source).expect("preview source");
                }
                let config = config(enable_ipv6, 100);
                let enforcement = FakeEnforcement {
                    ledger: Arc::clone(&ledger),
                    fail_at: None,
                    replacements: Mutex::new(Vec::new()),
                };
                let normal = execute_with(
                    &ledger,
                    config.clone(),
                    &normal_sources,
                    &enforcement,
                    &RecordingObserver::default(),
                )
                .expect("normal sync");
                ledger.lock().expect("ledger").clear();
                let temporary = ReadTemporary(TemporaryState::default());
                let preview = crate::preview::execute(
                    &crate::preview::PreviewRequest {
                        paths: request(),
                        allow_network: false,
                    },
                    &crate::preview::PreviewDependencies {
                        cancellation: &crate::ports::NoCancellation,
                        paths: &FakePaths {
                            ledger: Arc::clone(&ledger),
                            paths: test_paths(),
                        },
                        configs: &FakeConfigs {
                            ledger: Arc::clone(&ledger),
                            config,
                        },
                        locks: &ReadLock(FakeLocks(Arc::clone(&ledger))),
                        clock: &temporary.0,
                        temporary_bans: &temporary,
                        sources: &preview_sources,
                    },
                )
                .expect("preview");
                assert_eq!(
                    (normal.ipv4_entries, normal.ipv6_entries),
                    (preview.entries.ipv4_networks, preview.entries.ipv6_networks)
                );
                assert_eq!(normal.sources, preview.sources);
                let mut expected = Vec::new();
                if enable_ipv6 {
                    expected.push((AddressFamily::Ipv6, preview.entries.ipv6));
                }
                expected.push((AddressFamily::Ipv4, preview.entries.ipv4));
                assert_eq!(
                    *enforcement
                        .replacements
                        .lock()
                        .expect("normal kernel entries"),
                    expected
                );
                assert_eq!(
                    events(&ledger),
                    [
                        "paths",
                        "lock",
                        "config",
                        "source:local",
                        "source:safe",
                        "source:external",
                        "unlock"
                    ]
                );
            }
        }
    }
}
