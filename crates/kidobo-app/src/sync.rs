//! Ordered, fail-closed synchronization workflow and its enforcement port.

use kidobo_core::AddressFamily;
use kidobo_core::config::{Config, FirewallAction};
use kidobo_core::network::CanonicalCidr;
use kidobo_core::sync::compute_effective_blocklists;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::source::{FailurePolicy, Notice, SourceRole, SyncSourceContext, SyncSourceRegistry};
use crate::source::{PendingCachePromotion, SyncSourceBatch, SyncSourceLoad};

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

/// Observer for stable workflow stage markers and operator notices.
pub trait SyncObserver {
    /// Records completion of a named ordered synchronization stage.
    fn stage_completed(&self, stage: &'static str);

    /// Records a notice without changing workflow error policy.
    fn notice(&self, notice: &Notice);
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
}

/// Successful synchronization result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncOutcome {
    /// Number of effective IPv4 CIDRs installed.
    pub ipv4_entries: usize,
    /// Number of effective IPv6 CIDRs installed.
    pub ipv6_entries: usize,
    /// Per-provider load summaries in registry order.
    pub sources: Vec<SourceSummary>,
}

/// Ports and registries required by the synchronization workflow.
pub struct SyncDependencies<'a> {
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Nonblocking process lock manager.
    pub locks: &'a dyn LockManager,
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
    let paths = dependencies
        .paths
        .resolve(request, ConfigRequirement::Required)?;
    dependencies.observer.stage_completed("resolve_paths");

    let config = dependencies.configs.load(&paths.config_file)?;
    dependencies.observer.stage_completed("load_config");

    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    dependencies.observer.stage_completed("acquire_lock");

    let enforcement_plan = EnforcementPlan::from_config(&config);
    dependencies
        .enforcement
        .ensure_artifacts(&enforcement_plan)?;
    dependencies
        .observer
        .stage_completed("ensure_ipset_artifacts");

    let source_context = SyncSourceContext {
        paths: &paths,
        config: &config,
        env: &request.env,
    };
    let LoadedSources {
        mut candidates,
        mut safelist,
        external_safelists,
        mut pending_promotions,
        mut summaries,
    } = load_sources(dependencies.sources, &source_context, dependencies.observer)?;
    dependencies.observer.stage_completed("load_sources");

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
    );
    let effective =
        compute_effective_blocklists(&candidates, &safelist, enforcement_plan.enable_ipv6);
    dependencies
        .observer
        .stage_completed("compute_effective_blocklists");

    if enforcement_plan.enable_ipv6 {
        ensure_within_capacity(&enforcement_plan.ipv6, effective.ipv6.len())?;
    }
    ensure_within_capacity(&enforcement_plan.ipv4, effective.ipv4.len())?;

    promote_pending_caches(pending_promotions, dependencies.observer)?;

    if enforcement_plan.enable_ipv6 {
        let entries = effective
            .ipv6
            .iter()
            .copied()
            .map(CanonicalCidr::V6)
            .collect::<Vec<_>>();
        dependencies
            .enforcement
            .replace_set(&enforcement_plan.ipv6, &entries)?;
        dependencies.observer.stage_completed("apply_ipv6_ipset");
    }
    let entries = effective
        .ipv4
        .iter()
        .copied()
        .map(CanonicalCidr::V4)
        .collect::<Vec<_>>();
    dependencies
        .enforcement
        .replace_set(&enforcement_plan.ipv4, &entries)?;
    dependencies.observer.stage_completed("apply_ipv4_ipset");

    dependencies.enforcement.activate(&enforcement_plan)?;
    if !enforcement_plan.enable_ipv6 {
        for notice in dependencies
            .enforcement
            .cleanup_disabled_ipv6(&enforcement_plan)
        {
            dependencies.observer.notice(&notice);
        }
    }
    dependencies
        .observer
        .stage_completed("ensure_firewall_wiring");

    Ok(SyncOutcome {
        ipv4_entries: effective.ipv4.len(),
        ipv6_entries: effective.ipv6.len(),
        sources: summaries,
    })
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
        let descriptor = provider.descriptor();
        match provider.load(context) {
            Ok(loaded) => {
                let SyncSourceLoad {
                    primary,
                    fallback,
                    pending_promotions: loaded_promotions,
                } = loaded;
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
                        });
                    }
                }
                summaries.push(SourceSummary {
                    id: descriptor.id,
                    role: descriptor.role,
                    entries: entry_count,
                    loaded: true,
                });
            }
            Err(error @ AppError::SourceAggregateBudgetExceeded { .. }) => return Err(error),
            Err(error) if descriptor.failure_policy == FailurePolicy::BestEffort => {
                observer.notice(&Notice::warning(format!(
                    "source provider `{}` failed softly: {error}",
                    descriptor.id
                )));
                summaries.push(SourceSummary {
                    id: descriptor.id,
                    role: descriptor.role,
                    entries: 0,
                    loaded: false,
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
) -> Result<(), AppError> {
    for pending in pending_promotions {
        pending
            .promotion
            .promote()
            .map_err(|reason| AppError::CachePromotion {
                provider: pending.provider,
                reason,
            })?;
    }
    observer.stage_completed("promote_source_caches");
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn admit_external_safelists(
    candidates: &[CanonicalCidr],
    safelist: &mut Vec<CanonicalCidr>,
    external_safelists: Vec<LoadedExternalSafelist>,
    enable_ipv6: bool,
    pending_promotions: &mut Vec<PendingPromotion>,
    summaries: &mut [SourceSummary],
    observer: &dyn SyncObserver,
) {
    let baseline = compute_effective_blocklists(candidates, safelist, enable_ipv6);

    for external in external_safelists {
        let primary_admitted = external_safelist_preserves_baseline(
            candidates,
            safelist,
            &external.primary.networks,
            enable_ipv6,
            &baseline,
        );
        if primary_admitted {
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
        if let Some(fallback) = external.fallback.filter(|fallback| {
            external_safelist_preserves_baseline(
                candidates,
                safelist,
                &fallback.networks,
                enable_ipv6,
                &baseline,
            )
        }) {
            for notice in &fallback.notices {
                observer.notice(notice);
            }
            safelist.extend(fallback.networks.iter().copied());
            if let Some(summary) = summaries.get_mut(external.summary_index) {
                summary.entries = fallback.networks.len();
            }
        } else {
            observer.notice(&Notice::warning(format!(
                "externally controlled safelist `{}` has no admissible fallback; using only operator-controlled safelist entries",
                external.provider
            )));
            if let Some(summary) = summaries.get_mut(external.summary_index) {
                summary.entries = 0;
                summary.loaded = false;
            }
        }
    }

    safelist.sort_unstable();
    safelist.dedup();
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

    use super::{
        EnforcementBackend, EnforcementPlan, ManagedSetSpec, SyncDependencies, SyncObserver,
        execute,
    };
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, LockGuard, LockManager, PathResolver};
    use crate::source::{
        FailurePolicy, Notice, PendingCachePromotion, SourceRole, SyncSourceBatch,
        SyncSourceContext, SyncSourceDescriptor, SyncSourceLoad, SyncSourceProvider,
        SyncSourceRegistry,
    };

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
                    reason: "injected failure".to_string(),
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
        fn promote(self: Box<Self>) -> Result<(), String> {
            record(&self.ledger, "promote");
            if self.fail {
                Err("injected promotion failure".to_string())
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
                    reason: format!("injected {stage} failure"),
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
    }

    impl SyncObserver for RecordingObserver {
        fn stage_completed(&self, stage: &'static str) {
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
                paths: &paths,
                configs: &configs,
                locks: &locks,
                sources,
                enforcement,
                observer,
            },
        )
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
        assert!(
            enforcement
                .replacements
                .lock()
                .expect("replacements")
                .is_empty()
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
        assert!(
            enforcement
                .replacements
                .lock()
                .expect("replacements")
                .is_empty()
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
}
