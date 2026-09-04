//! Registries and contracts for synchronization and offline lookup sources.

use std::collections::BTreeSet;
use std::ffi::OsString;

use kidobo_core::config::Config;
use kidobo_core::lookup::LookupSourceEntry;
use kidobo_core::network::CanonicalCidr;

use crate::error::AppError;
use crate::paths::ResolvedPaths;

/// How a synchronization source contributes networks to the effective blocklist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRole {
    /// Networks are candidates for enforcement.
    Candidate,
    /// Networks are carved out of candidate ranges.
    Safelist,
    /// Externally controlled networks are carved out only after admission checks.
    ExternalSafelist,
}

/// Whether a source failure aborts synchronization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    /// A usable result is required for synchronization to continue.
    Required,
    /// A failure becomes an operator-visible warning and synchronization continues.
    BestEffort,
}

/// Stable metadata controlling a synchronization provider's workflow policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSourceDescriptor {
    /// Unique stable provider identifier.
    pub id: &'static str,
    /// Whether networks are candidates or safelist entries.
    pub role: SourceRole,
    /// Required or best-effort error policy.
    pub failure_policy: FailurePolicy,
}

/// Operator-visible notice severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    /// Informational status that does not indicate degraded behavior.
    Info,
    /// Warning about degraded or incomplete behavior.
    Warning,
}

/// Structured application notice rendered by the CLI layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    /// Notice severity.
    pub level: NoticeLevel,
    /// Human-readable operator message.
    pub message: String,
}

impl Notice {
    /// Creates an informational notice.
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Info,
            message: message.into(),
        }
    }

    /// Creates a warning notice.
    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Warning,
            message: message.into(),
        }
    }
}

/// Networks and notices loaded by one synchronization provider.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncSourceBatch {
    /// Canonical networks in the provider's declared role.
    pub networks: Vec<CanonicalCidr>,
    /// Operator-visible provider notices.
    pub notices: Vec<Notice>,
}

/// Deferred selection of a fully written cache generation.
pub trait PendingCachePromotion: Send {
    /// Atomically selects the staged generation.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the cache manifest cannot be promoted.
    fn promote(self: Box<Self>) -> Result<(), String>;
}

/// Primary source data, an optional validated fallback, and deferred cache selections.
#[derive(Default)]
pub struct SyncSourceLoad {
    /// Preferred batch for this synchronization attempt.
    pub primary: SyncSourceBatch,
    /// Previously selected compatible batch, when distinct from the primary.
    pub fallback: Option<SyncSourceBatch>,
    /// Cache manifests selected only after semantic and capacity preflight succeeds.
    pub pending_promotions: Vec<Box<dyn PendingCachePromotion>>,
    /// Persistence failure that must abort sync if neither cached batch passes admission.
    pub fallback_failure: Option<AppError>,
}

impl SyncSourceLoad {
    #[must_use]
    /// Wraps a source batch that has no deferred cache work.
    pub fn ready(primary: SyncSourceBatch) -> Self {
        Self {
            primary,
            fallback: None,
            pending_promotions: Vec::new(),
            fallback_failure: None,
        }
    }
}

/// Read-only context supplied to synchronization providers.
pub struct SyncSourceContext<'a> {
    /// Cancellation checked before starting another source operation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Pre-resolved runtime paths.
    pub paths: &'a ResolvedPaths,
    /// Validated active configuration.
    pub config: &'a Config,
    /// Recognized Kidobo environment values as native strings.
    pub env: &'a std::collections::BTreeMap<OsString, OsString>,
}

/// Provider of one candidate or safelist batch for synchronization.
pub trait SyncSourceProvider: Send + Sync {
    /// Returns stable provider identity and workflow policy.
    fn descriptor(&self) -> SyncSourceDescriptor;

    /// Loads one batch of candidate or safelist networks.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider cannot produce a usable batch. The registry descriptor
    /// determines whether the sync workflow treats that failure as required or best effort.
    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError>;
}

/// Ordered collection of uniquely identified synchronization providers.
#[derive(Default)]
pub struct SyncSourceRegistry {
    providers: Vec<Box<dyn SyncSourceProvider>>,
    ids: BTreeSet<&'static str>,
}

impl SyncSourceRegistry {
    #[must_use]
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a synchronization provider by its stable descriptor ID.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::DuplicateSourceProvider`] when the ID is already registered.
    pub fn register(
        &mut self,
        provider: impl SyncSourceProvider + 'static,
    ) -> Result<(), AppError> {
        let id = provider.descriptor().id;
        if !self.ids.insert(id) {
            return Err(AppError::DuplicateSourceProvider { provider: id });
        }
        self.providers.push(Box::new(provider));
        Ok(())
    }

    pub(crate) fn providers(&self) -> &[Box<dyn SyncSourceProvider>] {
        &self.providers
    }

    #[must_use]
    /// Returns provider descriptors in registration order.
    pub fn descriptors(&self) -> Vec<SyncSourceDescriptor> {
        self.providers
            .iter()
            .map(|provider| provider.descriptor())
            .collect()
    }
}

/// Read-only context supplied to offline lookup providers.
pub struct OfflineLookupContext<'a> {
    /// Cancellation checked between offline providers.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Pre-resolved runtime paths.
    pub paths: &'a ResolvedPaths,
    /// Validated configuration when available; lookup remains usable without it.
    pub config: Option<&'a Config>,
}

/// Provider of local or cached entries for the offline-only lookup workflow.
pub trait OfflineLookupProvider: Send + Sync {
    /// Returns the provider's unique stable identifier.
    fn id(&self) -> &'static str;

    /// Appends this provider's offline lookup entries.
    ///
    /// # Errors
    ///
    /// Returns an error when the provider's local or cached data cannot be loaded safely.
    fn append_offline(
        &self,
        context: &OfflineLookupContext<'_>,
        entries: &mut Vec<LookupSourceEntry>,
    ) -> Result<(), AppError>;
}

/// Ordered collection of uniquely identified offline lookup providers.
#[derive(Default)]
pub struct OfflineLookupRegistry {
    providers: Vec<Box<dyn OfflineLookupProvider>>,
    ids: BTreeSet<&'static str>,
}

impl OfflineLookupRegistry {
    #[must_use]
    /// Creates an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an offline provider by its stable ID.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::DuplicateSourceProvider`] when the ID is already registered.
    pub fn register(
        &mut self,
        provider: impl OfflineLookupProvider + 'static,
    ) -> Result<(), AppError> {
        let id = provider.id();
        if !self.ids.insert(id) {
            return Err(AppError::DuplicateSourceProvider { provider: id });
        }
        self.providers.push(Box::new(provider));
        Ok(())
    }

    /// Loads and deterministically orders entries from every offline provider.
    ///
    /// # Errors
    ///
    /// Returns the first provider error encountered while loading its local or cached data.
    pub fn load(
        &self,
        context: &OfflineLookupContext<'_>,
    ) -> Result<Vec<LookupSourceEntry>, AppError> {
        let mut entries = Vec::new();
        for provider in &self.providers {
            context.cancellation.check()?;
            provider.append_offline(context, &mut entries)?;
        }
        entries.sort_by(|a, b| {
            (&a.source_label, &a.source_line).cmp(&(&b.source_label, &b.source_line))
        });
        Ok(entries)
    }

    #[must_use]
    /// Returns provider IDs in registration order.
    pub fn provider_ids(&self) -> Vec<&'static str> {
        self.providers
            .iter()
            .map(|provider| provider.id())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FailurePolicy, OfflineLookupProvider, OfflineLookupRegistry, SourceRole, SyncSourceBatch,
        SyncSourceContext, SyncSourceDescriptor, SyncSourceLoad, SyncSourceProvider,
        SyncSourceRegistry,
    };
    use crate::AppError;

    struct EmptySyncProvider(&'static str);

    impl SyncSourceProvider for EmptySyncProvider {
        fn descriptor(&self) -> SyncSourceDescriptor {
            SyncSourceDescriptor {
                id: self.0,
                role: SourceRole::Candidate,
                failure_policy: FailurePolicy::Required,
            }
        }

        fn load(&self, _context: &SyncSourceContext<'_>) -> Result<SyncSourceLoad, AppError> {
            Ok(SyncSourceLoad::ready(SyncSourceBatch::default()))
        }
    }

    struct EmptyLookupProvider(&'static str);

    impl OfflineLookupProvider for EmptyLookupProvider {
        fn id(&self) -> &'static str {
            self.0
        }

        fn append_offline(
            &self,
            _context: &super::OfflineLookupContext<'_>,
            _entries: &mut Vec<kidobo_core::lookup::LookupSourceEntry>,
        ) -> Result<(), AppError> {
            Ok(())
        }
    }

    #[test]
    fn sync_registry_rejects_duplicate_ids() {
        let mut registry = SyncSourceRegistry::new();
        registry
            .register(EmptySyncProvider("local"))
            .expect("first registration");
        let error = registry
            .register(EmptySyncProvider("local"))
            .expect_err("duplicate must fail");
        assert!(matches!(
            error,
            AppError::DuplicateSourceProvider { provider: "local" }
        ));
    }

    #[test]
    fn lookup_registry_rejects_duplicate_ids() {
        let mut registry = OfflineLookupRegistry::new();
        registry
            .register(EmptyLookupProvider("remote"))
            .expect("first registration");
        let error = registry
            .register(EmptyLookupProvider("remote"))
            .expect_err("duplicate must fail");
        assert!(matches!(
            error,
            AppError::DuplicateSourceProvider { provider: "remote" }
        ));
    }
}
