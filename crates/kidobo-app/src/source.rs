use std::collections::BTreeSet;

use kidobo_core::config::Config;
use kidobo_core::lookup::LookupSourceEntry;
use kidobo_core::network::CanonicalCidr;

use crate::error::AppError;
use crate::paths::ResolvedPaths;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceRole {
    Candidate,
    Safelist,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailurePolicy {
    Required,
    BestEffort,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSourceDescriptor {
    pub id: &'static str,
    pub role: SourceRole,
    pub failure_policy: FailurePolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeLevel {
    Info,
    Warning,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notice {
    pub level: NoticeLevel,
    pub message: String,
}

impl Notice {
    pub fn info(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Info,
            message: message.into(),
        }
    }

    pub fn warning(message: impl Into<String>) -> Self {
        Self {
            level: NoticeLevel::Warning,
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncSourceBatch {
    pub networks: Vec<CanonicalCidr>,
    pub notices: Vec<Notice>,
}

pub struct SyncSourceContext<'a> {
    pub paths: &'a ResolvedPaths,
    pub config: &'a Config,
    pub env: &'a std::collections::BTreeMap<String, String>,
}

pub trait SyncSourceProvider: Send + Sync {
    fn descriptor(&self) -> SyncSourceDescriptor;

    fn load(&self, context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError>;
}

#[derive(Default)]
pub struct SyncSourceRegistry {
    providers: Vec<Box<dyn SyncSourceProvider>>,
    ids: BTreeSet<&'static str>,
}

impl SyncSourceRegistry {
    pub fn new() -> Self {
        Self::default()
    }

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
    pub fn descriptors(&self) -> Vec<SyncSourceDescriptor> {
        self.providers
            .iter()
            .map(|provider| provider.descriptor())
            .collect()
    }
}

pub struct OfflineLookupContext<'a> {
    pub paths: &'a ResolvedPaths,
    pub config: Option<&'a Config>,
}

pub trait OfflineLookupProvider: Send + Sync {
    fn id(&self) -> &'static str;

    fn load_offline(
        &self,
        context: &OfflineLookupContext<'_>,
    ) -> Result<Vec<LookupSourceEntry>, AppError>;
}

#[derive(Default)]
pub struct OfflineLookupRegistry {
    providers: Vec<Box<dyn OfflineLookupProvider>>,
    ids: BTreeSet<&'static str>,
}

impl OfflineLookupRegistry {
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn load(
        &self,
        context: &OfflineLookupContext<'_>,
    ) -> Result<Vec<LookupSourceEntry>, AppError> {
        let mut entries = Vec::new();
        for provider in &self.providers {
            entries.extend(provider.load_offline(context)?);
        }
        entries.sort_by(|a, b| {
            (&a.source_label, &a.source_line).cmp(&(&b.source_label, &b.source_line))
        });
        Ok(entries)
    }

    #[must_use]
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
        SyncSourceContext, SyncSourceDescriptor, SyncSourceProvider, SyncSourceRegistry,
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

        fn load(&self, _context: &SyncSourceContext<'_>) -> Result<SyncSourceBatch, AppError> {
            Ok(SyncSourceBatch::default())
        }
    }

    struct EmptyLookupProvider(&'static str);

    impl OfflineLookupProvider for EmptyLookupProvider {
        fn id(&self) -> &'static str {
            self.0
        }

        fn load_offline(
            &self,
            _context: &super::OfflineLookupContext<'_>,
        ) -> Result<Vec<kidobo_core::lookup::LookupSourceEntry>, AppError> {
            Ok(Vec::new())
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
