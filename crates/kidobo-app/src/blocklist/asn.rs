//! Locked ASN configuration and temporary-ban workflows.

use super::{
    BanChange, BanDuration, BlocklistRepository, TemporaryBanContext, partial_update_error,
    record_temporary_bans,
};
use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::source::Notice;
use crate::temporary_bans::TemporaryBanRepository;
use crate::temporary_bans::{Clock, kernel_timeout_notice};
use kidobo_core::asn::normalize_asn_tokens;
use kidobo_core::blocklist::exact_match_indexes;
use kidobo_core::network::CanonicalCidr;
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;

/// Request to add autonomous-system numbers to configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnBanRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Operator tokens such as `AS64496` or `64496`.
    pub tokens: Vec<String>,
    /// Optional ban duration.
    pub duration: Option<BanDuration>,
}

/// Result of an ASN ban configuration update and prefix validation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnBanOutcome {
    /// Normalized ASNs newly added to configuration.
    pub added: Vec<u32>,
    /// Duplicate configured ASN entries removed during normalization.
    pub removed_duplicate_entries: usize,
    /// Stale-cache and other best-effort notices.
    pub notices: Vec<Notice>,
    /// Results for a temporary ASN request, empty for permanent bans.
    pub temporary_changes: Vec<BanChange>,
}

/// Result of an ASN unban configuration and cache cleanup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnUnbanOutcome {
    /// Normalized ASNs removed from configuration.
    pub removed: Vec<u32>,
    /// Existing ASN cache files successfully deleted before lock release.
    pub deleted_cache_files: usize,
    /// Best-effort cache cleanup notices.
    pub notices: Vec<Notice>,
}

/// Usable ASN prefix resolution plus its freshness state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnPrefixBatch {
    /// Non-empty canonical prefix set for the ASN.
    pub prefixes: Vec<CanonicalCidr>,
    /// Whether stale cache was used after refresh failure.
    pub stale: bool,
}

/// Exact effect of an atomic ASN configuration mutation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnConfigUpdate {
    /// Requested ASNs newly added.
    pub added: Vec<u32>,
    /// Requested ASNs that were present and removed.
    pub removed: Vec<u32>,
}

/// Request to remove autonomous-system numbers from configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnUnbanRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Operator tokens such as `AS64496` or `64496`.
    pub tokens: Vec<String>,
}

/// Prefix resolution for ASN ban workflows.
pub trait AsnPrefixLoader {
    /// Loads prefixes for one ASN, using bounded cache fallback where available.
    ///
    /// # Errors
    ///
    /// Returns an error when neither a fresh resolution nor a usable cache is available.
    fn load_prefixes(
        &self,
        asn: u32,
        cache_dir: &Path,
        stale_after: Duration,
    ) -> Result<AsnPrefixBatch, AppError>;
}

/// Atomic ASN configuration editing.
pub trait AsnConfigEditor {
    /// Atomically updates the configured ASN ban set.
    ///
    /// # Errors
    ///
    /// Returns an error when the configuration cannot be read, parsed, or written.
    fn update_config(
        &self,
        config_path: &Path,
        add: &[u32],
        remove: &[u32],
    ) -> Result<AsnConfigUpdate, AppError>;
}

/// Cached ASN prefix removal.
pub trait AsnCacheRemover {
    /// Deletes the cache entry for one ASN.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing cache file cannot be removed.
    fn delete_cache(&self, asn: u32, cache_dir: &Path) -> Result<bool, AppError>;
}

/// Ports required to add ASN bans.
pub struct AsnBanDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Nonblocking process lock manager.
    pub locks: &'a dyn LockManager,
    /// Local blocklist persistence adapter.
    pub repository: &'a dyn BlocklistRepository,
    /// Persistent temporary IP and ASN bans.
    pub temporary_bans: &'a dyn TemporaryBanRepository,
    /// Wall clock sampled immediately before saving temporary bans.
    pub clock: &'a dyn Clock,
    /// ASN prefix resolution adapter.
    pub prefix_loader: &'a dyn AsnPrefixLoader,
    /// ASN configuration persistence adapter.
    pub config_editor: &'a dyn AsnConfigEditor,
}

/// Ports required to remove ASN bans and clean their caches.
pub struct AsnUnbanDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Nonblocking process lock manager.
    pub locks: &'a dyn LockManager,
    /// Persistent temporary IP and ASN bans.
    pub temporary_bans: &'a dyn TemporaryBanRepository,
    /// ASN configuration persistence adapter.
    pub config_editor: &'a dyn AsnConfigEditor,
    /// ASN cache removal adapter.
    pub cache_remover: &'a dyn AsnCacheRemover,
}

/// Resolves and records ASN bans, then best-effort removes duplicate local entries.
///
/// # Errors
///
/// Returns an error when paths, ASN parsing or resolution, locking, configuration loading, or the
/// required configuration update fails.
pub fn execute_ban_asn(
    request: &AsnBanRequest,
    dependencies: &AsnBanDependencies<'_>,
) -> Result<AsnBanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = normalize_asn_tokens(&request.tokens).map_err(|source| AppError::Asn {
        source: Box::new(source),
    })?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let config = dependencies.configs.load(&paths.config_file)?;
    let stale_after = Duration::from_secs(u64::from(config.asn.cache_stale_after_secs.get()));
    let temporary_path = paths.temporary_bans_file();
    let mut temporary = request
        .duration
        .map(|_| dependencies.temporary_bans.load(&temporary_path))
        .transpose()?;
    let cache_dir = paths.cache_dir.join("asn");
    let mut resolved_prefixes = Vec::new();
    let mut notices = Vec::new();
    for asn in &requested_asns {
        dependencies.cancellation.check()?;
        let loaded = dependencies
            .prefix_loader
            .load_prefixes(*asn, &cache_dir, stale_after)?;
        if loaded.stale {
            notices.push(Notice::warning(format!(
                "ASN cache stale fallback used for AS{asn}"
            )));
        }
        resolved_prefixes.extend(loaded.prefixes);
    }
    resolved_prefixes.sort_unstable();
    resolved_prefixes.dedup();
    dependencies.cancellation.check()?;
    if let Some(duration) = request.duration
        && let Some(temporary) = temporary.as_mut()
    {
        let permanent = config.asn.banned.iter().copied().collect::<HashSet<_>>();
        let (temporary_changes, changed) = record_temporary_bans(
            &mut temporary.asns,
            &requested_asns,
            &permanent,
            duration,
            &temporary_path,
            &TemporaryBanContext {
                cancellation: dependencies.cancellation,
                clock: dependencies.clock,
            },
            |asn| format!("AS{asn}"),
        )?;
        if changed {
            dependencies
                .temporary_bans
                .save(&temporary_path, temporary)?;
            if config.ipset.timeout != 0 {
                notices.push(kernel_timeout_notice());
            }
        }
        return Ok(AsnBanOutcome {
            notices,
            temporary_changes,
            ..AsnBanOutcome::default()
        });
    }
    let update =
        dependencies
            .config_editor
            .update_config(&paths.config_file, &requested_asns, &[])?;
    let removed_duplicate_entries = match remove_exact_duplicates(
        &paths.blocklist_file,
        &resolved_prefixes,
        dependencies.repository,
    ) {
        Ok(removed) => removed,
        Err(error) => {
            notices.push(Notice::warning(format!(
                "ASN ban duplicate cleanup failed after config update: {error}"
            )));
            0
        }
    };
    Ok(AsnBanOutcome {
        added: update.added,
        removed_duplicate_entries,
        notices,
        temporary_changes: Vec::new(),
    })
}

/// Removes ASN bans and best-effort deletes their cached prefix data.
///
/// # Errors
///
/// Returns an error when paths, ASN parsing, locking, or the required configuration update fails.
pub fn execute_unban_asn(
    request: &AsnUnbanRequest,
    dependencies: &AsnUnbanDependencies<'_>,
) -> Result<AsnUnbanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = normalize_asn_tokens(&request.tokens).map_err(|source| AppError::Asn {
        source: Box::new(source),
    })?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let config = dependencies.configs.load(&paths.config_file)?;
    let temporary_path = paths.temporary_bans_file();
    let mut temporary = dependencies.temporary_bans.load(&temporary_path)?;
    let mut removed = requested_asns
        .iter()
        .copied()
        .filter(|asn| temporary.asns.remove(asn).is_some())
        .collect::<Vec<_>>();
    dependencies.cancellation.check()?;
    let temporary_changed = !removed.is_empty();
    if temporary_changed {
        dependencies
            .temporary_bans
            .save(&temporary_path, &temporary)?;
    }
    let update = if temporary_changed
        && !requested_asns
            .iter()
            .any(|asn| config.asn.banned.contains(asn))
    {
        AsnConfigUpdate::default()
    } else {
        dependencies
            .config_editor
            .update_config(&paths.config_file, &[], &requested_asns)
            .map_err(|source| {
                partial_update_error(
                    source,
                    temporary_changed,
                    &temporary_path,
                    &paths.config_file,
                )
            })?
    };
    removed.extend(update.removed);
    removed.sort_unstable();
    removed.dedup();
    let cache_dir = paths.cache_dir.join("asn");
    let mut deleted_cache_files = 0;
    let mut notices = Vec::new();
    for asn in &requested_asns {
        match dependencies.cache_remover.delete_cache(*asn, &cache_dir) {
            Ok(true) => deleted_cache_files += 1,
            Ok(false) => {}
            Err(error) => notices.push(Notice::warning(format!(
                "ASN cache cleanup failed for AS{asn}: {error}"
            ))),
        }
    }
    Ok(AsnUnbanOutcome {
        removed,
        deleted_cache_files,
        notices,
    })
}

fn remove_exact_duplicates(
    path: &Path,
    duplicates: &[CanonicalCidr],
    repository: &dyn BlocklistRepository,
) -> Result<usize, AppError> {
    if duplicates.is_empty() {
        return Ok(0);
    }
    let document = repository.load(path)?;
    let line_canonicals = document
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let removal_indexes = exact_match_indexes(&line_canonicals, duplicates)
        .into_iter()
        .collect::<HashSet<_>>();
    let original_line_count = document.lines.len();
    let kept_lines = document
        .lines
        .into_iter()
        .enumerate()
        .filter(|(index, _)| !removal_indexes.contains(index))
        .map(|(_, line)| line.original)
        .collect::<Vec<_>>();
    let removed = original_line_count.saturating_sub(kept_lines.len());
    if removed > 0 {
        repository.write_lines(path, &kept_lines)?;
    }
    Ok(removed)
}
