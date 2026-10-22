//! Locked workflows for local blocklist and ASN configuration mutation.

#[cfg(test)]
#[path = "blocklist/temporary_tests.rs"]
mod temporary_tests;

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use kidobo_core::blocklist::{
    BanClassification, BlocklistDocument, classify_ban_targets, exact_match_indexes,
    parse_blocklist_target, plan_unban, plan_unban_many,
};
use kidobo_core::network::CanonicalCidr;
pub use kidobo_core::temporary_bans::BanDuration;
use kidobo_core::temporary_bans::TemporaryBans;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::source::Notice;
use crate::temporary_bans::{Clock, TemporaryBanRepository, kernel_timeout_notice};

/// One target supplied directly or through a bounded line-oriented file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocklistInput {
    /// One operator-supplied IP address or CIDR.
    Single(String),
    /// File containing one target per non-comment line.
    File(PathBuf),
}

/// Request to add IP or CIDR targets to the local blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Direct or file-based targets.
    pub input: BlocklistInput,
    /// Optional duration measured from when the request is recorded.
    pub duration: Option<BanDuration>,
}

/// Per-target result from a successful ban workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanChange {
    /// Canonical target appended to the blocklist.
    Added(String),
    /// Canonical target already present, including an earlier target in the same request.
    AlreadyPresent(String),
    /// An existing permanent entry prevents a temporary downgrade.
    AlreadyPermanent(String),
    /// A new temporary entry was recorded.
    TemporaryAdded {
        /// Canonical target identity.
        target: String,
        /// Absolute expiry in Unix seconds.
        expires_at: u64,
    },
    /// An existing temporary entry received a replacement deadline.
    TemporaryRescheduled {
        /// Canonical target identity.
        target: String,
        /// Replacement expiry in Unix seconds.
        expires_at: u64,
    },
}

/// Result of parsing and applying a local blocklist ban request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanOutcome {
    /// Changes in request order when all targets were valid.
    Applied(Vec<BanChange>),
    /// Temporary changes and operational warnings.
    TemporaryApplied {
        /// Results in request order.
        changes: Vec<BanChange>,
        /// Independent kernel timeout warnings.
        notices: Vec<Notice>,
    },
    /// Invalid input strings; any invalid target prevents mutation.
    InvalidTargets(Vec<String>),
    /// File input contained no targets.
    EmptyFile,
}

/// Request to prepare removal of IP or CIDR targets from the local blocklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Direct or file-based targets.
    pub input: BlocklistInput,
}

/// Mutation preview used to obtain the operator's partial-overlap decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanPreview {
    /// Operator-facing label for the direct target or source file.
    pub target_label: String,
    /// Number of valid, unique requested targets.
    pub requested_target_count: usize,
    /// Existing entries exactly matching at least one target.
    pub exact_entries: Vec<String>,
    /// Existing entries that overlap but do not exactly match a target.
    pub partial_entries: Vec<String>,
    targets: Vec<CanonicalCidr>,
    temporary_matches: BTreeMap<CanonicalCidr, u64>,
}

/// Result of read-only unban preparation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnbanPreparation {
    /// Valid targets and their current blocklist matches.
    Ready(UnbanPreview),
    /// Invalid input strings; any invalid target prevents mutation.
    InvalidTargets(Vec<String>),
    /// File input contained no targets.
    EmptyFile,
}

/// Operator decision controlling removal of partially overlapping entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanDecision {
    /// Whether partial overlaps should be removed along with exact matches.
    pub remove_partial: bool,
}

/// Result of applying a prepared unban decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanOutcome {
    /// Operator-facing label from the preview.
    pub target_label: String,
    /// Number of valid, unique requested targets.
    pub requested_target_count: usize,
    /// Number of exact entries removed.
    pub removed_exact: usize,
    /// Number of partial-overlap entries removed.
    pub removed_partial: usize,
    /// Whether the preview contained any partial overlaps.
    pub had_partial_matches: bool,
}

impl UnbanOutcome {
    #[must_use]
    /// Returns the total number of blocklist entries removed.
    pub fn total_removed(&self) -> usize {
        self.removed_exact + self.removed_partial
    }
}

/// Request to add autonomous-system numbers to configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnBanRequest {
    /// Runtime path inputs.
    pub paths: PathResolutionInput,
    /// Operator tokens such as `AS64496` or `64496`.
    pub tokens: Vec<String>,
    /// Optional ban duration; unban callers supply none.
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

/// Persistence boundary for the operator-managed local blocklist.
pub trait BlocklistRepository {
    /// Loads and parses the blocklist at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or contains an invalid entry.
    fn load(&self, path: &Path) -> Result<BlocklistDocument, AppError>;

    /// Appends canonical entries while preserving the document's newline structure.
    ///
    /// # Errors
    ///
    /// Returns an error when the blocklist cannot be updated atomically.
    fn append_entries(
        &self,
        path: &Path,
        entries: &[String],
        has_content: bool,
        trailing_newline: bool,
    ) -> Result<(), AppError>;

    /// Replaces the blocklist with the supplied lines.
    ///
    /// # Errors
    ///
    /// Returns an error when the blocklist cannot be written atomically.
    fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError>;

    /// Reads operator-supplied blocklist targets from a file.
    ///
    /// # Errors
    ///
    /// Returns an error when the target file cannot be read within its configured bound.
    fn read_target_lines(&self, path: &Path) -> Result<Vec<String>, AppError>;
}

/// Resolution, cache, and configuration operations for ASN workflows.
pub trait AsnOperations {
    /// Parses, validates, sorts, and deduplicates ASN tokens.
    ///
    /// # Errors
    ///
    /// Returns an error when any token is not a supported autonomous-system number.
    fn normalize_tokens(&self, tokens: &[String]) -> Result<Vec<u32>, AppError>;

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

    /// Deletes the cache entry for one ASN.
    ///
    /// # Errors
    ///
    /// Returns an error when an existing cache file cannot be removed.
    fn delete_cache(&self, asn: u32, cache_dir: &Path) -> Result<bool, AppError>;
}

/// Ports required by local blocklist and ASN workflows.
pub struct BlocklistDependencies<'a> {
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
    /// ASN resolution and persistence adapter.
    pub asn: &'a dyn AsnOperations,
    /// Persistent temporary IP and ASN bans.
    pub temporary_bans: &'a dyn TemporaryBanRepository,
    /// Wall clock sampled immediately before saving temporary bans.
    pub clock: &'a dyn Clock,
}

/// Applies IP and CIDR additions to the local blocklist under the process lock.
///
/// # Errors
///
/// Returns an error when paths or locking fail, input cannot be read, or the blocklist cannot be
/// loaded or updated.
pub fn execute_ban(
    request: &BanRequest,
    dependencies: &BlocklistDependencies<'_>,
) -> Result<BanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let config = dependencies.configs.load(&paths.config_file)?;
    let targets = match parse_input(&request.input, dependencies.repository)? {
        ParsedBlocklistInput::Ready(targets) => targets,
        ParsedBlocklistInput::InvalidTargets(targets) => {
            return Ok(BanOutcome::InvalidTargets(targets));
        }
        ParsedBlocklistInput::EmptyFile => return Ok(BanOutcome::EmptyFile),
    };

    let document = dependencies.repository.load(&paths.blocklist_file)?;
    let existing = document
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect::<Vec<_>>();
    if let Some(duration) = request.duration {
        let path = paths.temporary_bans_file();
        let mut temporary = dependencies.temporary_bans.load(&path)?;
        let permanent = existing.iter().copied().collect::<HashSet<_>>();
        let (changes, has_updates) = record_temporary_bans(
            &mut temporary.ips,
            &targets,
            &permanent,
            duration,
            &path,
            dependencies,
            ToString::to_string,
        )?;
        if has_updates {
            dependencies.temporary_bans.save(&path, &temporary)?;
        }
        return Ok(BanOutcome::TemporaryApplied {
            changes,
            notices: if has_updates && config.ipset.timeout != 0 {
                vec![kernel_timeout_notice()]
            } else {
                Vec::new()
            },
        });
    }
    let classifications = classify_ban_targets(&existing, &targets);
    let appended = classifications
        .iter()
        .filter_map(|classification| match classification {
            BanClassification::Added(cidr) => Some(cidr.to_string()),
            BanClassification::AlreadyPresent(_) => None,
        })
        .collect::<Vec<_>>();
    if !appended.is_empty() {
        dependencies.cancellation.check()?;
        dependencies.repository.append_entries(
            &paths.blocklist_file,
            &appended,
            document.has_content,
            document.trailing_newline,
        )?;
    }
    let changes = classifications
        .into_iter()
        .map(|classification| match classification {
            BanClassification::Added(cidr) => BanChange::Added(cidr.to_string()),
            BanClassification::AlreadyPresent(cidr) => BanChange::AlreadyPresent(cidr.to_string()),
        })
        .collect();
    Ok(BanOutcome::Applied(changes))
}

fn record_temporary_bans<T: Copy + Eq + std::hash::Hash + Ord>(
    entries: &mut BTreeMap<T, u64>,
    targets: &[T],
    permanent: &HashSet<T>,
    duration: BanDuration,
    path: &Path,
    dependencies: &BlocklistDependencies<'_>,
    render: impl Fn(&T) -> String,
) -> Result<(Vec<BanChange>, bool), AppError> {
    dependencies.cancellation.check()?;
    let has_updates = targets.iter().any(|target| !permanent.contains(target));
    let expires_at = if has_updates {
        duration
            .expires_at(dependencies.clock.now_unix_secs()?)
            .map_err(|error| AppError::TemporaryBans {
                path: path.to_path_buf(),
                reason: error.to_string(),
            })?
    } else {
        0
    };
    let mut seen = HashSet::new();
    let changes = targets
        .iter()
        .map(|target| {
            let rendered = render(target);
            if permanent.contains(target) {
                BanChange::AlreadyPermanent(rendered)
            } else if !seen.insert(*target) {
                BanChange::AlreadyPresent(rendered)
            } else if entries.insert(*target, expires_at).is_some() {
                BanChange::TemporaryRescheduled {
                    target: rendered,
                    expires_at,
                }
            } else {
                BanChange::TemporaryAdded {
                    target: rendered,
                    expires_at,
                }
            }
        })
        .collect();
    Ok((changes, has_updates))
}

/// Builds a read-only unban preview from the current blocklist.
///
/// # Errors
///
/// Returns an error when paths cannot be resolved or input and blocklist data cannot be read.
pub fn prepare_unban(
    request: &UnbanRequest,
    dependencies: &BlocklistDependencies<'_>,
) -> Result<UnbanPreparation, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    dependencies.configs.load(&paths.config_file)?;
    let targets = match parse_input(&request.input, dependencies.repository)? {
        ParsedBlocklistInput::Ready(targets) => targets,
        ParsedBlocklistInput::InvalidTargets(targets) => {
            return Ok(UnbanPreparation::InvalidTargets(targets));
        }
        ParsedBlocklistInput::EmptyFile => return Ok(UnbanPreparation::EmptyFile),
    };
    let document = dependencies.repository.load(&paths.blocklist_file)?;
    let temporary = dependencies
        .temporary_bans
        .load(&paths.temporary_bans_file())?;
    Ok(UnbanPreparation::Ready(build_preview(
        &request.input,
        targets,
        &document,
        &temporary,
    )))
}

/// Applies an approved unban preview under the process lock.
///
/// # Errors
///
/// Returns an error when paths, locking, or persistence fail, or when the blocklist changed after
/// the preview was prepared.
pub fn apply_unban(
    request: &UnbanRequest,
    preview: &UnbanPreview,
    decision: &UnbanDecision,
    dependencies: &BlocklistDependencies<'_>,
) -> Result<UnbanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    dependencies.configs.load(&paths.config_file)?;
    let document = dependencies.repository.load(&paths.blocklist_file)?;
    let temporary_path = paths.temporary_bans_file();
    let mut temporary = dependencies.temporary_bans.load(&temporary_path)?;
    let current = build_preview(
        &request.input,
        preview.targets.clone(),
        &document,
        &temporary,
    );
    if current != *preview {
        return Err(AppError::BlocklistChanged);
    }

    let line_canonicals = document
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let index_plan = plan_unban_many(&line_canonicals, &preview.targets);
    let mut removal_indexes = index_plan
        .exact_indexes
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if decision.remove_partial {
        removal_indexes.extend(index_plan.partial_indexes.iter().copied());
    }
    let temporary_targets = temporary.ips.keys().copied().collect::<Vec<_>>();
    let temporary_canonicals = temporary_targets
        .iter()
        .copied()
        .map(Some)
        .collect::<Vec<_>>();
    let temporary_plan = plan_unban_many(&temporary_canonicals, &preview.targets);
    let mut temporary_removed = 0;
    for index in temporary_plan.exact_indexes.iter().chain(
        temporary_plan
            .partial_indexes
            .iter()
            .filter(|_| decision.remove_partial),
    ) {
        if let Some(target) = temporary_targets.get(*index) {
            temporary_removed += usize::from(temporary.ips.remove(target).is_some());
        }
    }
    dependencies.cancellation.check()?;
    if temporary_removed > 0 {
        dependencies
            .temporary_bans
            .save(&temporary_path, &temporary)?;
    }
    if !removal_indexes.is_empty() {
        let kept_lines = document
            .lines
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !removal_indexes.contains(index))
            .map(|(_, line)| line.original)
            .collect::<Vec<_>>();
        dependencies
            .repository
            .write_lines(&paths.blocklist_file, &kept_lines)
            .map_err(|source| {
                partial_update_error(
                    source,
                    temporary_removed > 0,
                    &temporary_path,
                    &paths.blocklist_file,
                )
            })?;
    }
    Ok(UnbanOutcome {
        target_label: preview.target_label.clone(),
        requested_target_count: preview.requested_target_count,
        removed_exact: index_plan.exact_indexes.len() + temporary_plan.exact_indexes.len(),
        removed_partial: if decision.remove_partial {
            index_plan.partial_indexes.len() + temporary_plan.partial_indexes.len()
        } else {
            0
        },
        had_partial_matches: !index_plan.partial_indexes.is_empty()
            || !temporary_plan.partial_indexes.is_empty(),
    })
}

/// Resolves and records ASN bans, then best-effort removes duplicate local entries.
///
/// # Errors
///
/// Returns an error when paths, ASN parsing or resolution, locking, configuration loading, or the
/// required configuration update fails.
pub fn execute_ban_asn(
    request: &AsnBanRequest,
    dependencies: &BlocklistDependencies<'_>,
) -> Result<AsnBanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = dependencies.asn.normalize_tokens(&request.tokens)?;
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
            .asn
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
            dependencies,
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
    let update = dependencies
        .asn
        .update_config(&paths.config_file, &requested_asns, &[])?;
    let removed_duplicate_entries =
        match remove_exact_duplicates(&paths.blocklist_file, &resolved_prefixes, dependencies) {
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
    request: &AsnBanRequest,
    dependencies: &BlocklistDependencies<'_>,
) -> Result<AsnUnbanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = dependencies.asn.normalize_tokens(&request.tokens)?;
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
            .asn
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
        match dependencies.asn.delete_cache(*asn, &cache_dir) {
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

enum ParsedBlocklistInput {
    Ready(Vec<CanonicalCidr>),
    InvalidTargets(Vec<String>),
    EmptyFile,
}

fn parse_input(
    input: &BlocklistInput,
    repository: &dyn BlocklistRepository,
) -> Result<ParsedBlocklistInput, AppError> {
    let raw = match input {
        BlocklistInput::Single(value) => {
            return parse_blocklist_target(value)
                .map(|target| ParsedBlocklistInput::Ready(vec![target]))
                .map_err(|_| AppError::BlocklistTargetParse {
                    input: value.clone(),
                });
        }
        BlocklistInput::File(path) => repository.read_target_lines(path)?,
    };
    if raw.is_empty() {
        return Ok(ParsedBlocklistInput::EmptyFile);
    }
    let mut targets = Vec::with_capacity(raw.len());
    let mut invalid = Vec::new();
    for value in raw {
        match parse_blocklist_target(&value) {
            Ok(target) => targets.push(target),
            Err(_) => invalid.push(value),
        }
    }
    Ok(if invalid.is_empty() {
        ParsedBlocklistInput::Ready(targets)
    } else {
        ParsedBlocklistInput::InvalidTargets(invalid)
    })
}

fn build_preview(
    input: &BlocklistInput,
    targets: Vec<CanonicalCidr>,
    document: &BlocklistDocument,
    temporary: &TemporaryBans,
) -> UnbanPreview {
    let line_canonicals = document
        .lines
        .iter()
        .map(|line| line.canonical)
        .collect::<Vec<_>>();
    let index_plan = if let [target] = targets.as_slice() {
        plan_unban(&line_canonicals, *target)
    } else {
        plan_unban_many(&line_canonicals, &targets)
    };
    let mut exact_entries = entries_for_indexes(document, &index_plan.exact_indexes);
    let mut partial_entries = entries_for_indexes(document, &index_plan.partial_indexes);
    let temporary_targets = temporary.ips.keys().copied().map(Some).collect::<Vec<_>>();
    let temporary_plan = plan_unban_many(&temporary_targets, &targets);
    let mut temporary_matches = BTreeMap::new();
    for (indexes, entries) in [
        (&temporary_plan.exact_indexes, &mut exact_entries),
        (&temporary_plan.partial_indexes, &mut partial_entries),
    ] {
        for index in indexes {
            if let Some(Some(target)) = temporary_targets.get(*index)
                && let Some(expires_at) = temporary.ips.get(target)
            {
                temporary_matches.insert(*target, *expires_at);
                entries.push(format!(
                    "{target} (temporary, expires at Unix {expires_at})"
                ));
            }
        }
    }
    exact_entries.sort_unstable();
    partial_entries.sort_unstable();
    let target_label = match input {
        BlocklistInput::Single(value) => targets
            .first()
            .map_or_else(|| value.clone(), ToString::to_string),
        BlocklistInput::File(_) => format!("{} file target(s)", targets.len()),
    };
    UnbanPreview {
        target_label,
        requested_target_count: targets.len(),
        exact_entries,
        partial_entries,
        targets,
        temporary_matches,
    }
}

fn partial_update_error(
    source: AppError,
    completed: bool,
    temporary_path: &Path,
    permanent_path: &Path,
) -> AppError {
    if completed {
        AppError::PartialBanUpdate {
            completed: temporary_path.to_path_buf(),
            pending: permanent_path.to_path_buf(),
            source: Box::new(source),
        }
    } else {
        source
    }
}

fn entries_for_indexes(document: &BlocklistDocument, indexes: &[usize]) -> Vec<String> {
    indexes
        .iter()
        .filter_map(|index| document.lines.get(*index))
        .filter_map(|line| line.canonical.map(|cidr| cidr.to_string()))
        .collect()
}

fn remove_exact_duplicates(
    path: &Path,
    duplicates: &[CanonicalCidr],
    dependencies: &BlocklistDependencies<'_>,
) -> Result<usize, AppError> {
    if duplicates.is_empty() {
        return Ok(0);
    }
    let document = dependencies.repository.load(path)?;
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
        dependencies.repository.write_lines(path, &kept_lines)?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use kidobo_core::blocklist::BlocklistDocument;
    use kidobo_core::config::Config;

    use super::{
        AsnBanRequest, AsnConfigUpdate, AsnOperations, AsnPrefixBatch, BanChange, BanRequest,
        BlocklistDependencies, BlocklistInput, BlocklistRepository, UnbanDecision, UnbanRequest,
        apply_unban, execute_ban, execute_unban_asn, prepare_unban,
    };
    use crate::AppError;
    use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};
    use crate::ports::{ConfigRepository, LockGuard, LockManager, PathResolver};

    struct Paths;

    impl PathResolver for Paths {
        fn resolve(
            &self,
            _input: &PathResolutionInput,
            _requirement: ConfigRequirement,
        ) -> Result<ResolvedPaths, AppError> {
            Ok(ResolvedPaths {
                root_override: Some(PathBuf::from("/root")),
                config_dir: PathBuf::from("/root/config"),
                config_file: PathBuf::from("/root/config/config.toml"),
                data_dir: PathBuf::from("/root/data"),
                blocklist_file: PathBuf::from("/root/data/blocklist.txt"),
                cache_dir: PathBuf::from("/root/cache"),
                remote_cache_dir: PathBuf::from("/root/cache/remote"),
                lock_file: PathBuf::from("/root/cache/lock"),
            })
        }
    }

    struct Configs;

    struct EmptyTemporary;

    impl crate::temporary_bans::TemporaryBanRepository for EmptyTemporary {
        fn load(&self, _: &Path) -> Result<kidobo_core::temporary_bans::TemporaryBans, AppError> {
            Ok(kidobo_core::temporary_bans::TemporaryBans::default())
        }

        fn save(
            &self,
            _: &Path,
            _: &kidobo_core::temporary_bans::TemporaryBans,
        ) -> Result<(), AppError> {
            panic!("permanent-only test must not save temporary bans");
        }
    }

    struct FixedClock(u64);

    impl crate::temporary_bans::Clock for FixedClock {
        fn now_unix_secs(&self) -> Result<u64, AppError> {
            Ok(self.0)
        }
    }

    impl ConfigRepository for Configs {
        fn load(&self, _path: &Path) -> Result<Config, AppError> {
            Config::from_toml_str("[ipset]\nset_name='kidobo'\n").map_err(AppError::from)
        }
    }

    struct Guard;
    impl LockGuard for Guard {}

    #[derive(Default)]
    struct Locks(Mutex<usize>);

    impl LockManager for Locks {
        fn acquire(&self, _path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            *self.0.lock().expect("locks") += 1;
            Ok(Box::new(Guard))
        }
    }

    struct Repository {
        contents: Mutex<String>,
        target_lines: Mutex<Vec<String>>,
        fail_write: std::sync::atomic::AtomicBool,
    }

    impl Repository {
        fn new(contents: &str) -> Self {
            Self {
                contents: Mutex::new(contents.to_string()),
                target_lines: Mutex::new(Vec::new()),
                fail_write: std::sync::atomic::AtomicBool::new(false),
            }
        }
    }

    impl BlocklistRepository for Repository {
        fn load(&self, _path: &Path) -> Result<BlocklistDocument, AppError> {
            BlocklistDocument::parse(&self.contents.lock().expect("contents")).map_err(|error| {
                AppError::BlocklistParseLine {
                    path: PathBuf::from("/root/data/blocklist.txt"),
                    line: error.line_number,
                    content: error.content,
                }
            })
        }

        fn append_entries(
            &self,
            _path: &Path,
            entries: &[String],
            has_content: bool,
            trailing_newline: bool,
        ) -> Result<(), AppError> {
            let mut contents = self.contents.lock().expect("contents");
            if has_content && !trailing_newline {
                contents.push('\n');
            }
            for entry in entries {
                contents.push_str(entry);
                contents.push('\n');
            }
            Ok(())
        }

        fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError> {
            if self.fail_write.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AppError::BlocklistWrite {
                    path: path.to_path_buf(),
                    source: std::io::Error::other("injected write failure"),
                });
            }
            let mut rendered = lines.join("\n");
            if !rendered.is_empty() {
                rendered.push('\n');
            }
            *self.contents.lock().expect("contents") = rendered;
            Ok(())
        }

        fn read_target_lines(&self, _path: &Path) -> Result<Vec<String>, AppError> {
            Ok(self.target_lines.lock().expect("targets").clone())
        }
    }

    struct Asn;

    impl AsnOperations for Asn {
        fn normalize_tokens(&self, _tokens: &[String]) -> Result<Vec<u32>, AppError> {
            Ok(Vec::new())
        }

        fn load_prefixes(
            &self,
            _asn: u32,
            _cache_dir: &Path,
            _stale_after: Duration,
        ) -> Result<AsnPrefixBatch, AppError> {
            Ok(AsnPrefixBatch {
                prefixes: Vec::new(),
                stale: false,
            })
        }

        fn update_config(
            &self,
            _config_path: &Path,
            _add: &[u32],
            _remove: &[u32],
        ) -> Result<AsnConfigUpdate, AppError> {
            Ok(AsnConfigUpdate::default())
        }

        fn delete_cache(&self, _asn: u32, _cache_dir: &Path) -> Result<bool, AppError> {
            Ok(false)
        }
    }

    fn request_input() -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: std::collections::BTreeMap::new(),
        }
    }

    fn dependencies<'a>(repository: &'a Repository, locks: &'a Locks) -> BlocklistDependencies<'a> {
        BlocklistDependencies {
            cancellation: &crate::ports::NoCancellation,
            paths: &Paths,
            configs: &Configs,
            locks,
            repository,
            asn: &Asn,
            temporary_bans: &EmptyTemporary,
            clock: &FixedClock(1000),
        }
    }

    #[derive(Default)]
    struct TemporaryRepository {
        state: Mutex<kidobo_core::temporary_bans::TemporaryBans>,
        fail_save: std::sync::atomic::AtomicBool,
    }

    impl crate::temporary_bans::TemporaryBanRepository for TemporaryRepository {
        fn load(&self, _: &Path) -> Result<kidobo_core::temporary_bans::TemporaryBans, AppError> {
            Ok(self.state.lock().expect("state").clone())
        }

        fn save(
            &self,
            path: &Path,
            state: &kidobo_core::temporary_bans::TemporaryBans,
        ) -> Result<(), AppError> {
            if self.fail_save.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(AppError::TemporaryBans {
                    path: path.to_path_buf(),
                    reason: "injected failure".into(),
                });
            }
            *self.state.lock().expect("state") = state.clone();
            Ok(())
        }
    }

    fn cidr(text: &str) -> kidobo_core::network::CanonicalCidr {
        kidobo_core::network::parse_ip_cidr_strict(text).expect("CIDR")
    }

    #[test]
    fn temporary_file_ban_shares_deadline_replaces_it_and_preserves_permanent_entries() {
        let repository = Repository::new("203.0.113.7\n");
        *repository.target_lines.lock().expect("targets") = vec![
            "203.0.113.7".into(),
            "198.51.100.9".into(),
            "2001:db8::/48".into(),
        ];
        let temporary = TemporaryRepository::default();
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let mut request = BanRequest {
            paths: request_input(),
            input: BlocklistInput::File("targets.txt".into()),
            duration: Some("3d".parse().expect("duration")),
        };
        let result = execute_ban(&request, &dependencies).expect("temporary file ban");
        let super::BanOutcome::TemporaryApplied { changes, .. } = result else {
            panic!("temporary result")
        };
        assert_eq!(
            changes,
            vec![
                BanChange::AlreadyPermanent("203.0.113.7/32".into()),
                BanChange::TemporaryAdded {
                    target: "198.51.100.9/32".into(),
                    expires_at: 260_200
                },
                BanChange::TemporaryAdded {
                    target: "2001:db8::/48".into(),
                    expires_at: 260_200
                },
            ]
        );
        request.duration = Some("1h".parse().expect("duration"));
        let result = execute_ban(&request, &dependencies).expect("shorten");
        let super::BanOutcome::TemporaryApplied { changes, .. } = result else {
            panic!("temporary result")
        };
        assert_eq!(
            changes[1],
            BanChange::TemporaryRescheduled {
                target: "198.51.100.9/32".into(),
                expires_at: 4600
            }
        );
        assert_eq!(
            temporary.state.lock().expect("state").ips,
            [(cidr("198.51.100.9"), 4600), (cidr("2001:db8::/48"), 4600)]
                .into_iter()
                .collect()
        );
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n"
        );
        request.duration = None;
        execute_ban(&request, &dependencies).expect("make permanent");
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n198.51.100.9/32\n2001:db8::/48\n"
        );
        assert_eq!(temporary.state.lock().expect("state").ips.len(), 2);
    }

    #[test]
    fn unban_revalidates_temporary_deadlines_and_handles_both_store_failures() {
        use std::sync::atomic::Ordering;
        let repository = Repository::new("203.0.113.7\n");
        let temporary = TemporaryRepository::default();
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("203.0.113.7"), 4600);
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".into()),
        };
        let decision = UnbanDecision {
            remove_partial: false,
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies).expect("preview")
        else {
            panic!("preview")
        };
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("203.0.113.7"), 5600);
        assert!(matches!(
            apply_unban(&request, &preview, &decision, &dependencies),
            Err(AppError::BlocklistChanged)
        ));
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies).expect("preview")
        else {
            panic!("preview")
        };
        temporary.fail_save.store(true, Ordering::SeqCst);
        assert!(matches!(
            apply_unban(&request, &preview, &decision, &dependencies),
            Err(AppError::TemporaryBans { .. })
        ));
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n"
        );
        assert_eq!(
            temporary.state.lock().expect("state").ips[&cidr("203.0.113.7")],
            5600
        );
        temporary.fail_save.store(false, Ordering::SeqCst);
        repository.fail_write.store(true, Ordering::SeqCst);
        let error = apply_unban(&request, &preview, &decision, &dependencies)
            .expect_err("second store failure");
        assert!(matches!(error, AppError::PartialBanUpdate { .. }));
        assert!(error.to_string().contains("rerun"));
        assert!(temporary.state.lock().expect("state").ips.is_empty());
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.7\n"
        );
        repository.fail_write.store(false, Ordering::SeqCst);
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies).expect("retry preview")
        else {
            panic!("preview")
        };
        assert_eq!(
            apply_unban(&request, &preview, &decision, &dependencies)
                .expect("retry")
                .removed_exact,
            1
        );
        assert!(repository.contents.lock().expect("contents").is_empty());
    }

    #[test]
    fn temporary_partial_unban_respects_confirmation_and_leaves_asns() {
        let repository = Repository::new("");
        let temporary = TemporaryRepository::default();
        temporary
            .state
            .lock()
            .expect("state")
            .ips
            .insert(cidr("203.0.113.0/24"), 4600);
        temporary
            .state
            .lock()
            .expect("state")
            .asns
            .insert(64496, 4600);
        let locks = Locks::default();
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.temporary_bans = &temporary;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".into()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies).expect("preview")
        else {
            panic!("preview")
        };
        assert_eq!(
            preview.partial_entries,
            ["203.0.113.0/24 (temporary, expires at Unix 4600)"]
        );
        assert_eq!(
            apply_unban(
                &request,
                &preview,
                &UnbanDecision {
                    remove_partial: false
                },
                &dependencies
            )
            .expect("decline")
            .total_removed(),
            0
        );
        assert_eq!(temporary.state.lock().expect("state").ips.len(), 1);
        assert_eq!(
            apply_unban(
                &request,
                &preview,
                &UnbanDecision {
                    remove_partial: true
                },
                &dependencies
            )
            .expect("approve")
            .removed_partial,
            1
        );
        assert!(temporary.state.lock().expect("state").ips.is_empty());
        assert_eq!(
            temporary.state.lock().expect("state").asns,
            [(64496, 4600)].into_iter().collect()
        );
    }

    #[test]
    fn cancellation_after_configuration_or_preview_preserves_blocklist() {
        use std::sync::atomic::{AtomicBool, Ordering};
        struct CancellingConfigs<'a>(&'a AtomicBool);
        impl ConfigRepository for CancellingConfigs<'_> {
            fn load(&self, path: &Path) -> Result<Config, AppError> {
                self.0.store(true, Ordering::SeqCst);
                Configs.load(path)
            }
        }
        let repository = Repository::new("203.0.113.0/24\n");
        let locks = Locks::default();
        let cancelled = AtomicBool::new(false);
        let configs = CancellingConfigs(&cancelled);
        let mut dependencies = dependencies(&repository, &locks);
        dependencies.cancellation = &cancelled;
        dependencies.configs = &configs;
        let result = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::Single("198.51.100.1".to_string()),
            },
            &dependencies,
        );
        assert!(matches!(result, Err(AppError::Interrupted)));
        cancelled.store(false, Ordering::SeqCst);
        dependencies.configs = &Configs;
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("203.0.113.7".to_string()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies).expect("preview")
        else {
            panic!("expected preview");
        };
        cancelled.store(true, Ordering::SeqCst);
        let result = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: true,
            },
            &dependencies,
        );
        assert!(matches!(result, Err(AppError::Interrupted)));
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.0/24\n"
        );
    }

    #[test]
    fn ban_classifies_existing_and_appends_only_new_entries() {
        let repository = Repository::new("# header\n192.0.2.0/24");
        let locks = Locks::default();
        let outcome = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &{
                *repository.target_lines.lock().expect("targets") = vec![
                    "192.0.2.0/24".to_string(),
                    "2001:db8::/64".to_string(),
                    "2001:db8::/64".to_string(),
                ];
                dependencies(&repository, &locks)
            },
        )
        .expect("ban");

        assert_eq!(
            outcome,
            super::BanOutcome::Applied(vec![
                BanChange::AlreadyPresent("192.0.2.0/24".to_string()),
                BanChange::Added("2001:db8::/64".to_string()),
                BanChange::AlreadyPresent("2001:db8::/64".to_string()),
            ])
        );
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "# header\n192.0.2.0/24\n2001:db8::/64\n"
        );
        assert_eq!(*locks.0.lock().expect("locks"), 1);
    }

    #[test]
    fn file_ban_reports_all_invalid_targets_without_mutating() {
        let repository = Repository::new("192.0.2.0/24\n");
        *repository.target_lines.lock().expect("targets") = vec![
            "bad-one".to_string(),
            "198.51.100.7".to_string(),
            "bad-two".to_string(),
        ];
        let outcome = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &dependencies(&repository, &Locks::default()),
        )
        .expect("typed invalid outcome");

        assert_eq!(
            outcome,
            super::BanOutcome::InvalidTargets(vec!["bad-one".into(), "bad-two".into()])
        );
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "192.0.2.0/24\n"
        );
    }

    #[test]
    fn empty_file_and_invalid_single_bans_leave_blocklist_unchanged() {
        let repository = Repository::new("192.0.2.0/24\n");
        let locks = Locks::default();
        let dependencies = dependencies(&repository, &locks);
        let outcome = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &dependencies,
        )
        .expect("empty file outcome");
        assert_eq!(outcome, super::BanOutcome::EmptyFile);
        let error = execute_ban(
            &BanRequest {
                duration: None,
                paths: request_input(),
                input: BlocklistInput::Single("bad-target".into()),
            },
            &dependencies,
        )
        .expect_err("invalid single target");
        assert!(matches!(error, AppError::BlocklistTargetParse { input } if input == "bad-target"));
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "192.0.2.0/24\n"
        );
    }

    #[test]
    fn unban_applies_exact_and_user_approved_partial_matches() {
        let repository = Repository::new(
            "# header\n10.0.0.0/24\n\n10.0.0.1/32\n  192.0.2.0/24  \n# retained comment\n",
        );
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("10.0.0.1".to_string()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies(&repository, &locks)).expect("preview")
        else {
            panic!("expected preview");
        };
        assert_eq!(preview.exact_entries, ["10.0.0.1/32"]);
        assert_eq!(preview.partial_entries, ["10.0.0.0/24"]);

        let outcome = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: true,
            },
            &dependencies(&repository, &locks),
        )
        .expect("apply");

        assert_eq!(outcome.removed_exact, 1);
        assert_eq!(outcome.removed_partial, 1);
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "# header\n\n  192.0.2.0/24  \n# retained comment\n"
        );
    }

    #[test]
    fn unban_reloads_after_lock_and_rejects_changed_preview() {
        let repository = Repository::new("10.0.0.0/24\n");
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("10.0.0.1".to_string()),
        };
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies(&repository, &locks)).expect("prepare")
        else {
            panic!("expected preview")
        };
        *repository.contents.lock().expect("contents") = "10.0.0.0/16\n".to_string();

        let error = apply_unban(
            &request,
            &preview,
            &UnbanDecision {
                remove_partial: false,
            },
            &dependencies(&repository, &locks),
        )
        .expect_err("race must fail");

        assert!(matches!(error, AppError::BlocklistChanged));
        assert_eq!(*locks.0.lock().expect("locks"), 1);
    }

    #[test]
    fn file_unban_distinguishes_empty_invalid_and_ready_without_mutating() {
        let repository = Repository::new("203.0.113.0/24\n");
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::File(PathBuf::from("targets.txt")),
        };
        let dependencies = dependencies(&repository, &locks);
        assert_eq!(
            prepare_unban(&request, &dependencies).expect("empty file"),
            super::UnbanPreparation::EmptyFile
        );

        *repository.target_lines.lock().expect("targets") =
            vec!["bad-one".into(), "203.0.113.7".into(), "bad-two".into()];
        assert_eq!(
            prepare_unban(&request, &dependencies).expect("invalid file"),
            super::UnbanPreparation::InvalidTargets(vec!["bad-one".into(), "bad-two".into()])
        );

        *repository.target_lines.lock().expect("targets") = vec!["198.51.100.7".into()];
        let super::UnbanPreparation::Ready(preview) =
            prepare_unban(&request, &dependencies).expect("valid file")
        else {
            panic!("valid unmatched targets still need a preview");
        };
        assert_eq!(preview.requested_target_count, 1);
        assert_eq!(preview.exact_entries, Vec::<String>::new());
        assert_eq!(preview.partial_entries, Vec::<String>::new());
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "203.0.113.0/24\n"
        );
        assert_eq!(*locks.0.lock().expect("locks"), 0);
    }

    // Drop records lock release, making the ledger sensitive to deletion occurring one statement
    // too late even though both operations would otherwise succeed in a sequential unit test.
    struct EventGuard(Arc<Mutex<Vec<&'static str>>>);

    impl LockGuard for EventGuard {}

    impl Drop for EventGuard {
        fn drop(&mut self) {
            self.0.lock().expect("events").push("unlock");
        }
    }

    struct EventLocks(Arc<Mutex<Vec<&'static str>>>);

    impl LockManager for EventLocks {
        fn acquire(&self, _path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
            self.0.lock().expect("events").push("lock");
            Ok(Box::new(EventGuard(Arc::clone(&self.0))))
        }
    }

    struct EventAsn(Arc<Mutex<Vec<&'static str>>>);

    impl AsnOperations for EventAsn {
        fn normalize_tokens(&self, _tokens: &[String]) -> Result<Vec<u32>, AppError> {
            Ok(vec![64512])
        }

        fn load_prefixes(
            &self,
            _asn: u32,
            _cache_dir: &Path,
            _stale_after: Duration,
        ) -> Result<AsnPrefixBatch, AppError> {
            unreachable!("unban does not load prefixes")
        }

        fn update_config(
            &self,
            _config_path: &Path,
            _add: &[u32],
            _remove: &[u32],
        ) -> Result<AsnConfigUpdate, AppError> {
            self.0.lock().expect("events").push("update");
            Ok(AsnConfigUpdate {
                added: Vec::new(),
                removed: vec![64512],
            })
        }

        fn delete_cache(&self, _asn: u32, _cache_dir: &Path) -> Result<bool, AppError> {
            self.0.lock().expect("events").push("delete");
            Ok(true)
        }
    }

    #[test]
    fn asn_unban_holds_the_process_lock_through_cache_deletion() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let locks = EventLocks(Arc::clone(&events));
        let asn = EventAsn(Arc::clone(&events));
        let repository = Repository::new("");
        let dependencies = BlocklistDependencies {
            cancellation: &crate::ports::NoCancellation,
            paths: &Paths,
            configs: &Configs,
            locks: &locks,
            repository: &repository,
            asn: &asn,
            temporary_bans: &EmptyTemporary,
            clock: &FixedClock(1000),
        };

        let outcome = execute_unban_asn(
            &AsnBanRequest {
                duration: None,
                paths: request_input(),
                tokens: vec!["AS64512".to_string()],
            },
            &dependencies,
        )
        .expect("unban ASN");

        assert_eq!(outcome.removed, [64512]);
        assert_eq!(outcome.deleted_cache_files, 1);
        assert_eq!(
            *events.lock().expect("events"),
            ["lock", "update", "delete", "unlock"]
        );
    }
}
