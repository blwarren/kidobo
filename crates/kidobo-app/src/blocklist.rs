//! Locked workflows for local blocklist and ASN configuration mutation.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use kidobo_core::blocklist::{
    BanClassification, BlocklistDocument, classify_ban_targets, exact_match_indexes,
    parse_blocklist_target, plan_unban, plan_unban_many,
};
use kidobo_core::network::CanonicalCidr;

use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::source::Notice;

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
}

/// Per-target result from a successful ban workflow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanChange {
    /// Canonical target appended to the blocklist.
    Added(String),
    /// Canonical target already present, including an earlier target in the same request.
    AlreadyPresent(String),
}

/// Result of parsing and applying a local blocklist ban request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BanOutcome {
    /// Changes in request order when all targets were valid.
    pub changes: Vec<BanChange>,
    /// Invalid input strings; any invalid target prevents mutation.
    pub invalid_targets: Vec<String>,
    /// Whether file input contained no targets.
    pub empty_file: bool,
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
}

/// Result of read-only unban preparation under the process lock.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnbanPreparation {
    /// Preview to apply when input was usable.
    pub preview: Option<UnbanPreview>,
    /// Invalid input strings; any invalid target prevents mutation.
    pub invalid_targets: Vec<String>,
    /// Whether file input contained no targets.
    pub empty_file: bool,
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
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let (targets, invalid_targets, empty_file) =
        parse_input(&request.input, dependencies.repository)?;
    if !invalid_targets.is_empty() || empty_file {
        return Ok(BanOutcome {
            changes: Vec::new(),
            invalid_targets,
            empty_file,
        });
    }

    let document = dependencies.repository.load(&paths.blocklist_file)?;
    let existing = document
        .lines
        .iter()
        .filter_map(|line| line.canonical)
        .collect::<Vec<_>>();
    let classifications = classify_ban_targets(&existing, &targets);
    let appended = classifications
        .iter()
        .filter_map(|classification| match classification {
            BanClassification::Added(cidr) => Some(cidr.to_string()),
            BanClassification::AlreadyPresent(_) => None,
        })
        .collect::<Vec<_>>();
    if !appended.is_empty() {
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
    Ok(BanOutcome {
        changes,
        invalid_targets: Vec::new(),
        empty_file: false,
    })
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
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let (targets, invalid_targets, empty_file) =
        parse_input(&request.input, dependencies.repository)?;
    if !invalid_targets.is_empty() || empty_file {
        return Ok(UnbanPreparation {
            preview: None,
            invalid_targets,
            empty_file,
        });
    }
    let document = dependencies.repository.load(&paths.blocklist_file)?;
    Ok(UnbanPreparation {
        preview: Some(build_preview(&request.input, targets, &document)),
        invalid_targets: Vec::new(),
        empty_file: false,
    })
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
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let document = dependencies.repository.load(&paths.blocklist_file)?;
    let current = build_preview(&request.input, preview.targets.clone(), &document);
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
    if !removal_indexes.is_empty() {
        let kept_lines = document
            .lines
            .iter()
            .enumerate()
            .filter(|(index, _)| !removal_indexes.contains(index))
            .map(|(_, line)| line.original.clone())
            .collect::<Vec<_>>();
        dependencies
            .repository
            .write_lines(&paths.blocklist_file, &kept_lines)?;
    }
    Ok(UnbanOutcome {
        target_label: preview.target_label.clone(),
        requested_target_count: preview.requested_target_count,
        removed_exact: index_plan.exact_indexes.len(),
        removed_partial: if decision.remove_partial {
            index_plan.partial_indexes.len()
        } else {
            0
        },
        had_partial_matches: !index_plan.partial_indexes.is_empty(),
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
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = dependencies.asn.normalize_tokens(&request.tokens)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let config = dependencies.configs.load(&paths.config_file)?;
    let stale_after = Duration::from_secs(u64::from(config.asn.cache_stale_after_secs.get()));
    let cache_dir = paths.cache_dir.join("asn");
    let mut resolved_prefixes = Vec::new();
    let mut notices = Vec::new();
    for asn in &requested_asns {
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
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = dependencies.asn.normalize_tokens(&request.tokens)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    let update = dependencies
        .asn
        .update_config(&paths.config_file, &[], &requested_asns)?;
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
        removed: update.removed,
        deleted_cache_files,
        notices,
    })
}

fn parse_input(
    input: &BlocklistInput,
    repository: &dyn BlocklistRepository,
) -> Result<(Vec<CanonicalCidr>, Vec<String>, bool), AppError> {
    let raw = match input {
        BlocklistInput::Single(value) => {
            return parse_blocklist_target(value).map_or_else(
                |_| {
                    Err(AppError::BlocklistTargetParse {
                        input: value.clone(),
                    })
                },
                |target| Ok((vec![target], Vec::new(), false)),
            );
        }
        BlocklistInput::File(path) => repository.read_target_lines(path)?,
    };
    if raw.is_empty() {
        return Ok((Vec::new(), Vec::new(), true));
    }
    let mut targets = Vec::with_capacity(raw.len());
    let mut invalid = Vec::new();
    for value in raw {
        match parse_blocklist_target(&value) {
            Ok(target) => targets.push(target),
            Err(_) => invalid.push(value),
        }
    }
    Ok((targets, invalid, false))
}

fn build_preview(
    input: &BlocklistInput,
    targets: Vec<CanonicalCidr>,
    document: &BlocklistDocument,
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
    let kept_lines = document
        .lines
        .iter()
        .enumerate()
        .filter(|(index, _)| !removal_indexes.contains(index))
        .map(|(_, line)| line.original.clone())
        .collect::<Vec<_>>();
    let removed = document.lines.len().saturating_sub(kept_lines.len());
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
    }

    impl Repository {
        fn new(contents: &str) -> Self {
            Self {
                contents: Mutex::new(contents.to_string()),
                target_lines: Mutex::new(Vec::new()),
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

        fn write_lines(&self, _path: &Path, lines: &[String]) -> Result<(), AppError> {
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
            paths: &Paths,
            configs: &Configs,
            locks,
            repository,
            asn: &Asn,
        }
    }

    #[test]
    fn ban_classifies_existing_and_appends_only_new_entries() {
        let repository = Repository::new("# header\n192.0.2.0/24");
        let locks = Locks::default();
        let outcome = execute_ban(
            &BanRequest {
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &{
                *repository.target_lines.lock().expect("targets") =
                    vec!["192.0.2.0/24".to_string(), "2001:db8::/64".to_string()];
                dependencies(&repository, &locks)
            },
        )
        .expect("ban");

        assert_eq!(
            outcome.changes,
            [
                BanChange::AlreadyPresent("192.0.2.0/24".to_string()),
                BanChange::Added("2001:db8::/64".to_string()),
            ]
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
        *repository.target_lines.lock().expect("targets") =
            vec!["bad-one".to_string(), "bad-two".to_string()];
        let outcome = execute_ban(
            &BanRequest {
                paths: request_input(),
                input: BlocklistInput::File(PathBuf::from("targets.txt")),
            },
            &dependencies(&repository, &Locks::default()),
        )
        .expect("typed invalid outcome");

        assert_eq!(outcome.invalid_targets, ["bad-one", "bad-two"]);
        assert_eq!(
            *repository.contents.lock().expect("contents"),
            "192.0.2.0/24\n"
        );
    }

    #[test]
    fn unban_applies_exact_and_user_approved_partial_matches() {
        let repository = Repository::new("10.0.0.0/24\n10.0.0.1/32\n192.0.2.0/24\n");
        let locks = Locks::default();
        let request = UnbanRequest {
            paths: request_input(),
            input: BlocklistInput::Single("10.0.0.1".to_string()),
        };
        let preparation =
            prepare_unban(&request, &dependencies(&repository, &locks)).expect("preview");
        let preview = preparation.preview.expect("preview");
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
            "192.0.2.0/24\n"
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
        let preview = prepare_unban(&request, &dependencies(&repository, &locks))
            .expect("prepare")
            .preview
            .expect("preview");
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
            paths: &Paths,
            configs: &Configs,
            locks: &locks,
            repository: &repository,
            asn: &asn,
        };

        let outcome = execute_unban_asn(
            &AsnBanRequest {
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
