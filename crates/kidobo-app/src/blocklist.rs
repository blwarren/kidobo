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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlocklistInput {
    Single(String),
    File(PathBuf),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRequest {
    pub paths: PathResolutionInput,
    pub input: BlocklistInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BanChange {
    Added(String),
    AlreadyPresent(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BanOutcome {
    pub changes: Vec<BanChange>,
    pub invalid_targets: Vec<String>,
    pub empty_file: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanRequest {
    pub paths: PathResolutionInput,
    pub input: BlocklistInput,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanPreview {
    pub target_label: String,
    pub requested_target_count: usize,
    pub exact_entries: Vec<String>,
    pub partial_entries: Vec<String>,
    targets: Vec<CanonicalCidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct UnbanPreparation {
    pub preview: Option<UnbanPreview>,
    pub invalid_targets: Vec<String>,
    pub empty_file: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanDecision {
    pub remove_partial: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnbanOutcome {
    pub target_label: String,
    pub requested_target_count: usize,
    pub removed_exact: usize,
    pub removed_partial: usize,
    pub had_partial_matches: bool,
}

impl UnbanOutcome {
    #[must_use]
    pub fn total_removed(&self) -> usize {
        self.removed_exact + self.removed_partial
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnBanRequest {
    pub paths: PathResolutionInput,
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnBanOutcome {
    pub added: Vec<u32>,
    pub removed_duplicate_entries: usize,
    pub notices: Vec<Notice>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnUnbanOutcome {
    pub removed: Vec<u32>,
    pub deleted_cache_files: usize,
    pub notices: Vec<Notice>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsnPrefixBatch {
    pub prefixes: Vec<CanonicalCidr>,
    pub stale: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AsnConfigUpdate {
    pub added: Vec<u32>,
    pub removed: Vec<u32>,
}

pub trait BlocklistRepository {
    fn load(&self, path: &Path) -> Result<BlocklistDocument, AppError>;

    fn append_entries(
        &self,
        path: &Path,
        entries: &[String],
        has_content: bool,
        trailing_newline: bool,
    ) -> Result<(), AppError>;

    fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError>;

    fn read_target_lines(&self, path: &Path) -> Result<Vec<String>, AppError>;
}

pub trait AsnOperations {
    fn normalize_tokens(&self, tokens: &[String]) -> Result<Vec<u32>, AppError>;

    fn load_prefixes(
        &self,
        asn: u32,
        cache_dir: &Path,
        stale_after: Duration,
    ) -> Result<AsnPrefixBatch, AppError>;

    fn update_config(
        &self,
        config_path: &Path,
        add: &[u32],
        remove: &[u32],
    ) -> Result<AsnConfigUpdate, AppError>;

    fn delete_cache(&self, asn: u32, cache_dir: &Path) -> Result<bool, AppError>;
}

pub struct BlocklistDependencies<'a> {
    pub paths: &'a dyn PathResolver,
    pub configs: &'a dyn ConfigRepository,
    pub locks: &'a dyn LockManager,
    pub repository: &'a dyn BlocklistRepository,
    pub asn: &'a dyn AsnOperations,
}

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

pub fn execute_unban_asn(
    request: &AsnBanRequest,
    dependencies: &BlocklistDependencies<'_>,
) -> Result<AsnUnbanOutcome, AppError> {
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let requested_asns = dependencies.asn.normalize_tokens(&request.tokens)?;
    let update = {
        let _lock = dependencies.locks.acquire(&paths.lock_file)?;
        dependencies
            .asn
            .update_config(&paths.config_file, &[], &requested_asns)?
    };
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
    use std::sync::Mutex;
    use std::time::Duration;

    use kidobo_core::blocklist::BlocklistDocument;
    use kidobo_core::config::Config;

    use super::{
        AsnConfigUpdate, AsnOperations, AsnPrefixBatch, BanChange, BanRequest,
        BlocklistDependencies, BlocklistInput, BlocklistRepository, UnbanDecision, UnbanRequest,
        apply_unban, execute_ban, prepare_unban,
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
}
