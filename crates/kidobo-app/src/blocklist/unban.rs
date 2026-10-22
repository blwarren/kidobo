//! Read-only previews and locked IP and CIDR removal.

use super::{
    BlocklistInput, BlocklistRepository, ParsedBlocklistInput, parse_input, partial_update_error,
};
use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::temporary_bans::TemporaryBanRepository;
use kidobo_core::blocklist::{BlocklistDocument, UnbanIndexPlan, UnbanTargetIndex};
use kidobo_core::network::CanonicalCidr;
use kidobo_core::temporary_bans::TemporaryBans;
use std::collections::{BTreeMap, HashSet};

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
    targets: UnbanTargetIndex,
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

/// Ports required to prepare a read-only IP and CIDR unban preview.
pub struct UnbanPreparationDependencies<'a> {
    /// Cooperative cancellation outside a started mutation.
    pub cancellation: &'a dyn crate::ports::Cancellation,
    /// Runtime path resolver.
    pub paths: &'a dyn PathResolver,
    /// Validated configuration repository.
    pub configs: &'a dyn ConfigRepository,
    /// Local blocklist persistence adapter.
    pub repository: &'a dyn BlocklistRepository,
    /// Persistent temporary IP and ASN bans.
    pub temporary_bans: &'a dyn TemporaryBanRepository,
}

/// Ports required to apply an IP and CIDR unban decision.
pub struct UnbanApplyDependencies<'a> {
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
}

/// Builds a read-only unban preview from the current blocklist.
///
/// # Errors
///
/// Returns an error when paths cannot be resolved or input and blocklist data cannot be read.
pub fn prepare_unban(
    request: &UnbanRequest,
    dependencies: &UnbanPreparationDependencies<'_>,
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
    dependencies.cancellation.check()?;
    let targets = UnbanTargetIndex::new(targets);
    dependencies.cancellation.check()?;
    let document = dependencies.repository.load(&paths.blocklist_file)?;
    dependencies.cancellation.check()?;
    let temporary = dependencies
        .temporary_bans
        .load(&paths.temporary_bans_file())?;
    let plan = build_unban_plan(&targets, &document, &temporary, dependencies.cancellation)?;
    Ok(UnbanPreparation::Ready(UnbanPreview {
        target_label: unban_target_label(&request.input, &targets),
        requested_target_count: targets.targets().len(),
        exact_entries: plan.exact_entries,
        partial_entries: plan.partial_entries,
        targets,
        temporary_matches: plan.temporary_matches,
    }))
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
    dependencies: &UnbanApplyDependencies<'_>,
) -> Result<UnbanOutcome, AppError> {
    dependencies.cancellation.check()?;
    let paths = dependencies
        .paths
        .resolve(&request.paths, ConfigRequirement::Required)?;
    let _lock = dependencies.locks.acquire(&paths.lock_file)?;
    dependencies.configs.load(&paths.config_file)?;
    dependencies.cancellation.check()?;
    let document = dependencies.repository.load(&paths.blocklist_file)?;
    dependencies.cancellation.check()?;
    let temporary_path = paths.temporary_bans_file();
    let mut temporary = dependencies.temporary_bans.load(&temporary_path)?;
    let current = build_unban_plan(
        &preview.targets,
        &document,
        &temporary,
        dependencies.cancellation,
    )?;
    if current.exact_entries != preview.exact_entries
        || current.partial_entries != preview.partial_entries
        || current.temporary_matches != preview.temporary_matches
        || preview.requested_target_count != preview.targets.targets().len()
        || preview.target_label != unban_target_label(&request.input, &preview.targets)
    {
        return Err(AppError::BlocklistChanged);
    }
    let UnbanStatePlan {
        permanent: index_plan,
        temporary: temporary_plan,
        temporary_targets,
        ..
    } = current;
    let mut removal_indexes = index_plan
        .exact_indexes
        .iter()
        .copied()
        .collect::<HashSet<_>>();
    if decision.remove_partial {
        removal_indexes.extend(index_plan.partial_indexes.iter().copied());
    }
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

struct UnbanStatePlan {
    permanent: UnbanIndexPlan,
    temporary: UnbanIndexPlan,
    temporary_targets: Vec<CanonicalCidr>,
    exact_entries: Vec<String>,
    partial_entries: Vec<String>,
    temporary_matches: BTreeMap<CanonicalCidr, u64>,
}

fn build_unban_plan(
    targets: &UnbanTargetIndex,
    document: &BlocklistDocument,
    temporary: &TemporaryBans,
    cancellation: &dyn crate::ports::Cancellation,
) -> Result<UnbanStatePlan, AppError> {
    cancellation.check()?;
    let index_plan = targets.plan(document.lines.iter().map(|line| line.canonical));
    cancellation.check()?;
    let mut exact_entries = entries_for_indexes(document, &index_plan.exact_indexes);
    let mut partial_entries = entries_for_indexes(document, &index_plan.partial_indexes);
    let temporary_targets = temporary.ips.keys().copied().collect::<Vec<_>>();
    let temporary_plan = targets.plan(temporary_targets.iter().copied().map(Some));
    cancellation.check()?;
    let mut temporary_matches = BTreeMap::new();
    for (indexes, entries) in [
        (&temporary_plan.exact_indexes, &mut exact_entries),
        (&temporary_plan.partial_indexes, &mut partial_entries),
    ] {
        for index in indexes {
            if let Some(target) = temporary_targets.get(*index)
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
    cancellation.check()?;
    Ok(UnbanStatePlan {
        permanent: index_plan,
        temporary: temporary_plan,
        temporary_targets,
        exact_entries,
        partial_entries,
        temporary_matches,
    })
}

fn unban_target_label(input: &BlocklistInput, targets: &UnbanTargetIndex) -> String {
    match input {
        BlocklistInput::Single(value) => targets
            .targets()
            .first()
            .map_or_else(|| value.clone(), ToString::to_string),
        BlocklistInput::File(_) => format!("{} file target(s)", targets.targets().len()),
    }
}

fn entries_for_indexes(document: &BlocklistDocument, indexes: &[usize]) -> Vec<String> {
    indexes
        .iter()
        .filter_map(|index| document.lines.get(*index))
        .filter_map(|line| line.canonical.map(|cidr| cidr.to_string()))
        .collect()
}
