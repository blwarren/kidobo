//! Locked IP and CIDR ban workflow.

use super::{
    BanChange, BanDuration, BlocklistInput, BlocklistRepository, ParsedBlocklistInput,
    TemporaryBanContext, parse_input, record_temporary_bans,
};
use crate::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput};
use crate::ports::{ConfigRepository, LockManager, PathResolver};
use crate::source::Notice;
use crate::temporary_bans::TemporaryBanRepository;
use crate::temporary_bans::{Clock, kernel_timeout_notice};
use kidobo_core::blocklist::{BanClassification, classify_ban_targets};
use std::collections::HashSet;

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

/// Ports required to add IP and CIDR bans.
pub struct BanDependencies<'a> {
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
}

/// Applies IP and CIDR additions to the local blocklist under the process lock.
///
/// # Errors
///
/// Returns an error when paths or locking fail, input cannot be read, or the blocklist cannot be
/// loaded or updated.
pub fn execute_ban(
    request: &BanRequest,
    dependencies: &BanDependencies<'_>,
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
            &TemporaryBanContext {
                cancellation: dependencies.cancellation,
                clock: dependencies.clock,
            },
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
