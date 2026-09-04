//! Application ports implemented by operating-system and network adapters.

use std::path::Path;

use kidobo_core::config::Config;

use crate::error::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};

/// Cooperative cancellation checked between operations and outside enforcement commits.
pub trait Cancellation: Send + Sync {
    /// Returns whether the caller requested cancellation.
    fn is_cancelled(&self) -> bool;

    /// Rejects further work when cancellation has been requested.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Interrupted`] when cancellation is pending.
    fn check(&self) -> Result<(), AppError> {
        if self.is_cancelled() {
            Err(AppError::Interrupted)
        } else {
            Ok(())
        }
    }
}

/// Cancellation policy for callers that do not install an interrupt handler.
#[derive(Debug, Default)]
pub struct NoCancellation;

impl Cancellation for NoCancellation {
    fn is_cancelled(&self) -> bool {
        false
    }
}

impl Cancellation for std::sync::atomic::AtomicBool {
    fn is_cancelled(&self) -> bool {
        self.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Resolves all runtime locations before a command workflow begins.
pub trait PathResolver {
    /// Resolves compatibility-sensitive runtime paths.
    ///
    /// # Errors
    ///
    /// Returns an error when environment or explicit path inputs are invalid, or when required
    /// configuration is absent.
    fn resolve(
        &self,
        input: &PathResolutionInput,
        requirement: ConfigRequirement,
    ) -> Result<ResolvedPaths, AppError>;
}

/// Loads validated configuration without exposing filesystem details to workflows.
pub trait ConfigRepository {
    /// Loads validated configuration from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    fn load(&self, path: &Path) -> Result<Config, AppError>;
}

/// Lifetime guard for an acquired Kidobo process lock.
///
/// Implementations release the lock when the guard is dropped.
pub trait LockGuard {}

/// Acquires the process-wide workflow lock without blocking.
pub trait LockManager {
    /// Acquires the nonblocking process lock at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened securely or the lock is already held.
    fn acquire(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError>;
}

/// Reads operator-provided line-oriented target files through a bounded adapter.
pub trait TargetFileReader {
    /// Reads bounded line-oriented targets from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the target file cannot be read within its configured bound.
    fn read_lines(&self, path: &Path) -> Result<Vec<String>, AppError>;
}
