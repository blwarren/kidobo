use std::path::Path;

use kidobo_core::config::Config;

use crate::error::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};

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

pub trait ConfigRepository {
    /// Loads validated configuration from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read, parsed, or validated.
    fn load(&self, path: &Path) -> Result<Config, AppError>;
}

pub trait LockGuard {}

pub trait LockManager {
    /// Acquires the nonblocking process lock at `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the lock file cannot be opened securely or the lock is already held.
    fn acquire(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError>;
}

pub trait TargetFileReader {
    /// Reads bounded line-oriented targets from `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the target file cannot be read within its configured bound.
    fn read_lines(&self, path: &Path) -> Result<Vec<String>, AppError>;
}
