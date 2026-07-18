use std::path::Path;

use kidobo_core::config::Config;

use crate::error::AppError;
use crate::paths::{ConfigRequirement, PathResolutionInput, ResolvedPaths};

pub trait PathResolver {
    fn resolve(
        &self,
        input: &PathResolutionInput,
        requirement: ConfigRequirement,
    ) -> Result<ResolvedPaths, AppError>;
}

pub trait ConfigRepository {
    fn load(&self, path: &Path) -> Result<Config, AppError>;
}

pub trait LockGuard {}

pub trait LockManager {
    fn acquire(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError>;
}

pub trait TargetFileReader {
    fn read_lines(&self, path: &Path) -> Result<Vec<String>, AppError>;
}
