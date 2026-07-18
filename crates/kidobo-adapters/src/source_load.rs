//! Shared source loading errors.

use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SourceLoadError {
    #[error("failed to read source file {path}: {reason}")]
    Source { path: PathBuf, reason: String },

    #[error("failed to read remote cache directory {path}: {reason}")]
    CacheDir { path: PathBuf, reason: String },

    #[error("failed to read remote cache directory entry in {path}: {reason}")]
    CacheDirEntry { path: PathBuf, reason: String },
}
