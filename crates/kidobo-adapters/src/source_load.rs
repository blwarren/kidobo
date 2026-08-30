//! Shared source loading errors.

use std::path::PathBuf;

use thiserror::Error;

/// Failure while loading local or cached offline source data.
#[derive(Debug, Error)]
pub enum SourceLoadError {
    /// One selected source file could not be read safely.
    #[error("failed to read source file {path}: {reason}")]
    Source {
        /// Source path.
        path: PathBuf,
        /// Bounded-read or integrity diagnostic.
        reason: String,
    },

    /// The remote cache directory could not be enumerated.
    #[error("failed to read remote cache directory {path}: {reason}")]
    CacheDir {
        /// Cache directory path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// One remote cache directory entry could not be read.
    #[error("failed to read remote cache directory entry in {path}: {reason}")]
    CacheDirEntry {
        /// Cache directory path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },
}
