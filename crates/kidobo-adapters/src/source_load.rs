//! Shared source loading errors.

use std::path::PathBuf;

use thiserror::Error;

/// Failure while loading local or cached offline source data.
#[derive(Debug, Error)]
pub enum SourceLoadError {
    /// One selected source file could not be read safely.
    #[error("failed to read source file {path}: {source}")]
    Source {
        /// Source path.
        path: PathBuf,
        /// Bounded-read or integrity diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// The remote cache directory could not be enumerated.
    #[error("failed to read remote cache directory {path}: {source}")]
    CacheDir {
        /// Cache directory path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// One remote cache directory entry could not be read.
    #[error("failed to read remote cache directory entry in {path}: {source}")]
    CacheDirEntry {
        /// Cache directory path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },
}
