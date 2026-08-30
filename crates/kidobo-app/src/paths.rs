//! Compatibility-sensitive runtime path inputs and resolved locations.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::PathBuf;

/// Inputs used to resolve all paths for one command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathResolutionInput {
    /// Optional command-line configuration path override.
    pub explicit_config_path: Option<PathBuf>,
    /// Process temporary directory used for test-sandbox resolution.
    pub temp_dir: PathBuf,
    /// Recognized Kidobo environment variables as native operating-system strings.
    pub env: BTreeMap<OsString, OsString>,
}

/// Complete set of paths derived before a workflow performs side effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPaths {
    /// Directory containing the active configuration file.
    pub config_dir: PathBuf,
    /// Active configuration file.
    pub config_file: PathBuf,
    /// Directory containing persistent operator-managed data.
    pub data_dir: PathBuf,
    /// Local blocklist file.
    pub blocklist_file: PathBuf,
    /// Root cache directory.
    pub cache_dir: PathBuf,
    /// Directory containing remote source caches.
    pub remote_cache_dir: PathBuf,
    /// Nonblocking process lock file.
    pub lock_file: PathBuf,
}

/// Whether path resolution must confirm that the configuration exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigRequirement {
    /// Missing configuration is a hard error.
    Required,
    /// Missing configuration is allowed for workflows designed to operate without it.
    Optional,
}
