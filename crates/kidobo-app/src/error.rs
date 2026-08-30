//! Typed workflow failures shared with the CLI composition layer.

use std::path::PathBuf;

use kidobo_core::config::ConfigError;
use thiserror::Error;

/// Failure returned by an application workflow or port.
#[derive(Debug, Error)]
pub enum AppError {
    /// Compatibility-sensitive runtime paths could not be resolved.
    #[error("path resolution failed: {reason}")]
    PathResolution {
        /// Path validation diagnostic.
        reason: String,
    },

    /// A workflow requiring configuration found no file.
    #[error("config file does not exist: {path}")]
    MissingConfigFile {
        /// Expected configuration path.
        path: PathBuf,
    },

    /// The configuration file could not be read.
    #[error("failed to read config file {path}: {reason}")]
    ConfigRead {
        /// Configuration path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// An atomic configuration update could not be completed.
    #[error("failed to write config file {path}: {reason}")]
    ConfigWrite {
        /// Configuration path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// Configuration text was malformed or violated domain constraints.
    #[error("config parse/validation failed: {source}")]
    ConfigParse {
        /// Underlying parser or validation failure.
        #[from]
        source: ConfigError,
    },

    /// The process lock could not be opened securely or acquired without blocking.
    #[error("lock operation failed: {reason}")]
    Lock {
        /// Lock adapter diagnostic.
        reason: String,
    },

    /// The local blocklist could not be read.
    #[error("failed to read blocklist file {path}: {reason}")]
    BlocklistRead {
        /// Blocklist path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// A non-comment local blocklist line is invalid.
    #[error("invalid blocklist entry in {path} at line {line}: {content}")]
    BlocklistParseLine {
        /// Blocklist path.
        path: PathBuf,
        /// One-based invalid line number.
        line: usize,
        /// Original invalid contents.
        content: String,
    },

    /// An atomic local blocklist update could not be completed.
    #[error("failed to write blocklist file {path}: {reason}")]
    BlocklistWrite {
        /// Blocklist path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// One direct blocklist target was invalid.
    #[error("failed to parse blocklist target {input}")]
    BlocklistTargetParse {
        /// Original target text.
        input: String,
    },

    /// A blocklist target file could not be read within its bound.
    #[error("failed to read blocklist targets file {path}: {reason}")]
    BlocklistTargetFileRead {
        /// Target file path.
        path: PathBuf,
        /// Read diagnostic.
        reason: String,
    },

    /// A mutation was rejected because at least one target was invalid.
    #[error("blocklist update failed for {count} invalid target(s)")]
    BlocklistInvalidTargets {
        /// Number of invalid targets.
        count: usize,
    },

    /// The blocklist changed between a preview and its guarded application.
    #[error("blocklist changed while preparing the update; rerun the command")]
    BlocklistChanged,

    /// ASN parsing, resolution, caching, or persistence failed.
    #[error("ASN operation failed: {reason}")]
    Asn {
        /// ASN adapter diagnostic.
        reason: String,
    },

    /// Cache-only flush could not clear the remote cache.
    #[error("failed to clear remote cache at {path}: {reason}")]
    FlushCacheIo {
        /// Remote cache path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// One or more required full-flush cleanup operations failed.
    #[error("flush cleanup incomplete ({failures} failure(s)): {details}")]
    FlushIncomplete {
        /// Number of incomplete operations.
        failures: usize,
        /// Combined cleanup diagnostics.
        details: String,
    },

    /// Effective entries exceed a family's configured ipset capacity.
    #[error(
        "effective entry count exceeds ipset maxelem for {family} set `{set_name}`: entries={entries} maxelem={maxelem}"
    )]
    IpsetCapacityExceeded {
        /// Operator-visible address-family label.
        family: &'static str,
        /// Affected managed set name.
        set_name: String,
        /// Computed effective entry count.
        entries: usize,
        /// Configured maximum entry count.
        maxelem: u32,
    },

    /// Lookup input contained invalid targets.
    #[error("lookup failed for {count} invalid target(s)")]
    LookupInvalidTargets {
        /// Number of invalid targets.
        count: usize,
    },

    /// A lookup target file could not be read within its bound.
    #[error("failed to read lookup targets file {path}: {reason}")]
    LookupTargetFileRead {
        /// Target file path.
        path: PathBuf,
        /// Read diagnostic.
        reason: String,
    },

    /// Offline lookup sources could not be loaded safely.
    #[error("lookup source loading failed: {reason}")]
    LookupSourceLoad {
        /// Source loading diagnostic.
        reason: String,
    },

    /// Firewall preparation, activation, inspection, or cleanup failed.
    #[error("firewall operation failed: {reason}")]
    Firewall {
        /// Firewall adapter diagnostic.
        reason: String,
    },

    /// Managed ipset preparation, replacement, or cleanup failed.
    #[error("ipset operation failed: {reason}")]
    Ipset {
        /// Ipset adapter diagnostic.
        reason: String,
    },

    /// Initialization filesystem work failed.
    #[error("initialization I/O failed for {path}: {reason}")]
    InitIo {
        /// Affected path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// Live systemd initialization command failed.
    #[error("systemd setup failed during init for `{command}`: {reason}")]
    InitSystemd {
        /// Command name and arguments.
        command: String,
        /// Execution diagnostic.
        reason: String,
    },

    /// No trusted installed executable candidate was available.
    #[error("kidobo binary not found at a trusted installed path; expected one of: {candidates}")]
    InitBinaryPathUnavailable {
        /// Operator-facing candidate path list.
        candidates: String,
    },

    /// A registered synchronization source failed according to its policy.
    #[error("source provider `{provider}` failed: {reason}")]
    Source {
        /// Stable provider identifier.
        provider: &'static str,
        /// Provider diagnostic.
        reason: String,
    },

    /// A source registry contains duplicate stable provider IDs.
    #[error("source provider ID is registered more than once: {provider}")]
    DuplicateSourceProvider {
        /// Duplicated provider identifier.
        provider: &'static str,
    },
}
