//! Typed workflow failures shared with the CLI composition layer.

use std::path::PathBuf;

use kidobo_core::config::ConfigError;
use thiserror::Error;

/// Failure returned by an application workflow or port.
#[derive(Debug, Error)]
pub enum AppError {
    /// Temporary ban state could not be read, validated, or persisted.
    #[error("temporary ban state failed for {path}: {reason}")]
    TemporaryBans {
        /// Operator-managed state path.
        path: PathBuf,
        /// Persistence or validation diagnostic.
        reason: String,
    },
    /// Wall-clock time could not be represented as a supported Unix timestamp.
    #[error("could not determine temporary ban time: {reason}")]
    Clock {
        /// Clock diagnostic.
        reason: String,
    },
    /// A two-store source mutation confirmed only its first atomic write.
    #[error(
        "ban update partially completed: updated {completed}; could not confirm update to {pending}: {source}; rerun the command"
    )]
    PartialBanUpdate {
        /// State path whose update completed.
        completed: PathBuf,
        /// State path whose update failed.
        pending: PathBuf,
        /// Underlying failure of the pending update.
        #[source]
        source: Box<AppError>,
    },
    /// The caller cancelled work at a safe workflow boundary.
    #[error("operation interrupted by SIGINT")]
    Interrupted,
    /// A fresh source could not be staged and no admissible cache was available.
    #[error("cache staging failed for `{provider}` without a usable fallback: {source}")]
    CacheStaging {
        /// Source provider identifier.
        provider: &'static str,
        /// Persistence diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
    /// Compatibility-sensitive runtime paths could not be resolved.
    #[error("path resolution failed: {source}")]
    PathResolution {
        /// Path validation diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// A workflow requiring configuration found no file.
    #[error("config file does not exist: {path}")]
    MissingConfigFile {
        /// Expected configuration path.
        path: PathBuf,
    },

    /// The configuration file could not be read.
    #[error("failed to read config file {path}: {source}")]
    ConfigRead {
        /// Configuration path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// An atomic configuration update could not be completed.
    #[error("failed to write config file {path}: {source}")]
    ConfigWrite {
        /// Configuration path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// Configuration text was malformed or violated domain constraints.
    #[error("config parse/validation failed: {source}")]
    ConfigParse {
        /// Underlying parser or validation failure.
        #[from]
        source: ConfigError,
    },

    /// The process lock could not be opened securely or acquired without blocking.
    #[error("lock operation failed: {source}")]
    Lock {
        /// Lock adapter diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// The local blocklist could not be read.
    #[error("failed to read blocklist file {path}: {source}")]
    BlocklistRead {
        /// Blocklist path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
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
    #[error("failed to write blocklist file {path}: {source}")]
    BlocklistWrite {
        /// Blocklist path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// One direct blocklist target was invalid.
    #[error("failed to parse blocklist target {input}")]
    BlocklistTargetParse {
        /// Original target text.
        input: String,
    },

    /// A blocklist target file could not be read within its bound.
    #[error("failed to read blocklist targets file {path}: {source}")]
    BlocklistTargetFileRead {
        /// Target file path.
        path: PathBuf,
        /// Read diagnostic.
        #[source]
        source: std::io::Error,
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
    #[error("ASN operation failed: {source}")]
    Asn {
        /// ASN adapter diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Cache-only flush could not clear the remote cache.
    #[error("failed to clear remote cache at {path}: {source}")]
    FlushCacheIo {
        /// Remote cache path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
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
    #[error("failed to read lookup targets file {path}: {source}")]
    LookupTargetFileRead {
        /// Target file path.
        path: PathBuf,
        /// Read diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// Offline lookup sources could not be loaded safely.
    #[error("lookup source loading failed: {source}")]
    LookupSourceLoad {
        /// Source loading diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Firewall preparation, activation, inspection, or cleanup failed.
    #[error("firewall operation failed: {source}")]
    Firewall {
        /// Firewall adapter diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Managed ipset preparation, replacement, or cleanup failed.
    #[error("ipset operation failed: {source}")]
    Ipset {
        /// Ipset adapter diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Initialization filesystem work failed.
    #[error("initialization I/O failed for {path}: {source}")]
    InitIo {
        /// Affected path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
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
    #[error("source provider `{provider}` failed: {source}")]
    Source {
        /// Stable provider identifier.
        provider: &'static str,
        /// Provider diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Aggregate remote source material exceeded its deterministic admission budget.
    #[error("remote source aggregate exceeds admission budget: entries={entries} limit={limit}")]
    SourceAggregateBudgetExceeded {
        /// Number of distinct canonical CIDRs observed when the limit was exceeded.
        entries: usize,
        /// Maximum permitted aggregate distinct CIDRs.
        limit: usize,
    },

    /// A semantically accepted staged cache generation could not be selected before enforcement.
    #[error("cache promotion failed for source provider `{provider}`: {source}")]
    CachePromotion {
        /// Stable source provider identifier.
        provider: &'static str,
        /// Cache manifest diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// A source registry contains duplicate stable provider IDs.
    #[error("source provider ID is registered more than once: {provider}")]
    DuplicateSourceProvider {
        /// Duplicated provider identifier.
        provider: &'static str,
    },
}
