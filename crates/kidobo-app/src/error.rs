use std::path::PathBuf;

use kidobo_core::config::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("path resolution failed: {reason}")]
    PathResolution { reason: String },

    #[error("config file does not exist: {path}")]
    MissingConfigFile { path: PathBuf },

    #[error("failed to read config file {path}: {reason}")]
    ConfigRead { path: PathBuf, reason: String },

    #[error("failed to write config file {path}: {reason}")]
    ConfigWrite { path: PathBuf, reason: String },

    #[error("config parse/validation failed: {source}")]
    ConfigParse {
        #[from]
        source: ConfigError,
    },

    #[error("lock operation failed: {reason}")]
    Lock { reason: String },

    #[error("failed to read blocklist file {path}: {reason}")]
    BlocklistRead { path: PathBuf, reason: String },

    #[error("invalid blocklist entry in {path} at line {line}: {content}")]
    BlocklistParseLine {
        path: PathBuf,
        line: usize,
        content: String,
    },

    #[error("failed to write blocklist file {path}: {reason}")]
    BlocklistWrite { path: PathBuf, reason: String },

    #[error("failed to parse blocklist target {input}")]
    BlocklistTargetParse { input: String },

    #[error("failed to read blocklist targets file {path}: {reason}")]
    BlocklistTargetFileRead { path: PathBuf, reason: String },

    #[error("blocklist update failed for {count} invalid target(s)")]
    BlocklistInvalidTargets { count: usize },

    #[error("blocklist changed while preparing the update; rerun the command")]
    BlocklistChanged,

    #[error("ASN operation failed: {reason}")]
    Asn { reason: String },

    #[error("failed to clear remote cache at {path}: {reason}")]
    FlushCacheIo { path: PathBuf, reason: String },

    #[error("flush cleanup incomplete ({failures} failure(s)): {details}")]
    FlushIncomplete { failures: usize, details: String },

    #[error(
        "effective entry count exceeds ipset maxelem for {family} set `{set_name}`: entries={entries} maxelem={maxelem}"
    )]
    IpsetCapacityExceeded {
        family: &'static str,
        set_name: String,
        entries: usize,
        maxelem: u32,
    },

    #[error("lookup failed for {count} invalid target(s)")]
    LookupInvalidTargets { count: usize },

    #[error("failed to read lookup targets file {path}: {reason}")]
    LookupTargetFileRead { path: PathBuf, reason: String },

    #[error("lookup source loading failed: {reason}")]
    LookupSourceLoad { reason: String },

    #[error("firewall operation failed: {reason}")]
    Firewall { reason: String },

    #[error("ipset operation failed: {reason}")]
    Ipset { reason: String },

    #[error("initialization I/O failed for {path}: {reason}")]
    InitIo { path: PathBuf, reason: String },

    #[error("systemd setup failed during init for `{command}`: {reason}")]
    InitSystemd { command: String, reason: String },

    #[error("kidobo binary not found at a trusted installed path; expected one of: {candidates}")]
    InitBinaryPathUnavailable { candidates: String },

    #[error("source provider `{provider}` failed: {reason}")]
    Source {
        provider: &'static str,
        reason: String,
    },

    #[error("source provider ID is registered more than once: {provider}")]
    DuplicateSourceProvider { provider: &'static str },
}
