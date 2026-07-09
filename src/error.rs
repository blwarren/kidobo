use std::path::PathBuf;

use crate::adapters::asn::AsnError;
use crate::adapters::blocklist_analysis_sources::AnalysisSourceLoadError;
use crate::adapters::ipset::IpsetError;
use crate::adapters::iptables::FirewallError;
use crate::adapters::lock::LockError;
use crate::adapters::lookup_sources::LookupSourceLoadError;
use crate::adapters::path::PathResolutionError;
use crate::core::config::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KidoboError {
    #[error("failed to initialize logger: {reason}")]
    LoggerInit { reason: String },

    #[error("failed to serialize doctor report: {reason}")]
    DoctorReportSerialize { reason: String },

    #[error("failed to install SIGINT handler: {reason}")]
    SignalHandlerInstall { reason: String },

    #[error("operation interrupted by SIGINT")]
    Interrupted,

    #[error("doctor checks failed")]
    DoctorFailed,

    #[error("path resolution failed: {source}")]
    PathResolution {
        #[from]
        source: PathResolutionError,
    },

    #[error("config file does not exist: {path}")]
    MissingConfigFile { path: PathBuf },

    #[error("initialization I/O failed for {path}: {reason}")]
    InitIo { path: PathBuf, reason: String },

    #[error("systemd setup failed during init for `{command}`: {reason}")]
    InitSystemd { command: String, reason: String },

    #[error("kidobo binary not found at a trusted installed path; expected one of: {candidates}")]
    InitBinaryPathUnavailable { candidates: String },

    #[error("required binary not found on PATH: {binary}")]
    MissingRequiredBinary { binary: &'static str },

    #[error("failed to read config file {path}: {reason}")]
    ConfigRead { path: PathBuf, reason: String },

    #[error("failed to write config file {path}: {reason}")]
    ConfigWrite { path: PathBuf, reason: String },

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

    #[error("blocklist prompt failed: {reason}")]
    BlocklistPrompt { reason: String },

    #[error("blocklist changed while preparing the update; rerun the command")]
    BlocklistChanged,

    #[error("ASN operation failed: {source}")]
    Asn {
        #[from]
        source: AsnError,
    },

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

    #[error("config parse/validation failed: {source}")]
    ConfigParse {
        #[from]
        source: ConfigError,
    },

    #[error("failed to read lookup targets file {path}: {reason}")]
    LookupTargetFileRead { path: PathBuf, reason: String },

    #[error("lookup failed for {count} invalid target(s)")]
    LookupInvalidTargets { count: usize },

    #[error("lookup source loading failed: {source}")]
    LookupSourceLoad {
        #[from]
        source: LookupSourceLoadError,
    },

    #[error("blocklist analysis source loading failed: {source}")]
    AnalysisSourceLoad {
        #[from]
        source: AnalysisSourceLoadError,
    },

    #[error("lock operation failed: {source}")]
    Lock {
        #[from]
        source: LockError,
    },

    #[error("firewall operation failed: {source}")]
    Firewall {
        #[from]
        source: FirewallError,
    },

    #[error("ipset operation failed: {source}")]
    Ipset {
        #[from]
        source: IpsetError,
    },
}

impl KidoboError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Interrupted => 130,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KidoboError;

    #[test]
    fn interrupted_maps_to_130() {
        assert_eq!(KidoboError::Interrupted.exit_code(), 130);
    }

    #[test]
    fn non_interrupted_maps_to_1() {
        assert_eq!(KidoboError::DoctorFailed.exit_code(), 1);
        assert_eq!(
            KidoboError::FlushIncomplete {
                failures: 1,
                details: "test".to_string(),
            }
            .exit_code(),
            1
        );
    }
}
