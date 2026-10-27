//! Root CLI composition and rendering failures.

use kidobo_app::AppError;
use thiserror::Error;

/// Top-level failure mapped to Kidobo's stable process exit meanings.
#[derive(Debug, Error)]
pub enum KidoboError {
    /// An application workflow or adapter failed.
    #[error(transparent)]
    Application {
        /// Underlying typed application failure.
        #[from]
        source: AppError,
    },

    /// Process-wide logging could not be installed.
    #[error("failed to initialize logger: {reason}")]
    LoggerInit {
        /// Logger diagnostic.
        reason: String,
    },

    /// The machine-readable doctor report could not be serialized.
    #[error("failed to serialize doctor report: {reason}")]
    DoctorReportSerialize {
        /// Serialization diagnostic.
        reason: String,
    },

    /// The process SIGINT handler could not be installed.
    #[error("failed to install SIGINT handler: {reason}")]
    SignalHandlerInstall {
        /// Signal-handler diagnostic.
        reason: String,
    },

    /// Operation was interrupted and maps to exit status 130.
    #[error("operation interrupted by SIGINT")]
    Interrupted,

    /// Doctor completed with one or more failed checks.
    #[error("doctor checks failed")]
    DoctorFailed,

    /// Live inspection completed without enough evidence for a verified verdict.
    #[error(
        "unable to verify Kidobo enforcement; inspect the evidence above and retry with explicit privileges if needed"
    )]
    CheckUnknown,

    /// A new structured report could not be written as JSON.
    #[error("failed to write JSON report: {source}")]
    JsonReport {
        /// Serialization or underlying writer failure.
        #[from]
        source: serde_json::Error,
    },

    /// Source persistence succeeded, but a separately requested synchronization failed.
    #[error("{source_state}; live firewall update failed: {source}; retry: sudo kidobo sync")]
    SourceApplyFailed {
        /// Whether a source change was saved or the existing source state was retained.
        source_state: &'static str,
        /// Original synchronization failure, preserving interruption and cause information.
        #[source]
        source: Box<KidoboError>,
    },

    /// A source change was saved before confirmation input or output failed.
    #[error(
        "Source change saved; live firewall update was not started because confirmation failed: {source}; retry: sudo kidobo sync"
    )]
    SavedConfirmationFailed {
        /// Original prompt or interruption failure.
        #[source]
        source: Box<KidoboError>,
    },

    /// A valid command requires an explicit mode or terminal capability that was not supplied.
    #[error("{message}")]
    Usage {
        /// Actionable usage guidance.
        message: String,
    },

    /// Setup stopped after its reviewed configuration had already been saved.
    #[error(
        "Configuration saved; setup stopped during {stage}: {source}; inspect kidobo status before retrying"
    )]
    SetupAfterSave {
        /// Stage that did not complete normally.
        stage: &'static str,
        /// Original cause; saved files are retained and no rollback is implied.
        #[source]
        source: Box<KidoboError>,
    },

    /// Interactive blocklist confirmation could not be read or rendered.
    #[error("blocklist prompt failed: {source}")]
    BlocklistPrompt {
        /// Prompt diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// Standard input or output failed during CLI rendering.
    #[error("CLI I/O failed: {source}")]
    CliIo {
        /// I/O diagnostic.
        #[source]
        source: std::io::Error,
    },
}

impl KidoboError {
    #[must_use]
    /// Returns exit 130 for interruption and exit 1 for every other runtime failure.
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Interrupted
            | Self::Application {
                source: AppError::Interrupted,
            } => 130,
            Self::SourceApplyFailed { source, .. }
            | Self::SavedConfirmationFailed { source }
            | Self::SetupAfterSave { source, .. } => source.exit_code(),
            Self::Usage { .. } => 2,
            _ => 1,
        }
    }
}

impl From<std::io::Error> for KidoboError {
    fn from(error: std::io::Error) -> Self {
        Self::CliIo { source: error }
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
    }

    #[test]
    fn io_error_converts_without_losing_its_message() {
        let error = std::io::Error::other("write failed");

        match KidoboError::from(error) {
            KidoboError::CliIo { source } => assert_eq!(source.to_string(), "write failed"),
            other => panic!("expected CLI I/O error, got {other:?}"),
        }
    }
}
