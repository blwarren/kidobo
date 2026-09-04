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

    /// Interactive blocklist confirmation could not be read or rendered.
    #[error("blocklist prompt failed: {reason}")]
    BlocklistPrompt {
        /// Prompt diagnostic.
        reason: String,
    },

    /// Standard input or output failed during CLI rendering.
    #[error("CLI I/O failed: {reason}")]
    CliIo {
        /// I/O diagnostic.
        reason: String,
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
            _ => 1,
        }
    }
}

impl From<std::io::Error> for KidoboError {
    fn from(error: std::io::Error) -> Self {
        Self::CliIo {
            reason: error.to_string(),
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
    }

    #[test]
    fn io_error_converts_without_losing_its_message() {
        let error = std::io::Error::other("write failed");

        match KidoboError::from(error) {
            KidoboError::CliIo { reason } => assert_eq!(reason, "write failed"),
            other => panic!("expected CLI I/O error, got {other:?}"),
        }
    }
}
