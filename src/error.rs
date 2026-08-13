use kidobo_app::AppError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KidoboError {
    #[error(transparent)]
    Application {
        #[from]
        source: AppError,
    },

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

    #[error("blocklist prompt failed: {reason}")]
    BlocklistPrompt { reason: String },

    #[error("CLI I/O failed: {reason}")]
    CliIo { reason: String },
}

impl KidoboError {
    #[must_use]
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
    }
}
