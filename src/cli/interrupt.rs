use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::error::KidoboError;

static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static SIGNAL_INSTALL_RESULT: OnceLock<Result<(), String>> = OnceLock::new();

pub struct SigintCancellation;

impl kidobo_app::ports::Cancellation for SigintCancellation {
    fn is_cancelled(&self) -> bool {
        was_interrupted()
    }
}

pub fn install_handler() -> Result<(), KidoboError> {
    let result = SIGNAL_INSTALL_RESULT.get_or_init(|| {
        ctrlc::set_handler(|| {
            INTERRUPTED.store(true, Ordering::SeqCst);
        })
        .map_err(|err| err.to_string())
    });

    match result {
        Ok(()) => Ok(()),
        Err(reason) => Err(KidoboError::SignalHandlerInstall {
            reason: reason.clone(),
        }),
    }
}

pub fn was_interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}
