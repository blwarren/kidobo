//! Logging and optional timing observer for the production sync workflow.

use std::sync::Mutex;
use std::time::Instant;

use kidobo_app::source::{Notice, NoticeLevel};
use kidobo_app::sync::SyncObserver;
use log::{info, warn};

#[derive(Debug)]
struct StageTimer {
    enabled: bool,
    overall_start: Instant,
    stage_start: Instant,
}

#[derive(Debug)]
/// Production sync observer that logs stages and optionally reports elapsed timing.
pub struct LoggingSyncObserver {
    timer: Mutex<StageTimer>,
}

impl LoggingSyncObserver {
    #[must_use]
    /// Creates an observer with optional timer diagnostics.
    pub fn new(timer_enabled: bool) -> Self {
        let now = Instant::now();
        Self {
            timer: Mutex::new(StageTimer {
                enabled: timer_enabled,
                overall_start: now,
                stage_start: now,
            }),
        }
    }
}

impl SyncObserver for LoggingSyncObserver {
    fn stage_completed(&self, stage: &'static str) {
        let mut timer = self
            .timer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !timer.enabled {
            return;
        }
        let now = Instant::now();
        let stage_ms = now.duration_since(timer.stage_start).as_millis();
        let total_ms = now.duration_since(timer.overall_start).as_millis();
        info!("sync timer: stage={stage} stage_ms={stage_ms} total_ms={total_ms}");
        timer.stage_start = now;
    }

    fn notice(&self, notice: &Notice) {
        match notice.level {
            NoticeLevel::Info => info!("{}", notice.message),
            NoticeLevel::Warning => warn!("{}", notice.message),
        }
    }
}
