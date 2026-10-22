//! Focused persistence and time capabilities for temporary ban workflows.

use std::path::Path;

use kidobo_core::temporary_bans::TemporaryBans;

use crate::AppError;
use crate::source::Notice;

/// Wall-clock time used to create deadlines and capture command-wide cutoffs.
pub trait Clock {
    /// Returns elapsed whole seconds since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns an error if the clock cannot provide a supported Unix timestamp.
    fn now_unix_secs(&self) -> Result<u64, AppError>;
}

/// Bounded, atomic storage for operator-managed temporary ban records.
pub trait TemporaryBanRepository {
    /// Reads and validates all records; a missing file represents empty state.
    ///
    /// # Errors
    ///
    /// Returns an error on any other read failure or invalid state.
    fn load(&self, path: &Path) -> Result<TemporaryBans, AppError>;

    /// Validates and atomically writes all records while the caller holds the lock.
    ///
    /// # Errors
    ///
    /// Returns an error if validation or persistence fails.
    fn save(&self, path: &Path, state: &TemporaryBans) -> Result<(), AppError>;
}

/// Warns that a configured kernel timeout operates separately from source expiry.
#[must_use]
pub fn kernel_timeout_notice() -> Notice {
    Notice::warning(
        "ipset.timeout is nonzero: kernel entries can expire independently of temporary ban deadlines; temporary bans are added and removed by sync",
    )
}
