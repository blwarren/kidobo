//! Required remote-cache privacy preparation for mutating synchronization.

use std::path::Path;

use kidobo_app::AppError;
use kidobo_app::sync::SyncStoragePreparer;

/// Secures legacy and generation cache contents behind an owner-only directory.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSyncStorage;

impl SyncStoragePreparer for FileSyncStorage {
    fn prepare_remote_cache(&self, path: &Path) -> Result<(), AppError> {
        crate::private_fs::ensure_private_dir(path)
            .map(|_| ())
            .map_err(|source| AppError::StoragePreparation {
                path: path.to_path_buf(),
                source,
            })
    }
}
