//! Nonblocking process lock adapter.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use kidobo_app::AppError;
use kidobo_app::ports::{LockGuard, LockManager};
use thiserror::Error;

/// Failure while securely creating or acquiring the process lock.
#[derive(Debug, Error)]
pub enum LockError {
    /// The lock file's parent directory could not be created.
    #[error("failed to create lock parent directory {path}: {reason}")]
    CreateParentDir {
        /// Parent directory path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// The lock file could not be opened securely.
    #[error("failed to open lock file {path}: {reason}")]
    OpenFile {
        /// Lock file path.
        path: PathBuf,
        /// Filesystem diagnostic, including symlink rejection on Unix.
        reason: String,
    },

    /// The opened lock file could not be hardened to owner-only permissions.
    #[error("failed to set lock file permissions on {path}: {reason}")]
    SetPermissions {
        /// Lock file path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// Another process currently owns the nonblocking lock.
    #[error("lock already held: {path}")]
    AlreadyHeld {
        /// Contended lock file path.
        path: PathBuf,
    },

    /// The operating-system lock operation failed unexpectedly.
    #[error("failed to acquire lock {path}: {reason}")]
    Acquire {
        /// Lock file path.
        path: PathBuf,
        /// Locking diagnostic.
        reason: String,
    },
}

/// Open-file guard that owns an acquired exclusive process lock.
#[derive(Debug)]
pub struct FileLock {
    file: File,
}

impl LockGuard for FileLock {}

/// Production nonblocking lock manager.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileLockManager;

impl LockManager for FileLockManager {
    fn acquire(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
        acquire_non_blocking(path)
            .map(|lock| {
                let guard: Box<dyn LockGuard> = Box::new(lock);
                guard
            })
            .map_err(|error| AppError::Lock {
                reason: error.to_string(),
            })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _unlock_result = self.file.unlock();
    }
}

/// Opens a permission-hardened lock file and acquires it without blocking.
///
/// # Errors
///
/// Returns [`LockError`] when the parent or file cannot be prepared securely, another process
/// holds the lock, or the operating-system lock operation fails.
pub fn acquire_non_blocking(path: &Path) -> Result<FileLock, LockError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| LockError::CreateParentDir {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true).truncate(false);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC);
    }

    let file = options.open(path).map_err(|err| LockError::OpenFile {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;

    enforce_mode_0600(&file, path)?;

    match file.try_lock_exclusive() {
        Ok(()) => Ok(FileLock { file }),
        Err(err) if is_would_block(&err) => Err(LockError::AlreadyHeld {
            path: path.to_path_buf(),
        }),
        Err(err) => Err(LockError::Acquire {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }),
    }
}

fn is_would_block(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::WouldBlock
}

fn enforce_mode_0600(file: &File, path: &Path) -> Result<(), LockError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| LockError::SetPermissions {
                path: path.to_path_buf(),
                reason: err.to_string(),
            })?;
    }

    #[cfg(not(unix))]
    let _ = (file, path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io;

    use tempfile::TempDir;

    use crate::limited_io::read_bytes_with_limit;

    use super::{LockError, acquire_non_blocking, is_would_block};

    #[test]
    fn would_block_classifier_rejects_other_io_errors() {
        assert!(is_would_block(&io::Error::from(io::ErrorKind::WouldBlock)));
        assert!(!is_would_block(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
    }

    #[test]
    fn acquires_non_blocking_lock() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("sync.lock");

        let _lock = acquire_non_blocking(&path).expect("acquire");
        assert!(path.exists());
    }

    #[test]
    fn second_acquire_fails_when_held() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("sync.lock");

        let _lock = acquire_non_blocking(&path).expect("first lock");
        let err = acquire_non_blocking(&path).expect_err("second lock must fail");

        assert!(matches!(err, LockError::AlreadyHeld { .. }));
    }

    #[test]
    fn lock_is_released_on_drop() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("sync.lock");

        {
            let _lock = acquire_non_blocking(&path).expect("first lock");
        }

        let _second = acquire_non_blocking(&path).expect("second lock after drop");
    }

    #[cfg(unix)]
    #[test]
    fn lock_file_permissions_are_0600() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("sync.lock");

        let _lock = acquire_non_blocking(&path).expect("acquire");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_lock_file_is_rejected_without_touching_target() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temp = TempDir::new().expect("tempdir");
        let target = temp.path().join("target");
        let lock_path = temp.path().join("sync.lock");
        fs::write(&target, b"preserve").expect("write target");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("chmod target");
        symlink(&target, &lock_path).expect("create lock symlink");

        let error = acquire_non_blocking(&lock_path).expect_err("symlink must be rejected");

        assert!(matches!(error, LockError::OpenFile { .. }));
        assert_eq!(
            read_bytes_with_limit(&target, 16).expect("read target"),
            b"preserve"
        );
        let mode = fs::metadata(&target)
            .expect("target metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o644);
    }
}
