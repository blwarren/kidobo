use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LockError {
    #[error("failed to create lock parent directory {path}: {reason}")]
    CreateParentDir { path: PathBuf, reason: String },

    #[error("failed to open lock file {path}: {reason}")]
    OpenFile { path: PathBuf, reason: String },

    #[error("failed to set lock file permissions on {path}: {reason}")]
    SetPermissions { path: PathBuf, reason: String },

    #[error("lock already held: {path}")]
    AlreadyHeld { path: PathBuf },

    #[error("failed to acquire lock {path}: {reason}")]
    Acquire { path: PathBuf, reason: String },
}

#[derive(Debug)]
pub struct FileLock {
    file: File,
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _unlock_result = self.file.unlock();
    }
}

pub fn acquire_non_blocking(path: &Path) -> Result<FileLock, LockError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| LockError::CreateParentDir {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)
        .map_err(|err| LockError::OpenFile {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;

    enforce_mode_0600(path)?;

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

fn enforce_mode_0600(path: &Path) -> Result<(), LockError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            LockError::SetPermissions {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{LockError, acquire_non_blocking};

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
}
