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
    #[error("failed to create lock parent directory {path}: {source}")]
    CreateParentDir {
        /// Parent directory path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// The lock file could not be opened securely.
    #[error("failed to open lock file {path}: {source}")]
    OpenFile {
        /// Lock file path.
        path: PathBuf,
        /// Filesystem diagnostic, including symlink rejection on Unix.
        #[source]
        source: std::io::Error,
    },

    /// The opened lock file could not be hardened to owner-only permissions.
    #[error("failed to set lock file permissions on {path}: {source}")]
    SetPermissions {
        /// Lock file path.
        path: PathBuf,
        /// Filesystem diagnostic.
        #[source]
        source: std::io::Error,
    },

    /// Another process currently owns the nonblocking lock.
    #[error("lock already held: {path}")]
    AlreadyHeld {
        /// Contended lock file path.
        path: PathBuf,
        /// Original nonblocking lock failure.
        #[source]
        source: io::Error,
    },

    /// The operating-system lock operation failed unexpectedly.
    #[error("failed to acquire lock {path}: {source}")]
    Acquire {
        /// Lock file path.
        path: PathBuf,
        /// Locking diagnostic.
        #[source]
        source: std::io::Error,
    },
}

/// Open-file guard that owns an acquired shared or exclusive process lock.
#[derive(Debug)]
pub struct FileLock {
    file: File,
}

impl LockGuard for FileLock {}

/// Production nonblocking lock manager.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileLockManager;

/// Opens only an existing regular lock file, without creating or hardening filesystem state.
#[derive(Debug, Default, Clone, Copy)]
pub struct ReadOnlyFileLockManager;

impl kidobo_app::preview::SharedLockManager for ReadOnlyFileLockManager {
    fn acquire_existing(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
        acquire_existing_shared(path)
            .map(|guard| -> Box<dyn LockGuard> { Box::new(guard) })
            .map_err(|source| AppError::Lock {
                source: Box::new(source),
            })
    }
}

fn acquire_existing_shared(path: &Path) -> Result<FileLock, LockError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC | nix::libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(|source| LockError::OpenFile {
        path: path.to_path_buf(),
        source,
    })?;
    let metadata = file.metadata().map_err(|source| LockError::OpenFile {
        path: path.to_path_buf(),
        source,
    })?;
    if !metadata.is_file() {
        return Err(LockError::OpenFile {
            path: path.to_path_buf(),
            source: io::Error::new(
                io::ErrorKind::InvalidInput,
                "existing process lock must be a regular file",
            ),
        });
    }
    match FileExt::try_lock_shared(&file) {
        Ok(()) => Ok(FileLock { file }),
        Err(source) if source.kind() == io::ErrorKind::WouldBlock => Err(LockError::AlreadyHeld {
            path: path.to_path_buf(),
            source,
        }),
        Err(source) => Err(LockError::Acquire {
            path: path.to_path_buf(),
            source,
        }),
    }
}

impl LockManager for FileLockManager {
    fn acquire(&self, path: &Path) -> Result<Box<dyn LockGuard>, AppError> {
        acquire_non_blocking(path)
            .map(|lock| {
                let guard: Box<dyn LockGuard> = Box::new(lock);
                guard
            })
            .map_err(|error| AppError::Lock {
                source: Box::new(error),
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
            source: err,
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
        source: err,
    })?;

    enforce_mode_0600(&file, path)?;

    match file.try_lock_exclusive() {
        Ok(()) => Ok(FileLock { file }),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Err(LockError::AlreadyHeld {
            path: path.to_path_buf(),
            source: err,
        }),
        Err(err) => Err(LockError::Acquire {
            path: path.to_path_buf(),
            source: err,
        }),
    }
}

fn enforce_mode_0600(file: &File, path: &Path) -> Result<(), LockError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|err| LockError::SetPermissions {
                path: path.to_path_buf(),
                source: err,
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

    use super::{LockError, acquire_non_blocking};

    #[test]
    fn second_acquire_fails_when_held() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("sync.lock");

        let _lock = acquire_non_blocking(&path).expect("first lock");
        let err = acquire_non_blocking(&path).expect_err("second lock must fail");

        assert!(
            matches!(&err, LockError::AlreadyHeld { path: failed_path, source } if failed_path == &path && source.kind() == io::ErrorKind::WouldBlock)
        );
        assert_eq!(
            std::error::Error::source(&err)
                .expect("contention cause")
                .downcast_ref::<io::Error>()
                .expect("I/O cause")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            err.to_string(),
            format!("lock already held: {}", path.display())
        );
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

    #[test]
    fn shared_preview_lock_never_creates_missing_state() {
        let root = TempDir::new().expect("root");
        let path = root.path().join("absent/sync.lock");
        match super::acquire_existing_shared(&path).expect_err("existing file required") {
            LockError::OpenFile { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::NotFound);
            }
            other => panic!("unexpected error: {other:?}"),
        }
        assert!(!path.parent().expect("parent").exists());
        assert!(matches!(
            super::acquire_existing_shared(root.path()).expect_err("regular file required"),
            LockError::OpenFile { .. }
        ));
    }

    #[test]
    fn shared_preview_guards_cooperate_and_exclude_source_mutations() {
        let root = TempDir::new().expect("root");
        let path = root.path().join("sync.lock");
        let initial = acquire_non_blocking(&path).expect("initialize lock fixture");
        drop(initial);
        let first = super::acquire_existing_shared(&path).expect("first reader");
        let second = super::acquire_existing_shared(&path).expect("second reader");
        assert!(matches!(
            acquire_non_blocking(&path).expect_err("writer excluded"),
            LockError::AlreadyHeld { .. }
        ));
        drop((first, second));
        let writer = acquire_non_blocking(&path).expect("read guards released");
        assert!(matches!(
            super::acquire_existing_shared(&path).expect_err("writer excludes reader"),
            LockError::AlreadyHeld { .. }
        ));
        drop(writer);
    }

    #[cfg(unix)]
    #[test]
    fn shared_preview_lock_preserves_bytes_mode_and_mtime_and_rejects_symlinks() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let root = TempDir::new().expect("root");
        let path = root.path().join("sync.lock");
        fs::write(&path, "preserve").expect("fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode");
        let before = fs::metadata(&path).expect("metadata");
        let guard = super::acquire_existing_shared(&path).expect("read only lock");
        drop(guard);
        let after = fs::metadata(&path).expect("metadata after");
        assert_eq!(
            before.modified().expect("mtime"),
            after.modified().expect("mtime")
        );
        assert_eq!(after.permissions().mode() & 0o777, 0o640);
        assert_eq!(
            read_bytes_with_limit(&path, 16).expect("bytes"),
            b"preserve"
        );
        let link = root.path().join("symlink.lock");
        symlink(&path, &link).expect("symlink");
        assert!(matches!(
            super::acquire_existing_shared(&link).expect_err("symlink rejected"),
            LockError::OpenFile { .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn shared_preview_lock_rejects_fifo_without_waiting_for_a_writer() {
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::mpsc;
        use std::time::Duration;
        let root = TempDir::new().expect("root");
        let path = root.path().join("fifo.lock");
        nix::unistd::mkfifo(
            &path,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .expect("FIFO fixture");
        let (send, receive) = mpsc::channel();
        let fifo = path.clone();
        let worker = std::thread::spawn(move || {
            send.send(super::acquire_existing_shared(&fifo))
                .expect("result receiver");
        });
        let result = receive.recv_timeout(Duration::from_secs(2));
        // Unblock a regressed implementation before failing, so the test itself stays bounded.
        let _wakeup = result.is_err().then(|| {
            fs::OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(nix::libc::O_NONBLOCK)
                .open(&path)
                .expect("release blocked FIFO reader")
        });
        worker.join().expect("reader joined");
        match result
            .expect("lock file type must be rejected without waiting")
            .expect_err("FIFO is not a regular lock")
        {
            LockError::OpenFile { source, .. } => {
                assert_eq!(source.kind(), io::ErrorKind::InvalidInput);
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
