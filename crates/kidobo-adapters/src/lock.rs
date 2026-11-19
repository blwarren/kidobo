//! Nonblocking process lock adapter.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use fs2::FileExt;
use kidobo_app::AppError;
use kidobo_app::paths::PathResolutionInput;
use kidobo_app::ports::{FirewallTransactionLock, LockGuard, LockManager};
use thiserror::Error;

/// Failure while securely creating or acquiring the process lock.
#[derive(Debug, Error)]
pub enum LockError {
    /// The fixture lock would let a privileged process bypass firewall coordination.
    #[error(
        "firewall test sandbox requires unprivileged credentials and no new privileges: {source}"
    )]
    UnsafeTestSandbox {
        /// Credential verification or privilege restriction failure.
        #[source]
        source: io::Error,
    },
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

/// Acquires the Linux firewall transaction lock shared by all ordinary runtime roots.
#[derive(Debug)]
pub struct SystemFirewallTransactionLock<'a> {
    input: &'a PathResolutionInput,
}

impl<'a> SystemFirewallTransactionLock<'a> {
    /// Captures the runtime input, including the existing internal fixture sandbox selection.
    #[must_use]
    pub fn new(input: &'a PathResolutionInput) -> Self {
        Self { input }
    }
}

impl FirewallTransactionLock for SystemFirewallTransactionLock<'_> {
    fn acquire_firewall(&self) -> Result<Box<dyn LockGuard>, AppError> {
        let lock = if crate::path::test_sandbox_enabled(self.input) {
            acquire_test_firewall_lock(&self.input.temp_dir)
        } else {
            acquire_system_firewall_lock()
        };
        lock.map(|guard| -> Box<dyn LockGuard> { Box::new(guard) })
            .map_err(|source| AppError::Lock {
                source: Box::new(source),
            })
    }
}

fn acquire_test_firewall_lock(directory: &Path) -> Result<FileLock, LockError> {
    use std::os::unix::fs::OpenOptionsExt;

    let status = crate::limited_io::read_to_string_with_limit(
        Path::new("/proc/thread-self/status"),
        64 * 1024,
    )
    .map_err(|source| LockError::UnsafeTestSandbox { source })?;
    if !unprivileged_status(&status) {
        return Err(LockError::UnsafeTestSandbox {
            source: io::Error::new(io::ErrorKind::PermissionDenied, "privileged credentials"),
        });
    }
    // Every command spawned by this thread inherits this irreversible restriction.
    nix::sys::prctl::set_no_new_privs().map_err(|source| LockError::UnsafeTestSandbox {
        source: source.into(),
    })?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(directory)
        .map_err(|source| LockError::OpenFile {
            path: directory.to_path_buf(),
            source,
        })?;
    try_lock_file(file, directory)
}

fn unprivileged_status(status: &str) -> bool {
    let entry = |key| status.lines().find_map(|line| line.strip_prefix(key));
    let regular_uids = entry("Uid:").is_some_and(|uids| {
        uids.split_whitespace().count() == 4
            && uids
                .split_whitespace()
                .all(|uid| uid.parse::<std::num::NonZeroU32>().is_ok())
    });
    regular_uids
        && ["CapPrm:", "CapEff:", "CapAmb:"].into_iter().all(|key| {
            entry(key).and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok()) == Some(0)
        })
}

fn acquire_system_firewall_lock() -> Result<FileLock, LockError> {
    use nix::fcntl::{OFlag, openat};
    use nix::sys::stat::Mode;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    let netns_path = Path::new("/proc/self/ns/net");
    let namespace = fs::metadata(netns_path).map_err(|source| LockError::OpenFile {
        path: netns_path.to_path_buf(),
        source,
    })?;
    let directory_path = Path::new("/run/kidobo");
    match fs::DirBuilder::new().mode(0o700).create(directory_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(source) => {
            return Err(LockError::CreateParentDir {
                path: directory_path.to_path_buf(),
                source,
            });
        }
    }
    let directory_error = |source| LockError::OpenFile {
        path: directory_path.to_path_buf(),
        source,
    };
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW)
        .open(directory_path)
        .map_err(directory_error)?;
    let metadata = directory.metadata().map_err(directory_error)?;
    if metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(directory_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firewall lock directory must be root-owned and owner-only",
        )));
    }

    let name = format!("firewall-{}-{}.lock", namespace.dev(), namespace.ino());
    let path = directory_path.join(&name);
    let open_error = |source| LockError::OpenFile {
        path: path.clone(),
        source,
    };
    let fd = openat(
        &directory,
        Path::new(&name),
        OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|source| open_error(source.into()))?;
    let file = File::from(fd);
    let metadata = file.metadata().map_err(open_error)?;
    if !metadata.is_file() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(open_error(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "firewall lock must be a root-owned, owner-only regular file",
        )));
    }
    try_lock_file(file, &path)
}

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

    try_lock_file(file, path)
}

fn try_lock_file(file: File, path: &Path) -> Result<FileLock, LockError> {
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

    use super::{LockError, acquire_non_blocking, unprivileged_status};

    #[test]
    fn fixture_lock_rejects_root_capable_and_unreadable_credentials() {
        let regular = "Uid:\t1000\t1000\t1000\t1000\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n";
        assert!(unprivileged_status(regular));
        for privileged in [
            regular.replace("1000\t1000\t1000\t1000", "1000\t1000\t0\t1000"),
            regular.replace("CapPrm:\t0", "CapPrm:\t1000"),
            regular.replace("CapEff:\t0", "CapEff:\t1000"),
            regular.replace("CapAmb:\t0", "CapAmb:\t1000"),
            regular.replace("CapAmb:\t0\n", ""),
        ] {
            assert!(!unprivileged_status(&privileged), "{privileged}");
        }
    }

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
