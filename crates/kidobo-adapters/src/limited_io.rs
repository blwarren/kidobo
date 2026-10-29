//! Bounded and atomic filesystem I/O helpers.

use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Reads the entire file as UTF-8 while enforcing a byte limit.
///
/// # Errors
///
/// Returns an I/O error when the path does not resolve to a regular file, cannot be read,
/// exceeds `max_bytes`, or is not valid UTF-8.
pub fn read_to_string_with_limit(path: &Path, max_bytes: usize) -> io::Result<String> {
    let bytes = read_bytes_with_limit(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Reads the entire file while enforcing a byte limit.
///
/// # Errors
///
/// Returns an I/O error when the path does not resolve to a regular file, cannot be read,
/// or exceeds `max_bytes`.
pub fn read_bytes_with_limit(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(nix::libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must be a regular file",
        ));
    }
    let mut reader = BufReader::new(file);
    read_to_end_with_limit(&mut reader, max_bytes, |limit| {
        format!("file exceeds {limit} byte limit")
    })
}

/// Reads a stream to completion while enforcing a byte limit.
///
/// # Errors
///
/// Returns an I/O error when reading fails or the stream exceeds `max_bytes`.
pub fn read_to_end_with_limit<F>(
    reader: &mut impl Read,
    max_bytes: usize,
    over_limit_message: F,
) -> io::Result<Vec<u8>>
where
    F: FnOnce(usize) -> String,
{
    let extra_byte_limit = u64::try_from(max_bytes)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1);
    let mut limited = reader.take(extra_byte_limit);
    let mut contents = Vec::new();
    limited.read_to_end(&mut contents)?;

    if contents.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            over_limit_message(max_bytes),
        ));
    }

    Ok(contents)
}

/// Rejects oversized UTF-8 content before creating or replacing any file.
///
/// # Errors
///
/// Returns an I/O error when the content exceeds the byte limit or atomic writing fails.
pub(crate) fn write_string_atomic_with_limit(
    path: &Path,
    contents: &str,
    max_bytes: usize,
) -> io::Result<()> {
    if contents.len() > max_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {max_bytes} byte limit"),
        ));
    }
    write_string_atomic(path, contents)
}

/// Atomically replaces a UTF-8 file through a sibling temporary file.
///
/// # Errors
///
/// Returns an I/O error when temporary-file creation, writing, synchronization, permission
/// preservation, replacement, or parent-directory synchronization fails.
pub fn write_string_atomic(path: &Path, contents: &str) -> io::Result<()> {
    write_bytes_atomic(path, contents.as_bytes())
}

/// Atomically replaces a file through a sibling temporary file.
///
/// # Errors
///
/// Returns an I/O error when temporary-file creation, writing, synchronization, permission
/// preservation, replacement, or parent-directory synchronization fails.
pub fn write_bytes_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    write_bytes_atomic_mode(path, contents, PublicationMode::Replace)
}

/// Publishes a complete file without replacing an existing destination.
pub(crate) fn create_string_atomic(path: &Path, contents: &str) -> io::Result<()> {
    write_bytes_atomic_mode(path, contents.as_bytes(), PublicationMode::CreateNew)
}

#[derive(Clone, Copy)]
enum PublicationMode {
    Replace,
    CreateNew,
}

fn write_bytes_atomic_mode(path: &Path, contents: &[u8], mode: PublicationMode) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let existing_permissions = match mode {
        PublicationMode::CreateNew => None,
        PublicationMode::Replace => match fs::metadata(path) {
            Ok(metadata) => Some(metadata.permissions()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(error) => return Err(error),
        },
    };

    for _ in 0..16 {
        let temp_path = temp_write_path(parent, path);
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);

        match options.open(&temp_path) {
            Ok(mut temp_file) => {
                let write_result = (|| {
                    if let Some(permissions) = &existing_permissions {
                        fs::set_permissions(&temp_path, permissions.clone())?;
                    }

                    temp_file.write_all(contents)?;
                    temp_file.sync_all()?;
                    drop(temp_file);

                    #[cfg(test)]
                    publication_test::before_publish();

                    match mode {
                        PublicationMode::Replace => fs::rename(&temp_path, path)?,
                        PublicationMode::CreateNew => {
                            let publication = fs::hard_link(&temp_path, path);
                            fs::remove_file(&temp_path)?;
                            sync_directory(parent)?;
                            return publication;
                        }
                    }
                    sync_directory(parent)
                })();

                if let Err(err) = write_result {
                    let _cleanup_result = fs::remove_file(&temp_path);
                    return Err(err);
                }

                return Ok(());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        format!(
            "failed to create unique temporary file for atomic write to {}",
            path.display()
        ),
    ))
}

#[cfg(test)]
pub(crate) mod publication_test {
    use std::cell::RefCell;

    thread_local! {
        static BEFORE_PUBLISH: RefCell<Option<Box<dyn FnOnce()>>> = const { RefCell::new(None) };
    }

    pub(super) fn before_publish() {
        let callback = BEFORE_PUBLISH.with(|slot| slot.borrow_mut().take());
        if let Some(callback) = callback {
            callback();
        }
    }

    pub(crate) fn interleave<T>(before: impl FnOnce() + 'static, action: impl FnOnce() -> T) -> T {
        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                BEFORE_PUBLISH.with(|slot| *slot.borrow_mut() = None);
            }
        }
        BEFORE_PUBLISH.with(|slot| {
            assert!(
                slot.borrow().is_none(),
                "publication hooks must not overlap"
            );
            *slot.borrow_mut() = Some(Box::new(before));
        });
        let _reset = Reset;
        action()
    }
}

fn temp_write_path(parent: &Path, path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("kidobo");
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".{file_name}.kidobo-tmp-{}-{counter}",
        process::id()
    ))
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        File::open(path)?.sync_all()?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{read_bytes_with_limit, read_to_string_with_limit};

    #[test]
    fn read_to_string_with_limit_errors_when_file_exceeds_limit() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("oversized.txt");
        fs::write(&path, "abcd").expect("write");

        let err = read_to_string_with_limit(&path, 3).expect_err("must fail");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(err.to_string(), "file exceeds 3 byte limit");
    }

    #[test]
    fn read_bytes_with_limit_accepts_exact_limit() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("bytes.txt");
        fs::write(&path, [0_u8, 1, 2]).expect("write");

        let bytes = read_bytes_with_limit(&path, 3).expect("read");
        assert_eq!(bytes, vec![0, 1, 2]);
    }

    #[test]
    fn bounded_file_reader_requires_a_regular_file() {
        let temp = TempDir::new().expect("tempdir");
        let error = read_bytes_with_limit(temp.path(), 16).expect_err("directory rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(error.to_string(), "input must be a regular file");
    }

    #[cfg(unix)]
    #[test]
    fn bounded_file_reader_follows_regular_symlinks_and_rejects_devices() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("file");
        let link = temp.path().join("link");
        fs::write(&file, b"abc").expect("write");
        std::os::unix::fs::symlink(&file, &link).expect("symlink");
        assert_eq!(read_bytes_with_limit(&link, 3).expect("read link"), b"abc");
        let error = read_bytes_with_limit(std::path::Path::new("/dev/null"), 16)
            .expect_err("device rejected");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn bounded_file_reader_preserves_invalid_utf8_error() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("invalid.txt");
        fs::write(&file, [0xff]).expect("write");
        let error = read_to_string_with_limit(&file, 1).expect_err("invalid UTF-8");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(read_bytes_with_limit(&file, 1).expect("raw bytes"), [0xff]);
    }

    #[test]
    fn atomic_creation_reports_existing_destination_and_removes_staging_file() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        fs::write(&path, "saved contents").expect("existing file");
        let error = super::create_string_atomic(&path, "replacement")
            .expect_err("existing destination must not be replaced");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            read_to_string_with_limit(&path, 1024).expect("read"),
            "saved contents"
        );
        assert_eq!(fs::read_dir(temp.path()).expect("directory").count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_creation_keeps_umask_and_replacement_keeps_existing_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().expect("tempdir");
        let control = temp.path().join("control");
        let path = temp.path().join("config.toml");
        fs::write(&control, "control").expect("default permissions");
        super::create_string_atomic(&path, "initial").expect("create");
        assert_eq!(
            fs::metadata(&path)
                .expect("created metadata")
                .permissions()
                .mode(),
            fs::metadata(&control)
                .expect("control metadata")
                .permissions()
                .mode()
        );
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("set permissions");
        super::write_string_atomic(&path, "replacement").expect("replace");
        assert_eq!(
            fs::metadata(&path)
                .expect("replacement metadata")
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        assert_eq!(
            read_to_string_with_limit(&path, 1024).expect("read"),
            "replacement"
        );
        assert_eq!(fs::read_dir(temp.path()).expect("directory").count(), 2);
    }
}
