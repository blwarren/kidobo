use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Read the entire file into a `String`, but cap how many bytes are read.
pub fn read_to_string_with_limit(path: &Path, max_bytes: usize) -> io::Result<String> {
    let bytes = read_bytes_with_limit(path, max_bytes)?;
    String::from_utf8(bytes).map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))
}

/// Read the entire file into a byte vector, while capping how many bytes are read.
pub fn read_bytes_with_limit(path: &Path, max_bytes: usize) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let mut reader = BufReader::new(file);
    read_to_end_with_limit(&mut reader, max_bytes, |limit| {
        format!("file exceeds {limit} byte limit")
    })
}

/// Read from any stream into a byte vector while capping how many bytes are read.
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

/// Atomically replace a file by writing a sibling temporary file and renaming it.
pub fn write_string_atomic(path: &Path, contents: &str) -> io::Result<()> {
    write_bytes_atomic(path, contents.as_bytes())
}

/// Atomically replace a file by writing a sibling temporary file and renaming it.
pub fn write_bytes_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let existing_permissions = fs::metadata(path).ok().map(|meta| meta.permissions());

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

                    fs::rename(&temp_path, path)?;
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

    use super::{read_bytes_with_limit, read_to_string_with_limit, write_string_atomic};

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
    fn atomic_write_replaces_existing_contents() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("atomic.txt");
        fs::write(&path, "before").expect("write");

        write_string_atomic(&path, "after").expect("atomic write");

        assert_eq!(read_to_string_with_limit(&path, 16).expect("read"), "after");
    }
}
