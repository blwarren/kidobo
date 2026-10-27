//! Local blocklist filesystem adapter.

use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use log::warn;

use crate::limited_io::{
    read_to_string_with_limit, write_string_atomic, write_string_atomic_with_limit,
};
use kidobo_app::AppError;
use kidobo_app::blocklist::BlocklistRepository;
use kidobo_core::blocklist::canonicalize_blocklist;
use kidobo_core::blocklist::{BlocklistDocument as CoreBlocklistDocument, InvalidBlocklistLine};

/// Maximum accepted local blocklist size.
pub const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;
const BLOCKLIST_TARGET_FILE_READ_LIMIT: usize = 2 * 1024 * 1024;
const BLOCKLIST_FAST_STATE_VERSION: &str = "v1";
const BLOCKLIST_FAST_STATE_READ_LIMIT: usize = 1024;

/// Production local blocklist repository using bounded reads and atomic writes.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileBlocklistRepository;

impl BlocklistRepository for FileBlocklistRepository {
    fn load(&self, path: &Path) -> Result<CoreBlocklistDocument, AppError> {
        load_blocklist_document(path)
    }

    fn append_entries(
        &self,
        path: &Path,
        entries: &[String],
        has_content: bool,
        trailing_newline: bool,
    ) -> Result<(), AppError> {
        append_entries_with_limit(
            path,
            entries,
            has_content,
            trailing_newline,
            BLOCKLIST_READ_LIMIT,
        )
    }

    fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError> {
        write_blocklist_lines(path, lines)
    }

    fn read_target_lines(&self, path: &Path) -> Result<Vec<String>, AppError> {
        let contents =
            read_to_string_with_limit(path, BLOCKLIST_TARGET_FILE_READ_LIMIT).map_err(|error| {
                AppError::BlocklistTargetFileRead {
                    path: path.to_path_buf(),
                    source: error,
                }
            })?;
        Ok(contents.lines().map(ToString::to_string).collect())
    }
}

fn append_entries_with_limit(
    path: &Path,
    entries: &[String],
    has_content: bool,
    trailing_newline: bool,
    limit: usize,
) -> Result<(), AppError> {
    if entries.is_empty() {
        return Ok(());
    }
    ensure_blocklist_parent(path)?;
    let mut contents = match read_to_string_with_limit(path, limit) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(AppError::BlocklistRead {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    if has_content && !trailing_newline {
        contents.push('\n');
    }
    for entry in entries {
        contents.push_str(entry);
        contents.push('\n');
    }
    write_string_atomic_with_limit(path, &contents, limit).map_err(|error| {
        AppError::BlocklistWrite {
            path: path.to_path_buf(),
            source: error,
        }
    })
}

/// Result of checking or normalizing the local blocklist during sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistNormalizeResult {
    /// The blocklist did not exist and no file was created.
    MissingBlocklist,
    /// File metadata matched the previous successful normalization state.
    SkippedUnchanged,
    /// Contents were parsed and any canonical rewrite was completed.
    Checked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlocklistFastState {
    byte_len: u64,
    modified_nanos: u128,
}

impl BlocklistFastState {
    fn capture(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        let modified = metadata.modified().ok()?;
        let since_epoch = modified.duration_since(UNIX_EPOCH).ok()?;

        Some(Self {
            byte_len: metadata.len(),
            modified_nanos: since_epoch.as_nanos(),
        })
    }

    fn parse(contents: &str) -> Option<Self> {
        let mut parts = contents.split_whitespace();
        let version = parts.next()?;
        if version != BLOCKLIST_FAST_STATE_VERSION {
            return None;
        }

        let byte_len = parts.next()?.parse::<u64>().ok()?;
        let modified_nanos = parts.next()?.parse::<u128>().ok()?;
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            byte_len,
            modified_nanos,
        })
    }

    fn serialize(self) -> String {
        format!(
            "{} {} {}\n",
            BLOCKLIST_FAST_STATE_VERSION, self.byte_len, self.modified_nanos
        )
    }
}

/// Atomically replaces a blocklist with normalized line endings.
///
/// # Errors
///
/// Returns [`AppError::BlocklistWrite`] when the destination cannot be replaced atomically.
pub fn write_blocklist_lines<S: AsRef<str>>(path: &Path, lines: &[S]) -> Result<(), AppError> {
    write_blocklist_lines_with_limit(path, lines, BLOCKLIST_READ_LIMIT)
}

fn write_blocklist_lines_with_limit<S: AsRef<str>>(
    path: &Path,
    lines: &[S],
    limit: usize,
) -> Result<(), AppError> {
    let mut contents = lines
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\n");
    if !contents.is_empty() {
        contents.push('\n');
    }

    write_string_atomic_with_limit(path, &contents, limit).map_err(|err| AppError::BlocklistWrite {
        path: path.to_path_buf(),
        source: err,
    })
}

/// Creates the blocklist's parent directory when necessary.
///
/// # Errors
///
/// Returns [`AppError::BlocklistWrite`] when the parent directory cannot be created.
pub fn ensure_blocklist_parent(path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AppError::BlocklistWrite {
            path: parent.to_path_buf(),
            source: err,
        })?;
    }

    Ok(())
}

/// Validates and atomically canonicalizes an existing local blocklist.
///
/// # Errors
///
/// Returns an error when the file cannot be read or written, or contains an invalid blocklist
/// entry.
pub fn normalize_local_blocklist(path: &Path) -> Result<(), AppError> {
    normalize_local_blocklist_with_limit(path, BLOCKLIST_READ_LIMIT)
}

fn normalize_local_blocklist_with_limit(path: &Path, limit: usize) -> Result<(), AppError> {
    let original = match read_to_string_with_limit(path, limit) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(AppError::BlocklistRead {
                path: path.to_path_buf(),
                source,
            });
        }
    };

    let normalized =
        canonicalize_blocklist(&original).map_err(|err| map_invalid_blocklist_line(path, err))?;

    if normalized != original {
        write_string_atomic_with_limit(path, &normalized, limit).map_err(|err| {
            AppError::BlocklistWrite {
                path: path.to_path_buf(),
                source: err,
            }
        })?;
    }

    Ok(())
}

/// Canonicalizes a changed blocklist and updates its best-effort fast-state sidecar.
///
/// # Errors
///
/// Returns an error when required blocklist validation, reading, or writing fails. Sidecar write
/// failures remain warnings.
pub fn normalize_local_blocklist_with_fast_state(
    blocklist_path: &Path,
    fast_state_path: &Path,
) -> Result<BlocklistNormalizeResult, AppError> {
    if !blocklist_path
        .try_exists()
        .map_err(|source| AppError::BlocklistRead {
            path: blocklist_path.to_path_buf(),
            source,
        })?
    {
        return Ok(BlocklistNormalizeResult::MissingBlocklist);
    }

    let current_state = BlocklistFastState::capture(blocklist_path);
    let cached_state = read_blocklist_fast_state(fast_state_path);
    if current_state
        .zip(cached_state)
        .is_some_and(|(current, cached)| current == cached)
    {
        return Ok(BlocklistNormalizeResult::SkippedUnchanged);
    }

    normalize_local_blocklist(blocklist_path)?;

    if let Some(final_state) = BlocklistFastState::capture(blocklist_path)
        && let Err(err) = write_blocklist_fast_state(fast_state_path, final_state)
    {
        warn!(
            "best-effort blocklist fast-state write failed for {} ({err})",
            fast_state_path.display()
        );
    }

    Ok(BlocklistNormalizeResult::Checked)
}

fn read_blocklist_fast_state(path: &Path) -> Option<BlocklistFastState> {
    let contents = read_to_string_with_limit(path, BLOCKLIST_FAST_STATE_READ_LIMIT).ok()?;
    BlocklistFastState::parse(&contents)
}

fn write_blocklist_fast_state(
    path: &Path,
    state: BlocklistFastState,
) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_string_atomic(path, &state.serialize())
}

/// Loads and parses an existing blocklist, treating a missing file as empty.
///
/// # Errors
///
/// Returns an error when the file cannot be read within its bound or contains an invalid
/// entry.
pub fn load_blocklist_document(path: &Path) -> Result<CoreBlocklistDocument, AppError> {
    let contents = match read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(source) => {
            return Err(AppError::BlocklistRead {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    CoreBlocklistDocument::parse(&contents).map_err(|err| map_invalid_blocklist_line(path, err))
}

fn map_invalid_blocklist_line(path: &Path, err: InvalidBlocklistLine) -> AppError {
    AppError::BlocklistParseLine {
        path: path.to_path_buf(),
        line: err.line_number,
        content: err.content,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use kidobo_app::blocklist::BlocklistRepository;
    use tempfile::TempDir;

    use super::{
        BLOCKLIST_TARGET_FILE_READ_LIMIT, BlocklistNormalizeResult, FileBlocklistRepository,
        load_blocklist_document, normalize_local_blocklist_with_fast_state,
    };
    use crate::limited_io::read_to_string_with_limit;

    fn read(path: &std::path::Path) -> String {
        read_to_string_with_limit(path, super::BLOCKLIST_READ_LIMIT).expect("read")
    }

    fn assert_contents(actual: &str, expected: &str) {
        // Report mismatches without dumping production-sized fixtures.
        assert_eq!(actual.len(), expected.len());
        assert_eq!(
            actual
                .bytes()
                .zip(expected.bytes())
                .position(|(a, b)| a != b),
            None
        );
    }

    const TEST_WRITE_LIMIT: usize = 128;

    #[test]
    fn production_limit_allows_readable_replacement_and_rejects_append() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist");
        let line = format!("#{}", "x".repeat(super::BLOCKLIST_READ_LIMIT - 2));
        FileBlocklistRepository
            .write_lines(&path, std::slice::from_ref(&line))
            .expect("exact production limit");
        assert_eq!(
            fs::metadata(&path).expect("metadata").len(),
            16 * 1024 * 1024
        );
        load_blocklist_document(&path).expect("production-size document is readable");
        assert!(matches!(
            FileBlocklistRepository.append_entries(&path, &["192.0.2.1/32".into()], true, true),
            Err(kidobo_app::AppError::BlocklistWrite { .. })
        ));
        assert_contents(&read(&path), &format!("{line}\n"));
    }

    #[test]
    fn append_enforces_serialized_byte_limit_and_preserves_rejected_file() {
        for trailing_newline in [false, true] {
            for size in [TEST_WRITE_LIMIT - 1, TEST_WRITE_LIMIT, TEST_WRITE_LIMIT + 1] {
                let temp = TempDir::new().expect("tempdir");
                let path = temp.path().join("blocklist");
                let entry = "192.0.2.1/32";
                let original_len = size - entry.len() - 1 - usize::from(!trailing_newline);
                let mut original = format!(
                    "#é{}",
                    "x".repeat(original_len - 3 - usize::from(trailing_newline))
                );
                if trailing_newline {
                    original.push('\n');
                }
                fs::write(&path, &original).expect("fixture");
                let result = super::append_entries_with_limit(
                    &path,
                    &[entry.to_string()],
                    true,
                    trailing_newline,
                    TEST_WRITE_LIMIT,
                );
                if size > TEST_WRITE_LIMIT {
                    assert!(matches!(
                        result,
                        Err(kidobo_app::AppError::BlocklistWrite { .. })
                    ));
                    assert_contents(&read(&path), &original);
                } else {
                    result.expect("within limit");
                    let expected = format!(
                        "{}{}{}\n",
                        original,
                        if trailing_newline { "" } else { "\n" },
                        entry
                    );
                    assert_contents(&read(&path), &expected);
                    assert_eq!(expected.len(), size);
                    load_blocklist_document(&path).expect("readable");
                }
            }
        }
    }

    #[test]
    fn replacement_enforces_serialized_byte_limit() {
        for size in [TEST_WRITE_LIMIT - 1, TEST_WRITE_LIMIT, TEST_WRITE_LIMIT + 1] {
            let temp = TempDir::new().expect("tempdir");
            let path = temp.path().join("blocklist");
            fs::write(&path, "192.0.2.0/24\n").expect("fixture");
            let line = format!("#é{}", "x".repeat(size - 4));
            let result = super::write_blocklist_lines_with_limit(
                &path,
                std::slice::from_ref(&line),
                TEST_WRITE_LIMIT,
            );
            if size > TEST_WRITE_LIMIT {
                assert!(matches!(
                    result,
                    Err(kidobo_app::AppError::BlocklistWrite { .. })
                ));
                assert_eq!(read(&path), "192.0.2.0/24\n");
            } else {
                result.expect("within limit");
                assert_contents(&read(&path), &format!("{line}\n"));
                load_blocklist_document(&path).expect("readable");
            }
        }
    }

    #[test]
    fn normalization_growth_enforces_serialized_byte_limit() {
        for size in [TEST_WRITE_LIMIT - 1, TEST_WRITE_LIMIT, TEST_WRITE_LIMIT + 1] {
            let temp = TempDir::new().expect("tempdir");
            let path = temp.path().join("blocklist");
            let header = format!("#é{}\n", "x".repeat(size - 5 - "192.0.2.1/32\n".len()));
            let original = format!("{header}192.0.2.1");
            fs::write(&path, &original).expect("fixture");
            let result = super::normalize_local_blocklist_with_limit(&path, TEST_WRITE_LIMIT);
            if size > TEST_WRITE_LIMIT {
                assert!(matches!(
                    result,
                    Err(kidobo_app::AppError::BlocklistWrite { .. })
                ));
                assert_contents(&read(&path), &original);
            } else {
                result.expect("within limit");
                assert_contents(&read(&path), &format!("{header}\n192.0.2.1/32\n"));
                load_blocklist_document(&path).expect("readable");
            }
        }
    }

    #[test]
    fn repository_append_preserves_unterminated_content() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("nested/blocklist.txt");
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, "# header").expect("write");

        FileBlocklistRepository
            .append_entries(&path, &["192.0.2.0/24".to_string()], true, false)
            .expect("append");

        assert_eq!(read(&path), "# header\n192.0.2.0/24\n");
    }

    #[test]
    fn repository_append_creates_missing_parent() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("nested/blocklist.txt");

        FileBlocklistRepository
            .append_entries(&path, &["192.0.2.0/24".to_string()], false, false)
            .expect("append");

        assert_eq!(read(&path), "192.0.2.0/24\n");
    }

    #[test]
    fn repository_write_lines_is_newline_terminated() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");

        FileBlocklistRepository
            .write_lines(
                &path,
                &["# header".to_string(), "2001:db8::/64".to_string()],
            )
            .expect("write");

        assert_eq!(read(&path), "# header\n2001:db8::/64\n");
    }

    #[test]
    fn repository_target_reader_enforces_limit() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("targets.txt");
        fs::write(&path, "1".repeat(BLOCKLIST_TARGET_FILE_READ_LIMIT + 1)).expect("write");

        let error = FileBlocklistRepository
            .read_target_lines(&path)
            .expect_err("oversized targets must fail");

        assert!(
            error
                .to_string()
                .contains("file exceeds 2097152 byte limit")
        );
    }

    #[test]
    fn document_load_reports_invalid_line_without_rewriting() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        let original = "# header\n192.0.2.1 trailing\n";
        fs::write(&path, original).expect("write");

        let error = load_blocklist_document(&path).expect_err("invalid line must fail");

        assert!(error.to_string().contains("at line 2"));
        assert_eq!(read(&path), original);
    }

    #[test]
    fn fast_state_skips_unchanged_blocklist_after_first_check() {
        let temp = TempDir::new().expect("tempdir");
        let blocklist = temp.path().join("data/blocklist.txt");
        let state = temp.path().join("cache/blocklist.fast-state");
        fs::create_dir_all(blocklist.parent().expect("parent")).expect("mkdir");
        fs::write(&blocklist, "192.0.2.1\n").expect("write");

        assert_eq!(
            normalize_local_blocklist_with_fast_state(&blocklist, &state).expect("normalize"),
            BlocklistNormalizeResult::Checked
        );
        assert_eq!(
            normalize_local_blocklist_with_fast_state(&blocklist, &state).expect("normalize"),
            BlocklistNormalizeResult::SkippedUnchanged
        );
        assert_eq!(read(&blocklist), "192.0.2.1/32\n");
    }

    #[test]
    fn document_loader_preserves_missing_empty_and_valid_contents() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        let missing = load_blocklist_document(&path).expect("missing document");
        assert!(!path.exists());
        assert_eq!(
            missing.lines,
            Vec::<kidobo_core::blocklist::BlocklistLine>::new()
        );
        assert!(!missing.has_content);
        assert!(!missing.trailing_newline);

        fs::write(&path, b"").expect("empty file");
        assert_eq!(
            load_blocklist_document(&path).expect("empty document"),
            missing
        );
        for contents in ["# header\n203.0.113.7\n2001:db8::/64\n", "203.0.113.7"] {
            fs::write(&path, contents).expect("valid file");
            assert_eq!(
                load_blocklist_document(&path).expect("valid document"),
                kidobo_core::blocklist::BlocklistDocument::parse(contents)
                    .expect("parsed document")
            );
            assert_eq!(read(&path), contents);
        }
    }

    #[test]
    fn document_loader_rejects_non_utf8_and_oversized_files_without_rewriting() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        for contents in [vec![0xff], vec![b'#'; super::BLOCKLIST_READ_LIMIT + 1]] {
            fs::write(&path, &contents).expect("invalid file");
            let error = load_blocklist_document(&path).expect_err("invalid document");
            assert!(
                matches!(&error, kidobo_app::AppError::BlocklistRead { path: failed_path, source } if failed_path == &path && source.kind() == std::io::ErrorKind::InvalidData)
            );
            assert_eq!(
                std::error::Error::source(&error)
                    .expect("read cause")
                    .downcast_ref::<std::io::Error>()
                    .expect("I/O cause")
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
            assert_eq!(
                fs::metadata(&path).expect("metadata").len(),
                u64::try_from(contents.len()).expect("length")
            );
            assert_eq!(
                crate::limited_io::read_bytes_with_limit(&path, contents.len())
                    .expect("original bytes"),
                contents
            );
        }
    }

    #[test]
    fn fast_state_reports_missing_blocklist_without_writes() {
        let temp = TempDir::new().expect("tempdir");
        let blocklist = temp.path().join("data/blocklist.txt");
        let state = temp.path().join("cache/blocklist.fast-state");

        assert_eq!(
            normalize_local_blocklist_with_fast_state(&blocklist, &state).expect("normalize"),
            BlocklistNormalizeResult::MissingBlocklist
        );
        assert!(!state.exists());
    }
}
