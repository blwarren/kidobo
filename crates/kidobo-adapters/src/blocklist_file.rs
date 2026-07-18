//! Local blocklist filesystem adapter.

use std::fs;
use std::ops::Deref;
use std::path::Path;
use std::time::UNIX_EPOCH;

use log::warn;

use crate::limited_io::{read_to_string_with_limit, write_string_atomic};
use kidobo_app::AppError;
use kidobo_app::blocklist::BlocklistRepository;
use kidobo_core::blocklist::canonicalize_blocklist;
use kidobo_core::blocklist::{BlocklistDocument as CoreBlocklistDocument, InvalidBlocklistLine};

pub const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;
const BLOCKLIST_TARGET_FILE_READ_LIMIT: usize = 2 * 1024 * 1024;
const BLOCKLIST_FAST_STATE_VERSION: &str = "v1";
const BLOCKLIST_FAST_STATE_READ_LIMIT: usize = 1024;

#[derive(Debug, Clone)]
pub struct BlocklistDocument(CoreBlocklistDocument);

#[derive(Debug, Default, Clone, Copy)]
pub struct FileBlocklistRepository;

impl BlocklistRepository for FileBlocklistRepository {
    fn load(&self, path: &Path) -> Result<CoreBlocklistDocument, AppError> {
        BlocklistDocument::load(path).map(|document| document.0)
    }

    fn append_entries(
        &self,
        path: &Path,
        entries: &[String],
        has_content: bool,
        trailing_newline: bool,
    ) -> Result<(), AppError> {
        if entries.is_empty() {
            return Ok(());
        }
        ensure_blocklist_parent(path)?;
        let mut contents = if path.exists() {
            read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|error| {
                AppError::BlocklistRead {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                }
            })?
        } else {
            String::new()
        };
        if has_content && !trailing_newline {
            contents.push('\n');
        }
        for entry in entries {
            contents.push_str(entry);
            contents.push('\n');
        }
        write_string_atomic(path, &contents).map_err(|error| AppError::BlocklistWrite {
            path: path.to_path_buf(),
            reason: error.to_string(),
        })
    }

    fn write_lines(&self, path: &Path, lines: &[String]) -> Result<(), AppError> {
        write_blocklist_lines(path, lines)
    }

    fn read_target_lines(&self, path: &Path) -> Result<Vec<String>, AppError> {
        let contents =
            read_to_string_with_limit(path, BLOCKLIST_TARGET_FILE_READ_LIMIT).map_err(|error| {
                AppError::BlocklistTargetFileRead {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                }
            })?;
        Ok(contents.lines().map(ToString::to_string).collect())
    }
}

impl Deref for BlocklistDocument {
    type Target = CoreBlocklistDocument;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistNormalizeResult {
    MissingBlocklist,
    SkippedUnchanged,
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

pub fn write_blocklist_lines<S: AsRef<str>>(path: &Path, lines: &[S]) -> Result<(), AppError> {
    let mut contents = lines
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\n");
    if !contents.is_empty() {
        contents.push('\n');
    }

    write_string_atomic(path, &contents).map_err(|err| AppError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

pub fn ensure_blocklist_parent(path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AppError::BlocklistWrite {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    Ok(())
}

pub fn normalize_local_blocklist(path: &Path) -> Result<(), AppError> {
    if !path.exists() {
        return Ok(());
    }

    let original = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
        AppError::BlocklistRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let normalized =
        canonicalize_blocklist(&original).map_err(|err| map_invalid_blocklist_line(path, err))?;

    if normalized != original {
        write_string_atomic(path, &normalized).map_err(|err| AppError::BlocklistWrite {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    Ok(())
}

pub fn normalize_local_blocklist_with_fast_state(
    blocklist_path: &Path,
    fast_state_path: &Path,
) -> Result<BlocklistNormalizeResult, AppError> {
    if !blocklist_path.exists() {
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

impl BlocklistDocument {
    pub fn load(path: &Path) -> Result<Self, AppError> {
        if !path.exists() {
            return Ok(Self(CoreBlocklistDocument {
                lines: Vec::new(),
                has_content: false,
                trailing_newline: false,
            }));
        }

        let contents = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
            AppError::BlocklistRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?;
        CoreBlocklistDocument::parse(&contents)
            .map(Self)
            .map_err(|err| map_invalid_blocklist_line(path, err))
    }
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
        BLOCKLIST_TARGET_FILE_READ_LIMIT, BlocklistDocument, BlocklistNormalizeResult,
        FileBlocklistRepository, normalize_local_blocklist_with_fast_state,
    };
    use crate::limited_io::read_to_string_with_limit;

    fn read(path: &std::path::Path) -> String {
        read_to_string_with_limit(path, super::BLOCKLIST_READ_LIMIT).expect("read")
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

        let error = BlocklistDocument::load(&path).expect_err("invalid line must fail");

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
