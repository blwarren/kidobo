//! Local blocklist filesystem adapter.

use std::fs;
use std::io;
use std::path::Path;

use crate::limited_io::{
    AtomicWriteError, read_to_string_with_limit, sync_directory,
    write_bytes_atomic_with_publication,
};
use kidobo_app::AppError;
use kidobo_app::blocklist::BlocklistRepository;
use kidobo_core::blocklist::{BlocklistDocument, InvalidBlocklistLine, parse_blocklist_entry};
use kidobo_core::network::CanonicalCidr;

/// Maximum accepted local blocklist size.
pub const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;
const BLOCKLIST_TARGET_FILE_READ_LIMIT: usize = 2 * 1024 * 1024;
/// Production local blocklist repository using bounded reads and atomic writes.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileBlocklistRepository;

impl BlocklistRepository for FileBlocklistRepository {
    fn load(&self, path: &Path) -> Result<BlocklistDocument, AppError> {
        load_blocklist_document(path)
    }

    fn write(&self, path: &Path, contents: &str) -> Result<(), AppError> {
        write_blocklist_with_limit(path, contents, BLOCKLIST_READ_LIMIT)
    }

    fn confirm_durable(&self, path: &Path) -> Result<(), AppError> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        match sync_directory(parent) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            result => result.map_err(|source| AppError::BlocklistDurability {
                path: path.to_path_buf(),
                source,
            }),
        }
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

fn write_blocklist_with_limit(path: &Path, contents: &str, limit: usize) -> Result<(), AppError> {
    let write_error = |source| AppError::BlocklistWrite {
        path: path.to_path_buf(),
        source,
    };
    if contents.len() > limit {
        return Err(write_error(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("file exceeds {limit} byte limit"),
        )));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(write_error)?;
    }
    write_bytes_atomic_with_publication(path, contents.as_bytes()).map_err(|error| match error {
        AtomicWriteError::BeforePublication(source) => write_error(source),
        AtomicWriteError::AfterPublication(source) => AppError::BlocklistDurability {
            path: path.to_path_buf(),
            source,
        },
    })
}

fn read_contents(path: &Path) -> Result<String, AppError> {
    match read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT) {
        Ok(contents) => Ok(contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(source) => Err(AppError::BlocklistRead {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Loads only the networks used by read-only consumers, without building an edit index.
///
/// # Errors
///
/// Returns an error when the file cannot be read within its bound or contains an invalid
/// entry.
pub fn load_blocklist_networks(path: &Path) -> Result<Vec<CanonicalCidr>, AppError> {
    read_contents(path)?
        .lines()
        .enumerate()
        .filter_map(|(index, line)| parse_blocklist_entry(line, index + 1).transpose())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| map_invalid_blocklist_line(path, error))
}

/// Loads the original bytes and indexes the entries for a source edit.
///
/// # Errors
///
/// Returns an error if the bounded file cannot be read or contains invalid entries.
pub fn load_blocklist_document(path: &Path) -> Result<BlocklistDocument, AppError> {
    BlocklistDocument::parse(read_contents(path)?)
        .map_err(|error| map_invalid_blocklist_line(path, error))
}

pub(crate) fn map_invalid_blocklist_line(path: &Path, err: InvalidBlocklistLine) -> AppError {
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
        BLOCKLIST_TARGET_FILE_READ_LIMIT, FileBlocklistRepository, load_blocklist_document,
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
        let line = format!("#{}\n", "x".repeat(super::BLOCKLIST_READ_LIMIT - 2));
        FileBlocklistRepository
            .write(&path, &line)
            .expect("exact production limit");
        assert_eq!(
            fs::metadata(&path).expect("metadata").len(),
            16 * 1024 * 1024
        );
        load_blocklist_document(&path).expect("production-size document is readable");
        assert!(matches!(
            FileBlocklistRepository.write(
                &path,
                &load_blocklist_document(&path)
                    .expect("read original")
                    .with_appended(&["192.0.2.1/32".into()])
            ),
            Err(kidobo_app::AppError::BlocklistWrite { .. })
        ));
        assert_contents(&read(&path), &line);
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
                let appended = load_blocklist_document(&path)
                    .expect("read original")
                    .with_appended(&[entry.to_owned()]);
                let result = super::write_blocklist_with_limit(&path, &appended, TEST_WRITE_LIMIT);
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
            let line = format!("#é{}\n", "x".repeat(size - 4));
            let result = super::write_blocklist_with_limit(&path, &line, TEST_WRITE_LIMIT);
            if size > TEST_WRITE_LIMIT {
                assert!(matches!(
                    result,
                    Err(kidobo_app::AppError::BlocklistWrite { .. })
                ));
                assert_eq!(read(&path), "192.0.2.0/24\n");
            } else {
                result.expect("within limit");
                assert_contents(&read(&path), &line);
                load_blocklist_document(&path).expect("readable");
            }
        }
    }

    #[test]
    fn repository_writes_first_document_under_a_missing_parent() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("nested/blocklist.txt");
        FileBlocklistRepository
            .confirm_durable(&path)
            .expect("absent parent");
        assert!(!path.parent().unwrap().exists());
        FileBlocklistRepository
            .write(&path, "192.0.2.0/24\n")
            .expect("write");
        assert_eq!(read(&path), "192.0.2.0/24\n");
    }

    #[cfg(unix)]
    fn check_retry(
        path: &std::path::Path,
        operation: impl Fn() -> Result<(), kidobo_app::AppError>,
        expected: &str,
    ) {
        use crate::limited_io::directory_sync_test::fail_once_at;
        use std::os::unix::fs::MetadataExt;

        let failed_attempt = || {
            fail_once_at(
                path.parent().expect("data directory"),
                std::io::Error::other("injected fsync failure"),
                &operation,
            )
        };
        assert!(matches!(
            failed_attempt(),
            Err(kidobo_app::AppError::BlocklistDurability { .. })
        ));
        assert_eq!(read(path), expected);
        let inode = path.metadata().unwrap().ino();
        assert!(matches!(
            failed_attempt(),
            Err(kidobo_app::AppError::BlocklistDurability { .. })
        ));
        operation().expect("durable retry");
        assert_eq!(path.metadata().unwrap().ino(), inode);
        assert_eq!(read(path), expected);
    }

    #[cfg(unix)]
    #[test]
    fn retry_after_visible_ban_or_unban_requires_directory_sync_without_republication() {
        use crate::config::FileConfigRepository;
        use crate::lock::FileLockManager;
        use crate::path::{ENV_KIDOBO_ROOT, SystemPathResolver};
        use crate::temporary_bans::{FileTemporaryBanRepository, SystemClock};
        use kidobo_app::blocklist::{
            BanDependencies, BanRequest, BlocklistInput, UnbanApplyDependencies, UnbanDecision,
            UnbanPreparation, UnbanPreparationDependencies, UnbanRequest, apply_unban, execute_ban,
            prepare_unban,
        };
        use kidobo_app::paths::PathResolutionInput;
        use kidobo_app::ports::NoCancellation;

        let root = TempDir::new().expect("root");
        let data = root.path().join("data");
        let path = data.join("blocklist.txt");
        fs::create_dir_all(root.path().join("config")).unwrap();
        fs::write(
            root.path().join("config/config.toml"),
            "[ipset]\nset_name='kidobo'\n",
        )
        .unwrap();
        let paths = PathResolutionInput {
            explicit_config_path: None,
            temp_dir: root.path().to_path_buf(),
            env: [(ENV_KIDOBO_ROOT.into(), root.path().as_os_str().to_owned())].into(),
        };
        let input = BlocklistInput::Single("192.0.2.4".into());
        let ban = || {
            execute_ban(
                &BanRequest {
                    paths: paths.clone(),
                    input: input.clone(),
                    duration: None,
                },
                &BanDependencies {
                    cancellation: &NoCancellation,
                    paths: &SystemPathResolver,
                    configs: &FileConfigRepository,
                    locks: &FileLockManager,
                    repository: &FileBlocklistRepository,
                    temporary_bans: &FileTemporaryBanRepository,
                    clock: &SystemClock,
                },
            )
            .map(|_| ())
        };
        let unban = || {
            let request = UnbanRequest {
                paths: paths.clone(),
                input: input.clone(),
            };
            let preview = prepare_unban(
                &request,
                &UnbanPreparationDependencies {
                    cancellation: &NoCancellation,
                    paths: &SystemPathResolver,
                    configs: &FileConfigRepository,
                    repository: &FileBlocklistRepository,
                    temporary_bans: &FileTemporaryBanRepository,
                },
            )?;
            let UnbanPreparation::Ready(preview) = preview else {
                panic!("valid target");
            };
            apply_unban(
                &request,
                &preview,
                &UnbanDecision {
                    remove_partial: false,
                },
                &UnbanApplyDependencies {
                    cancellation: &NoCancellation,
                    paths: &SystemPathResolver,
                    configs: &FileConfigRepository,
                    locks: &FileLockManager,
                    repository: &FileBlocklistRepository,
                    temporary_bans: &FileTemporaryBanRepository,
                },
            )
            .map(|_| ())
        };
        check_retry(&path, ban, "192.0.2.4/32\n");
        check_retry(&path, unban, "");
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
    fn document_loader_preserves_missing_empty_and_valid_contents() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("blocklist.txt");
        let missing = load_blocklist_document(&path).expect("missing document");
        assert!(!path.exists());
        assert_eq!(missing.networks().len(), 0);

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
}
