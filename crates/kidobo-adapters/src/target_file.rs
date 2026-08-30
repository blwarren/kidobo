//! Bounded user-supplied target file adapter.

use std::path::Path;

use kidobo_app::AppError;
use kidobo_app::ports::TargetFileReader;

use crate::limited_io::read_to_string_with_limit;

const LOOKUP_TARGET_READ_LIMIT: usize = 2 * 1024 * 1024;

/// Production bounded reader for lookup target files.
#[derive(Debug, Default, Clone, Copy)]
pub struct LookupTargetFileReader;

impl TargetFileReader for LookupTargetFileReader {
    fn read_lines(&self, path: &Path) -> Result<Vec<String>, AppError> {
        let contents =
            read_to_string_with_limit(path, LOOKUP_TARGET_READ_LIMIT).map_err(|error| {
                AppError::LookupTargetFileRead {
                    path: path.to_path_buf(),
                    reason: error.to_string(),
                }
            })?;
        Ok(contents.lines().map(ToString::to_string).collect())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use kidobo_app::AppError;
    use kidobo_app::ports::TargetFileReader;
    use tempfile::TempDir;

    use super::{LOOKUP_TARGET_READ_LIMIT, LookupTargetFileReader};

    #[test]
    fn reads_target_lines() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("targets.txt");
        fs::write(&file, "10.0.0.1\n2001:db8::1\n").expect("write");

        let targets = LookupTargetFileReader.read_lines(&file).expect("read");
        assert_eq!(targets, vec!["10.0.0.1", "2001:db8::1"]);
    }

    #[test]
    fn reports_file_read_error() {
        let missing = PathBuf::from("/definitely/missing/targets.txt");
        let error = LookupTargetFileReader
            .read_lines(&missing)
            .expect_err("must fail");
        match error {
            AppError::LookupTargetFileRead { path, .. } => assert_eq!(path, missing),
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn rejects_oversized_file() {
        let temp = TempDir::new().expect("tempdir");
        let file = temp.path().join("targets.txt");
        fs::write(&file, "1".repeat(LOOKUP_TARGET_READ_LIMIT + 1)).expect("write");

        let error = LookupTargetFileReader
            .read_lines(&file)
            .expect_err("must fail");
        match error {
            AppError::LookupTargetFileRead { reason, .. } => {
                assert!(reason.contains("file exceeds 2097152 byte limit"));
            }
            _ => panic!("unexpected error variant"),
        }
    }
}
