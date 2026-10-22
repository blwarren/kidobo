//! Bounded temporary-ban persistence and the production wall clock.

use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use kidobo_app::AppError;
use kidobo_app::temporary_bans::{Clock, TemporaryBanRepository};
use kidobo_core::temporary_bans::{TemporaryBans, parse_temporary_bans, serialize_temporary_bans};

use crate::limited_io::{read_to_string_with_limit, write_string_atomic_with_limit};

/// Maximum accepted temporary-ban state size, matching the local blocklist bound.
pub const TEMPORARY_BANS_READ_LIMIT: usize = 16 * 1024 * 1024;

/// Filesystem-backed temporary ban state with bounded reads and atomic writes.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileTemporaryBanRepository;

impl TemporaryBanRepository for FileTemporaryBanRepository {
    fn load(&self, path: &Path) -> Result<TemporaryBans, AppError> {
        let contents = match read_to_string_with_limit(path, TEMPORARY_BANS_READ_LIMIT) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(TemporaryBans::default());
            }
            Err(error) => return Err(state_error(path, error)),
        };
        parse_temporary_bans(&contents).map_err(|error| state_error(path, error))
    }

    fn save(&self, path: &Path, state: &TemporaryBans) -> Result<(), AppError> {
        let contents = serialize_temporary_bans(state).map_err(|error| state_error(path, error))?;
        if contents.len() > TEMPORARY_BANS_READ_LIMIT {
            return Err(state_error(
                path,
                format!("file exceeds {TEMPORARY_BANS_READ_LIMIT} byte limit"),
            ));
        }
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent).map_err(|error| state_error(path, error))?;
        }
        write_string_atomic_with_limit(path, &contents, TEMPORARY_BANS_READ_LIMIT)
            .map_err(|error| state_error(path, error))
    }
}

fn state_error(path: &Path, error: impl std::fmt::Display) -> AppError {
    AppError::TemporaryBans {
        path: path.to_path_buf(),
        reason: error.to_string(),
    }
}

/// Production UTC wall clock used only at application workflow boundaries.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> Result<u64, AppError> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| AppError::Clock {
                reason: error.to_string(),
            })?
            .as_secs();
        i64::try_from(seconds).map_err(|error| AppError::Clock {
            reason: error.to_string(),
        })?;
        Ok(seconds)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;
    use kidobo_core::network::parse_ip_cidr_strict;

    #[test]
    fn missing_state_is_empty_and_roundtrip_creates_parents() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("data/temporary-bans.toml");
        let repository = FileTemporaryBanRepository;
        assert_eq!(
            repository.load(&path).expect("missing"),
            TemporaryBans::default()
        );
        assert!(!path.exists());
        let mut state = TemporaryBans::default();
        state
            .ips
            .insert(parse_ip_cidr_strict("203.0.113.7").expect("ip"), 1234);
        state.asns.insert(64496, 5678);
        repository.save(&path, &state).expect("save");
        assert_eq!(repository.load(&path).expect("load"), state);
        assert_eq!(
            fs::read_dir(path.parent().expect("parent"))
                .expect("read")
                .count(),
            1
        );
    }

    #[test]
    fn malformed_oversized_and_nonfile_state_are_errors() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("temporary-bans.toml");
        let repository = FileTemporaryBanRepository;
        for contents in [b"version = 2".as_slice(), b"\xff", b""] {
            fs::write(&path, contents).expect("write");
            assert!(matches!(
                repository.load(&path),
                Err(AppError::TemporaryBans { .. })
            ));
        }
        File::create(&path)
            .expect("create")
            .set_len(u64::try_from(TEMPORARY_BANS_READ_LIMIT + 1).expect("limit"))
            .expect("resize");
        assert!(
            repository
                .load(&path)
                .expect_err("oversized")
                .to_string()
                .contains("byte limit")
        );
        assert!(matches!(
            repository.load(root.path()),
            Err(AppError::TemporaryBans { path, .. }) if path == root.path()
        ));
    }

    #[test]
    fn invalid_and_oversized_saves_preserve_existing_state() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("temporary-bans.toml");
        let repository = FileTemporaryBanRepository;
        let mut state = TemporaryBans::default();
        state.asns.insert(64496, 1234);
        repository.save(&path, &state).expect("original");
        let original = read_to_string_with_limit(&path, TEMPORARY_BANS_READ_LIMIT).expect("read");
        state.asns.insert(0, 1);
        assert!(repository.save(&path, &state).is_err());
        assert_eq!(
            read_to_string_with_limit(&path, TEMPORARY_BANS_READ_LIMIT).expect("preserved"),
            original
        );
        state.asns = (1..=400_000)
            .map(|asn| (asn, 9_223_372_036_854_775_807))
            .collect();
        assert!(
            repository
                .save(&path, &state)
                .expect_err("oversized")
                .to_string()
                .contains("byte limit")
        );
        assert_eq!(
            read_to_string_with_limit(&path, TEMPORARY_BANS_READ_LIMIT).expect("preserved"),
            original
        );
        assert_eq!(fs::read_dir(root.path()).expect("read dir").count(), 1);
    }

    #[test]
    fn failed_atomic_replacement_retains_existing_directory_contents() {
        let root = tempfile::tempdir().expect("root");
        let path = root.path().join("temporary-bans.toml");
        fs::create_dir(&path).expect("directory");
        fs::write(path.join("preserve"), "original").expect("marker");
        assert!(
            FileTemporaryBanRepository
                .save(&path, &TemporaryBans::default())
                .is_err()
        );
        assert_eq!(
            read_to_string_with_limit(&path.join("preserve"), 32).expect("marker"),
            "original"
        );
        assert_eq!(fs::read_dir(root.path()).expect("read dir").count(), 1);
    }
}
