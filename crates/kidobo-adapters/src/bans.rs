//! Bounded read-only storage access for the saved-ban inventory.

use kidobo_app::AppError;
use kidobo_app::bans::{SavedBanReader, SavedBanSources};
use kidobo_app::paths::ResolvedPaths;
use kidobo_app::temporary_bans::TemporaryBanRepository;

use crate::blocklist_file::load_blocklist_document;
use crate::temporary_bans::FileTemporaryBanRepository;

/// Reads only operator-managed local and temporary files, without normalization or cache access.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSavedBanReader;

impl SavedBanReader for FileSavedBanReader {
    fn read(&self, paths: &ResolvedPaths) -> Result<SavedBanSources, AppError> {
        let document = load_blocklist_document(&paths.blocklist_file)?;
        let temporary = FileTemporaryBanRepository.load(&paths.temporary_bans_file())?;
        Ok(SavedBanSources {
            local: document
                .lines
                .into_iter()
                .filter_map(|line| line.canonical)
                .collect(),
            temporary,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use kidobo_core::network::parse_ip_cidr_strict;

    use super::*;
    use crate::limited_io::read_to_string_with_limit;

    fn paths(root: &Path) -> ResolvedPaths {
        ResolvedPaths {
            root_override: Some(root.to_path_buf()),
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        }
    }

    #[test]
    fn missing_saved_files_are_empty_without_creating_any_state() {
        let root = tempfile::tempdir().expect("root");
        assert_eq!(
            FileSavedBanReader
                .read(&paths(root.path()))
                .expect("missing files"),
            SavedBanSources::default()
        );
        assert_eq!(fs::read_dir(root.path()).expect("directory").count(), 0);
    }

    #[test]
    fn reads_saved_and_expired_records_without_normalizing_or_pruning() {
        let root = tempfile::tempdir().expect("root");
        let paths = paths(root.path());
        fs::create_dir_all(&paths.data_dir).expect("data directory");
        let local = "# preserve header\r\n203.0.113.7\r\n203.0.113.7/32\n";
        let temporary = "version = 1\n[[ips]]\ncidr = '2001:db8::1'\nexpires_at = 1\n[[asns]]\nasn = 64496\nexpires_at = 2\n";
        fs::write(&paths.blocklist_file, local).expect("local source");
        fs::write(paths.temporary_bans_file(), temporary).expect("temporary source");
        let local_modified = fs::metadata(&paths.blocklist_file)
            .expect("local metadata")
            .modified()
            .expect("mtime");
        let loaded = FileSavedBanReader.read(&paths).expect("saved sources");
        assert_eq!(
            loaded.local,
            vec![parse_ip_cidr_strict("203.0.113.7").expect("ip"); 2]
        );
        assert_eq!(
            loaded
                .temporary
                .ips
                .get(&parse_ip_cidr_strict("2001:db8::1").expect("ip")),
            Some(&1)
        );
        assert_eq!(loaded.temporary.asns.get(&64496), Some(&2));
        assert_eq!(
            read_to_string_with_limit(&paths.blocklist_file, 1024).expect("local file"),
            local
        );
        assert_eq!(
            read_to_string_with_limit(&paths.temporary_bans_file(), 1024).expect("temporary file"),
            temporary
        );
        assert_eq!(
            fs::metadata(&paths.blocklist_file)
                .expect("local metadata")
                .modified()
                .expect("mtime"),
            local_modified
        );
        assert_eq!(
            fs::read_dir(&paths.data_dir)
                .expect("data directory")
                .count(),
            2
        );
        assert!(!paths.cache_dir.exists());
    }

    #[test]
    fn malformed_or_unreadable_sources_are_reported_instead_of_hidden() {
        let root = tempfile::tempdir().expect("root");
        let paths = paths(root.path());
        fs::create_dir_all(&paths.data_dir).expect("data directory");
        fs::write(&paths.blocklist_file, "not a network\n").expect("malformed local source");
        assert!(matches!(
            FileSavedBanReader.read(&paths),
            Err(AppError::BlocklistParseLine { line: 1, .. })
        ));
        fs::remove_file(&paths.blocklist_file).expect("remove local source");
        fs::create_dir(&paths.blocklist_file).expect("nonfile local source");
        assert!(matches!(
            FileSavedBanReader.read(&paths),
            Err(AppError::BlocklistRead { .. })
        ));
        fs::remove_dir(&paths.blocklist_file).expect("remove nonfile");
        fs::write(paths.temporary_bans_file(), "version = 2\n").expect("malformed temporary state");
        assert!(matches!(
            FileSavedBanReader.read(&paths),
            Err(AppError::TemporaryBans { .. })
        ));
    }
}
