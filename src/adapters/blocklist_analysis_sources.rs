use std::path::Path;

use thiserror::Error;

use crate::adapters::cached_sources::load_remote_sources;
use crate::adapters::path::ResolvedPaths;
use crate::adapters::source_files::{SOURCE_FILE_READ_LIMIT, read_cidrs_from_source_file};
use crate::adapters::source_load::SourceLoadError;
use crate::core::network::CanonicalCidr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnalysisRemoteSource {
    pub label: String,
    pub cidrs: Vec<CanonicalCidr>,
    pub stale: bool,
    pub age_secs: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisSources {
    pub local_cidrs: Vec<CanonicalCidr>,
    pub remote_sources: Vec<AnalysisRemoteSource>,
}

#[derive(Debug, Error)]
#[error(transparent)]
pub struct AnalysisSourceLoadError(#[from] pub SourceLoadError);

pub fn load_analysis_sources(
    paths: &ResolvedPaths,
    stale_after_secs: u64,
) -> Result<AnalysisSources, AnalysisSourceLoadError> {
    let mut local_cidrs = Vec::new();
    if paths.blocklist_file.exists() {
        local_cidrs = read_source_file(&paths.blocklist_file)?;
    }

    let mut remote_sources = Vec::new();
    if paths.remote_cache_dir.exists() {
        let loaded =
            load_remote_sources(&paths.remote_cache_dir).map_err(AnalysisSourceLoadError::from)?;

        for source in loaded {
            let cidrs = source.entries.into_iter().map(|entry| entry.cidr).collect();
            let age_secs = source.age_secs;
            let stale = remote_source_is_stale(age_secs, stale_after_secs);
            remote_sources.push(AnalysisRemoteSource {
                label: source.label,
                cidrs,
                stale,
                age_secs,
            });
        }
    }

    Ok(AnalysisSources {
        local_cidrs,
        remote_sources,
    })
}

fn read_source_file(path: &Path) -> Result<Vec<CanonicalCidr>, AnalysisSourceLoadError> {
    read_cidrs_from_source_file(path, SOURCE_FILE_READ_LIMIT).map_err(|err| {
        AnalysisSourceLoadError::from(SourceLoadError::Source {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })
    })
}

fn remote_source_is_stale(age_secs: Option<u64>, stale_after_secs: u64) -> bool {
    age_secs.is_some_and(|age| age > stale_after_secs)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{load_analysis_sources, remote_source_is_stale};
    use crate::adapters::hash::sha256_hex;
    use crate::adapters::path::ResolvedPaths;
    use crate::adapters::source_load::SourceLoadError;

    fn test_paths(root: &std::path::Path) -> ResolvedPaths {
        ResolvedPaths {
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
    fn loads_local_and_remote_sources_with_stale_flag() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");

        fs::write(&paths.blocklist_file, "10.0.0.0/24\n").expect("write blocklist");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "203.0.113.0/24\n")
            .expect("write remote");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/a.txt"}"#,
        )
        .expect("write meta");

        let sources = load_analysis_sources(&paths, 86_400).expect("load");
        assert_eq!(sources.local_cidrs.len(), 1);
        assert_eq!(sources.remote_sources.len(), 1);
        assert_eq!(sources.remote_sources[0].label, "https://example.com/a.txt");
        assert!(!sources.remote_sources[0].stale);
        assert!(sources.remote_sources[0].age_secs.is_some());
    }

    #[test]
    fn rejects_remote_iplist_when_metadata_hash_mismatches() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");

        fs::write(paths.remote_cache_dir.join("a.iplist"), "203.0.113.0/24\n")
            .expect("write remote");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            format!(
                "{{\"url\":\"https://example.com/a.txt\",\"etag\":null,\"last_modified\":null,\"sha256_raw\":\"{}\",\"sha256_iplist\":\"{}\"}}",
                sha256_hex(b"raw"),
                sha256_hex(b"198.51.100.0/24\n")
            ),
        )
        .expect("write meta");

        let err = load_analysis_sources(&paths, 86_400).expect_err("load must fail");
        match err.0 {
            SourceLoadError::Source { reason, .. } => {
                assert!(reason.contains("hash mismatch"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn remote_staleness_uses_strict_threshold() {
        assert!(!remote_source_is_stale(None, 86_400));
        assert!(!remote_source_is_stale(Some(86_400), 86_400));
        assert!(remote_source_is_stale(Some(86_401), 86_400));
    }
}
