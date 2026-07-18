use std::path::{Path, PathBuf};

use crate::adapters::source_files::{
    REMOTE_META_READ_LIMIT, RemoteCacheFilesError, SOURCE_FILE_READ_LIMIT,
    collect_remote_cache_files, parse_cidr_source_line, read_remote_cache_iplist_text,
    resolve_remote_source_label,
};
use crate::adapters::source_load::SourceLoadError;
use crate::core::network::CanonicalCidr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRemoteEntry {
    pub cidr: CanonicalCidr,
    pub source_line: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRemoteSource {
    pub path: PathBuf,
    pub label: String,
    pub entries: Vec<CachedRemoteEntry>,
}

pub fn load_remote_sources(
    remote_cache_dir: &Path,
) -> Result<Vec<CachedRemoteSource>, SourceLoadError> {
    if !remote_cache_dir.exists() {
        return Ok(Vec::new());
    }

    let mut remote_files =
        collect_remote_cache_files(remote_cache_dir).map_err(|err| match err {
            RemoteCacheFilesError::ReadDir(err) => SourceLoadError::CacheDir {
                path: remote_cache_dir.to_path_buf(),
                reason: err.to_string(),
            },
            RemoteCacheFilesError::ReadDirEntry(err) => SourceLoadError::CacheDirEntry {
                path: remote_cache_dir.to_path_buf(),
                reason: err.to_string(),
            },
        })?;

    remote_files.sort();

    let mut sources = Vec::with_capacity(remote_files.len());
    for path in remote_files {
        let contents =
            read_remote_cache_iplist_text(&path, SOURCE_FILE_READ_LIMIT, REMOTE_META_READ_LIMIT)
                .map_err(|err| SourceLoadError::Source {
                    path: path.clone(),
                    reason: err.to_string(),
                })?;

        let entries = contents
            .lines()
            .filter_map(parse_cidr_source_line)
            .map(|(cidr, token)| CachedRemoteEntry {
                cidr,
                source_line: token.to_string(),
            })
            .collect::<Vec<_>>();

        sources.push(CachedRemoteSource {
            label: resolve_remote_source_label(&path, REMOTE_META_READ_LIMIT),
            path,
            entries,
        });
    }

    sources.sort_by(|left, right| {
        (left.label.as_str(), left.path.as_os_str())
            .cmp(&(right.label.as_str(), right.path.as_os_str()))
    });

    Ok(sources)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::load_remote_sources;
    use crate::adapters::hash::sha256_hex;
    use crate::adapters::source_load::SourceLoadError;

    #[test]
    fn loads_remote_sources_and_sorts_by_resolved_label() {
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote");

        fs::write(remote_cache_dir.join("a.iplist"), "2001:db8::/64\n").expect("write a");
        fs::write(remote_cache_dir.join("b.iplist"), "10.0.0.0/24\n").expect("write b");
        fs::write(
            remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/z.txt"}"#,
        )
        .expect("write a meta");
        fs::write(
            remote_cache_dir.join("b.meta.json"),
            r#"{"url":"https://example.com/a.txt"}"#,
        )
        .expect("write b meta");

        let sources = load_remote_sources(&remote_cache_dir).expect("load");
        assert_eq!(sources.len(), 2);
        assert_eq!(sources[0].label, "https://example.com/a.txt");
        assert_eq!(sources[0].entries[0].source_line, "10.0.0.0/24");
        assert_eq!(sources[1].label, "https://example.com/z.txt");
    }

    #[test]
    fn label_falls_back_when_metadata_missing() {
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote");
        fs::write(remote_cache_dir.join("a.iplist"), "2001:db8::/64\n").expect("write a");

        let sources = load_remote_sources(&remote_cache_dir).expect("load");
        assert_eq!(sources[0].label, "remote:a.iplist");
    }

    #[test]
    fn hash_mismatch_is_reported() {
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote");
        fs::write(remote_cache_dir.join("a.iplist"), "203.0.113.0/24\n").expect("write a");
        fs::write(
            remote_cache_dir.join("a.meta.json"),
            format!(
                "{{\"url\":\"https://example.com/a.txt\",\"etag\":null,\"last_modified\":null,\"sha256_raw\":\"{}\",\"sha256_iplist\":\"{}\"}}",
                sha256_hex(b"raw"),
                sha256_hex(b"198.51.100.0/24\n")
            ),
        )
        .expect("write meta");

        let err = load_remote_sources(&remote_cache_dir).expect_err("must fail");
        match err {
            SourceLoadError::Source { reason, .. } => {
                assert!(reason.contains("hash mismatch"));
            }
            _ => panic!("unexpected error variant"),
        }
    }
}
