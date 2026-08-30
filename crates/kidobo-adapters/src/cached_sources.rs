//! Cached source loading adapter.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::http_cache::collect_offline_remote_generations;
use crate::source_files::{
    REMOTE_META_READ_LIMIT, RemoteCacheFilesError, SOURCE_FILE_READ_LIMIT,
    collect_remote_cache_files, parse_cidr_source_line, read_remote_cache_iplist_text,
    resolve_remote_source_label,
};
use crate::source_load::SourceLoadError;
use kidobo_core::network::CanonicalCidr;

/// One canonical entry retained from an offline remote cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRemoteEntry {
    /// Canonical CIDR used by lookup.
    pub cidr: CanonicalCidr,
    /// Original cached source line shown to the operator.
    pub source_line: String,
}

/// One validated legacy or v2 remote cache source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedRemoteSource {
    /// Selected iplist file path.
    pub path: PathBuf,
    /// Configured URL when valid metadata is available, otherwise a stable cache label.
    pub label: String,
    /// Parsed canonical entries.
    pub entries: Vec<CachedRemoteEntry>,
}

/// Loads cached remote feeds in deterministic label and path order.
///
/// # Errors
///
/// Returns [`SourceLoadError`] when the cache directory cannot be enumerated or a selected source
/// cannot be read within its configured bound.
pub fn load_remote_sources(
    remote_cache_dir: &Path,
) -> Result<Vec<CachedRemoteSource>, SourceLoadError> {
    if !remote_cache_dir.exists() {
        return Ok(Vec::new());
    }

    let generation_sources =
        collect_offline_remote_generations(remote_cache_dir).map_err(|err| {
            SourceLoadError::CacheDir {
                path: remote_cache_dir.join("v2/remote"),
                reason: err.to_string(),
            }
        })?;
    let generation_hashes = generation_sources
        .iter()
        .map(|source| source.url_hash.clone())
        .collect::<BTreeSet<_>>();

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

    let mut sources = Vec::with_capacity(remote_files.len() + generation_sources.len());
    for source in generation_sources {
        sources.push(CachedRemoteSource {
            path: source.iplist_path,
            label: source.label,
            entries: parse_cached_entries(&source.iplist),
        });
    }
    for path in remote_files {
        if path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|stem| generation_hashes.contains(stem))
        {
            continue;
        }
        let contents =
            read_remote_cache_iplist_text(&path, SOURCE_FILE_READ_LIMIT, REMOTE_META_READ_LIMIT)
                .map_err(|err| SourceLoadError::Source {
                    path: path.clone(),
                    reason: err.to_string(),
                })?;

        sources.push(CachedRemoteSource {
            label: resolve_remote_source_label(&path, REMOTE_META_READ_LIMIT),
            path,
            entries: parse_cached_entries(&contents),
        });
    }

    sources.sort_by(|left, right| {
        (left.label.as_str(), left.path.as_os_str())
            .cmp(&(right.label.as_str(), right.path.as_os_str()))
    });

    Ok(sources)
}

fn parse_cached_entries(contents: &str) -> Vec<CachedRemoteEntry> {
    contents
        .lines()
        .filter_map(parse_cidr_source_line)
        .map(|(cidr, token)| CachedRemoteEntry {
            cidr,
            source_line: token.to_string(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::load_remote_sources;
    use crate::cache_generation::{GenerationFile, commit_generation};
    use crate::hash::sha256_hex;
    use crate::http_cache::{RemoteCacheMetadata, remote_generation_store, url_hash_prefix};
    use crate::source_load::SourceLoadError;

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

    #[test]
    fn loads_v2_generations_deterministically_without_duplicate_legacy_entries() {
        let temp = TempDir::new().expect("tempdir");
        let remote_cache_dir = temp.path().join("remote");
        fs::create_dir_all(&remote_cache_dir).expect("mkdir remote");
        let sources = [
            ("https://example.com/z.txt", "2001:db8::/64"),
            ("https://example.com/a.txt", "10.0.0.0/24"),
        ];
        for (url, iplist) in sources {
            let raw = iplist.as_bytes();
            let metadata = serde_json::to_vec_pretty(&RemoteCacheMetadata {
                url: url.to_string(),
                etag: None,
                last_modified: None,
                sha256_raw: sha256_hex(raw),
                sha256_iplist: sha256_hex(iplist.as_bytes()),
            })
            .expect("metadata");
            commit_generation(
                &remote_generation_store(&remote_cache_dir, url),
                &[
                    GenerationFile {
                        name: "raw",
                        contents: raw,
                    },
                    GenerationFile {
                        name: "iplist",
                        contents: iplist.as_bytes(),
                    },
                    GenerationFile {
                        name: "meta.json",
                        contents: &metadata,
                    },
                ],
                None,
            )
            .expect("commit generation");
        }

        let duplicate_hash = url_hash_prefix("https://example.com/a.txt");
        fs::write(
            remote_cache_dir.join(format!("{duplicate_hash}.iplist")),
            "203.0.113.0/24\n",
        )
        .expect("write duplicate legacy cache");

        let loaded = load_remote_sources(&remote_cache_dir).expect("load");

        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].label, "https://example.com/a.txt");
        assert_eq!(loaded[0].entries[0].source_line, "10.0.0.0/24");
        assert_eq!(loaded[1].label, "https://example.com/z.txt");
        assert_eq!(loaded[1].entries[0].source_line, "2001:db8::/64");
    }
}
