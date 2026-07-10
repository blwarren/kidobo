use std::path::Path;
use std::sync::Arc;

use log::warn;
use thiserror::Error;

use crate::adapters::asn::{AsnError, load_cached_asn_prefixes};
use crate::adapters::cached_sources::load_remote_sources;
use crate::adapters::github_meta::load_cached_github_meta_safelist;
use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::path::ResolvedPaths;
use crate::adapters::source_files::{SOURCE_FILE_READ_LIMIT, parse_cidr_source_line};
use crate::adapters::source_load::SourceLoadError;
use crate::core::config::Config;
use crate::core::lookup::LookupSourceEntry;
use crate::core::network::CanonicalCidr;

#[derive(Debug, Error)]
pub enum LookupSourceLoadError {
    #[error(transparent)]
    Source(#[from] SourceLoadError),

    #[error(transparent)]
    Asn(#[from] AsnError),
}

pub fn load_lookup_sources(
    paths: &ResolvedPaths,
    config: Option<&Config>,
) -> Result<Vec<LookupSourceEntry>, LookupSourceLoadError> {
    let mut entries = Vec::new();

    if paths.blocklist_file.exists() {
        entries.extend(read_source_file(
            &paths.blocklist_file,
            "internal:blocklist",
        )?);
    }

    if paths.remote_cache_dir.exists() {
        let remote_sources =
            load_remote_sources(&paths.remote_cache_dir).map_err(LookupSourceLoadError::from)?;

        for source in remote_sources {
            let source_label: Arc<str> = Arc::from(source.label);
            entries.extend(source.entries.into_iter().map(|entry| LookupSourceEntry {
                source_label: Arc::clone(&source_label),
                source_line: entry.source_line,
                cidr: entry.cidr,
            }));
        }
    }

    if let Some(config) = config {
        append_canonical_entries(
            &mut entries,
            "safelist:config",
            config.safe.ips.iter().copied(),
        );

        if config.safe.include_github_meta {
            let github_networks = load_cached_github_meta_safelist(
                &paths.remote_cache_dir,
                &config.safe.github_meta_url,
                &config.safe.github_meta_category_mode(),
            );
            if let Some(github_networks) = github_networks {
                append_canonical_entries(&mut entries, "safelist:github-meta", github_networks);
            } else {
                warn!(
                    "lookup GitHub meta safelist cache unavailable; GitHub safelist was not evaluated"
                );
            }
        }

        let asn_cache_dir = paths.cache_dir.join("asn");
        for asn in &config.asn.banned {
            let source_label = format!("asn:AS{asn}");
            if let Some(prefixes) = load_cached_asn_prefixes(*asn, &asn_cache_dir)? {
                append_canonical_entries(&mut entries, &source_label, prefixes);
            } else {
                warn!(
                    "lookup ASN cache unavailable for AS{asn}; this configured ASN was not evaluated"
                );
            }
        }
    }

    entries
        .sort_by(|a, b| (&a.source_label, &a.source_line).cmp(&(&b.source_label, &b.source_line)));
    Ok(entries)
}

fn append_canonical_entries<I>(entries: &mut Vec<LookupSourceEntry>, source_label: &str, cidrs: I)
where
    I: IntoIterator<Item = CanonicalCidr>,
{
    let source_label: Arc<str> = Arc::from(source_label);
    entries.extend(cidrs.into_iter().map(|cidr| LookupSourceEntry {
        source_label: Arc::clone(&source_label),
        source_line: cidr.to_string(),
        cidr,
    }));
}

fn read_source_file(
    path: &Path,
    source_label: &str,
) -> Result<Vec<LookupSourceEntry>, LookupSourceLoadError> {
    let contents = read_to_string_with_limit(path, SOURCE_FILE_READ_LIMIT).map_err(|err| {
        LookupSourceLoadError::from(SourceLoadError::Source {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })
    })?;

    let source_label: Arc<str> = Arc::from(source_label);
    Ok(contents
        .lines()
        .filter_map(parse_cidr_source_line)
        .map(|(cidr, token)| LookupSourceEntry {
            source_label: Arc::clone(&source_label),
            source_line: token.to_string(),
            cidr,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::{LookupSourceLoadError, load_lookup_sources};
    use crate::adapters::hash::sha256_hex;
    use crate::adapters::path::ResolvedPaths;
    use crate::adapters::source_files::parse_cidr_source_line;
    use crate::adapters::source_load::SourceLoadError;
    use crate::core::config::Config;

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
    fn loads_blocklist_and_remote_cached_sources() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");

        fs::write(
            &paths.blocklist_file,
            "10.0.0.0/24\ninvalid\n198.51.100.7 trailing\n",
        )
        .expect("write blocklist");

        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/allowlist.txt"}"#,
        )
        .expect("write remote meta");
        fs::write(paths.remote_cache_dir.join("ignore.txt"), "10.0.0.1\n").expect("write ignore");

        let entries = load_lookup_sources(&paths, None).expect("load sources");

        let labels = entries
            .iter()
            .map(|entry| entry.source_label.as_ref())
            .collect::<Vec<_>>();
        let lines = entries
            .iter()
            .map(|entry| entry.source_line.as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            labels,
            vec![
                "https://example.com/allowlist.txt",
                "internal:blocklist",
                "internal:blocklist"
            ]
        );
        assert_eq!(lines, vec!["2001:db8::/64", "10.0.0.0/24", "198.51.100.7"]);
    }

    #[test]
    fn remote_source_label_falls_back_to_cache_file_when_metadata_missing() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");

        let entries = load_lookup_sources(&paths, None).expect("load sources");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_label.as_ref(), "remote:a.iplist");
    }

    #[test]
    fn remote_source_label_falls_back_to_cache_file_when_metadata_invalid() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(paths.remote_cache_dir.join("a.meta.json"), "{").expect("write invalid meta");

        let entries = load_lookup_sources(&paths, None).expect("load sources");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_label.as_ref(), "remote:a.iplist");
    }

    #[test]
    fn hash_mismatched_remote_iplist_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            format!(
                "{{\"url\":\"https://example.com/a.txt\",\"etag\":null,\"last_modified\":null,\"sha256_raw\":\"{}\",\"sha256_iplist\":\"{}\"}}",
                sha256_hex(b"raw"),
                sha256_hex(b"10.0.0.0/24\n")
            ),
        )
        .expect("write remote meta");

        let err = load_lookup_sources(&paths, None).expect_err("load must fail");
        match err {
            LookupSourceLoadError::Source(SourceLoadError::Source { reason, .. }) => {
                assert!(reason.contains("hash mismatch"));
            }
            _ => panic!("unexpected error variant"),
        }
    }

    #[test]
    fn remote_entries_are_sorted_by_resolved_label_not_cache_filename() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/z.txt"}"#,
        )
        .expect("write remote meta a");
        fs::write(paths.remote_cache_dir.join("b.iplist"), "10.0.0.0/24\n")
            .expect("write remote b");
        fs::write(
            paths.remote_cache_dir.join("b.meta.json"),
            r#"{"url":"https://example.com/a.txt"}"#,
        )
        .expect("write remote meta b");

        let entries = load_lookup_sources(&paths, None).expect("load sources");
        let labels = entries
            .iter()
            .map(|entry| entry.source_label.as_ref())
            .collect::<Vec<_>>();

        assert_eq!(
            labels,
            vec!["https://example.com/a.txt", "https://example.com/z.txt"]
        );
    }

    #[test]
    fn multiple_remote_files_with_same_label_are_all_loaded() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(paths.remote_cache_dir.join("a.iplist"), "2001:db8::/64\n")
            .expect("write remote a");
        fs::write(paths.remote_cache_dir.join("b.iplist"), "10.0.0.0/24\n")
            .expect("write remote b");
        fs::write(
            paths.remote_cache_dir.join("a.meta.json"),
            r#"{"url":"https://example.com/shared.txt"}"#,
        )
        .expect("write remote meta a");
        fs::write(
            paths.remote_cache_dir.join("b.meta.json"),
            r#"{"url":"https://example.com/shared.txt"}"#,
        )
        .expect("write remote meta b");

        let entries = load_lookup_sources(&paths, None).expect("load sources");
        let rendered = entries
            .iter()
            .map(|entry| {
                (
                    entry.source_label.as_ref().to_string(),
                    entry.source_line.clone(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                (
                    "https://example.com/shared.txt".to_string(),
                    "10.0.0.0/24".to_string(),
                ),
                (
                    "https://example.com/shared.txt".to_string(),
                    "2001:db8::/64".to_string(),
                ),
            ]
        );
    }

    #[test]
    fn loads_all_configured_safelist_and_cached_asn_sources() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let config = Config::from_toml_str(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             enable_ipv6 = false\n\
             [safe]\n\
             ips = ['10.0.0.0/24', '2001:db8::/64']\n\
             include_github_meta = true\n\
             github_meta_categories = ['api']\n\
             [asn]\n\
             banned = [64512, 64513]\n",
        )
        .expect("valid config");

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote cache");
        fs::create_dir_all(paths.cache_dir.join("asn")).expect("mkdir ASN cache");
        fs::write(
            paths.remote_cache_dir.join("github-meta.raw.json"),
            r#"{"api":["192.0.2.0/24","2001:db8:1::/64"]}"#,
        )
        .expect("write GitHub cache");
        fs::write(
            paths.remote_cache_dir.join("github-meta.categories.json"),
            r#"{"mode":"selected","categories":["api"]}"#,
        )
        .expect("write GitHub category cache");
        fs::write(
            paths.cache_dir.join("asn/as64512.iplist"),
            "# kidobo-asn-cache-v1\n198.51.100.0/24\n192.0.2.0/24\n2001:db8:2::/64\n",
        )
        .expect("write first ASN cache");
        fs::write(
            paths.cache_dir.join("asn/as64513.iplist"),
            "203.0.113.0/24\n192.0.2.0/24\n",
        )
        .expect("write second ASN cache");
        fs::write(
            paths.cache_dir.join("asn/as64514.iplist"),
            "100.64.0.0/10\n",
        )
        .expect("write unconfigured ASN cache");

        let entries = load_lookup_sources(&paths, Some(&config)).expect("load sources");
        let rendered = entries
            .iter()
            .map(|entry| (entry.source_label.as_ref(), entry.source_line.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(
            rendered,
            vec![
                ("asn:AS64512", "192.0.2.0/24"),
                ("asn:AS64512", "198.51.100.0/24"),
                ("asn:AS64512", "2001:db8:2::/64"),
                ("asn:AS64513", "192.0.2.0/24"),
                ("asn:AS64513", "203.0.113.0/24"),
                ("safelist:config", "10.0.0.0/24"),
                ("safelist:config", "2001:db8::/64"),
                ("safelist:github-meta", "192.0.2.0/24"),
                ("safelist:github-meta", "2001:db8:1::/64"),
            ]
        );
    }

    #[test]
    fn loads_static_safelist_without_cache_directories() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let config = Config::from_toml_str(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             [safe]\n\
             ips = ['192.0.2.0/24']\n\
             include_github_meta = false\n",
        )
        .expect("valid config");

        let entries = load_lookup_sources(&paths, Some(&config)).expect("load sources");

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].source_label.as_ref(), "safelist:config");
        assert_eq!(entries[0].source_line, "192.0.2.0/24");
    }

    #[test]
    fn github_safelist_respects_custom_url_and_selected_categories() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let github_meta_url = "https://example.com/meta.json";
        let config = Config::from_toml_str(&format!(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             [safe]\n\
             include_github_meta = true\n\
             github_meta_url = '{github_meta_url}'\n\
             github_meta_categories = ['api']\n"
        ))
        .expect("valid config");
        let raw = br#"{"api":["192.0.2.0/24"],"actions":["198.51.100.0/24"]}"#;

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote cache");
        fs::write(paths.remote_cache_dir.join("github-meta.raw.json"), raw)
            .expect("write GitHub cache");
        fs::write(
            paths.remote_cache_dir.join("github-meta.meta.json"),
            format!(
                r#"{{"url":"{github_meta_url}","etag":null,"last_modified":null,"sha256_raw":"{}"}}"#,
                sha256_hex(raw)
            ),
        )
        .expect("write GitHub metadata");
        fs::write(
            paths.remote_cache_dir.join("github-meta.categories.json"),
            r#"{"mode":"selected","categories":["api"]}"#,
        )
        .expect("write GitHub category cache");

        let entries = load_lookup_sources(&paths, Some(&config)).expect("load sources");
        let rendered = entries
            .iter()
            .map(|entry| (entry.source_label.as_ref(), entry.source_line.as_str()))
            .collect::<Vec<_>>();

        assert_eq!(rendered, vec![("safelist:github-meta", "192.0.2.0/24")]);
    }

    #[test]
    fn missing_configured_asn_cache_is_not_resolved_or_globbed() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let config = Config::from_toml_str(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             [safe]\n\
             include_github_meta = false\n\
             [asn]\n\
             banned = [64512]\n",
        )
        .expect("valid config");

        fs::create_dir_all(paths.cache_dir.join("asn")).expect("mkdir ASN cache");
        fs::write(
            paths.cache_dir.join("asn/as64513.iplist"),
            "203.0.113.0/24\n",
        )
        .expect("write unconfigured ASN cache");

        let entries = load_lookup_sources(&paths, Some(&config)).expect("load sources");

        assert!(entries.is_empty());
    }

    #[test]
    fn disabled_github_safelist_cache_is_not_loaded() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());
        let config = Config::from_toml_str(
            "[ipset]\n\
             set_name = 'kidobo'\n\
             [safe]\n\
             include_github_meta = false\n\
             github_meta_categories = ['api']\n",
        )
        .expect("valid config");

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote cache");
        fs::write(
            paths.remote_cache_dir.join("github-meta.raw.json"),
            r#"{"api":["192.0.2.0/24"]}"#,
        )
        .expect("write GitHub cache");
        fs::write(
            paths.remote_cache_dir.join("github-meta.categories.json"),
            r#"{"mode":"selected","categories":["api"]}"#,
        )
        .expect("write GitHub category cache");

        let entries = load_lookup_sources(&paths, Some(&config)).expect("load sources");

        assert!(entries.is_empty());
    }

    #[test]
    fn missing_source_files_return_empty_entries() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        let entries = load_lookup_sources(&paths, None).expect("load sources");
        assert!(entries.is_empty());
    }

    #[test]
    fn source_read_errors_are_reported() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.blocklist_file).expect("make dir instead of file");

        let err = load_lookup_sources(&paths, None).expect_err("must fail");
        assert!(err.to_string().contains("failed to read source file"));
    }

    #[test]
    fn oversized_remote_iplist_is_rejected() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir remote");
        fs::write(
            paths.remote_cache_dir.join("a.iplist"),
            "1".repeat(super::SOURCE_FILE_READ_LIMIT + 1),
        )
        .expect("write oversized iplist");

        let err = load_lookup_sources(&paths, None).expect_err("must fail");
        match err {
            LookupSourceLoadError::Source(SourceLoadError::Source { reason, .. }) => {
                assert!(reason.contains("file exceeds 16777216 byte limit"));
            }
            _ => panic!("expected source read error"),
        }
    }

    #[test]
    fn cache_dir_entry_errors_are_reported() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.remote_cache_dir.parent().expect("parent")).expect("mkdir cache");
        fs::write(&paths.remote_cache_dir, "not a directory").expect("write file");

        let err = load_lookup_sources(&paths, None).expect_err("must fail");
        assert!(matches!(
            err,
            LookupSourceLoadError::Source(
                SourceLoadError::CacheDir { .. } | SourceLoadError::CacheDirEntry { .. }
            )
        ));
    }

    #[test]
    fn parse_lookup_source_line_tolerates_comments_and_blank_lines() {
        assert!(parse_cidr_source_line("# comment").is_none());
        assert!(parse_cidr_source_line("   ").is_none());

        let parsed = parse_cidr_source_line("203.0.113.1 # trailing").expect("parse");
        assert_eq!(parsed.1, "203.0.113.1");
    }

    #[test]
    fn io_error_display_is_stable() {
        let io_err = std::io::Error::other("boom");
        assert_eq!(io_err.to_string(), "boom");
    }
}
