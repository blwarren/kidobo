//! Offline lookup source adapter.

use std::path::Path;
use std::sync::Arc;

use log::warn;
use thiserror::Error;

use crate::asn::{AsnError, load_cached_asn_prefixes};
use crate::cached_sources::load_remote_sources;
use crate::github_meta::load_cached_github_meta_safelist;
use crate::limited_io::read_to_string_with_limit;
use crate::source_files::{SOURCE_FILE_READ_LIMIT, parse_cidr_source_line};
use crate::source_load::SourceLoadError;
use kidobo_app::AppError;
use kidobo_app::source::{OfflineLookupContext, OfflineLookupProvider, OfflineLookupRegistry};
use kidobo_core::lookup::LookupSourceEntry;
use kidobo_core::network::CanonicalCidr;

#[derive(Debug, Error)]
enum LookupSourceLoadError {
    #[error(transparent)]
    Source(#[from] SourceLoadError),

    #[error(transparent)]
    Asn(#[from] AsnError),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct LocalBlocklistLookupProvider;

impl OfflineLookupProvider for LocalBlocklistLookupProvider {
    fn id(&self) -> &'static str {
        "local-blocklist"
    }

    fn append_offline(
        &self,
        context: &OfflineLookupContext<'_>,
        entries: &mut Vec<LookupSourceEntry>,
    ) -> Result<(), AppError> {
        if !context.paths.blocklist_file.exists() {
            return Ok(());
        }
        append_source_file(&context.paths.blocklist_file, "internal:blocklist", entries)
            .map_err(|error| map_lookup_error(&error))
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct RemoteCacheLookupProvider;

impl OfflineLookupProvider for RemoteCacheLookupProvider {
    fn id(&self) -> &'static str {
        "remote-cache"
    }

    fn append_offline(
        &self,
        context: &OfflineLookupContext<'_>,
        entries: &mut Vec<LookupSourceEntry>,
    ) -> Result<(), AppError> {
        let remote_sources = load_remote_sources(&context.paths.remote_cache_dir)
            .map_err(|error| map_lookup_error(&LookupSourceLoadError::from(error)))?;
        entries.reserve(
            remote_sources
                .iter()
                .map(|source| source.entries.len())
                .sum(),
        );
        for source in remote_sources {
            let source_label: Arc<str> = Arc::from(source.label);
            entries.extend(source.entries.into_iter().map(|entry| LookupSourceEntry {
                source_label: Arc::clone(&source_label),
                source_line: entry.source_line,
                cidr: entry.cidr,
            }));
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct ConfigSafelistLookupProvider;

impl OfflineLookupProvider for ConfigSafelistLookupProvider {
    fn id(&self) -> &'static str {
        "config-safelist"
    }

    fn append_offline(
        &self,
        context: &OfflineLookupContext<'_>,
        entries: &mut Vec<LookupSourceEntry>,
    ) -> Result<(), AppError> {
        if let Some(config) = context.config {
            append_canonical_entries(entries, "safelist:config", config.safe.ips.iter().copied());
        }
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct GithubMetaLookupProvider;

impl OfflineLookupProvider for GithubMetaLookupProvider {
    fn id(&self) -> &'static str {
        "github-meta-cache"
    }

    fn append_offline(
        &self,
        context: &OfflineLookupContext<'_>,
        entries: &mut Vec<LookupSourceEntry>,
    ) -> Result<(), AppError> {
        let Some(config) = context
            .config
            .filter(|config| config.safe.include_github_meta)
        else {
            return Ok(());
        };
        let Some(networks) = load_cached_github_meta_safelist(
            &context.paths.remote_cache_dir,
            &config.safe.github_meta_url,
            &config.safe.github_meta_category_mode(),
        ) else {
            warn!(
                "lookup GitHub meta safelist cache unavailable; GitHub safelist was not evaluated"
            );
            return Ok(());
        };
        append_canonical_entries(entries, "safelist:github-meta", networks);
        Ok(())
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct AsnCacheLookupProvider;

impl OfflineLookupProvider for AsnCacheLookupProvider {
    fn id(&self) -> &'static str {
        "asn-cache"
    }

    fn append_offline(
        &self,
        context: &OfflineLookupContext<'_>,
        entries: &mut Vec<LookupSourceEntry>,
    ) -> Result<(), AppError> {
        let Some(config) = context.config else {
            return Ok(());
        };
        let cache_dir = context.paths.cache_dir.join("asn");
        for asn in &config.asn.banned {
            let prefixes = load_cached_asn_prefixes(*asn, &cache_dir)
                .map_err(|error| map_lookup_error(&LookupSourceLoadError::from(error)))?;
            if let Some(prefixes) = prefixes {
                append_canonical_entries(entries, &format!("asn:AS{asn}"), prefixes);
            } else {
                warn!(
                    "lookup ASN cache unavailable for AS{asn}; this configured ASN was not evaluated"
                );
            }
        }
        Ok(())
    }
}

pub fn build_offline_lookup_registry() -> Result<OfflineLookupRegistry, AppError> {
    let mut registry = OfflineLookupRegistry::new();
    registry.register(LocalBlocklistLookupProvider)?;
    registry.register(RemoteCacheLookupProvider)?;
    registry.register(ConfigSafelistLookupProvider)?;
    registry.register(GithubMetaLookupProvider)?;
    registry.register(AsnCacheLookupProvider)?;
    Ok(registry)
}

fn map_lookup_error(error: &LookupSourceLoadError) -> AppError {
    AppError::LookupSourceLoad {
        reason: error.to_string(),
    }
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

fn append_source_file(
    path: &Path,
    source_label: &str,
    entries: &mut Vec<LookupSourceEntry>,
) -> Result<(), LookupSourceLoadError> {
    let contents = read_to_string_with_limit(path, SOURCE_FILE_READ_LIMIT).map_err(|err| {
        LookupSourceLoadError::from(SourceLoadError::Source {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })
    })?;

    let source_label: Arc<str> = Arc::from(source_label);
    entries.extend(
        contents
            .lines()
            .filter_map(parse_cidr_source_line)
            .map(|(cidr, token)| LookupSourceEntry {
                source_label: Arc::clone(&source_label),
                source_line: token.to_string(),
                cidr,
            }),
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::build_offline_lookup_registry;
    use crate::hash::sha256_hex;
    use crate::path::ResolvedPaths;
    use crate::source_files::parse_cidr_source_line;
    use kidobo_app::AppError;
    use kidobo_app::source::OfflineLookupContext;
    use kidobo_core::config::Config;

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

    fn load_registry_sources(
        paths: &ResolvedPaths,
        config: Option<&Config>,
    ) -> Result<Vec<kidobo_core::lookup::LookupSourceEntry>, AppError> {
        build_offline_lookup_registry()?.load(&OfflineLookupContext { paths, config })
    }

    #[test]
    fn offline_registry_has_stable_cache_only_provider_order() {
        assert_eq!(
            build_offline_lookup_registry()
                .expect("registry")
                .provider_ids(),
            [
                "local-blocklist",
                "remote-cache",
                "config-safelist",
                "github-meta-cache",
                "asn-cache",
            ]
        );
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

        let entries = load_registry_sources(&paths, None).expect("load sources");

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

        let entries = load_registry_sources(&paths, None).expect("load sources");

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

        let entries = load_registry_sources(&paths, None).expect("load sources");

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

        let err = load_registry_sources(&paths, None).expect_err("load must fail");
        assert!(err.to_string().contains("hash mismatch"));
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

        let entries = load_registry_sources(&paths, None).expect("load sources");
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

        let entries = load_registry_sources(&paths, None).expect("load sources");
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

        let entries = load_registry_sources(&paths, Some(&config)).expect("load sources");
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

        let entries = load_registry_sources(&paths, Some(&config)).expect("load sources");

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

        let entries = load_registry_sources(&paths, Some(&config)).expect("load sources");
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

        let entries = load_registry_sources(&paths, Some(&config)).expect("load sources");

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

        let entries = load_registry_sources(&paths, Some(&config)).expect("load sources");

        assert!(entries.is_empty());
    }

    #[test]
    fn missing_source_files_return_empty_entries() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        let entries = load_registry_sources(&paths, None).expect("load sources");
        assert!(entries.is_empty());
    }

    #[test]
    fn source_read_errors_are_reported() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.blocklist_file).expect("make dir instead of file");

        let err = load_registry_sources(&paths, None).expect_err("must fail");
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

        let err = load_registry_sources(&paths, None).expect_err("must fail");
        assert!(err.to_string().contains("file exceeds 16777216 byte limit"));
    }

    #[test]
    fn cache_dir_entry_errors_are_reported() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.remote_cache_dir.parent().expect("parent")).expect("mkdir cache");
        fs::write(&paths.remote_cache_dir, "not a directory").expect("write file");

        let err = load_registry_sources(&paths, None).expect_err("must fail");
        assert!(
            err.to_string()
                .contains("failed to read remote cache directory")
        );
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
