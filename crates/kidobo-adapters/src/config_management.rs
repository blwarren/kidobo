//! Formatting-preserving, bounded configuration management and read-only source cache evidence.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use kidobo_app::AppError;
use kidobo_app::configuration::{
    CacheAvailability, ConfigurationDocument, ConfigurationEdit, ConfigurationEditor,
    ConfigurationReader, ConfigurationWriteMode, ConfigurationWriter, SourceCacheInspector,
    SourceCacheStatus,
};
use kidobo_core::config::{Config, ConfigError};
use kidobo_core::network::{CanonicalCidr, parse_ip_cidr_strict};
use reqwest::Url;
use toml_edit::{Array, DocumentMut, Item, Table, Value, value};

use crate::config::CONFIG_READ_LIMIT;
use crate::http_cache::inspect_cached_source;
use crate::limited_io::{read_to_string_with_limit, write_string_atomic_with_limit};

static NEW_CONFIG_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Exact configuration reads, pure TOML editing, and atomic publication through narrow app ports.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileConfigurationManager;

impl ConfigurationReader for FileConfigurationManager {
    fn read(&self, path: &Path) -> Result<Option<ConfigurationDocument>, AppError> {
        let contents = match read_to_string_with_limit(path, CONFIG_READ_LIMIT) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(AppError::ConfigRead {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let document = parse_document(&contents)?;
        let mut explicit_fields = BTreeSet::new();
        for (section, item) in document.iter() {
            if let Some(table) = item.as_table_like() {
                for (key, _) in table.iter() {
                    explicit_fields.insert(format!("{section}.{key}"));
                }
            }
        }
        let legacy_remote_stale_after_secs = document
            .get("remote")
            .and_then(Item::as_table_like)
            .and_then(|table| table.get("cache_stale_after_secs"))
            .and_then(Item::as_integer)
            .and_then(|value| u64::try_from(value).ok());
        Ok(Some(ConfigurationDocument {
            contents,
            explicit_fields,
            legacy_remote_stale_after_secs,
        }))
    }
}

impl ConfigurationEditor for FileConfigurationManager {
    fn render(&self, original: &str, edit: &ConfigurationEdit) -> Result<String, AppError> {
        let config = Config::from_toml_str(original)?;
        let mut document = parse_document(original)?;
        match edit {
            ConfigurationEdit::AddSource(url) => {
                edit_source(&mut document, &config.remote.urls, url, true)?;
            }
            ConfigurationEdit::RemoveSource(url) => {
                edit_source(&mut document, &config.remote.urls, url, false)?;
            }
            ConfigurationEdit::AddAllow(target) => {
                edit_allow(&mut document, &config.safe.ips, target, true)?;
            }
            ConfigurationEdit::RemoveAllow(target) => {
                edit_allow(&mut document, &config.safe.ips, target, false)?;
            }
            ConfigurationEdit::SetBasic {
                enable_ipv6,
                include_github_meta,
                remote_urls,
                safe_ips,
            } => {
                if config.ipset.enable_ipv6 != *enable_ipv6 {
                    set_boolean(&mut document, "ipset", "enable_ipv6", *enable_ipv6)?;
                }
                if config.safe.include_github_meta != *include_github_meta {
                    set_boolean(
                        &mut document,
                        "safe",
                        "include_github_meta",
                        *include_github_meta,
                    )?;
                }
                replace_sources(&mut document, &config.remote.urls, remote_urls)?;
                replace_allow(&mut document, &config.safe.ips, safe_ips)?;
            }
        }
        let candidate = document.to_string();
        ensure_size(&candidate)?;
        Config::from_toml_str(&candidate)?;
        Ok(candidate)
    }
}

impl ConfigurationWriter for FileConfigurationManager {
    fn write(
        &self,
        path: &Path,
        contents: &str,
        mode: ConfigurationWriteMode,
    ) -> Result<(), AppError> {
        ensure_size(contents)?;
        Config::from_toml_str(contents)?;
        match mode {
            ConfigurationWriteMode::ReplaceExisting => {
                write_string_atomic_with_limit(path, contents, CONFIG_READ_LIMIT).map_err(
                    |source| AppError::ConfigWrite {
                        path: path.to_path_buf(),
                        source,
                    },
                )
            }
            ConfigurationWriteMode::CreateNew => publish_new(path, contents),
        }
    }
}

/// Read-only per-URL cache inspection without network clients, staging, repair, or cleanup.
#[derive(Debug, Default, Clone, Copy)]
pub struct FileSourceCacheInspector;

impl SourceCacheInspector for FileSourceCacheInspector {
    fn inspect(&self, cache_dir: &Path, url: &str, maxelem: u32) -> SourceCacheStatus {
        match inspect_cached_source(cache_dir, url, maxelem) {
            Ok(Some(provenance)) => SourceCacheStatus {
                availability: CacheAvailability::Available,
                provenance: Some(provenance.to_string()),
                detail: "Compatible cached contents were selected; refresh time is not recorded"
                    .to_string(),
            },
            Ok(None) => SourceCacheStatus {
                availability: CacheAvailability::Unavailable,
                provenance: None,
                detail: "No usable compatible cached contents were selected; freshness is unknown"
                    .to_string(),
            },
            Err(error) => SourceCacheStatus {
                availability: CacheAvailability::Unknown,
                provenance: None,
                detail: format!("Cache availability could not be verified: {error}"),
            },
        }
    }
}

fn parse_document(contents: &str) -> Result<DocumentMut, AppError> {
    contents
        .parse::<DocumentMut>()
        .map_err(|error| AppError::ConfigParse {
            source: ConfigError::Parse {
                reason: error.to_string(),
            },
        })
}

fn edit_error(reason: &str) -> AppError {
    AppError::ConfigurationEdit {
        reason: reason.to_string(),
    }
}

fn ensure_size(contents: &str) -> Result<(), AppError> {
    if contents.len() > CONFIG_READ_LIMIT {
        return Err(edit_error(
            "proposed configuration exceeds the 65536-byte limit",
        ));
    }
    Ok(())
}

fn normalized_url(input: &str) -> Result<Url, AppError> {
    let url = Url::parse(input.trim())
        .map_err(|_| edit_error("source must be an HTTP or HTTPS URL with a host"))?;
    if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
        return Err(edit_error(
            "source must be an HTTP or HTTPS URL with a host",
        ));
    }
    Ok(url)
}

fn canonical_target(input: &str) -> Result<CanonicalCidr, AppError> {
    parse_ip_cidr_strict(input)
        .ok_or_else(|| edit_error("safelist target must be one IPv4 or IPv6 address or CIDR"))
}

fn array_mut<'a>(
    document: &'a mut DocumentMut,
    section: &'static str,
    key: &'static str,
) -> Result<&'a mut Array, AppError> {
    let section = document.entry(section).or_insert(Item::Table(Table::new()));
    let table = section
        .as_table_like_mut()
        .ok_or_else(|| edit_error("configuration section is not a table"))?;
    table
        .entry(key)
        .or_insert(value(Array::new()))
        .as_array_mut()
        .ok_or_else(|| edit_error("configuration setting is not an array"))
}

fn set_boolean(
    document: &mut DocumentMut,
    section: &'static str,
    key: &'static str,
    setting: bool,
) -> Result<(), AppError> {
    let section = document.entry(section).or_insert(Item::Table(Table::new()));
    let table = section
        .as_table_like_mut()
        .ok_or_else(|| edit_error("configuration section is not a table"))?;
    let item = table.entry(key).or_insert(value(setting));
    let decoration = item.as_value().map(|value| value.decor().clone());
    *item = value(setting);
    if let (Some(decoration), Some(value)) = (decoration, item.as_value_mut()) {
        *value.decor_mut() = decoration;
    }
    Ok(())
}

fn edit_source(
    document: &mut DocumentMut,
    existing: &[String],
    input: &str,
    add: bool,
) -> Result<(), AppError> {
    let identity = normalized_url(input)?;
    let present = existing
        .iter()
        .any(|url| normalized_url(url).is_ok_and(|url| url == identity));
    if add && present {
        return Err(edit_error(
            "source is already configured; use kidobo sources list to inspect it",
        ));
    }
    if !add && !present {
        return Ok(());
    }
    let array = array_mut(document, "remote", "urls")?;
    if add {
        append_value(array, Value::from(input.trim()));
    } else {
        array.retain(|value| {
            value
                .as_str()
                .and_then(|url| normalized_url(url).ok())
                .is_none_or(|url| url != identity)
        });
    }
    Ok(())
}

fn edit_allow(
    document: &mut DocumentMut,
    existing: &[CanonicalCidr],
    input: &str,
    add: bool,
) -> Result<(), AppError> {
    let identity = canonical_target(input)?;
    let present = existing.contains(&identity);
    if add == present {
        return Ok(());
    }
    let array = array_mut(document, "safe", "ips")?;
    if add {
        append_value(array, Value::from(identity.to_string()));
    } else {
        array.retain(|value| value.as_str().and_then(parse_ip_cidr_strict) != Some(identity));
    }
    Ok(())
}

fn replace_sources(
    document: &mut DocumentMut,
    existing: &[String],
    requested: &[String],
) -> Result<(), AppError> {
    let old_identities = existing
        .iter()
        .map(|url| normalized_url(url).map(|url| url.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let identities = requested
        .iter()
        .map(|url| normalized_url(url).map(|url| url.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if old_identities == identities {
        return Ok(());
    }
    if identities.iter().collect::<BTreeSet<_>>().len() != identities.len() {
        return Err(edit_error(
            "setup sources contain duplicate normalized URLs",
        ));
    }
    let array = array_mut(document, "remote", "urls")?;
    let trailing_owner = array
        .iter()
        .last()
        .and_then(Value::as_str)
        .and_then(|url| normalized_url(url).ok());
    let preserved = array
        .iter()
        .filter_map(|value| {
            value
                .as_str()
                .and_then(|url| normalized_url(url).ok())
                .map(|url| (url.to_string(), value.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    array.clear();
    for (identity, requested) in identities.iter().zip(requested) {
        let value = preserved
            .get(identity)
            .cloned()
            .unwrap_or_else(|| Value::from(requested.trim()));
        let previous = array
            .iter()
            .last()
            .and_then(Value::as_str)
            .and_then(|url| normalized_url(url).ok());
        if previous.is_some() && previous == trailing_owner {
            append_value(array, value);
        } else {
            array.push_formatted(value);
        }
    }
    Ok(())
}

fn replace_allow(
    document: &mut DocumentMut,
    existing: &[CanonicalCidr],
    requested: &[String],
) -> Result<(), AppError> {
    let identities = requested
        .iter()
        .map(|target| canonical_target(target))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if existing.iter().copied().collect::<BTreeSet<_>>() == identities {
        return Ok(());
    }
    let array = array_mut(document, "safe", "ips")?;
    let trailing_owner = array
        .iter()
        .last()
        .and_then(Value::as_str)
        .and_then(parse_ip_cidr_strict);
    let preserved = array
        .iter()
        .filter_map(|value| {
            value
                .as_str()
                .and_then(parse_ip_cidr_strict)
                .map(|target| (target, value.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    array.clear();
    for target in identities {
        let value = preserved
            .get(&target)
            .cloned()
            .unwrap_or_else(|| Value::from(target.to_string()));
        let previous = array
            .iter()
            .last()
            .and_then(Value::as_str)
            .and_then(parse_ip_cidr_strict);
        if previous.is_some() && previous == trailing_owner {
            append_value(array, value);
        } else {
            array.push_formatted(value);
        }
    }
    Ok(())
}

fn append_value(array: &mut Array, mut value: Value) {
    let trailing = array.trailing().as_str().unwrap_or_default();
    if trailing.contains('\n') {
        let closing_indent = trailing.rsplit('\n').next().unwrap_or_default();
        let entry_indent = array
            .iter()
            .last()
            .and_then(|value| value.decor().prefix())
            .and_then(|prefix| prefix.as_str())
            .and_then(|prefix| prefix.rsplit('\n').next())
            .filter(|indent| indent.chars().all(char::is_whitespace))
            .unwrap_or("  ");
        let previous_prefix = value.decor().prefix().and_then(|prefix| prefix.as_str());
        let prefix =
            if let Some(previous_prefix) = previous_prefix.filter(|prefix| prefix.contains('\n')) {
                format!(
                    "{}{previous_prefix}",
                    trailing.trim_end_matches([' ', '\t'])
                )
            } else {
                format!("{}{entry_indent}", trailing.trim_end_matches([' ', '\t']))
            };
        let newline = if trailing.contains("\r\n") {
            "\r\n"
        } else {
            "\n"
        };
        let closing = format!("{newline}{closing_indent}");
        value.decor_mut().set_prefix(prefix);
        array.set_trailing(closing);
    }
    array.push_formatted(value);
}

fn publish_new(path: &Path, contents: &str) -> Result<(), AppError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|source| AppError::ConfigWrite {
        path: path.to_path_buf(),
        source,
    })?;
    let (temporary_path, mut file) =
        create_temporary(parent).map_err(|source| AppError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })?;
    let publication = (|| -> io::Result<()> {
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::hard_link(&temporary_path, path)?;
        Ok(())
    })();
    let cleanup = fs::remove_file(&temporary_path);
    if let Err(source) = publication {
        if source.kind() == io::ErrorKind::AlreadyExists {
            return Err(AppError::ConfigurationChanged);
        }
        return Err(AppError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        });
    }
    cleanup.map_err(|source| AppError::ConfigWrite {
        path: path.to_path_buf(),
        source,
    })?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| AppError::ConfigWrite {
            path: path.to_path_buf(),
            source,
        })
}

fn create_temporary(parent: &Path) -> io::Result<(PathBuf, File)> {
    for _ in 0..16 {
        let sequence = NEW_CONFIG_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = parent.join(format!(
            ".kidobo-config-new-{}-{sequence}",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no unique configuration staging filename was available",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kidobo_app::configuration::{ReadDependencies, SettingOrigin, SettingValue};
    use kidobo_app::paths::PathResolutionInput;
    use kidobo_app::ports::NoCancellation;
    use tempfile::TempDir;

    const CONFIG: &str = "# configuration header\nipset = { set_name = 'custom', maxelem = 65536 }\nsafe = { ips = ['203.0.113.0/24'], include_github_meta = true }\nremote = { urls = ['HTTP://EXAMPLE.test:80/feed'], timeout_secs = 91 }\n# keep these ASN settings exactly\n[asn]\nbanned = [64512]\ncache_stale_after_secs = 7200\n";

    #[test]
    fn source_addition_and_removal_preserve_inline_tables_comments_and_stored_url_spelling() {
        let manager = FileConfigurationManager;
        let added = manager
            .render(
                CONFIG,
                &ConfigurationEdit::AddSource("https://second.test/list".to_string()),
            )
            .expect("add");
        assert!(added.starts_with("# configuration header\n"));
        assert!(added.contains("'HTTP://EXAMPLE.test:80/feed'"));
        assert!(added.contains("# keep these ASN settings exactly\n[asn]\nbanned = [64512]\ncache_stale_after_secs = 7200\n"));
        assert!(added.contains("safe = { ips = ['203.0.113.0/24'], include_github_meta = true }"));
        let config = Config::from_toml_str(&added).expect("valid candidate");
        assert_eq!(
            config.remote.urls,
            ["HTTP://EXAMPLE.test:80/feed", "https://second.test/list"]
        );
        assert_eq!(config.remote.timeout_secs.get(), 91);
        let removed = manager
            .render(
                &added,
                &ConfigurationEdit::RemoveSource("http://example.test/feed".to_string()),
            )
            .expect("remove equivalent URL");
        assert_eq!(
            Config::from_toml_str(&removed).expect("config").remote.urls,
            ["https://second.test/list"]
        );
        assert!(removed.contains("remote = { urls = ["));
        assert!(removed.contains("timeout_secs = 91 }"));
    }

    #[test]
    fn multiline_array_additions_preserve_existing_comments_and_literals() {
        let original = "[ipset]\nset_name='kidobo'\n[remote]\nurls = [\n  # first source explanation\n  'https://first.test/list', # preserve this annotation\n]\n# unrelated tail\n[safe]\nips=[]\n";
        let candidate = FileConfigurationManager
            .render(
                original,
                &ConfigurationEdit::AddSource("https://second.test/list".to_string()),
            )
            .expect("candidate");
        assert!(candidate.contains("# first source explanation"));
        assert!(
            candidate.contains("'https://first.test/list', # preserve this annotation"),
            "{candidate}"
        );
        assert!(candidate.contains("# unrelated tail\n[safe]\nips=[]\n"));
        assert_eq!(
            Config::from_toml_str(&candidate)
                .expect("config")
                .remote
                .urls
                .len(),
            2
        );
    }

    #[test]
    fn normalized_source_duplicates_and_invalid_inputs_are_rejected_without_secret_error_values() {
        let manager = FileConfigurationManager;
        let duplicate = manager
            .render(
                CONFIG,
                &ConfigurationEdit::AddSource("http://example.test/feed".to_string()),
            )
            .expect_err("semantic duplicate");
        assert!(matches!(duplicate, AppError::ConfigurationEdit { .. }));
        for input in [
            "file:///etc/passwd",
            "ftp://feed.test/list",
            "not a URL",
            "https://",
        ] {
            assert!(matches!(
                manager.render(CONFIG, &ConfigurationEdit::AddSource(input.to_string())),
                Err(AppError::ConfigurationEdit { .. })
            ));
        }
        let candidate = manager
            .render(
                CONFIG,
                &ConfigurationEdit::RemoveSource("https://absent.test".to_string()),
            )
            .expect("absent source no-op");
        assert_eq!(candidate, CONFIG);
    }

    #[test]
    fn safelist_edits_use_canonical_exact_identities_without_carving_ranges() {
        let manager = FileConfigurationManager;
        assert_eq!(
            manager
                .render(
                    CONFIG,
                    &ConfigurationEdit::RemoveAllow("203.0.113.7".to_string())
                )
                .expect("inside range is not exact"),
            CONFIG
        );
        assert_eq!(
            manager
                .render(
                    CONFIG,
                    &ConfigurationEdit::AddAllow("203.0.113.123/24".to_string())
                )
                .expect("equivalent identity no-op"),
            CONFIG
        );
        let added = manager
            .render(
                CONFIG,
                &ConfigurationEdit::AddAllow("2001:db8::1234/64".to_string()),
            )
            .expect("IPv6 addition");
        assert_eq!(
            Config::from_toml_str(&added)
                .expect("config")
                .safe
                .ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["203.0.113.0/24", "2001:db8::/64"]
        );
        let removed = manager
            .render(
                &added,
                &ConfigurationEdit::RemoveAllow("2001:0db8:0000:0000::/64".to_string()),
            )
            .expect("equivalent IPv6 removal");
        assert_eq!(
            Config::from_toml_str(&removed)
                .expect("config")
                .safe
                .ips
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["203.0.113.0/24"]
        );
        assert!(matches!(
            manager.render(
                CONFIG,
                &ConfigurationEdit::AddAllow("203.0.113.7 trailing".to_string())
            ),
            Err(AppError::ConfigurationEdit { .. })
        ));
    }

    #[test]
    fn basic_setup_edits_preserve_retained_sources_and_scalar_comments() {
        let original = "[ipset]\nset_name='kidobo'\nenable_ipv6=true # preserve IPv6 explanation\n[safe]\ninclude_github_meta=true # preserve GitHub explanation\nips=['203.0.113.0/24']\n[remote]\nurls=['HTTP://EXAMPLE.test:80/feed']\n";
        let candidate = FileConfigurationManager
            .render(
                original,
                &ConfigurationEdit::SetBasic {
                    enable_ipv6: false,
                    include_github_meta: false,
                    remote_urls: vec![
                        "http://example.test/feed".to_string(),
                        "https://second.test/list".to_string(),
                    ],
                    safe_ips: vec!["203.0.113.17/24".to_string(), "2001:db8::/64".to_string()],
                },
            )
            .expect("basic settings");
        assert!(candidate.contains("enable_ipv6=false # preserve IPv6 explanation"));
        assert!(candidate.contains("include_github_meta=false # preserve GitHub explanation"));
        assert!(candidate.contains("'HTTP://EXAMPLE.test:80/feed'"));
        let config = Config::from_toml_str(&candidate).expect("valid basic settings");
        assert!(!config.ipset.enable_ipv6);
        assert!(!config.safe.include_github_meta);
        assert_eq!(
            config.remote.urls,
            ["HTTP://EXAMPLE.test:80/feed", "https://second.test/list"]
        );
        assert_eq!(config.safe.ips.len(), 2);
        let duplicate = ConfigurationEdit::SetBasic {
            enable_ipv6: false,
            include_github_meta: false,
            remote_urls: vec![
                "http://example.test/feed".to_string(),
                "HTTP://EXAMPLE.test:80/feed".to_string(),
            ],
            safe_ips: Vec::new(),
        };
        assert!(matches!(
            FileConfigurationManager.render(original, &duplicate),
            Err(AppError::ConfigurationEdit { .. })
        ));
    }

    #[test]
    fn complete_candidate_validation_prevents_enabling_an_invalid_derived_ipv6_set_name() {
        let original = format!(
            "[ipset]\nset_name='{}'\nenable_ipv6=false\n",
            "a".repeat(31)
        );
        let edit = ConfigurationEdit::SetBasic {
            enable_ipv6: true,
            include_github_meta: true,
            remote_urls: Vec::new(),
            safe_ips: Vec::new(),
        };
        assert!(matches!(
            FileConfigurationManager.render(&original, &edit),
            Err(AppError::ConfigParse { .. })
        ));
        let unknown = "[ipset]\nset_name='kidobo'\nunknown=true\n";
        assert!(matches!(
            FileConfigurationManager.render(
                unknown,
                &ConfigurationEdit::AddAllow("203.0.113.7".to_string())
            ),
            Err(AppError::ConfigParse { .. })
        ));
    }

    #[test]
    fn serialized_byte_limit_is_checked_before_any_directory_or_file_write() {
        let original = format!(
            "#é{}\n[ipset]\nset_name='kidobo'\n",
            "x".repeat(CONFIG_READ_LIMIT - 37)
        );
        assert!(original.len() < CONFIG_READ_LIMIT);
        assert!(matches!(
            FileConfigurationManager.render(
                &original,
                &ConfigurationEdit::AddSource("https://feed.test/list".to_string())
            ),
            Err(AppError::ConfigurationEdit { .. })
        ));
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("absent/config.toml");
        let oversized = format!(
            "[ipset]\nset_name='kidobo'\n#{}",
            "é".repeat(CONFIG_READ_LIMIT)
        );
        assert!(matches!(
            FileConfigurationManager.write(&path, &oversized, ConfigurationWriteMode::CreateNew),
            Err(AppError::ConfigurationEdit { .. })
        ));
        assert!(!path.parent().expect("parent").exists());
    }

    #[test]
    fn fresh_publication_is_atomic_and_never_replaces_a_file_that_appeared() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("new/config.toml");
        FileConfigurationManager
            .write(&path, CONFIG, ConfigurationWriteMode::CreateNew)
            .expect("publish new");
        assert_eq!(
            read_to_string_with_limit(&path, CONFIG_READ_LIMIT).expect("saved"),
            CONFIG
        );
        let replacement = "[ipset]\nset_name='other'\n";
        assert!(matches!(
            FileConfigurationManager.write(&path, replacement, ConfigurationWriteMode::CreateNew),
            Err(AppError::ConfigurationChanged)
        ));
        assert_eq!(
            read_to_string_with_limit(&path, CONFIG_READ_LIMIT).expect("unchanged"),
            CONFIG
        );
        assert_eq!(
            fs::read_dir(path.parent().expect("parent"))
                .expect("directory")
                .count(),
            1
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn replacement_preserves_permissions_and_atomic_failures_leave_complete_existing_state() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        fs::write(&path, CONFIG).expect("original");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode");
        }
        let candidate = FileConfigurationManager
            .render(
                CONFIG,
                &ConfigurationEdit::AddSource("https://second.test".to_string()),
            )
            .expect("candidate");
        FileConfigurationManager
            .write(&path, &candidate, ConfigurationWriteMode::ReplaceExisting)
            .expect("replace");
        assert_eq!(
            read_to_string_with_limit(&path, CONFIG_READ_LIMIT).expect("saved"),
            candidate
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
                0o640
            );
        }
        let directory = temp.path().join("directory");
        fs::create_dir(&directory).expect("directory");
        fs::write(directory.join("keep"), "original").expect("retained file");
        assert!(matches!(
            FileConfigurationManager.write(
                &directory,
                CONFIG,
                ConfigurationWriteMode::ReplaceExisting
            ),
            Err(AppError::ConfigWrite { .. })
        ));
        assert_eq!(
            read_to_string_with_limit(&directory.join("keep"), 32).expect("retained"),
            "original"
        );
        assert_eq!(
            fs::read_dir(temp.path()).expect("no staging leaks").count(),
            2
        );
    }

    fn request(root: &Path) -> PathResolutionInput {
        PathResolutionInput {
            explicit_config_path: None,
            temp_dir: PathBuf::from("/tmp"),
            env: [("KIDOBO_ROOT".into(), root.as_os_str().to_os_string())].into(),
        }
    }

    #[test]
    fn effective_view_attributes_explicit_defaults_derived_names_and_ignored_legacy_values() {
        let temp = TempDir::new().expect("tempdir");
        fs::create_dir(temp.path().join("config")).expect("config dir");
        fs::write(temp.path().join("config/config.toml"), "[ipset]\nset_name='custom'\n[safe]\ngithub_meta_categories=[]\n[remote]\ncache_stale_after_secs=7200\n").expect("config");
        let view = kidobo_app::configuration::read(
            &request(temp.path()),
            false,
            &ReadDependencies {
                cancellation: &NoCancellation,
                paths: &crate::path::SystemPathResolver,
                reader: &FileConfigurationManager,
            },
        )
        .expect("effective view");
        let setting = |key| {
            view.settings
                .iter()
                .find(|setting| setting.key == key)
                .expect("setting")
        };
        assert_eq!(setting("ipset.set_name").origin, SettingOrigin::Explicit);
        assert_eq!(setting("ipset.set_name_v6").origin, SettingOrigin::Derived);
        assert_eq!(
            setting("ipset.set_name_v6").value,
            SettingValue::Text("custom-v6".to_string())
        );
        assert_eq!(setting("ipset.maxelem").origin, SettingOrigin::Default);
        assert_eq!(
            setting("ipset.maxelem").value,
            SettingValue::Number(500_000)
        );
        let legacy = setting("remote.cache_stale_after_secs");
        assert_eq!(legacy.origin, SettingOrigin::Explicit);
        assert_eq!(legacy.value, SettingValue::Number(7200));
        assert!(
            legacy
                .note
                .expect("legacy explanation")
                .contains("does not control refresh")
        );
        assert_eq!(
            setting("safe.github_meta_categories").value,
            SettingValue::Strings(Vec::new())
        );
        assert!(
            setting("safe.github_meta_categories")
                .note
                .expect("category explanation")
                .contains("all categories")
        );
    }

    #[test]
    fn missing_and_invalid_document_reads_do_not_create_configuration_state() {
        let temp = TempDir::new().expect("tempdir");
        let missing = temp.path().join("absent/config.toml");
        assert!(
            FileConfigurationManager
                .read(&missing)
                .expect("missing read")
                .is_none()
        );
        assert!(!missing.parent().expect("parent").exists());
        let invalid = temp.path().join("invalid.toml");
        fs::write(&invalid, [0xff, 0xfe]).expect("invalid UTF8");
        assert!(
            matches!(FileConfigurationManager.read(&invalid), Err(AppError::ConfigRead { source, .. }) if source.kind() == io::ErrorKind::InvalidData)
        );
        fs::write(&invalid, "[invalid").expect("invalid TOML");
        assert!(matches!(
            FileConfigurationManager.read(&invalid),
            Err(AppError::ConfigParse { .. })
        ));
    }

    #[test]
    fn validated_generation_inspection_does_not_stage_promote_or_prune_orphan_data() {
        struct SeedClient;
        impl crate::http_client::HttpClient for SeedClient {
            fn fetch(
                &self,
                _: crate::http_client::HttpRequest,
            ) -> Result<crate::http_client::HttpResponse, crate::http_client::HttpClientError>
            {
                Ok(crate::http_client::HttpResponse {
                    status: reqwest::StatusCode::OK,
                    body: b"203.0.113.0/24\n".to_vec(),
                    etag: Some("fixture-etag".to_string()),
                    last_modified: Some("Tue, 20 Oct 2026 12:00:00 GMT".to_string()),
                })
            }
        }
        fn inventory(path: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
            for entry in fs::read_dir(path).expect("directory") {
                let path = entry.expect("entry").path();
                if path.is_dir() {
                    inventory(&path, files);
                } else {
                    files.insert(
                        path.clone(),
                        crate::limited_io::read_bytes_with_limit(&path, 1024 * 1024)
                            .expect("bounded fixture file"),
                    );
                }
            }
        }
        let temp = TempDir::new().expect("tempdir");
        let url = "https://feed.test/list";
        let prepared = crate::http_cache::prepare_iplist_with_cache(
            &SeedClient,
            url,
            temp.path(),
            &BTreeMap::new(),
            500_000,
        )
        .expect("seed generation");
        prepared
            .pending_promotion
            .expect("promotion")
            .promote()
            .expect("select fixture generation");
        let orphan = crate::http_cache::remote_generation_store(temp.path(), url)
            .join("generations/orphan-fixture");
        fs::create_dir(&orphan).expect("orphan");
        fs::write(orphan.join("keep"), "unselected fixture data").expect("orphan data");
        let mut before = BTreeMap::new();
        inventory(temp.path(), &mut before);
        let status = FileSourceCacheInspector.inspect(temp.path(), url, 500_000);
        assert_eq!(status.availability, CacheAvailability::Available);
        assert_eq!(
            status.provenance.as_deref(),
            Some("validated cache generation")
        );
        let mut after = BTreeMap::new();
        inventory(temp.path(), &mut after);
        assert_eq!(after, before);
    }

    #[test]
    fn source_cache_inspection_is_read_only_and_never_invents_freshness() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path().join("missing-cache");
        let unavailable =
            FileSourceCacheInspector.inspect(&cache_dir, "https://feed.test/list", 500_000);
        assert_eq!(unavailable.availability, CacheAvailability::Unavailable);
        assert!(!cache_dir.exists());
        fs::create_dir(&cache_dir).expect("cache");
        let paths = crate::http_cache::cache_paths_for_url(&cache_dir, "https://feed.test/list");
        fs::write(&paths.iplist_path, "203.0.113.0/24\n").expect("legacy cache");
        let before = read_to_string_with_limit(&paths.iplist_path, 1024).expect("before");
        let available =
            FileSourceCacheInspector.inspect(&cache_dir, "https://feed.test/list", 500_000);
        assert_eq!(available.availability, CacheAvailability::Available);
        assert_eq!(
            available.provenance.as_deref(),
            Some("compatible legacy cache")
        );
        assert!(available.detail.contains("refresh time is not recorded"));
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, 1024).expect("unchanged"),
            before
        );
        assert_eq!(
            fs::read_dir(&cache_dir).expect("cache unchanged").count(),
            1
        );
    }
}
