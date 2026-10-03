//! Formatting-preserving configuration mutation adapter.

use std::collections::BTreeSet;
use std::path::Path;

use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::config::CONFIG_READ_LIMIT;
use crate::limited_io::{read_to_string_with_limit, write_string_atomic_with_limit};
use kidobo_app::AppError;
use kidobo_core::config::{ConfigError, DEFAULT_ASN_CACHE_STALE_AFTER_SECS};

/// Exact changes made to the normalized configured ASN set.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AsnBanUpdateResult {
    /// ASNs newly added.
    pub added: Vec<u32>,
    /// ASNs that were present and removed.
    pub removed: Vec<u32>,
}

/// Atomically adds and removes ASNs while preserving unrelated TOML content.
///
/// # Errors
///
/// Returns an error when configuration cannot be read, parsed, validated, or atomically written.
pub fn update_asn_bans(
    config_path: &Path,
    add: &[u32],
    remove: &[u32],
) -> Result<AsnBanUpdateResult, AppError> {
    let mut doc = load_config_document(config_path)?;
    let table = doc.as_table_mut();
    let asn_value = table.entry("asn").or_insert(Item::Table(Table::new()));
    let asn_table = asn_value
        .as_table_like_mut()
        .ok_or_else(|| AppError::ConfigParse {
            source: ConfigError::InvalidField {
                field: "asn",
                reason: "must be a TOML table".to_string(),
            },
        })?;
    let existing = asn_table
        .get("banned")
        .map(parse_asn_list_from_toml)
        .transpose()?
        .unwrap_or_default();

    let mut before = BTreeSet::new();
    before.extend(existing);
    let mut after = before.clone();
    for asn in add {
        after.insert(*asn);
    }
    for asn in remove {
        after.remove(asn);
    }

    let added = after.difference(&before).copied().collect::<Vec<_>>();
    let removed = before.difference(&after).copied().collect::<Vec<_>>();
    let mut values = Array::default();
    for asn in after {
        values.push(i64::from(asn));
    }
    asn_table.insert("banned", value(values));
    if !asn_table.contains_key("cache_stale_after_secs") {
        asn_table.insert(
            "cache_stale_after_secs",
            value(i64::from(DEFAULT_ASN_CACHE_STALE_AFTER_SECS)),
        );
    }

    let rendered = doc.to_string();
    write_string_atomic_with_limit(config_path, &rendered, CONFIG_READ_LIMIT).map_err(|err| {
        AppError::ConfigWrite {
            path: config_path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;
    Ok(AsnBanUpdateResult { added, removed })
}

fn load_config_document(path: &Path) -> Result<DocumentMut, AppError> {
    let contents =
        read_to_string_with_limit(path, CONFIG_READ_LIMIT).map_err(|err| AppError::ConfigRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    contents
        .parse::<DocumentMut>()
        .map_err(|err| AppError::ConfigParse {
            source: ConfigError::Parse {
                reason: err.to_string(),
            },
        })
}

fn parse_asn_list_from_toml(value: &Item) -> Result<Vec<u32>, AppError> {
    let array = value.as_array().ok_or_else(|| AppError::ConfigParse {
        source: ConfigError::InvalidField {
            field: "asn.banned",
            reason: "must be an array".to_string(),
        },
    })?;
    let mut parsed = Vec::new();
    for raw in array {
        let Some(num) = raw.as_integer() else {
            return Err(AppError::ConfigParse {
                source: ConfigError::InvalidField {
                    field: "asn.banned",
                    reason: "must contain positive integers".to_string(),
                },
            });
        };
        if num <= 0 || num > i64::from(u32::MAX) {
            return Err(AppError::ConfigParse {
                source: ConfigError::InvalidField {
                    field: "asn.banned",
                    reason: "must contain positive integers".to_string(),
                },
            });
        }
        let parsed_asn = u32::try_from(num).map_err(|_| AppError::ConfigParse {
            source: ConfigError::InvalidField {
                field: "asn.banned",
                reason: "must contain positive integers".to_string(),
            },
        })?;
        parsed.push(parsed_asn);
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::update_asn_bans;
    use crate::limited_io::read_to_string_with_limit;
    use kidobo_app::AppError;
    use kidobo_core::config::DEFAULT_ASN_CACHE_STALE_AFTER_SECS;

    #[test]
    fn asn_table_representations_preserve_unrelated_settings() {
        for (asn, inline) in [
            (
                "asn = { banned = [64512, 64512], cache_stale_after_secs = 123 }\n",
                true,
            ),
            (
                "[asn]\nbanned = [64512, 64512]\ncache_stale_after_secs = 123\n",
                false,
            ),
            ("asn = { cache_stale_after_secs = 123 }\n", true),
        ] {
            let temp = TempDir::new().expect("tempdir");
            let path = temp.path().join("config.toml");
            let unrelated = "\n# preserve this\n[ipset]\nset_name = 'custom'\n";
            std::fs::write(&path, format!("# top\n{asn}{unrelated}")).expect("fixture");
            let added = update_asn_bans(&path, &[64513, 64513], &[]).expect("add");
            assert_eq!(added.added, vec![64513]);
            assert!(added.removed.is_empty());
            let duplicate = update_asn_bans(&path, &[64513], &[64514]).expect("no-op");
            assert_eq!(duplicate, super::AsnBanUpdateResult::default());
            let removed = update_asn_bans(&path, &[], &[64512, 64513]).expect("remove");
            assert_eq!(
                removed.removed,
                if asn.contains("64512") {
                    vec![64512, 64513]
                } else {
                    vec![64513]
                }
            );
            assert!(removed.added.is_empty());
            let rendered = read_to_string_with_limit(&path, 65536).expect("read");
            assert!(rendered.starts_with("# top\n"));
            assert!(rendered.ends_with(unrelated));
            let doc = rendered.parse::<toml_edit::DocumentMut>().expect("TOML");
            assert_eq!(doc["asn"].is_inline_table(), inline);
            let config = crate::config::load_config_from_file(&path).expect("config");
            assert_eq!(config.asn.banned, Vec::<u32>::new());
            assert_eq!(doc["asn"]["cache_stale_after_secs"].as_integer(), Some(123));
        }
    }

    #[test]
    fn inline_asn_creates_banned_and_default_cache_setting() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("config.toml");
        std::fs::write(&path, "asn = {}\n[ipset]\nset_name='kidobo'\n").expect("fixture");
        update_asn_bans(&path, &[64512], &[]).expect("update");
        let rendered = read_to_string_with_limit(&path, 65536).expect("read");
        let doc = rendered.parse::<toml_edit::DocumentMut>().expect("TOML");
        assert!(doc["asn"].is_inline_table());
        assert_eq!(
            doc["asn"]["cache_stale_after_secs"].as_integer(),
            Some(86400)
        );
        assert_eq!(
            crate::config::load_config_from_file(&path)
                .expect("config")
                .asn
                .banned,
            vec![64512]
        );
    }

    #[test]
    fn invalid_asn_representations_preserve_original_file() {
        for asn in [
            "asn = 42",
            "asn = { banned = 'bad' }",
            "asn = { banned = [0] }",
            "asn = { banned = [4294967296] }",
            "[asn]\nbanned = [-1]",
        ] {
            let temp = TempDir::new().expect("tempdir");
            let path = temp.path().join("config.toml");
            std::fs::write(&path, asn).expect("fixture");
            assert!(matches!(
                update_asn_bans(&path, &[64512], &[]),
                Err(AppError::ConfigParse { .. })
            ));
            assert_eq!(read_to_string_with_limit(&path, 65536).expect("read"), asn);
        }
    }

    #[test]
    fn asn_edits_enforce_serialized_byte_limit() {
        for (before, after, add, remove, expected) in [
            (
                "[ipset]\nset_name = 'kidobo'\n[asn]\nbanned = [64512]\ncache_stale_after_secs = 86400\n",
                "[ipset]\nset_name = 'kidobo'\n[asn]\nbanned = [64512, 64513]\ncache_stale_after_secs = 86400\n",
                vec![64513],
                vec![],
                vec![64512, 64513],
            ),
            (
                "[ipset]\nset_name = 'kidobo'\n[asn]\nbanned = [64512]\n",
                "[ipset]\nset_name = 'kidobo'\n[asn]\nbanned = []\ncache_stale_after_secs = 86400\n",
                vec![],
                vec![64512],
                vec![],
            ),
        ] {
            for size in [65535, 65536, 65537] {
                let temp = TempDir::new().expect("tempdir");
                let path = temp.path().join("config.toml");
                let header = format!("#é{}\n", "x".repeat(size - after.len() - 4));
                let original = format!("{header}{before}");
                std::fs::write(&path, &original).expect("fixture");
                let result = update_asn_bans(&path, &add, &remove);
                if size > 65536 {
                    assert!(matches!(result, Err(AppError::ConfigWrite { .. })));
                    assert_eq!(
                        read_to_string_with_limit(&path, 65536).expect("read"),
                        original
                    );
                } else {
                    result.expect("within bound");
                    assert_eq!(
                        read_to_string_with_limit(&path, 65536).expect("read"),
                        format!("{header}{after}")
                    );
                    let config =
                        crate::config::load_config_from_file(&path).expect("readable config");
                    assert_eq!(config.asn.banned, expected);
                }
            }
        }
    }

    #[test]
    fn update_asn_bans_adds_and_removes_values() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64512]\n",
        )
        .expect("write");

        let added = update_asn_bans(&config_path, &[64513, 64514], &[]).expect("add");
        assert_eq!(added.added, vec![64513, 64514]);
        assert!(added.removed.is_empty());

        let removed = update_asn_bans(&config_path, &[], &[64512, 64514]).expect("remove");
        assert_eq!(removed.removed, vec![64512, 64514]);
    }

    #[test]
    fn update_asn_bans_creates_asn_table_when_missing() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(&config_path, "[ipset]\nset_name='kidobo'\n").expect("write");

        let result = update_asn_bans(&config_path, &[64513], &[]).expect("update");
        assert_eq!(result.added, vec![64513]);

        let rendered = read_to_string_with_limit(&config_path, 64 * 1024).expect("read");
        assert!(rendered.contains("[asn]"));
        assert!(rendered.contains("banned = [64513]"));
    }

    #[test]
    fn update_asn_bans_adds_default_cache_stale_after_when_missing() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[64512]\n",
        )
        .expect("write");

        let _ = update_asn_bans(&config_path, &[64513], &[]).expect("update");
        let rendered = read_to_string_with_limit(&config_path, 64 * 1024).expect("read");
        assert!(rendered.contains(&format!(
            "cache_stale_after_secs = {DEFAULT_ASN_CACHE_STALE_AFTER_SECS}"
        )));
    }

    #[test]
    fn update_asn_bans_rejects_non_array_banned_values() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned='not-an-array'\n",
        )
        .expect("write");

        let err = update_asn_bans(&config_path, &[64513], &[]).expect_err("must fail");
        assert!(matches!(
            err,
            AppError::ConfigParse {
                source: kidobo_core::config::ConfigError::InvalidField { field, .. }
            } if field == "asn.banned"
        ));
    }

    #[test]
    fn update_asn_bans_rejects_non_positive_asn_values() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "[ipset]\nset_name='kidobo'\n[asn]\nbanned=[0]\n",
        )
        .expect("write");

        let err = update_asn_bans(&config_path, &[64513], &[]).expect_err("must fail");
        assert!(matches!(
            err,
            AppError::ConfigParse {
                source: kidobo_core::config::ConfigError::InvalidField { field, .. }
            } if field == "asn.banned"
        ));
    }

    #[test]
    fn update_asn_bans_preserves_comments_and_unrelated_formatting() {
        let temp = TempDir::new().expect("tempdir");
        let config_path = temp.path().join("config.toml");
        std::fs::write(
            &config_path,
            "# top comment\n[ipset]\nset_name = 'kidobo'\n\n# keep this comment\n[remote]\nurls = [\"https://example.com/list.txt\"]\n",
        )
        .expect("write");

        let result = update_asn_bans(&config_path, &[64513], &[]).expect("update");
        assert_eq!(result.added, vec![64513]);

        let rendered = read_to_string_with_limit(&config_path, 64 * 1024).expect("read");
        assert!(rendered.contains("# top comment"));
        assert!(rendered.contains("# keep this comment"));
        assert!(rendered.contains("[remote]"));
        assert!(rendered.contains("urls = [\"https://example.com/list.txt\"]"));
        assert!(rendered.contains("[asn]"));
        assert!(rendered.contains("banned = [64513]"));
    }
}
