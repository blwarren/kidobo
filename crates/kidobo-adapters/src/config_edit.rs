//! Formatting-preserving configuration mutation adapter.

use std::collections::BTreeSet;
use std::path::Path;

use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::limited_io::{read_to_string_with_limit, write_string_atomic};
use kidobo_app::AppError;
use kidobo_core::config::{ConfigError, DEFAULT_ASN_CACHE_STALE_AFTER_SECS};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AsnBanUpdateResult {
    pub added: Vec<u32>,
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
        .as_table_mut()
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
    asn_table["banned"] = value(values);
    if !asn_table.contains_key("cache_stale_after_secs") {
        asn_table["cache_stale_after_secs"] = value(i64::from(DEFAULT_ASN_CACHE_STALE_AFTER_SECS));
    }

    let rendered = doc.to_string();
    write_string_atomic(config_path, &rendered).map_err(|err| AppError::ConfigWrite {
        path: config_path.to_path_buf(),
        reason: err.to_string(),
    })?;
    Ok(AsnBanUpdateResult { added, removed })
}

fn load_config_document(path: &Path) -> Result<DocumentMut, AppError> {
    let contents =
        read_to_string_with_limit(path, 64 * 1024).map_err(|err| AppError::ConfigRead {
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
