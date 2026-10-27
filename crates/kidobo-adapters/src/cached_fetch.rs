//! Shared cache read and write helpers.

use std::path::Path;

use log::warn;
use serde::de::DeserializeOwned;

use crate::hash::sha256_hex;
use crate::limited_io::read_bytes_with_limit;

#[must_use]
/// Reads a bounded optional cache file, logging and returning `None` when unusable.
pub fn read_optional_bytes_lossy(
    path: &Path,
    read_limit: usize,
    description: &str,
) -> Option<Vec<u8>> {
    match read_bytes_with_limit(path, read_limit) {
        Ok(contents) => Some(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => {
            warn!("failed to read {description} {}: {err}", path.display());
            None
        }
    }
}

#[must_use]
/// Reads and deserializes bounded optional JSON, logging and returning `None` when unusable.
pub fn read_optional_json_lossy<T>(path: &Path, read_limit: usize, description: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    let bytes = read_optional_bytes_lossy(path, read_limit, description)?;

    match serde_json::from_slice::<T>(&bytes) {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            warn!(
                "failed to parse {description} {} as JSON: {err}",
                path.display()
            );
            None
        }
    }
}

#[must_use]
/// Reads bounded optional bytes and validates an optional SHA-256 checksum.
///
/// Missing, unreadable, or mismatched cache data is logged and returned as `None`.
pub fn read_validated_bytes_lossy(
    path: &Path,
    read_limit: usize,
    description: &str,
    expected_sha256: Option<&str>,
    mismatch_subject: &str,
    ignored_label: &str,
) -> Option<Vec<u8>> {
    let bytes = read_optional_bytes_lossy(path, read_limit, description)?;

    if let Some(expected_sha256) = expected_sha256 {
        let actual_hash = sha256_hex(&bytes);
        if actual_hash != expected_sha256 {
            warn!(
                "{mismatch_subject} hash mismatch for {}: ignoring cached {ignored_label}",
                path.display()
            );
            return None;
        }
    }

    Some(bytes)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::Deserialize;
    use tempfile::TempDir;

    use super::{read_optional_bytes_lossy, read_optional_json_lossy, read_validated_bytes_lossy};

    #[derive(Debug, Deserialize, PartialEq, Eq)]
    struct SampleJson {
        value: String,
    }

    #[test]
    fn validated_cache_accepts_matching_or_absent_hash_and_rejects_mismatch() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("raw.json");
        fs::write(&path, b"raw-body").expect("write raw");

        for expected_hash in [
            None,
            Some(crate::hash::sha256_hex(b"raw-body")),
            Some("not-the-right-hash".into()),
        ] {
            let result = read_validated_bytes_lossy(
                &path,
                1024,
                "raw cache file",
                expected_hash.as_deref(),
                "raw cache",
                "body",
            );

            assert_eq!(
                result,
                if expected_hash.as_deref() == Some("not-the-right-hash") {
                    None
                } else {
                    Some(b"raw-body".to_vec())
                }
            );
        }
    }

    #[test]
    fn reads_cache_helpers() {
        let temp = TempDir::new().expect("tempdir");
        let raw_path = temp.path().join("cache/raw.bin");
        let json_path = temp.path().join("cache/meta.json");

        fs::create_dir_all(raw_path.parent().expect("cache parent")).expect("mkdir cache");
        fs::write(&raw_path, b"payload").expect("write raw fixture");
        fs::write(&json_path, br#"{"value":"ok"}"#).expect("write json fixture");

        let json = read_optional_json_lossy::<SampleJson>(&json_path, 1024, "json cache file")
            .expect("read json");

        assert_eq!(
            read_optional_bytes_lossy(&raw_path, 1024, "raw cache file"),
            Some(b"payload".to_vec())
        );
        assert_eq!(
            json,
            SampleJson {
                value: "ok".to_string()
            }
        );
        assert_eq!(
            read_optional_bytes_lossy(&raw_path, 6, "oversized cache"),
            None
        );
        assert_eq!(
            read_optional_bytes_lossy(&temp.path().join("missing"), 1024, "missing cache"),
            None
        );
        fs::write(&json_path, b"invalid JSON").expect("malformed metadata");
        assert_eq!(
            read_optional_json_lossy::<SampleJson>(&json_path, 1024, "json cache file"),
            None
        );
    }
}
