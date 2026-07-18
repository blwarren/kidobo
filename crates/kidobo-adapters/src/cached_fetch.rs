//! Shared cache read and write helpers.

use std::path::Path;

use log::warn;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::hash::sha256_hex;
use crate::limited_io::{read_bytes_with_limit, write_bytes_atomic};

#[derive(Debug, Error)]
pub enum WriteJsonError {
    #[error("failed to serialize JSON: {reason}")]
    Serialize { reason: String },

    #[error("failed to write JSON file: {reason}")]
    Write { reason: String },
}

pub fn read_optional_bytes_lossy(
    path: &Path,
    read_limit: usize,
    description: &str,
) -> Option<Vec<u8>> {
    if !path.exists() {
        return None;
    }

    match read_bytes_with_limit(path, read_limit) {
        Ok(contents) => Some(contents),
        Err(err) => {
            warn!("failed to read {description} {}: {err}", path.display());
            None
        }
    }
}

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

pub fn write_bytes_atomic_in_cache(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    ensure_parent_dir(path)?;
    write_bytes_atomic(path, bytes)
}

pub fn write_json_pretty_atomic<T>(path: &Path, value: &T) -> Result<(), WriteJsonError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| WriteJsonError::Serialize {
        reason: err.to_string(),
    })?;
    write_bytes_atomic_in_cache(path, &bytes).map_err(|err| WriteJsonError::Write {
        reason: err.to_string(),
    })
}

fn ensure_parent_dir(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    use super::{
        read_optional_json_lossy, read_validated_bytes_lossy, write_bytes_atomic_in_cache,
        write_json_pretty_atomic,
    };
    use crate::limited_io::read_bytes_with_limit;

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct SampleJson {
        value: String,
    }

    #[test]
    fn invalid_hash_blocks_cached_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("raw.json");
        fs::write(&path, b"raw-body").expect("write raw");

        let result = read_validated_bytes_lossy(
            &path,
            1024,
            "raw cache file",
            Some("not-the-right-hash"),
            "raw cache",
            "body",
        );

        assert!(result.is_none());
    }

    #[test]
    fn writes_and_reads_cache_helpers() {
        let temp = TempDir::new().expect("tempdir");
        let raw_path = temp.path().join("cache/raw.bin");
        let json_path = temp.path().join("cache/meta.json");

        write_bytes_atomic_in_cache(&raw_path, b"payload").expect("write bytes");
        write_json_pretty_atomic(
            &json_path,
            &SampleJson {
                value: "ok".to_string(),
            },
        )
        .expect("write json");

        let json = read_optional_json_lossy::<SampleJson>(&json_path, 1024, "json cache file")
            .expect("read json");

        assert_eq!(
            read_bytes_with_limit(&raw_path, 1024).expect("read raw"),
            b"payload"
        );
        assert_eq!(
            json,
            SampleJson {
                value: "ok".to_string()
            }
        );
    }
}
