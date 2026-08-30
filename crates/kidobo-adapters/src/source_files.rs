//! Cached source file parsing helpers.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::hash::sha256_hex;
use crate::http_cache::RemoteCacheMetadata;
use crate::limited_io::read_to_string_with_limit;
use kidobo_core::network::{CanonicalCidr, parse_ip_cidr_token};

/// Maximum accepted cached source text size.
pub const SOURCE_FILE_READ_LIMIT: usize = 16 * 1024 * 1024;
/// Maximum accepted legacy remote metadata sidecar size.
pub const REMOTE_META_READ_LIMIT: usize = 256 * 1024;

/// Failure while enumerating legacy cached remote sources.
#[derive(Debug)]
pub enum RemoteCacheFilesError {
    /// The cache directory could not be opened.
    ReadDir(io::Error),
    /// One cache directory entry could not be read.
    ReadDirEntry(io::Error),
}

/// Collects regular `.iplist` files from a remote-cache directory.
///
/// # Errors
///
/// Returns [`RemoteCacheFilesError`] when the directory or any directory entry cannot be read.
pub fn collect_remote_cache_files(
    remote_cache_dir: &Path,
) -> Result<Vec<PathBuf>, RemoteCacheFilesError> {
    let mut files = Vec::new();
    let dir_iter = fs::read_dir(remote_cache_dir).map_err(RemoteCacheFilesError::ReadDir)?;

    for entry in dir_iter {
        let entry = entry.map_err(RemoteCacheFilesError::ReadDirEntry)?;
        let path = entry.path();
        if path.is_file() && path.extension() == Some(OsStr::new("iplist")) {
            files.push(path);
        }
    }

    Ok(files)
}

/// Reads a bounded cached iplist and validates its metadata hash when available.
///
/// # Errors
///
/// Returns an I/O error when the payload or metadata cannot be read within its bound, or when a
/// recorded payload hash does not match.
pub fn read_remote_cache_iplist_text(
    iplist_path: &Path,
    read_limit: usize,
    meta_read_limit: usize,
) -> io::Result<String> {
    let contents = read_to_string_with_limit(iplist_path, read_limit)?;
    validate_remote_cache_iplist_hash(iplist_path, &contents, meta_read_limit)?;
    Ok(contents)
}

#[must_use]
/// Parses the first token of a non-comment source line as a canonical CIDR.
pub fn parse_cidr_source_line(line: &str) -> Option<(CanonicalCidr, &str)> {
    let token = line.split_whitespace().next()?.trim();
    if token.is_empty() {
        return None;
    }

    let cidr = parse_ip_cidr_token(token)?;
    Some((cidr, token))
}

#[must_use]
/// Returns the metadata URL for a legacy iplist, or a stable filename-based label.
pub fn resolve_remote_source_label(iplist_path: &Path, meta_read_limit: usize) -> String {
    let Some(meta_path) = remote_meta_path_for_iplist(iplist_path) else {
        return fallback_remote_source_label(iplist_path);
    };

    let Ok(contents) = read_to_string_with_limit(&meta_path, meta_read_limit) else {
        return fallback_remote_source_label(iplist_path);
    };

    let Ok(metadata) = serde_json::from_str::<RemoteSourceMetadata>(&contents) else {
        return fallback_remote_source_label(iplist_path);
    };

    let normalized_url = metadata.url.trim();
    if normalized_url.is_empty() {
        return fallback_remote_source_label(iplist_path);
    }

    normalized_url.to_string()
}

#[derive(Debug, Deserialize)]
struct RemoteSourceMetadata {
    url: String,
}

fn validate_remote_cache_iplist_hash(
    iplist_path: &Path,
    contents: &str,
    meta_read_limit: usize,
) -> io::Result<()> {
    let Some(meta_path) = remote_meta_path_for_iplist(iplist_path) else {
        return Ok(());
    };

    let metadata_contents = match read_to_string_with_limit(&meta_path, meta_read_limit) {
        Ok(contents) => contents,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Ok(()),
    };

    let Ok(metadata) = serde_json::from_str::<RemoteCacheMetadata>(&metadata_contents) else {
        return Ok(());
    };

    let actual_hash = sha256_hex(contents.as_bytes());
    if actual_hash == metadata.sha256_iplist {
        return Ok(());
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "remote cache iplist hash mismatch for {}",
            iplist_path.display()
        ),
    ))
}

fn remote_meta_path_for_iplist(iplist_path: &Path) -> Option<PathBuf> {
    let stem = iplist_path.file_stem()?.to_str()?;
    Some(iplist_path.with_file_name(format!("{stem}.meta.json")))
}

fn fallback_remote_source_label(iplist_path: &Path) -> String {
    let file_name = iplist_path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or("unknown.iplist");
    format!("remote:{file_name}")
}
