//! Remote-feed cache validation and persistence adapter.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use log::warn;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cache_generation::{
    GenerationCandidate, GenerationFile, GenerationFileLimit, StagedGeneration,
    cleanup_unselected_generations, generation_candidates, generation_contents_match,
    stage_generation,
};
use crate::cached_fetch::{read_optional_json_lossy, read_validated_bytes_lossy};
use crate::hash::sha256_hex;
use crate::http_client::{HttpClient, HttpResponse, MAX_HTTP_BODY_BYTES, max_http_body_bytes};
use crate::http_fetch::{ConditionalFetchResult, fetch_with_conditional_cache};
use crate::limited_io::read_to_string_with_limit;
use crate::remote_parse::{
    RemoteFeedLimits, RemoteParseBudget, format_normalized_cidrs, parse_cached_iplist_bounded,
    parse_remote_cidrs_bounded,
};
use kidobo_app::source::{Notice, SourceProvenance};
use kidobo_core::network::CanonicalCidr;

const MAX_IPLIST_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_READ_BYTES: usize = 512 * 1024;
const V2_REMOTE_CACHE_DIRECTORY: &str = "v2/remote";
const GENERATION_RAW_FILE: &str = "raw";
const GENERATION_IPLIST_FILE: &str = "iplist";
const GENERATION_METADATA_FILE: &str = "meta.json";

/// Legacy flat-file cache paths retained for read compatibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePaths {
    /// Normalized CIDR list path.
    pub iplist_path: PathBuf,
    /// Integrity and HTTP metadata path.
    pub meta_path: PathBuf,
    /// Raw response body path.
    pub raw_path: PathBuf,
}

/// URL, HTTP validators, and checksums bound to a remote-feed cache.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCacheMetadata {
    /// Configured URL whose response was cached.
    pub url: String,
    /// Optional HTTP entity tag.
    pub etag: Option<String>,
    /// Optional HTTP last-modified validator.
    pub last_modified: Option<String>,
    /// Lowercase SHA-256 checksum of raw response bytes.
    pub sha256_raw: String,
    /// Lowercase SHA-256 checksum of normalized CIDR text.
    pub sha256_iplist: String,
}

/// Origin of a remote-feed load result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    /// Newly validated network response.
    Network,
    /// Existing cache accepted after HTTP 304.
    CacheNotModified,
    /// Existing cache used after a failed or invalid refresh.
    FallbackCache,
    /// No usable network or cache data was available.
    Empty,
}

/// Canonical remote-feed networks and cache provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedIplist {
    /// Sorted, unique canonical networks.
    pub networks: Vec<CanonicalCidr>,
    /// Data provenance.
    pub source: CacheSource,
    /// Validated URL, HTTP, and checksum metadata when available.
    pub metadata: Option<RemoteCacheMetadata>,
}

pub(crate) struct PreparedCachedIplist {
    pub(crate) loaded: CachedIplist,
    pub(crate) pending_promotion: Option<StagedGeneration>,
}

/// Validated preview data with no cache staging or publication capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReadOnlyIplist {
    pub(crate) networks: Vec<CanonicalCidr>,
    pub(crate) provenance: SourceProvenance,
    pub(crate) notices: Vec<Notice>,
}

/// Read-only cache failure or an input-size boundary that a real sync would also reject.
#[derive(Debug, Error)]
pub(crate) enum ReadOnlyIplistError {
    #[error(transparent)]
    CacheRead(#[from] HttpCacheError),
    #[error("normalized iplist size {bytes} exceeds {limit} byte limit")]
    NormalizedLimit { bytes: usize, limit: usize },
}

struct ValidatedRemoteResponse {
    networks: Vec<CanonicalCidr>,
    normalized: String,
}

#[derive(Debug, Clone)]
struct LoadedRemoteCache {
    networks: Option<Vec<CanonicalCidr>>,
    metadata: Option<RemoteCacheMetadata>,
    generation_id: Option<String>,
}

#[derive(Clone, Copy)]
struct RemoteRefreshContext<'a> {
    url: &'a str,
    cache_dir: &'a Path,
    max_bytes: usize,
    previous_generation: Option<&'a str>,
    feed_limits: RemoteFeedLimits,
    max_iplist_bytes: usize,
}

#[derive(Debug, Clone)]
struct ValidatedRemoteGeneration {
    iplist_path: PathBuf,
    iplist: String,
    metadata: RemoteCacheMetadata,
}

#[derive(Debug, Clone)]
pub(crate) struct OfflineRemoteGeneration {
    pub(crate) url_hash: String,
    pub(crate) iplist_path: PathBuf,
    pub(crate) label: String,
    pub(crate) iplist: String,
}

/// Failure to read legacy cache data or commit a validated v2 generation.
#[derive(Debug, Error)]
pub enum HttpCacheError {
    /// Cache metadata or v2 manifest write failed.
    #[error("failed to write metadata cache {path}: {source}")]
    WriteMetadata {
        /// Cache path.
        path: PathBuf,
        /// Serialization or filesystem diagnostic.
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Selected normalized CIDR cache could not be read safely.
    #[error("failed to read iplist cache {path}: {source}")]
    ReadIplist {
        /// Cache path.
        path: PathBuf,
        /// Bounded-read diagnostic.
        #[source]
        source: std::io::Error,
    },
}

#[must_use]
/// Returns the stable 16-hex-character cache key prefix for a configured URL.
pub fn url_hash_prefix(url: &str) -> String {
    sha256_hex(url.as_bytes())[..16].to_string()
}

#[must_use]
/// Derives all legacy flat-file cache paths for a configured URL.
pub fn cache_paths_for_url(cache_dir: &Path, url: &str) -> CachePaths {
    let hash = url_hash_prefix(url);
    CachePaths {
        iplist_path: cache_dir.join(format!("{hash}.iplist")),
        meta_path: cache_dir.join(format!("{hash}.meta.json")),
        raw_path: cache_dir.join(format!("{hash}.raw")),
    }
}

#[cfg(test)]
#[must_use]
/// Parses and canonicalizes remote text for adapter regression tests.
pub fn normalize_remote_text(raw: &[u8]) -> String {
    parse_remote_cidrs_bounded(raw, RemoteFeedLimits::from_maxelem(u32::MAX)).map_or_else(
        |_| String::new(),
        |parsed| format_normalized_cidrs(&parsed.networks),
    )
}

/// Fetches and validates a remote feed with conditional, atomic cache fallback.
///
/// # Errors
///
/// Returns [`HttpCacheError`] when required cache data cannot be read or a valid network response
/// cannot be persisted. Network and invalid-response failures retain usable cached data.
#[cfg(test)]
pub fn fetch_iplist_with_cache(
    client: &dyn HttpClient,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<OsString, OsString>,
) -> Result<CachedIplist, HttpCacheError> {
    let prepared = prepare_iplist_with_cache(client, url, cache_dir, env, u32::MAX)?;
    if let Some(promotion) = prepared.pending_promotion {
        promotion
            .promote()
            .map_err(|err| HttpCacheError::WriteMetadata {
                path: remote_generation_store(cache_dir, url).join("current.json"),
                source: Box::new(err),
            })?;
    }
    Ok(prepared.loaded)
}

pub(crate) fn prepare_iplist_with_cache(
    client: &dyn HttpClient,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<OsString, OsString>,
    maxelem: u32,
) -> Result<PreparedCachedIplist, HttpCacheError> {
    prepare_iplist_with_cache_limit(client, url, cache_dir, env, maxelem, MAX_IPLIST_READ_BYTES)
}

/// Reads compatible cached data, optionally refreshing only in memory, without cache maintenance.
pub(crate) fn read_iplist_for_preview(
    client: Option<&dyn HttpClient>,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<OsString, OsString>,
    maxelem: u32,
) -> Result<ReadOnlyIplist, ReadOnlyIplistError> {
    read_iplist_for_preview_with_limit(client, url, cache_dir, env, maxelem, MAX_IPLIST_READ_BYTES)
}

fn read_iplist_for_preview_with_limit(
    client: Option<&dyn HttpClient>,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<OsString, OsString>,
    maxelem: u32,
    max_iplist_bytes: usize,
) -> Result<ReadOnlyIplist, ReadOnlyIplistError> {
    let limits = RemoteFeedLimits::from_maxelem(maxelem);
    let cached = read_remote_cache(
        cache_dir,
        url,
        &cache_paths_for_url(cache_dir, url),
        MAX_HTTP_BODY_BYTES,
        limits,
    )?;
    let Some(client) = client else {
        return Ok(read_only_cached(cached, SourceProvenance::Cache, true));
    };
    let max_bytes = max_http_body_bytes(env);
    let (etag, modified) = cached.metadata.as_ref().map_or((None, None), |metadata| {
        (metadata.etag.clone(), metadata.last_modified.clone())
    });
    match fetch_with_conditional_cache(
        client,
        url,
        max_bytes,
        etag,
        modified,
        cached.networks.is_some(),
        "remote source",
    ) {
        ConditionalFetchResult::CacheNotModified => {
            Ok(read_only_cached(cached, SourceProvenance::Cache, false))
        }
        ConditionalFetchResult::FallbackCache => Ok(read_only_cached(
            cached,
            SourceProvenance::FallbackCache,
            false,
        )),
        ConditionalFetchResult::Network(response) => {
            let Some(validated) = validate_remote_response(&response, url, max_bytes, limits)
            else {
                return Ok(read_only_cached(
                    cached,
                    SourceProvenance::FallbackCache,
                    false,
                ));
            };
            if let Err(error) = ensure_normalized_size(validated.normalized.len(), max_iplist_bytes)
            {
                if cached.networks.is_none() {
                    return Err(error);
                }
                let mut fallback = read_only_cached(cached, SourceProvenance::FallbackCache, false);
                fallback.notices.push(Notice::warning(format!(
                    "remote preview refresh rejected: {error}; using validated cache"
                )));
                return Ok(fallback);
            }
            Ok(ReadOnlyIplist {
                networks: validated.networks,
                provenance: SourceProvenance::Network,
                notices: Vec::new(),
            })
        }
    }
}

fn read_only_cached(
    cached: LoadedRemoteCache,
    provenance: SourceProvenance,
    offline: bool,
) -> ReadOnlyIplist {
    let Some(networks) = cached.networks else {
        return ReadOnlyIplist {
            networks: Vec::new(),
            provenance: SourceProvenance::Unavailable,
            notices: vec![Notice::warning(
                "no usable remote feed data is available for this preview",
            )],
        };
    };
    let notices = if offline {
        vec![Notice::info(
            "preview uses validated cached feed data without refreshing it; freshness is unknown",
        )]
    } else if provenance == SourceProvenance::FallbackCache {
        vec![Notice::warning(
            "remote refresh was unavailable or rejected; preview uses validated cached data",
        )]
    } else {
        Vec::new()
    };
    ReadOnlyIplist {
        networks,
        provenance,
        notices,
    }
}

fn prepare_iplist_with_cache_limit(
    client: &dyn HttpClient,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<OsString, OsString>,
    maxelem: u32,
    max_iplist_bytes: usize,
) -> Result<PreparedCachedIplist, HttpCacheError> {
    let max_bytes = max_http_body_bytes(env);
    let feed_limits = RemoteFeedLimits::from_maxelem(maxelem);
    let cache_paths = cache_paths_for_url(cache_dir, url);
    cleanup_unselected_generations(&remote_generation_store(cache_dir, url));
    let cached = read_remote_cache(
        cache_dir,
        url,
        &cache_paths,
        MAX_HTTP_BODY_BYTES,
        feed_limits,
    )?;
    let cached_meta = cached.metadata;
    let cached_networks = cached.networks;
    let previous_generation = cached.generation_id;
    let (cached_etag, cached_last_modified) = cached_meta.as_ref().map_or((None, None), |meta| {
        (meta.etag.clone(), meta.last_modified.clone())
    });

    match fetch_with_conditional_cache(
        client,
        url,
        max_bytes,
        cached_etag,
        cached_last_modified,
        cached_networks.is_some(),
        "remote source",
    ) {
        ConditionalFetchResult::CacheNotModified => {
            if let Some(networks) = cached_networks {
                Ok(PreparedCachedIplist {
                    loaded: CachedIplist {
                        networks,
                        source: CacheSource::CacheNotModified,
                        metadata: cached_meta,
                    },
                    pending_promotion: None,
                })
            } else {
                Ok(PreparedCachedIplist {
                    loaded: CachedIplist {
                        networks: Vec::new(),
                        source: CacheSource::Empty,
                        metadata: None,
                    },
                    pending_promotion: None,
                })
            }
        }
        ConditionalFetchResult::FallbackCache => Ok(PreparedCachedIplist {
            loaded: cache_fallback(cached_networks, cached_meta),
            pending_promotion: None,
        }),
        ConditionalFetchResult::Network(response) => handle_network_response(
            response,
            cached_networks,
            cached_meta,
            RemoteRefreshContext {
                url,
                cache_dir,
                max_bytes,
                previous_generation: previous_generation.as_deref(),
                feed_limits,
                max_iplist_bytes,
            },
        ),
    }
}

fn handle_network_response(
    response: HttpResponse,
    cached_networks: Option<Vec<CanonicalCidr>>,
    cached_meta: Option<RemoteCacheMetadata>,
    context: RemoteRefreshContext<'_>,
) -> Result<PreparedCachedIplist, HttpCacheError> {
    let RemoteRefreshContext {
        url,
        cache_dir,
        max_bytes,
        previous_generation,
        feed_limits,
        max_iplist_bytes,
    } = context;
    let Some(ValidatedRemoteResponse {
        networks,
        normalized,
    }) = validate_remote_response(&response, url, max_bytes, feed_limits)
    else {
        return Ok(prepared_fallback(cached_networks, cached_meta));
    };
    let metadata = RemoteCacheMetadata {
        url: url.to_string(),
        etag: response.etag,
        last_modified: response.last_modified,
        sha256_raw: sha256_hex(&response.body),
        sha256_iplist: sha256_hex(normalized.as_bytes()),
    };

    let pending_promotion = match stage_cache(
        cache_dir,
        url,
        &normalized,
        &response.body,
        &metadata,
        previous_generation,
        max_iplist_bytes,
    ) {
        Ok(promotion) => promotion,
        Err(error) if cached_networks.is_some() => {
            warn!("remote cache staging failed for {url}; using validated cache: {error}");
            return Ok(prepared_fallback(cached_networks, cached_meta));
        }
        Err(error) => return Err(error),
    };

    Ok(PreparedCachedIplist {
        loaded: CachedIplist {
            networks,
            source: CacheSource::Network,
            metadata: Some(metadata),
        },
        pending_promotion: Some(pending_promotion),
    })
}

fn validate_remote_response(
    response: &HttpResponse,
    url: &str,
    max_bytes: usize,
    feed_limits: RemoteFeedLimits,
) -> Option<ValidatedRemoteResponse> {
    if !response.status.is_success() {
        warn!(
            "remote fetch failed for {url}: unexpected status {}",
            response.status
        );
        return None;
    }

    if response.body.len() > max_bytes {
        warn!(
            "remote fetch failed for {url}: body size {} exceeds max {} bytes",
            response.body.len(),
            max_bytes
        );
        return None;
    }

    let parsed = match parse_remote_cidrs_bounded(&response.body, feed_limits) {
        Ok(parsed) => parsed,
        Err(budget) => {
            warn_remote_budget_rejection(url, budget);
            return None;
        }
    };
    if parsed.data_lines > 0 && parsed.networks.is_empty() {
        warn!(
            "remote fetch failed for {url}: non-empty response contained no valid IP/CIDR entries"
        );
        return None;
    }
    if parsed.invalid_lines > 0 {
        warn!(
            "remote source {url} ignored {} invalid line(s)",
            parsed.invalid_lines
        );
    }
    let networks = parsed.networks;
    let normalized = format_normalized_cidrs(&networks);
    Some(ValidatedRemoteResponse {
        networks,
        normalized,
    })
}

fn ensure_normalized_size(bytes: usize, limit: usize) -> Result<(), ReadOnlyIplistError> {
    if bytes > limit {
        Err(ReadOnlyIplistError::NormalizedLimit { bytes, limit })
    } else {
        Ok(())
    }
}

fn stage_cache(
    cache_dir: &Path,
    url: &str,
    iplist: &str,
    raw: &[u8],
    meta: &RemoteCacheMetadata,
    previous_generation: Option<&str>,
    max_iplist_bytes: usize,
) -> Result<StagedGeneration, HttpCacheError> {
    let store = remote_generation_store(cache_dir, url);
    ensure_normalized_size(iplist.len(), max_iplist_bytes).map_err(|error| {
        HttpCacheError::WriteMetadata {
            path: store.join("current.json"),
            source: Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                error.to_string(),
            )),
        }
    })?;
    let metadata =
        serde_json::to_vec_pretty(meta).map_err(|err| HttpCacheError::WriteMetadata {
            path: store.join("current.json"),
            source: Box::new(err),
        })?;
    stage_generation(
        &store,
        &[
            GenerationFile {
                name: GENERATION_RAW_FILE,
                contents: raw,
            },
            GenerationFile {
                name: GENERATION_IPLIST_FILE,
                contents: iplist.as_bytes(),
            },
            GenerationFile {
                name: GENERATION_METADATA_FILE,
                contents: &metadata,
            },
        ],
        previous_generation,
    )
    .map_err(|err| HttpCacheError::WriteMetadata {
        path: store.join("current.json"),
        source: Box::new(err),
    })
}

fn read_remote_cache(
    cache_dir: &Path,
    url: &str,
    legacy_paths: &CachePaths,
    raw_read_limit: usize,
    feed_limits: RemoteFeedLimits,
) -> Result<LoadedRemoteCache, HttpCacheError> {
    for candidate in generation_candidates(&remote_generation_store(cache_dir, url)) {
        if !remote_generation_contents_match(&candidate, raw_read_limit) {
            continue;
        }
        let Some(generation) =
            read_validated_remote_generation(&candidate.directory, Some(url), raw_read_limit)
        else {
            continue;
        };
        let networks = match parse_cached_iplist_bounded(&generation.iplist, feed_limits) {
            Ok(networks) => networks,
            Err(budget) => {
                warn_remote_budget_rejection(url, budget);
                continue;
            }
        };
        return Ok(LoadedRemoteCache {
            networks: Some(networks),
            metadata: Some(generation.metadata),
            generation_id: Some(candidate.id),
        });
    }

    let metadata = read_optional_metadata_lossy(legacy_paths);
    let networks = read_optional_iplist_networks(legacy_paths, metadata.as_ref(), feed_limits)?;
    Ok(LoadedRemoteCache {
        networks,
        metadata,
        generation_id: None,
    })
}

pub(crate) fn inspect_cached_source(
    cache_dir: &Path,
    url: &str,
    maxelem: u32,
) -> Result<Option<&'static str>, HttpCacheError> {
    let cached = read_remote_cache(
        cache_dir,
        url,
        &cache_paths_for_url(cache_dir, url),
        MAX_HTTP_BODY_BYTES,
        RemoteFeedLimits::from_maxelem(maxelem),
    )?;
    Ok(cached.networks.map(|_| {
        if cached.generation_id.is_some() {
            "validated cache generation"
        } else {
            "compatible legacy cache"
        }
    }))
}

pub(crate) fn remote_generation_store(cache_dir: &Path, url: &str) -> PathBuf {
    cache_dir
        .join(V2_REMOTE_CACHE_DIRECTORY)
        .join(url_hash_prefix(url))
}

pub(crate) fn collect_offline_remote_generations(
    cache_dir: &Path,
) -> Result<Vec<OfflineRemoteGeneration>, std::io::Error> {
    let stores_root = cache_dir.join(V2_REMOTE_CACHE_DIRECTORY);
    let entries = match std::fs::read_dir(&stores_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut stores = Vec::new();
    for entry in entries {
        let entry = entry?;
        let url_hash = entry.file_name().to_string_lossy().into_owned();
        if !is_url_hash(&url_hash) {
            continue;
        }
        let metadata = match std::fs::metadata(entry.path()) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        if !metadata.is_dir() {
            continue;
        }
        stores.push((url_hash, entry.path()));
    }
    stores.sort_by(|left, right| left.0.cmp(&right.0));

    let mut generations = Vec::new();
    for (url_hash, store) in stores {
        for candidate in generation_candidates(&store) {
            if !remote_generation_contents_match(&candidate, MAX_HTTP_BODY_BYTES) {
                continue;
            }
            let Some(generation) =
                read_validated_remote_generation(&candidate.directory, None, MAX_HTTP_BODY_BYTES)
            else {
                continue;
            };
            generations.push(OfflineRemoteGeneration {
                url_hash,
                iplist_path: generation.iplist_path,
                label: generation.metadata.url.trim().to_string(),
                iplist: generation.iplist,
            });
            break;
        }
    }
    Ok(generations)
}

fn remote_generation_contents_match(
    candidate: &GenerationCandidate,
    raw_read_limit: usize,
) -> bool {
    generation_contents_match(
        candidate,
        &[
            GenerationFileLimit {
                name: GENERATION_RAW_FILE,
                read_limit: raw_read_limit,
            },
            GenerationFileLimit {
                name: GENERATION_IPLIST_FILE,
                read_limit: MAX_IPLIST_READ_BYTES,
            },
            GenerationFileLimit {
                name: GENERATION_METADATA_FILE,
                read_limit: MAX_METADATA_READ_BYTES,
            },
        ],
    )
}

fn read_validated_remote_generation(
    directory: &Path,
    expected_url: Option<&str>,
    raw_read_limit: usize,
) -> Option<ValidatedRemoteGeneration> {
    let paths = CachePaths {
        iplist_path: directory.join(GENERATION_IPLIST_FILE),
        meta_path: directory.join(GENERATION_METADATA_FILE),
        raw_path: directory.join(GENERATION_RAW_FILE),
    };
    let metadata = read_optional_metadata_lossy(&paths)?;
    let normalized_url = metadata.url.trim();
    if normalized_url.is_empty()
        || expected_url.is_some_and(|expected| normalized_url != expected.trim())
    {
        warn!(
            "remote cache generation URL is missing or differs from the configured URL: {}",
            directory.display()
        );
        return None;
    }
    read_validated_bytes_lossy(
        &paths.raw_path,
        raw_read_limit,
        "remote raw cache generation",
        Some(&metadata.sha256_raw),
        "remote raw cache",
        "raw body",
    )?;
    let iplist = match read_to_string_with_limit(&paths.iplist_path, MAX_IPLIST_READ_BYTES) {
        Ok(iplist) => iplist,
        Err(error) => {
            warn!(
                "failed to read remote iplist cache generation {}: {error}",
                paths.iplist_path.display()
            );
            return None;
        }
    };
    if sha256_hex(iplist.as_bytes()) != metadata.sha256_iplist {
        warn!(
            "remote iplist cache hash mismatch for {}: ignoring generation",
            paths.iplist_path.display()
        );
        return None;
    }
    Some(ValidatedRemoteGeneration {
        iplist_path: paths.iplist_path,
        iplist,
        metadata,
    })
}

fn is_url_hash(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn read_optional_iplist_networks(
    paths: &CachePaths,
    metadata: Option<&RemoteCacheMetadata>,
    feed_limits: RemoteFeedLimits,
) -> Result<Option<Vec<CanonicalCidr>>, HttpCacheError> {
    let iplist = match read_to_string_with_limit(&paths.iplist_path, MAX_IPLIST_READ_BYTES) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(HttpCacheError::ReadIplist {
                path: paths.iplist_path.clone(),
                source,
            });
        }
    };

    if let Some(metadata) = metadata {
        let actual_hash = sha256_hex(iplist.as_bytes());
        if actual_hash != metadata.sha256_iplist {
            warn!(
                "remote iplist cache hash mismatch for {}: ignoring cached iplist",
                paths.iplist_path.display()
            );
            return Ok(None);
        }
    }

    match parse_cached_iplist_bounded(&iplist, feed_limits) {
        Ok(networks) => Ok(Some(networks)),
        Err(budget) => {
            warn_remote_budget_rejection(&paths.iplist_path.display().to_string(), budget);
            Ok(None)
        }
    }
}

fn prepared_fallback(
    cached_networks: Option<Vec<CanonicalCidr>>,
    cached_meta: Option<RemoteCacheMetadata>,
) -> PreparedCachedIplist {
    PreparedCachedIplist {
        loaded: cache_fallback(cached_networks, cached_meta),
        pending_promotion: None,
    }
}

fn warn_remote_budget_rejection(source: &str, budget: RemoteParseBudget) {
    match budget {
        RemoteParseBudget::DataLines { observed, limit } => warn!(
            "remote source {source} rejected: data line budget exceeded ({observed} > {limit})"
        ),
        RemoteParseBudget::UniqueCidrs { observed, limit } => warn!(
            "remote source {source} rejected: unique CIDR budget exceeded ({observed} > {limit})"
        ),
    }
}

fn read_optional_metadata_lossy(paths: &CachePaths) -> Option<RemoteCacheMetadata> {
    read_optional_json_lossy(
        &paths.meta_path,
        MAX_METADATA_READ_BYTES,
        "remote metadata cache",
    )
}

fn cache_fallback(
    cached_networks: Option<Vec<CanonicalCidr>>,
    cached_meta: Option<RemoteCacheMetadata>,
) -> CachedIplist {
    if let Some(networks) = cached_networks {
        CachedIplist {
            networks,
            source: CacheSource::FallbackCache,
            metadata: cached_meta,
        }
    } else {
        CachedIplist {
            networks: Vec::new(),
            source: CacheSource::Empty,
            metadata: cached_meta,
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::collections::BTreeMap;
    use std::path::{Path, PathBuf};
    use std::time::SystemTime;

    use crate::http_client::{HttpClient, HttpClientError, HttpRequest, HttpResponse};

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct SnapshotEntry {
        contents: Option<Vec<u8>>,
        mode: u32,
        modified: SystemTime,
    }

    pub(crate) fn snapshot(root: &Path) -> BTreeMap<PathBuf, SnapshotEntry> {
        let mut entries = BTreeMap::new();
        snapshot_into(root, root, &mut entries);
        entries
    }

    fn snapshot_into(root: &Path, path: &Path, entries: &mut BTreeMap<PathBuf, SnapshotEntry>) {
        let metadata = std::fs::metadata(path).expect("fixture metadata");
        #[cfg(unix)]
        let mode = {
            use std::os::unix::fs::PermissionsExt;
            metadata.permissions().mode()
        };
        #[cfg(not(unix))]
        let mode = u32::from(metadata.permissions().readonly());
        let contents = metadata.is_file().then(|| {
            crate::limited_io::read_bytes_with_limit(path, super::MAX_HTTP_BODY_BYTES)
                .expect("bounded fixture bytes")
        });
        entries.insert(
            path.strip_prefix(root)
                .expect("fixture relative path")
                .to_path_buf(),
            SnapshotEntry {
                contents,
                mode,
                modified: metadata.modified().expect("fixture mtime"),
            },
        );
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).expect("fixture directory") {
                snapshot_into(root, &entry.expect("fixture entry").path(), entries);
            }
        }
    }

    // Hide the store after its validated contents have been loaded, then block generation staging.
    // This injects the same failure under root and unprivileged test users without chmod assumptions.
    pub(crate) struct StagingFailureClient<'a> {
        pub(crate) cache_dir: &'a std::path::Path,
        pub(crate) response: HttpResponse,
    }

    impl HttpClient for StagingFailureClient<'_> {
        fn fetch(&self, _: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            std::fs::rename(self.cache_dir.join("v2"), self.cache_dir.join("saved-v2"))
                .expect("hide store");
            std::fs::write(self.cache_dir.join("v2"), b"block staging").expect("block staging");
            Ok(self.response.clone())
        }
    }

    impl StagingFailureClient<'_> {
        pub(crate) fn restore_store(&self) {
            std::fs::remove_file(self.cache_dir.join("v2")).expect("remove blocker");
            std::fs::rename(self.cache_dir.join("saved-v2"), self.cache_dir.join("v2"))
                .expect("restore store");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::error::Error;
    use std::fmt::Write as _;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::Duration;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::test_support::snapshot;
    use super::{
        CacheSource, ReadOnlyIplistError, RemoteCacheMetadata, cache_paths_for_url,
        fetch_iplist_with_cache, normalize_remote_text, prepare_iplist_with_cache,
        read_iplist_for_preview, read_iplist_for_preview_with_limit, remote_generation_store,
    };
    use crate::cache_generation::generation_candidates;
    use crate::hash::sha256_hex;
    use crate::http_client::test_support::CrossOriginRedirectFixture;
    use crate::http_client::{
        DEFAULT_MAX_HTTP_BODY_BYTES, ENV_KIDOBO_MAX_HTTP_BODY_BYTES, HttpClient, HttpClientError,
        HttpRequest, HttpResponse, MAX_HTTP_BODY_BYTES, ReqwestHttpClient,
    };
    use crate::limited_io::{read_bytes_with_limit, read_to_string_with_limit};
    use kidobo_app::source::SourceProvenance;

    struct MockHttpClient {
        responses: RefCell<VecDeque<Result<HttpResponse, HttpClientError>>>,
        requests: RefCell<Vec<HttpRequest>>,
    }

    impl MockHttpClient {
        fn new(responses: Vec<Result<HttpResponse, HttpClientError>>) -> Self {
            Self {
                responses: RefCell::new(VecDeque::from(responses)),
                requests: RefCell::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl HttpClient for MockHttpClient {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            self.requests.borrow_mut().push(request);
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    fn network_response_for_test(body: &[u8]) -> HttpResponse {
        HttpResponse {
            status: StatusCode::OK,
            body: body.to_vec(),
            etag: None,
            last_modified: None,
        }
    }

    fn normalized_limit_body(tail: &str) -> String {
        let mut body = String::new();
        for index in 0..3_u32 {
            writeln!(
                body,
                "2001:1234:5678:9abc:def0:1111:{:x}:{:x}/128",
                0x8000 | (index >> 15),
                0x8000 | (index & 0x7fff)
            )
            .expect("write full-width IPv6 entry");
        }
        body.push_str(tail);
        body
    }

    const TEST_IPLIST_LIMIT: usize = 148;

    #[test]
    fn preview_cache_reads_select_current_previous_and_legacy_without_cleanup_or_repair() {
        let url = "https://example.test/feed";
        for (corrupt, expected) in [
            (0, "203.0.113.0/24"),
            (1, "198.51.100.0/24"),
            (2, "192.0.2.0/24"),
        ] {
            let temp = TempDir::new().expect("root");
            fs::write(
                cache_paths_for_url(temp.path(), url).iplist_path,
                "192.0.2.0/24\n",
            )
            .expect("legacy cache");
            for seed in [b"198.51.100.0/24".as_slice(), b"203.0.113.0/24".as_slice()] {
                fetch_iplist_with_cache(
                    &MockHttpClient::new(vec![Ok(network_response_for_test(seed))]),
                    url,
                    temp.path(),
                    &BTreeMap::new(),
                )
                .expect("seed cache");
            }
            let store = remote_generation_store(temp.path(), url);
            for candidate in generation_candidates(&store).into_iter().take(corrupt) {
                fs::write(candidate.directory.join("raw"), "corrupt raw member")
                    .expect("corrupt generation");
            }
            for name in ["a".repeat(64), ".staging-preview-fixture".to_string()] {
                let orphan = store.join("generations").join(name);
                fs::create_dir(&orphan).expect("unselected directory");
                fs::write(orphan.join("partial"), "retain this unselected state")
                    .expect("orphan contents");
            }
            fs::write(
                temp.path().join("blocklist-normalize.fast-state"),
                "retain sidecar",
            )
            .expect("fast state");
            let before = snapshot(temp.path());
            let loaded = read_iplist_for_preview(None, url, temp.path(), &BTreeMap::new(), 100)
                .expect("read-only selected cache");
            assert_eq!(loaded.provenance, SourceProvenance::Cache);
            assert_eq!(
                loaded
                    .networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                [expected]
            );
            assert_eq!(snapshot(temp.path()), before);
        }
    }

    #[test]
    fn preview_online_refresh_validation_and_conditional_cache_are_nonpersisting() {
        let temp = TempDir::new().expect("root");
        let url = "https://example.test/feed";
        let mut seed = network_response_for_test(b"203.0.113.0/24");
        seed.etag = Some("seed-etag".to_string());
        seed.last_modified = Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string());
        fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(seed)]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("seed cache");
        let before = snapshot(temp.path());
        for (response, provenance, expected) in [
            (
                Ok(network_response_for_test(b"198.51.100.0/24")),
                SourceProvenance::Network,
                "198.51.100.0/24",
            ),
            (
                Ok(network_response_for_test(b"invalid response")),
                SourceProvenance::FallbackCache,
                "203.0.113.0/24",
            ),
            (
                Err(HttpClientError::Request {
                    reason: "offline".to_string(),
                }),
                SourceProvenance::FallbackCache,
                "203.0.113.0/24",
            ),
            (
                Ok(HttpResponse {
                    status: StatusCode::NOT_MODIFIED,
                    body: Vec::new(),
                    etag: None,
                    last_modified: None,
                }),
                SourceProvenance::Cache,
                "203.0.113.0/24",
            ),
        ] {
            let client = MockHttpClient::new(vec![response]);
            let loaded =
                read_iplist_for_preview(Some(&client), url, temp.path(), &BTreeMap::new(), 100)
                    .expect("preview response");
            assert_eq!(loaded.provenance, provenance);
            assert_eq!(
                loaded
                    .networks
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                [expected]
            );
            let requests = client.requests();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].if_none_match.as_deref(), Some("seed-etag"));
            assert_eq!(requests[0].max_body_bytes, DEFAULT_MAX_HTTP_BODY_BYTES);
            assert_eq!(snapshot(temp.path()), before);
        }
    }

    #[test]
    fn preview_missing_cache_stays_unavailable_and_unconditional_retry_writes_nothing() {
        let temp = TempDir::new().expect("root");
        let cache = temp.path().join("missing-cache");
        let url = "https://example.test/feed";
        let before = snapshot(temp.path());
        let offline = read_iplist_for_preview(None, url, &cache, &BTreeMap::new(), 100)
            .expect("offline preview");
        assert_eq!(offline.provenance, SourceProvenance::Unavailable);
        assert_eq!(offline.networks, []);
        let client = MockHttpClient::new(vec![
            Ok(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                body: Vec::new(),
                etag: None,
                last_modified: None,
            }),
            Ok(network_response_for_test(b"198.51.100.0/24")),
        ]);
        let online = read_iplist_for_preview(Some(&client), url, &cache, &BTreeMap::new(), 100)
            .expect("online preview");
        assert_eq!(online.provenance, SourceProvenance::Network);
        assert_eq!(
            online
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["198.51.100.0/24"]
        );
        let requests = client.requests();
        assert_eq!(requests.len(), 2);
        assert!(
            requests
                .iter()
                .all(|request| request.if_none_match.is_none()
                    && request.if_modified_since.is_none())
        );
        assert_eq!(snapshot(temp.path()), before);
    }

    #[test]
    fn preview_normalized_limit_uses_cache_or_a_typed_fatal_budget_without_writes() {
        let url = "https://example.test/feed";
        let body = normalized_limit_body("2001:db8:111::/64");
        for existing in [false, true] {
            let temp = TempDir::new().expect("root");
            if existing {
                fs::write(
                    cache_paths_for_url(temp.path(), url).iplist_path,
                    "203.0.113.0/24\n",
                )
                .expect("legacy cache");
            }
            let before = snapshot(temp.path());
            let client = MockHttpClient::new(vec![Ok(network_response_for_test(body.as_bytes()))]);
            let loaded = read_iplist_for_preview_with_limit(
                Some(&client),
                url,
                temp.path(),
                &BTreeMap::new(),
                100,
                TEST_IPLIST_LIMIT,
            );
            if existing {
                let loaded = loaded.expect("cache fallback");
                assert_eq!(loaded.provenance, SourceProvenance::FallbackCache);
                assert_eq!(
                    loaded
                        .networks
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    ["203.0.113.0/24"]
                );
                assert!(loaded.notices.iter().any(|notice| {
                    notice
                        .message
                        .contains("normalized iplist size 149 exceeds 148")
                }));
            } else {
                assert!(matches!(
                    loaded,
                    Err(ReadOnlyIplistError::NormalizedLimit {
                        bytes: 149,
                        limit: 148
                    })
                ));
            }
            assert_eq!(snapshot(temp.path()), before);
        }
    }

    #[test]
    fn preview_enforces_body_bounds_without_requiring_writable_staging() {
        let temp = TempDir::new().expect("root");
        let url = "https://example.test/feed";
        fs::write(
            temp.path().join("v2"),
            "prevent persistent generation writes",
        )
        .expect("staging blocker");
        fs::write(
            cache_paths_for_url(temp.path(), url).iplist_path,
            "203.0.113.0/24\n",
        )
        .expect("legacy cache");
        let before = snapshot(temp.path());
        let client = MockHttpClient::new(vec![Ok(network_response_for_test(b"198.51.100.0/24"))]);
        let fresh = read_iplist_for_preview(Some(&client), url, temp.path(), &BTreeMap::new(), 100)
            .expect("memory refresh");
        assert_eq!(fresh.provenance, SourceProvenance::Network);
        let env = BTreeMap::from([(ENV_KIDOBO_MAX_HTTP_BODY_BYTES.into(), "5".into())]);
        let client = MockHttpClient::new(vec![Ok(network_response_for_test(b"198.51.100.0/24"))]);
        let bounded = read_iplist_for_preview(Some(&client), url, temp.path(), &env, 100)
            .expect("bounded fallback");
        assert_eq!(bounded.provenance, SourceProvenance::FallbackCache);
        assert_eq!(client.requests()[0].max_body_bytes, 5);
        assert_eq!(snapshot(temp.path()), before);
    }

    #[test]
    fn preview_existing_unreadable_cache_has_a_typed_read_failure() {
        let temp = TempDir::new().expect("root");
        let url = "https://example.test/feed";
        fs::create_dir(cache_paths_for_url(temp.path(), url).iplist_path)
            .expect("nonfile legacy cache");
        let before = snapshot(temp.path());
        assert!(matches!(
            read_iplist_for_preview(None, url, temp.path(), &BTreeMap::new(), 100),
            Err(ReadOnlyIplistError::CacheRead(
                super::HttpCacheError::ReadIplist { .. }
            ))
        ));
        assert_eq!(snapshot(temp.path()), before);
    }

    #[test]
    fn production_iplist_limit_persists_readable_content_and_rejects_growth() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.test/feed";
        let raw = b"192.0.2.0/24";
        let mut iplist = format!(
            "#{}\n192.0.2.0/24",
            "x".repeat(super::MAX_IPLIST_READ_BYTES - 14)
        );
        assert_eq!(iplist.len(), 16 * 1024 * 1024);
        let metadata = RemoteCacheMetadata {
            url: url.into(),
            etag: None,
            last_modified: None,
            sha256_raw: sha256_hex(raw),
            sha256_iplist: sha256_hex(iplist.as_bytes()),
        };
        super::stage_cache(
            temp.path(),
            url,
            &iplist,
            raw,
            &metadata,
            None,
            super::MAX_IPLIST_READ_BYTES,
        )
        .expect("production boundary")
        .promote()
        .expect("promote");
        let generations =
            super::collect_offline_remote_generations(temp.path()).expect("offline read");
        assert_eq!(generations.len(), 1);
        assert!(
            generations[0].iplist == iplist,
            "production-sized cached bytes must roundtrip"
        );
        let store = remote_generation_store(temp.path(), url);
        let selected = generation_candidates(&store);
        iplist.push('\n');
        let error = super::stage_cache(
            temp.path(),
            url,
            &iplist,
            raw,
            &metadata,
            None,
            super::MAX_IPLIST_READ_BYTES,
        )
        .expect_err("over production limit");
        assert!(
            matches!(error, super::HttpCacheError::WriteMetadata { source, .. }
            if source.downcast_ref::<std::io::Error>().expect("I/O cause").kind() == std::io::ErrorKind::InvalidData)
        );
        assert_eq!(generation_candidates(&store), selected);
    }

    #[test]
    fn normalized_cache_limit_accepts_readable_boundary_generations() {
        let env = BTreeMap::from([(
            ENV_KIDOBO_MAX_HTTP_BODY_BYTES.into(),
            MAX_HTTP_BODY_BYTES.to_string().into(),
        )]);
        for (tail, expected_bytes) in [
            ("2001:db8:1::/64", TEST_IPLIST_LIMIT - 1),
            ("2001:db8:11::/64", TEST_IPLIST_LIMIT),
        ] {
            let temp = TempDir::new().expect("tempdir");
            let url = "https://example.test/large-feed";
            let body = normalized_limit_body(tail);
            assert_eq!(body.len(), expected_bytes);
            let client = MockHttpClient::new(vec![Ok(network_response_for_test(body.as_bytes()))]);
            let prepared = super::prepare_iplist_with_cache_limit(
                &client,
                url,
                temp.path(),
                &env,
                100,
                TEST_IPLIST_LIMIT,
            )
            .expect("prepare boundary generation");
            assert_eq!(prepared.loaded.source, CacheSource::Network);
            assert_eq!(prepared.loaded.networks.len(), 4);
            prepared
                .pending_promotion
                .expect("pending promotion")
                .promote()
                .expect("promote boundary generation");
            assert_eq!(
                fs::metadata(current_generation_dir(temp.path(), url).join("iplist"))
                    .expect("iplist metadata")
                    .len(),
                u64::try_from(expected_bytes).expect("byte count")
            );
            let offline = crate::cached_sources::load_remote_sources(temp.path())
                .expect("offline cache read");
            assert_eq!(offline.len(), 1);
            assert_eq!(
                offline[0]
                    .entries
                    .iter()
                    .map(|entry| entry.cidr)
                    .collect::<Vec<_>>(),
                prepared.loaded.networks
            );
            let unavailable = MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]);
            let fallback = prepare_iplist_with_cache(&unavailable, url, temp.path(), &env, 500_000)
                .expect("read boundary fallback");
            assert_eq!(fallback.loaded.source, CacheSource::FallbackCache);
            assert_eq!(fallback.loaded.networks, prepared.loaded.networks);
            assert!(fallback.pending_promotion.is_none());
        }
    }

    #[test]
    fn normalized_cache_limit_rejection_preserves_selected_or_absent_cache() {
        let body = normalized_limit_body("2001:db8:111::/64");
        assert_eq!(body.len(), TEST_IPLIST_LIMIT + 1);
        let env = BTreeMap::from([(
            ENV_KIDOBO_MAX_HTTP_BODY_BYTES.into(),
            MAX_HTTP_BODY_BYTES.to_string().into(),
        )]);
        for existing in [true, false] {
            let temp = TempDir::new().expect("tempdir");
            let url = "https://example.test/large-feed";
            if existing {
                for seed in [b"192.0.2.0/24".as_slice(), b"198.51.100.0/24".as_slice()] {
                    fetch_iplist_with_cache(
                        &MockHttpClient::new(vec![Ok(network_response_for_test(seed))]),
                        url,
                        temp.path(),
                        &env,
                    )
                    .expect("seed selected cache");
                }
            }
            let store = remote_generation_store(temp.path(), url);
            let selected = generation_candidates(&store);
            let manifest_before =
                read_bytes_with_limit(&store.join("current.json"), 16 * 1024).ok();
            let client = MockHttpClient::new(vec![Ok(network_response_for_test(body.as_bytes()))]);
            let result = super::prepare_iplist_with_cache_limit(
                &client,
                url,
                temp.path(),
                &env,
                100,
                TEST_IPLIST_LIMIT,
            );
            if existing {
                let prepared = result.expect("validated fallback");
                assert_eq!(prepared.loaded.source, CacheSource::FallbackCache);
                assert_eq!(
                    prepared
                        .loaded
                        .networks
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    ["198.51.100.0/24"]
                );
                assert!(prepared.pending_promotion.is_none());
                assert_eq!(
                    fs::read_dir(store.join("generations"))
                        .expect("generations")
                        .count(),
                    2
                );
            } else {
                let Err(super::HttpCacheError::WriteMetadata { source, .. }) = result else {
                    panic!("oversized normalized content without fallback must fail");
                };
                assert_eq!(
                    source
                        .downcast_ref::<std::io::Error>()
                        .expect("I/O cause")
                        .kind(),
                    std::io::ErrorKind::InvalidData
                );
                assert_eq!(
                    source.to_string(),
                    "normalized iplist size 149 exceeds 148 byte limit"
                );
                assert!(!store.exists());
            }
            assert_eq!(generation_candidates(&store), selected);
            assert_eq!(
                read_bytes_with_limit(&store.join("current.json"), 16 * 1024).ok(),
                manifest_before
            );
        }
    }

    fn current_generation_dir(cache_dir: &Path, url: &str) -> PathBuf {
        generation_candidates(&remote_generation_store(cache_dir, url))
            .into_iter()
            .next()
            .expect("current cache generation")
            .directory
    }

    #[test]
    fn staging_failure_uses_validated_current_or_previous_generation() {
        let url = "https://example.test/feed";
        for corrupt_current in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            for body in [b"203.0.113.0/24".as_slice(), b"198.51.100.0/24".as_slice()] {
                let client = MockHttpClient::new(vec![Ok(network_response_for_test(body))]);
                fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("seed");
            }
            if corrupt_current {
                fs::write(
                    current_generation_dir(temp.path(), url).join(super::GENERATION_RAW_FILE),
                    b"corrupt",
                )
                .expect("corrupt");
            }
            let client = super::test_support::StagingFailureClient {
                cache_dir: temp.path(),
                response: network_response_for_test(b"192.0.2.0/24"),
            };
            let result =
                prepare_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new(), 100);
            client.restore_store();
            let prepared = result.expect("fallback");
            assert_eq!(prepared.loaded.source, CacheSource::FallbackCache);
            assert_eq!(
                prepared.loaded.networks[0].to_string(),
                if corrupt_current {
                    "203.0.113.0/24"
                } else {
                    "198.51.100.0/24"
                }
            );
            assert!(prepared.pending_promotion.is_none());
            assert_eq!(
                super::collect_offline_remote_generations(temp.path()).expect("offline")[0].iplist,
                crate::remote_parse::format_normalized_cidrs(&prepared.loaded.networks)
            );
        }
    }

    #[test]
    fn staging_failure_keeps_validated_legacy_including_empty_cache() {
        let url = "https://example.test/feed";
        for contents in [Some("203.0.113.0/24\n"), Some(""), None] {
            let temp = TempDir::new().expect("tempdir");
            fs::write(temp.path().join("v2"), b"block generation staging").expect("block");
            if let Some(contents) = contents {
                fs::write(cache_paths_for_url(temp.path(), url).iplist_path, contents)
                    .expect("legacy");
            }
            let client =
                MockHttpClient::new(vec![Ok(network_response_for_test(b"198.51.100.0/24\n"))]);
            let result =
                prepare_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new(), 100);
            if let Some(contents) = contents {
                let result = result.expect("validated fallback");
                assert_eq!(result.loaded.source, CacheSource::FallbackCache);
                assert_eq!(
                    crate::remote_parse::format_normalized_cidrs(&result.loaded.networks),
                    contents.trim()
                );
                assert!(result.pending_promotion.is_none());
            } else {
                let Err(error) = result else {
                    panic!("a staging error without cache must remain fatal");
                };
                let super::HttpCacheError::WriteMetadata { path, source } = &error else {
                    panic!("expected metadata staging failure, got {error:?}");
                };
                assert_eq!(
                    path,
                    &super::remote_generation_store(temp.path(), url).join("current.json")
                );
                let io_error = source
                    .downcast_ref::<std::io::Error>()
                    .expect("staging error must retain its filesystem cause");
                assert_eq!(io_error.kind(), std::io::ErrorKind::NotADirectory);
                assert!(io_error.raw_os_error().is_some());
                assert!(
                    Error::source(&error)
                        .and_then(|cause| cause.downcast_ref::<std::io::Error>())
                        .is_some(),
                    "HTTP cache error must expose the staging I/O error in its source chain"
                );
            }
        }
    }

    #[test]
    fn identical_refresh_repairs_cache_for_offline_and_failed_fetch_reads() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.test/feed";
        let body = b"203.0.113.0/24\n";
        let client = MockHttpClient::new(vec![
            Ok(network_response_for_test(body)),
            Ok(network_response_for_test(body)),
            Err(HttpClientError::Request {
                reason: "offline".to_string(),
            }),
        ]);
        fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("seed");
        fs::write(
            current_generation_dir(temp.path(), url).join(super::GENERATION_RAW_FILE),
            b"corrupt",
        )
        .expect("corrupt");
        fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("repair");
        let cached = super::read_remote_cache(
            temp.path(),
            url,
            &cache_paths_for_url(temp.path(), url),
            MAX_HTTP_BODY_BYTES,
            crate::remote_parse::RemoteFeedLimits::from_maxelem(100),
        )
        .expect("offline read");
        assert_eq!(cached.networks.expect("cache").len(), 1);
        let fallback =
            fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("fallback");
        assert_eq!(fallback.source, CacheSource::FallbackCache);
        assert_eq!(fallback.networks[0].to_string(), "203.0.113.0/24");
    }

    #[test]
    fn cache_paths_use_hash_suffixes() {
        let paths = cache_paths_for_url(Path::new("/cache/remote"), "https://example.com/feed.txt");
        assert_eq!(
            paths.iplist_path,
            PathBuf::from("/cache/remote/8d1ab0f09e05f237.iplist")
        );
        assert_eq!(
            paths.meta_path,
            PathBuf::from("/cache/remote/8d1ab0f09e05f237.meta.json")
        );
        assert_eq!(
            paths.raw_path,
            PathBuf::from("/cache/remote/8d1ab0f09e05f237.raw")
        );
    }

    #[test]
    fn normalization_filters_and_canonicalizes_lines() {
        let raw = b"\xEF\xBB\xBF 10.0.0.5 \n# comment\ninvalid\n2001:db8::1 trailing\n";
        let normalized = normalize_remote_text(raw);
        assert_eq!(normalized, "10.0.0.5/32\n2001:db8::1/128");
    }

    #[test]
    fn normalization_accepts_networks_in_first_csv_column() {
        let raw =
            b"ip,score\n161.117.138.100,0.164985\n2001:db8::1/64,0.125\ninvalid,203.0.113.7\n";

        let normalized = normalize_remote_text(raw);

        assert_eq!(normalized, "161.117.138.100/32\n2001:db8::/64");
    }

    #[test]
    fn csv_network_response_replaces_existing_cache() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.csv";
        let paths = cache_paths_for_url(temp.path(), url);
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let body = b"ip,score\n161.117.138.100,0.164985\n";
        let client = MockHttpClient::new(vec![Ok(network_response_for_test(body))]);

        let result =
            fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::Network);
        assert_eq!(result.networks.len(), 1);
        let generation = current_generation_dir(temp.path(), url);
        assert_eq!(
            read_to_string_with_limit(
                &generation.join(super::GENERATION_IPLIST_FILE),
                super::MAX_IPLIST_READ_BYTES,
            )
            .expect("read cache"),
            "161.117.138.100/32"
        );
        assert_eq!(
            read_bytes_with_limit(
                &generation.join(super::GENERATION_RAW_FILE),
                DEFAULT_MAX_HTTP_BODY_BYTES,
            )
            .expect("read raw"),
            body
        );
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read legacy cache"),
            "10.0.0.0/24\n"
        );
    }

    #[test]
    fn sends_conditional_headers_from_metadata() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let metadata = RemoteCacheMetadata {
            url: url.to_string(),
            etag: Some("etag-1".to_string()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            sha256_raw: sha256_hex(b"raw"),
            sha256_iplist: sha256_hex(b"10.0.0.0/24\n"),
        };
        fs::write(
            &paths.meta_path,
            serde_json::to_vec_pretty(&metadata).expect("json"),
        )
        .expect("write meta");

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::NOT_MODIFIED,
            body: Vec::new(),
            etag: None,
            last_modified: None,
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::CacheNotModified);
        assert_eq!(result.networks.len(), 1);

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].if_none_match.as_deref(), Some("etag-1"));
        assert_eq!(
            requests[0].if_modified_since.as_deref(),
            Some("Mon, 01 Jan 2024 00:00:00 GMT")
        );
    }

    #[test]
    fn status_304_without_cache_triggers_unconditional_refetch() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";

        let client = MockHttpClient::new(vec![
            Ok(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                body: Vec::new(),
                etag: None,
                last_modified: None,
            }),
            Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7".to_vec(),
                etag: Some("etag-2".to_string()),
                last_modified: Some("Tue, 02 Jan 2024 00:00:00 GMT".to_string()),
            }),
        ]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::Network);
        assert_eq!(result.networks.len(), 1);

        let requests = client.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].if_none_match, None);
        assert_eq!(requests[1].if_modified_since, None);

        let generation = current_generation_dir(cache_dir, url);
        assert!(generation.join(super::GENERATION_IPLIST_FILE).exists());
        assert!(generation.join(super::GENERATION_METADATA_FILE).exists());
        assert!(generation.join(super::GENERATION_RAW_FILE).exists());
    }

    #[test]
    fn network_error_falls_back_to_cache() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
        assert_eq!(result.networks[0].to_string(), "10.0.0.0/24");
    }

    #[test]
    fn unexpected_status_falls_back_to_existing_cache_without_overwriting() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: b"198.51.100.7".to_vec(),
            etag: Some("etag-new".to_string()),
            last_modified: Some("Tue, 02 Jan 2024 00:00:00 GMT".to_string()),
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
        assert_eq!(result.networks[0].to_string(), "10.0.0.0/24");
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read cache"),
            "10.0.0.0/24\n"
        );
    }

    #[test]
    fn successful_fetch_persists_normalized_iplist_and_raw_body_separately() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let body = b"\xEF\xBB\xBF 10.0.0.5 \n# comment\ninvalid\n2001:db8::1 trailing\n";
        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::OK,
            body: body.to_vec(),
            etag: Some("etag-1".to_string()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::Network);
        assert_eq!(result.networks.len(), 2);
        let generation = current_generation_dir(cache_dir, url);

        assert_eq!(
            read_to_string_with_limit(
                &generation.join(super::GENERATION_IPLIST_FILE),
                super::MAX_IPLIST_READ_BYTES,
            )
            .expect("read iplist"),
            "10.0.0.5/32\n2001:db8::1/128"
        );
        assert_eq!(
            read_bytes_with_limit(
                &generation.join(super::GENERATION_RAW_FILE),
                DEFAULT_MAX_HTTP_BODY_BYTES,
            )
            .expect("read raw"),
            body
        );

        let metadata: RemoteCacheMetadata = serde_json::from_slice(
            &read_bytes_with_limit(
                &generation.join(super::GENERATION_METADATA_FILE),
                super::MAX_METADATA_READ_BYTES,
            )
            .expect("read metadata"),
        )
        .expect("metadata json");
        assert_eq!(metadata.url, url);
        assert_eq!(metadata.etag.as_deref(), Some("etag-1"));
        assert_eq!(
            metadata.last_modified.as_deref(),
            Some("Mon, 01 Jan 2024 00:00:00 GMT")
        );
    }

    #[test]
    fn corrupt_current_generation_falls_back_to_previous_then_legacy() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";

        fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(network_response_for_test(b"10.0.0.0/24\n"))]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("first generation");
        fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(network_response_for_test(b"198.51.100.0/24\n"))]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("second generation");

        let candidates = generation_candidates(&remote_generation_store(temp.path(), url));
        assert_eq!(candidates.len(), 2);
        fs::write(
            candidates[0].directory.join(super::GENERATION_IPLIST_FILE),
            "corrupt\n",
        )
        .expect("corrupt current");
        let fallback = fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("previous fallback");
        assert_eq!(fallback.source, CacheSource::FallbackCache);
        assert_eq!(
            fallback
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.0/24"]
        );

        fs::write(
            candidates[1].directory.join(super::GENERATION_IPLIST_FILE),
            "also corrupt\n",
        )
        .expect("corrupt previous");
        let legacy = cache_paths_for_url(temp.path(), url);
        fs::write(&legacy.iplist_path, "203.0.113.0/24\n").expect("write legacy iplist");
        let fallback = fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("legacy fallback");
        assert_eq!(
            fallback
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["203.0.113.0/24"]
        );
    }

    #[test]
    fn successful_commits_retain_only_current_and_previous_generations() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";
        for body in [
            b"10.0.0.0/24\n".as_slice(),
            b"198.51.100.0/24\n".as_slice(),
            b"203.0.113.0/24\n".as_slice(),
        ] {
            fetch_iplist_with_cache(
                &MockHttpClient::new(vec![Ok(network_response_for_test(body))]),
                url,
                temp.path(),
                &BTreeMap::new(),
            )
            .expect("commit generation");
        }

        let store = remote_generation_store(temp.path(), url);
        let candidates = generation_candidates(&store);
        assert_eq!(candidates.len(), 2);
        let generation_directories = fs::read_dir(store.join("generations"))
            .expect("read generations")
            .filter_map(Result::ok)
            .filter(|entry| entry.path().is_dir())
            .collect::<Vec<_>>();
        assert_eq!(generation_directories.len(), 2);
    }

    #[test]
    fn all_invalid_network_body_preserves_existing_cache() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(temp.path(), url);
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::OK,
            body: b"not-a-network\nalso-invalid\n".to_vec(),
            etag: Some("bad-etag".to_string()),
            last_modified: None,
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read"),
            "10.0.0.0/24\n"
        );
        assert!(!paths.raw_path.exists());
        assert!(!paths.meta_path.exists());
        assert!(!remote_generation_store(temp.path(), url).exists());
    }

    #[test]
    fn all_invalid_network_body_without_cache_stays_empty_and_unpersisted() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(temp.path(), url);
        let client = MockHttpClient::new(vec![Ok(network_response_for_test(b"invalid\n"))]);

        let result =
            fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::Empty);
        assert_eq!(result.networks.len(), 0);
        assert!(!paths.iplist_path.exists());
        assert!(!paths.raw_path.exists());
        assert!(!paths.meta_path.exists());
        assert!(!remote_generation_store(temp.path(), url).exists());
    }

    #[test]
    fn comment_only_network_body_is_an_intentional_empty_feed() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";
        let body = b"# intentionally empty\n\n";
        let client = MockHttpClient::new(vec![Ok(network_response_for_test(body))]);

        let result =
            fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::Network);
        assert_eq!(result.networks.len(), 0);
        let generation = current_generation_dir(temp.path(), url);
        assert_eq!(
            read_to_string_with_limit(
                &generation.join(super::GENERATION_IPLIST_FILE),
                super::MAX_IPLIST_READ_BYTES,
            )
            .expect("read"),
            ""
        );
        assert_eq!(
            read_bytes_with_limit(
                &generation.join(super::GENERATION_RAW_FILE),
                DEFAULT_MAX_HTTP_BODY_BYTES,
            )
            .expect("read raw"),
            body
        );
        assert!(generation.join(super::GENERATION_METADATA_FILE).exists());
    }

    #[test]
    fn body_size_cap_falls_back_to_existing_cache() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::OK,
            body: b"10.0.0.1\n".to_vec(),
            etag: None,
            last_modified: None,
        })]);

        let mut env = BTreeMap::new();
        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".into(), "1".into());

        let result = fetch_iplist_with_cache(&client, url, cache_dir, &env).expect("fetch");
        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
        assert_eq!(result.networks[0].to_string(), "10.0.0.0/24");
    }

    #[test]
    fn invalid_metadata_cache_does_not_block_stale_iplist_fallback() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");
        fs::write(&paths.meta_path, "{invalid-json").expect("write invalid metadata");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
        assert_eq!(result.networks[0].to_string(), "10.0.0.0/24");

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].if_none_match, None);
        assert_eq!(requests[0].if_modified_since, None);
    }

    #[test]
    fn iplist_hash_mismatch_blocks_cached_fallback() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");
        fs::write(
            &paths.meta_path,
            serde_json::to_vec_pretty(&RemoteCacheMetadata {
                url: url.to_string(),
                etag: Some("etag-1".to_string()),
                last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
                sha256_raw: sha256_hex(b"raw"),
                sha256_iplist: sha256_hex(b"198.51.100.0/24\n"),
            })
            .expect("json"),
        )
        .expect("write meta");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::Empty);
        assert_eq!(result.networks.len(), 0);
    }

    #[test]
    fn body_size_cap_enforced() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::OK,
            body: b"10.0.0.1\n".to_vec(),
            etag: None,
            last_modified: None,
        })]);

        let mut env = BTreeMap::new();
        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".into(), "1".into());

        let result = fetch_iplist_with_cache(&client, url, cache_dir, &env).expect("fetch");
        assert_eq!(result.source, CacheSource::Empty);
        assert_eq!(result.networks.len(), 0);
    }

    #[test]
    fn staged_response_is_invisible_until_manifest_promotion() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";
        fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(network_response_for_test(b"192.0.2.0/24\n"))]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("initial fetch");
        let manifest_path = remote_generation_store(temp.path(), url).join("current.json");
        let before =
            read_bytes_with_limit(&manifest_path, 16 * 1024).expect("read selected manifest");

        let prepared = prepare_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(network_response_for_test(b"198.51.100.0/24\n"))]),
            url,
            temp.path(),
            &BTreeMap::new(),
            100,
        )
        .expect("prepare response");
        assert_eq!(prepared.loaded.source, CacheSource::Network);
        assert_eq!(
            read_bytes_with_limit(&manifest_path, 16 * 1024).expect("read manifest"),
            before
        );
        drop(prepared);

        let fallback = fetch_iplist_with_cache(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            url,
            temp.path(),
            &BTreeMap::new(),
        )
        .expect("fallback");
        assert_eq!(fallback.source, CacheSource::FallbackCache);
        assert_eq!(
            fallback
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.0.2.0/24"]
        );
    }

    #[test]
    fn duplicate_and_sparse_feeds_hit_distinct_parser_budgets() {
        let temp = TempDir::new().expect("tempdir");
        let url = "https://example.com/feed.txt";
        let duplicate_body = "192.0.2.1\n".repeat(16_385);
        let duplicate = prepare_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(network_response_for_test(
                duplicate_body.as_bytes(),
            ))]),
            url,
            temp.path(),
            &BTreeMap::new(),
            1,
        )
        .expect("duplicate rejection is a soft empty result");
        assert_eq!(duplicate.loaded.source, CacheSource::Empty);
        assert!(duplicate.pending_promotion.is_none());

        let mut sparse_body = String::new();
        for index in 0..4_097 {
            writeln!(sparse_body, "10.0.{}.{}", index / 256, index % 256)
                .expect("write sparse fixture");
        }
        let sparse = prepare_iplist_with_cache(
            &MockHttpClient::new(vec![Ok(network_response_for_test(sparse_body.as_bytes()))]),
            url,
            temp.path(),
            &BTreeMap::new(),
            1,
        )
        .expect("unique rejection is a soft empty result");
        assert_eq!(sparse.loaded.source, CacheSource::Empty);
        assert!(sparse.pending_promotion.is_none());
        assert!(
            !remote_generation_store(temp.path(), url)
                .join("current.json")
                .exists()
        );
    }

    #[test]
    fn blocked_remote_feed_redirect_preserves_cached_networks() {
        let temp = TempDir::new().expect("tempdir");
        let fixture = CrossOriginRedirectFixture::new();
        let paths = cache_paths_for_url(temp.path(), fixture.source_url());
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");
        let client = ReqwestHttpClient::with_timeout(Duration::from_secs(1));

        let result =
            fetch_iplist_with_cache(&client, fixture.source_url(), temp.path(), &BTreeMap::new())
                .expect("fetch");

        fixture.finish();
        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(
            result
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["10.0.0.0/24"]
        );
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read cache"),
            "10.0.0.0/24\n"
        );
    }
}
