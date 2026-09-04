//! Bounded HTTP and remote-feed cache adapter.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Duration;

use log::warn;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, USER_AGENT};
use reqwest::{StatusCode, Url, redirect};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cache_generation::{
    GenerationCandidate, GenerationFile, GenerationFileLimit, StagedGeneration,
    cleanup_unselected_generations, generation_candidates, generation_contents_match,
    stage_generation,
};
use crate::cached_fetch::{read_optional_json_lossy, read_validated_bytes_lossy};
use crate::hash::sha256_hex;
use crate::http_fetch::{ConditionalFetchResult, fetch_with_conditional_cache};
use crate::limited_io::{read_to_end_with_limit, read_to_string_with_limit};
use crate::remote_parse::{
    RemoteFeedLimits, RemoteParseBudget, format_normalized_cidrs, parse_cached_iplist_bounded,
    parse_remote_cidrs_bounded,
};
use kidobo_core::network::CanonicalCidr;

/// Default maximum accepted HTTP response body size.
pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 8 * 1024 * 1024;
/// Hard ceiling for the HTTP response body environment override.
pub const MAX_HTTP_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Environment variable that overrides the maximum HTTP body size when valid Unicode and positive.
pub const ENV_KIDOBO_MAX_HTTP_BODY_BYTES: &str = "KIDOBO_MAX_HTTP_BODY_BYTES";
/// Default timeout for one HTTP request.
pub const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(DEFAULT_HTTP_REQUEST_TIMEOUT_SECS);
const MAX_HTTP_REDIRECTS: usize = 10;
const MAX_IPLIST_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_READ_BYTES: usize = 512 * 1024;
const V2_REMOTE_CACHE_DIRECTORY: &str = "v2/remote";
const GENERATION_RAW_FILE: &str = "raw";
const GENERATION_IPLIST_FILE: &str = "iplist";
const GENERATION_METADATA_FILE: &str = "meta.json";
static RUSTLS_PROVIDER_INIT: Once = Once::new();

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

/// One bounded conditional HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Absolute HTTP or HTTPS URL.
    pub url: String,
    /// Optional `If-None-Match` validator.
    pub if_none_match: Option<String>,
    /// Optional `If-Modified-Since` validator.
    pub if_modified_since: Option<String>,
    /// Maximum accepted response body bytes.
    pub max_body_bytes: usize,
}

/// Bounded HTTP response and cache validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status code.
    pub status: StatusCode,
    /// Response body constrained by the request bound.
    pub body: Vec<u8>,
    /// Optional response entity tag.
    pub etag: Option<String>,
    /// Optional response last-modified value.
    pub last_modified: Option<String>,
}

/// Failure to initialize or use an HTTP client safely.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HttpClientError {
    /// TLS or client construction failed.
    #[error("http client initialization failed: {reason}")]
    Initialization {
        /// Client construction diagnostic.
        reason: String,
    },

    /// Request, redirect, response, or bounded body handling failed.
    #[error("http client request failed: {reason}")]
    Request {
        /// Request diagnostic.
        reason: String,
    },
}

/// Bounded HTTP client abstraction used by cache policy and tests.
pub trait HttpClient {
    /// Fetches one response while enforcing the request's body-size bound.
    ///
    /// # Errors
    ///
    /// Returns [`HttpClientError`] when client initialization, the request, response headers, or
    /// the bounded body read fails.
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError>;
}

/// Reqwest-backed client enforcing same-origin redirects and bounded bodies.
#[derive(Debug, Clone)]
pub struct ReqwestHttpClient {
    client: Result<reqwest::blocking::Client, HttpClientError>,
    user_agent: String,
    request_timeout: Duration,
}

impl Default for ReqwestHttpClient {
    fn default() -> Self {
        Self::with_timeout(DEFAULT_HTTP_REQUEST_TIMEOUT)
    }
}

impl ReqwestHttpClient {
    #[must_use]
    /// Creates a client with the default user agent and an explicit request timeout.
    pub fn with_timeout(request_timeout: Duration) -> Self {
        Self::new_with_timeout(default_user_agent(), request_timeout)
    }

    /// Creates a client with explicit user agent and request timeout.
    pub fn with_user_agent_and_timeout(
        user_agent: impl Into<String>,
        request_timeout: Duration,
    ) -> Self {
        Self::new_with_timeout(user_agent, request_timeout)
    }

    fn new_with_timeout(user_agent: impl Into<String>, request_timeout: Duration) -> Self {
        ensure_rustls_provider_installed();
        let client = reqwest::blocking::Client::builder()
            .redirect(same_origin_redirect_policy())
            .build()
            .map_err(|error| HttpClientError::Initialization {
                reason: error.to_string(),
            });
        Self {
            client,
            user_agent: user_agent.into(),
            request_timeout,
        }
    }
}

fn same_origin_redirect_policy() -> redirect::Policy {
    redirect::Policy::custom(|attempt| {
        if attempt.previous().len() > MAX_HTTP_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let Some(initial_url) = attempt.previous().first() else {
            return attempt.error("redirect chain is missing its initial URL");
        };
        if !has_same_http_origin(initial_url, attempt.url()) {
            return attempt.error("redirect target has a different origin");
        }
        attempt.follow()
    })
}

fn has_same_http_origin(initial_url: &Url, redirect_url: &Url) -> bool {
    matches!(initial_url.scheme(), "http" | "https")
        && matches!(redirect_url.scheme(), "http" | "https")
        && initial_url.origin() == redirect_url.origin()
}

fn ensure_rustls_provider_installed() {
    RUSTLS_PROVIDER_INIT.call_once(|| {
        let _install_result = rustls::crypto::ring::default_provider().install_default();
    });
}

impl HttpClient for ReqwestHttpClient {
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
        let client = self.client.as_ref().map_err(Clone::clone)?;
        let mut builder = client
            .get(&request.url)
            .header(USER_AGENT, &self.user_agent)
            .timeout(self.request_timeout);

        if let Some(etag) = &request.if_none_match {
            builder = builder.header(IF_NONE_MATCH, etag);
        }
        if let Some(last_modified) = &request.if_modified_since {
            builder = builder.header(IF_MODIFIED_SINCE, last_modified);
        }

        let mut response = builder.send().map_err(|err| HttpClientError::Request {
            reason: err.to_string(),
        })?;

        let status = response.status();
        let headers = response.headers().clone();
        let body = if status.is_success() {
            if response.content_length().is_some_and(|length| {
                length > u64::try_from(request.max_body_bytes).unwrap_or(u64::MAX)
            }) {
                return Err(HttpClientError::Request {
                    reason: format!("response body exceeds max {} bytes", request.max_body_bytes),
                });
            }
            read_response_body_capped(&mut response, request.max_body_bytes)?
        } else {
            Vec::new()
        };

        Ok(HttpResponse {
            status,
            body,
            etag: header_to_string(&headers, ETAG),
            last_modified: header_to_string(&headers, LAST_MODIFIED),
        })
    }
}

fn default_user_agent() -> String {
    format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"))
}

fn read_response_body_capped(
    response: &mut reqwest::blocking::Response,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpClientError> {
    read_to_end_with_limit(response, max_body_bytes, |limit| {
        format!("response body exceeds max {limit} bytes")
    })
    .map_err(|err| HttpClientError::Request {
        reason: err.to_string(),
    })
}

/// Failure to read legacy cache data or commit a validated v2 generation.
#[derive(Debug, Error)]
pub enum HttpCacheError {
    /// Normalized CIDR cache write failed.
    #[error("failed to write iplist cache {path}: {reason}")]
    WriteIplist {
        /// Cache path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// Cache metadata or v2 manifest write failed.
    #[error("failed to write metadata cache {path}: {reason}")]
    WriteMetadata {
        /// Cache path.
        path: PathBuf,
        /// Serialization or filesystem diagnostic.
        reason: String,
    },

    /// Raw response cache write failed.
    #[error("failed to write raw cache {path}: {reason}")]
    WriteRaw {
        /// Cache path.
        path: PathBuf,
        /// Filesystem diagnostic.
        reason: String,
    },

    /// Selected normalized CIDR cache could not be read safely.
    #[error("failed to read iplist cache {path}: {reason}")]
    ReadIplist {
        /// Cache path.
        path: PathBuf,
        /// Bounded-read diagnostic.
        reason: String,
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

#[must_use]
/// Resolves the positive Unicode body-size override or returns the documented default.
///
/// Missing, non-Unicode, zero, and malformed settings are treated as unset.
pub fn max_http_body_bytes(env: &BTreeMap<OsString, OsString>) -> usize {
    env.get(OsStr::new(ENV_KIDOBO_MAX_HTTP_BODY_BYTES))
        .and_then(|value| value.to_str())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .map_or(DEFAULT_MAX_HTTP_BODY_BYTES, |value| {
            value.min(MAX_HTTP_BODY_BYTES)
        })
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
                reason: err.to_string(),
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
    } = context;
    if !response.status.is_success() {
        warn!(
            "remote fetch failed for {url}: unexpected status {}",
            response.status
        );
        return Ok(prepared_fallback(cached_networks, cached_meta));
    }

    if response.body.len() > max_bytes {
        warn!(
            "remote fetch failed for {url}: body size {} exceeds max {} bytes",
            response.body.len(),
            max_bytes
        );
        return Ok(prepared_fallback(cached_networks, cached_meta));
    }

    let parsed = match parse_remote_cidrs_bounded(&response.body, feed_limits) {
        Ok(parsed) => parsed,
        Err(budget) => {
            warn_remote_budget_rejection(url, budget);
            return Ok(prepared_fallback(cached_networks, cached_meta));
        }
    };
    if parsed.data_lines > 0 && parsed.networks.is_empty() {
        warn!(
            "remote fetch failed for {url}: non-empty response contained no valid IP/CIDR entries"
        );
        return Ok(prepared_fallback(cached_networks, cached_meta));
    }
    if parsed.invalid_lines > 0 {
        warn!(
            "remote source {url} ignored {} invalid line(s)",
            parsed.invalid_lines
        );
    }
    let networks = parsed.networks;
    let normalized = format_normalized_cidrs(&networks);
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

fn stage_cache(
    cache_dir: &Path,
    url: &str,
    iplist: &str,
    raw: &[u8],
    meta: &RemoteCacheMetadata,
    previous_generation: Option<&str>,
) -> Result<StagedGeneration, HttpCacheError> {
    let metadata =
        serde_json::to_vec_pretty(meta).map_err(|err| HttpCacheError::WriteMetadata {
            path: remote_generation_store(cache_dir, url).join("current.json"),
            reason: err.to_string(),
        })?;
    let store = remote_generation_store(cache_dir, url);
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
        reason: err.to_string(),
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

pub(crate) fn remote_generation_store(cache_dir: &Path, url: &str) -> PathBuf {
    cache_dir
        .join(V2_REMOTE_CACHE_DIRECTORY)
        .join(url_hash_prefix(url))
}

pub(crate) fn collect_offline_remote_generations(
    cache_dir: &Path,
) -> Result<Vec<OfflineRemoteGeneration>, std::io::Error> {
    let stores_root = cache_dir.join(V2_REMOTE_CACHE_DIRECTORY);
    if !stores_root.exists() {
        return Ok(Vec::new());
    }
    let mut stores = Vec::new();
    for entry in std::fs::read_dir(&stores_root)? {
        let entry = entry?;
        let url_hash = entry.file_name().to_string_lossy().into_owned();
        if !entry.path().is_dir() || !is_url_hash(&url_hash) {
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
    if !paths.iplist_path.exists() {
        return Ok(None);
    }

    let iplist =
        read_to_string_with_limit(&paths.iplist_path, MAX_IPLIST_READ_BYTES).map_err(|err| {
            HttpCacheError::ReadIplist {
                path: paths.iplist_path.clone(),
                reason: err.to_string(),
            }
        })?;

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

fn header_to_string(
    headers: &reqwest::header::HeaderMap,
    name: reqwest::header::HeaderName,
) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // Hide the store after its validated contents have been loaded, then block generation staging.
    // This injects the same failure under root and unprivileged test users without chmod assumptions.
    pub(crate) struct StagingFailureClient<'a> {
        pub(crate) cache_dir: &'a std::path::Path,
        pub(crate) response: super::HttpResponse,
    }

    impl super::HttpClient for StagingFailureClient<'_> {
        fn fetch(
            &self,
            _: super::HttpRequest,
        ) -> Result<super::HttpResponse, super::HttpClientError> {
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

    pub(crate) struct CrossOriginRedirectFixture {
        source_url: String,
        destination_contacted: Arc<AtomicBool>,
        stop_tx: mpsc::Sender<()>,
        source_server: thread::JoinHandle<()>,
        destination_server: thread::JoinHandle<()>,
    }

    impl CrossOriginRedirectFixture {
        pub(crate) fn new() -> Self {
            let destination = TcpListener::bind("127.0.0.1:0").expect("bind destination listener");
            destination
                .set_nonblocking(true)
                .expect("set destination nonblocking");
            let destination_addr = destination.local_addr().expect("destination addr");
            let destination_contacted = Arc::new(AtomicBool::new(false));
            let destination_contacted_for_server = Arc::clone(&destination_contacted);
            let (stop_tx, stop_rx) = mpsc::channel();
            let destination_server = thread::spawn(move || {
                loop {
                    match destination.accept() {
                        Ok((mut socket, _)) => {
                            destination_contacted_for_server.store(true, Ordering::SeqCst);
                            let mut request_buf = [0_u8; 1024];
                            let _ = socket.read(&mut request_buf).expect("read request");
                            socket
                                .write_all(
                                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .expect("write response");
                            return;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            if stop_rx.try_recv().is_ok() {
                                return;
                            }
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => panic!("accept destination: {error}"),
                    }
                }
            });

            let source = TcpListener::bind("127.0.0.1:0").expect("bind source listener");
            let source_addr = source.local_addr().expect("source addr");
            let source_server = thread::spawn(move || {
                let (mut socket, _) = source.accept().expect("accept source");
                let mut request_buf = [0_u8; 1024];
                let _ = socket.read(&mut request_buf).expect("read source request");
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{destination_addr}/internal\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                socket
                    .write_all(response.as_bytes())
                    .expect("write redirect");
            });

            Self {
                source_url: format!("http://{source_addr}/source"),
                destination_contacted,
                stop_tx,
                source_server,
                destination_server,
            }
        }

        pub(crate) fn source_url(&self) -> &str {
            &self.source_url
        }

        pub(crate) fn finish(self) {
            self.source_server.join().expect("source server thread");
            let _ = self.stop_tx.send(());
            self.destination_server
                .join()
                .expect("destination server thread");
            assert!(
                !self.destination_contacted.load(Ordering::SeqCst),
                "redirect destination must not receive a request"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::fmt::Write as _;
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        CacheSource, DEFAULT_MAX_HTTP_BODY_BYTES, ENV_KIDOBO_MAX_HTTP_BODY_BYTES, HttpClient,
        HttpClientError, HttpRequest, HttpResponse, MAX_HTTP_BODY_BYTES, MAX_HTTP_REDIRECTS,
        RemoteCacheMetadata, ReqwestHttpClient, cache_paths_for_url, fetch_iplist_with_cache,
        has_same_http_origin, max_http_body_bytes, normalize_remote_text,
        prepare_iplist_with_cache, remote_generation_store, url_hash_prefix,
    };
    use crate::cache_generation::generation_candidates;
    use crate::hash::sha256_hex;
    use crate::http_cache::test_support::CrossOriginRedirectFixture;
    use crate::limited_io::{read_bytes_with_limit, read_to_string_with_limit};

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

    fn current_generation_dir(cache_dir: &Path, url: &str) -> PathBuf {
        generation_candidates(&remote_generation_store(cache_dir, url))
            .into_iter()
            .next()
            .expect("current cache generation")
            .directory
    }

    fn spawn_same_origin_redirect_chain(
        redirect_count: usize,
        final_response: bool,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let request_count = redirect_count + usize::from(final_response);
        let server = thread::spawn(move || {
            for index in 0..request_count {
                let (mut socket, _) = listener.accept().expect("accept");
                let mut request_buf = [0_u8; 1024];
                let _ = socket.read(&mut request_buf).expect("read request");
                let response = if final_response && index == redirect_count {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: /redirect-{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        index + 1
                    )
                };
                socket
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });
        (format!("http://{addr}/start"), server)
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
                assert!(
                    result.is_err(),
                    "a staging error without cache must remain fatal"
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
    fn url_hash_is_first_16_hex_of_sha256() {
        assert_eq!(
            url_hash_prefix("https://example.com/feed.txt"),
            "8d1ab0f09e05f237"
        );
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
    fn max_body_bytes_env_override_is_supported() {
        let mut env = BTreeMap::new();
        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".into(), "12345".into());
        assert_eq!(max_http_body_bytes(&env), 12345);

        env.insert(
            "KIDOBO_MAX_HTTP_BODY_BYTES".into(),
            usize::MAX.to_string().into(),
        );
        assert_eq!(max_http_body_bytes(&env), MAX_HTTP_BODY_BYTES);

        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".into(), "invalid".into());
        assert_eq!(
            max_http_body_bytes(&env),
            super::DEFAULT_MAX_HTTP_BODY_BYTES
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_unicode_max_body_bytes_uses_the_default() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let env = BTreeMap::from([(
            OsString::from(ENV_KIDOBO_MAX_HTTP_BODY_BYTES),
            OsString::from_vec(vec![0xff]),
        )]);

        assert_eq!(max_http_body_bytes(&env), DEFAULT_MAX_HTTP_BODY_BYTES);
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
                super::DEFAULT_MAX_HTTP_BODY_BYTES,
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
                super::DEFAULT_MAX_HTTP_BODY_BYTES,
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
        assert!(result.networks.is_empty());
        assert!(!paths.iplist_path.exists());
        assert!(!paths.raw_path.exists());
        assert!(!paths.meta_path.exists());
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
        assert!(result.networks.is_empty());
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
                super::DEFAULT_MAX_HTTP_BODY_BYTES,
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
        assert!(result.networks.is_empty());
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
        assert!(result.networks.is_empty());
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
    fn reqwest_http_client_enforces_max_body_bytes_while_reading() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let mut request_buf = [0_u8; 1024];
            let _ = socket.read(&mut request_buf).expect("read request");

            let body = b"0123456789";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            socket
                .write_all(response.as_bytes())
                .and_then(|()| socket.write_all(body))
                .expect("write response");
        });

        let client = ReqwestHttpClient::default();
        let err = client
            .fetch(HttpRequest {
                url: format!("http://{addr}/feed"),
                if_none_match: None,
                if_modified_since: None,
                max_body_bytes: 4,
            })
            .expect_err("oversized body should fail");

        let HttpClientError::Request { reason } = err else {
            panic!("body read should fail during the request");
        };
        assert!(reason.contains("exceeds max"));

        server.join().expect("server thread");
    }

    #[test]
    fn reqwest_http_client_follows_same_origin_redirect() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");

        let server = thread::spawn(move || {
            for response in [
                "HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string(),
                "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nConnection: close\r\n\r\n198.51.100.7"
                    .to_string(),
            ] {
                let (mut socket, _) = listener.accept().expect("accept");
                let mut request_buf = [0_u8; 1024];
                let _ = socket.read(&mut request_buf).expect("read request");
                socket
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
        });

        let client = ReqwestHttpClient::default();
        let response = client
            .fetch(HttpRequest {
                url: format!("http://{addr}/start"),
                if_none_match: None,
                if_modified_since: None,
                max_body_bytes: 1024,
            })
            .expect("same-origin redirect should succeed");

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.body, b"198.51.100.7");
        server.join().expect("server thread");
    }

    #[test]
    fn reqwest_http_client_rejects_cross_origin_redirect_before_contact() {
        let fixture = CrossOriginRedirectFixture::new();
        let client = ReqwestHttpClient::with_timeout(Duration::from_secs(1));
        let result = client.fetch(HttpRequest {
            url: fixture.source_url().to_string(),
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes: 1024,
        });

        fixture.finish();
        assert!(result.is_err(), "cross-origin redirect should fail");
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
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read cache"),
            "10.0.0.0/24\n"
        );
    }

    #[test]
    fn http_origin_requires_matching_scheme_host_and_effective_port() {
        let configured = reqwest::Url::parse("https://EXAMPLE.com/feed").expect("configured URL");

        assert!(has_same_http_origin(
            &configured,
            &reqwest::Url::parse("https://example.com:443/next").expect("same origin")
        ));
        assert!(!has_same_http_origin(
            &configured,
            &reqwest::Url::parse("http://example.com/next").expect("downgrade URL")
        ));
        assert!(!has_same_http_origin(
            &configured,
            &reqwest::Url::parse("https://other.example/next").expect("other host")
        ));
        assert!(!has_same_http_origin(
            &configured,
            &reqwest::Url::parse("https://example.com:8443/next").expect("other port")
        ));
    }

    #[test]
    fn reqwest_http_client_allows_ten_same_origin_redirects() {
        let (url, server) = spawn_same_origin_redirect_chain(MAX_HTTP_REDIRECTS, true);
        let client = ReqwestHttpClient::default();

        let response = client
            .fetch(HttpRequest {
                url,
                if_none_match: None,
                if_modified_since: None,
                max_body_bytes: 1024,
            })
            .expect("ten redirects should succeed");

        assert_eq!(response.status, StatusCode::OK);
        server.join().expect("server thread");
    }

    #[test]
    fn reqwest_http_client_rejects_eleventh_same_origin_redirect() {
        let (url, server) = spawn_same_origin_redirect_chain(MAX_HTTP_REDIRECTS + 1, false);
        let client = ReqwestHttpClient::default();

        let result = client.fetch(HttpRequest {
            url,
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes: 1024,
        });

        assert!(result.is_err(), "eleventh redirect should fail");
        server.join().expect("server thread");
    }

    #[test]
    fn reqwest_http_client_returns_stored_initialization_error() {
        let expected = HttpClientError::Initialization {
            reason: "test initialization failure".to_string(),
        };
        let client = ReqwestHttpClient {
            client: Err(expected.clone()),
            user_agent: "kidobo/test".to_string(),
            request_timeout: Duration::from_secs(1),
        };

        let error = client
            .fetch(HttpRequest {
                url: "https://example.com/feed".to_string(),
                if_none_match: None,
                if_modified_since: None,
                max_body_bytes: 1024,
            })
            .expect_err("stored initialization error should be returned");

        assert_eq!(error, expected);
    }

    #[test]
    fn reqwest_http_client_timeout_can_be_overridden() {
        let client = ReqwestHttpClient::with_timeout(Duration::from_secs(7));
        assert_eq!(client.request_timeout, Duration::from_secs(7));
    }
}
