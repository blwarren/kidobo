//! GitHub metadata safelist adapter.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::cache_generation::{
    GenerationFile, GenerationFileLimit, StagedGeneration, cleanup_unselected_generations,
    generation_candidates, generation_contents_match, stage_generation,
};
use crate::cached_fetch::{read_optional_json_lossy, read_validated_bytes_lossy};
use crate::hash::sha256_hex;
use crate::http_cache::{HttpClient, HttpResponse, max_http_body_bytes};
use crate::http_fetch::{ConditionalFetchResult, fetch_with_conditional_cache};
use kidobo_core::config::{
    DEFAULT_GITHUB_META_CATEGORIES, DEFAULT_GITHUB_META_URL, GithubMetaCategoryMode,
};
use kidobo_core::network::{
    CanonicalCidr, collapse_ipv4, collapse_ipv6, parse_ip_cidr_non_strict, split_by_family,
};

const GITHUB_META_RAW_CACHE_FILE: &str = "github-meta.raw.json";
const GITHUB_META_META_CACHE_FILE: &str = "github-meta.meta.json";
const GITHUB_META_CATEGORY_CACHE_FILE: &str = "github-meta.categories.json";
const GITHUB_META_V2_STORE: &str = "v2/github-meta";
const GENERATION_RAW_FILE: &str = "raw.json";
const GENERATION_META_FILE: &str = "meta.json";
const GENERATION_CATEGORY_FILE: &str = "categories.json";

const GITHUB_META_CACHE_READ_LIMIT: usize = 8 * 1024 * 1024;
const GITHUB_META_META_READ_LIMIT: usize = 512 * 1024;
const GITHUB_META_CATEGORY_READ_LIMIT: usize = 256 * 1024;
const GITHUB_META_MAX_ENTRIES: usize = 4_096;
const GITHUB_META_MIN_IPV4_PREFIX: u8 = 8;
const GITHUB_META_MIN_IPV6_PREFIX: u8 = 16;
const GITHUB_META_IPV4_COVERAGE_LIMIT: u64 = 1_u64 << 28;
const GITHUB_META_IPV6_COVERAGE_LIMIT: u128 = 1_u128 << 124;

/// HTTP validators and checksum bound to a GitHub metadata cache body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubMetaCacheMetadata {
    /// Configured endpoint URL whose response was cached.
    pub url: String,
    /// Optional HTTP entity tag.
    pub etag: Option<String>,
    /// Optional HTTP last-modified validator.
    pub last_modified: Option<String>,
    /// Lowercase SHA-256 checksum of the raw response bytes.
    pub sha256_raw: String,
}

/// Category selection recorded with a GitHub metadata cache generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubMetaCategorySidecar {
    /// Stable selection mode identifier.
    pub mode: String,
    /// Sorted selected categories when the mode is explicit.
    pub categories: Vec<String>,
}

/// Origin of a GitHub metadata load result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubMetaSource {
    /// Newly validated network response.
    Network,
    /// Existing cache accepted after HTTP 304.
    CacheNotModified,
    /// Existing cache used after a failed or invalid refresh.
    FallbackCache,
    /// No usable network or cache data was available.
    Empty,
}

/// Selected GitHub networks and cache provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubMetaLoadResult {
    /// Canonical networks from categories compatible with the requested scope.
    pub networks: Vec<CanonicalCidr>,
    /// Data provenance.
    pub source: GithubMetaSource,
    /// Validated HTTP metadata when available.
    pub metadata: Option<GithubMetaCacheMetadata>,
}

pub(crate) struct PreparedGithubMetaLoad {
    pub(crate) primary: GithubMetaLoadResult,
    pub(crate) fallback: Option<GithubMetaLoadResult>,
    pub(crate) pending_promotion: Option<StagedGeneration>,
    pub(crate) staging_failure: Option<GithubMetaLoadError>,
}

/// Failure to persist a fully validated GitHub metadata generation.
#[derive(Debug, Error)]
pub enum GithubMetaLoadError {
    /// A generation member or manifest could not be atomically written.
    #[error("failed to write github meta cache file {path}: {reason}")]
    WriteCacheFile {
        /// Cache generation store path.
        path: PathBuf,
        /// Serialization or filesystem diagnostic.
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CategorySelection {
    All,
    Selected(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachePaths {
    raw: PathBuf,
    metadata: PathBuf,
    category_sidecar: PathBuf,
    generation_store: PathBuf,
}

#[derive(Debug, Clone)]
struct CachedFallback<'a> {
    raw: Option<&'a [u8]>,
    networks: Option<Vec<CanonicalCidr>>,
    meta: Option<GithubMetaCacheMetadata>,
    sidecar: Option<&'a GithubMetaCategorySidecar>,
    previous_networks: Option<Vec<CanonicalCidr>>,
    previous_meta: Option<GithubMetaCacheMetadata>,
}

#[derive(Debug, Clone)]
struct GithubMetaCache {
    raw: Option<Vec<u8>>,
    networks: Option<Vec<CanonicalCidr>>,
    meta: Option<GithubMetaCacheMetadata>,
    sidecar: Option<GithubMetaCategorySidecar>,
    generation_id: Option<String>,
    previous_networks: Option<Vec<CanonicalCidr>>,
    previous_meta: Option<GithubMetaCacheMetadata>,
}

impl CachePaths {
    fn from_cache_dir(cache_dir: &Path) -> Self {
        Self {
            raw: cache_dir.join(GITHUB_META_RAW_CACHE_FILE),
            metadata: cache_dir.join(GITHUB_META_META_CACHE_FILE),
            category_sidecar: cache_dir.join(GITHUB_META_CATEGORY_CACHE_FILE),
            generation_store: cache_dir.join(GITHUB_META_V2_STORE),
        }
    }
}

/// Loads the selected GitHub metadata networks with conditional cache fallback.
///
/// # Errors
///
/// Returns [`GithubMetaLoadError::WriteCacheFile`] when a valid network response cannot be
/// persisted atomically and no compatible fallback exists, or when promotion fails. Network and
/// invalid-response failures otherwise use a validated fallback.
#[cfg(test)]
pub fn load_github_meta_safelist(
    client: &dyn HttpClient,
    cache_dir: &Path,
    github_meta_url: &str,
    category_mode: &GithubMetaCategoryMode,
    env: &BTreeMap<OsString, OsString>,
) -> Result<GithubMetaLoadResult, GithubMetaLoadError> {
    let prepared =
        prepare_github_meta_safelist(client, cache_dir, github_meta_url, category_mode, env)?;
    if let Some(promotion) = prepared.pending_promotion {
        promotion
            .promote()
            .map_err(|err| GithubMetaLoadError::WriteCacheFile {
                path: CachePaths::from_cache_dir(cache_dir)
                    .generation_store
                    .join("current.json"),
                reason: err.to_string(),
            })?;
    }
    Ok(prepared.primary)
}

pub(crate) fn prepare_github_meta_safelist(
    client: &dyn HttpClient,
    cache_dir: &Path,
    github_meta_url: &str,
    category_mode: &GithubMetaCategoryMode,
    env: &BTreeMap<OsString, OsString>,
) -> Result<PreparedGithubMetaLoad, GithubMetaLoadError> {
    let selection = CategorySelection::from_mode(category_mode);
    let max_bytes = max_http_body_bytes(env).min(GITHUB_META_CACHE_READ_LIMIT);
    let paths = CachePaths::from_cache_dir(cache_dir);
    cleanup_unselected_generations(&paths.generation_store);
    let cache = read_github_meta_cache(&paths, &selection, github_meta_url);
    let (cached_etag, cached_last_modified) = cache.http_validators();
    let previous = cache.previous_result();

    match fetch_with_conditional_cache(
        client,
        github_meta_url,
        max_bytes,
        cached_etag,
        cached_last_modified,
        cache.networks.is_some(),
        "github meta",
    ) {
        ConditionalFetchResult::CacheNotModified => {
            if let Some(networks) = cache.networks.clone() {
                Ok(PreparedGithubMetaLoad {
                    staging_failure: None,
                    primary: GithubMetaLoadResult {
                        networks,
                        source: GithubMetaSource::CacheNotModified,
                        metadata: cache.meta,
                    },
                    fallback: previous,
                    pending_promotion: None,
                })
            } else {
                Ok(PreparedGithubMetaLoad {
                    staging_failure: None,
                    primary: cache.fallback(None, &selection, GithubMetaSource::FallbackCache),
                    fallback: previous,
                    pending_promotion: None,
                })
            }
        }
        ConditionalFetchResult::FallbackCache => Ok(PreparedGithubMetaLoad {
            staging_failure: None,
            primary: cache.fallback(
                cache.networks.clone(),
                &selection,
                GithubMetaSource::FallbackCache,
            ),
            fallback: previous,
            pending_promotion: None,
        }),
        ConditionalFetchResult::Network(response) => handle_network_response(
            response,
            &paths,
            github_meta_url,
            max_bytes,
            cache.as_fallback(),
            &selection,
            cache.generation_id.as_deref(),
        ),
    }
}

#[must_use]
/// Loads a validated compatible GitHub metadata cache without network access.
///
/// The current v2 generation is preferred, followed by previous and legacy data.
pub fn load_cached_github_meta_safelist(
    cache_dir: &Path,
    github_meta_url: &str,
    category_mode: &GithubMetaCategoryMode,
) -> Option<Vec<CanonicalCidr>> {
    let selection = CategorySelection::from_mode(category_mode);
    let paths = CachePaths::from_cache_dir(cache_dir);

    read_github_meta_cache(&paths, &selection, github_meta_url).networks
}

fn read_github_meta_cache(
    paths: &CachePaths,
    selection: &CategorySelection,
    github_meta_url: &str,
) -> GithubMetaCache {
    let mut selected: Option<GithubMetaCache> = None;
    for candidate in generation_candidates(&paths.generation_store) {
        if !generation_contents_match(
            &candidate,
            &[
                GenerationFileLimit {
                    name: GENERATION_RAW_FILE,
                    read_limit: GITHUB_META_CACHE_READ_LIMIT,
                },
                GenerationFileLimit {
                    name: GENERATION_META_FILE,
                    read_limit: GITHUB_META_META_READ_LIMIT,
                },
                GenerationFileLimit {
                    name: GENERATION_CATEGORY_FILE,
                    read_limit: GITHUB_META_CATEGORY_READ_LIMIT,
                },
            ],
        ) {
            continue;
        }
        let generation_paths = CachePaths {
            raw: candidate.directory.join(GENERATION_RAW_FILE),
            metadata: candidate.directory.join(GENERATION_META_FILE),
            category_sidecar: candidate.directory.join(GENERATION_CATEGORY_FILE),
            generation_store: paths.generation_store.clone(),
        };
        let mut cache =
            read_github_meta_cache_files(&generation_paths, selection, github_meta_url, true);
        if cache.raw.is_some()
            && cache.networks.is_some()
            && cache.meta.is_some()
            && cache.sidecar.is_some()
        {
            if let Some(mut primary) = selected {
                primary.previous_networks = cache.networks;
                primary.previous_meta = cache.meta;
                return primary;
            }
            cache.generation_id = Some(candidate.id);
            selected = Some(cache);
        }
    }

    let legacy = read_github_meta_cache_files(paths, selection, github_meta_url, false);
    if let Some(mut primary) = selected {
        primary.previous_networks = legacy.networks;
        primary.previous_meta = legacy.meta;
        primary
    } else {
        legacy
    }
}

fn read_github_meta_cache_files(
    paths: &CachePaths,
    selection: &CategorySelection,
    github_meta_url: &str,
    require_metadata: bool,
) -> GithubMetaCache {
    let cached_meta = read_optional_json_lossy::<GithubMetaCacheMetadata>(
        &paths.metadata,
        GITHUB_META_META_READ_LIMIT,
        "github meta cache file",
    );
    let cache_url_matches = match cached_meta.as_ref() {
        Some(meta) => github_meta_cache_url_matches(meta, github_meta_url),
        None => !require_metadata && github_meta_url == DEFAULT_GITHUB_META_URL,
    };
    if !cache_url_matches {
        if cached_meta.is_some() {
            warn!("github meta cache URL differs from configured URL; ignoring stale cache");
        } else {
            warn!("github meta cache metadata is missing for custom URL; ignoring stale cache");
        }
    }

    let meta = if cache_url_matches { cached_meta } else { None };
    let raw = if cache_url_matches {
        read_validated_bytes_lossy(
            &paths.raw,
            GITHUB_META_CACHE_READ_LIMIT,
            "github meta cache file",
            meta.as_ref().map(|metadata| metadata.sha256_raw.as_str()),
            "github meta raw cache",
            "raw body",
        )
    } else {
        None
    };
    let sidecar = if cache_url_matches {
        read_optional_json_lossy::<GithubMetaCategorySidecar>(
            &paths.category_sidecar,
            GITHUB_META_CATEGORY_READ_LIMIT,
            "github meta cache file",
        )
    } else {
        None
    };

    let networks = if cache_scope_compatible(selection, sidecar.as_ref()) {
        raw.as_deref()
            .and_then(|contents| parse_and_extract_networks(contents, selection))
    } else {
        None
    };

    GithubMetaCache {
        raw,
        networks,
        meta,
        sidecar,
        generation_id: None,
        previous_networks: None,
        previous_meta: None,
    }
}

impl GithubMetaCache {
    fn http_validators(&self) -> (Option<String>, Option<String>) {
        self.meta.as_ref().map_or((None, None), |meta| {
            (meta.etag.clone(), meta.last_modified.clone())
        })
    }

    fn as_fallback(&self) -> CachedFallback<'_> {
        CachedFallback {
            raw: self.raw.as_deref(),
            networks: self.networks.clone(),
            meta: self.meta.clone(),
            sidecar: self.sidecar.as_ref(),
            previous_networks: self.previous_networks.clone(),
            previous_meta: self.previous_meta.clone(),
        }
    }

    fn previous_result(&self) -> Option<GithubMetaLoadResult> {
        self.previous_networks
            .clone()
            .map(|networks| GithubMetaLoadResult {
                networks,
                source: GithubMetaSource::FallbackCache,
                metadata: self.previous_meta.clone(),
            })
    }

    fn fallback(
        &self,
        cached_networks: Option<Vec<CanonicalCidr>>,
        selection: &CategorySelection,
        source: GithubMetaSource,
    ) -> GithubMetaLoadResult {
        cache_fallback(
            self.raw.as_deref(),
            cached_networks,
            self.meta.clone(),
            self.sidecar.as_ref(),
            selection,
            source,
        )
    }
}

fn handle_network_response(
    response: HttpResponse,
    paths: &CachePaths,
    github_meta_url: &str,
    max_bytes: usize,
    cached: CachedFallback<'_>,
    selection: &CategorySelection,
    previous_generation: Option<&str>,
) -> Result<PreparedGithubMetaLoad, GithubMetaLoadError> {
    if !response.status.is_success() {
        warn!(
            "github meta fetch failed: unexpected status {}",
            response.status
        );
        return Ok(prepared_github_fallback(cached, selection));
    }

    if response.body.len() > max_bytes {
        warn!(
            "github meta fetch failed: body size {} exceeds max {} bytes",
            response.body.len(),
            max_bytes
        );
        return Ok(prepared_github_fallback(cached, selection));
    }

    let Some(networks) = parse_and_extract_networks(&response.body, selection) else {
        warn!("github meta fetch failed: response body has invalid JSON or category data");
        return Ok(prepared_github_fallback(cached, selection));
    };

    let metadata = GithubMetaCacheMetadata {
        url: github_meta_url.to_string(),
        etag: response.etag,
        last_modified: response.last_modified,
        sha256_raw: sha256_hex(&response.body),
    };

    let pending_promotion = match stage_cache(
        paths,
        &response.body,
        &metadata,
        selection,
        previous_generation,
    ) {
        Ok(promotion) => promotion,
        Err(error) => {
            let mut fallback = prepared_github_fallback(cached, selection);
            if fallback.primary.source == GithubMetaSource::Empty {
                return Err(error);
            }
            warn!("github meta cache staging failed; using validated cache: {error}");
            fallback.staging_failure = Some(error);
            return Ok(fallback);
        }
    };

    let fallback = cached.networks.map(|networks| GithubMetaLoadResult {
        networks,
        source: GithubMetaSource::FallbackCache,
        metadata: cached.meta,
    });
    Ok(PreparedGithubMetaLoad {
        primary: GithubMetaLoadResult {
            networks,
            source: GithubMetaSource::Network,
            metadata: Some(metadata),
        },
        fallback,
        pending_promotion: Some(pending_promotion),
        staging_failure: None,
    })
}

fn stage_cache(
    paths: &CachePaths,
    raw: &[u8],
    metadata: &GithubMetaCacheMetadata,
    selection: &CategorySelection,
    previous_generation: Option<&str>,
) -> Result<StagedGeneration, GithubMetaLoadError> {
    let sidecar = selection.to_sidecar();
    let sidecar_bytes =
        serde_json::to_vec_pretty(&sidecar).map_err(|err| GithubMetaLoadError::WriteCacheFile {
            path: paths.generation_store.join("current.json"),
            reason: err.to_string(),
        })?;
    let metadata_bytes =
        serde_json::to_vec_pretty(metadata).map_err(|err| GithubMetaLoadError::WriteCacheFile {
            path: paths.generation_store.join("current.json"),
            reason: err.to_string(),
        })?;
    stage_generation(
        &paths.generation_store,
        &[
            GenerationFile {
                name: GENERATION_RAW_FILE,
                contents: raw,
            },
            GenerationFile {
                name: GENERATION_CATEGORY_FILE,
                contents: &sidecar_bytes,
            },
            GenerationFile {
                name: GENERATION_META_FILE,
                contents: &metadata_bytes,
            },
        ],
        previous_generation,
    )
    .map_err(|err| GithubMetaLoadError::WriteCacheFile {
        path: paths.generation_store.join("current.json"),
        reason: err.to_string(),
    })
}

fn prepared_github_fallback(
    cached: CachedFallback<'_>,
    selection: &CategorySelection,
) -> PreparedGithubMetaLoad {
    let CachedFallback {
        raw,
        networks,
        meta,
        sidecar,
        previous_networks,
        previous_meta,
    } = cached;
    PreparedGithubMetaLoad {
        primary: cache_fallback(
            raw,
            networks,
            meta,
            sidecar,
            selection,
            GithubMetaSource::FallbackCache,
        ),
        fallback: previous_networks.map(|networks| GithubMetaLoadResult {
            networks,
            source: GithubMetaSource::FallbackCache,
            metadata: previous_meta,
        }),
        pending_promotion: None,
        staging_failure: None,
    }
}

fn cache_fallback(
    cached_raw: Option<&[u8]>,
    cached_networks: Option<Vec<CanonicalCidr>>,
    cached_meta: Option<GithubMetaCacheMetadata>,
    cached_sidecar: Option<&GithubMetaCategorySidecar>,
    selection: &CategorySelection,
    source: GithubMetaSource,
) -> GithubMetaLoadResult {
    let Some(raw) = cached_raw else {
        return GithubMetaLoadResult {
            networks: Vec::new(),
            source: GithubMetaSource::Empty,
            metadata: cached_meta,
        };
    };

    if !cache_scope_compatible(selection, cached_sidecar) {
        warn!("github meta cache scope is incompatible with current category filter");
        return GithubMetaLoadResult {
            networks: Vec::new(),
            source: GithubMetaSource::Empty,
            metadata: cached_meta,
        };
    }

    let networks = if let Some(networks) = cached_networks {
        networks
    } else {
        let Some(networks) = parse_and_extract_networks(raw, selection) else {
            warn!("github meta cache is invalid JSON; ignoring stale cache");
            return GithubMetaLoadResult {
                networks: Vec::new(),
                source: GithubMetaSource::Empty,
                metadata: cached_meta,
            };
        };
        networks
    };

    GithubMetaLoadResult {
        networks,
        source,
        metadata: cached_meta,
    }
}

fn parse_and_extract_networks(
    raw: &[u8],
    selection: &CategorySelection,
) -> Option<Vec<CanonicalCidr>> {
    let value: Value = serde_json::from_slice(raw).ok()?;
    let selected_values = match selection {
        CategorySelection::All => None,
        CategorySelection::Selected(categories) => {
            let Value::Object(root) = &value else {
                return None;
            };
            let values = categories
                .iter()
                .map(|category| root.get(category))
                .collect::<Option<Vec<_>>>()?;
            Some(values)
        }
    };

    let networks = extract_networks(&value, selection);
    if networks.is_empty() {
        let intentionally_empty = selected_values.as_ref().map_or_else(
            || is_empty_container_tree(&value),
            |values| values.iter().all(|entry| is_empty_container_tree(entry)),
        );
        if !intentionally_empty {
            return None;
        }
    }

    if !github_meta_networks_within_envelope(&networks) {
        return None;
    }

    Some(networks)
}

fn github_meta_networks_within_envelope(networks: &[CanonicalCidr]) -> bool {
    if networks.len() > GITHUB_META_MAX_ENTRIES
        || networks.iter().any(|network| match network {
            CanonicalCidr::V4(cidr) => cidr.prefix() < GITHUB_META_MIN_IPV4_PREFIX,
            CanonicalCidr::V6(cidr) => cidr.prefix() < GITHUB_META_MIN_IPV6_PREFIX,
        })
    {
        return false;
    }

    let families = split_by_family(networks);
    let ipv4_coverage = collapse_ipv4(&families.ipv4)
        .iter()
        .map(|cidr| 1_u64 << (32 - u32::from(cidr.prefix())))
        .try_fold(0_u64, u64::checked_add);
    let ipv6_coverage = collapse_ipv6(&families.ipv6)
        .iter()
        .map(|cidr| 1_u128 << (128 - u32::from(cidr.prefix())))
        .try_fold(0_u128, u128::checked_add);

    ipv4_coverage.is_some_and(|coverage| coverage <= GITHUB_META_IPV4_COVERAGE_LIMIT)
        && ipv6_coverage.is_some_and(|coverage| coverage <= GITHUB_META_IPV6_COVERAGE_LIMIT)
}

fn is_empty_container_tree(value: &Value) -> bool {
    match value {
        Value::Array(values) => values.iter().all(is_empty_container_tree),
        Value::Object(values) => values.values().all(is_empty_container_tree),
        _ => false,
    }
}

fn extract_networks(value: &Value, selection: &CategorySelection) -> Vec<CanonicalCidr> {
    let mut extracted = Vec::new();

    match selection {
        CategorySelection::All => collect_networks_recursively(value, &mut extracted),
        CategorySelection::Selected(categories) => {
            if let Value::Object(root) = value {
                for category in categories {
                    if let Some(category_value) = root.get(category) {
                        collect_networks_recursively(category_value, &mut extracted);
                    }
                }
            }
        }
    }

    extracted.sort_unstable();
    extracted.dedup();
    extracted
}

fn collect_networks_recursively(value: &Value, extracted: &mut Vec<CanonicalCidr>) {
    let mut queue = VecDeque::from([value]);

    while let Some(next) = queue.pop_front() {
        match next {
            Value::String(value) => {
                if let Some(cidr) = parse_ip_cidr_non_strict(value) {
                    extracted.push(cidr);
                }
            }
            Value::Array(values) => {
                for entry in values {
                    queue.push_back(entry);
                }
            }
            Value::Object(map) => {
                for entry in map.values() {
                    queue.push_back(entry);
                }
            }
            _ => {}
        }
    }
}

fn cache_scope_compatible(
    selection: &CategorySelection,
    sidecar: Option<&GithubMetaCategorySidecar>,
) -> bool {
    match selection {
        CategorySelection::All => true,
        CategorySelection::Selected(categories) => {
            let Some(sidecar) = sidecar else {
                return false;
            };

            if sidecar.mode != "selected" {
                return false;
            }

            normalize_categories(sidecar.categories.iter().map(String::as_str)) == *categories
        }
    }
}

fn github_meta_cache_url_matches(meta: &GithubMetaCacheMetadata, configured_url: &str) -> bool {
    meta.url.trim() == configured_url.trim()
}

impl CategorySelection {
    fn from_mode(mode: &GithubMetaCategoryMode) -> Self {
        match mode {
            GithubMetaCategoryMode::All => Self::All,
            GithubMetaCategoryMode::Default => {
                Self::Selected(normalize_categories(DEFAULT_GITHUB_META_CATEGORIES))
            }
            GithubMetaCategoryMode::Explicit(values) => {
                Self::Selected(normalize_categories(values.iter().map(String::as_str)))
            }
        }
    }

    fn to_sidecar(&self) -> GithubMetaCategorySidecar {
        match self {
            CategorySelection::All => GithubMetaCategorySidecar {
                mode: "all".to_string(),
                categories: Vec::new(),
            },
            CategorySelection::Selected(categories) => GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: categories.clone(),
            },
        }
    }
}

fn normalize_categories<I, S>(values: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut unique = BTreeSet::new();

    for value in values {
        let normalized = value.as_ref().trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            unique.insert(normalized);
        }
    }

    unique.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::fmt::Write as _;
    use std::fs;
    use std::time::Duration;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        CachePaths, CategorySelection, GITHUB_META_CATEGORY_CACHE_FILE,
        GITHUB_META_CATEGORY_READ_LIMIT, GITHUB_META_META_CACHE_FILE, GITHUB_META_META_READ_LIMIT,
        GITHUB_META_RAW_CACHE_FILE, GithubMetaCacheMetadata, GithubMetaCategorySidecar,
        GithubMetaLoadResult, GithubMetaSource, load_github_meta_safelist,
        parse_and_extract_networks, prepare_github_meta_safelist,
    };
    use crate::cache_generation::generation_candidates;
    use crate::hash::sha256_hex;
    use crate::http_cache::test_support::CrossOriginRedirectFixture;
    use crate::http_cache::{
        HttpClient, HttpClientError, HttpRequest, HttpResponse, ReqwestHttpClient,
    };
    use crate::limited_io::read_bytes_with_limit;
    use kidobo_core::config::GithubMetaCategoryMode;
    use kidobo_core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};

    const TEST_GITHUB_META_URL: &str = "https://api.github.com/meta";

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

    fn network_response(body: &[u8]) -> HttpResponse {
        HttpResponse {
            status: StatusCode::OK,
            body: body.to_vec(),
            etag: Some("etag-1".to_string()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
        }
    }

    fn assert_has(result: &GithubMetaLoadResult, cidr: CanonicalCidr) {
        assert!(result.networks.contains(&cidr));
    }

    fn current_generation_dir(cache_dir: &std::path::Path) -> std::path::PathBuf {
        generation_candidates(&CachePaths::from_cache_dir(cache_dir).generation_store)
            .into_iter()
            .next()
            .expect("current GitHub cache generation")
            .directory
    }

    #[test]
    fn fetches_and_filters_default_categories() {
        let temp = TempDir::new().expect("tempdir");
        let client = MockHttpClient::new(vec![Ok(network_response(
            br#"{
                "api": ["192.30.252.0/22", "2001:db8::1"],
                "git": ["198.51.100.7"],
                "hooks": ["10.0.0.0/24"],
                "packages": ["203.0.113.0/24"],
                "actions": ["203.0.114.0/24"]
            }"#,
        ))]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Network);
        assert_eq!(result.networks.len(), 5);
        assert_has(
            &result,
            CanonicalCidr::V4(
                Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc01e_fc00_u32), 22)
                    .expect("valid test CIDR"),
            ),
        );
        assert_has(
            &result,
            CanonicalCidr::V6(
                Ipv6Cidr::new(
                    std::net::Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0001_u128),
                    128,
                )
                .expect("valid test CIDR"),
            ),
        );
        assert!(!result.networks.contains(&CanonicalCidr::V4(
            Ipv4Cidr::new(std::net::Ipv4Addr::from(0xcb00_7200_u32), 24).expect("valid test CIDR")
        )));

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].url, TEST_GITHUB_META_URL);
    }

    #[test]
    fn explicit_category_filter_is_applied() {
        let temp = TempDir::new().expect("tempdir");
        let client = MockHttpClient::new(vec![Ok(network_response(
            br#"{
                "api": ["192.30.252.0/22"],
                "hooks": ["10.0.0.0/24"],
                "packages": ["203.0.113.0/24"]
            }"#,
        ))]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["hooks".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Network);
        assert_eq!(
            result.networks,
            vec![CanonicalCidr::V4(
                Ipv4Cidr::new(std::net::Ipv4Addr::from(0x0a00_0000_u32), 24)
                    .expect("valid test CIDR")
            )]
        );
    }

    #[test]
    fn staging_failure_retains_current_or_previous_github_generation() {
        for corrupt_current in [false, true] {
            let temp = TempDir::new().expect("tempdir");
            for body in [
                br#"{"hooks":["203.0.113.0/24"]}"#.as_slice(),
                br#"{"hooks":["198.51.100.0/24"]}"#.as_slice(),
            ] {
                let client = MockHttpClient::new(vec![Ok(network_response(body))]);
                load_github_meta_safelist(
                    &client,
                    temp.path(),
                    TEST_GITHUB_META_URL,
                    &GithubMetaCategoryMode::All,
                    &BTreeMap::new(),
                )
                .expect("seed");
            }
            if corrupt_current {
                fs::write(
                    current_generation_dir(temp.path()).join(super::GENERATION_RAW_FILE),
                    b"corrupt",
                )
                .expect("corrupt");
            }
            let client = crate::http_cache::test_support::StagingFailureClient {
                cache_dir: temp.path(),
                response: network_response(br#"{"hooks":["192.0.2.0/24"]}"#),
            };
            let result = super::prepare_github_meta_safelist(
                &client,
                temp.path(),
                TEST_GITHUB_META_URL,
                &GithubMetaCategoryMode::All,
                &BTreeMap::new(),
            );
            client.restore_store();
            let prepared = result.expect("fallback");
            assert_eq!(prepared.primary.source, GithubMetaSource::FallbackCache);
            assert_eq!(
                prepared.primary.networks[0].to_string(),
                if corrupt_current {
                    "203.0.113.0/24"
                } else {
                    "198.51.100.0/24"
                }
            );
            assert!(prepared.staging_failure.is_some());
            assert!(prepared.pending_promotion.is_none());
        }
    }

    #[test]
    fn staging_failure_retains_legacy_fallback_and_rejects_absent_cache() {
        for raw in [
            Some(br#"{"hooks":["203.0.113.0/24"]}"#.as_slice()),
            Some(b"{}".as_slice()),
            None,
        ] {
            let temp = TempDir::new().expect("tempdir");
            fs::write(temp.path().join("v2"), b"block generation staging").expect("block");
            if let Some(raw) = raw {
                fs::write(temp.path().join(GITHUB_META_RAW_CACHE_FILE), raw).expect("legacy");
            }
            let client = MockHttpClient::new(vec![Ok(network_response(
                br#"{"hooks":["198.51.100.0/24"]}"#,
            ))]);
            let result = super::prepare_github_meta_safelist(
                &client,
                temp.path(),
                TEST_GITHUB_META_URL,
                &GithubMetaCategoryMode::All,
                &BTreeMap::new(),
            );
            if let Some(raw) = raw {
                let prepared = result.expect("fallback");
                assert_eq!(prepared.primary.source, GithubMetaSource::FallbackCache);
                assert!(prepared.staging_failure.is_some());
                assert!(prepared.pending_promotion.is_none());
                assert_eq!(prepared.primary.networks.len(), usize::from(raw != b"{}"));
            } else {
                assert!(result.is_err());
            }
        }
    }

    #[test]
    fn unchanged_refresh_retains_previous_and_repairs_identical_corruption() {
        let temp = TempDir::new().expect("tempdir");
        let first = br#"{"hooks":["203.0.113.0/24"]}"#;
        let second = br#"{"hooks":["198.51.100.0/24"]}"#;
        for body in [first.as_slice(), second.as_slice(), second.as_slice()] {
            let client = MockHttpClient::new(vec![Ok(network_response(body))]);
            load_github_meta_safelist(
                &client,
                temp.path(),
                TEST_GITHUB_META_URL,
                &GithubMetaCategoryMode::All,
                &BTreeMap::new(),
            )
            .expect("refresh");
        }
        let candidates = crate::cache_generation::generation_candidates(
            &super::CachePaths::from_cache_dir(temp.path()).generation_store,
        );
        assert_eq!(candidates.len(), 2);
        fs::write(
            candidates[0].directory.join(super::GENERATION_RAW_FILE),
            b"corrupt",
        )
        .expect("corrupt");
        let offline = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);
        let fallback = load_github_meta_safelist(
            &offline,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("previous");
        assert_eq!(fallback.networks[0].to_string(), "203.0.113.0/24");
        let client = MockHttpClient::new(vec![Ok(network_response(second))]);
        load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("repair");
        assert_eq!(
            read_bytes_with_limit(
                &candidates[0].directory.join(super::GENERATION_RAW_FILE),
                1024
            )
            .expect("repaired"),
            second
        );
    }

    #[test]
    fn selected_mode_rejects_missing_category_without_overwriting_cache() {
        let temp = TempDir::new().expect("tempdir");
        let cached_raw = br#"{"hooks":["10.0.0.0/24"],"packages":[]}"#;
        fs::write(temp.path().join(GITHUB_META_RAW_CACHE_FILE), cached_raw)
            .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec!["hooks".to_string(), "packages".to_string()],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");
        let client = MockHttpClient::new(vec![Ok(network_response(
            br#"{"hooks":["198.51.100.0/24"]}"#,
        ))]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["hooks".to_string(), "packages".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::FallbackCache);
        assert_eq!(
            read_bytes_with_limit(
                &temp.path().join(GITHUB_META_RAW_CACHE_FILE),
                super::GITHUB_META_CACHE_READ_LIMIT,
            )
            .expect("read cache"),
            cached_raw
        );
    }

    #[test]
    fn selected_mode_accepts_present_empty_categories() {
        let temp = TempDir::new().expect("tempdir");
        let client =
            MockHttpClient::new(vec![Ok(network_response(br#"{"hooks":[],"packages":{}}"#))]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["hooks".to_string(), "packages".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Network);
        assert!(result.networks.is_empty());
        assert!(
            current_generation_dir(temp.path())
                .join(super::GENERATION_RAW_FILE)
                .exists()
        );
    }

    #[test]
    fn all_mode_distinguishes_empty_from_nonempty_invalid_trees() {
        let empty_temp = TempDir::new().expect("tempdir");
        let empty_client = MockHttpClient::new(vec![Ok(network_response(br"{}"))]);
        let empty = load_github_meta_safelist(
            &empty_client,
            empty_temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("load empty");
        assert_eq!(empty.source, GithubMetaSource::Network);

        let invalid_temp = TempDir::new().expect("tempdir");
        let invalid_client = MockHttpClient::new(vec![Ok(network_response(
            br#"{"nested":["not-a-network"]}"#,
        ))]);
        let invalid = load_github_meta_safelist(
            &invalid_client,
            invalid_temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("load invalid");
        assert_eq!(invalid.source, GithubMetaSource::Empty);
        assert!(
            !invalid_temp
                .path()
                .join(GITHUB_META_RAW_CACHE_FILE)
                .exists()
        );
    }

    #[test]
    fn all_mode_extracts_recursively() {
        let temp = TempDir::new().expect("tempdir");
        let client = MockHttpClient::new(vec![Ok(network_response(
            br#"{
                "nested": {
                    "layer": [
                        {"value": "198.51.100.7"},
                        ["2001:db8::/126", "invalid"]
                    ]
                }
            }"#,
        ))]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Network);
        assert_eq!(result.networks.len(), 2);
        assert_has(
            &result,
            CanonicalCidr::V4(
                Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc633_6407_u32), 32)
                    .expect("valid test CIDR"),
            ),
        );
        assert_has(
            &result,
            CanonicalCidr::V6(
                Ipv6Cidr::new(
                    std::net::Ipv6Addr::from(0x2001_0db8_0000_0000_0000_0000_0000_0000_u128),
                    126,
                )
                .expect("valid test CIDR"),
            ),
        );
    }

    #[test]
    fn writes_metadata_and_category_sidecar() {
        let temp = TempDir::new().expect("tempdir");
        let client =
            MockHttpClient::new(vec![Ok(network_response(br#"{"hooks":["10.0.0.0/24"]}"#))]);

        let _ = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["hooks".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        let generation = current_generation_dir(temp.path());
        let metadata: GithubMetaCacheMetadata = serde_json::from_slice(
            &read_bytes_with_limit(
                &generation.join(super::GENERATION_META_FILE),
                GITHUB_META_META_READ_LIMIT,
            )
            .expect("read metadata"),
        )
        .expect("metadata json");
        assert_eq!(metadata.url, TEST_GITHUB_META_URL);

        let sidecar: GithubMetaCategorySidecar = serde_json::from_slice(
            &read_bytes_with_limit(
                &generation.join(super::GENERATION_CATEGORY_FILE),
                GITHUB_META_CATEGORY_READ_LIMIT,
            )
            .expect("read sidecar"),
        )
        .expect("sidecar json");
        assert_eq!(sidecar.mode, "selected");
        assert_eq!(sidecar.categories, vec!["hooks".to_string()]);

        assert!(generation.join(super::GENERATION_RAW_FILE).exists());
    }

    #[test]
    fn corrupt_current_generation_falls_back_to_previous_then_legacy() {
        let temp = TempDir::new().expect("tempdir");
        let mode = GithubMetaCategoryMode::Explicit(vec!["hooks".to_string()]);
        load_github_meta_safelist(
            &MockHttpClient::new(vec![Ok(network_response(br#"{"hooks":["10.0.0.0/24"]}"#))]),
            temp.path(),
            TEST_GITHUB_META_URL,
            &mode,
            &BTreeMap::new(),
        )
        .expect("first generation");
        load_github_meta_safelist(
            &MockHttpClient::new(vec![Ok(network_response(
                br#"{"hooks":["198.51.100.0/24"]}"#,
            ))]),
            temp.path(),
            TEST_GITHUB_META_URL,
            &mode,
            &BTreeMap::new(),
        )
        .expect("second generation");

        let store = CachePaths::from_cache_dir(temp.path()).generation_store;
        let candidates = generation_candidates(&store);
        assert_eq!(candidates.len(), 2);
        fs::write(
            candidates[0].directory.join(super::GENERATION_RAW_FILE),
            b"corrupt",
        )
        .expect("corrupt current");
        let fallback = load_github_meta_safelist(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            temp.path(),
            TEST_GITHUB_META_URL,
            &mode,
            &BTreeMap::new(),
        )
        .expect("previous fallback");
        assert_eq!(fallback.source, GithubMetaSource::FallbackCache);
        assert_eq!(fallback.networks[0].to_string(), "10.0.0.0/24");

        fs::write(
            candidates[1].directory.join(super::GENERATION_RAW_FILE),
            b"also corrupt",
        )
        .expect("corrupt previous");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"hooks":["203.0.113.0/24"]}"#,
        )
        .expect("write legacy raw");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec!["hooks".to_string()],
            })
            .expect("serialize legacy sidecar"),
        )
        .expect("write legacy sidecar");
        let fallback = load_github_meta_safelist(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            temp.path(),
            TEST_GITHUB_META_URL,
            &mode,
            &BTreeMap::new(),
        )
        .expect("legacy fallback");
        assert_eq!(fallback.networks[0].to_string(), "203.0.113.0/24");
    }

    #[test]
    fn network_failure_exposes_previous_generation_for_application_admission() {
        let temp = TempDir::new().expect("tempdir");
        for body in [
            br#"{"api":["192.0.2.0/25"],"git":[],"hooks":[],"packages":[]}"#.as_slice(),
            br#"{"api":["198.51.100.0/25"],"git":[],"hooks":[],"packages":[]}"#.as_slice(),
        ] {
            load_github_meta_safelist(
                &MockHttpClient::new(vec![Ok(network_response(body))]),
                temp.path(),
                TEST_GITHUB_META_URL,
                &GithubMetaCategoryMode::Default,
                &BTreeMap::new(),
            )
            .expect("populate generation");
        }

        let prepared = prepare_github_meta_safelist(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("prepare fallback");

        assert_eq!(
            prepared
                .primary
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["198.51.100.0/25"]
        );
        assert_eq!(
            prepared
                .fallback
                .expect("previous generation")
                .networks
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["192.0.2.0/25"]
        );
    }

    #[test]
    fn network_error_falls_back_to_compatible_cache() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"api":["192.30.252.0/22"],"git":[],"hooks":[],"packages":[]}"#,
        )
        .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "api".to_string(),
                    "git".to_string(),
                    "hooks".to_string(),
                    "packages".to_string(),
                ],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
    }

    #[test]
    fn blocked_github_meta_redirect_preserves_compatible_cache() {
        let temp = TempDir::new().expect("tempdir");
        let fixture = CrossOriginRedirectFixture::new();
        let cached_raw = br#"{"api":["192.30.252.0/22"],"git":[],"hooks":[],"packages":[]}"#;
        fs::write(temp.path().join(GITHUB_META_RAW_CACHE_FILE), cached_raw)
            .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_META_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCacheMetadata {
                url: fixture.source_url().to_string(),
                etag: None,
                last_modified: None,
                sha256_raw: sha256_hex(cached_raw),
            })
            .expect("metadata json"),
        )
        .expect("write metadata");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "api".to_string(),
                    "git".to_string(),
                    "hooks".to_string(),
                    "packages".to_string(),
                ],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");
        let client = ReqwestHttpClient::with_timeout(Duration::from_secs(1));

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            fixture.source_url(),
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        fixture.finish();
        assert_eq!(result.source, GithubMetaSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
        assert_eq!(
            read_bytes_with_limit(
                &temp.path().join(GITHUB_META_RAW_CACHE_FILE),
                super::GITHUB_META_CACHE_READ_LIMIT,
            )
            .expect("read cache"),
            cached_raw
        );
    }

    #[test]
    fn cache_with_different_url_is_not_reused() {
        let temp = TempDir::new().expect("tempdir");
        let raw = br#"{"api":["192.30.252.0/22"]}"#;
        fs::write(temp.path().join(GITHUB_META_RAW_CACHE_FILE), raw).expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_META_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCacheMetadata {
                url: "https://example.com/old-meta".to_string(),
                etag: Some("old-etag".to_string()),
                last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
                sha256_raw: sha256_hex(raw),
            })
            .expect("meta json"),
        )
        .expect("write metadata");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "api".to_string(),
                    "git".to_string(),
                    "hooks".to_string(),
                    "packages".to_string(),
                ],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Empty);
        assert!(result.networks.is_empty());

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].if_none_match, None);
        assert_eq!(requests[0].if_modified_since, None);
    }

    #[test]
    fn cache_without_metadata_is_not_reused_for_custom_url() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"api":["192.30.252.0/22"]}"#,
        )
        .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "api".to_string(),
                    "git".to_string(),
                    "hooks".to_string(),
                    "packages".to_string(),
                ],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            "https://example.com/custom-meta",
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Empty);
        assert!(result.networks.is_empty());

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].if_none_match, None);
        assert_eq!(requests[0].if_modified_since, None);
    }

    #[test]
    fn all_mode_uses_cache_without_sidecar() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"nested":{"values":["198.51.100.7"]}}"#,
        )
        .expect("write raw cache");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::FallbackCache);
        assert_eq!(
            result.networks,
            vec![CanonicalCidr::V4(
                Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc633_6407_u32), 32)
                    .expect("valid test CIDR")
            )]
        );
    }

    #[test]
    fn selected_mode_cache_compatibility_ignores_order_case_and_duplicates() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"api":["192.30.252.0/22"],"hooks":["198.51.100.7"]}"#,
        )
        .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "HOOKS".to_string(),
                    " api ".to_string(),
                    "hooks".to_string(),
                ],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["api".to_string(), "hooks".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::FallbackCache);
        assert_eq!(
            result.networks,
            vec![
                CanonicalCidr::V4(
                    Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc01e_fc00_u32), 22)
                        .expect("valid test CIDR")
                ),
                CanonicalCidr::V4(
                    Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc633_6407_u32), 32)
                        .expect("valid test CIDR")
                ),
            ]
        );
    }

    #[test]
    fn filtered_mode_refuses_cache_without_compatible_sidecar() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"api":["192.30.252.0/22"],"actions":["203.0.114.0/24"]}"#,
        )
        .expect("write raw cache");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Empty);
        assert!(result.networks.is_empty());
    }

    #[test]
    fn selected_mode_refuses_cache_for_superset_request() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"hooks":["10.0.0.0/24"],"packages":["203.0.113.0/24"]}"#,
        )
        .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec!["hooks".to_string()],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["hooks".to_string(), "packages".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Empty);
        assert!(result.networks.is_empty());
    }

    #[test]
    fn selected_mode_dedupes_duplicate_networks_across_categories() {
        let temp = TempDir::new().expect("tempdir");
        let client = MockHttpClient::new(vec![Ok(network_response(
            br#"{
                "api": ["192.30.252.0/22", "198.51.100.7"],
                "hooks": ["192.30.252.0/22", "198.51.100.7"]
            }"#,
        ))]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Explicit(vec!["hooks".to_string(), "api".to_string()]),
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Network);
        assert_eq!(
            result.networks,
            vec![
                CanonicalCidr::V4(
                    Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc01e_fc00_u32), 22)
                        .expect("valid test CIDR")
                ),
                CanonicalCidr::V4(
                    Ipv4Cidr::new(std::net::Ipv4Addr::from(0xc633_6407_u32), 32)
                        .expect("valid test CIDR")
                ),
            ]
        );
    }

    #[test]
    fn status_304_uses_cache_when_compatible() {
        let temp = TempDir::new().expect("tempdir");
        let raw = br#"{"api":["192.30.252.0/22"],"git":[],"hooks":[],"packages":[]}"#;

        fs::write(temp.path().join(GITHUB_META_RAW_CACHE_FILE), raw).expect("write raw cache");

        fs::write(
            temp.path().join(GITHUB_META_META_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCacheMetadata {
                url: TEST_GITHUB_META_URL.to_string(),
                etag: Some("etag-1".to_string()),
                last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
                sha256_raw: sha256_hex(raw),
            })
            .expect("meta json"),
        )
        .expect("write metadata");

        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "api".to_string(),
                    "git".to_string(),
                    "hooks".to_string(),
                    "packages".to_string(),
                ],
            })
            .expect("sidecar json"),
        )
        .expect("write sidecar");

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::NOT_MODIFIED,
            body: Vec::new(),
            etag: None,
            last_modified: None,
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");
        assert_eq!(result.source, GithubMetaSource::CacheNotModified);

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
        let client = MockHttpClient::new(vec![
            Ok(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                body: Vec::new(),
                etag: None,
                last_modified: None,
            }),
            Ok(network_response(
                br#"{"api":["192.30.252.0/22"],"git":[],"hooks":[],"packages":[]}"#,
            )),
        ]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Network);

        let requests = client.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].if_none_match, None);
        assert_eq!(requests[1].if_modified_since, None);
    }

    #[test]
    fn raw_hash_mismatch_blocks_cached_fallback() {
        let temp = TempDir::new().expect("tempdir");
        fs::write(
            temp.path().join(GITHUB_META_RAW_CACHE_FILE),
            br#"{"api":["192.30.252.0/22"]}"#,
        )
        .expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_META_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCacheMetadata {
                url: TEST_GITHUB_META_URL.to_string(),
                etag: Some("etag-1".to_string()),
                last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
                sha256_raw: sha256_hex(br#"{"hooks":["10.0.0.0/24"]}"#),
            })
            .expect("meta json"),
        )
        .expect("write metadata");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = load_github_meta_safelist(
            &client,
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::All,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Empty);
        assert!(result.networks.is_empty());
    }

    #[test]
    fn fixed_envelope_rejects_universal_broad_coverage_and_count_cases() {
        let selection = CategorySelection::All;
        for raw in [
            br#"{"ranges":["0.0.0.0/0"]}"#.as_slice(),
            br#"{"ranges":["::/0"]}"#.as_slice(),
            br#"{"ranges":["0.0.0.0/1","128.0.0.0/1"]}"#.as_slice(),
            br#"{"ranges":["2001:db8::/15"]}"#.as_slice(),
        ] {
            assert!(parse_and_extract_networks(raw, &selection).is_none());
        }

        let mut coverage_ranges = String::new();
        for octet in 0..17 {
            if octet > 0 {
                coverage_ranges.push(',');
            }
            write!(coverage_ranges, "\"{octet}.0.0.0/8\"").expect("write coverage fixture");
        }
        let excessive_coverage = format!("{{\"ranges\":[{coverage_ranges}]}}");
        assert!(parse_and_extract_networks(excessive_coverage.as_bytes(), &selection).is_none());

        let mut count_ranges = String::new();
        for index in 0..4_097 {
            if index > 0 {
                count_ranges.push(',');
            }
            write!(
                count_ranges,
                "\"198.18.{}.{}\"",
                (index / 256) % 256,
                index % 256
            )
            .expect("write count fixture");
        }
        let excessive_count = format!("{{\"ranges\":[{count_ranges}]}}");
        assert!(parse_and_extract_networks(excessive_count.as_bytes(), &selection).is_none());
    }

    #[test]
    fn fixed_envelope_accepts_exact_coverage_boundary() {
        let mut ranges = String::new();
        for octet in 0..16 {
            if octet > 0 {
                ranges.push(',');
            }
            write!(ranges, "\"{octet}.0.0.0/8\"").expect("write boundary fixture");
        }
        let raw = format!("{{\"ranges\":[{ranges}]}}");

        let networks = parse_and_extract_networks(raw.as_bytes(), &CategorySelection::All)
            .expect("one-sixteenth coverage is permitted");
        assert_eq!(networks.len(), 16);
    }

    #[test]
    fn poisoned_legacy_cache_is_ignored_under_the_fixed_envelope() {
        let temp = TempDir::new().expect("tempdir");
        let raw = br#"{"api":["0.0.0.0/0"]}"#;
        fs::write(temp.path().join(GITHUB_META_RAW_CACHE_FILE), raw).expect("write raw cache");
        fs::write(
            temp.path().join(GITHUB_META_META_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCacheMetadata {
                url: TEST_GITHUB_META_URL.to_string(),
                etag: None,
                last_modified: None,
                sha256_raw: sha256_hex(raw),
            })
            .expect("metadata"),
        )
        .expect("write metadata");

        fs::write(
            temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
            serde_json::to_vec_pretty(&GithubMetaCategorySidecar {
                mode: "selected".to_string(),
                categories: vec![
                    "api".to_string(),
                    "git".to_string(),
                    "hooks".to_string(),
                    "packages".to_string(),
                ],
            })
            .expect("sidecar"),
        )
        .expect("write sidecar");

        let result = load_github_meta_safelist(
            &MockHttpClient::new(vec![Err(HttpClientError::Request {
                reason: "offline".to_string(),
            })]),
            temp.path(),
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::Empty);
        assert!(result.networks.is_empty());
    }
}
