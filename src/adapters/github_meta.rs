use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use log::warn;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

use crate::adapters::cached_fetch::{
    CachedFetchRequest, read_optional_json_lossy, read_validated_bytes_lossy, run_cached_fetch,
    write_bytes_atomic_in_cache, write_json_pretty_atomic,
};
use crate::adapters::hash::sha256_hex;
use crate::adapters::http_cache::{HttpClient, HttpResponse, max_http_body_bytes};
use crate::core::config::{DEFAULT_GITHUB_META_CATEGORIES, GithubMetaCategoryMode};
use crate::core::network::{CanonicalCidr, parse_ip_cidr_non_strict};

const GITHUB_META_RAW_CACHE_FILE: &str = "github-meta.raw.json";
const GITHUB_META_META_CACHE_FILE: &str = "github-meta.meta.json";
const GITHUB_META_CATEGORY_CACHE_FILE: &str = "github-meta.categories.json";

const GITHUB_META_CACHE_READ_LIMIT: usize = 8 * 1024 * 1024;
const GITHUB_META_META_READ_LIMIT: usize = 512 * 1024;
const GITHUB_META_CATEGORY_READ_LIMIT: usize = 256 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubMetaCacheMetadata {
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256_raw: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GithubMetaCategorySidecar {
    pub mode: String,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GithubMetaSource {
    Network,
    CacheNotModified,
    FallbackCache,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GithubMetaLoadResult {
    pub networks: Vec<CanonicalCidr>,
    pub source: GithubMetaSource,
    pub metadata: Option<GithubMetaCacheMetadata>,
}

#[derive(Debug, Error)]
pub enum GithubMetaLoadError {
    #[error("failed to write github meta cache file {path}: {reason}")]
    WriteCacheFile { path: PathBuf, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CategorySelection {
    All,
    Selected(Vec<String>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CachePaths {
    raw_path: PathBuf,
    meta_path: PathBuf,
    category_path: PathBuf,
}

#[derive(Debug, Clone)]
struct CachedFallback<'a> {
    raw: Option<&'a [u8]>,
    networks: Option<Vec<CanonicalCidr>>,
    meta: Option<GithubMetaCacheMetadata>,
    sidecar: Option<&'a GithubMetaCategorySidecar>,
}

#[derive(Debug, Clone)]
struct GithubMetaCache {
    raw: Option<Vec<u8>>,
    networks: Option<Vec<CanonicalCidr>>,
    meta: Option<GithubMetaCacheMetadata>,
    sidecar: Option<GithubMetaCategorySidecar>,
}

impl CachePaths {
    fn from_cache_dir(cache_dir: &Path) -> Self {
        Self {
            raw_path: cache_dir.join(GITHUB_META_RAW_CACHE_FILE),
            meta_path: cache_dir.join(GITHUB_META_META_CACHE_FILE),
            category_path: cache_dir.join(GITHUB_META_CATEGORY_CACHE_FILE),
        }
    }
}

pub fn load_github_meta_safelist(
    client: &dyn HttpClient,
    cache_dir: &Path,
    github_meta_url: &str,
    category_mode: &GithubMetaCategoryMode,
    env: &BTreeMap<String, String>,
) -> Result<GithubMetaLoadResult, GithubMetaLoadError> {
    let selection = CategorySelection::from_mode(category_mode);
    let max_bytes = max_http_body_bytes(env);
    let paths = CachePaths::from_cache_dir(cache_dir);
    let cache = read_github_meta_cache(&paths, &selection, github_meta_url);
    let (cached_etag, cached_last_modified) = cache.http_validators();

    run_cached_fetch(
        CachedFetchRequest {
            client,
            url: github_meta_url,
            max_body_bytes: max_bytes,
            cached_etag,
            cached_last_modified,
            has_usable_cache: cache.networks.is_some(),
            log_subject: "github meta",
            missing_response_warning: "github meta fetch returned network outcome without response",
        },
        || {
            if let Some(networks) = cache.networks.clone() {
                return Ok(GithubMetaLoadResult {
                    networks,
                    source: GithubMetaSource::CacheNotModified,
                    metadata: cache.meta.clone(),
                });
            }

            Ok::<GithubMetaLoadResult, GithubMetaLoadError>(cache.fallback(
                None,
                &selection,
                GithubMetaSource::FallbackCache,
            ))
        },
        || {
            Ok(cache.fallback(
                cache.networks.clone(),
                &selection,
                GithubMetaSource::FallbackCache,
            ))
        },
        |response| {
            handle_network_response(
                response,
                &paths,
                github_meta_url,
                max_bytes,
                cache.as_fallback(),
                &selection,
            )
        },
    )
}

fn read_github_meta_cache(
    paths: &CachePaths,
    selection: &CategorySelection,
    github_meta_url: &str,
) -> GithubMetaCache {
    let cached_meta = read_optional_json_lossy::<GithubMetaCacheMetadata>(
        &paths.meta_path,
        GITHUB_META_META_READ_LIMIT,
        "github meta cache file",
    );
    let cache_url_matches = cached_meta
        .as_ref()
        .is_none_or(|meta| github_meta_cache_url_matches(meta, github_meta_url));
    if !cache_url_matches {
        warn!("github meta cache URL differs from configured URL; ignoring stale cache");
    }

    let meta = if cache_url_matches { cached_meta } else { None };
    let raw = if cache_url_matches {
        read_validated_bytes_lossy(
            &paths.raw_path,
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
            &paths.category_path,
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
        }
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
) -> Result<GithubMetaLoadResult, GithubMetaLoadError> {
    if !response.status.is_success() {
        warn!(
            "github meta fetch failed: unexpected status {}",
            response.status
        );
        return Ok(cache_fallback(
            cached.raw,
            cached.networks,
            cached.meta,
            cached.sidecar,
            selection,
            GithubMetaSource::FallbackCache,
        ));
    }

    if response.body.len() > max_bytes {
        warn!(
            "github meta fetch failed: body size {} exceeds max {} bytes",
            response.body.len(),
            max_bytes
        );
        return Ok(cache_fallback(
            cached.raw,
            cached.networks,
            cached.meta,
            cached.sidecar,
            selection,
            GithubMetaSource::FallbackCache,
        ));
    }

    let Some(networks) = parse_and_extract_networks(&response.body, selection) else {
        warn!("github meta fetch failed: response body is not valid JSON");
        return Ok(cache_fallback(
            cached.raw,
            cached.networks,
            cached.meta,
            cached.sidecar,
            selection,
            GithubMetaSource::FallbackCache,
        ));
    };

    let metadata = GithubMetaCacheMetadata {
        url: github_meta_url.to_string(),
        etag: response.etag,
        last_modified: response.last_modified,
        sha256_raw: sha256_hex(&response.body),
    };

    persist_cache(paths, &response.body, &metadata, selection)?;

    Ok(GithubMetaLoadResult {
        networks,
        source: GithubMetaSource::Network,
        metadata: Some(metadata),
    })
}

fn persist_cache(
    paths: &CachePaths,
    raw: &[u8],
    metadata: &GithubMetaCacheMetadata,
    selection: &CategorySelection,
) -> Result<(), GithubMetaLoadError> {
    write_bytes_atomic_in_cache(&paths.raw_path, raw).map_err(|err| {
        GithubMetaLoadError::WriteCacheFile {
            path: paths.raw_path.clone(),
            reason: err.to_string(),
        }
    })?;

    let sidecar = selection.to_sidecar();
    write_json_pretty_atomic(&paths.category_path, &sidecar).map_err(|err| {
        GithubMetaLoadError::WriteCacheFile {
            path: paths.category_path.clone(),
            reason: err.to_string(),
        }
    })?;

    write_json_pretty_atomic(&paths.meta_path, metadata).map_err(|err| {
        GithubMetaLoadError::WriteCacheFile {
            path: paths.meta_path.clone(),
            reason: err.to_string(),
        }
    })?;

    Ok(())
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

    let networks = match cached_networks {
        Some(networks) => networks,
        None => {
            let Some(networks) = parse_and_extract_networks(raw, selection) else {
                warn!("github meta cache is invalid JSON; ignoring stale cache");
                return GithubMetaLoadResult {
                    networks: Vec::new(),
                    source: GithubMetaSource::Empty,
                    metadata: cached_meta,
                };
            };
            networks
        }
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
    Some(extract_networks(&value, selection))
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
    use std::fs;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        GITHUB_META_CATEGORY_CACHE_FILE, GITHUB_META_CATEGORY_READ_LIMIT,
        GITHUB_META_META_CACHE_FILE, GITHUB_META_META_READ_LIMIT, GITHUB_META_RAW_CACHE_FILE,
        GithubMetaCacheMetadata, GithubMetaCategorySidecar, GithubMetaLoadResult, GithubMetaSource,
        load_github_meta_safelist,
    };
    use crate::adapters::hash::sha256_hex;
    use crate::adapters::http_cache::{HttpClient, HttpClientError, HttpRequest, HttpResponse};
    use crate::adapters::limited_io::read_bytes_with_limit;
    use crate::core::config::GithubMetaCategoryMode;
    use crate::core::network::{CanonicalCidr, Ipv4Cidr, Ipv6Cidr};

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
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc01efc00, 22)),
        );
        assert_has(
            &result,
            CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000001,
                128,
            )),
        );
        assert!(
            !result
                .networks
                .contains(&CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb007200, 24)))
        );

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
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0x0a000000, 24))]
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
            CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc6336407, 32)),
        );
        assert_has(
            &result,
            CanonicalCidr::V6(Ipv6Cidr::from_parts(
                0x20010db8000000000000000000000000,
                126,
            )),
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

        let metadata: GithubMetaCacheMetadata = serde_json::from_slice(
            &read_bytes_with_limit(
                &temp.path().join(GITHUB_META_META_CACHE_FILE),
                GITHUB_META_META_READ_LIMIT,
            )
            .expect("read metadata"),
        )
        .expect("metadata json");
        assert_eq!(metadata.url, TEST_GITHUB_META_URL);

        let sidecar: GithubMetaCategorySidecar = serde_json::from_slice(
            &read_bytes_with_limit(
                &temp.path().join(GITHUB_META_CATEGORY_CACHE_FILE),
                GITHUB_META_CATEGORY_READ_LIMIT,
            )
            .expect("read sidecar"),
        )
        .expect("sidecar json");
        assert_eq!(sidecar.mode, "selected");
        assert_eq!(sidecar.categories, vec!["hooks".to_string()]);

        assert!(temp.path().join(GITHUB_META_RAW_CACHE_FILE).exists());
    }

    #[test]
    fn network_error_falls_back_to_compatible_cache() {
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
            TEST_GITHUB_META_URL,
            &GithubMetaCategoryMode::Default,
            &BTreeMap::new(),
        )
        .expect("load");

        assert_eq!(result.source, GithubMetaSource::FallbackCache);
        assert_eq!(result.networks.len(), 1);
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
            vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc6336407, 32))]
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
                CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc01efc00, 22)),
                CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc6336407, 32)),
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
                CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc01efc00, 22)),
                CanonicalCidr::V4(Ipv4Cidr::from_parts(0xc6336407, 32)),
            ]
        );
    }

    #[test]
    fn status_304_uses_cache_when_compatible() {
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
                sha256_raw: sha256_hex(br#"{"api":["192.30.252.0/22"]}"#),
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
            Ok(network_response(br#"{"api":["192.30.252.0/22"]}"#)),
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
}
