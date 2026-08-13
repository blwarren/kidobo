//! Bounded HTTP and remote-feed cache adapter.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::Duration;

use log::warn;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, USER_AGENT};
use reqwest::{StatusCode, Url, redirect};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::cached_fetch::{
    read_optional_json_lossy, write_bytes_atomic_in_cache, write_json_pretty_atomic,
};
use crate::hash::sha256_hex;
use crate::http_fetch::{ConditionalFetchResult, fetch_with_conditional_cache};
use crate::limited_io::{read_to_end_with_limit, read_to_string_with_limit, write_string_atomic};
use crate::remote_parse::{format_normalized_cidrs, parse_cached_iplist, parse_remote_cidrs};
use kidobo_core::network::CanonicalCidr;

pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const ENV_KIDOBO_MAX_HTTP_BODY_BYTES: &str = "KIDOBO_MAX_HTTP_BODY_BYTES";
pub const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(DEFAULT_HTTP_REQUEST_TIMEOUT_SECS);
const MAX_HTTP_REDIRECTS: usize = 10;
const MAX_IPLIST_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_METADATA_READ_BYTES: usize = 512 * 1024;
static RUSTLS_PROVIDER_INIT: Once = Once::new();

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePaths {
    pub iplist_path: PathBuf,
    pub meta_path: PathBuf,
    pub raw_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCacheMetadata {
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256_raw: String,
    pub sha256_iplist: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    Network,
    CacheNotModified,
    FallbackCache,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedIplist {
    pub networks: Vec<CanonicalCidr>,
    pub source: CacheSource,
    pub metadata: Option<RemoteCacheMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub if_none_match: Option<String>,
    pub if_modified_since: Option<String>,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HttpClientError {
    #[error("http client initialization failed: {reason}")]
    Initialization { reason: String },

    #[error("http client request failed: {reason}")]
    Request { reason: String },
}

pub trait HttpClient {
    /// Fetches one response while enforcing the request's body-size bound.
    ///
    /// # Errors
    ///
    /// Returns [`HttpClientError`] when client initialization, the request, response headers, or
    /// the bounded body read fails.
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError>;
}

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
    pub fn with_timeout(request_timeout: Duration) -> Self {
        Self::new_with_timeout(default_user_agent(), request_timeout)
    }

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
        let body = read_response_body_capped(&mut response, request.max_body_bytes)?;

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

#[derive(Debug, Error)]
pub enum HttpCacheError {
    #[error("failed to write iplist cache {path}: {reason}")]
    WriteIplist { path: PathBuf, reason: String },

    #[error("failed to write metadata cache {path}: {reason}")]
    WriteMetadata { path: PathBuf, reason: String },

    #[error("failed to write raw cache {path}: {reason}")]
    WriteRaw { path: PathBuf, reason: String },

    #[error("failed to read iplist cache {path}: {reason}")]
    ReadIplist { path: PathBuf, reason: String },
}

#[must_use]
pub fn url_hash_prefix(url: &str) -> String {
    sha256_hex(url.as_bytes())[..16].to_string()
}

#[must_use]
pub fn cache_paths_for_url(cache_dir: &Path, url: &str) -> CachePaths {
    let hash = url_hash_prefix(url);
    CachePaths {
        iplist_path: cache_dir.join(format!("{hash}.iplist")),
        meta_path: cache_dir.join(format!("{hash}.meta.json")),
        raw_path: cache_dir.join(format!("{hash}.raw")),
    }
}

#[must_use]
pub fn max_http_body_bytes(env: &BTreeMap<String, String>) -> usize {
    env.get(ENV_KIDOBO_MAX_HTTP_BODY_BYTES)
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_HTTP_BODY_BYTES)
}

#[cfg(test)]
#[must_use]
pub fn normalize_remote_text(raw: &[u8]) -> String {
    format_normalized_cidrs(&parse_remote_cidrs(raw).networks)
}

/// Fetches and validates a remote feed with conditional, atomic cache fallback.
///
/// # Errors
///
/// Returns [`HttpCacheError`] when required cache data cannot be read or a valid network response
/// cannot be persisted. Network and invalid-response failures retain usable cached data.
pub fn fetch_iplist_with_cache(
    client: &dyn HttpClient,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Result<CachedIplist, HttpCacheError> {
    let max_bytes = max_http_body_bytes(env);
    let cache_paths = cache_paths_for_url(cache_dir, url);

    let cached_meta = read_optional_metadata_lossy(&cache_paths);
    let cached_networks = read_optional_iplist_networks(&cache_paths, cached_meta.as_ref())?;
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
                Ok(CachedIplist {
                    networks,
                    source: CacheSource::CacheNotModified,
                    metadata: cached_meta,
                })
            } else {
                Ok(CachedIplist {
                    networks: Vec::new(),
                    source: CacheSource::Empty,
                    metadata: None,
                })
            }
        }
        ConditionalFetchResult::FallbackCache => Ok(cache_fallback(cached_networks, cached_meta)),
        ConditionalFetchResult::Network(response) => handle_network_response(
            response,
            url,
            &cache_paths,
            max_bytes,
            cached_networks,
            cached_meta,
        ),
    }
}

fn handle_network_response(
    response: HttpResponse,
    url: &str,
    cache_paths: &CachePaths,
    max_bytes: usize,
    cached_networks: Option<Vec<CanonicalCidr>>,
    cached_meta: Option<RemoteCacheMetadata>,
) -> Result<CachedIplist, HttpCacheError> {
    if !response.status.is_success() {
        warn!(
            "remote fetch failed for {url}: unexpected status {}",
            response.status
        );
        return Ok(cache_fallback(cached_networks, cached_meta));
    }

    if response.body.len() > max_bytes {
        warn!(
            "remote fetch failed for {url}: body size {} exceeds max {} bytes",
            response.body.len(),
            max_bytes
        );
        return Ok(cache_fallback(cached_networks, cached_meta));
    }

    let parsed = parse_remote_cidrs(&response.body);
    if parsed.data_lines > 0 && parsed.networks.is_empty() {
        warn!(
            "remote fetch failed for {url}: non-empty response contained no valid IP/CIDR entries"
        );
        return Ok(cache_fallback(cached_networks, cached_meta));
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

    persist_cache(cache_paths, &normalized, &response.body, &metadata)?;

    Ok(CachedIplist {
        networks,
        source: CacheSource::Network,
        metadata: Some(metadata),
    })
}

fn persist_cache(
    paths: &CachePaths,
    iplist: &str,
    raw: &[u8],
    meta: &RemoteCacheMetadata,
) -> Result<(), HttpCacheError> {
    write_bytes_atomic_in_cache(&paths.raw_path, raw).map_err(|err| HttpCacheError::WriteRaw {
        path: paths.raw_path.clone(),
        reason: err.to_string(),
    })?;

    write_string_atomic(&paths.iplist_path, iplist).map_err(|err| HttpCacheError::WriteIplist {
        path: paths.iplist_path.clone(),
        reason: err.to_string(),
    })?;

    write_json_pretty_atomic(&paths.meta_path, meta).map_err(|err| {
        HttpCacheError::WriteMetadata {
            path: paths.meta_path.clone(),
            reason: err.to_string(),
        }
    })?;

    Ok(())
}

fn read_optional_iplist_networks(
    paths: &CachePaths,
    metadata: Option<&RemoteCacheMetadata>,
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

    Ok(Some(parse_cached_iplist(&iplist)))
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
    use std::fs;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::path::{Path, PathBuf};
    use std::thread;
    use std::time::Duration;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        CacheSource, HttpClient, HttpClientError, HttpRequest, HttpResponse, MAX_HTTP_REDIRECTS,
        RemoteCacheMetadata, ReqwestHttpClient, cache_paths_for_url, fetch_iplist_with_cache,
        has_same_http_origin, max_http_body_bytes, normalize_remote_text, url_hash_prefix,
    };
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
        env.insert(
            "KIDOBO_MAX_HTTP_BODY_BYTES".to_string(),
            "12345".to_string(),
        );
        assert_eq!(max_http_body_bytes(&env), 12345);

        env.insert(
            "KIDOBO_MAX_HTTP_BODY_BYTES".to_string(),
            "invalid".to_string(),
        );
        assert_eq!(
            max_http_body_bytes(&env),
            super::DEFAULT_MAX_HTTP_BODY_BYTES
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
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read cache"),
            "161.117.138.100/32"
        );
        assert_eq!(
            read_bytes_with_limit(&paths.raw_path, super::DEFAULT_MAX_HTTP_BODY_BYTES)
                .expect("read raw"),
            body
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

        let paths = cache_paths_for_url(cache_dir, url);
        assert!(paths.iplist_path.exists());
        assert!(paths.meta_path.exists());
        assert!(paths.raw_path.exists());
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
        let paths = cache_paths_for_url(cache_dir, url);

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

        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read iplist"),
            "10.0.0.5/32\n2001:db8::1/128"
        );
        assert_eq!(
            read_bytes_with_limit(&paths.raw_path, super::DEFAULT_MAX_HTTP_BODY_BYTES)
                .expect("read raw"),
            body
        );

        let metadata: RemoteCacheMetadata = serde_json::from_slice(
            &read_bytes_with_limit(&paths.meta_path, super::MAX_METADATA_READ_BYTES)
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
        let paths = cache_paths_for_url(temp.path(), url);
        let body = b"# intentionally empty\n\n";
        let client = MockHttpClient::new(vec![Ok(network_response_for_test(body))]);

        let result =
            fetch_iplist_with_cache(&client, url, temp.path(), &BTreeMap::new()).expect("fetch");

        assert_eq!(result.source, CacheSource::Network);
        assert!(result.networks.is_empty());
        assert_eq!(
            read_to_string_with_limit(&paths.iplist_path, super::MAX_IPLIST_READ_BYTES)
                .expect("read"),
            ""
        );
        assert_eq!(
            read_bytes_with_limit(&paths.raw_path, super::DEFAULT_MAX_HTTP_BODY_BYTES)
                .expect("read raw"),
            body
        );
        assert!(paths.meta_path.exists());
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
        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".to_string(), "1".to_string());

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
        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".to_string(), "1".to_string());

        let result = fetch_iplist_with_cache(&client, url, cache_dir, &env).expect("fetch");
        assert_eq!(result.source, CacheSource::Empty);
        assert!(result.networks.is_empty());
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
