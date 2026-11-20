//! Bounded HTTP transport with same-origin redirects.

use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::sync::Once;
use std::time::{Duration, Instant};

use reqwest::header::{
    ETAG, HeaderValue, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED, LOCATION, REFERER,
    USER_AGENT,
};
use reqwest::{StatusCode, Url, redirect};
use thiserror::Error;

use crate::hash::sha256_hex;
use crate::limited_io::read_to_end_with_limit;

/// Default maximum accepted HTTP response body size.
pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 16 * 1024 * 1024;
/// Hard ceiling for the HTTP response body environment override.
pub const MAX_HTTP_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Environment variable that overrides the maximum HTTP body size when valid Unicode and positive.
pub const ENV_KIDOBO_MAX_HTTP_BODY_BYTES: &str = "KIDOBO_MAX_HTTP_BODY_BYTES";
/// Default timeout for one HTTP request.
pub const DEFAULT_HTTP_REQUEST_TIMEOUT_SECS: u64 = 30;
const DEFAULT_HTTP_REQUEST_TIMEOUT: Duration =
    Duration::from_secs(DEFAULT_HTTP_REQUEST_TIMEOUT_SECS);
const MAX_HTTP_REDIRECTS: usize = 10;
static RUSTLS_PROVIDER_INIT: Once = Once::new();

/// One bounded conditional HTTP request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// Absolute HTTP or HTTPS URL.
    pub url: String,
    /// Optional `If-None-Match` validator.
    pub if_none_match: Option<String>,
    /// Optional `If-Modified-Since` validator.
    pub if_modified_since: Option<String>,
    /// SHA-256 of the resource URL to which the validators belong.
    pub validator_scope: Option<String>,
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
    /// SHA-256 of the resource URL that returned this response.
    pub validator_scope: Option<String>,
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
            .redirect(redirect::Policy::none())
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
        let start = Instant::now();
        let initial = client
            .get(&request.url)
            .header(USER_AGENT, &self.user_agent)
            .build()
            .map_err(|error| request_error(error.without_url().to_string()))?;
        let mut url = initial.url().clone();
        let mut referer: Option<HeaderValue> = None;
        for hops in 0..=MAX_HTTP_REDIRECTS {
            let mut outgoing = initial
                .try_clone()
                .ok_or_else(|| request_error("cannot clone a bodyless HTTP request"))?;
            *outgoing.url_mut() = url.clone();
            *outgoing.timeout_mut() = Some(
                self.request_timeout
                    .checked_sub(start.elapsed())
                    .ok_or_else(|| request_error("request timed out"))?,
            );
            if let Some(value) = referer.take() {
                outgoing.headers_mut().insert(REFERER, value);
            }
            let scope = validator_scope(&url);
            if request.validator_scope.as_deref() == Some(scope.as_str()) {
                for (name, value) in [
                    (IF_NONE_MATCH, request.if_none_match.as_deref()),
                    (IF_MODIFIED_SINCE, request.if_modified_since.as_deref()),
                ] {
                    if let Some(value) = value {
                        outgoing.headers_mut().insert(
                            name,
                            value
                                .parse::<HeaderValue>()
                                .map_err(|error| request_error(error.to_string()))?,
                        );
                    }
                }
            }

            let mut response = client
                .execute(outgoing)
                .map_err(|error| request_error(error.without_url().to_string()))?;
            if let Some(mut next_url) = redirect_target(&response, &url)? {
                if !has_same_http_origin(initial.url(), &next_url) {
                    return Err(request_error("redirect target has a different origin"));
                }
                if hops == MAX_HTTP_REDIRECTS {
                    return Err(request_error("too many redirects"));
                }
                next_url
                    .set_username("")
                    .and_then(|()| next_url.set_password(None))
                    .map_err(|()| request_error("invalid redirect authority"))?;
                url.set_fragment(None);
                referer = url.as_str().parse().ok();
                url = next_url;
                continue;
            }

            let status = response.status();
            let headers = response.headers().clone();
            let body = if status == StatusCode::OK {
                if response.content_length().is_some_and(|length| {
                    length > u64::try_from(request.max_body_bytes).unwrap_or(u64::MAX)
                }) {
                    return Err(request_error(format!(
                        "response body exceeds max {} bytes",
                        request.max_body_bytes
                    )));
                }
                read_response_body_capped(&mut response, request.max_body_bytes)?
            } else {
                Vec::new()
            };
            return Ok(HttpResponse {
                status,
                body,
                validator_scope: Some(scope),
                etag: header_to_string(&headers, ETAG),
                last_modified: header_to_string(&headers, LAST_MODIFIED),
            });
        }
        Err(request_error("too many redirects"))
    }
}

fn request_error(reason: impl Into<String>) -> HttpClientError {
    HttpClientError::Request {
        reason: reason.into(),
    }
}

fn redirect_target(
    response: &reqwest::blocking::Response,
    url: &Url,
) -> Result<Option<Url>, HttpClientError> {
    if !matches!(
        response.status(),
        StatusCode::MOVED_PERMANENTLY
            | StatusCode::FOUND
            | StatusCode::SEE_OTHER
            | StatusCode::TEMPORARY_REDIRECT
            | StatusCode::PERMANENT_REDIRECT
    ) {
        return Ok(None);
    }
    response
        .headers()
        .get(LOCATION)
        .map(|location| {
            let target = location
                .to_str()
                .map_err(|error| request_error(error.to_string()))?;
            url.join(target)
                .map_err(|error| request_error(error.to_string()))
        })
        .transpose()
}

fn validator_scope(url: &Url) -> String {
    let mut resource = url.clone();
    resource.set_fragment(None);
    sha256_hex(resource.as_str().as_bytes())
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
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc::{self, RecvTimeoutError};
    use std::thread;
    use std::time::Duration;

    use reqwest::{StatusCode, Url};

    use super::test_support::CrossOriginRedirectFixture;
    use super::{
        DEFAULT_MAX_HTTP_BODY_BYTES, ENV_KIDOBO_MAX_HTTP_BODY_BYTES, HttpClient, HttpClientError,
        HttpRequest, MAX_HTTP_BODY_BYTES, ReqwestHttpClient, has_same_http_origin,
        max_http_body_bytes,
    };

    fn fetch_same_origin_redirect_chain(
        redirect_count: usize,
    ) -> (Result<super::HttpResponse, HttpClientError>, usize) {
        use std::io::{BufRead, BufReader};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let (stop, stopped) = mpsc::channel();
        let server = thread::spawn(move || {
            let mut requests = 0;
            let mut stopping = false;
            loop {
                let mut socket = match listener.accept() {
                    Ok((socket, _)) => socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopping {
                            break;
                        }
                        stopping = !matches!(
                            stopped.recv_timeout(Duration::from_millis(5)),
                            Err(RecvTimeoutError::Timeout)
                        );
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                socket
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("write timeout");
                let mut request_line = String::new();
                BufReader::new((&socket).take(4096))
                    .read_line(&mut request_line)
                    .expect("read redirect request line");
                let expected_path = if requests == 0 {
                    "/start".to_owned()
                } else {
                    format!("/redirect-{requests}")
                };
                assert_eq!(
                    request_line.split_whitespace().nth(1),
                    Some(expected_path.as_str())
                );
                requests += 1;
                let response = if requests > redirect_count {
                    "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
                } else {
                    format!(
                        "HTTP/1.1 302 Found\r\nLocation: /redirect-{requests}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                };
                socket
                    .write_all(response.as_bytes())
                    .expect("write response");
            }
            requests
        });
        let result = ReqwestHttpClient::with_timeout(Duration::from_secs(2)).fetch(HttpRequest {
            validator_scope: None,
            url: format!("http://{addr}/start"),
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes: 1024,
        });
        stop.send(()).expect("stop server thread");
        (result, server.join().expect("server thread"))
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
                validator_scope: None,
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
    fn reqwest_http_client_bounds_body_without_content_length() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let server = thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "accept timed out");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("read timeout");
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("write timeout");
            let mut request = [0_u8; 1024];
            let _ = socket.read(&mut request).expect("read request");
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n0123456789")
                .expect("write response without content length");
        });
        let result = ReqwestHttpClient::with_timeout(Duration::from_secs(2)).fetch(HttpRequest {
            validator_scope: None,
            url: format!("http://{addr}/feed"),
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes: 4,
        });
        server.join().expect("server thread");
        let HttpClientError::Request { reason } =
            result.expect_err("streaming limit must reject body")
        else {
            panic!("expected request error");
        };
        assert_eq!(reason, "response body exceeds max 4 bytes");
    }

    #[test]
    fn redirect_sends_validators_only_to_the_cached_resource() {
        use std::io::{BufRead, BufReader};

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let alias = format!("http://{addr}/feed");
        let cached = Url::parse(&format!("http://{addr}/current")).expect("cached resource URL");
        let replacement =
            Url::parse(&format!("http://{addr}/replacement")).expect("replacement resource URL");
        let server = thread::spawn(move || {
            for (request_path, conditional, response) in [
                ("/feed", false, "302 Found\r\nLocation: /current"),
                ("/current", true, "304 Not Modified"),
                ("/feed", false, "302 Found\r\nLocation: /replacement"),
                ("/replacement", false, "200 OK"),
            ] {
                let (mut socket, _) = listener.accept().expect("accept");
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                let mut request = String::new();
                let mut stream = BufReader::new(&mut socket);
                loop {
                    let mut line = String::new();
                    assert_ne!(stream.read_line(&mut line).expect("request header"), 0);
                    if line == "\r\n" {
                        break;
                    }
                    request.push_str(&line);
                }
                let request = request.to_ascii_lowercase();
                assert!(request.starts_with(&format!("get {request_path} ")));
                assert_eq!(request.contains("if-none-match: \"shared\""), conditional);
                assert_eq!(request.contains("if-modified-since: "), conditional);
                let reply = format!(
                    "HTTP/1.1 {response}\r\nETag: \"shared\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                socket.write_all(reply.as_bytes()).expect("response");
            }
        });

        let scope = super::validator_scope(&cached);
        let request = HttpRequest {
            url: alias,
            if_none_match: Some(r#""shared""#.into()),
            if_modified_since: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
            validator_scope: Some(scope.clone()),
            max_body_bytes: 1024,
        };
        let client = ReqwestHttpClient::with_timeout(Duration::from_secs(2));
        let unchanged = client.fetch(request.clone()).expect("same redirect target");
        assert_eq!(unchanged.status, StatusCode::NOT_MODIFIED);
        assert_eq!(unchanged.validator_scope.as_deref(), Some(scope.as_str()));
        let changed = client.fetch(request).expect("changed redirect target");
        assert_eq!(changed.status, StatusCode::OK);
        assert_eq!(
            changed.validator_scope,
            Some(super::validator_scope(&replacement))
        );
        server.join().expect("redirect fixture");
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
                validator_scope: None,
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
            validator_scope: None,
            url: fixture.source_url().to_string(),
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes: 1024,
        });

        fixture.finish();
        assert!(result.is_err(), "cross-origin redirect should fail");
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
        let (result, requests) = fetch_same_origin_redirect_chain(10);
        assert_eq!(
            result.expect("ten redirects should succeed").status,
            StatusCode::OK
        );
        assert_eq!(requests, 11);
    }

    #[test]
    fn reqwest_http_client_rejects_eleventh_same_origin_redirect() {
        let (result, requests) = fetch_same_origin_redirect_chain(11);
        assert_eq!(
            requests, 11,
            "the final redirect target must not be contacted"
        );
        assert_eq!(
            result.expect_err("eleventh redirect should fail"),
            HttpClientError::Request {
                reason: "too many redirects".to_string(),
            }
        );
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
                validator_scope: None,
                url: "https://example.com/feed".to_string(),
                if_none_match: None,
                if_modified_since: None,
                max_body_bytes: 1024,
            })
            .expect_err("stored initialization error should be returned");

        assert_eq!(error, expected);
    }
}
