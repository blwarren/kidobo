//! Conditional HTTP fetch policy.

use log::warn;
use reqwest::StatusCode;

use crate::http_cache::{HttpClient, HttpRequest, HttpResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalFetchResult {
    Network(HttpResponse),
    CacheNotModified,
    FallbackCache,
}

pub fn fetch_with_conditional_cache(
    client: &dyn HttpClient,
    url: &str,
    max_body_bytes: usize,
    etag: Option<String>,
    last_modified: Option<String>,
    has_usable_cache: bool,
    log_subject: &str,
) -> ConditionalFetchResult {
    let conditional_request = HttpRequest {
        url: url.to_string(),
        if_none_match: etag,
        if_modified_since: last_modified,
        max_body_bytes,
    };

    let response = match client.fetch(conditional_request) {
        Ok(response) => response,
        Err(err) => {
            warn!("{log_subject} fetch failed for {url}: {err}");
            return ConditionalFetchResult::FallbackCache;
        }
    };

    if response.status != StatusCode::NOT_MODIFIED {
        return ConditionalFetchResult::Network(response);
    }

    if has_usable_cache {
        return ConditionalFetchResult::CacheNotModified;
    }

    let unconditional_request = HttpRequest {
        url: url.to_string(),
        if_none_match: None,
        if_modified_since: None,
        max_body_bytes,
    };

    match client.fetch(unconditional_request) {
        Ok(response) => ConditionalFetchResult::Network(response),
        Err(err) => {
            warn!("{log_subject} refetch failed for {url} after 304: {err}");
            ConditionalFetchResult::FallbackCache
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use reqwest::StatusCode;

    use super::{ConditionalFetchResult, fetch_with_conditional_cache};
    use crate::http_cache::{HttpClient, HttpClientError, HttpRequest, HttpResponse};

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

    fn unwrap_network_result(result: ConditionalFetchResult) -> HttpResponse {
        match result {
            ConditionalFetchResult::Network(response) => response,
            _ => panic!("response should exist"),
        }
    }

    #[test]
    fn returns_network_response_for_non_304_status() {
        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::OK,
            body: b"10.0.0.1".to_vec(),
            etag: None,
            last_modified: None,
        })]);

        let response = unwrap_network_result(fetch_with_conditional_cache(
            &client,
            "https://example.com/feed.txt",
            1024,
            None,
            None,
            false,
            "remote source",
        ));

        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(client.requests().len(), 1);
    }

    #[test]
    fn returns_cache_not_modified_for_304_with_usable_cache() {
        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::NOT_MODIFIED,
            body: Vec::new(),
            etag: None,
            last_modified: None,
        })]);

        let result = fetch_with_conditional_cache(
            &client,
            "https://example.com/feed.txt",
            1024,
            Some("etag-1".to_string()),
            Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            true,
            "remote source",
        );

        assert_eq!(result, ConditionalFetchResult::CacheNotModified);
        assert_eq!(client.requests().len(), 1);
    }

    #[test]
    fn refetches_unconditionally_for_304_without_cache() {
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
                etag: None,
                last_modified: None,
            }),
        ]);

        let response = unwrap_network_result(fetch_with_conditional_cache(
            &client,
            "https://example.com/feed.txt",
            1024,
            Some("etag-1".to_string()),
            Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            false,
            "remote source",
        ));

        assert_eq!(response.status, StatusCode::OK);

        let requests = client.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].if_none_match, None);
        assert_eq!(requests[1].if_modified_since, None);
    }

    #[test]
    fn falls_back_when_refetch_after_304_fails() {
        let client = MockHttpClient::new(vec![
            Ok(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                body: Vec::new(),
                etag: None,
                last_modified: None,
            }),
            Err(HttpClientError::Request {
                reason: "offline".to_string(),
            }),
        ]);

        let result = fetch_with_conditional_cache(
            &client,
            "https://example.com/feed.txt",
            1024,
            None,
            None,
            false,
            "remote source",
        );

        assert_eq!(result, ConditionalFetchResult::FallbackCache);
    }
}
