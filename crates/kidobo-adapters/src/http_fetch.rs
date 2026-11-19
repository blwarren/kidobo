//! Conditional HTTP fetch policy.

use log::warn;
use reqwest::StatusCode;

use crate::http_client::{HttpClient, HttpRequest, HttpResponse};

/// Policy result from conditional HTTP fetching with soft cache fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionalFetchResult {
    /// A response body that still requires domain validation.
    Network(HttpResponse),
    /// HTTP 304 with a usable validated cache.
    CacheNotModified,
    /// Request failure or partial response; caller should attempt cache fallback.
    FallbackCache,
}

/// Validators and cached data available for one source.
#[derive(Default)]
pub(crate) struct CachedHttpValidators {
    pub(crate) scope: Option<String>,
    pub(crate) etag: Option<String>,
    pub(crate) last_modified: Option<String>,
}

impl CachedHttpValidators {
    fn has_scoped_validator(&self) -> bool {
        self.scope.is_some() && (self.etag.is_some() || self.last_modified.is_some())
    }
}

/// Gets a complete response or reuses a validated body after a matching 304.
pub(crate) fn fetch_with_conditional_cache(
    client: &dyn HttpClient,
    url: &str,
    max_body_bytes: usize,
    validators: CachedHttpValidators,
    has_usable_cache: bool,
    log_subject: &str,
) -> ConditionalFetchResult {
    let conditional = has_usable_cache && validators.has_scoped_validator();
    let scope = validators.scope.filter(|_| conditional);
    let request = HttpRequest {
        url: url.to_string(),
        validator_scope: scope.clone(),
        if_none_match: validators.etag.filter(|_| conditional),
        if_modified_since: validators.last_modified.filter(|_| conditional),
        max_body_bytes,
    };
    let mut response = match client.fetch(request) {
        Ok(response) => response,
        Err(err) => {
            warn!("{log_subject} fetch failed for {url}: {err}");
            return ConditionalFetchResult::FallbackCache;
        }
    };

    if response.status == StatusCode::NOT_MODIFIED {
        if conditional && response.validator_scope == scope {
            return ConditionalFetchResult::CacheNotModified;
        }
        response = match client.fetch(HttpRequest {
            url: url.to_string(),
            validator_scope: None,
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes,
        }) {
            Ok(response) => response,
            Err(err) => {
                warn!("{log_subject} refetch failed for {url} after 304: {err}");
                return ConditionalFetchResult::FallbackCache;
            }
        };
    }

    if response.status == StatusCode::OK {
        ConditionalFetchResult::Network(response)
    } else {
        warn!(
            "{log_subject} fetch failed for {url}: unexpected status {}",
            response.status
        );
        ConditionalFetchResult::FallbackCache
    }
}
#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use reqwest::StatusCode;

    use super::{CachedHttpValidators, ConditionalFetchResult, fetch_with_conditional_cache};
    use crate::http_client::{HttpClient, HttpClientError, HttpRequest, HttpResponse};

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

    const URL: &str = "https://example.com/feed.txt";
    const SCOPE: &str = "test-resource-scope";

    fn validators(scope: Option<&str>) -> CachedHttpValidators {
        CachedHttpValidators {
            scope: scope.map(str::to_string),
            etag: Some("etag-1".into()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".into()),
        }
    }

    fn request(conditional: bool) -> HttpRequest {
        HttpRequest {
            url: URL.into(),
            validator_scope: conditional.then(|| SCOPE.into()),
            if_none_match: conditional.then(|| "etag-1".into()),
            if_modified_since: conditional.then(|| "Mon, 01 Jan 2024 00:00:00 GMT".into()),
            max_body_bytes: 1024,
        }
    }

    fn response(status: StatusCode, scope: &str) -> HttpResponse {
        HttpResponse {
            status,
            body: if status == StatusCode::OK {
                b"192.0.2.0/24".to_vec()
            } else {
                Vec::new()
            },
            validator_scope: Some(scope.into()),
            etag: None,
            last_modified: None,
        }
    }

    #[test]
    fn accepts_304_only_for_a_scoped_validator_and_usable_cache() {
        for (cached_scope, usable, response_scope) in [
            (Some(SCOPE), true, SCOPE),
            (Some(SCOPE), true, "other-resource"),
            (Some(SCOPE), false, SCOPE),
            (None, true, SCOPE),
        ] {
            let matches = cached_scope == Some(response_scope) && usable;
            let mut responses = vec![Ok(response(StatusCode::NOT_MODIFIED, response_scope))];
            let fresh = response(StatusCode::OK, response_scope);
            if !matches {
                responses.push(Ok(fresh.clone()));
            }
            let client = MockHttpClient::new(responses);

            let result = fetch_with_conditional_cache(
                &client,
                URL,
                1024,
                validators(cached_scope),
                usable,
                "remote source",
            );

            let mut expected_requests = vec![request(cached_scope.is_some() && usable)];
            if matches {
                assert_eq!(result, ConditionalFetchResult::CacheNotModified);
            } else {
                assert_eq!(result, ConditionalFetchResult::Network(fresh));
                expected_requests.push(request(false));
            }
            assert_eq!(client.requests(), expected_requests);
        }
    }

    #[test]
    fn falls_back_when_unconditional_refetch_fails() {
        let client = MockHttpClient::new(vec![
            Ok(response(StatusCode::NOT_MODIFIED, "other-resource")),
            Err(HttpClientError::Request {
                reason: "offline".into(),
            }),
        ]);

        let result = fetch_with_conditional_cache(
            &client,
            URL,
            1024,
            validators(Some(SCOPE)),
            true,
            "remote source",
        );

        assert_eq!(result, ConditionalFetchResult::FallbackCache);
        assert_eq!(client.requests(), [request(true), request(false)]);
    }

    #[test]
    fn rejects_non_200_success_responses_and_an_unconditional_304() {
        for status in [
            StatusCode::ACCEPTED,
            StatusCode::NO_CONTENT,
            StatusCode::PARTIAL_CONTENT,
            StatusCode::NOT_MODIFIED,
        ] {
            for retry in [false, true] {
                if !retry && status == StatusCode::NOT_MODIFIED {
                    continue;
                }
                let mut responses = Vec::new();
                if retry {
                    responses.push(Ok(response(StatusCode::NOT_MODIFIED, "other-resource")));
                }
                responses.push(Ok(response(status, SCOPE)));
                let client = MockHttpClient::new(responses);

                let result = fetch_with_conditional_cache(
                    &client,
                    URL,
                    1024,
                    validators(Some(SCOPE)),
                    true,
                    "remote source",
                );

                assert_eq!(result, ConditionalFetchResult::FallbackCache);
                let mut expected_requests = vec![request(true)];
                if retry {
                    expected_requests.push(request(false));
                }
                assert_eq!(client.requests(), expected_requests);
            }
        }
    }
}
