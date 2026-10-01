//! The request-size quotas API Gateway enforces before a request reaches a route.
//!
//! - REST: the URL is at most 10,240 characters (Regional endpoints) and all
//!   header names, values, and line terminators together at most 20,480 bytes.
//! - HTTP: the request line and the header values together are at most 10,240
//!   bytes.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html>
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-quotas.html>
//!
//! The documentation does not give the status codes. Oversized URLs answer
//! `414` and oversized headers `431`, the codes HTTP defines for them.

use axum::extract::{OriginalUri, Request};
use axum::http::{HeaderMap, Method, Uri, Version};

use crate::model::ApiKind;

/// Which quota a request exceeded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LimitExceeded {
    UrlTooLong,
    HeadersTooLarge,
}

/// The quotas of one API type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestLimits {
    /// Longest URL, in characters, when the API type limits it on its own.
    url_chars: Option<usize>,
    /// Most bytes of header text (plus the request line, where it counts).
    header_bytes: usize,
    request_line: RequestLine,
}

/// Whether the request line counts against the header quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RequestLine {
    Counted,
    NotCounted,
}

impl ApiKind {
    pub(crate) const fn request_limits(self) -> RequestLimits {
        match self {
            Self::Rest => RequestLimits {
                url_chars: Some(10_240),
                header_bytes: 20_480,
                request_line: RequestLine::NotCounted,
            },
            Self::Http => RequestLimits {
                url_chars: None,
                header_bytes: 10_240,
                request_line: RequestLine::Counted,
            },
        }
    }
}

impl RequestLimits {
    /// Checks a request against the quotas. A request is measured as it was
    /// received: before a base path is stripped, with every header counted as
    /// `name: value` and a CRLF.
    ///
    /// # Errors
    ///
    /// Names the first quota the request exceeds.
    pub(crate) fn check(self, request: &Request) -> Result<(), LimitExceeded> {
        let uri = request
            .extensions()
            .get::<OriginalUri>()
            .map_or_else(|| request.uri(), |original| &original.0);
        let target = Self::target(uri);
        if self
            .url_chars
            .is_some_and(|max| target.chars().count() > max)
        {
            return Err(LimitExceeded::UrlTooLong);
        }
        let mut bytes = Self::header_bytes(request.headers());
        if self.request_line == RequestLine::Counted {
            bytes = bytes.saturating_add(Self::request_line_bytes(
                request.method(),
                &target,
                request.version(),
            ));
        }
        if bytes > self.header_bytes {
            return Err(LimitExceeded::HeadersTooLarge);
        }
        Ok(())
    }

    /// The request target: the path and query as the client sent them.
    fn target(uri: &Uri) -> String {
        uri.path_and_query()
            .map_or_else(|| uri.path().to_owned(), ToString::to_string)
    }

    /// Bytes of `name: value\r\n` for every header.
    fn header_bytes(headers: &HeaderMap) -> usize {
        headers.iter().fold(0_usize, |total, (name, value)| {
            total.saturating_add(
                name.as_str()
                    .len()
                    .saturating_add(": ".len())
                    .saturating_add(value.len())
                    .saturating_add("\r\n".len()),
            )
        })
    }

    /// Bytes of `METHOD target HTTP/x.y\r\n`.
    fn request_line_bytes(method: &Method, target: &str, version: Version) -> usize {
        let version = match version {
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            Version::HTTP_10 => "HTTP/1.0",
            _ => "HTTP/1.1",
        };
        method
            .as_str()
            .len()
            .saturating_add(1)
            .saturating_add(target.len())
            .saturating_add(1)
            .saturating_add(version.len())
            .saturating_add("\r\n".len())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::body::Body;

    use super::*;

    fn request(path: &str, headers: &[(&str, String)]) -> Request {
        let mut builder = Request::builder().method(Method::GET).uri(path);
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        builder.body(Body::empty()).unwrap()
    }

    /// A header value that makes the request's headers exactly `total` bytes.
    fn padded_to(total: usize, fixed: usize) -> (&'static str, String) {
        let overhead = "x-pad: \r\n".len().saturating_add(fixed);
        ("x-pad", "a".repeat(total.saturating_sub(overhead)))
    }

    #[test]
    fn rest_urls_are_limited_to_10240_characters() {
        let limits = ApiKind::Rest.request_limits();
        let at_limit = format!("/{}", "a".repeat(10_239));
        assert_eq!(at_limit.chars().count(), 10_240);
        assert_eq!(limits.check(&request(&at_limit, &[])), Ok(()));
        let over = format!("/{}", "a".repeat(10_240));
        assert_eq!(
            limits.check(&request(&over, &[])),
            Err(LimitExceeded::UrlTooLong)
        );
        let query = format!("/p?q={}", "a".repeat(10_240 - "/p?q=".len()));
        assert_eq!(limits.check(&request(&query, &[])), Ok(()));
        assert_eq!(
            limits.check(&request(&format!("{query}a"), &[])),
            Err(LimitExceeded::UrlTooLong)
        );
    }

    #[test]
    fn rest_headers_are_limited_to_20480_bytes() {
        let limits = ApiKind::Rest.request_limits();
        let (name, value) = padded_to(20_480, 0);
        assert_eq!(limits.check(&request("/", &[(name, value)])), Ok(()));
        let (name, value) = padded_to(20_481, 0);
        assert_eq!(
            limits.check(&request("/", &[(name, value)])),
            Err(LimitExceeded::HeadersTooLarge)
        );
        let long_url = format!("/{}", "a".repeat(10_000));
        let (name, value) = padded_to(20_480, 0);
        assert_eq!(
            limits.check(&request(&long_url, &[(name, value)])),
            Ok(()),
            "the REST header quota does not include the request line"
        );
    }

    #[test]
    fn http_api_counts_the_request_line_with_the_headers() {
        let limits = ApiKind::Http.request_limits();
        let line = "GET / HTTP/1.1\r\n".len();
        let (name, value) = padded_to(10_240, line);
        assert_eq!(limits.check(&request("/", &[(name, value)])), Ok(()));
        let (name, value) = padded_to(10_241, line);
        assert_eq!(
            limits.check(&request("/", &[(name, value)])),
            Err(LimitExceeded::HeadersTooLarge)
        );
        let long_url = format!("/{}", "a".repeat(20_000));
        assert_eq!(
            limits.check(&request(&long_url, &[])),
            Err(LimitExceeded::HeadersTooLarge),
            "HTTP APIs have no URL quota of their own"
        );
    }

    #[test]
    fn the_original_uri_is_measured_when_a_base_path_was_stripped() {
        let mut request = request("/inner", &[]);
        let original = format!("/stage/{}", "a".repeat(10_240));
        request
            .extensions_mut()
            .insert(OriginalUri(original.parse().unwrap()));
        assert_eq!(
            ApiKind::Rest.request_limits().check(&request),
            Err(LimitExceeded::UrlTooLong)
        );
    }

    #[test]
    fn many_small_headers_add_up() {
        let limits = ApiKind::Rest.request_limits();
        let headers: Vec<(&str, String)> = (0..300).map(|_| ("x-h", "v".repeat(70))).collect();
        assert_eq!(
            limits.check(&request("/", &headers)),
            Err(LimitExceeded::HeadersTooLarge)
        );
        let fewer: Vec<(&str, String)> = headers.iter().take(200).cloned().collect();
        assert_eq!(limits.check(&request("/", &fewer)), Ok(()));
    }
}
