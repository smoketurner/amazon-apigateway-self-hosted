//! How a REST API reads the path of a request, measured against a deployed API.
//!
//! - Slashes before the first segment beyond the first, and slashes after the
//!   last segment, do not take part in routing: `//pets` and `/pets//` are
//!   `/pets`. A doubled slash between segments does: `/pets//7` is not
//!   `/pets/7`, though a greedy parameter takes it as part of its value.
//! - Path parameters are never percent-decoded: `/pets/a%20b` gives the
//!   parameter `a%20b` to Lambda events, mapping templates, and integration
//!   URLs alike.
//! - A `%` that does not start an escape, in the path or the query string, is
//!   a `400` with no body.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::{OriginalUri, Request};
use axum::http::uri::{InvalidUri, PathAndQuery};
use axum::http::{StatusCode, Uri};
use axum::response::Response;
use tower::ServiceExt as _;

/// The request path as API Gateway reports it in a Lambda event's `path`:
/// what the client sent, less the extra leading slashes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReportedPath(pub(crate) String);

/// A request path, in the forms a REST API uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestPath<'a>(&'a str);

impl<'a> RestPath<'a> {
    pub(crate) const fn new(path: &'a str) -> Self {
        Self(path)
    }

    /// The path without its extra leading slashes.
    fn reported(self) -> &'a str {
        let segments = self.0.trim_start_matches('/');
        let slashes = self.0.len().saturating_sub(segments.len());
        match slashes {
            0 | 1 => self.0,
            _ => self.0.get(slashes.saturating_sub(1)..).unwrap_or(self.0),
        }
    }

    /// The path routes are matched against: [`Self::reported`] without
    /// trailing slashes. The root stays `/`.
    fn routed(self) -> &'a str {
        match self.reported().trim_end_matches('/') {
            "" => "/",
            trimmed => trimmed,
        }
    }

    /// Whether a `%` in `text` is not followed by two hex digits.
    fn has_malformed_escape(text: &str) -> bool {
        let mut bytes = text.bytes();
        while let Some(byte) = bytes.next() {
            if byte == b'%' {
                let escape = [bytes.next(), bytes.next()];
                if !escape
                    .iter()
                    .all(|digit| digit.is_some_and(|d| d.is_ascii_hexdigit()))
                {
                    return true;
                }
            }
        }
        false
    }

    /// The values of `template`'s `{name}` and `{name+}` parameters in this
    /// (routed) path, exactly as the client wrote them. `None` when the path
    /// is not one the template matches.
    pub(crate) fn parameters(self, template: &str) -> Option<Vec<(String, String)>> {
        let mut values = Vec::new();
        let mut sent = self.0.strip_prefix('/')?;
        let mut names = template.strip_prefix('/')?.split('/').peekable();
        while let Some(name) = names.next() {
            if let Some(greedy) = name.strip_prefix('{').and_then(|n| n.strip_suffix("+}")) {
                values.push((greedy.to_owned(), sent.to_owned()));
                return names.peek().is_none().then_some(values);
            }
            let (segment, rest) = match sent.split_once('/') {
                Some((segment, rest)) => (segment, Some(rest)),
                None => (sent, None),
            };
            match name.strip_prefix('{').and_then(|n| n.strip_suffix('}')) {
                Some(parameter) => values.push((parameter.to_owned(), segment.to_owned())),
                None if name == segment => {}
                None => return None,
            }
            match (rest, names.peek()) {
                (Some(rest), Some(_)) => sent = rest,
                (None, None) => return Some(values),
                (Some(_), None) | (None, Some(_)) => return None,
            }
        }
        Some(values)
    }
}

/// Serves `router` the way a REST API reads paths: malformed escapes are
/// refused, and routing sees the path without its extra slashes.
pub(crate) fn serve(router: Router) -> Router {
    let router = Arc::new(router);
    Router::new().fallback(move |mut request: Request| {
        let router = Arc::clone(&router);
        async move {
            let uri = request.uri().clone();
            if RestPath::has_malformed_escape(uri.path())
                || uri.query().is_some_and(RestPath::has_malformed_escape)
            {
                return malformed();
            }
            let path = RestPath::new(uri.path());
            if path.routed() != uri.path()
                && let Ok(routed) = with_path(&uri, path.routed())
            {
                let extensions = request.extensions_mut();
                extensions.insert(ReportedPath(path.reported().to_owned()));
                if extensions.get::<OriginalUri>().is_none() {
                    extensions.insert(OriginalUri(uri));
                }
                *request.uri_mut() = routed;
            }
            match Router::clone(&router).oneshot(request).await {
                Ok(response) => response,
                Err(never) => match never {},
            }
        }
    })
}

/// `uri` with its path replaced and its query string kept.
fn with_path(uri: &Uri, path: &str) -> Result<Uri, InvalidUri> {
    let target = match uri.query() {
        Some(query) => format!("{path}?{query}"),
        None => path.to_owned(),
    };
    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(PathAndQuery::try_from(target)?);
    Ok(Uri::from_parts(parts).unwrap_or_else(|_| uri.clone()))
}

/// API Gateway's answer to a malformed escape: `400` and nothing else.
fn malformed() -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::BAD_REQUEST;
    response
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::routing::get;

    use super::*;

    fn params(template: &str, path: &str) -> Option<Vec<(String, String)>> {
        RestPath::new(path).parameters(template)
    }

    fn pair(name: &str, value: &str) -> (String, String) {
        (name.to_owned(), value.to_owned())
    }

    #[test]
    fn extra_leading_and_trailing_slashes_do_not_route() {
        for (sent, routed, reported) in [
            ("/mock", "/mock", "/mock"),
            ("/mock/", "/mock", "/mock/"),
            ("//mock", "/mock", "/mock"),
            ("/mock/teapot///", "/mock/teapot", "/mock/teapot///"),
            ("/mock//teapot", "/mock//teapot", "/mock//teapot"),
            (
                "//lambda-proxy//x//",
                "/lambda-proxy//x",
                "/lambda-proxy//x//",
            ),
            ("/", "/", "/"),
            ("///", "/", "/"),
        ] {
            let path = RestPath::new(sent);
            assert_eq!(path.routed(), routed, "{sent}");
            assert_eq!(path.reported(), reported, "{sent}");
        }
    }

    /// Values measured against a deployed REST API.
    #[test]
    fn parameters_keep_the_clients_escapes() {
        assert_eq!(
            params("/validated/{id}", "/validated/a%20b%2Fc%2B+d"),
            Some(vec![pair("id", "a%20b%2Fc%2B+d")])
        );
        assert_eq!(
            params("/lambda-proxy/{proxy+}", "/lambda-proxy/a%20b/c%2Fd"),
            Some(vec![pair("proxy", "a%20b/c%2Fd")])
        );
        assert_eq!(
            params("/lambda-proxy/{proxy+}", "/lambda-proxy//x"),
            Some(vec![pair("proxy", "/x")]),
            "a doubled slash belongs to the greedy value"
        );
        assert_eq!(
            params("/a/{b}/c/{d}", "/a/1/c/2"),
            Some(vec![pair("b", "1"), pair("d", "2")])
        );
        assert_eq!(params("/mock", "/mock"), Some(Vec::new()));
        assert_eq!(params("/", "/"), Some(Vec::new()));
    }

    #[test]
    fn paths_the_template_does_not_match_have_no_parameters() {
        assert_eq!(params("/pets/{id}", "/pets"), None);
        assert_eq!(params("/pets/{id}", "/pets/1/2"), None);
        assert_eq!(params("/pets/{id}", "/dogs/1"), None);
        assert_eq!(params("/pets/{id+}/x", "/pets/1/x"), None);
    }

    #[test]
    fn a_percent_sign_must_start_an_escape() {
        for malformed in ["%zz", "a%2", "%", "x%G0", "100%"] {
            assert!(RestPath::has_malformed_escape(malformed), "{malformed}");
        }
        for fine in ["", "a%20b", "%2F%2f", "plain", "a+b"] {
            assert!(!RestPath::has_malformed_escape(fine), "{fine}");
        }
    }

    async fn status(router: &Router, target: &str) -> StatusCode {
        let request = Request::builder().uri(target).body(Body::empty()).unwrap();
        router.clone().oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn requests_are_routed_without_their_extra_slashes() {
        let router = serve(Router::new().route("/mock", get(|| async { "ok" })));
        for found in ["/mock", "/mock/", "//mock", "/mock//", "/mock/?a=1"] {
            assert_eq!(status(&router, found).await, StatusCode::OK, "{found}");
        }
        assert_eq!(status(&router, "/mock//x").await, StatusCode::NOT_FOUND);
        for refused in ["/mock?d=%zz", "/%zz", "/mock?a=%"] {
            assert_eq!(
                status(&router, refused).await,
                StatusCode::BAD_REQUEST,
                "{refused}"
            );
        }
    }
}
