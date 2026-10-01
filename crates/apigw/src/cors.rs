//! HTTP API CORS: the gateway answers preflight requests itself and adds the
//! configured headers to other responses, ignoring CORS headers from the
//! backend. See
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-cors.html>.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::Response;

use crate::model::CorsConfig;
use crate::pipeline::RequestContext;

const ALLOW_ORIGIN: HeaderName = HeaderName::from_static("access-control-allow-origin");
const ALLOW_METHODS: HeaderName = HeaderName::from_static("access-control-allow-methods");
const ALLOW_HEADERS: HeaderName = HeaderName::from_static("access-control-allow-headers");
const ALLOW_CREDENTIALS: HeaderName = HeaderName::from_static("access-control-allow-credentials");
const EXPOSE_HEADERS: HeaderName = HeaderName::from_static("access-control-expose-headers");
const MAX_AGE: HeaderName = HeaderName::from_static("access-control-max-age");
const REQUEST_METHOD: &str = "access-control-request-method";
const CORS_HEADER_PREFIX: &str = "access-control-";

/// An `allowOrigins` entry: an exact origin, or a pattern in which `*` matches
/// any run of characters (`*`, `https://*`, `https://*.example.com`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct OriginPattern(String);

impl OriginPattern {
    fn matches(&self, origin: &str) -> bool {
        let mut pieces = self.0.split('*');
        let Some(first) = pieces.next() else {
            return false;
        };
        let Some(mut rest) = origin.strip_prefix(first) else {
            return false;
        };
        let mut wildcards = pieces.peekable();
        if wildcards.peek().is_none() {
            return rest.is_empty();
        }
        while let Some(piece) = wildcards.next() {
            if wildcards.peek().is_none() {
                return rest.ends_with(piece);
            }
            let Some(at) = rest.find(piece) else {
                return false;
            };
            rest = rest.split_at(at.saturating_add(piece.len())).1;
        }
        true
    }

    fn is_wildcard(&self) -> bool {
        self.0 == "*"
    }
}

/// An HTTP API's CORS configuration, compiled for request handling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cors {
    origins: Vec<OriginPattern>,
    methods: Vec<String>,
    headers: Vec<String>,
    expose_headers: Vec<String>,
    max_age: Option<u64>,
    credentials: bool,
}

impl Cors {
    pub(crate) fn compile(config: &CorsConfig) -> Self {
        Self {
            origins: config
                .allow_origins
                .iter()
                .cloned()
                .map(OriginPattern)
                .collect(),
            methods: config.allow_methods.clone(),
            headers: config.allow_headers.clone(),
            expose_headers: config.expose_headers.clone(),
            max_age: config.max_age,
            credentials: config.allow_credentials,
        }
    }

    /// Whether `ctx` is a preflight: an `OPTIONS` request with both an `Origin`
    /// and an `Access-Control-Request-Method` header.
    pub(crate) fn is_preflight(ctx: &RequestContext) -> bool {
        ctx.method == Method::OPTIONS
            && ctx.headers.contains_key(header::ORIGIN)
            && ctx.headers.contains_key(REQUEST_METHOD)
    }

    /// The `Access-Control-Allow-Origin` value for `origin`, if the API allows
    /// it. A literal `*` is answered as `*` unless credentials are allowed,
    /// which browsers reject with `*`, so the origin is echoed instead.
    fn allowed_origin(&self, origin: &str) -> Option<String> {
        let pattern = self.origins.iter().find(|p| p.matches(origin))?;
        if pattern.is_wildcard() && !self.credentials {
            Some("*".to_owned())
        } else {
            Some(origin.to_owned())
        }
    }

    fn insert(response: &mut Response, name: &HeaderName, value: &str) {
        if let Ok(value) = HeaderValue::try_from(value) {
            response.headers_mut().insert(name.clone(), value);
        }
    }

    fn vary_origin(response: &mut Response) {
        response
            .headers_mut()
            .append(header::VARY, HeaderValue::from_static("Origin"));
    }

    /// The gateway's answer to a preflight, given without calling the
    /// integration. An origin the API does not allow gets no CORS headers, so
    /// the browser blocks the request.
    pub(crate) fn preflight(&self, ctx: &RequestContext) -> Response {
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::NO_CONTENT;
        let Some(allowed) = ctx
            .header_str("origin")
            .and_then(|o| self.allowed_origin(o))
        else {
            return response;
        };
        if allowed != "*" {
            Self::vary_origin(&mut response);
        }
        Self::insert(&mut response, &ALLOW_ORIGIN, &allowed);
        if self.credentials {
            Self::insert(&mut response, &ALLOW_CREDENTIALS, "true");
        }
        if !self.methods.is_empty() {
            Self::insert(&mut response, &ALLOW_METHODS, &self.methods.join(", "));
        }
        if !self.headers.is_empty() {
            Self::insert(&mut response, &ALLOW_HEADERS, &self.headers.join(", "));
        }
        if let Some(seconds) = self.max_age {
            Self::insert(&mut response, &MAX_AGE, &seconds.to_string());
        }
        response
    }

    /// Replaces any CORS headers on `response` (the backend's are ignored)
    /// with the configured ones when the request's origin is allowed.
    pub(crate) fn decorate(&self, ctx: &RequestContext, response: &mut Response) {
        if Self::is_preflight(ctx) {
            return;
        }
        let stale: Vec<HeaderName> = response
            .headers()
            .keys()
            .filter(|name| name.as_str().starts_with(CORS_HEADER_PREFIX))
            .cloned()
            .collect();
        for name in stale {
            response.headers_mut().remove(name);
        }
        let Some(origin) = ctx.header_str("origin") else {
            return;
        };
        let Some(allowed) = self.allowed_origin(origin) else {
            return;
        };
        if allowed != "*" {
            Self::vary_origin(response);
        }
        Self::insert(response, &ALLOW_ORIGIN, &allowed);
        if self.credentials {
            Self::insert(response, &ALLOW_CREDENTIALS, "true");
        }
        if !self.expose_headers.is_empty() {
            Self::insert(response, &EXPOSE_HEADERS, &self.expose_headers.join(", "));
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;
    use crate::model::ApiKind;
    use crate::pipeline::context::tests::request;

    fn config(origins: &[&str]) -> CorsConfig {
        CorsConfig {
            allow_origins: origins.iter().map(|o| (*o).to_owned()).collect(),
            allow_methods: vec!["GET".to_owned(), "POST".to_owned()],
            allow_headers: vec!["authorization".to_owned()],
            expose_headers: vec!["x-id".to_owned()],
            max_age: Some(300),
            allow_credentials: false,
        }
    }

    fn from(origin: &str, method: Method, preflight: bool) -> RequestContext {
        let mut ctx = request(ApiKind::Http);
        ctx.method = method;
        ctx.headers
            .insert("origin", HeaderValue::from_str(origin).unwrap());
        if preflight {
            ctx.headers
                .insert(REQUEST_METHOD, HeaderValue::from_static("POST"));
        }
        ctx
    }

    #[test]
    fn origin_patterns() {
        let matches =
            |pattern: &str, origin: &str| OriginPattern(pattern.to_owned()).matches(origin);
        assert!(matches("https://a.example", "https://a.example"));
        assert!(!matches("https://a.example", "https://a.example.evil"));
        assert!(!matches("https://a.example", "http://a.example"));
        assert!(matches("*", "https://anything"));
        assert!(matches("https://*", "https://a.example"));
        assert!(!matches("https://*", "http://a.example"));
        assert!(matches("https://*.example.com", "https://app.example.com"));
        assert!(!matches("https://*.example.com", "https://app.example.org"));
        assert!(matches("http://*:3000", "http://localhost:3000"));
        assert!(matches("a*b*c", "aXbYc"));
        assert!(!matches("a*b*c", "aXcYb"));
        assert!(!matches("", "https://a"));
    }

    #[test]
    fn preflight_is_answered_with_the_configured_headers() {
        let cors = Cors::compile(&config(&["https://app.example"]));
        let ctx = from("https://app.example", Method::OPTIONS, true);
        assert!(Cors::is_preflight(&ctx));
        let response = cors.preflight(&ctx);
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let headers = response.headers();
        assert_eq!(
            headers["access-control-allow-origin"],
            "https://app.example"
        );
        assert_eq!(headers["access-control-allow-methods"], "GET, POST");
        assert_eq!(headers["access-control-allow-headers"], "authorization");
        assert_eq!(headers["access-control-max-age"], "300");
        assert_eq!(headers["vary"], "Origin");
        assert!(headers.get("access-control-allow-credentials").is_none());
    }

    #[test]
    fn wildcard_origins_answer_star_unless_credentials_are_allowed() {
        let mut config = config(&["*"]);
        let ctx = from("https://x.example", Method::OPTIONS, true);
        let response = Cors::compile(&config).preflight(&ctx);
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        assert!(response.headers().get("vary").is_none());
        config.allow_credentials = true;
        let response = Cors::compile(&config).preflight(&ctx);
        assert_eq!(
            response.headers()["access-control-allow-origin"],
            "https://x.example"
        );
        assert_eq!(
            response.headers()["access-control-allow-credentials"],
            "true"
        );
    }

    #[test]
    fn disallowed_origins_get_no_cors_headers() {
        let cors = Cors::compile(&config(&["https://app.example"]));
        let ctx = from("https://evil.example", Method::OPTIONS, true);
        let response = cors.preflight(&ctx);
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(response.headers().is_empty());
        let mut actual = Response::new(Body::empty());
        cors.decorate(
            &from("https://evil.example", Method::GET, false),
            &mut actual,
        );
        assert!(actual.headers().is_empty());
    }

    #[test]
    fn options_without_the_preflight_headers_is_not_a_preflight() {
        let plain = from("https://app.example", Method::OPTIONS, false);
        assert!(!Cors::is_preflight(&plain));
        let get = from("https://app.example", Method::GET, true);
        assert!(!Cors::is_preflight(&get));
        let mut no_origin = request(ApiKind::Http);
        no_origin.method = Method::OPTIONS;
        no_origin
            .headers
            .insert(REQUEST_METHOD, HeaderValue::from_static("GET"));
        assert!(!Cors::is_preflight(&no_origin));
    }

    #[test]
    fn actual_responses_replace_backend_cors_headers() {
        let cors = Cors::compile(&config(&["https://app.example"]));
        let mut response = Response::new(Body::empty());
        response
            .headers_mut()
            .insert(ALLOW_ORIGIN, HeaderValue::from_static("*"));
        response
            .headers_mut()
            .insert(MAX_AGE, HeaderValue::from_static("9"));
        response
            .headers_mut()
            .insert("x-keep", HeaderValue::from_static("1"));
        cors.decorate(
            &from("https://app.example", Method::GET, false),
            &mut response,
        );
        let headers = response.headers();
        assert_eq!(
            headers["access-control-allow-origin"],
            "https://app.example"
        );
        assert_eq!(headers["access-control-expose-headers"], "x-id");
        assert!(headers.get("access-control-max-age").is_none());
        assert_eq!(headers["x-keep"], "1");
    }

    #[test]
    fn requests_without_an_origin_only_lose_backend_cors_headers() {
        let cors = Cors::compile(&config(&["*"]));
        let mut response = Response::new(Body::empty());
        response
            .headers_mut()
            .insert(ALLOW_ORIGIN, HeaderValue::from_static("https://backend"));
        cors.decorate(&request(ApiKind::Http), &mut response);
        assert!(response.headers().is_empty());
    }
}
