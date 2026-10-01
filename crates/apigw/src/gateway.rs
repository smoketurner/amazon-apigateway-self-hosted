//! Per-request execution: turns a matched route into an integration call and
//! shapes errors the way API Gateway does.

use std::net::SocketAddr;

use axum::body::{Body, Bytes};
use axum::extract::{ConnectInfo, FromRequestParts, RawPathParams};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::integration::{Integration, MockResponse, StageVariables};
use crate::model::{ApiKind, Protection};
use crate::route::Route;
use crate::{lambda, proxy};

/// API Gateway's maximum payload size.
pub(crate) const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorizationMode {
    /// Refuse routes that have an authorizer, IAM auth, or API key requirement.
    Enforce,
    /// Serve them without checking credentials, for deployments that
    /// authenticate in front of the gateway.
    Skip,
}

/// What to do with a protection this gateway cannot evaluate yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Unsupported {
    /// Refuse the request so the backend is never reached unprotected.
    Reject,
    /// Serve the route as if the protection were absent.
    Ignore,
}

/// How the gateway treats protections it does not evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Enforcement {
    pub(crate) authorization: AuthorizationMode,
    pub(crate) resource_policy: Unsupported,
    pub(crate) request_validation: Unsupported,
}

impl Enforcement {
    pub(crate) fn warn_if_relaxed(self) {
        if self.authorization == AuthorizationMode::Skip {
            tracing::warn!(
                "serving routes that require authorization WITHOUT checking credentials"
            );
        }
        if self.resource_policy == Unsupported::Ignore {
            tracing::warn!(
                "serving routes under resource policies WITHOUT evaluating the policies"
            );
        }
        if self.request_validation == Unsupported::Ignore {
            tracing::warn!(
                "forwarding requests to routes with request validators WITHOUT validating them"
            );
        }
    }
}

impl Enforcement {
    fn refuses(self, protection: Protection) -> bool {
        match protection {
            Protection::ResourcePolicy => self.resource_policy == Unsupported::Reject,
            Protection::Iam | Protection::Authorizer | Protection::ApiKey => {
                self.authorization == AuthorizationMode::Enforce
            }
            Protection::RequestValidation => self.request_validation == Unsupported::Reject,
        }
    }

    /// The protections on `route` that refuse requests, in evaluation order;
    /// a request gets the first one's response.
    pub(crate) fn refusals(self, route: &Route) -> impl Iterator<Item = Protection> + '_ {
        route.protections.iter().filter(move |&p| self.refuses(p))
    }
}

impl Protection {
    /// The response API Gateway gives a client that fails this check, or a 501
    /// where API Gateway would do work this gateway cannot do yet.
    pub(crate) fn refusal_response(self, kind: ApiKind) -> Response {
        match (self, kind) {
            (Self::ResourcePolicy | Self::ApiKey, _) | (Self::Iam, ApiKind::Http) => {
                error(StatusCode::FORBIDDEN, "Forbidden")
            }
            (Self::Iam, ApiKind::Rest) => {
                error(StatusCode::FORBIDDEN, "Missing Authentication Token")
            }
            (Self::Authorizer, _) => error(StatusCode::UNAUTHORIZED, "Unauthorized"),
            (Self::RequestValidation, _) => error(
                StatusCode::NOT_IMPLEMENTED,
                "Request validation is not supported by this gateway",
            ),
        }
    }

    /// Why a route with this protection is refused, for `/routes` and logs.
    pub(crate) fn refusal_reason(self) -> &'static str {
        match self {
            Self::ResourcePolicy => {
                "has a resource policy, which this gateway does not evaluate; answering 403 (--unsupported-resource-policy=ignore serves it)"
            }
            Self::Iam => {
                "requires IAM authorization, which cannot be verified outside AWS; answering 403"
            }
            Self::Authorizer => {
                "requires an authorizer, which this gateway does not evaluate; answering 401"
            }
            Self::ApiKey => "requires an API key, which this gateway does not check; answering 403",
            Self::RequestValidation => {
                "has a request validator, which this gateway does not run; answering 501 (--unsupported-validation=ignore serves it)"
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct RequestId(pub(crate) Uuid);

/// State shared by every route built from one snapshot.
pub(crate) struct ApiContext {
    pub(crate) kind: ApiKind,
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
    pub(crate) stage_variables: StageVariables,
    pub(crate) enforcement: Enforcement,
    pub(crate) http: reqwest::Client,
    pub(crate) lambda: aws_sdk_lambda::Client,
}

/// The parts of a client request that integrations consume, with the body
/// already buffered (API Gateway buffers too, up to [`MAX_BODY_BYTES`]).
pub(crate) struct Incoming {
    pub(crate) request_id: Uuid,
    pub(crate) received: jiff::Timestamp,
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) query: Option<String>,
    pub(crate) headers: HeaderMap,
    pub(crate) path_params: Vec<(String, String)>,
    pub(crate) source_ip: Option<String>,
    pub(crate) body: Bytes,
}

impl Incoming {
    pub(crate) fn path_param(&self, name: &str) -> Option<&str> {
        self.path_params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn query_pairs(&self) -> Vec<(String, String)> {
        let Some(query) = self.query.as_deref() else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            pairs.push((percent_decode(key), percent_decode(value)));
        }
        pairs
    }

    pub(crate) fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut iter = bytes.iter().copied();
    while let Some(byte) = iter.next() {
        match byte {
            b'+' => out.push(b' '),
            b'%' => {
                let mut lookahead = iter.clone();
                let decoded = match (lookahead.next(), lookahead.next()) {
                    (Some(hi), Some(lo)) => hex_value(hi).zip(hex_value(lo)),
                    (Some(_) | None, _) => None,
                };
                if let Some((hi, lo)) = decoded {
                    out.push((hi << 4) | lo);
                    iter = lookahead;
                } else {
                    out.push(b'%');
                }
            }
            other => out.push(other),
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

pub(crate) async fn handle(
    ctx: &ApiContext,
    route: &Route,
    request: axum::extract::Request,
) -> Response {
    if let Some(protection) = ctx.enforcement.refusals(route).next() {
        return protection.refusal_response(ctx.kind);
    }
    let (mut parts, body) = request.into_parts();
    let path_params = match RawPathParams::from_request_parts(&mut parts, &()).await {
        Ok(params) => params
            .iter()
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect(),
        Err(rejection) => return rejection.into_response(),
    };
    let Ok(body) = axum::body::to_bytes(body, MAX_BODY_BYTES).await else {
        return error(StatusCode::PAYLOAD_TOO_LARGE, "Request Entity Too Large");
    };
    let request_id = parts
        .extensions
        .get::<RequestId>()
        .map_or_else(Uuid::now_v7, |id| id.0);
    let source_ip = parts
        .extensions
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    let incoming = Incoming {
        request_id,
        received: jiff::Timestamp::now(),
        method: parts.method,
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().map(str::to_owned),
        headers: parts.headers,
        path_params,
        source_ip,
        body,
    };
    match route.integration {
        Integration::HttpProxy(ref target) => {
            proxy::forward(&ctx.http, ctx.kind, target, route, incoming).await
        }
        Integration::Lambda(ref target) => lambda::invoke(ctx, target, route, &incoming).await,
        Integration::Mock(ref mock) => mock_response(mock),
        Integration::Unsupported { ref reason } => {
            tracing::warn!(route = %route.key, reason, "unsupported integration invoked");
            error(
                StatusCode::NOT_IMPLEMENTED,
                "Integration not supported by this gateway",
            )
        }
    }
}

fn mock_response(mock: &MockResponse) -> Response {
    let mut response = Response::new(Body::from(mock.body.clone()));
    *response.status_mut() = mock.status;
    let headers = response.headers_mut();
    if let Some(ref content_type) = mock.content_type {
        headers.insert(header::CONTENT_TYPE, content_type.clone());
    }
    for (name, value) in &mock.headers {
        headers.insert(name.clone(), value.clone());
    }
    response
}

/// A JSON `{"message": ...}` body, matching API Gateway's own error responses.
pub(crate) fn error(status: StatusCode, message: &str) -> Response {
    let body = serde_json::json!({ "message": message }).to_string();
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        )],
        body,
    )
        .into_response()
}

/// The response for a path or method with no route: REST APIs answer 403
/// "Missing Authentication Token", HTTP APIs answer 404 "Not Found".
pub(crate) fn not_found(kind: ApiKind) -> Response {
    match kind {
        ApiKind::Rest => error(StatusCode::FORBIDDEN, "Missing Authentication Token"),
        ApiKind::Http => error(StatusCode::NOT_FOUND, "Not Found"),
    }
}

pub(crate) fn request_id_header(kind: ApiKind) -> HeaderName {
    match kind {
        ApiKind::Rest => HeaderName::from_static("x-amzn-requestid"),
        ApiKind::Http => HeaderName::from_static("apigw-requestid"),
    }
}

/// Connection-level headers that a proxy must not forward (RFC 9110 §7.6.1).
pub(crate) fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "proxy-connection"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    #[test]
    fn percent_decode_handles_malformed_escapes() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz%4"), "%zz%4");
        assert_eq!(percent_decode("%E2%9C%93"), "\u{2713}");
        assert_eq!(percent_decode("%FF"), "\u{FFFD}");
    }

    #[test]
    fn query_pairs_keeps_repeats_and_bare_keys() {
        let incoming = Incoming {
            request_id: Uuid::now_v7(),
            received: jiff::Timestamp::now(),
            method: Method::GET,
            path: "/".to_owned(),
            query: Some("a=1&a=2&flag&&b=x%3Dy".to_owned()),
            headers: HeaderMap::new(),
            path_params: Vec::new(),
            source_ip: None,
            body: Bytes::new(),
        };
        assert_eq!(
            incoming.query_pairs(),
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("a".to_owned(), "2".to_owned()),
                ("flag".to_owned(), String::new()),
                ("b".to_owned(), "x=y".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn error_bodies_match_api_gateway() {
        let response = not_found(ApiKind::Rest);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&body[..], br#"{"message":"Missing Authentication Token"}"#);
        assert_eq!(not_found(ApiKind::Http).status(), StatusCode::NOT_FOUND);
    }
}
