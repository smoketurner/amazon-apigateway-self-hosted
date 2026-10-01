//! Gateway-wide state and policy: what every route of one API shares, how
//! unevaluated protections are enforced, and API Gateway's error responses.

use std::sync::Arc;

use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use uuid::Uuid;

use crate::aws::AwsClients;
use crate::integration::StageVariables;
use crate::model::{ApiKind, Protection};
use crate::route::Route;

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
                ErrorBody::new(StatusCode::FORBIDDEN, "Forbidden").into_response()
            }
            (Self::Iam, ApiKind::Rest) => {
                ErrorBody::new(StatusCode::FORBIDDEN, "Missing Authentication Token")
                    .into_response()
            }
            (Self::Authorizer, _) => {
                ErrorBody::new(StatusCode::UNAUTHORIZED, "Unauthorized").into_response()
            }
            (Self::RequestValidation, _) => ErrorBody::new(
                StatusCode::NOT_IMPLEMENTED,
                "Request validation is not supported by this gateway",
            )
            .into_response(),
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
    pub(crate) aws: Arc<AwsClients>,
}

/// A JSON `{"message": ...}` body, the shape of API Gateway's own errors.
pub(crate) struct ErrorBody {
    status: StatusCode,
    message: &'static str,
}

impl ErrorBody {
    pub(crate) const fn new(status: StatusCode, message: &'static str) -> Self {
        Self { status, message }
    }
}

impl IntoResponse for ErrorBody {
    fn into_response(self) -> Response {
        let body = serde_json::json!({ "message": self.message }).to_string();
        (
            self.status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response()
    }
}

/// Errors the gateway itself answers with, worded as API Gateway words them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GatewayError {
    /// No route matches the path and method.
    NoRoute,
    /// The request can't be read (for example a path parameter that isn't
    /// valid UTF-8 after decoding).
    InvalidRequest,
    /// The integration could not be reached or answered unusably.
    IntegrationFailure,
    IntegrationTimeout,
    RequestTooLarge,
    /// An integration this gateway can't execute yet.
    UnsupportedIntegration,
}

impl GatewayError {
    pub(crate) fn response(self, kind: ApiKind) -> Response {
        let body = match (self, kind) {
            (Self::NoRoute, ApiKind::Rest) => {
                ErrorBody::new(StatusCode::FORBIDDEN, "Missing Authentication Token")
            }
            (Self::NoRoute, ApiKind::Http) => ErrorBody::new(StatusCode::NOT_FOUND, "Not Found"),
            (Self::InvalidRequest, _) => ErrorBody::new(StatusCode::BAD_REQUEST, "Bad Request"),
            (Self::IntegrationFailure, _) => {
                ErrorBody::new(StatusCode::BAD_GATEWAY, "Internal server error")
            }
            (Self::IntegrationTimeout, ApiKind::Rest) => {
                ErrorBody::new(StatusCode::GATEWAY_TIMEOUT, "Endpoint request timed out")
            }
            (Self::IntegrationTimeout, ApiKind::Http) => {
                ErrorBody::new(StatusCode::GATEWAY_TIMEOUT, "Service Unavailable")
            }
            (Self::RequestTooLarge, _) => {
                ErrorBody::new(StatusCode::PAYLOAD_TOO_LARGE, "Request Entity Too Large")
            }
            (Self::UnsupportedIntegration, _) => ErrorBody::new(
                StatusCode::NOT_IMPLEMENTED,
                "Integration not supported by this gateway",
            ),
        };
        body.into_response()
    }
}

impl ApiKind {
    /// The header carrying the request ID on every response.
    pub(crate) fn request_id_header(self) -> HeaderName {
        match self {
            Self::Rest => HeaderName::from_static("x-amzn-requestid"),
            Self::Http => HeaderName::from_static("apigw-requestid"),
        }
    }
}

pub(crate) trait HeaderNameExt {
    /// Connection-level headers that a proxy must not forward (RFC 9110 §7.6.1).
    fn is_hop_by_hop(&self) -> bool;
}

impl HeaderNameExt for HeaderName {
    fn is_hop_by_hop(&self) -> bool {
        matches!(
            self.as_str(),
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
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    async fn body(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn error_bodies_match_api_gateway() {
        let cases = [
            (
                GatewayError::NoRoute,
                ApiKind::Rest,
                403,
                "Missing Authentication Token",
            ),
            (GatewayError::NoRoute, ApiKind::Http, 404, "Not Found"),
            (
                GatewayError::InvalidRequest,
                ApiKind::Rest,
                400,
                "Bad Request",
            ),
            (
                GatewayError::IntegrationFailure,
                ApiKind::Rest,
                502,
                "Internal server error",
            ),
            (
                GatewayError::IntegrationTimeout,
                ApiKind::Rest,
                504,
                "Endpoint request timed out",
            ),
            (
                GatewayError::IntegrationTimeout,
                ApiKind::Http,
                504,
                "Service Unavailable",
            ),
            (
                GatewayError::RequestTooLarge,
                ApiKind::Http,
                413,
                "Request Entity Too Large",
            ),
            (
                GatewayError::UnsupportedIntegration,
                ApiKind::Rest,
                501,
                "Integration not supported by this gateway",
            ),
        ];
        for (error, kind, status, message) in cases {
            let response = error.response(kind);
            assert_eq!(response.status().as_u16(), status, "{error:?} {kind:?}");
            assert_eq!(response.headers()["content-type"], "application/json");
            assert_eq!(
                body(response).await,
                format!("{{\"message\":\"{message}\"}}")
            );
        }
    }

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        assert!(HeaderName::from_static("connection").is_hop_by_hop());
        assert!(HeaderName::from_static("transfer-encoding").is_hop_by_hop());
        assert!(!HeaderName::from_static("x-forwarded-for").is_hop_by_hop());
    }

    #[test]
    fn request_id_header_names_follow_api_kind() {
        assert_eq!(ApiKind::Rest.request_id_header(), "x-amzn-requestid");
        assert_eq!(ApiKind::Http.request_id_header(), "apigw-requestid");
    }
}
