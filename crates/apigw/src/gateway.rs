//! Gateway-wide state and policy: what every route of one API shares, how
//! unevaluated protections are enforced, and API Gateway's error responses.

use std::sync::Arc;

use std::num::NonZeroU32;

use axum::extract::Request;
use axum::http::{HeaderName, Method, StatusCode};
use axum::response::Response;
use uuid::Uuid;

use crate::authz::KeyStore;
use crate::aws::AwsClients;
use crate::cache::CacheScope;
use crate::canary::Release;
use crate::cors::Cors;
use crate::gateway_response::{Failure, GatewayResponses};
use crate::integration::StageVariables;
use crate::limits::LimitExceeded;
use crate::model::{ApiKind, Protection, ResponseType};
use crate::observability::StageObserver;
use crate::payload::PayloadSettings;
use crate::pipeline::RequestContext;
use crate::route::Route;
use crate::state::StateBackend;
use crate::vpc_link::VpcLinks;

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

/// What to do with request validators, which this gateway cannot run yet.
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
    pub(crate) request_validation: Unsupported,
}

impl Enforcement {
    pub(crate) fn warn_if_relaxed(self) {
        if self.authorization == AuthorizationMode::Skip {
            tracing::warn!(
                "serving routes that require authorization WITHOUT checking credentials"
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
    fn refuses(self, protection: Protection, route: &Route) -> bool {
        match protection {
            Protection::ResourcePolicy => route.policy.is_unevaluable(),
            Protection::Authorizer => {
                self.authorization == AuthorizationMode::Enforce
                    && route.authorizer.is_unevaluable()
            }
            Protection::Iam | Protection::ApiKey => {
                self.authorization == AuthorizationMode::Enforce
            }
            Protection::RequestValidation => self.request_validation == Unsupported::Reject,
        }
    }

    /// The protections on `route` that refuse requests, in evaluation order;
    /// a request gets the first one's response.
    pub(crate) fn refusals(self, route: &Route) -> impl Iterator<Item = Protection> + '_ {
        route
            .protections
            .iter()
            .filter(move |&p| self.refuses(p, route))
    }
}

impl Protection {
    /// The failure API Gateway gives a client that fails this check, or a 501
    /// where API Gateway would do work this gateway cannot do yet.
    pub(crate) fn refusal(self, kind: ApiKind) -> Failure {
        match (self, kind) {
            (Self::ResourcePolicy, _) | (Self::Iam, ApiKind::Http) => {
                Failure::new(ResponseType::AccessDenied).with_message("Forbidden")
            }
            (Self::ApiKey, _) => Failure::new(ResponseType::InvalidApiKey),
            (Self::Iam, ApiKind::Rest) => Failure::new(ResponseType::MissingAuthenticationToken),
            (Self::Authorizer, _) => Failure::new(ResponseType::Unauthorized),
            (Self::RequestValidation, _) => Failure::gateway(
                StatusCode::NOT_IMPLEMENTED,
                "Request validation is not supported by this gateway",
            ),
        }
    }

    /// Why a route with this protection is refused, for `/routes` and logs.
    pub(crate) fn refusal_reason(self, route: &Route) -> String {
        match self {
            Self::ResourcePolicy => format!(
                "has a resource policy this gateway cannot evaluate: {}; answering 403",
                route
                    .policy
                    .unevaluable_reason()
                    .unwrap_or("it could not be read")
            ),
            Self::Iam => {
                "requires IAM authorization, which cannot be verified outside AWS; answering 403".to_owned()
            }
            Self::Authorizer => format!(
                "requires an authorizer this gateway cannot evaluate: {}; answering 401",
                route
                    .authorizer
                    .unevaluable_reason()
                    .unwrap_or("it has no definition")
            ),
            Self::ApiKey => "requires an API key, which this gateway does not check; answering 403".to_owned(),
            Self::RequestValidation => {
                "has a request validator, which this gateway does not run; answering 501 (--unsupported-validation=ignore serves it)".to_owned()
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
    pub(crate) stage_variables: Arc<StageVariables>,
    pub(crate) enforcement: Enforcement,
    pub(crate) responses: GatewayResponses,
    pub(crate) cors: Option<Cors>,
    pub(crate) state: Arc<StateBackend>,
    pub(crate) replicas: NonZeroU32,
    pub(crate) vpc_links: VpcLinks,
    pub(crate) http: reqwest::Client,
    pub(crate) aws: Arc<AwsClients>,
    pub(crate) keys: Arc<KeyStore>,
    pub(crate) observer: StageObserver,
    /// Which release of a canary stage this context serves; `None` when the
    /// stage has no canary.
    pub(crate) release: Option<Release>,
    /// Binary media types and compression settings.
    pub(crate) payload: Arc<PayloadSettings>,
    /// Whether this release caches responses, and where.
    pub(crate) cache: CacheScope,
}

impl ApiContext {
    /// Answers `request` with `failure`, applying the API's gateway response
    /// customizations.
    pub(crate) fn respond(&self, request: &RequestContext, failure: &Failure) -> Response {
        self.responses.render(failure, request)
    }

    /// Answers a request that never reached a route's pipeline.
    pub(crate) fn reject(&self, request: Request, error: GatewayError) -> Response {
        let (parts, _) = request.into_parts();
        let context = RequestContext::new(self, None, parts, Vec::new());
        let Some(ref cors) = self.cors else {
            return self.respond(&context, &error.failure(self.kind));
        };
        if Cors::is_preflight(&context) {
            return cors.preflight(&context);
        }
        let mut response = self.respond(&context, &error.failure(self.kind));
        cors.decorate(&context, &mut response);
        response
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
    /// The integration answered unusably, for example a malformed Lambda proxy
    /// response or a function error.
    IntegrationFailure,
    /// The integration could not be reached.
    IntegrationUnreachable,
    IntegrationTimeout,
    /// The integration is configured in a way that cannot be executed, such as
    /// an invalid endpoint address.
    ApiConfiguration,
    RequestTooLarge,
    /// An integration this gateway can't execute yet.
    UnsupportedIntegration,
    /// No request template matches the request's `Content-Type` and the
    /// integration's `passthroughBehavior` does not allow the body through.
    UnsupportedMediaType,
    /// A streaming integration's output doesn't follow the response streaming
    /// format; API Gateway answers `500`.
    MalformedStreamingResponse,
    /// The URL is longer than the API type allows.
    UrlTooLong,
    /// The headers (and request line, for HTTP APIs) are larger than the API
    /// type allows.
    HeadersTooLarge,
}

impl From<LimitExceeded> for GatewayError {
    fn from(exceeded: LimitExceeded) -> Self {
        match exceeded {
            LimitExceeded::UrlTooLong => Self::UrlTooLong,
            LimitExceeded::HeadersTooLarge => Self::HeadersTooLarge,
        }
    }
}

impl GatewayError {
    pub(crate) fn failure(self, kind: ApiKind) -> Failure {
        match (self, kind) {
            (Self::NoRoute, ApiKind::Rest) => {
                Failure::new(ResponseType::MissingAuthenticationToken)
            }
            (Self::NoRoute, ApiKind::Http) => Failure::gateway(StatusCode::NOT_FOUND, "Not Found"),
            (Self::InvalidRequest, _) => Failure::new(ResponseType::Default4xx),
            (Self::IntegrationFailure, _) | (Self::IntegrationUnreachable, ApiKind::Http) => {
                Failure::new(ResponseType::IntegrationFailure)
                    .with_status(StatusCode::BAD_GATEWAY)
                    .with_message("Internal server error")
            }
            (Self::IntegrationUnreachable, ApiKind::Rest) => {
                Failure::new(ResponseType::IntegrationFailure)
            }
            (Self::IntegrationTimeout, ApiKind::Rest) => {
                Failure::new(ResponseType::IntegrationTimeout)
            }
            (Self::IntegrationTimeout, ApiKind::Http) => {
                Failure::new(ResponseType::IntegrationTimeout).with_message("Service Unavailable")
            }
            (Self::ApiConfiguration, _) => Failure::new(ResponseType::ApiConfigurationError),
            (Self::RequestTooLarge, ApiKind::Rest) => Failure::new(ResponseType::RequestTooLarge),
            (Self::RequestTooLarge, ApiKind::Http) => {
                Failure::new(ResponseType::RequestTooLarge).with_message("Request Entity Too Large")
            }
            (Self::MalformedStreamingResponse, _) => Failure::new(ResponseType::Default5xx),
            (Self::UrlTooLong, _) => {
                Failure::gateway(StatusCode::URI_TOO_LONG, "Request-URI Too Large")
            }
            (Self::HeadersTooLarge, _) => Failure::gateway(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                "Request Header Fields Too Large",
            ),
            (Self::UnsupportedMediaType, _) => Failure::new(ResponseType::UnsupportedMediaType),
            (Self::UnsupportedIntegration, _) => Failure::gateway(
                StatusCode::NOT_IMPLEMENTED,
                "Integration not supported by this gateway",
            ),
        }
    }
}

impl ApiKind {
    /// REST APIs honor `X-HTTP-Method-Override`: the header's value replaces the
    /// request's method before routing, and a header that is not a valid method
    /// is ignored. HTTP APIs ignore the header.
    ///
    /// <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html>
    pub(crate) fn override_method(self, request: &mut Request) {
        if self != Self::Rest {
            return;
        }
        let Some(method) = request
            .headers()
            .get("x-http-method-override")
            .and_then(|value| Method::from_bytes(value.as_bytes()).ok())
        else {
            return;
        };
        *request.method_mut() = method;
    }

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

    #[test]
    fn hop_by_hop_headers_are_recognised() {
        assert!(HeaderName::from_static("connection").is_hop_by_hop());
        assert!(HeaderName::from_static("transfer-encoding").is_hop_by_hop());
        assert!(!HeaderName::from_static("x-forwarded-for").is_hop_by_hop());
    }

    #[test]
    fn method_override_applies_to_rest_apis_only() {
        use axum::body::Body;
        let request = |method: Method, value: &str| {
            Request::builder()
                .method(method)
                .uri("/")
                .header("x-http-method-override", value)
                .body(Body::empty())
                .unwrap()
        };
        let mut rest = request(Method::POST, "PUT");
        ApiKind::Rest.override_method(&mut rest);
        assert_eq!(rest.method(), Method::PUT);
        let mut http = request(Method::POST, "PUT");
        ApiKind::Http.override_method(&mut http);
        assert_eq!(http.method(), Method::POST);
        let mut invalid = request(Method::POST, "NOT A METHOD");
        ApiKind::Rest.override_method(&mut invalid);
        assert_eq!(invalid.method(), Method::POST);
        let mut absent = Request::builder().uri("/").body(Body::empty()).unwrap();
        ApiKind::Rest.override_method(&mut absent);
        assert_eq!(absent.method(), Method::GET);
    }

    #[test]
    fn request_id_header_names_follow_api_kind() {
        assert_eq!(ApiKind::Rest.request_id_header(), "x-amzn-requestid");
        assert_eq!(ApiKind::Http.request_id_header(), "apigw-requestid");
    }
}
