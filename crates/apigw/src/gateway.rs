//! Gateway-wide state and policy: what every route of one API shares, how
//! unevaluated protections are enforced, and API Gateway's error responses.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use std::collections::BTreeMap;
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
use crate::incomplete_signature::UnclaimedSignature;
use crate::integration::StageVariables;
use crate::limits::LimitExceeded;
use crate::model::{ApiKind, Protection, ResponseType};
use crate::observability::StageObserver;
use crate::payload::PayloadSettings;
use crate::pipeline::RequestContext;
use crate::route::Route;
use crate::state::StateBackend;
use crate::usage::UsageStore;
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

/// How the gateway treats protections it does not evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Enforcement {
    pub(crate) authorization: AuthorizationMode,
}

impl Enforcement {
    pub(crate) fn warn_if_relaxed(self) {
        if self.authorization == AuthorizationMode::Skip {
            tracing::warn!(
                "serving routes that require authorization WITHOUT checking credentials"
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
            Protection::ApiKey => {
                self.authorization == AuthorizationMode::Enforce && route.api_key.is_unevaluable()
            }
            Protection::Iam => self.authorization == AuthorizationMode::Enforce,
            Protection::RequestValidation => route.validation.is_unevaluable(),
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
                "The request validator of this route cannot be run by this gateway",
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
                "requires IAM authorization, which cannot be verified outside AWS; answering 403"
                    .to_owned()
            }
            Self::Authorizer => format!(
                "requires an authorizer this gateway cannot evaluate: {}; answering 401",
                route
                    .authorizer
                    .unevaluable_reason()
                    .unwrap_or("it has no definition")
            ),
            Self::ApiKey => format!(
                "requires an API key this gateway cannot check: {}; answering 403",
                route
                    .api_key
                    .unevaluable_reason()
                    .unwrap_or("it has no usage plans")
            ),
            Self::RequestValidation => format!(
                "has a request validator this gateway cannot run: {}; answering 501",
                route
                    .validation
                    .unevaluable_reason()
                    .unwrap_or("it could not be compiled")
            ),
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
    /// The stage's API keys and usage plans; `None` when they cannot be read
    /// (HTTP APIs, and APIs read from a file).
    pub(crate) usage: Option<Arc<UsageStore>>,
    pub(crate) observer: StageObserver,
    /// Which release of a canary stage this context serves; `None` when the
    /// stage has no canary.
    pub(crate) release: Option<Release>,
    /// The deployment this release serves, when API Gateway named one.
    pub(crate) deployment_id: Option<String>,
    /// The ID of each REST resource by its path, when they could be read.
    pub(crate) resource_ids: Arc<BTreeMap<String, String>>,
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
        // A REST API reads an `Authorization` header no route claims as a
        // failed attempt at Signature Version 4.
        let failure = match (self.kind, error) {
            (ApiKind::Rest, GatewayError::NoRoute) => {
                UnclaimedSignature::of(&context.headers, &context.query)
                    .map(|unclaimed| unclaimed.failure(&context.headers, context.received))
            }
            _ => None,
        }
        .unwrap_or_else(|| error.failure(self.kind));
        let Some(ref cors) = self.cors else {
            return self.respond(&context, &failure);
        };
        if Cors::is_preflight(&context) {
            return cors.preflight(&context);
        }
        let mut response = self.respond(&context, &failure);
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
    /// A request template read the body as JSON and the body is broken JSON.
    UnprocessablePayload,
    /// The integration answered, but not in a form a response can be made
    /// from, such as a Lambda proxy response without a usable `statusCode`.
    MalformedIntegrationResponse,
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
    /// The integration host's name did not resolve. A deployed REST API calls that an
    /// API configuration error; what an HTTP API answers is not measured, so it keeps
    /// treating the integration as unreachable.
    pub(crate) const fn unresolvable_host(kind: ApiKind) -> Self {
        match kind {
            ApiKind::Rest => Self::ApiConfiguration,
            ApiKind::Http => Self::IntegrationUnreachable,
        }
    }

    pub(crate) fn failure(self, kind: ApiKind) -> Failure {
        match (self, kind) {
            (Self::NoRoute, ApiKind::Rest) => {
                Failure::new(ResponseType::MissingAuthenticationToken)
            }
            (Self::NoRoute, ApiKind::Http) => Failure::gateway(StatusCode::NOT_FOUND, "Not Found"),
            (Self::InvalidRequest, _) => Failure::new(ResponseType::Default4xx),
            // Both are a 502 `InternalServerErrorException` on a deployed REST
            // API, but `$context.error.responseType` tells them apart: a
            // function error is an `INTEGRATION_FAILURE`, an answer no
            // response can be made from is only a `DEFAULT_5XX`.
            (Self::IntegrationFailure, ApiKind::Rest) => {
                Failure::new(ResponseType::IntegrationFailure)
                    .with_status(StatusCode::BAD_GATEWAY)
                    .with_message("Internal server error")
                    .with_error_type("InternalServerErrorException")
            }
            (Self::MalformedIntegrationResponse, ApiKind::Rest) => {
                Failure::new(ResponseType::Default5xx)
                    .with_status(StatusCode::BAD_GATEWAY)
                    .with_error_type("InternalServerErrorException")
            }
            // A deployed HTTP API answers a function error, or a response it
            // can make nothing of, with a 500 worded this way.
            (Self::IntegrationFailure | Self::MalformedIntegrationResponse, ApiKind::Http) => {
                Failure::new(ResponseType::IntegrationFailure)
                    .with_status(StatusCode::INTERNAL_SERVER_ERROR)
                    .with_message("Internal Server Error")
            }
            (Self::IntegrationUnreachable, ApiKind::Http) => {
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
            // Measured against a deployed REST API: a 500 named
            // `InternalServerErrorException`, not `ApiConfigurationException`.
            (Self::ApiConfiguration, ApiKind::Rest) => {
                Failure::new(ResponseType::ApiConfigurationError)
                    .with_error_type("InternalServerErrorException")
            }
            (Self::ApiConfiguration, ApiKind::Http) => {
                Failure::new(ResponseType::ApiConfigurationError)
            }
            (Self::UnprocessablePayload, _) => Failure::new(ResponseType::Default4xx)
                .with_message("Could not process payload")
                .while_executing(),
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
        // The override is consumed: neither a Lambda event nor an HTTP
        // backend sees the header.
        request.headers_mut().remove("x-http-method-override");
    }

    /// The header carrying the request ID on every response.
    pub(crate) fn request_id_header(self) -> HeaderName {
        match self {
            Self::Rest => HeaderName::from_static("x-amzn-requestid"),
            Self::Http => HeaderName::from_static("apigw-requestid"),
        }
    }
}

impl RequestId {
    /// `$context.extendedRequestId` and the `x-amz-apigw-id` header. API
    /// Gateway's is an opaque base64 token; this one is derived from the random
    /// half of the request ID so the header and the context variable agree.
    pub(crate) fn extended(self) -> String {
        BASE64.encode(self.0.as_bytes().get(8..).unwrap_or_default())
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
        assert!(
            !rest.headers().contains_key("x-http-method-override"),
            "the override is consumed"
        );
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
