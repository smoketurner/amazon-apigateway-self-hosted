//! API Gateway's own error responses.
//!
//! Every response the gateway generates instead of forwarding a backend's goes
//! through [`GatewayResponses::render`]. REST APIs let their owners customize
//! each [`ResponseType`] (status, headers, body template); HTTP APIs answer with
//! fixed messages. See
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-gatewayResponse-definition.html>.

use std::borrow::Cow;
use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use serde_json::json;

use crate::integration::ParamSource;
use crate::model::{ApiKind, GatewayResponseSpec, ResponseType};
use crate::pipeline::RequestContext;
use crate::pipeline::context::ContextVariables;

const ERROR_TYPE_HEADER: HeaderName = HeaderName::from_static("x-amzn-errortype");
const EXTENDED_REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-amz-apigw-id");
const HEADER_PARAMETER_PREFIX: &str = "gatewayresponse.header.";
const JSON: &str = "application/json";
/// What API Gateway uses when a response has no template of its own.
const DEFAULT_TEMPLATE: &str = r#"{"message":$context.error.messageString}"#;

impl ResponseType {
    /// The status API Gateway answers with unless the API customizes it. The
    /// two fallback types have no status of their own; the values here are the
    /// generic 4xx and 5xx codes.
    pub(crate) const fn default_status(self) -> StatusCode {
        match self {
            Self::BadRequestBody | Self::BadRequestParameters | Self::Default4xx => {
                StatusCode::BAD_REQUEST
            }
            Self::Unauthorized => StatusCode::UNAUTHORIZED,
            Self::AccessDenied
            | Self::ExpiredToken
            | Self::InvalidApiKey
            | Self::InvalidSignature
            | Self::MissingAuthenticationToken
            | Self::WafFiltered => StatusCode::FORBIDDEN,
            Self::ResourceNotFound => StatusCode::NOT_FOUND,
            Self::RequestTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Self::QuotaExceeded | Self::Throttled => StatusCode::TOO_MANY_REQUESTS,
            Self::ApiConfigurationError
            | Self::AuthorizerConfigurationError
            | Self::AuthorizerFailure
            | Self::Default5xx => StatusCode::INTERNAL_SERVER_ERROR,
            Self::IntegrationFailure | Self::IntegrationTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// The `message` API Gateway uses unless the API customizes the body.
    pub(crate) const fn default_message(self) -> &'static str {
        match self {
            Self::AccessDenied => {
                "User is not authorized to access this resource with an explicit deny"
            }
            Self::ApiConfigurationError
            | Self::AuthorizerConfigurationError
            | Self::AuthorizerFailure
            | Self::Default5xx => "Internal server error",
            Self::BadRequestBody => "Invalid request body",
            Self::BadRequestParameters => "Missing required request parameters",
            Self::Default4xx => "Bad Request",
            Self::ExpiredToken => "The security token included in the request is expired",
            Self::IntegrationFailure => "Network error communicating with endpoint",
            Self::IntegrationTimeout => "Endpoint request timed out",
            Self::InvalidApiKey | Self::WafFiltered => "Forbidden",
            Self::InvalidSignature => {
                "The request signature we calculated does not match the signature you provided. Check your AWS Secret Access Key and signing method. Consult the service documentation for details."
            }
            Self::MissingAuthenticationToken => "Missing Authentication Token",
            Self::QuotaExceeded => "Limit Exceeded",
            Self::RequestTooLarge => "HTTP content length exceeded 10485760 bytes",
            Self::ResourceNotFound => "Not Found",
            Self::Throttled => "Too Many Requests",
            Self::Unauthorized => "Unauthorized",
            Self::UnsupportedMediaType => "Unsupported Media Type",
        }
    }

    /// The `x-amzn-ErrorType` header value API Gateway sets on this response.
    pub(crate) const fn error_type(self) -> &'static str {
        match self {
            Self::AccessDenied => "AccessDeniedException",
            Self::ApiConfigurationError => "ApiConfigurationException",
            Self::AuthorizerConfigurationError => "AuthorizerConfigurationException",
            Self::AuthorizerFailure => "AuthorizerFailureException",
            Self::BadRequestBody | Self::BadRequestParameters | Self::Default4xx => {
                "BadRequestException"
            }
            Self::Default5xx => "InternalFailureException",
            Self::ExpiredToken => "ExpiredTokenException",
            Self::IntegrationFailure => "IntegrationFailureException",
            Self::IntegrationTimeout => "IntegrationTimeoutException",
            Self::InvalidApiKey => "ForbiddenException",
            Self::InvalidSignature => "InvalidSignatureException",
            Self::MissingAuthenticationToken => "MissingAuthenticationTokenException",
            Self::QuotaExceeded => "LimitExceededException",
            Self::RequestTooLarge => "RequestTooLargeException",
            Self::ResourceNotFound => "NotFoundException",
            Self::Throttled => "ThrottlingException",
            Self::Unauthorized => "UnauthorizedException",
            Self::UnsupportedMediaType => "UnsupportedMediaTypeException",
            Self::WafFiltered => "WafFilteredException",
        }
    }

    /// The type whose customization applies when this type has none.
    /// `REQUEST_TOO_LARGE` is never customizable and has no fallback.
    pub(crate) const fn fallback(self) -> Option<Self> {
        match self {
            Self::Default4xx | Self::Default5xx | Self::RequestTooLarge => None,
            Self::AccessDenied
            | Self::BadRequestBody
            | Self::BadRequestParameters
            | Self::ExpiredToken
            | Self::InvalidApiKey
            | Self::InvalidSignature
            | Self::MissingAuthenticationToken
            | Self::QuotaExceeded
            | Self::ResourceNotFound
            | Self::Throttled
            | Self::Unauthorized
            | Self::UnsupportedMediaType
            | Self::WafFiltered => Some(Self::Default4xx),
            Self::ApiConfigurationError
            | Self::AuthorizerConfigurationError
            | Self::AuthorizerFailure
            | Self::IntegrationFailure
            | Self::IntegrationTimeout => Some(Self::Default5xx),
        }
    }

    /// API Gateway does not let APIs customize the 413 response.
    pub(crate) const fn customizable(self) -> bool {
        !matches!(self, Self::RequestTooLarge)
    }
}

/// Which kind of response a [`Failure`] is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    /// One of API Gateway's response types.
    Aws(ResponseType),
    /// Something this gateway answers that API Gateway has no response type
    /// for, such as a feature it cannot execute. Never customizable.
    Gateway,
}

/// An error the gateway answers a request with. Carries the API Gateway
/// defaults for its type, which the caller may refine, and which an API's
/// customizations may override.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    origin: Origin,
    status: StatusCode,
    message: Cow<'static, str>,
}

impl Failure {
    /// A failure of `response_type` with API Gateway's default status and message.
    pub(crate) fn new(response_type: ResponseType) -> Self {
        Self {
            origin: Origin::Aws(response_type),
            status: response_type.default_status(),
            message: Cow::Borrowed(response_type.default_message()),
        }
    }

    /// A response with no API Gateway counterpart.
    pub(crate) const fn gateway(status: StatusCode, message: &'static str) -> Self {
        Self {
            origin: Origin::Gateway,
            status,
            message: Cow::Borrowed(message),
        }
    }

    #[must_use]
    pub(crate) fn with_status(mut self, status: StatusCode) -> Self {
        self.status = status;
        self
    }

    #[must_use]
    pub(crate) fn with_message(mut self, message: impl Into<Cow<'static, str>>) -> Self {
        self.message = message.into();
        self
    }

    fn response_type(&self) -> Option<ResponseType> {
        match self.origin {
            Origin::Aws(response_type) => Some(response_type),
            Origin::Gateway => None,
        }
    }
}

/// A gateway response body template. Gateway responses are not run through
/// VTL: only `$context.*`, `$stageVariables.*`, and `$method.request.*`
/// references are substituted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Template(String);

/// What template references resolve against.
struct TemplateScope<'a> {
    context: ContextVariables,
    request: &'a RequestContext,
}

impl TemplateScope<'_> {
    /// `None` when `name` isn't a reference this scope owns, so the text stays
    /// as written (`$5.00` is a price, not a variable).
    fn resolve(&self, name: &str) -> Option<String> {
        if let Some(path) = name.strip_prefix("context.") {
            return Some(self.context.lookup(path).unwrap_or_default());
        }
        if let Some(variable) = name.strip_prefix("stageVariables.") {
            return Some(
                self.request
                    .stage_variables
                    .get(variable)
                    .unwrap_or_default()
                    .to_owned(),
            );
        }
        if name.starts_with("method.request.") {
            return Some(
                ParamSource::parse(name)
                    .and_then(|source| source.resolve(self.request))
                    .unwrap_or_default(),
            );
        }
        None
    }
}

impl Template {
    fn is_reference_char(c: char) -> bool {
        c.is_ascii_alphanumeric() || c == '_' || c == '.'
    }

    fn render(&self, scope: &TemplateScope<'_>) -> String {
        let mut out = String::with_capacity(self.0.len());
        let mut rest = self.0.as_str();
        while let Some(start) = rest.find('$') {
            let (before, dollar_and_after) = rest.split_at(start);
            out.push_str(before);
            let after = dollar_and_after
                .strip_prefix('$')
                .unwrap_or(dollar_and_after);
            let (name, consumed) = Self::reference(after);
            let (written, tail) = after.split_at(consumed);
            if let Some(value) = scope.resolve(name) {
                out.push_str(&value);
            } else {
                out.push('$');
                out.push_str(written);
            }
            rest = tail;
        }
        out.push_str(rest);
        out
    }

    /// The reference at the start of `text` (just after a `$`) and how many
    /// bytes it spans. `${name}` takes the braces off; a bare name stops
    /// before trailing dots so a sentence-ending `.` stays text.
    fn reference(text: &str) -> (&str, usize) {
        if let Some(braced) = text.strip_prefix('{') {
            return match braced.split_once('}') {
                Some((name, _)) => (name, name.len().saturating_add(2)),
                None => ("", 0),
            };
        }
        let end = text
            .char_indices()
            .find(|&(_, c)| !Self::is_reference_char(c))
            .map_or(text.len(), |(index, _)| index);
        let name = text.split_at(end).0.trim_end_matches('.');
        (name, name.len())
    }
}

/// One customized response type, compiled from its `GatewayResponseSpec`.
#[derive(Debug, Clone, Default)]
struct CustomResponse {
    status: Option<StatusCode>,
    headers: Vec<(HeaderName, ParamSource)>,
    templates: BTreeMap<String, Template>,
}

impl CustomResponse {
    fn compile(response_type: ResponseType, spec: &GatewayResponseSpec) -> Self {
        let status = spec.status_code.as_ref().and_then(|_| {
            let status = spec.status().and_then(|s| StatusCode::from_u16(s).ok());
            if status.is_none() {
                tracing::warn!(%response_type, "ignoring invalid gateway response status code");
            }
            status
        });
        let mut headers = Vec::new();
        for (target, source) in &spec.response_parameters {
            let Some(name) = target.strip_prefix(HEADER_PARAMETER_PREFIX) else {
                tracing::warn!(%response_type, target, "ignoring unsupported gateway response parameter");
                continue;
            };
            let (Ok(name), Some(source)) = (HeaderName::try_from(name), ParamSource::parse(source))
            else {
                tracing::warn!(%response_type, target, source, "ignoring unsupported gateway response header");
                continue;
            };
            headers.push((name, source));
        }
        let templates = spec
            .response_templates
            .iter()
            .filter_map(|(content_type, template)| {
                template
                    .as_ref()
                    .map(|template| (content_type.clone(), Template(template.clone())))
            })
            .collect();
        Self {
            status,
            headers,
            templates,
        }
    }

    /// The template for the first of the client's `Accept` types this response
    /// has one for, else its `application/json` template.
    fn template_for(&self, accept: Option<&str>) -> Option<(&str, &Template)> {
        for media_type in accept.unwrap_or_default().split(',') {
            let media_type = media_type.split(';').next().unwrap_or_default().trim();
            if let Some((content_type, template)) = self
                .templates
                .iter()
                .find(|(content_type, _)| content_type.eq_ignore_ascii_case(media_type))
            {
                return Some((content_type, template));
            }
        }
        self.templates
            .get_key_value(JSON)
            .map(|(content_type, template)| (content_type.as_str(), template))
    }
}

/// The gateway responses an API customizes, ready to render failures with.
#[derive(Debug, Clone, Default)]
pub(crate) struct GatewayResponses {
    custom: BTreeMap<ResponseType, CustomResponse>,
}

impl GatewayResponses {
    /// Compiles an export's customizations. HTTP APIs have none: their
    /// responses are fixed. Unknown or non-customizable types are skipped.
    pub(crate) fn compile(kind: ApiKind, specs: &BTreeMap<String, GatewayResponseSpec>) -> Self {
        let mut custom = BTreeMap::new();
        if kind == ApiKind::Http {
            return Self { custom };
        }
        for (name, spec) in specs {
            let Ok(response_type) = ResponseType::try_from(name.clone()) else {
                tracing::warn!(name, "ignoring unknown gateway response type");
                continue;
            };
            if !response_type.customizable() {
                tracing::warn!(%response_type, "ignoring customization of a gateway response API Gateway does not allow customizing");
                continue;
            }
            custom.insert(response_type, CustomResponse::compile(response_type, spec));
        }
        Self { custom }
    }

    /// The customization that governs `failure` and the one for its fallback type.
    fn lookup(
        &self,
        response_type: Option<ResponseType>,
    ) -> (Option<&CustomResponse>, Option<&CustomResponse>) {
        let Some(response_type) = response_type else {
            return (None, None);
        };
        let own = self.custom.get(&response_type);
        let fallback = response_type
            .fallback()
            .and_then(|fallback| self.custom.get(&fallback));
        (own, fallback)
    }

    /// Builds the response for `failure` on `request`.
    ///
    /// The response of the failure's own type governs when the API customized
    /// it, otherwise `DEFAULT_4XX`/`DEFAULT_5XX`'s does. A status set on the
    /// fallback type also applies to a customized type that sets none.
    pub(crate) fn render(&self, failure: &Failure, request: &RequestContext) -> Response {
        if request.api.kind == ApiKind::Http {
            return Self::plain(failure.status, &failure.message);
        }
        let (own, fallback) = self.lookup(failure.response_type());
        let governing = own.or(fallback);
        let status = own
            .and_then(|c| c.status)
            .or_else(|| fallback.and_then(|c| c.status))
            .unwrap_or(failure.status);

        let mut context = ContextVariables::new(request.variables());
        context.set(
            "error",
            json!({
                "message": failure.message,
                "messageString": json!(failure.message).to_string(),
                "responseType": failure.response_type().map(ResponseType::as_str),
            }),
        );
        let scope = TemplateScope { context, request };
        let accept = request.header_str("accept");
        let chosen = governing.and_then(|c| c.template_for(accept));
        let (content_type, body) = match chosen {
            Some((content_type, template)) => (content_type, template.render(&scope)),
            None => (JSON, Template(DEFAULT_TEMPLATE.to_owned()).render(&scope)),
        };

        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        let headers = response.headers_mut();
        if let Some(response_type) = failure.response_type() {
            headers.insert(
                ERROR_TYPE_HEADER,
                HeaderValue::from_static(response_type.error_type()),
            );
        }
        if let Ok(id) = HeaderValue::try_from(request.extended_request_id()) {
            headers.insert(EXTENDED_REQUEST_ID_HEADER, id);
        }
        if let Ok(content_type) = HeaderValue::try_from(content_type) {
            headers.insert(header::CONTENT_TYPE, content_type);
        }
        for (name, source) in governing.map_or(&[][..], |c| c.headers.as_slice()) {
            let Some(value) = source.resolve(request) else {
                continue;
            };
            match HeaderValue::try_from(value) {
                Ok(value) => {
                    headers.insert(name.clone(), value);
                }
                Err(_) => {
                    tracing::warn!(header = %name, "gateway response header value is not valid");
                }
            }
        }
        response
    }

    /// The fixed `{"message": ...}` body of HTTP APIs.
    fn plain(status: StatusCode, message: &str) -> Response {
        let mut response = Response::new(Body::from(json!({ "message": message }).to_string()));
        *response.status_mut() = status;
        response
            .headers_mut()
            .insert(header::CONTENT_TYPE, HeaderValue::from_static(JSON));
        response
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known headers")]
mod tests {
    use std::sync::Arc;

    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::*;
    use crate::gateway::GatewayError;
    use crate::integration::StageVariables;
    use crate::pipeline::context::tests::request;

    async fn body(response: Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn responses(specs: &Value) -> GatewayResponses {
        let specs: BTreeMap<String, GatewayResponseSpec> =
            serde_json::from_value(specs.clone()).unwrap();
        GatewayResponses::compile(ApiKind::Rest, &specs)
    }

    fn rest_request() -> RequestContext {
        let mut ctx = request(ApiKind::Rest);
        ctx.stage_variables = Arc::new(StageVariables::new(BTreeMap::from([(
            "a".to_owned(),
            "stage-a".to_owned(),
        )])));
        ctx.headers
            .insert("origin", HeaderValue::from_static("https://app.example"));
        ctx
    }

    #[tokio::test]
    async fn default_responses_match_api_gateway() {
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
                GatewayError::IntegrationFailure,
                ApiKind::Http,
                502,
                "Internal server error",
            ),
            (
                GatewayError::IntegrationUnreachable,
                ApiKind::Rest,
                504,
                "Network error communicating with endpoint",
            ),
            (
                GatewayError::IntegrationUnreachable,
                ApiKind::Http,
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
                GatewayError::ApiConfiguration,
                ApiKind::Rest,
                500,
                "Internal server error",
            ),
            (
                GatewayError::RequestTooLarge,
                ApiKind::Rest,
                413,
                "HTTP content length exceeded 10485760 bytes",
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
            let response = GatewayResponses::default().render(&error.failure(kind), &request(kind));
            assert_eq!(response.status().as_u16(), status, "{error:?} {kind:?}");
            assert_eq!(response.headers()["content-type"], "application/json");
            assert_eq!(
                body(response).await,
                json!({ "message": message }).to_string(),
                "{error:?} {kind:?}"
            );
        }
    }

    #[test]
    fn rest_errors_carry_error_type_and_extended_request_id() {
        let ctx = request(ApiKind::Rest);
        let response =
            GatewayResponses::default().render(&GatewayError::NoRoute.failure(ApiKind::Rest), &ctx);
        assert_eq!(
            response.headers()["x-amzn-errortype"],
            "MissingAuthenticationTokenException"
        );
        assert_eq!(
            response.headers()["x-amz-apigw-id"].to_str().unwrap(),
            ctx.extended_request_id()
        );
        assert_eq!(ctx.extended_request_id().len(), 12);
    }

    #[test]
    fn http_errors_have_no_rest_error_headers() {
        let response = GatewayResponses::default().render(
            &GatewayError::NoRoute.failure(ApiKind::Http),
            &request(ApiKind::Http),
        );
        assert!(response.headers().get("x-amzn-errortype").is_none());
        assert!(response.headers().get("x-amz-apigw-id").is_none());
    }

    #[test]
    fn gateway_specific_failures_have_no_error_type() {
        let failure = GatewayError::UnsupportedIntegration.failure(ApiKind::Rest);
        let response = GatewayResponses::default().render(&failure, &request(ApiKind::Rest));
        assert!(response.headers().get("x-amzn-errortype").is_none());
    }

    #[test]
    fn default_statuses_follow_the_documented_table() {
        let table = [
            (ResponseType::AccessDenied, 403),
            (ResponseType::ApiConfigurationError, 500),
            (ResponseType::AuthorizerConfigurationError, 500),
            (ResponseType::AuthorizerFailure, 500),
            (ResponseType::BadRequestParameters, 400),
            (ResponseType::BadRequestBody, 400),
            (ResponseType::ExpiredToken, 403),
            (ResponseType::IntegrationFailure, 504),
            (ResponseType::IntegrationTimeout, 504),
            (ResponseType::InvalidApiKey, 403),
            (ResponseType::InvalidSignature, 403),
            (ResponseType::MissingAuthenticationToken, 403),
            (ResponseType::QuotaExceeded, 429),
            (ResponseType::RequestTooLarge, 413),
            (ResponseType::ResourceNotFound, 404),
            (ResponseType::Throttled, 429),
            (ResponseType::Unauthorized, 401),
            (ResponseType::UnsupportedMediaType, 415),
            (ResponseType::WafFiltered, 403),
        ];
        for (response_type, status) in table {
            assert_eq!(
                response_type.default_status().as_u16(),
                status,
                "{response_type}"
            );
            let expected = match status {
                413 => None,
                400..=499 => Some(ResponseType::Default4xx),
                _ => Some(ResponseType::Default5xx),
            };
            assert_eq!(response_type.fallback(), expected, "{response_type}");
        }
        assert!(!ResponseType::RequestTooLarge.customizable());
    }

    #[tokio::test]
    async fn customization_sets_status_headers_and_template() {
        let responses = responses(&json!({
            "MISSING_AUTHENTICATION_TOKEN": {
                "statusCode": "404",
                "responseParameters": {
                    "gatewayresponse.header.Access-Control-Allow-Origin": "'*'",
                    "gatewayresponse.header.x-origin": "method.request.header.Origin",
                    "gatewayresponse.header.x-stage": "context.stage",
                    "gatewayresponse.header.x-var": "stageVariables.a"
                },
                "responseTemplates": {
                    "application/json": "{\"message\": $context.error.messageString, \"type\": \"$context.error.responseType\", \"stage\": \"$context.stage\", \"var\": \"$stageVariables.a\", \"origin\": \"$method.request.header.origin\"}"
                }
            }
        }));
        let failure = GatewayError::NoRoute.failure(ApiKind::Rest);
        let response = responses.render(&failure, &rest_request());
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let headers = response.headers().clone();
        assert_eq!(headers["access-control-allow-origin"], "*");
        assert_eq!(headers["x-origin"], "https://app.example");
        assert_eq!(headers["x-stage"], "prod");
        assert_eq!(headers["x-var"], "stage-a");
        assert_eq!(
            headers["x-amzn-errortype"],
            "MissingAuthenticationTokenException"
        );
        assert_eq!(
            body(response).await,
            r#"{"message": "Missing Authentication Token", "type": "MISSING_AUTHENTICATION_TOKEN", "stage": "prod", "var": "stage-a", "origin": "https://app.example"}"#
        );
    }

    #[tokio::test]
    async fn default_4xx_governs_unspecified_4xx_types_only() {
        let responses = responses(&json!({
            "DEFAULT_4XX": {
                "statusCode": "418",
                "responseParameters": {"gatewayresponse.header.x-default": "'4xx'"},
                "responseTemplates": {"application/json": "{\"e\":\"$context.error.responseType\"}"}
            },
            "UNAUTHORIZED": {"statusCode": "499"}
        }));
        let ctx = rest_request();
        let denied = responses.render(&Failure::new(ResponseType::AccessDenied), &ctx);
        assert_eq!(denied.status().as_u16(), 418);
        assert_eq!(denied.headers()["x-default"], "4xx");
        assert_eq!(body(denied).await, r#"{"e":"ACCESS_DENIED"}"#);

        let unauthorized = responses.render(&Failure::new(ResponseType::Unauthorized), &ctx);
        assert_eq!(unauthorized.status().as_u16(), 499);
        assert!(unauthorized.headers().get("x-default").is_none());
        assert_eq!(body(unauthorized).await, r#"{"message":"Unauthorized"}"#);

        let timeout = responses.render(&Failure::new(ResponseType::IntegrationTimeout), &ctx);
        assert_eq!(timeout.status().as_u16(), 504);
        assert!(timeout.headers().get("x-default").is_none());
    }

    #[test]
    fn default_5xx_status_applies_to_customized_types_without_one() {
        let responses = responses(&json!({
            "DEFAULT_5XX": {"statusCode": "599"},
            "INTEGRATION_TIMEOUT": {}
        }));
        let ctx = rest_request();
        for response_type in [
            ResponseType::IntegrationTimeout,
            ResponseType::AuthorizerFailure,
        ] {
            let response = responses.render(&Failure::new(response_type), &ctx);
            assert_eq!(response.status().as_u16(), 599, "{response_type}");
        }
        let unrelated = responses.render(&Failure::new(ResponseType::Throttled), &ctx);
        assert_eq!(unrelated.status().as_u16(), 429);
    }

    #[test]
    fn request_too_large_cannot_be_customized() {
        let responses = responses(&json!({
            "REQUEST_TOO_LARGE": {"statusCode": "400"},
            "DEFAULT_4XX": {"statusCode": "418"}
        }));
        let failure = GatewayError::RequestTooLarge.failure(ApiKind::Rest);
        let response = responses.render(&failure, &rest_request());
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[test]
    fn http_apis_ignore_customizations() {
        let specs: BTreeMap<String, GatewayResponseSpec> =
            serde_json::from_value(json!({"MISSING_AUTHENTICATION_TOKEN": {"statusCode": "404"}}))
                .unwrap();
        let responses = GatewayResponses::compile(ApiKind::Http, &specs);
        let failure = Failure::new(ResponseType::MissingAuthenticationToken);
        let response = responses.render(&failure, &request(ApiKind::Http));
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let rest = GatewayResponses::compile(ApiKind::Rest, &specs);
        assert_eq!(
            rest.render(&failure, &request(ApiKind::Rest)).status(),
            StatusCode::NOT_FOUND
        );
    }

    #[test]
    fn gateway_specific_failures_ignore_default_customizations() {
        let responses = responses(&json!({"DEFAULT_5XX": {"statusCode": "599"}}));
        let failure = GatewayError::UnsupportedIntegration.failure(ApiKind::Rest);
        assert_eq!(
            responses.render(&failure, &rest_request()).status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[tokio::test]
    async fn template_is_chosen_by_accept_then_json() {
        let responses = responses(&json!({
            "DEFAULT_4XX": {"responseTemplates": {
                "application/json": "{\"j\":1}",
                "text/plain": "plain $context.error.message"
            }}
        }));
        let failure = Failure::new(ResponseType::Throttled);
        let mut ctx = rest_request();
        let json_response = responses.render(&failure, &ctx);
        assert_eq!(body(json_response).await, r#"{"j":1}"#);
        ctx.headers.insert(
            "accept",
            HeaderValue::from_static("text/html, text/plain;q=0.9"),
        );
        let text = responses.render(&failure, &ctx);
        assert_eq!(text.headers()["content-type"], "text/plain");
        assert_eq!(body(text).await, "plain Too Many Requests");
    }

    #[test]
    fn invalid_customizations_are_skipped() {
        let responses = responses(&json!({
            "NOT_A_TYPE": {"statusCode": "404"},
            "THROTTLED": {
                "statusCode": "not-a-number",
                "responseParameters": {
                    "method.response.header.x": "'1'",
                    "gatewayresponse.header.bad name": "'1'",
                    "gatewayresponse.header.x-unknown-source": "integration.response.body.id"
                }
            }
        }));
        let response = responses.render(&Failure::new(ResponseType::Throttled), &rest_request());
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(response.headers().get("x-unknown-source").is_none());
    }

    fn render_text(text: &str) -> String {
        let request = rest_request();
        let scope = TemplateScope {
            context: ContextVariables::new(request.variables()),
            request: &request,
        };
        Template(text.to_owned()).render(&scope)
    }

    #[test]
    fn template_substitution_rules() {
        assert_eq!(render_text("costs $5.00"), "costs $5.00");
        assert_eq!(render_text("stage is $context.stage."), "stage is prod.");
        assert_eq!(render_text("${context.stage}x"), "prodx");
        assert_eq!(render_text("[$context.missing]"), "[]");
        assert_eq!(render_text("[$stageVariables.nope]"), "[]");
        assert_eq!(render_text("$ $"), "$ $");
        assert_eq!(render_text("${context.stage"), "${context.stage");
        assert_eq!(
            render_text("\u{e9}$context.stage\u{e9}"),
            "\u{e9}prod\u{e9}"
        );
        assert_eq!(render_text("$context.identity.sourceIp"), "192.0.2.1");
    }

    proptest! {
        #[test]
        fn template_rendering_never_panics(text in ".*") {
            drop(render_text(&text));
        }
    }
}
