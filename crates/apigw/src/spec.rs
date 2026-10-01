//! Translates an API Gateway `OpenAPI` 3.0 export (with `x-amazon-apigateway-*`
//! extensions) into the route table the gateway serves.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;

const ANY_METHOD_KEY: &str = "x-amazon-apigateway-any-method";
const HTTP_API_DEFAULT_ROUTE: &str = "/$default";
const REST_DEFAULT_TIMEOUT: Duration = Duration::from_secs(29);
const HTTP_DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Which API Gateway product the definition came from. The two differ in Lambda
/// payload defaults, error bodies, and response headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ApiKind {
    /// API Gateway REST API (v1).
    Rest,
    /// API Gateway HTTP API (v2).
    Http,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SpecError {
    #[error("the export is not a valid OpenAPI document: {0}")]
    Json(#[from] serde_json::Error),
    #[error("integration override for {route_key:?} is invalid: {source}")]
    InvalidOverride {
        route_key: String,
        source: serde_json::Error,
    },
    #[error("integration overrides name routes that do not exist: {}", .0.join(", "))]
    UnknownOverrides(Vec<String>),
}

/// Local replacements for integrations, keyed by API Gateway route key
/// (`GET /pets/{petId}`, `ANY /{proxy+}`, `$default`). Each value has the shape
/// of an `x-amazon-apigateway-integration` object.
pub(crate) type IntegrationOverrides = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MethodMatch {
    Any,
    Exact(Method),
}

impl fmt::Display for MethodMatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("ANY"),
            Self::Exact(method) => f.write_str(method.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RoutePath {
    /// The HTTP API `$default` catch-all route.
    Default,
    /// An API Gateway resource path such as `/pets/{petId}` or `/{proxy+}`.
    Resource(String),
}

impl fmt::Display for RoutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("$default"),
            Self::Resource(path) => f.write_str(path),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PayloadVersion {
    V1,
    V2,
}

#[derive(Debug, Clone)]
pub(crate) struct Route {
    pub(crate) method: MethodMatch,
    pub(crate) path: RoutePath,
    pub(crate) integration: Integration,
    pub(crate) protections: Protections,
}

impl Route {
    /// The route key in API Gateway's own notation, e.g. `GET /pets/{petId}`.
    pub(crate) fn route_key(&self) -> String {
        route_key(&self.method, &self.path)
    }
}

/// An access control API Gateway applies to a route before its integration.
/// Variants are declared in the order API Gateway evaluates them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Protection {
    ResourcePolicy,
    Iam,
    Authorizer,
    ApiKey,
    RequestValidation,
}

/// The protections on one route, iterated in evaluation order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub(crate) struct Protections(BTreeSet<Protection>);

impl Protections {
    #[cfg(test)]
    pub(crate) fn contains(&self, protection: Protection) -> bool {
        self.0.contains(&protection)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = Protection> + '_ {
        self.0.iter().copied()
    }

    fn insert(&mut self, protection: Protection) {
        self.0.insert(protection);
    }
}

impl FromIterator<Protection> for Protections {
    fn from_iter<I: IntoIterator<Item = Protection>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Integration {
    HttpProxy(HttpProxy),
    Mock(MockResponse),
    Lambda(LambdaProxy),
    Unsupported { reason: String },
}

impl Integration {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::HttpProxy(_) => "HTTP_PROXY",
            Self::Mock(_) => "MOCK",
            Self::Lambda(_) => "AWS_PROXY",
            Self::Unsupported { .. } => "UNSUPPORTED",
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HttpProxy {
    /// `None` forwards the client's method (`ANY` in API Gateway).
    pub(crate) method: Option<Method>,
    /// Target URI; `{name}` placeholders are filled from `path_params`.
    pub(crate) uri: String,
    pub(crate) path_params: BTreeMap<String, ParamSource>,
    pub(crate) query_params: BTreeMap<String, ParamSource>,
    pub(crate) headers: BTreeMap<String, ParamSource>,
    pub(crate) timeout: Duration,
}

/// The right-hand side of an API Gateway `requestParameters` mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParamSource {
    Path(String),
    Query(String),
    Header(String),
    Literal(String),
}

impl ParamSource {
    fn parse(expr: &str) -> Option<Self> {
        if let Some(literal) = expr.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            return Some(Self::Literal(literal.to_owned()));
        }
        if let Some(name) = expr.strip_prefix("method.request.path.") {
            return Some(Self::Path(name.to_owned()));
        }
        if let Some(name) = expr.strip_prefix("method.request.querystring.") {
            return Some(Self::Query(name.to_owned()));
        }
        if let Some(name) = expr.strip_prefix("method.request.header.") {
            return Some(Self::Header(name.to_owned()));
        }
        None
    }
}

#[derive(Debug, Clone)]
pub(crate) struct MockResponse {
    pub(crate) status: StatusCode,
    pub(crate) headers: Vec<(HeaderName, HeaderValue)>,
    pub(crate) content_type: Option<HeaderValue>,
    pub(crate) body: String,
}

#[derive(Debug, Clone)]
pub(crate) struct LambdaProxy {
    pub(crate) function: String,
    pub(crate) payload: PayloadVersion,
    pub(crate) timeout: Duration,
}

#[derive(Debug, Clone)]
pub(crate) struct ApiDefinition {
    pub(crate) routes: Vec<Route>,
}

#[derive(Deserialize)]
struct Document {
    #[serde(default)]
    paths: BTreeMap<String, BTreeMap<String, Value>>,
    #[serde(default)]
    security: Option<SecurityRequirements>,
    #[serde(default)]
    components: Components,
    #[serde(rename = "x-amazon-apigateway-policy")]
    policy: Option<ResourcePolicy>,
    #[serde(rename = "x-amazon-apigateway-request-validators", default)]
    validators: RequestValidators,
    #[serde(rename = "x-amazon-apigateway-request-validator")]
    default_validator: Option<ValidatorName>,
}

impl Document {
    /// The protections API Gateway applies to `operation`.
    fn protections(&self, kind: ApiKind, operation: &Operation) -> Protections {
        // HTTP APIs apply the document-level `security` to every route; REST APIs
        // only honor per-method requirements.
        let security = match kind {
            ApiKind::Rest => operation.security.as_ref(),
            ApiKind::Http => operation.security.as_ref().or(self.security.as_ref()),
        };
        let mut protections = security.map_or_else(Protections::default, |requirements| {
            requirements.protections(&self.components.security_schemes)
        });
        if self
            .policy
            .as_ref()
            .is_some_and(ResourcePolicy::has_statements)
        {
            protections.insert(Protection::ResourcePolicy);
        }
        let validator = operation
            .validator
            .as_ref()
            .or(self.default_validator.as_ref());
        if validator.is_some_and(|name| self.validators.validates(name)) {
            protections.insert(Protection::RequestValidation);
        }
        protections
    }
}

/// `x-amazon-apigateway-policy`: an IAM policy document, embedded as an object or
/// as a JSON-encoded string.
#[derive(Deserialize)]
#[serde(transparent)]
struct ResourcePolicy(Value);

impl ResourcePolicy {
    fn has_statements(&self) -> bool {
        let parsed;
        let document = match self.0 {
            Value::Null => return false,
            Value::String(ref text) => match serde_json::from_str::<Value>(text) {
                Ok(value) => {
                    parsed = value;
                    &parsed
                }
                Err(_) => return !text.trim().is_empty(),
            },
            Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => &self.0,
        };
        match document.get("Statement") {
            Some(Value::Array(statements)) => !statements.is_empty(),
            Some(Value::Null) | None => false,
            Some(_) => true,
        }
    }
}

/// A method's (or HTTP API document's) `security` list. Alternatives are OR-ed;
/// the schemes inside one alternative are AND-ed.
#[derive(Deserialize)]
#[serde(transparent)]
struct SecurityRequirements(Vec<BTreeMap<String, Value>>);

impl SecurityRequirements {
    /// An empty requirement object (`[{}]`) makes authentication optional, so the
    /// route is only protected when every alternative names a scheme.
    fn protections(&self, schemes: &SecuritySchemes) -> Protections {
        let mut protections = Protections::default();
        if self.0.is_empty() || self.0.iter().any(BTreeMap::is_empty) {
            return protections;
        }
        for name in self.0.iter().flat_map(BTreeMap::keys) {
            protections.insert(schemes.protection(name));
        }
        protections
    }
}

#[derive(Deserialize, Default)]
#[serde(transparent)]
struct SecuritySchemes(BTreeMap<String, SecurityScheme>);

impl SecuritySchemes {
    /// Schemes the document doesn't declare count as authorizers so the route
    /// fails closed.
    fn protection(&self, name: &str) -> Protection {
        self.0
            .get(name)
            .map_or(Protection::Authorizer, SecurityScheme::protection)
    }
}

#[derive(Deserialize)]
struct SecurityScheme {
    #[serde(rename = "type")]
    scheme_type: Option<String>,
    #[serde(rename = "x-amazon-apigateway-authtype")]
    auth_type: Option<String>,
    #[serde(rename = "x-amazon-apigateway-authorizer")]
    authorizer: Option<Value>,
}

impl SecurityScheme {
    /// How this scheme authenticates callers.
    fn protection(&self) -> Protection {
        let auth_type = self.auth_type.as_deref();
        if auth_type.is_some_and(|t| t.eq_ignore_ascii_case("awsSigv4")) {
            Protection::Iam
        } else if self.authorizer.is_none()
            && auth_type.is_none()
            && self.scheme_type.as_deref() == Some("apiKey")
        {
            Protection::ApiKey
        } else {
            Protection::Authorizer
        }
    }
}

#[derive(Deserialize, Default)]
struct Components {
    #[serde(rename = "securitySchemes", default)]
    security_schemes: SecuritySchemes,
}

#[derive(Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(transparent)]
struct ValidatorName(String);

#[derive(Deserialize, Default)]
#[serde(transparent)]
struct RequestValidators(BTreeMap<ValidatorName, RawValidator>);

impl RequestValidators {
    /// A name with no definition counts as validating so the route fails closed.
    fn validates(&self, name: &ValidatorName) -> bool {
        self.0.get(name).is_none_or(RawValidator::validates)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawValidator {
    #[serde(default)]
    validate_request_body: bool,
    #[serde(default)]
    validate_request_parameters: bool,
}

impl RawValidator {
    fn validates(&self) -> bool {
        self.validate_request_body || self.validate_request_parameters
    }
}

#[derive(Deserialize)]
struct Operation {
    #[serde(rename = "x-amazon-apigateway-integration")]
    integration: Option<RawIntegration>,
    #[serde(default)]
    security: Option<SecurityRequirements>,
    #[serde(rename = "x-amazon-apigateway-request-validator")]
    validator: Option<ValidatorName>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawIntegration {
    #[serde(rename = "type")]
    kind: String,
    uri: Option<String>,
    http_method: Option<String>,
    payload_format_version: Option<String>,
    connection_type: Option<String>,
    timeout_in_millis: Option<u64>,
    #[serde(default)]
    request_parameters: BTreeMap<String, String>,
    #[serde(default)]
    request_templates: BTreeMap<String, String>,
    #[serde(default)]
    responses: BTreeMap<String, RawIntegrationResponse>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawIntegrationResponse {
    status_code: Option<Value>,
    #[serde(default)]
    response_parameters: BTreeMap<String, String>,
    #[serde(default)]
    response_templates: BTreeMap<String, Option<String>>,
}

impl ApiDefinition {
    /// Parses an export. Operations that cannot be served are kept as
    /// [`Integration::Unsupported`] so they answer with a clear error instead of
    /// silently disappearing.
    pub(crate) fn from_openapi(
        document: &Value,
        kind: ApiKind,
        stage_variables: &BTreeMap<String, String>,
        overrides: &IntegrationOverrides,
    ) -> Result<Self, SpecError> {
        let document = Document::deserialize(document)?;
        let mut unused: BTreeSet<&str> = overrides.keys().map(String::as_str).collect();
        let mut routes = Vec::new();
        for (path, item) in &document.paths {
            for (key, operation) in item {
                let Some(method) = method_match(key) else {
                    continue;
                };
                let operation = Operation::deserialize(operation)?;
                let route_path = if path == HTTP_API_DEFAULT_ROUTE {
                    RoutePath::Default
                } else {
                    RoutePath::Resource(path.clone())
                };
                let protections = document.protections(kind, &operation);
                let route_key = route_key(&method, &route_path);
                let raw = match overrides.get(&route_key) {
                    Some(value) => {
                        unused.remove(route_key.as_str());
                        let raw = RawIntegration::deserialize(value).map_err(|source| {
                            SpecError::InvalidOverride {
                                route_key: route_key.clone(),
                                source,
                            }
                        })?;
                        Some(raw)
                    }
                    None => operation.integration,
                };
                let integration = match raw {
                    Some(ref raw) => build_integration(raw, kind, stage_variables),
                    None => Integration::Unsupported {
                        reason: "operation has no x-amazon-apigateway-integration".to_owned(),
                    },
                };
                routes.push(Route {
                    method,
                    path: route_path,
                    integration,
                    protections,
                });
            }
        }
        if !unused.is_empty() {
            return Err(SpecError::UnknownOverrides(
                unused.into_iter().map(str::to_owned).collect(),
            ));
        }
        Ok(Self { routes })
    }
}

fn route_key(method: &MethodMatch, path: &RoutePath) -> String {
    match *path {
        RoutePath::Default => "$default".to_owned(),
        RoutePath::Resource(ref path) => format!("{method} {path}"),
    }
}

fn method_match(key: &str) -> Option<MethodMatch> {
    if key == ANY_METHOD_KEY {
        return Some(MethodMatch::Any);
    }
    let method = match key {
        "get" => Method::GET,
        "put" => Method::PUT,
        "post" => Method::POST,
        "delete" => Method::DELETE,
        "options" => Method::OPTIONS,
        "head" => Method::HEAD,
        "patch" => Method::PATCH,
        _ => return None,
    };
    Some(MethodMatch::Exact(method))
}

fn build_integration(
    raw: &RawIntegration,
    kind: ApiKind,
    stage_variables: &BTreeMap<String, String>,
) -> Integration {
    let default_timeout = match kind {
        ApiKind::Rest => REST_DEFAULT_TIMEOUT,
        ApiKind::Http => HTTP_DEFAULT_TIMEOUT,
    };
    let timeout = raw
        .timeout_in_millis
        .map_or(default_timeout, Duration::from_millis);
    if raw
        .connection_type
        .as_deref()
        .is_some_and(|c| c.eq_ignore_ascii_case("VPC_LINK"))
    {
        return Integration::Unsupported {
            reason: "VPC link integrations are only reachable from inside AWS".to_owned(),
        };
    }
    let uri = raw
        .uri
        .as_deref()
        .map(|uri| substitute_stage_variables(uri, stage_variables));
    match raw.kind.to_ascii_lowercase().as_str() {
        "http_proxy" => {
            let Some(uri) = uri else {
                return unsupported("HTTP_PROXY integration has no uri");
            };
            http_proxy(
                uri,
                raw.http_method.as_deref(),
                &raw.request_parameters,
                timeout,
            )
        }
        "mock" => mock(&raw.request_templates, &raw.responses),
        "aws_proxy" => {
            let Some(function) = uri.as_deref().and_then(lambda_function) else {
                return unsupported("AWS_PROXY integration is not a Lambda function");
            };
            let payload = match (raw.payload_format_version.as_deref(), kind) {
                (Some("1.0"), _) | (None, ApiKind::Rest) => PayloadVersion::V1,
                (Some(_), _) | (None, ApiKind::Http) => PayloadVersion::V2,
            };
            Integration::Lambda(LambdaProxy {
                function,
                payload,
                timeout,
            })
        }
        other => unsupported(&format!(
            "{} integrations need mapping templates, which are not supported",
            other.to_ascii_uppercase()
        )),
    }
}

fn unsupported(reason: &str) -> Integration {
    Integration::Unsupported {
        reason: reason.to_owned(),
    }
}

fn http_proxy(
    uri: String,
    method: Option<&str>,
    request_parameters: &BTreeMap<String, String>,
    timeout: Duration,
) -> Integration {
    let method = match method {
        None => None,
        Some(m) if m.eq_ignore_ascii_case("ANY") => None,
        Some(m) => match Method::from_bytes(m.to_ascii_uppercase().as_bytes()) {
            Ok(method) => Some(method),
            Err(_) => return unsupported(&format!("invalid integration httpMethod {m:?}")),
        },
    };
    let mut path_params = BTreeMap::new();
    let mut query_params = BTreeMap::new();
    let mut headers = BTreeMap::new();
    for (target, source) in request_parameters {
        let Some(source) = ParamSource::parse(source) else {
            tracing::warn!(
                target,
                source,
                "ignoring unsupported request parameter mapping"
            );
            continue;
        };
        if let Some(name) = target.strip_prefix("integration.request.path.") {
            path_params.insert(name.to_owned(), source);
        } else if let Some(name) = target.strip_prefix("integration.request.querystring.") {
            query_params.insert(name.to_owned(), source);
        } else if let Some(name) = target.strip_prefix("integration.request.header.") {
            headers.insert(name.to_owned(), source);
        } else {
            tracing::warn!(target, "ignoring unsupported request parameter mapping");
        }
    }
    Integration::HttpProxy(HttpProxy {
        method,
        uri,
        path_params,
        query_params,
        headers,
        timeout,
    })
}

/// Builds a MOCK response. API Gateway selects the integration response by the
/// `statusCode` in the request template; templates are returned verbatim because
/// VTL is not evaluated.
fn mock(
    request_templates: &BTreeMap<String, String>,
    responses: &BTreeMap<String, RawIntegrationResponse>,
) -> Integration {
    let requested = request_templates
        .values()
        .next()
        .and_then(|template| mock_status(template))
        .unwrap_or(200);
    let requested_key = requested.to_string();
    let selected = responses
        .get(&requested_key)
        .or_else(|| responses.get("default"))
        .or_else(|| responses.values().next());
    let Some(response) = selected else {
        return match StatusCode::from_u16(requested) {
            Ok(status) => Integration::Mock(MockResponse {
                status,
                headers: Vec::new(),
                content_type: None,
                body: String::new(),
            }),
            Err(_) => unsupported(&format!("invalid mock status code {requested}")),
        };
    };
    let status = response
        .status_code
        .as_ref()
        .and_then(status_from_value)
        .unwrap_or(requested);
    let Ok(status) = StatusCode::from_u16(status) else {
        return unsupported(&format!("invalid mock status code {status}"));
    };
    let mut headers = Vec::new();
    for (target, source) in &response.response_parameters {
        let Some(name) = target.strip_prefix("method.response.header.") else {
            continue;
        };
        let Some(ParamSource::Literal(value)) = ParamSource::parse(source) else {
            tracing::warn!(
                header = name,
                "mock response header is not a literal; skipping"
            );
            continue;
        };
        match (HeaderName::try_from(name), HeaderValue::try_from(value)) {
            (Ok(name), Ok(value)) => headers.push((name, value)),
            (Err(_), _) | (_, Err(_)) => {
                tracing::warn!(header = name, "invalid mock response header; skipping");
            }
        }
    }
    let template = response
        .response_templates
        .get("application/json")
        .map(|body| ("application/json", body))
        .or_else(|| {
            response
                .response_templates
                .iter()
                .next()
                .map(|(content_type, body)| (content_type.as_str(), body))
        });
    let (content_type, body) = match template {
        Some((content_type, body)) => (
            HeaderValue::try_from(content_type).ok(),
            body.clone().unwrap_or_default(),
        ),
        None => (None, String::new()),
    };
    Integration::Mock(MockResponse {
        status,
        headers,
        content_type,
        body,
    })
}

fn mock_status(template: &str) -> Option<u16> {
    let value: Value = serde_json::from_str(template).ok()?;
    status_from_value(value.get("statusCode")?)
}

fn status_from_value(value: &Value) -> Option<u16> {
    match value {
        Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
        Value::String(s) => s.parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

/// Extracts the function ARN from a Lambda integration URI. REST APIs use the
/// `arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{arn}/invocations`
/// form; HTTP APIs may also give the function ARN directly.
fn lambda_function(uri: &str) -> Option<String> {
    if let Some((_, rest)) = uri.split_once(":lambda:path/") {
        let (_, functions) = rest.split_once("/functions/")?;
        let function = functions.strip_suffix("/invocations").unwrap_or(functions);
        return (!function.is_empty()).then(|| function.to_owned());
    }
    uri.contains(":lambda:").then(|| uri.to_owned())
}

fn substitute_stage_variables(uri: &str, stage_variables: &BTreeMap<String, String>) -> String {
    let mut out = String::with_capacity(uri.len());
    let mut rest = uri;
    while let Some(start) = rest.find("${stageVariables.") {
        let (before, after) = rest.split_at(start);
        out.push_str(before);
        let name_start = after.trim_start_matches("${stageVariables.");
        let Some((name, tail)) = name_start.split_once('}') else {
            out.push_str(after);
            return out;
        };
        match stage_variables.get(name) {
            Some(value) => out.push_str(value),
            None => {
                tracing::warn!(variable = name, "stage variable is not defined");
            }
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known length"
)]
#[expect(clippy::panic, reason = "tests fail loudly on unexpected variants")]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(doc: &Value, kind: ApiKind) -> ApiDefinition {
        ApiDefinition::from_openapi(doc, kind, &BTreeMap::new(), &BTreeMap::new()).unwrap()
    }

    #[test]
    fn parses_rest_http_proxy_with_parameter_mappings() {
        let doc = json!({
            "openapi": "3.0.1",
            "paths": {
                "/pets/{petId}": {
                    "get": {
                        "x-amazon-apigateway-integration": {
                            "type": "http_proxy",
                            "httpMethod": "GET",
                            "uri": "http://backend.example/pets/{id}",
                            "requestParameters": {
                                "integration.request.path.id": "method.request.path.petId",
                                "integration.request.header.x-api": "'static'",
                                "integration.request.querystring.q": "method.request.querystring.search",
                                "integration.request.header.bad": "context.requestId"
                            },
                            "timeoutInMillis": 5000
                        }
                    }
                }
            }
        });
        let def = parse(&doc, ApiKind::Rest);
        assert_eq!(def.routes.len(), 1);
        let route = &def.routes[0];
        assert_eq!(route.route_key(), "GET /pets/{petId}");
        let Integration::HttpProxy(proxy) = &route.integration else {
            panic!("expected HTTP proxy, got {:?}", route.integration);
        };
        assert_eq!(proxy.method, Some(Method::GET));
        assert_eq!(proxy.timeout, Duration::from_millis(5000));
        assert_eq!(
            proxy.path_params["id"],
            ParamSource::Path("petId".to_owned())
        );
        assert_eq!(
            proxy.headers["x-api"],
            ParamSource::Literal("static".to_owned())
        );
        assert_eq!(
            proxy.query_params["q"],
            ParamSource::Query("search".to_owned())
        );
        assert!(!proxy.headers.contains_key("bad"));
    }

    #[test]
    fn any_method_http_proxy_forwards_client_method() {
        let doc = json!({"paths": {"/{proxy+}": {"x-amazon-apigateway-any-method": {
            "x-amazon-apigateway-integration": {"type": "HTTP_PROXY", "httpMethod": "ANY", "uri": "https://example.com/{proxy}"}
        }}}});
        let def = parse(&doc, ApiKind::Http);
        let route = &def.routes[0];
        assert_eq!(route.method, MethodMatch::Any);
        let Integration::HttpProxy(proxy) = &route.integration else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(proxy.method, None);
        assert_eq!(proxy.timeout, HTTP_DEFAULT_TIMEOUT);
    }

    #[test]
    fn skips_non_operation_keys() {
        let doc = json!({"paths": {"/a": {"parameters": [], "summary": "x", "get": {
            "x-amazon-apigateway-integration": {"type": "mock"}
        }}}});
        assert_eq!(parse(&doc, ApiKind::Rest).routes.len(), 1);
    }

    #[test]
    fn lambda_payload_versions_follow_api_kind_defaults() {
        let integration = json!({"type": "aws_proxy", "httpMethod": "POST",
            "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:pets/invocations"});
        let doc =
            json!({"paths": {"/a": {"post": {"x-amazon-apigateway-integration": integration}}}});
        for (kind, expected) in [
            (ApiKind::Rest, PayloadVersion::V1),
            (ApiKind::Http, PayloadVersion::V2),
        ] {
            let def = parse(&doc, kind);
            let Integration::Lambda(lambda) = &def.routes[0].integration else {
                panic!("expected Lambda");
            };
            assert_eq!(lambda.payload, expected);
            assert_eq!(
                lambda.function,
                "arn:aws:lambda:us-east-1:123456789012:function:pets"
            );
        }
        let explicit = json!({"paths": {"/a": {"post": {"x-amazon-apigateway-integration":
            {"type": "aws_proxy", "payloadFormatVersion": "1.0", "uri": "arn:aws:lambda:us-east-1:1:function:f"}}}}});
        let def = parse(&explicit, ApiKind::Http);
        let Integration::Lambda(lambda) = &def.routes[0].integration else {
            panic!("expected Lambda");
        };
        assert_eq!(lambda.payload, PayloadVersion::V1);
        assert_eq!(lambda.function, "arn:aws:lambda:us-east-1:1:function:f");
    }

    #[test]
    fn lambda_function_rejects_non_lambda_uris() {
        assert_eq!(
            lambda_function("arn:aws:apigateway:us-east-1:sqs:path/q"),
            None
        );
        assert_eq!(
            lambda_function("arn:aws:apigateway:r:lambda:path/2015-03-31/functions//invocations"),
            None
        );
        assert_eq!(
            lambda_function("arn:aws:apigateway:r:lambda:path/nofunctions"),
            None
        );
        let doc = json!({"paths": {"/a": {"get": {"x-amazon-apigateway-integration":
            {"type": "aws_proxy", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}}}}});
        assert!(matches!(
            parse(&doc, ApiKind::Rest).routes[0].integration,
            Integration::Unsupported { .. }
        ));
    }

    #[test]
    fn mock_selects_response_by_requested_status() {
        let doc = json!({"paths": {"/m": {"options": {"x-amazon-apigateway-integration": {
            "type": "mock",
            "requestTemplates": {"application/json": "{\"statusCode\": 201}"},
            "responses": {
                "default": {"statusCode": "200"},
                "201": {
                    "statusCode": "201",
                    "responseParameters": {
                        "method.response.header.Access-Control-Allow-Origin": "'*'",
                        "method.response.header.X-Dynamic": "integration.response.header.x",
                        "method.response.header.Bad Name": "'v'"
                    },
                    "responseTemplates": {"application/json": "{\"ok\":true}"}
                }
            }
        }}}}});
        let def = parse(&doc, ApiKind::Rest);
        let Integration::Mock(mock) = &def.routes[0].integration else {
            panic!("expected mock");
        };
        assert_eq!(mock.status, StatusCode::CREATED);
        assert_eq!(mock.body, "{\"ok\":true}");
        assert_eq!(mock.headers.len(), 1);
        assert_eq!(mock.headers[0].0, "access-control-allow-origin");
        assert_eq!(mock.content_type.as_ref().unwrap(), "application/json");
    }

    #[test]
    fn mock_without_responses_returns_requested_status_or_rejects_invalid() {
        let ok = mock(
            &BTreeMap::from([(
                "application/json".to_owned(),
                "{\"statusCode\": 204}".to_owned(),
            )]),
            &BTreeMap::new(),
        );
        let Integration::Mock(m) = ok else {
            panic!("expected mock")
        };
        assert_eq!(m.status, StatusCode::NO_CONTENT);
        let bad = mock(
            &BTreeMap::from([(
                "application/json".to_owned(),
                "{\"statusCode\": 42}".to_owned(),
            )]),
            &BTreeMap::new(),
        );
        assert!(matches!(bad, Integration::Unsupported { .. }));
        let vtl = mock(
            &BTreeMap::from([("application/json".to_owned(), "#set($x = 1)".to_owned())]),
            &BTreeMap::new(),
        );
        let Integration::Mock(m) = vtl else {
            panic!("expected mock")
        };
        assert_eq!(m.status, StatusCode::OK);
    }

    #[test]
    fn non_proxy_and_vpc_link_integrations_are_unsupported() {
        let doc = json!({"paths": {
            "/aws": {"get": {"x-amazon-apigateway-integration": {"type": "aws", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}}},
            "/http": {"get": {"x-amazon-apigateway-integration": {"type": "http", "uri": "http://x"}}},
            "/vpc": {"get": {"x-amazon-apigateway-integration": {"type": "http_proxy", "connectionType": "VPC_LINK", "uri": "http://x"}}},
            "/none": {"get": {}},
            "/nouri": {"get": {"x-amazon-apigateway-integration": {"type": "http_proxy"}}},
            "/badmethod": {"get": {"x-amazon-apigateway-integration": {"type": "http_proxy", "httpMethod": "GE T", "uri": "http://x"}}}
        }});
        let def = parse(&doc, ApiKind::Rest);
        assert_eq!(def.routes.len(), 6);
        for route in &def.routes {
            assert!(
                matches!(route.integration, Integration::Unsupported { .. }),
                "{}",
                route.route_key()
            );
        }
    }

    fn protections_by_path(doc: &Value, kind: ApiKind) -> BTreeMap<String, Protections> {
        parse(doc, kind)
            .routes
            .iter()
            .map(|r| (r.path.to_string(), r.protections.clone()))
            .collect()
    }

    fn only<const N: usize>(protections: [Protection; N]) -> Protections {
        Protections::from_iter(protections)
    }

    #[test]
    fn http_apis_inherit_document_security_and_honor_optional_auth() {
        let integration = json!({"type": "mock"});
        let doc = json!({
            "security": [{"jwt": []}],
            "components": {"securitySchemes": {"jwt": {"type": "oauth2",
                "x-amazon-apigateway-authorizer": {"type": "jwt"}}}},
            "paths": {
                "/global": {"get": {"x-amazon-apigateway-integration": integration}},
                "/open": {"get": {"security": [], "x-amazon-apigateway-integration": integration}},
                "/optional": {"get": {"security": [{}, {"jwt": []}], "x-amazon-apigateway-integration": integration}},
                "/jwt": {"get": {"security": [{"jwt": ["read"]}], "x-amazon-apigateway-integration": integration}}
            }
        });
        let auth = protections_by_path(&doc, ApiKind::Http);
        let jwt = only([Protection::Authorizer]);
        assert_eq!(auth["/global"], jwt);
        assert_eq!(auth["/open"], Protections::default());
        assert_eq!(auth["/optional"], Protections::default());
        assert_eq!(auth["/jwt"], jwt);
    }

    #[test]
    fn rest_apis_ignore_document_security() {
        let doc = json!({
            "security": [{"api_key": []}],
            "components": {"securitySchemes": {"api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"}}},
            "paths": {"/a": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}}}}
        });
        assert_eq!(
            protections_by_path(&doc, ApiKind::Rest)["/a"],
            Protections::default()
        );
        assert!(protections_by_path(&doc, ApiKind::Http)["/a"].contains(Protection::ApiKey));
    }

    #[test]
    fn security_schemes_are_classified() {
        let integration = json!({"type": "mock"});
        let op = |schemes: Value| json!({"security": [schemes], "x-amazon-apigateway-integration": integration});
        let doc = json!({
            "components": {"securitySchemes": {
                "sigv4": {"type": "apiKey", "name": "Authorization", "in": "header", "x-amazon-apigateway-authtype": "awsSigv4"},
                "api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"},
                "lambda": {"type": "apiKey", "name": "Authorization", "in": "header",
                    "x-amazon-apigateway-authtype": "custom", "x-amazon-apigateway-authorizer": {"type": "token"}},
                "cognito": {"type": "apiKey", "name": "Authorization", "in": "header",
                    "x-amazon-apigateway-authtype": "cognito_user_pools", "x-amazon-apigateway-authorizer": {"type": "cognito_user_pools"}}
            }},
            "paths": {
                "/iam": {"get": op(json!({"sigv4": []}))},
                "/key": {"get": op(json!({"api_key": []}))},
                "/lambda-and-key": {"get": op(json!({"lambda": [], "api_key": []}))},
                "/cognito": {"get": op(json!({"cognito": ["email"]}))},
                "/undeclared": {"get": op(json!({"mystery": []}))}
            }
        });
        let auth = protections_by_path(&doc, ApiKind::Rest);
        assert_eq!(auth["/iam"], only([Protection::Iam]));
        assert_eq!(auth["/key"], only([Protection::ApiKey]));
        assert_eq!(
            auth["/lambda-and-key"],
            only([Protection::Authorizer, Protection::ApiKey])
        );
        assert_eq!(auth["/cognito"], only([Protection::Authorizer]));
        assert_eq!(auth["/undeclared"], only([Protection::Authorizer]));
    }

    #[test]
    fn resource_policies_with_statements_protect_every_route() {
        let paths = json!({"/a": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}}}});
        let statement = json!({"Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "*"});
        let cases = [
            (
                json!({"Version": "2012-10-17", "Statement": [statement]}),
                true,
            ),
            (
                json!({"Version": "2012-10-17", "Statement": statement}),
                true,
            ),
            (
                Value::String(json!({"Statement": [statement]}).to_string()),
                true,
            ),
            (Value::String("not json".to_owned()), true),
            (json!({"Version": "2012-10-17", "Statement": []}), false),
            (json!({"Version": "2012-10-17"}), false),
            (Value::String("  ".to_owned()), false),
            (Value::Null, false),
        ];
        for (policy, expected) in cases {
            let doc = json!({"x-amazon-apigateway-policy": policy, "paths": paths});
            assert_eq!(
                protections_by_path(&doc, ApiKind::Rest)["/a"].contains(Protection::ResourcePolicy),
                expected,
                "{policy}"
            );
        }
        assert!(
            !protections_by_path(&json!({"paths": paths}), ApiKind::Rest)["/a"]
                .contains(Protection::ResourcePolicy)
        );
    }

    #[test]
    fn request_validators_resolve_default_override_and_unknown_names() {
        let integration = json!({"type": "mock"});
        let doc = json!({
            "x-amazon-apigateway-request-validators": {
                "all": {"validateRequestBody": true, "validateRequestParameters": true},
                "params": {"validateRequestParameters": true},
                "none": {"validateRequestBody": false, "validateRequestParameters": false}
            },
            "x-amazon-apigateway-request-validator": "params",
            "paths": {
                "/default": {"get": {"x-amazon-apigateway-integration": integration}},
                "/off": {"get": {"x-amazon-apigateway-request-validator": "none", "x-amazon-apigateway-integration": integration}},
                "/all": {"get": {"x-amazon-apigateway-request-validator": "all", "x-amazon-apigateway-integration": integration}},
                "/unknown": {"get": {"x-amazon-apigateway-request-validator": "missing", "x-amazon-apigateway-integration": integration}}
            }
        });
        let auth = protections_by_path(&doc, ApiKind::Rest);
        assert!(auth["/default"].contains(Protection::RequestValidation));
        assert!(!auth["/off"].contains(Protection::RequestValidation));
        assert!(auth["/all"].contains(Protection::RequestValidation));
        assert!(auth["/unknown"].contains(Protection::RequestValidation));
        let no_validators =
            json!({"paths": {"/a": {"get": {"x-amazon-apigateway-integration": integration}}}});
        assert!(
            !protections_by_path(&no_validators, ApiKind::Rest)["/a"]
                .contains(Protection::RequestValidation)
        );
    }

    #[test]
    fn default_route_is_recognised() {
        let doc = json!({"paths": {"/$default": {"x-amazon-apigateway-any-method": {
            "x-amazon-apigateway-integration": {"type": "mock"}
        }}}});
        let def = parse(&doc, ApiKind::Http);
        assert_eq!(def.routes[0].path, RoutePath::Default);
        assert_eq!(def.routes[0].route_key(), "$default");
    }

    #[test]
    fn stage_variables_are_substituted() {
        let vars = BTreeMap::from([("host".to_owned(), "api.internal".to_owned())]);
        assert_eq!(
            substitute_stage_variables(
                "https://${stageVariables.host}/v1/${stageVariables.missing}x",
                &vars
            ),
            "https://api.internal/v1/x"
        );
        assert_eq!(
            substitute_stage_variables("https://${stageVariables.host", &vars),
            "https://${stageVariables.host"
        );
    }

    #[test]
    fn rejects_documents_that_are_not_openapi() {
        let err = ApiDefinition::from_openapi(
            &json!({"paths": []}),
            ApiKind::Rest,
            &BTreeMap::new(),
            &BTreeMap::new(),
        );
        assert!(err.is_err());
    }

    fn lambda_doc() -> Value {
        json!({"paths": {
            "/pets/{petId}": {"get": {"x-amazon-apigateway-integration": {
                "type": "aws_proxy", "uri": "arn:aws:lambda:us-east-1:1:function:pets"}}},
            "/$default": {"x-amazon-apigateway-any-method": {"x-amazon-apigateway-integration": {"type": "mock"}}}
        }})
    }

    #[test]
    fn overrides_replace_integrations_by_route_key() {
        let vars = BTreeMap::from([("host".to_owned(), "pets.internal".to_owned())]);
        let overrides = IntegrationOverrides::from([
            (
                "GET /pets/{petId}".to_owned(),
                json!({"type": "http_proxy", "uri": "http://${stageVariables.host}/pets/{petId}"}),
            ),
            (
                "$default".to_owned(),
                json!({"type": "http_proxy", "uri": "http://fallback.internal"}),
            ),
        ]);
        let def =
            ApiDefinition::from_openapi(&lambda_doc(), ApiKind::Http, &vars, &overrides).unwrap();
        for route in &def.routes {
            let Integration::HttpProxy(proxy) = &route.integration else {
                panic!("{} was not overridden", route.route_key());
            };
            assert!(proxy.uri.starts_with("http://"), "{}", proxy.uri);
            assert!(!proxy.uri.contains("stageVariables"), "{}", proxy.uri);
        }
    }

    #[test]
    fn overrides_for_unknown_routes_are_rejected() {
        let overrides = IntegrationOverrides::from([
            ("GET /pets/{id}".to_owned(), json!({"type": "mock"})),
            ("POST /pets/{petId}".to_owned(), json!({"type": "mock"})),
        ]);
        let err =
            ApiDefinition::from_openapi(&lambda_doc(), ApiKind::Http, &BTreeMap::new(), &overrides)
                .unwrap_err();
        let SpecError::UnknownOverrides(keys) = err else {
            panic!("expected UnknownOverrides, got {err}");
        };
        assert_eq!(
            keys,
            vec!["GET /pets/{id}".to_owned(), "POST /pets/{petId}".to_owned()]
        );
    }

    #[test]
    fn malformed_overrides_are_rejected() {
        let overrides = IntegrationOverrides::from([(
            "GET /pets/{petId}".to_owned(),
            json!({"uri": "http://x"}),
        )]);
        let err =
            ApiDefinition::from_openapi(&lambda_doc(), ApiKind::Http, &BTreeMap::new(), &overrides)
                .unwrap_err();
        assert!(matches!(err, SpecError::InvalidOverride { .. }), "{err}");
    }
}
