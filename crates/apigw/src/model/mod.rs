//! The normalized description of one deployed API: everything the gateway reads
//! from API Gateway, whether or not it is enforced yet.
//!
//! [`ApiModel::import`] builds it from an `OpenAPI` export; the runtime route
//! table is compiled from it in [`crate::route`]. Anything imported but not yet
//! enforced is reported through [`ApiModel::unenforced`] and
//! [`Operation::unenforced`] so `/routes` shows exactly where behavior differs
//! from API Gateway.

mod import;
mod stage;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use axum::http::Method;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(test)]
pub(crate) use stage::{AccessLogSettings, MethodSettings, SettingsScope};
pub(crate) use stage::{DeploymentStamp, ExecutionLogging, LoggingLevel, StageSettings};

/// Which API Gateway product the definition came from. The two differ in Lambda
/// payload defaults, error bodies, and response headers.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub(crate) enum ApiKind {
    /// API Gateway REST API (v1).
    Rest,
    /// API Gateway HTTP API (v2).
    Http,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MethodMatch {
    Any,
    Exact(Method),
}

impl MethodMatch {
    const ANY_METHOD_KEY: &str = "x-amazon-apigateway-any-method";

    /// The method an `OpenAPI` path-item key names, if it names one.
    fn from_openapi_key(key: &str) -> Option<Self> {
        if key == Self::ANY_METHOD_KEY {
            return Some(Self::Any);
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
        Some(Self::Exact(method))
    }
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

impl RoutePath {
    const HTTP_API_DEFAULT_ROUTE: &str = "/$default";

    fn from_openapi_path(path: &str) -> Self {
        if path == Self::HTTP_API_DEFAULT_ROUTE {
            Self::Default
        } else {
            Self::Resource(path.to_owned())
        }
    }
}

impl fmt::Display for RoutePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Default => f.write_str("$default"),
            Self::Resource(path) => f.write_str(path),
        }
    }
}

/// A route in API Gateway's own notation: `GET /pets/{petId}`, `ANY /{proxy+}`,
/// or `$default`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct RouteKey(String);

impl RouteKey {
    pub(crate) fn new(method: &MethodMatch, path: &RoutePath) -> Self {
        match *path {
            RoutePath::Default => Self("$default".to_owned()),
            RoutePath::Resource(ref path) => Self(format!("{method} {path}")),
        }
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RouteKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<&str> for RouteKey {
    fn from(key: &str) -> Self {
        Self(key.to_owned())
    }
}

impl From<String> for RouteKey {
    fn from(key: String) -> Self {
        Self(key)
    }
}

impl PartialEq<&str> for RouteKey {
    fn eq(&self, other: &&str) -> bool {
        self.0 == *other
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

/// Declares an enum read from API Gateway's wire format. API Gateway is
/// inconsistent about case (`http_proxy` in exports, `HTTP_PROXY` in the API), so
/// parsing is case-insensitive and serialization uses the canonical spelling.
macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "&'static str")]
        pub(crate) enum $name {
            $($variant),+
        }

        impl $name {
            pub(crate) const fn as_str(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire),+
                }
            }
        }

        impl TryFrom<String> for $name {
            type Error = String;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                $(if value.eq_ignore_ascii_case($wire) {
                    return Ok(Self::$variant);
                })+
                Err(format!("unknown {} {value:?}", stringify!($name)))
            }
        }

        impl From<$name> for &'static str {
            fn from(value: $name) -> Self {
                value.as_str()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}

wire_enum!(IntegrationType {
    Http => "HTTP",
    HttpProxy => "HTTP_PROXY",
    Aws => "AWS",
    AwsProxy => "AWS_PROXY",
    Mock => "MOCK",
});

wire_enum!(PassthroughBehavior {
    WhenNoMatch => "WHEN_NO_MATCH",
    WhenNoTemplates => "WHEN_NO_TEMPLATES",
    Never => "NEVER",
});

wire_enum!(ContentHandling {
    ConvertToText => "CONVERT_TO_TEXT",
    ConvertToBinary => "CONVERT_TO_BINARY",
});

wire_enum!(ConnectionType {
    Internet => "INTERNET",
    VpcLink => "VPC_LINK",
});

wire_enum!(ResponseTransferMode {
    Buffered => "BUFFERED",
    Stream => "STREAM",
});

wire_enum!(PayloadVersion {
    V1 => "1.0",
    V2 => "2.0",
});

wire_enum!(ApiKeySource {
    Header => "HEADER",
    Authorizer => "AUTHORIZER",
});

wire_enum!(ParameterLocation {
    Path => "path",
    Query => "query",
    Header => "header",
    Cookie => "cookie",
});

/// An `x-amazon-apigateway-integration` object. It doubles as the format of the
/// integration override file, so overrides can say anything an export can.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrationSpec {
    #[serde(rename = "type")]
    pub(crate) integration_type: IntegrationType,
    #[serde(rename = "integrationSubtype")]
    pub(crate) subtype: Option<String>,
    pub(crate) uri: Option<String>,
    pub(crate) http_method: Option<String>,
    pub(crate) connection_type: Option<ConnectionType>,
    pub(crate) connection_id: Option<String>,
    pub(crate) credentials: Option<String>,
    pub(crate) payload_format_version: Option<PayloadVersion>,
    pub(crate) timeout_in_millis: Option<u64>,
    #[serde(default)]
    pub(crate) request_parameters: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) request_templates: BTreeMap<String, Option<String>>,
    pub(crate) passthrough_behavior: Option<PassthroughBehavior>,
    pub(crate) content_handling: Option<ContentHandling>,
    #[serde(default)]
    pub(crate) cache_key_parameters: Vec<String>,
    pub(crate) cache_namespace: Option<String>,
    pub(crate) tls_config: Option<TlsConfig>,
    pub(crate) response_transfer_mode: Option<ResponseTransferMode>,
    #[serde(default)]
    pub(crate) responses: BTreeMap<String, IntegrationResponseSpec>,
    /// HTTP API response parameter mapping, keyed by backend status code.
    #[serde(default)]
    pub(crate) response_parameters: BTreeMap<String, BTreeMap<String, String>>,
}

impl IntegrationSpec {
    fn unenforced(&self, kind: ApiKind) -> Vec<Feature> {
        let mut features = Vec::new();
        if self.content_handling.is_some() {
            features.push(Feature::ContentHandling);
        }
        if self.tls_config.is_some() {
            features.push(Feature::IntegrationTlsConfig);
        }
        if !self.response_parameters.is_empty()
            || (kind == ApiKind::Http && self.request_parameters.keys().any(|k| k.contains(':')))
        {
            features.push(Feature::ParameterMapping);
        }
        if !self.cache_key_parameters.is_empty() {
            features.push(Feature::ResponseCaching);
        }
        features
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TlsConfig {
    #[serde(default)]
    pub(crate) insecure_skip_verification: bool,
    pub(crate) server_name_to_verify: Option<String>,
}

/// An integration response, keyed in [`IntegrationSpec::responses`] by its
/// selection pattern (`default` when there is none).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrationResponseSpec {
    /// A string in exports, sometimes a number in hand-written files.
    pub(crate) status_code: Option<Value>,
    #[serde(default)]
    pub(crate) response_parameters: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) response_templates: BTreeMap<String, Option<String>>,
    pub(crate) content_handling: Option<ContentHandling>,
}

impl IntegrationResponseSpec {
    pub(crate) fn status(&self) -> Option<u16> {
        match self.status_code.as_ref()? {
            Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
            Value::String(s) => s.parse().ok(),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
        }
    }
}

/// A request parameter declared on a method.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ParameterSpec {
    pub(crate) name: String,
    #[serde(rename = "in")]
    pub(crate) location: ParameterLocation,
    #[serde(default)]
    pub(crate) required: bool,
}

/// A method's request body: whether it is required and the model (JSON schema)
/// per content type.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct RequestBodySpec {
    pub(crate) required: bool,
    pub(crate) schemas: BTreeMap<String, Value>,
}

/// What a request validator checks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ValidatorSpec {
    #[serde(default)]
    pub(crate) validate_request_body: bool,
    #[serde(default)]
    pub(crate) validate_request_parameters: bool,
}

impl ValidatorSpec {
    pub(crate) fn validates(self) -> bool {
        self.validate_request_body || self.validate_request_parameters
    }
}

/// A route's reference to an authorizer, with the OAuth scopes it requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct AuthorizerRef {
    pub(crate) name: String,
    pub(crate) scopes: Vec<String>,
}

/// An authorizer definition (`x-amazon-apigateway-authorizer` on a security
/// scheme), with the scheme fields that say where the identity comes from.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct AuthorizerSpec {
    pub(crate) auth_type: Option<String>,
    pub(crate) header_name: Option<String>,
    pub(crate) config: Value,
}

/// A customized gateway response (`x-amazon-apigateway-gateway-responses`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct GatewayResponseSpec {
    pub(crate) status_code: Option<Value>,
    #[serde(default)]
    pub(crate) response_parameters: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) response_templates: BTreeMap<String, Option<String>>,
}

/// HTTP API CORS configuration (`x-amazon-apigateway-cors`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CorsConfig {
    #[serde(default)]
    pub(crate) allow_origins: Vec<String>,
    #[serde(default)]
    pub(crate) allow_methods: Vec<String>,
    #[serde(default)]
    pub(crate) allow_headers: Vec<String>,
    #[serde(default)]
    pub(crate) expose_headers: Vec<String>,
    pub(crate) max_age: Option<u64>,
    #[serde(default)]
    pub(crate) allow_credentials: bool,
}

/// API-wide settings carried in the export.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub(crate) struct ApiSettings {
    /// The API's name (`info.title` of the export).
    pub(crate) title: Option<String>,
    pub(crate) binary_media_types: Vec<String>,
    pub(crate) minimum_compression_size: Option<u64>,
    pub(crate) api_key_source: Option<ApiKeySource>,
    pub(crate) cors: Option<CorsConfig>,
    pub(crate) resource_policy: Option<Value>,
    pub(crate) disable_execute_api_endpoint: bool,
}

/// One method of one route.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct Operation {
    #[serde(skip)]
    pub(crate) method: MethodMatch,
    #[serde(skip)]
    pub(crate) path: RoutePath,
    pub(crate) route_key: RouteKey,
    pub(crate) protections: Protections,
    pub(crate) integration: Option<IntegrationSpec>,
    pub(crate) parameters: Vec<ParameterSpec>,
    pub(crate) request_body: Option<RequestBodySpec>,
    pub(crate) validator: Option<ValidatorSpec>,
    pub(crate) authorizer: Option<AuthorizerRef>,
}

impl Operation {
    /// Imported settings on this operation that the gateway does not enforce yet.
    pub(crate) fn unenforced(&self, kind: ApiKind) -> Vec<Feature> {
        self.integration
            .as_ref()
            .map(|integration| integration.unenforced(kind))
            .unwrap_or_default()
    }
}

/// Everything the gateway knows about one deployed API stage.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ApiModel {
    pub(crate) kind: ApiKind,
    pub(crate) operations: Vec<Operation>,
    pub(crate) settings: ApiSettings,
    pub(crate) authorizers: BTreeMap<String, AuthorizerSpec>,
    pub(crate) gateway_responses: BTreeMap<String, GatewayResponseSpec>,
    pub(crate) models: BTreeMap<String, Value>,
    pub(crate) stage: StageSettings,
}

impl ApiModel {
    /// API- and stage-level settings imported but not enforced yet.
    pub(crate) fn unenforced(&self) -> Vec<Feature> {
        let mut features = Vec::new();
        if !self.gateway_responses.is_empty() {
            features.push(Feature::GatewayResponses);
        }
        if !self.settings.binary_media_types.is_empty() {
            features.push(Feature::BinaryMediaTypes);
        }
        if self.settings.minimum_compression_size.is_some() {
            features.push(Feature::Compression);
        }
        if self.settings.cors.is_some() {
            features.push(Feature::Cors);
        }
        features.extend(self.stage.unenforced());
        features
    }
}

/// An API Gateway feature that was imported but is not enforced yet. Each one is
/// removed from this list by the change that implements it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Feature {
    GatewayResponses,
    BinaryMediaTypes,
    Compression,
    Cors,
    ContentHandling,
    IntegrationTlsConfig,
    ParameterMapping,
    Throttling,
    ResponseCaching,
    Tracing,
    Canary,
}

impl fmt::Display for Feature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::GatewayResponses => "gateway responses",
            Self::BinaryMediaTypes => "binary media types",
            Self::Compression => "compression",
            Self::Cors => "CORS",
            Self::ContentHandling => "content handling",
            Self::IntegrationTlsConfig => "integration TLS config",
            Self::ParameterMapping => "parameter mapping",
            Self::Throttling => "throttling",
            Self::ResponseCaching => "response caching",
            Self::Tracing => "tracing",
            Self::Canary => "canary",
        };
        f.write_str(name)
    }
}

/// Local replacements for integrations, keyed by route key.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(transparent)]
pub(crate) struct IntegrationOverrides(BTreeMap<RouteKey, Value>);

impl IntegrationOverrides {
    fn get(&self, key: &RouteKey) -> Option<&Value> {
        self.0.get(key)
    }

    fn keys(&self) -> impl Iterator<Item = &RouteKey> {
        self.0.keys()
    }
}

impl<K: Into<RouteKey>> FromIterator<(K, Value)> for IntegrationOverrides {
    fn from_iter<I: IntoIterator<Item = (K, Value)>>(iter: I) -> Self {
        Self(iter.into_iter().map(|(k, v)| (k.into(), v)).collect())
    }
}
