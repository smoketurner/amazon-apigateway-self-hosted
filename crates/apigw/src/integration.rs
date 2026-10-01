//! Integrations compiled from the model into the form requests execute against.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use axum::http::{HeaderValue, Method};

use crate::aws::{FunctionArn, IntegrationCredentials, RoleArn};
use crate::aws_service::ServiceUri;
use crate::aws_subtype::SubtypeIntegration;
use crate::integration_tls::TlsClient;
use crate::mapped::{AwsBackend, Backend, LambdaBackend, MappedIntegration};
use crate::mapping::ServiceParameters;
use crate::mapping::{RequestMapping, ResponseMapping};
use crate::model::{
    ApiKind, ConnectionType, IntegrationSpec, IntegrationType, PayloadVersion, ResponseTransferMode,
};
use crate::request_parameters::RequestParameters;
use crate::vpc_link::VpcLinks;

/// The longest a streamed response may take, and the default timeout of
/// streaming integrations.
pub(crate) const STREAM_LIMIT: Duration = Duration::from_mins(15);
/// The shortest integration timeout API Gateway accepts.
const MIN_INTEGRATION_TIMEOUT: Duration = Duration::from_millis(50);
/// The longest HTTP API integration timeout.
const HTTP_API_MAX_TIMEOUT: Duration = Duration::from_secs(30);

impl ApiKind {
    /// Brings an integration's `timeoutInMillis` into the range API Gateway
    /// allows: at least 50 ms, at most 30 s for HTTP APIs and 15 minutes for
    /// streaming responses. REST APIs may raise a buffered integration's timeout
    /// past the default 29 s (a service quota increase), so it is not capped.
    ///
    /// <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-execution-service-limits-table.html>
    fn bound_timeout(self, requested: Duration, transfer: ResponseTransferMode) -> Duration {
        let bounded = requested.max(MIN_INTEGRATION_TIMEOUT);
        match (self, transfer) {
            (_, ResponseTransferMode::Stream) => bounded.min(STREAM_LIMIT),
            (Self::Http, ResponseTransferMode::Buffered) => bounded.min(HTTP_API_MAX_TIMEOUT),
            (Self::Rest, ResponseTransferMode::Buffered) => bounded,
        }
    }

    /// API Gateway's integration timeout when the integration sets none.
    fn default_integration_timeout(self, transfer: ResponseTransferMode) -> Duration {
        match (self, transfer) {
            (_, ResponseTransferMode::Stream) => STREAM_LIMIT,
            (Self::Rest, ResponseTransferMode::Buffered) => Duration::from_secs(29),
            (Self::Http, ResponseTransferMode::Buffered) => Duration::from_secs(30),
        }
    }
}

/// A stage's variables, substituted into integration URIs as
/// `${stageVariables.name}`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StageVariables(BTreeMap<String, String>);

impl StageVariables {
    pub(crate) fn new(variables: BTreeMap<String, String>) -> Self {
        Self(variables)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn get(&self, name: &str) -> Option<&str> {
        self.0.get(name).map(String::as_str)
    }

    pub(crate) fn substitute(&self, text: &str) -> String {
        const PREFIX: &str = "${stageVariables.";
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find(PREFIX) {
            let (before, after) = rest.split_at(start);
            out.push_str(before);
            let Some((name, tail)) = after.trim_start_matches(PREFIX).split_once('}') else {
                out.push_str(after);
                return out;
            };
            if let Some(value) = self.0.get(name) {
                out.push_str(value);
            } else {
                tracing::warn!(variable = name, "stage variable is not defined");
            }
            rest = tail;
        }
        out.push_str(rest);
        out
    }
}

impl<'a> IntoIterator for &'a StageVariables {
    type Item = (&'a String, &'a String);
    type IntoIter = std::collections::btree_map::Iter<'a, String, String>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum Integration {
    HttpProxy(HttpProxy),
    /// A non-proxy `HTTP` or `MOCK` integration that runs mapping templates.
    Mapped(Box<MappedIntegration>),
    /// An HTTP API integration subtype that calls an AWS service.
    AwsSubtype(Box<SubtypeIntegration>),
    Lambda(LambdaProxy),
    Unsupported {
        reason: String,
    },
}

impl Integration {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::HttpProxy(_) => "HTTP_PROXY",
            Self::Mapped(mapped) => mapped.kind(),
            Self::AwsSubtype(_) | Self::Lambda(_) => "AWS_PROXY",
            Self::Unsupported { .. } => "UNSUPPORTED",
        }
    }

    /// Compiles an operation's integration. Anything that can't be served
    /// becomes [`Integration::Unsupported`] with the reason.
    pub(crate) fn compile(
        spec: Option<&IntegrationSpec>,
        kind: ApiKind,
        variables: &StageVariables,
        vpc_links: &VpcLinks,
    ) -> Self {
        let Some(spec) = spec else {
            return Self::unsupported("operation has no x-amazon-apigateway-integration");
        };
        Self::compile_spec(spec, kind, variables, vpc_links)
            .unwrap_or_else(|reason| Self::Unsupported { reason })
    }

    fn compile_spec(
        spec: &IntegrationSpec,
        kind: ApiKind,
        variables: &StageVariables,
        vpc_links: &VpcLinks,
    ) -> Result<Self, String> {
        let private = spec.connection_type == Some(ConnectionType::VpcLink);
        if private
            && !matches!(
                spec.integration_type,
                IntegrationType::HttpProxy | IntegrationType::Http
            )
        {
            return Err("only HTTP and HTTP_PROXY integrations can use a VPC link".to_owned());
        }
        let transfer = spec
            .response_transfer_mode
            .unwrap_or(ResponseTransferMode::Buffered);
        if transfer == ResponseTransferMode::Stream
            && !matches!(
                spec.integration_type,
                IntegrationType::HttpProxy | IntegrationType::AwsProxy
            )
        {
            return Err(format!(
                "response streaming applies to proxy integrations, not {}",
                spec.integration_type
            ));
        }
        let timeout = kind.bound_timeout(
            spec.timeout_in_millis.map_or_else(
                || kind.default_integration_timeout(transfer),
                Duration::from_millis,
            ),
            transfer,
        );
        let uri = spec.uri.as_deref().map(|uri| variables.substitute(uri));
        match spec.integration_type {
            IntegrationType::HttpProxy | IntegrationType::Http => {
                let uri =
                    uri.ok_or_else(|| format!("{} integration has no uri", spec.integration_type))?;
                let (uri, private) = if private {
                    let (uri, routing) =
                        PrivateRouting::resolve(spec, &uri, kind, variables, vpc_links)?;
                    (uri, Some(routing))
                } else {
                    (uri, None)
                };
                let proxy = HttpProxy::compile(spec, uri, timeout, transfer, kind, private)?;
                if spec.integration_type == IntegrationType::Http {
                    Ok(Self::Mapped(Box::new(MappedIntegration::compile(
                        spec,
                        Backend::Http(Box::new(proxy)),
                    ))))
                } else {
                    Ok(Self::HttpProxy(proxy))
                }
            }
            IntegrationType::Mock => Ok(Self::Mapped(Box::new(MappedIntegration::compile(
                spec,
                Backend::Mock,
            )))),
            IntegrationType::AwsProxy if spec.subtype.is_some() => {
                Self::compile_subtype(spec, kind, timeout)
            }
            IntegrationType::AwsProxy => {
                let target = uri
                    .as_deref()
                    .and_then(|uri| uri.parse::<LambdaTarget>().ok())
                    .ok_or("AWS_PROXY integration is not a Lambda function")?;
                if target.streaming != (transfer == ResponseTransferMode::Stream) {
                    return Err(match transfer {
                        ResponseTransferMode::Stream => "responseTransferMode STREAM needs the response-streaming-invocations integration URI".to_owned(),
                        ResponseTransferMode::Buffered => "a response-streaming-invocations integration URI needs responseTransferMode STREAM".to_owned(),
                    });
                }
                let function = target.function.parse::<FunctionArn>()?;
                let credentials = integration_role(spec)?;
                let payload = spec.payload_format_version.unwrap_or(match kind {
                    ApiKind::Rest => PayloadVersion::V1,
                    ApiKind::Http => PayloadVersion::V2,
                });
                Ok(Self::Lambda(LambdaProxy {
                    function,
                    credentials,
                    payload,
                    timeout,
                    transfer,
                }))
            }
            IntegrationType::Aws => Self::compile_aws(spec, uri, timeout),
        }
    }

    /// An HTTP API integration subtype, which calls an AWS service.
    fn compile_subtype(
        spec: &IntegrationSpec,
        kind: ApiKind,
        timeout: Duration,
    ) -> Result<Self, String> {
        if kind != ApiKind::Http {
            return Err("integration subtypes belong to HTTP APIs".to_owned());
        }
        let subtype = spec.subtype.as_deref().unwrap_or_default().parse()?;
        Ok(Self::AwsSubtype(Box::new(SubtypeIntegration::new(
            subtype,
            ServiceParameters::compile(&spec.request_parameters),
            integration_role(spec)?,
            timeout,
        ))))
    }

    /// A REST `AWS` integration: a non-proxy Lambda function or an AWS service.
    fn compile_aws(
        spec: &IntegrationSpec,
        uri: Option<String>,
        timeout: Duration,
    ) -> Result<Self, String> {
        let uri = uri.ok_or("AWS integration has no uri")?;
        let role = integration_role(spec)?;
        let backend = if uri.contains(":lambda:") {
            let target = uri.parse::<LambdaTarget>()?;
            let function = target.function.parse::<FunctionArn>()?;
            Backend::Lambda(Box::new(LambdaBackend::compile(
                spec, function, role, timeout,
            )))
        } else {
            let service = uri.parse::<ServiceUri>()?;
            Backend::Aws(Box::new(AwsBackend::compile(
                spec, uri, service, role, timeout,
            )?))
        };
        Ok(Self::Mapped(Box::new(MappedIntegration::compile(
            spec, backend,
        ))))
    }

    fn unsupported(reason: &str) -> Self {
        Self::Unsupported {
            reason: reason.to_owned(),
        }
    }
}

/// The role an integration runs as, from its `credentials`.
fn integration_role(spec: &IntegrationSpec) -> Result<Option<RoleArn>, String> {
    match spec.credentials.as_deref().map(str::parse).transpose()? {
        None => Ok(None),
        Some(IntegrationCredentials::Role(role)) => Ok(Some(role)),
        Some(IntegrationCredentials::Caller) => Err("caller credential passthrough (arn:aws:iam::*:user/*) needs IAM-authenticated callers, which cannot be verified outside AWS".to_owned()),
    }
}

#[derive(Debug, Clone)]
pub(crate) struct HttpProxy {
    /// `None` forwards the client's method (`ANY` in API Gateway).
    pub(crate) method: Option<Method>,
    /// Target URI; `{name}` placeholders are filled from the path parameters.
    pub(crate) uri: String,
    pub(crate) parameters: RequestParameters,
    /// HTTP API `requestParameters` (`append:header.x`, `overwrite:path`, ...).
    pub(crate) request_mapping: RequestMapping,
    /// HTTP API `responseParameters`, by backend status code.
    pub(crate) response_mapping: ResponseMapping,
    pub(crate) timeout: Duration,
    pub(crate) transfer: ResponseTransferMode,
    /// Present when the integration's `tlsConfig` changes certificate checks.
    pub(crate) tls: Option<TlsClient>,
    /// How a VPC link integration reaches its in-cluster backend.
    pub(crate) private: Option<PrivateRouting>,
}

/// What a VPC link integration needs besides the mapped base URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrivateRouting {
    /// REST: the integration URI's authority is sent as the `Host` header, as
    /// API Gateway does, and its path and query follow the mapped base URL.
    HostHeader(HeaderValue),
    /// HTTP API: the URI is a load balancer listener or Cloud Map service ARN,
    /// so the request path follows the mapped base URL, preceded by the stage
    /// name as API Gateway sends it.
    RequestPath,
}

impl PrivateRouting {
    /// Maps `uri` through the `--vpc-link` for the integration's connection ID.
    /// Returns the URL template to forward to.
    fn resolve(
        spec: &IntegrationSpec,
        uri: &str,
        kind: ApiKind,
        variables: &StageVariables,
        vpc_links: &VpcLinks,
    ) -> Result<(String, Self), String> {
        let id = spec
            .connection_id
            .as_deref()
            .map(|id| variables.substitute(id))
            .ok_or("VPC link integration has no connectionId")?;
        let base = vpc_links.base(&id).ok_or_else(|| {
            format!(
                "VPC link {id} is only reachable from inside AWS; map it to an in-cluster URL with --vpc-link {id}=<url> to serve this route"
            )
        })?;
        match kind {
            ApiKind::Http => {
                if !uri.starts_with("arn:") {
                    return Err("an HTTP API private integration uri must be a load balancer listener or Cloud Map service ARN".to_owned());
                }
                Ok((base, Self::RequestPath))
            }
            ApiKind::Rest => {
                let (_, after_scheme) = uri
                    .split_once("://")
                    .ok_or("a REST API private integration uri must be an http or https URL")?;
                let (authority, tail) = after_scheme
                    .split_at(after_scheme.find(['/', '?']).unwrap_or(after_scheme.len()));
                let host = HeaderValue::try_from(authority)
                    .map_err(|_| format!("{authority:?} is not a valid Host header"))?;
                Ok((format!("{base}{tail}"), Self::HostHeader(host)))
            }
        }
    }
}

impl HttpProxy {
    fn compile(
        spec: &IntegrationSpec,
        uri: String,
        timeout: Duration,
        transfer: ResponseTransferMode,
        kind: ApiKind,
        private: Option<PrivateRouting>,
    ) -> Result<Self, String> {
        let method = match spec.http_method.as_deref() {
            None => None,
            Some(m) if m.eq_ignore_ascii_case("ANY") => None,
            Some(m) => Some(
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| format!("invalid integration httpMethod {m:?}"))?,
            ),
        };
        Ok(Self {
            method,
            uri,
            parameters: RequestParameters::compile(&spec.request_parameters, kind),
            request_mapping: RequestMapping::compile(&spec.request_parameters),
            response_mapping: ResponseMapping::compile(&spec.response_parameters),
            timeout,
            transfer,
            tls: spec.tls_config.as_ref().and_then(TlsClient::new),
            private,
        })
    }
}

/// The right-hand side of an API Gateway `requestParameters` mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParamSource {
    Path(String),
    Query(String),
    /// `method.request.multivaluequerystring.<name>`: every value.
    MultiQuery(String),
    Header(String),
    /// `method.request.multivalueheader.<name>`: every value.
    MultiHeader(String),
    /// `method.request.body`: the whole body.
    Body,
    /// `method.request.body.<json path>`: a field of a JSON body.
    BodyPath(String),
    /// A `context.<variable>` path into `$context`.
    Context(String),
    StageVariable(String),
    Literal(String),
}

impl ParamSource {
    pub(crate) fn parse(expr: &str) -> Option<Self> {
        if let Some(literal) = expr.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
            return Some(Self::Literal(literal.to_owned()));
        }
        let Some(request) = expr.strip_prefix("method.request.") else {
            return Self::parse_variable(expr);
        };
        if request == "body" {
            return Some(Self::Body);
        }
        if let Some(path) = request.strip_prefix("body.") {
            return Some(Self::BodyPath(path.to_owned()));
        }
        let (kind, name) = request.split_once('.')?;
        let name = name.to_owned();
        match kind {
            "path" => Some(Self::Path(name)),
            "querystring" => Some(Self::Query(name)),
            "multivaluequerystring" => Some(Self::MultiQuery(name)),
            "header" => Some(Self::Header(name)),
            "multivalueheader" => Some(Self::MultiHeader(name)),
            _ => None,
        }
    }

    fn parse_variable(expr: &str) -> Option<Self> {
        if let Some(path) = expr.strip_prefix("context.") {
            return Some(Self::Context(path.to_owned()));
        }
        expr.strip_prefix("stageVariables.")
            .map(|name| Self::StageVariable(name.to_owned()))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LambdaProxy {
    pub(crate) function: FunctionArn,
    /// The integration role to invoke as; `None` uses the gateway's credentials.
    pub(crate) credentials: Option<RoleArn>,
    pub(crate) payload: PayloadVersion,
    pub(crate) timeout: Duration,
    /// `Stream` invokes with `InvokeWithResponseStream` and streams the output.
    pub(crate) transfer: ResponseTransferMode,
}

/// A Lambda integration URI split into the function and how it is invoked.
///
/// REST APIs use
/// `arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{arn}/invocations`,
/// or `.../2021-11-15/functions/{arn}/response-streaming-invocations` for
/// streaming; HTTP APIs may also give the function ARN directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LambdaTarget {
    pub(crate) function: String,
    pub(crate) streaming: bool,
}

impl FromStr for LambdaTarget {
    type Err = String;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let Some((_, rest)) = uri.split_once(":lambda:path/") else {
            return if uri.contains(":lambda:") {
                Ok(Self {
                    function: uri.to_owned(),
                    streaming: false,
                })
            } else {
                Err(format!("{uri:?} is not a Lambda integration URI"))
            };
        };
        let (_, functions) = rest
            .split_once("/functions/")
            .ok_or_else(|| format!("{uri:?} has no /functions/ segment"))?;
        let (function, streaming) = match functions.strip_suffix("/response-streaming-invocations")
        {
            Some(function) => (function, true),
            None => (
                functions.strip_suffix("/invocations").unwrap_or(functions),
                false,
            ),
        };
        if function.is_empty() {
            return Err(format!("{uri:?} names no function"));
        }
        Ok(Self {
            function: function.to_owned(),
            streaming,
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::panic, reason = "tests fail loudly on unexpected variants")]
mod tests {
    use serde::Deserialize;
    use serde_json::{Value, json};

    use super::*;

    fn compile(integration: Value, kind: ApiKind) -> Integration {
        let spec = IntegrationSpec::deserialize(integration).unwrap();
        Integration::compile(
            Some(&spec),
            kind,
            &StageVariables::default(),
            &VpcLinks::default(),
        )
    }

    #[test]
    fn http_proxy_with_parameter_mappings() {
        let integration = compile(
            json!({
                "type": "http_proxy",
                "httpMethod": "GET",
                "uri": "http://backend.example/pets/{id}",
                "requestParameters": {
                    "integration.request.path.id": "method.request.path.petId",
                    "integration.request.header.x-api": "'static'",
                    "integration.request.querystring.q": "method.request.querystring.search",
                    "integration.request.header.bad": "method.request.unknown.id",
                    "integration.response.header.x": "'ignored'"
                },
                "timeoutInMillis": 5000
            }),
            ApiKind::Rest,
        );
        let Integration::HttpProxy(proxy) = integration else {
            panic!("expected HTTP proxy, got {integration:?}");
        };
        assert_eq!(proxy.method, Some(Method::GET));
        assert_eq!(proxy.timeout, Duration::from_millis(5000));
        assert_eq!(
            proxy.parameters.path.get("id"),
            Some(&ParamSource::Path("petId".to_owned()))
        );
        assert_eq!(
            proxy.parameters.headers.get("x-api"),
            Some(&ParamSource::Literal("static".to_owned()))
        );
        assert_eq!(
            proxy.parameters.query.get("q"),
            Some(&ParamSource::Query("search".to_owned()))
        );
        assert!(!proxy.parameters.headers.contains_key("bad"));
    }

    #[test]
    fn request_parameter_sources_cover_every_rest_form() {
        let source = |expr: &str| ParamSource::parse(expr);
        assert_eq!(
            source("method.request.path.id"),
            Some(ParamSource::Path("id".to_owned()))
        );
        assert_eq!(
            source("method.request.querystring.q"),
            Some(ParamSource::Query("q".to_owned()))
        );
        assert_eq!(
            source("method.request.multivaluequerystring.q"),
            Some(ParamSource::MultiQuery("q".to_owned()))
        );
        assert_eq!(
            source("method.request.header.X-A"),
            Some(ParamSource::Header("X-A".to_owned()))
        );
        assert_eq!(
            source("method.request.multivalueheader.X-A"),
            Some(ParamSource::MultiHeader("X-A".to_owned()))
        );
        assert_eq!(source("method.request.body"), Some(ParamSource::Body));
        assert_eq!(
            source("method.request.body.a.b[0]"),
            Some(ParamSource::BodyPath("a.b[0]".to_owned()))
        );
        assert_eq!(
            source("context.requestId"),
            Some(ParamSource::Context("requestId".to_owned()))
        );
        assert_eq!(
            source("stageVariables.env"),
            Some(ParamSource::StageVariable("env".to_owned()))
        );
        assert_eq!(
            source("'fixed'"),
            Some(ParamSource::Literal("fixed".to_owned()))
        );
        for unknown in [
            "method.request.cookie.c",
            "method.request.path",
            "integration.request.header.x",
            "",
        ] {
            assert_eq!(source(unknown), None, "{unknown}");
        }
    }

    #[test]
    fn multi_value_targets_compile_into_the_query_and_header_maps() {
        let Integration::HttpProxy(proxy) = compile(
            json!({"type": "http_proxy", "httpMethod": "GET", "uri": "http://b/",
            "requestParameters": {
                "integration.request.multivaluequerystring.tag": "method.request.multivaluequerystring.tag",
                "integration.request.multivalueheader.x-all": "method.request.multivalueheader.x-all",
            }}),
            ApiKind::Rest,
        ) else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(
            proxy.parameters.query.get("tag"),
            Some(&ParamSource::MultiQuery("tag".to_owned()))
        );
        assert_eq!(
            proxy.parameters.headers.get("x-all"),
            Some(&ParamSource::MultiHeader("x-all".to_owned()))
        );
    }

    #[test]
    fn http_and_mock_integrations_compile_to_mapped_integrations() {
        let http = compile(
            json!({"type": "http", "httpMethod": "POST", "uri": "http://b/x"}),
            ApiKind::Rest,
        );
        assert_eq!(http.kind(), "HTTP");
        let mock = compile(json!({"type": "mock"}), ApiKind::Rest);
        assert_eq!(mock.kind(), "MOCK");
        let private = compile_private(
            json!({"type": "http", "httpMethod": "GET", "connectionType": "VPC_LINK", "connectionId": "vl1",
                "uri": "http://nlb.internal/x"}),
            ApiKind::Rest,
            &["vl1=http://svc"],
            &[],
        );
        assert_eq!(private.kind(), "HTTP");
    }

    #[test]
    fn any_method_http_proxy_forwards_client_method_with_kind_default_timeout() {
        let integration = compile(
            json!({"type": "HTTP_PROXY", "httpMethod": "ANY", "uri": "https://e/{proxy}"}),
            ApiKind::Http,
        );
        let Integration::HttpProxy(proxy) = integration else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(proxy.method, None);
        assert_eq!(proxy.timeout, Duration::from_secs(30));
    }

    #[test]
    fn lambda_payload_versions_follow_api_kind_defaults() {
        let integration = json!({"type": "aws_proxy", "httpMethod": "POST",
            "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:pets/invocations"});
        for (kind, expected) in [
            (ApiKind::Rest, PayloadVersion::V1),
            (ApiKind::Http, PayloadVersion::V2),
        ] {
            let Integration::Lambda(lambda) = compile(integration.clone(), kind) else {
                panic!("expected Lambda");
            };
            assert_eq!(lambda.payload, expected);
            assert_eq!(
                lambda.function.as_str(),
                "arn:aws:lambda:us-east-1:123456789012:function:pets"
            );
        }
        let explicit = json!({"type": "aws_proxy", "payloadFormatVersion": "1.0", "uri": "arn:aws:lambda:us-east-1:1:function:f"});
        let Integration::Lambda(lambda) = compile(explicit, ApiKind::Http) else {
            panic!("expected Lambda");
        };
        assert_eq!(lambda.payload, PayloadVersion::V1);
        assert_eq!(
            lambda.function.as_str(),
            "arn:aws:lambda:us-east-1:1:function:f"
        );
    }

    #[test]
    fn lambda_target_uris_split_function_and_invocation_mode() {
        let target = |uri: &str| uri.parse::<LambdaTarget>();
        assert_eq!(
            target(
                "arn:aws:apigateway:r:lambda:path/2015-03-31/functions/arn:aws:lambda:r:1:function:f:live/invocations"
            ),
            Ok(LambdaTarget {
                function: "arn:aws:lambda:r:1:function:f:live".to_owned(),
                streaming: false
            })
        );
        assert_eq!(
            target(
                "arn:aws:apigateway:r:lambda:path/2021-11-15/functions/arn:aws:lambda:r:1:function:f/response-streaming-invocations"
            ),
            Ok(LambdaTarget {
                function: "arn:aws:lambda:r:1:function:f".to_owned(),
                streaming: true
            })
        );
        assert!(target("arn:aws:apigateway:us-east-1:sqs:path/q").is_err());
        assert!(
            target("arn:aws:apigateway:r:lambda:path/2015-03-31/functions//invocations").is_err()
        );
        assert!(
            target("arn:aws:apigateway:r:lambda:path/2021-11-15/functions//response-streaming-invocations").is_err()
        );
        assert!(target("arn:aws:apigateway:r:lambda:path/nofunctions").is_err());
        let integration = compile(
            json!({"type": "aws_proxy", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}),
            ApiKind::Rest,
        );
        assert!(matches!(integration, Integration::Unsupported { .. }));
    }

    fn compile_private(
        integration: Value,
        kind: ApiKind,
        links: &[&str],
        variables: &[(&str, &str)],
    ) -> Integration {
        let spec = IntegrationSpec::deserialize(integration).unwrap();
        let links = VpcLinks::new(links.iter().map(|l| l.parse().unwrap()));
        let variables = StageVariables::new(
            variables
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
        );
        Integration::compile(Some(&spec), kind, &variables, &links)
    }

    fn unsupported_reason(integration: Integration) -> String {
        let Integration::Unsupported { reason } = integration else {
            panic!("expected an unsupported integration, got {integration:?}");
        };
        reason
    }

    #[test]
    fn rest_vpc_link_routes_to_the_mapped_url_with_the_uri_host_header() {
        let integration = compile_private(
            json!({"type": "http_proxy", "httpMethod": "GET", "connectionType": "VPC_LINK",
                "connectionId": "vl1",
                "uri": "http://my-nlb-1234.elb.us-east-1.amazonaws.com:8080/pets/{id}?fixed=1"}),
            ApiKind::Rest,
            &["vl1=http://pets.default.svc:9000/base"],
            &[],
        );
        let Integration::HttpProxy(proxy) = integration else {
            panic!("expected HTTP proxy, got {integration:?}");
        };
        assert_eq!(
            proxy.uri,
            "http://pets.default.svc:9000/base/pets/{id}?fixed=1"
        );
        assert_eq!(
            proxy.private,
            Some(PrivateRouting::HostHeader(HeaderValue::from_static(
                "my-nlb-1234.elb.us-east-1.amazonaws.com:8080"
            )))
        );
    }

    #[test]
    fn rest_vpc_link_uri_without_a_path_maps_to_the_base_url() {
        let integration = compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl1",
                "uri": "https://nlb.internal"}),
            ApiKind::Rest,
            &["vl1=https://svc.ns"],
            &[],
        );
        let Integration::HttpProxy(proxy) = integration else {
            panic!("expected HTTP proxy, got {integration:?}");
        };
        assert_eq!(proxy.uri, "https://svc.ns");
        assert_eq!(
            proxy.private,
            Some(PrivateRouting::HostHeader(HeaderValue::from_static(
                "nlb.internal"
            )))
        );
    }

    #[test]
    fn http_api_vpc_link_forwards_the_request_path_to_the_mapped_url() {
        let integration = compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl2",
                "uri": "arn:aws:elasticloadbalancing:us-east-2:123456789012:listener/app/lb/50dc/0467"}),
            ApiKind::Http,
            &["vl2=http://pets.default.svc"],
            &[],
        );
        let Integration::HttpProxy(proxy) = integration else {
            panic!("expected HTTP proxy, got {integration:?}");
        };
        assert_eq!(proxy.uri, "http://pets.default.svc");
        assert_eq!(proxy.private, Some(PrivateRouting::RequestPath));
        let cloud_map = compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl2",
                "uri": "arn:aws:servicediscovery:us-east-2:123456789012:service/srv-1?stage=prod"}),
            ApiKind::Http,
            &["vl2=http://pets.default.svc"],
            &[],
        );
        assert!(matches!(cloud_map, Integration::HttpProxy(_)));
    }

    #[test]
    fn connection_ids_may_be_stage_variables() {
        let integration = compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK",
                "connectionId": "${stageVariables.link}", "uri": "http://nlb/x"}),
            ApiKind::Rest,
            &["vl9=http://svc"],
            &[("link", "vl9")],
        );
        assert!(matches!(integration, Integration::HttpProxy(_)));
    }

    #[test]
    fn unmapped_or_unusable_vpc_links_stay_unsupported_with_a_reason() {
        let unmapped = unsupported_reason(compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "nope", "uri": "http://x"}),
            ApiKind::Rest,
            &["vl1=http://svc"],
            &[],
        ));
        assert!(unmapped.contains("--vpc-link nope=<url>"), "{unmapped}");
        let no_id = unsupported_reason(compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "uri": "http://x"}),
            ApiKind::Rest,
            &["vl1=http://svc"],
            &[],
        ));
        assert!(no_id.contains("connectionId"), "{no_id}");
        let missing_variable = unsupported_reason(compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "${stageVariables.x}", "uri": "http://x"}),
            ApiKind::Rest,
            &["vl1=http://svc"],
            &[],
        ));
        assert!(
            missing_variable.contains("--vpc-link"),
            "{missing_variable}"
        );
        let http_non_arn = unsupported_reason(compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl1", "uri": "http://x"}),
            ApiKind::Http,
            &["vl1=http://svc"],
            &[],
        ));
        assert!(http_non_arn.contains("ARN"), "{http_non_arn}");
        let rest_non_url = unsupported_reason(compile_private(
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl1", "uri": "arn:aws:elasticloadbalancing:x"}),
            ApiKind::Rest,
            &["vl1=http://svc"],
            &[],
        ));
        assert!(rest_non_url.contains("http or https"), "{rest_non_url}");
        let other_type = unsupported_reason(compile_private(
            json!({"type": "aws", "connectionType": "VPC_LINK", "connectionId": "vl1", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}),
            ApiKind::Rest,
            &["vl1=http://svc"],
            &[],
        ));
        assert!(other_type.contains("HTTP_PROXY"), "{other_type}");
    }

    #[test]
    fn unservable_integrations_are_unsupported_with_reasons() {
        let cases = [
            json!({"type": "aws", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}),
            json!({"type": "http"}),
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "uri": "http://x"}),
            json!({"type": "http_proxy"}),
            json!({"type": "http_proxy", "httpMethod": "GE T", "uri": "http://x"}),
            json!({"type": "aws_proxy", "responseTransferMode": "STREAM", "uri": "arn:aws:lambda:us-east-1:1:function:f"}),
            json!({"type": "aws_proxy", "uri": "arn:aws:apigateway:us-east-1:lambda:path/2021-11-15/functions/arn:aws:lambda:us-east-1:1:function:f/response-streaming-invocations"}),
            json!({"type": "mock", "responseTransferMode": "STREAM"}),
            json!({"type": "aws_proxy", "integrationSubtype": "SQS-SendMessage"}),
        ];
        for case in cases {
            let integration = compile(case.clone(), ApiKind::Rest);
            let Integration::Unsupported { reason } = integration else {
                panic!("{case} compiled to {integration:?}");
            };
            assert!(!reason.is_empty());
        }
        assert!(matches!(
            Integration::compile(
                None,
                ApiKind::Rest,
                &StageVariables::default(),
                &VpcLinks::default(),
            ),
            Integration::Unsupported { .. }
        ));
    }

    #[test]
    fn streaming_integrations_compile_with_the_stream_timeout() {
        let lambda = compile(
            json!({"type": "aws_proxy", "responseTransferMode": "STREAM",
                "uri": "arn:aws:apigateway:us-east-1:lambda:path/2021-11-15/functions/arn:aws:lambda:us-east-1:1:function:f:live/response-streaming-invocations"}),
            ApiKind::Rest,
        );
        let Integration::Lambda(lambda) = lambda else {
            panic!("expected Lambda");
        };
        assert_eq!(lambda.transfer, ResponseTransferMode::Stream);
        assert_eq!(lambda.timeout, STREAM_LIMIT);
        assert_eq!(lambda.function.qualifier(), Some("live"));

        let http = compile(
            json!({"type": "http_proxy", "responseTransferMode": "STREAM", "uri": "http://x/",
                "timeoutInMillis": 3_600_000}),
            ApiKind::Rest,
        );
        let Integration::HttpProxy(http) = http else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(http.transfer, ResponseTransferMode::Stream);
        assert_eq!(http.timeout, STREAM_LIMIT, "streams stop at 15 minutes");
    }

    #[test]
    fn integration_timeouts_are_bounded_per_api_type() {
        let timeout = |kind: ApiKind, millis: Option<u64>| {
            let mut spec = json!({"type": "http_proxy", "uri": "http://x/"});
            if let (Some(millis), Some(fields)) = (millis, spec.as_object_mut()) {
                fields.insert("timeoutInMillis".to_owned(), json!(millis));
            }
            let Integration::HttpProxy(proxy) = compile(spec, kind) else {
                panic!("expected HTTP proxy");
            };
            proxy.timeout
        };
        let ms = Duration::from_millis;
        assert_eq!(timeout(ApiKind::Rest, None), ms(29_000));
        assert_eq!(
            timeout(ApiKind::Rest, Some(120_000)),
            ms(120_000),
            "REST timeouts may exceed 29 s"
        );
        assert_eq!(timeout(ApiKind::Rest, Some(50)), ms(50));
        assert_eq!(timeout(ApiKind::Rest, Some(10)), ms(50));
        assert_eq!(timeout(ApiKind::Http, None), ms(30_000));
        assert_eq!(timeout(ApiKind::Http, Some(30_000)), ms(30_000));
        assert_eq!(timeout(ApiKind::Http, Some(30_001)), ms(30_000));
        assert_eq!(timeout(ApiKind::Http, Some(1)), ms(50));
    }

    #[test]
    fn lambda_credentials_are_typed_and_caller_passthrough_is_unsupported() {
        let lambda = |credentials: &str| {
            compile(
                json!({"type": "aws_proxy", "uri": "arn:aws:lambda:eu-west-1:1:function:f", "credentials": credentials}),
                ApiKind::Rest,
            )
        };
        let Integration::Lambda(proxy) = lambda("arn:aws:iam::123456789012:role/invoke") else {
            panic!("expected Lambda");
        };
        assert_eq!(
            proxy.credentials.unwrap().as_str(),
            "arn:aws:iam::123456789012:role/invoke"
        );
        assert_eq!(proxy.function.region(), Some("eu-west-1"));
        assert!(
            matches!(lambda("arn:aws:iam::*:user/*"), Integration::Unsupported { ref reason } if reason.contains("passthrough"))
        );
        assert!(matches!(
            lambda("not-an-arn"),
            Integration::Unsupported { .. }
        ));
    }

    #[test]
    fn stage_variables_are_substituted() {
        let vars = StageVariables::new(BTreeMap::from([(
            "host".to_owned(),
            "api.internal".to_owned(),
        )]));
        assert_eq!(
            vars.substitute("https://${stageVariables.host}/v1/${stageVariables.missing}x"),
            "https://api.internal/v1/x"
        );
        assert_eq!(
            vars.substitute("https://${stageVariables.host"),
            "https://${stageVariables.host"
        );
        let Integration::HttpProxy(proxy) = Integration::compile(
            Some(
                &IntegrationSpec::deserialize(
                    json!({"type": "http_proxy", "uri": "http://${stageVariables.host}/"}),
                )
                .unwrap(),
            ),
            ApiKind::Rest,
            &vars,
            &VpcLinks::default(),
        ) else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(proxy.uri, "http://api.internal/");
    }
}
