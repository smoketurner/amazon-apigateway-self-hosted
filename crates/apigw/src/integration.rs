//! Integrations compiled from the model into the form requests execute against.

use std::collections::BTreeMap;
use std::time::Duration;

use axum::http::{HeaderName, HeaderValue, Method, StatusCode};
use serde_json::Value;

use crate::aws::{FunctionArn, IntegrationCredentials, RoleArn};
use crate::model::{
    ApiKind, ConnectionType, IntegrationSpec, IntegrationType, PayloadVersion, ResponseTransferMode,
};

impl ApiKind {
    /// API Gateway's integration timeout when the integration sets none.
    fn default_integration_timeout(self) -> Duration {
        match self {
            Self::Rest => Duration::from_secs(29),
            Self::Http => Duration::from_secs(30),
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

    /// Compiles an operation's integration. Anything that can't be served
    /// becomes [`Integration::Unsupported`] with the reason.
    pub(crate) fn compile(
        spec: Option<&IntegrationSpec>,
        kind: ApiKind,
        variables: &StageVariables,
    ) -> Self {
        let Some(spec) = spec else {
            return Self::unsupported("operation has no x-amazon-apigateway-integration");
        };
        Self::compile_spec(spec, kind, variables)
            .unwrap_or_else(|reason| Self::Unsupported { reason })
    }

    fn compile_spec(
        spec: &IntegrationSpec,
        kind: ApiKind,
        variables: &StageVariables,
    ) -> Result<Self, String> {
        if spec.connection_type == Some(ConnectionType::VpcLink) {
            return Err("VPC link integrations are only reachable from inside AWS".to_owned());
        }
        if spec.response_transfer_mode == Some(ResponseTransferMode::Stream) {
            return Err("response streaming is not supported yet".to_owned());
        }
        let timeout = spec
            .timeout_in_millis
            .map_or_else(|| kind.default_integration_timeout(), Duration::from_millis);
        let uri = spec.uri.as_deref().map(|uri| variables.substitute(uri));
        match spec.integration_type {
            IntegrationType::HttpProxy => {
                let uri = uri.ok_or("HTTP_PROXY integration has no uri")?;
                HttpProxy::compile(spec, uri, timeout).map(Self::HttpProxy)
            }
            IntegrationType::Mock => MockResponse::compile(spec).map(Self::Mock),
            IntegrationType::AwsProxy if spec.subtype.is_some() => Err(format!(
                "{} integrations are not supported yet",
                spec.subtype.as_deref().unwrap_or_default()
            )),
            IntegrationType::AwsProxy => {
                let function = uri
                    .as_deref()
                    .and_then(LambdaProxy::function_arn)
                    .ok_or("AWS_PROXY integration is not a Lambda function")?
                    .parse::<FunctionArn>()?;
                let credentials = match spec.credentials.as_deref().map(str::parse).transpose()? {
                    None => None,
                    Some(IntegrationCredentials::Role(role)) => Some(role),
                    Some(IntegrationCredentials::Caller) => {
                        return Err("caller credential passthrough (arn:aws:iam::*:user/*) needs IAM-authenticated callers, which cannot be verified outside AWS".to_owned());
                    }
                };
                let payload = spec.payload_format_version.unwrap_or(match kind {
                    ApiKind::Rest => PayloadVersion::V1,
                    ApiKind::Http => PayloadVersion::V2,
                });
                Ok(Self::Lambda(LambdaProxy {
                    function,
                    credentials,
                    payload,
                    timeout,
                }))
            }
            IntegrationType::Http | IntegrationType::Aws => Err(format!(
                "{} integrations need mapping templates, which are not supported yet",
                spec.integration_type
            )),
        }
    }

    fn unsupported(reason: &str) -> Self {
        Self::Unsupported {
            reason: reason.to_owned(),
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

impl HttpProxy {
    fn compile(spec: &IntegrationSpec, uri: String, timeout: Duration) -> Result<Self, String> {
        let method = match spec.http_method.as_deref() {
            None => None,
            Some(m) if m.eq_ignore_ascii_case("ANY") => None,
            Some(m) => Some(
                Method::from_bytes(m.to_ascii_uppercase().as_bytes())
                    .map_err(|_| format!("invalid integration httpMethod {m:?}"))?,
            ),
        };
        let mut path_params = BTreeMap::new();
        let mut query_params = BTreeMap::new();
        let mut headers = BTreeMap::new();
        for (target, source) in &spec.request_parameters {
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
        Ok(Self {
            method,
            uri,
            path_params,
            query_params,
            headers,
            timeout,
        })
    }
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

impl MockResponse {
    /// API Gateway selects the integration response by the `statusCode` in the
    /// request template; templates are returned verbatim because VTL is not
    /// evaluated yet.
    fn compile(spec: &IntegrationSpec) -> Result<Self, String> {
        let requested = spec
            .request_templates
            .values()
            .flatten()
            .next()
            .and_then(|template| Self::requested_status(template))
            .unwrap_or(200);
        let responses = &spec.responses;
        let selected = responses
            .get(&requested.to_string())
            .or_else(|| responses.get("default"))
            .or_else(|| responses.values().next());
        let Some(response) = selected else {
            let status = StatusCode::from_u16(requested)
                .map_err(|_| format!("invalid mock status code {requested}"))?;
            return Ok(Self {
                status,
                headers: Vec::new(),
                content_type: None,
                body: String::new(),
            });
        };
        let status = response.status().unwrap_or(requested);
        let status = StatusCode::from_u16(status)
            .map_err(|_| format!("invalid mock status code {status}"))?;
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
        let templates = &response.response_templates;
        let template = templates
            .get_key_value("application/json")
            .or_else(|| templates.iter().next());
        let (content_type, body) = match template {
            Some((content_type, body)) => (
                HeaderValue::try_from(content_type.as_str()).ok(),
                body.clone().unwrap_or_default(),
            ),
            None => (None, String::new()),
        };
        Ok(Self {
            status,
            headers,
            content_type,
            body,
        })
    }

    fn requested_status(template: &str) -> Option<u16> {
        let value: Value = serde_json::from_str(template).ok()?;
        match value.get("statusCode")? {
            Value::Number(n) => n.as_u64().and_then(|n| u16::try_from(n).ok()),
            Value::String(s) => s.parse().ok(),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LambdaProxy {
    pub(crate) function: FunctionArn,
    /// The integration role to invoke as; `None` uses the gateway's credentials.
    pub(crate) credentials: Option<RoleArn>,
    pub(crate) payload: PayloadVersion,
    pub(crate) timeout: Duration,
}

impl LambdaProxy {
    /// Extracts the function ARN from a Lambda integration URI. REST APIs use the
    /// `arn:aws:apigateway:{region}:lambda:path/2015-03-31/functions/{arn}/invocations`
    /// form; HTTP APIs may also give the function ARN directly.
    pub(crate) fn function_arn(uri: &str) -> Option<String> {
        if let Some((_, rest)) = uri.split_once(":lambda:path/") {
            let (_, functions) = rest.split_once("/functions/")?;
            let function = functions.strip_suffix("/invocations").unwrap_or(functions);
            return (!function.is_empty()).then(|| function.to_owned());
        }
        uri.contains(":lambda:").then(|| uri.to_owned())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::panic, reason = "tests fail loudly on unexpected variants")]
mod tests {
    use serde::Deserialize;
    use serde_json::json;

    use super::*;

    fn compile(integration: Value, kind: ApiKind) -> Integration {
        let spec = IntegrationSpec::deserialize(integration).unwrap();
        Integration::compile(Some(&spec), kind, &StageVariables::default())
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
                    "integration.request.header.bad": "context.requestId",
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
            proxy.path_params.get("id"),
            Some(&ParamSource::Path("petId".to_owned()))
        );
        assert_eq!(
            proxy.headers.get("x-api"),
            Some(&ParamSource::Literal("static".to_owned()))
        );
        assert_eq!(
            proxy.query_params.get("q"),
            Some(&ParamSource::Query("search".to_owned()))
        );
        assert!(!proxy.headers.contains_key("bad"));
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
    fn lambda_function_arn_rejects_non_lambda_uris() {
        assert_eq!(
            LambdaProxy::function_arn("arn:aws:apigateway:us-east-1:sqs:path/q"),
            None
        );
        assert_eq!(
            LambdaProxy::function_arn(
                "arn:aws:apigateway:r:lambda:path/2015-03-31/functions//invocations"
            ),
            None
        );
        assert_eq!(
            LambdaProxy::function_arn("arn:aws:apigateway:r:lambda:path/nofunctions"),
            None
        );
        let integration = compile(
            json!({"type": "aws_proxy", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}),
            ApiKind::Rest,
        );
        assert!(matches!(integration, Integration::Unsupported { .. }));
    }

    #[test]
    fn mock_selects_response_by_requested_status() {
        let integration = compile(
            json!({
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
            }),
            ApiKind::Rest,
        );
        let Integration::Mock(mock) = integration else {
            panic!("expected mock");
        };
        assert_eq!(mock.status, StatusCode::CREATED);
        assert_eq!(mock.body, "{\"ok\":true}");
        assert_eq!(mock.headers.len(), 1);
        assert_eq!(mock.content_type.unwrap(), "application/json");
    }

    #[test]
    fn mock_without_responses_returns_requested_status_or_rejects_invalid() {
        let mock = |template: &str| {
            compile(
                json!({"type": "mock", "requestTemplates": {"application/json": template}}),
                ApiKind::Rest,
            )
        };
        let Integration::Mock(m) = mock("{\"statusCode\": 204}") else {
            panic!("expected mock")
        };
        assert_eq!(m.status, StatusCode::NO_CONTENT);
        assert!(matches!(
            mock("{\"statusCode\": 42}"),
            Integration::Unsupported { .. }
        ));
        let Integration::Mock(m) = mock("#set($x = 1)") else {
            panic!("expected mock")
        };
        assert_eq!(m.status, StatusCode::OK);
    }

    #[test]
    fn unservable_integrations_are_unsupported_with_reasons() {
        let cases = [
            json!({"type": "aws", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}),
            json!({"type": "http", "uri": "http://x"}),
            json!({"type": "http_proxy", "connectionType": "VPC_LINK", "uri": "http://x"}),
            json!({"type": "http_proxy"}),
            json!({"type": "http_proxy", "httpMethod": "GE T", "uri": "http://x"}),
            json!({"type": "aws_proxy", "responseTransferMode": "STREAM", "uri": "arn:aws:lambda:us-east-1:1:function:f"}),
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
            Integration::compile(None, ApiKind::Rest, &StageVariables::default()),
            Integration::Unsupported { .. }
        ));
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
        ) else {
            panic!("expected HTTP proxy");
        };
        assert_eq!(proxy.uri, "http://api.internal/");
    }
}
