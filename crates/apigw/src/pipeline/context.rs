//! `RequestContext`: one request as the pipeline sees it, and the single owner
//! of API Gateway's `$context` variables. Lambda events, mapping templates,
//! gateway responses, and access logs all read `$context` from here.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::Request;
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, Version, header};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::canary::Release;
use crate::gateway::{ApiContext, RequestId};
use crate::header_case::HeaderCase;
use crate::identity::ClientIdentity;
use crate::integration::StageVariables;
use crate::model::{ApiKind, PayloadVersion, ResponseTransferMode, RouteKey};
use crate::observability::Trace;
use crate::route::Route;

/// The API and stage a request was received on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiInfo {
    pub(crate) kind: ApiKind,
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
    /// Which release serves the request, for stages that have a canary.
    pub(crate) release: Option<Release>,
}

impl ApiInfo {
    /// The `$context.stage` value: HTTP APIs without a named stage use `$default`.
    pub(crate) fn stage_name(&self) -> &str {
        self.stage.as_deref().unwrap_or("$default")
    }
}

/// A raw (still percent-encoded) query string.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct QueryString(Option<String>);

impl QueryString {
    pub(crate) fn new(raw: Option<&str>) -> Self {
        Self(raw.filter(|q| !q.is_empty()).map(str::to_owned))
    }

    pub(crate) fn raw(&self) -> Option<&str> {
        self.0.as_deref()
    }

    /// Decoded `name=value` pairs in order, repeats included; a bare `name`
    /// has an empty value.
    pub(crate) fn pairs(&self) -> Vec<(String, String)> {
        let Some(ref query) = self.0 else {
            return Vec::new();
        };
        let mut pairs = Vec::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            pairs.push((FormEncoded(key).decode(), FormEncoded(value).decode()));
        }
        pairs
    }
}

/// One `application/x-www-form-urlencoded` component (`+` is a space).
struct FormEncoded<'a>(&'a str);

impl FormEncoded<'_> {
    fn decode(&self) -> String {
        let mut out = Vec::with_capacity(self.0.len());
        let mut iter = self.0.bytes();
        while let Some(byte) = iter.next() {
            match byte {
                b'+' => out.push(b' '),
                b'%' => {
                    let mut lookahead = iter.clone();
                    let decoded = match (lookahead.next(), lookahead.next()) {
                        (Some(hi), Some(lo)) => Self::hex(hi).zip(Self::hex(lo)),
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

    fn hex(byte: u8) -> Option<u8> {
        char::from(byte)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    }
}

/// What produced `$context.authorizer`, which decides how Lambda proxy events
/// of HTTP API payload format 2.0 nest it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum AuthorizerSource {
    #[default]
    None,
    Lambda,
    /// Verified token claims (and, for HTTP APIs, scopes).
    Claims,
}

/// `$context.authorizer.*`: what the request's authorizer produced.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct AuthorizerContext {
    values: Map<String, Value>,
    source: AuthorizerSource,
}

impl AuthorizerContext {
    /// A Lambda authorizer's `principalId` and `context` map.
    pub(crate) fn lambda(values: Map<String, Value>) -> Self {
        Self {
            values,
            source: AuthorizerSource::Lambda,
        }
    }

    /// A token authorizer's `claims` (and `scopes`).
    pub(crate) fn claims(values: Map<String, Value>) -> Self {
        Self {
            values,
            source: AuthorizerSource::Claims,
        }
    }

    pub(crate) fn values(&self) -> &Map<String, Value> {
        &self.values
    }

    /// The value of `requestContext.authorizer` in a Lambda proxy event of this
    /// payload version, if an authorizer ran.
    pub(crate) fn event_value(&self, version: PayloadVersion) -> Option<Value> {
        match (self.source, version) {
            (AuthorizerSource::None, _) => None,
            (AuthorizerSource::Lambda | AuthorizerSource::Claims, PayloadVersion::V1) => {
                Some(Value::Object(self.values.clone()))
            }
            (AuthorizerSource::Lambda, PayloadVersion::V2) => {
                let mut context = self.values.clone();
                context.remove("principalId");
                Some(json!({ "lambda": context }))
            }
            (AuthorizerSource::Claims, PayloadVersion::V2) => Some(json!({ "jwt": self.values })),
        }
    }
}

/// Outcome of the integration call, for `$context.integration.*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IntegrationOutcome {
    pub(crate) status: Option<u16>,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) error: Option<String>,
    pub(crate) transfer_mode: Option<ResponseTransferMode>,
    /// Streaming integrations: time from connecting to having every response
    /// header (`$context.integration.timeToAllHeaders`).
    pub(crate) time_to_all_headers_ms: Option<u64>,
}

impl ResponseTransferMode {
    /// The value `$context.integration.responseTransferMode` reports.
    fn context_name(self) -> &'static str {
        match self {
            Self::Buffered => "BUFFERED",
            Self::Stream => "STREAMED",
        }
    }
}

/// One request: what the client sent, plus everything API Gateway records
/// about it while processing.
#[derive(Debug, Clone)]
pub(crate) struct RequestContext {
    pub(crate) api: ApiInfo,
    pub(crate) route_key: RouteKey,
    /// The resource path as configured (`/pets/{petId}`), not the request path.
    pub(crate) resource_path: String,
    pub(crate) request_id: Uuid,
    pub(crate) received: jiff::Timestamp,
    pub(crate) method: Method,
    pub(crate) path: String,
    pub(crate) query: QueryString,
    pub(crate) headers: HeaderMap,
    /// The client's spelling of header names, known for HTTP/1 requests.
    pub(crate) header_case: HeaderCase,
    pub(crate) version: Version,
    pub(crate) path_params: Vec<(String, String)>,
    pub(crate) identity: ClientIdentity,
    pub(crate) body: Bytes,
    pub(crate) authorizer: AuthorizerContext,
    pub(crate) stage_variables: Arc<StageVariables>,
    /// This request's place in an X-Ray trace, when the stage traces.
    pub(crate) trace: Option<Trace>,
    pub(crate) integration: IntegrationOutcome,
}

/// A `$context` document, addressable by dotted path (`identity.sourceIp`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ContextVariables(Value);

impl ContextVariables {
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    /// The variable at `path` as text: strings as they are, numbers and
    /// booleans as written, structures as compact JSON. Missing and `null`
    /// variables have no value.
    pub(crate) fn lookup(&self, path: &str) -> Option<String> {
        let mut value = &self.0;
        for segment in path.split('.') {
            value = value.get(segment)?;
        }
        match value {
            Value::Null => None,
            Value::String(text) => Some(text.clone()),
            Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
                Some(value.to_string())
            }
        }
    }

    pub(crate) fn set(&mut self, name: &str, value: Value) {
        if let Value::Object(ref mut fields) = self.0 {
            fields.insert(name.to_owned(), value);
        }
    }
}

impl RequestContext {
    /// A copy of `request`'s metadata for logging, taken before the request
    /// moves into its route: no body and no path parameters.
    pub(crate) fn observed(api: &ApiContext, route: Option<&Route>, request: &Request) -> Self {
        let mut snapshot = axum::http::Request::new(());
        *snapshot.method_mut() = request.method().clone();
        *snapshot.uri_mut() = request.uri().clone();
        *snapshot.headers_mut() = request.headers().clone();
        if let Some(id) = request.extensions().get::<RequestId>() {
            snapshot.extensions_mut().insert(*id);
        }
        if let Some(identity) = request.extensions().get::<ClientIdentity>() {
            snapshot.extensions_mut().insert(identity.clone());
        }
        if let Some(trace) = request.extensions().get::<Trace>() {
            snapshot.extensions_mut().insert(*trace);
        }
        let (parts, ()) = snapshot.into_parts();
        Self::new(api, route, parts, Vec::new())
    }

    /// Captures a request before its body is read. `route` is `None` for
    /// requests that matched no route.
    pub(crate) fn new(
        api: &ApiContext,
        route: Option<&Route>,
        parts: Parts,
        path_params: Vec<(String, String)>,
    ) -> Self {
        let Parts {
            method,
            uri,
            version,
            mut headers,
            mut extensions,
            ..
        } = parts;
        if !headers.contains_key(header::HOST)
            && let Some(authority) = uri.authority()
            && let Ok(host) = HeaderValue::from_str(authority.as_str())
        {
            headers.insert(header::HOST, host);
        }
        let header_case = extensions.remove::<HeaderCase>().unwrap_or_default();
        let request_id = extensions
            .get::<RequestId>()
            .map_or_else(Uuid::now_v7, |id| id.0);
        let trace = extensions.get::<Trace>().copied();
        let identity = extensions.remove::<ClientIdentity>().unwrap_or_else(|| {
            tracing::warn!("request reached the pipeline without a client identity");
            ClientIdentity::unknown()
        });
        let (route_key, resource_path) = match route {
            Some(route) => (route.key.clone(), route.path.to_string()),
            None => (RouteKey::from(""), uri.path().to_owned()),
        };
        Self {
            api: ApiInfo {
                kind: api.kind,
                api_id: api.api_id.clone(),
                stage: api.stage.clone(),
                release: api.release,
            },
            route_key,
            resource_path,
            request_id,
            received: jiff::Timestamp::now(),
            method,
            path: uri.path().to_owned(),
            query: QueryString::new(uri.query()),
            headers,
            header_case,
            version,
            path_params,
            identity,
            body: Bytes::new(),
            authorizer: AuthorizerContext::default(),
            stage_variables: Arc::clone(&api.stage_variables),
            trace,
            integration: IntegrationOutcome::default(),
        }
    }

    /// `$context.extendedRequestId`: API Gateway's is an opaque 12-character
    /// base64 token; this one is derived from the random half of the request
    /// ID so the header and the context variable agree.
    pub(crate) fn extended_request_id(&self) -> String {
        BASE64.encode(
            self.request_id
                .as_bytes()
                .iter()
                .skip(8)
                .copied()
                .collect::<Vec<u8>>(),
        )
    }

    /// `$context.protocol`. REST APIs report `HTTP/1.1` even to HTTP/2 clients
    /// (the REST `$context.protocol` documentation says so); HTTP APIs report
    /// the client's version.
    pub(crate) fn protocol(&self) -> &'static str {
        if self.api.kind == ApiKind::Rest {
            return "HTTP/1.1";
        }
        match self.version {
            Version::HTTP_09 => "HTTP/0.9",
            Version::HTTP_10 => "HTTP/1.0",
            Version::HTTP_2 => "HTTP/2.0",
            Version::HTTP_3 => "HTTP/3.0",
            _ => "HTTP/1.1",
        }
    }

    pub(crate) fn context_value(&self, path: &str) -> Option<String> {
        ContextVariables::new(self.variables()).lookup(path)
    }

    pub(crate) fn path_param(&self, name: &str) -> Option<&str> {
        self.path_params
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    pub(crate) fn source_ip(&self) -> Option<String> {
        self.identity.source_ip().ip().map(|ip| ip.to_string())
    }

    pub(crate) fn domain_name(&self) -> &str {
        self.header_str("host").unwrap_or_default()
    }

    pub(crate) fn domain_prefix(&self) -> &str {
        self.domain_name().split('.').next().unwrap_or_default()
    }

    /// `$context.requestTime` in API Gateway's CLF format.
    pub(crate) fn request_time(&self) -> String {
        self.received.strftime("%d/%b/%Y:%H:%M:%S %z").to_string()
    }

    /// The `X-Amzn-Trace-Id` to propagate to integrations.
    pub(crate) fn trace_header(&self) -> Option<String> {
        self.header_str("x-amzn-trace-id").map(str::to_owned)
    }

    /// API Gateway's `$context` variables as a JSON object, using API Gateway's
    /// names. Values that aren't known yet are omitted rather than invented.
    pub(crate) fn variables(&self) -> Value {
        let mut context = json!({
            "apiId": self.api.api_id,
            "domainName": self.domain_name(),
            "domainPrefix": self.domain_prefix(),
            "extendedRequestId": self.extended_request_id(),
            "httpMethod": self.method.as_str(),
            "identity": {
                "sourceIp": self.source_ip(),
                "userAgent": self.header_str("user-agent"),
            },
            "path": self.path,
            "protocol": self.protocol(),
            "requestId": self.request_id.to_string(),
            "requestTime": self.request_time(),
            "requestTimeEpoch": self.received.as_millisecond(),
            "resourcePath": self.resource_path,
            "routeKey": self.route_key.as_str(),
            "stage": self.api.stage_name(),
            "authorizer": Value::Object(self.authorizer.values().clone()),
        });
        if let (Value::Object(fields), Some(trace)) = (&mut context, self.trace) {
            fields.insert("xrayTraceId".to_owned(), json!(trace.id().to_string()));
        }
        if let Some(cert) = self.identity.client_cert()
            && let Some(Value::Object(identity)) = context.get_mut("identity")
        {
            identity.insert("clientCert".to_owned(), cert.to_json());
        }
        if let (Value::Object(fields), Some(release)) = (&mut context, self.api.release) {
            fields.insert("isCanaryRequest".to_owned(), json!(release.is_canary()));
        }
        let mut integration = BTreeMap::new();
        if let Some(status) = self.integration.status {
            integration.insert("status", json!(status));
        }
        if let Some(latency) = self.integration.latency_ms {
            integration.insert("latency", json!(latency));
        }
        if let Some(ref error) = self.integration.error {
            integration.insert("error", json!(error));
        }
        if let Some(mode) = self.integration.transfer_mode {
            integration.insert("responseTransferMode", json!(mode.context_name()));
        }
        if let Some(time) = self.integration.time_to_all_headers_ms {
            integration.insert("timeToAllHeaders", json!(time));
        }
        if let Value::Object(ref mut fields) = context {
            fields.insert("integration".to_owned(), json!(integration));
        }
        context
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]
pub(crate) mod tests {
    use std::net::SocketAddr;

    use axum::http::HeaderValue;

    use super::*;
    use crate::client_cert::ClientCertDetails;
    use crate::client_cert::tests::certificate;
    use crate::identity::TrustedProxies;

    /// A request from 192.0.2.1 to `POST /pets/7` on `POST /pets/{petId}`.
    pub(crate) fn request(kind: ApiKind) -> RequestContext {
        let mut headers = HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("api.example.com"));
        headers.insert("user-agent", HeaderValue::from_static("curl/8"));
        let peer: SocketAddr = "192.0.2.1:5000".parse().unwrap();
        let identity = TrustedProxies::none().identify(peer, &mut headers);
        RequestContext {
            api: ApiInfo {
                kind,
                api_id: "abc123".to_owned(),
                stage: Some("prod".to_owned()),
                release: None,
            },
            route_key: RouteKey::from("POST /pets/{petId}"),
            resource_path: "/pets/{petId}".to_owned(),
            request_id: Uuid::now_v7(),
            received: jiff::Timestamp::from_second(1_700_000_000).unwrap(),
            method: Method::POST,
            path: "/pets/7".to_owned(),
            query: QueryString::new(Some("q=1&q=2")),
            headers,
            header_case: HeaderCase::default(),
            version: Version::HTTP_11,
            path_params: vec![("petId".to_owned(), "7".to_owned())],
            identity,
            body: Bytes::new(),
            authorizer: AuthorizerContext::default(),
            trace: None,
            stage_variables: Arc::default(),
            integration: IntegrationOutcome::default(),
        }
    }

    #[test]
    fn form_decoding_handles_malformed_escapes() {
        assert_eq!(FormEncoded("a%20b+c").decode(), "a b c");
        assert_eq!(FormEncoded("100%").decode(), "100%");
        assert_eq!(FormEncoded("%zz%4").decode(), "%zz%4");
        assert_eq!(FormEncoded("%E2%9C%93").decode(), "\u{2713}");
        assert_eq!(FormEncoded("%FF").decode(), "\u{FFFD}");
    }

    #[test]
    fn query_pairs_keep_repeats_and_bare_keys() {
        let query = QueryString::new(Some("a=1&a=2&flag&&b=x%3Dy"));
        assert_eq!(
            query.pairs(),
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("a".to_owned(), "2".to_owned()),
                ("flag".to_owned(), String::new()),
                ("b".to_owned(), "x=y".to_owned()),
            ]
        );
        assert_eq!(QueryString::new(Some("")).raw(), None);
        assert!(QueryString::new(None).pairs().is_empty());
    }

    #[test]
    fn context_variables_use_api_gateway_names() {
        let mut request = request(ApiKind::Rest);
        request.integration = IntegrationOutcome {
            status: Some(200),
            latency_ms: Some(12),
            error: None,
            transfer_mode: Some(ResponseTransferMode::Stream),
            time_to_all_headers_ms: Some(5),
        };
        request.authorizer = AuthorizerContext::lambda(Map::from_iter([
            ("principalId".to_owned(), json!("user-1")),
            ("tenant".to_owned(), json!("acme")),
        ]));
        let vars = request.variables();
        assert_eq!(vars["apiId"], "abc123");
        assert_eq!(vars["stage"], "prod");
        assert_eq!(vars["resourcePath"], "/pets/{petId}");
        assert_eq!(vars["routeKey"], "POST /pets/{petId}");
        assert_eq!(vars["identity"]["sourceIp"], "192.0.2.1");
        assert_eq!(vars["identity"]["userAgent"], "curl/8");
        assert_eq!(vars["domainPrefix"], "api");
        assert_eq!(vars["requestTime"], "14/Nov/2023:22:13:20 +0000");
        assert_eq!(vars["requestTimeEpoch"], 1_700_000_000_000_i64);
        assert_eq!(vars["integration"]["status"], 200);
        assert_eq!(vars["integration"]["responseTransferMode"], "STREAMED");
        assert_eq!(vars["integration"]["timeToAllHeaders"], 5);
        assert_eq!(vars["authorizer"]["principalId"], "user-1");
        assert!(vars["integration"].get("error").is_none());
    }

    #[test]
    fn protocol_follows_the_client_for_http_apis_only() {
        let mut http = request(ApiKind::Http);
        let mut rest = request(ApiKind::Rest);
        for (version, expected) in [
            (Version::HTTP_10, "HTTP/1.0"),
            (Version::HTTP_11, "HTTP/1.1"),
            (Version::HTTP_2, "HTTP/2.0"),
        ] {
            http.version = version;
            rest.version = version;
            assert_eq!(http.protocol(), expected);
            assert_eq!(
                rest.protocol(),
                "HTTP/1.1",
                "REST reports HTTP/1.1 for every client"
            );
        }
    }

    #[test]
    fn lambda_authorizer_context_nests_by_payload_version() {
        let context = AuthorizerContext::lambda(Map::from_iter([
            ("principalId".to_owned(), json!("user-1")),
            ("tenant".to_owned(), json!("acme")),
        ]));
        assert_eq!(
            context.event_value(PayloadVersion::V1),
            Some(json!({"principalId": "user-1", "tenant": "acme"}))
        );
        assert_eq!(
            context.event_value(PayloadVersion::V2),
            Some(json!({"lambda": {"tenant": "acme"}}))
        );
        assert_eq!(
            AuthorizerContext::default().event_value(PayloadVersion::V1),
            None
        );
        assert_eq!(
            AuthorizerContext::default().event_value(PayloadVersion::V2),
            None
        );
    }

    #[test]
    fn unnamed_http_api_stage_is_default() {
        let info = ApiInfo {
            kind: ApiKind::Http,
            api_id: "a".to_owned(),
            stage: None,
            release: None,
        };
        assert_eq!(info.stage_name(), "$default");
    }

    #[test]
    fn the_client_certificate_is_a_context_variable_only_when_there_is_one() {
        let mut ctx = request(ApiKind::Rest);
        assert!(ctx.variables()["identity"].get("clientCert").is_none());
        let (der, _) = certificate("mtls client");
        ctx.identity = ctx
            .identity
            .with_verified_certificate(ClientCertDetails::from_der(der.as_ref()).unwrap());
        let vars = ctx.variables();
        assert_eq!(
            vars["identity"]["clientCert"]["subjectDN"],
            "C=US,O=Acme,CN=mtls client"
        );
        assert_eq!(vars["identity"]["sourceIp"], "192.0.2.1");
        assert_eq!(
            ctx.context_value("identity.clientCert.issuerDN").as_deref(),
            Some("C=US,O=Acme,CN=mtls client")
        );
    }
}
