//! `RequestContext`: one request as the pipeline sees it, and the single owner
//! of API Gateway's `$context` variables. Lambda events, mapping templates,
//! gateway responses, and access logs all read `$context` from here.

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, Method};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::gateway::RequestId;
use crate::identity::ClientIdentity;
use crate::model::{ApiKind, RouteKey};
use crate::route::Route;

/// The API and stage a request was received on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiInfo {
    pub(crate) kind: ApiKind,
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
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

/// Outcome of the integration call, for `$context.integration.*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IntegrationOutcome {
    pub(crate) status: Option<u16>,
    pub(crate) latency_ms: Option<u64>,
    pub(crate) error: Option<String>,
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
    pub(crate) path_params: Vec<(String, String)>,
    pub(crate) identity: ClientIdentity,
    pub(crate) body: Bytes,
    /// `$context.authorizer.*`, filled by authorizers.
    pub(crate) authorizer: Map<String, Value>,
    pub(crate) integration: IntegrationOutcome,
}

impl RequestContext {
    /// The request as observation sees it, before a route has run: everything
    /// but the body and the path parameters, which logging does not need.
    /// `route` is `None` for a request no route matched.
    pub(crate) fn observed(api: ApiInfo, route: Option<&Route>, request: &Request) -> Self {
        Self {
            api,
            route_key: route.map_or_else(|| RouteKey::from("-"), |r| r.key.clone()),
            resource_path: route.map_or_else(|| "-".to_owned(), |r| r.path.to_string()),
            request_id: request
                .extensions()
                .get::<RequestId>()
                .map_or_else(Uuid::now_v7, |id| id.0),
            received: jiff::Timestamp::now(),
            method: request.method().clone(),
            path: request.uri().path().to_owned(),
            query: QueryString::new(request.uri().query()),
            headers: request.headers().clone(),
            path_params: Vec::new(),
            identity: request
                .extensions()
                .get::<ClientIdentity>()
                .cloned()
                .unwrap_or_else(ClientIdentity::unknown),
            body: Bytes::new(),
            authorizer: Map::new(),
            integration: IntegrationOutcome::default(),
        }
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
            "extendedRequestId": self.request_id.to_string(),
            "httpMethod": self.method.as_str(),
            "identity": {
                "sourceIp": self.source_ip(),
                "userAgent": self.header_str("user-agent"),
            },
            "path": self.path,
            "protocol": "HTTP/1.1",
            "requestId": self.request_id.to_string(),
            "requestTime": self.request_time(),
            "requestTimeEpoch": self.received.as_millisecond(),
            "resourcePath": self.resource_path,
            "routeKey": self.route_key.as_str(),
            "stage": self.api.stage_name(),
            "authorizer": Value::Object(self.authorizer.clone()),
        });
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
            },
            route_key: RouteKey::from("POST /pets/{petId}"),
            resource_path: "/pets/{petId}".to_owned(),
            request_id: Uuid::now_v7(),
            received: jiff::Timestamp::from_second(1_700_000_000).unwrap(),
            method: Method::POST,
            path: "/pets/7".to_owned(),
            query: QueryString::new(Some("q=1&q=2")),
            headers,
            path_params: vec![("petId".to_owned(), "7".to_owned())],
            identity,
            body: Bytes::new(),
            authorizer: Map::new(),
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
        };
        request
            .authorizer
            .insert("principalId".to_owned(), json!("user-1"));
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
        assert_eq!(vars["authorizer"]["principalId"], "user-1");
        assert!(vars["integration"].get("error").is_none());
    }

    #[test]
    fn unnamed_http_api_stage_is_default() {
        let info = ApiInfo {
            kind: ApiKind::Http,
            api_id: "a".to_owned(),
            stage: None,
        };
        assert_eq!(info.stage_name(), "$default");
    }
}
