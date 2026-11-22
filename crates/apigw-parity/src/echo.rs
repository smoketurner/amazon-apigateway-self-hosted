//! The echo backend: the wire format of the reference echo Lambda's function-URL
//! event, a parser for what it returns, and an in-process server that reproduces
//! it so replay can run without AWS.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::routing::post;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::task::JoinHandle;

use crate::error::{ParityError, Result};

const SECRET_HEADER: &str = "x-echo-secret";
const REDACTED: &str = "[redacted]";
const MAX_ECHO_BODY: usize = 10 * 1024 * 1024;
/// Where the echo accepts Lambda Invoke requests; `apigw --lambda-endpoint` points here.
pub(crate) const LAMBDA_INVOKE_PATH: &str = "/__lambda/invocations";
/// Where replay points the reference stack's authorizer function.
pub(crate) const AUTHORIZER_INVOKE_PATH: &str = "/__lambda/authorizer";
const FUNCTION_ERROR_HEADER: &str = "x-amz-function-error";
/// The longest `echo_sleep_ms` the reference echo function honors.
const MAX_SLEEP_MS: u64 = 3000;

/// A Lambda event the echo returns: payload format 2.0 (HTTP API and Lambda
/// function URLs) or payload format 1.0 (REST API, and HTTP API with payload 1.0).
/// Only the fields the runner reads are modeled; extra fields are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(crate) enum EchoEvent {
    V2(EventV2),
    V1(EventV1),
}

/// Payload format 2.0, which is also what the function URL sends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventV2 {
    version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    route_key: Option<String>,
    raw_path: String,
    raw_query_string: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    request_context: RequestContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    path_parameters: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    #[serde(default)]
    is_base64_encoded: bool,
}

/// Payload format 1.0.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EventV1 {
    http_method: String,
    path: String,
    #[serde(default)]
    resource: Option<String>,
    #[serde(default)]
    headers: Option<BTreeMap<String, String>>,
    #[serde(default)]
    multi_value_query_string_parameters: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    path_parameters: Option<BTreeMap<String, String>>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    is_base64_encoded: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RequestContext {
    http: HttpContext,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HttpContext {
    method: String,
    path: String,
}

/// What the echo backend received, in the form fixtures store: header names
/// lowercased, the query string sorted so parameter order does not matter, and a
/// base64 body decoded when it is text. `resource` is the route's resource path
/// (payload 1.0) or route key (payload 2.0), when the event carries one.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EchoReceived {
    pub(crate) method: String,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) query: String,
    #[serde(default)]
    pub(crate) headers: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) body: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) path_parameters: BTreeMap<String, String>,
}

impl EchoEvent {
    /// Parses the body of an echo response.
    ///
    /// # Errors
    /// Fails with the JSON error when the body is not an echo event.
    pub(crate) fn parse(body: &[u8]) -> std::result::Result<Self, serde_json::Error> {
        serde_json::from_slice(body)
    }

    /// The fixture form of this event; header values are returned untouched so
    /// the normalizer can mask or drop them.
    pub(crate) fn received(self) -> EchoReceived {
        match self {
            Self::V2(event) => event.received(),
            Self::V1(event) => event.received(),
        }
    }
}

impl EventV2 {
    fn received(self) -> EchoReceived {
        EchoReceived {
            method: self.request_context.http.method,
            path: self.raw_path,
            query: sorted_query(&self.raw_query_string),
            headers: lowercase_names(self.headers),
            body: decoded_body(self.body, self.is_base64_encoded),
            resource: self.route_key,
            path_parameters: self.path_parameters.unwrap_or_default(),
        }
    }
}

impl EventV1 {
    fn received(self) -> EchoReceived {
        let mut pairs: Vec<String> = Vec::new();
        for (name, values) in self.multi_value_query_string_parameters.unwrap_or_default() {
            for value in values {
                pairs.push(format!("{name}={value}"));
            }
        }
        pairs.sort_unstable();
        EchoReceived {
            method: self.http_method,
            path: self.path,
            query: pairs.join("&"),
            headers: lowercase_names(self.headers.unwrap_or_default()),
            body: decoded_body(self.body, self.is_base64_encoded),
            resource: self.resource,
            path_parameters: self.path_parameters.unwrap_or_default(),
        }
    }
}

fn lowercase_names(headers: BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .into_iter()
        .map(|(name, value)| (name.to_ascii_lowercase(), value))
        .collect()
}

fn decoded_body(body: Option<String>, is_base64: bool) -> Option<String> {
    body.map(|text| if is_base64 { decode_body(&text) } else { text })
}

fn decode_body(encoded: &str) -> String {
    match base64::engine::general_purpose::STANDARD.decode(encoded) {
        Ok(bytes) => String::from_utf8(bytes).unwrap_or_else(|err| {
            format!(
                "base64:{}",
                base64::engine::general_purpose::STANDARD.encode(err.as_bytes())
            )
        }),
        Err(_) => encoded.to_owned(),
    }
}

/// Sorts the `&`-separated pairs so two requests that differ only in parameter
/// order compare equal.
fn sorted_query(query: &str) -> String {
    let mut pairs: Vec<&str> = query.split('&').filter(|pair| !pair.is_empty()).collect();
    pairs.sort_unstable();
    pairs.join("&")
}

/// An echo server on a loopback port, stopped when dropped.
#[derive(Debug)]
pub(crate) struct EchoServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl EchoServer {
    /// Starts serving on an ephemeral loopback port.
    ///
    /// # Errors
    /// Fails when no port can be bound.
    pub(crate) async fn start() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .map_err(|e| ParityError::Start {
                what: "echo server",
                reason: e.to_string(),
            })?;
        let addr = listener.local_addr().map_err(|e| ParityError::Start {
            what: "echo server",
            reason: e.to_string(),
        })?;
        let app = Router::new()
            .route(LAMBDA_INVOKE_PATH, post(lambda_invoke))
            .route(AUTHORIZER_INVOKE_PATH, post(authorizer_invoke))
            .fallback(respond);
        let task = tokio::spawn(async move {
            if let Err(err) = axum::serve(listener, app).await {
                tracing::error!(%err, "echo server stopped");
            }
        });
        Ok(Self { addr, task })
    }

    /// The `host:port` to give integrations as the echo's stage variable.
    pub(crate) fn authority(&self) -> String {
        self.addr.to_string()
    }
}

impl Drop for EchoServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn respond(request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = axum::body::to_bytes(body, MAX_ECHO_BODY)
        .await
        .unwrap_or_default();
    let query = parts.uri.query().unwrap_or_default();
    let steer = Steering::from_query(query);
    tokio::time::sleep(steer.sleep).await;

    if steer.binary {
        return steer.binary_response();
    }

    let mut headers = BTreeMap::new();
    for (name, value) in &parts.headers {
        let name = name.as_str().to_owned();
        let value = if name == SECRET_HEADER {
            REDACTED.to_owned()
        } else {
            String::from_utf8_lossy(value.as_bytes()).into_owned()
        };
        headers
            .entry(name)
            .and_modify(|joined: &mut String| {
                joined.push(',');
                joined.push_str(&value);
            })
            .or_insert(value);
    }
    let event = EchoEvent::V2(EventV2 {
        version: "2.0".to_owned(),
        route_key: None,
        raw_path: parts.uri.path().to_owned(),
        raw_query_string: query.to_owned(),
        headers,
        request_context: RequestContext {
            http: HttpContext {
                method: parts.method.to_string(),
                path: parts.uri.path().to_owned(),
            },
        },
        path_parameters: None,
        body: body_field(&bytes),
        is_base64_encoded: std::str::from_utf8(&bytes).is_err() && !bytes.is_empty(),
    });
    json_response(steer.status, &event)
}

/// Lambda's Invoke protocol: the request body is the event, and the response
/// body is the function's payload.
async fn lambda_invoke(body: Bytes) -> Response {
    let Ok(event) = serde_json::from_slice::<Value>(&body) else {
        let mut response = Response::new(Body::from("the event is not JSON"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    };
    if !is_proxy_event(&event) {
        // The reference function returns any other event as it is, and fails
        // when the event's body asks it to.
        let fail = event
            .pointer("/body/fail")
            .is_some_and(|fail| !matches!(fail, Value::Null | Value::Bool(false)));
        // `(event.get("body") or {}).get("fail")` raises on a truthy body
        // that is not an object.
        let not_an_object = event.get("body").filter(|body| match body {
            Value::Null | Value::Object(_) => false,
            Value::Bool(truthy) => *truthy,
            Value::Number(number) => number.as_f64() != Some(0.0),
            Value::String(text) => !text.is_empty(),
            Value::Array(items) => !items.is_empty(),
        });
        return match (fail, not_an_object) {
            (true, _) => function_error("Error: forced failure"),
            (false, Some(body)) => function_error(&format!(
                "'{}' object has no attribute 'get'",
                python_type(body)
            )),
            (false, None) => payload_response(&event),
        };
    }
    let steer = Steering::from_event(&event);
    tokio::time::sleep(steer.sleep).await;
    if let Some(ref text) = steer.unparsed_status {
        return function_error(&format!("invalid literal for int() with base 10: '{text}'"));
    }
    let payload = steer.lambda_payload(&String::from_utf8_lossy(&body));
    payload_response(&payload)
}

/// What the reference echo function treats as an API Gateway or function URL event.
fn is_proxy_event(event: &Value) -> bool {
    event.get("requestContext").is_some()
        && (event.get("httpMethod").is_some()
            || event.get("version").and_then(Value::as_str) == Some("2.0"))
}

fn python_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "NoneType",
        Value::Bool(_) => "bool",
        Value::Number(number) if number.is_f64() => "float",
        Value::Number(_) => "int",
        Value::String(_) => "str",
        Value::Array(_) => "list",
        Value::Object(_) => "dict",
    }
}

fn payload_response(payload: &Value) -> Response {
    let mut response = Response::new(Body::from(payload.to_string()));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// An unhandled exception, as Lambda's Invoke API reports one.
fn function_error(message: &str) -> Response {
    let mut response = payload_response(&json!({
        "errorMessage": message,
        "errorType": "Exception",
        "requestId": "00000000-0000-0000-0000-000000000000",
        "stackTrace": [],
    }));
    response
        .headers_mut()
        .insert(FUNCTION_ERROR_HEADER, HeaderValue::from_static("Unhandled"));
    response
}

/// The reference stack's authorizer function: the credential `allow`
/// authorizes, `deny` denies, and anything else raises.
async fn authorizer_invoke(body: Bytes) -> Response {
    let Ok(event) = serde_json::from_slice::<Value>(&body) else {
        let mut response = Response::new(Body::from("the event is not JSON"));
        *response.status_mut() = StatusCode::BAD_REQUEST;
        return response;
    };
    let credential = if event.get("type").and_then(Value::as_str) == Some("TOKEN") {
        event.get("authorizationToken").and_then(Value::as_str)
    } else {
        event
            .get("headers")
            .and_then(Value::as_object)
            .and_then(|headers| {
                headers
                    .iter()
                    .find(|(name, _)| name.eq_ignore_ascii_case("x-auth"))
            })
            .and_then(|(_, value)| value.as_str())
    };
    let claims = json!({
        "principal": "parity-user",
        "credential": credential.unwrap_or("None"),
    });
    if credential == Some("error") {
        return function_error("Error: authorizer failure");
    }
    if event.get("version").and_then(Value::as_str) == Some("2.0") {
        return payload_response(&json!({
            "isAuthorized": credential == Some("allow"),
            "context": claims,
        }));
    }
    let effect = match credential {
        Some("allow") => "Allow",
        Some("deny") => "Deny",
        // A response without a policy document, which API Gateway cannot use.
        Some("malformed") => {
            return payload_response(&json!({"principalId": "parity-user", "context": claims}));
        }
        Some(_) | None => return function_error("Unauthorized"),
    };
    let method_arn = event
        .get("methodArn")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut parts = method_arn.split('/');
    let (api_arn, stage) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    payload_response(&json!({
        "principalId": "parity-user",
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [{
                "Action": "execute-api:Invoke",
                "Effect": effect,
                "Resource": format!("{api_arn}/{stage}/*/*"),
            }],
        },
        "context": claims,
    }))
}

fn body_field(bytes: &Bytes) -> Option<String> {
    if bytes.is_empty() {
        return None;
    }
    Some(match std::str::from_utf8(bytes) {
        Ok(text) => text.to_owned(),
        Err(_) => base64::engine::general_purpose::STANDARD.encode(bytes),
    })
}

fn json_response(status: StatusCode, event: &EchoEvent) -> Response {
    let body = serde_json::to_vec(event).unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    // A function URL names its own request and trace, which a gateway in
    // front of it has to deal with.
    response.headers_mut().insert(
        "x-amzn-requestid",
        HeaderValue::from_static("00000000-0000-0000-0000-000000000000"),
    );
    response.headers_mut().insert(
        "x-amzn-trace-id",
        HeaderValue::from_static("Root=1-00000000-000000000000000000000000"),
    );
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// The `echo_status`, `echo_binary`, and `echo_content_type` query parameters the
/// reference Lambda honors.
#[derive(Debug)]
struct Steering {
    status: StatusCode,
    binary: bool,
    content_type: String,
    /// An `echo_status` that is not an integer, which the reference function
    /// fails on (`int()` raises).
    unparsed_status: Option<String>,
    /// How long to wait before answering (`echo_sleep_ms`, at most 3 seconds).
    sleep: Duration,
}

impl Steering {
    fn new() -> Self {
        Self {
            status: StatusCode::OK,
            binary: false,
            content_type: "image/png".to_owned(),
            unparsed_status: None,
            sleep: Duration::ZERO,
        }
    }

    fn from_query(query: &str) -> Self {
        let mut steer = Self::new();
        for pair in query.split('&') {
            if let Some((name, value)) = pair.split_once('=') {
                steer.apply(name, value);
            }
        }
        steer
    }

    /// Reads the parameters from a Lambda event's `queryStringParameters`.
    fn from_event(event: &Value) -> Self {
        let mut steer = Self::new();
        if let Some(Value::Object(parameters)) = event.get("queryStringParameters") {
            for (name, value) in parameters {
                if let Some(value) = value.as_str() {
                    steer.apply(name, value);
                }
            }
        }
        steer
    }

    fn apply(&mut self, name: &str, value: &str) {
        match name {
            "echo_status" => {
                if let Some(status) = value
                    .parse::<u16>()
                    .ok()
                    .and_then(|code| StatusCode::from_u16(code).ok())
                {
                    self.status = status;
                } else if value.parse::<i64>().is_err() {
                    self.unparsed_status = Some(value.to_owned());
                }
            }
            "echo_binary" => self.binary = value == "1",
            "echo_content_type" => value.clone_into(&mut self.content_type),
            "echo_sleep_ms" => {
                if let Ok(millis) = value.parse::<u64>() {
                    self.sleep = Duration::from_millis(millis.min(MAX_SLEEP_MS));
                }
            }
            _ => {}
        }
    }

    /// The proxy-format response the reference echo Lambda returns for `event`.
    fn lambda_payload(&self, event: &str) -> Value {
        if self.binary {
            let bytes: Vec<u8> = (0..=u8::MAX).collect();
            return json!({
                "statusCode": 200,
                "headers": {"content-type": self.content_type},
                "body": base64::engine::general_purpose::STANDARD.encode(bytes),
                "isBase64Encoded": true,
            });
        }
        json!({
            "statusCode": self.status.as_u16(),
            "headers": {"content-type": "application/json"},
            "body": event,
            "isBase64Encoded": false,
        })
    }

    fn binary_response(&self) -> Response {
        let bytes: Vec<u8> = (0..=u8::MAX).collect();
        let mut response = Response::new(Body::from(bytes));
        if let Ok(value) = HeaderValue::try_from(self.content_type.as_str()) {
            response.headers_mut().insert(header::CONTENT_TYPE, value);
        }
        response
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known shape"
)]
mod tests {
    use super::*;

    async fn get(server: &EchoServer, path: &str) -> (u16, Vec<u8>, Option<String>) {
        let response = reqwest::Client::new()
            .get(format!("http://{}{path}", server.authority()))
            .header("x-echo-secret", "s3cret")
            .header("x-keep", "kept")
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let content_type = response
            .headers()
            .get("content-type")
            .map(|v| v.to_str().unwrap().to_owned());
        (
            status,
            response.bytes().await.unwrap().to_vec(),
            content_type,
        )
    }

    #[tokio::test]
    async fn echoes_the_request_and_redacts_the_secret_header() {
        let server = EchoServer::start().await.unwrap();
        let (status, body, content_type) = get(&server, "/a/b?z=1&a=2").await;
        assert_eq!(status, 200);
        assert_eq!(content_type.as_deref(), Some("application/json"));
        let received = EchoEvent::parse(&body).unwrap().received();
        assert_eq!(received.method, "GET");
        assert_eq!(received.path, "/a/b");
        assert_eq!(received.query, "a=2&z=1");
        assert_eq!(received.headers["x-keep"], "kept");
        assert_eq!(received.headers["x-echo-secret"], "[redacted]");
        assert_eq!(received.body, None);
    }

    #[tokio::test]
    async fn steering_parameters_change_status_and_body() {
        let server = EchoServer::start().await.unwrap();
        let (status, _, _) = get(&server, "/x?echo_status=418").await;
        assert_eq!(status, 418);
        let (status, body, content_type) = get(
            &server,
            "/x?echo_binary=1&echo_content_type=application/octet-stream",
        )
        .await;
        assert_eq!(status, 200);
        assert_eq!(content_type.as_deref(), Some("application/octet-stream"));
        assert_eq!(body.len(), 256);
        let (status, _, _) = get(&server, "/x?echo_status=notanumber").await;
        assert_eq!(status, 200);
    }

    #[tokio::test]
    async fn request_bodies_are_echoed_as_text_or_base64() {
        let server = EchoServer::start().await.unwrap();
        let client = reqwest::Client::new();
        let url = format!("http://{}/p", server.authority());
        let text = client.post(&url).body("{\"a\":1}").send().await.unwrap();
        let received = EchoEvent::parse(&text.bytes().await.unwrap())
            .unwrap()
            .received();
        assert_eq!(received.method, "POST");
        assert_eq!(received.body.as_deref(), Some("{\"a\":1}"));
        let binary = client
            .post(&url)
            .body(vec![0xff, 0xfe])
            .send()
            .await
            .unwrap();
        let received = EchoEvent::parse(&binary.bytes().await.unwrap())
            .unwrap()
            .received();
        assert_eq!(received.body.as_deref(), Some("base64://4="));
    }

    #[test]
    fn real_function_url_events_parse_and_normalize() {
        let event = r#"{"version":"2.0","routeKey":"$default","rawPath":"/http-proxy/a","rawQueryString":"y=2&x=1",
            "headers":{"X-Mapped":"v","content-length":"0"},"queryStringParameters":{"x":"1","y":"2"},
            "requestContext":{"accountId":"anonymous","http":{"method":"PUT","path":"/http-proxy/a","protocol":"HTTP/1.1"}},
            "body":"aGk=","isBase64Encoded":true}"#;
        let received = EchoEvent::parse(event.as_bytes()).unwrap().received();
        assert_eq!(received.method, "PUT");
        assert_eq!(received.query, "x=1&y=2");
        assert_eq!(received.body.as_deref(), Some("hi"));
        assert!(received.headers.contains_key("x-mapped"));
        assert!(EchoEvent::parse(b"{\"message\":\"Forbidden\"}").is_err());
    }

    #[test]
    fn payload_1_0_events_parse_and_normalize() {
        let event = r#"{"resource":"/lambda-proxy/{proxy+}","path":"/lambda-proxy/a/b","httpMethod":"POST",
            "headers":{"X-Mapped":"v"},"multiValueHeaders":{"X-Mapped":["v"]},
            "queryStringParameters":{"y":"2","x":"1"},
            "multiValueQueryStringParameters":{"y":["2"],"x":["1","3"]},
            "pathParameters":{"proxy":"a/b"},"stageVariables":null,
            "requestContext":{"httpMethod":"POST","stage":"ref"},
            "body":"{\"a\":1}","isBase64Encoded":false}"#;
        let received = EchoEvent::parse(event.as_bytes()).unwrap().received();
        assert_eq!(received.method, "POST");
        assert_eq!(received.path, "/lambda-proxy/a/b");
        assert_eq!(received.query, "x=1&x=3&y=2");
        assert_eq!(received.resource.as_deref(), Some("/lambda-proxy/{proxy+}"));
        assert_eq!(received.path_parameters["proxy"], "a/b");
        assert_eq!(received.headers["x-mapped"], "v");
        assert_eq!(received.body.as_deref(), Some("{\"a\":1}"));
        let bare = r#"{"path":"/p","httpMethod":"GET","headers":null,"multiValueQueryStringParameters":null,"pathParameters":null,"body":null}"#;
        let received = EchoEvent::parse(bare.as_bytes()).unwrap().received();
        assert_eq!(received.query, "");
        assert!(received.headers.is_empty() && received.path_parameters.is_empty());
    }

    #[test]
    fn payload_2_0_route_key_and_path_parameters_are_kept() {
        let event = r#"{"version":"2.0","routeKey":"ANY /lambda-v2/{proxy+}","rawPath":"/lambda-v2/x","rawQueryString":"",
            "pathParameters":{"proxy":"x"},"requestContext":{"http":{"method":"GET","path":"/lambda-v2/x"}}}"#;
        let received = EchoEvent::parse(event.as_bytes()).unwrap().received();
        assert_eq!(
            received.resource.as_deref(),
            Some("ANY /lambda-v2/{proxy+}")
        );
        assert_eq!(received.path_parameters["proxy"], "x");
    }

    async fn invoke(server: &EchoServer, event: &str) -> (u16, Value) {
        let response = reqwest::Client::new()
            .post(format!("http://{}{LAMBDA_INVOKE_PATH}", server.authority()))
            .body(event.to_owned())
            .send()
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = response.bytes().await.unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn lambda_endpoint_answers_with_a_proxy_response_carrying_the_event() {
        let server = EchoServer::start().await.unwrap();
        let event = r#"{"httpMethod":"GET","path":"/p","requestContext":{},"queryStringParameters":{"echo_status":"418"},"headers":{"a":"b"}}"#;
        let (status, payload) = invoke(&server, event).await;
        assert_eq!(status, 200);
        assert_eq!(payload["statusCode"], 418);
        assert_eq!(payload["headers"]["content-type"], "application/json");
        assert_eq!(payload["isBase64Encoded"], false);
        let echoed = EchoEvent::parse(payload["body"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(echoed.received().path, "/p");

        let binary = r#"{"httpMethod":"GET","requestContext":{},"queryStringParameters":{"echo_binary":"1","echo_content_type":"image/gif"}}"#;
        let (_, payload) = invoke(&server, binary).await;
        assert_eq!(payload["statusCode"], 200);
        assert_eq!(payload["isBase64Encoded"], true);
        assert_eq!(payload["headers"]["content-type"], "image/gif");

        let (status, _) = invoke(&server, "not json").await;
        assert_eq!(status, 400);
    }

    /// What the reference function does with an event that is not a proxy event.
    #[tokio::test]
    async fn other_events_are_returned_or_fail_as_the_reference_function_does() {
        let server = EchoServer::start().await.unwrap();
        let event = r#"{"body":{"a":1},"method":"POST"}"#;
        let (_, payload) = invoke(&server, event).await;
        assert_eq!(payload, json!({"body": {"a": 1}, "method": "POST"}));

        let (_, payload) = invoke(&server, r#"{"body":{"fail":true}}"#).await;
        assert_eq!(payload["errorMessage"], "Error: forced failure");

        let (_, payload) = invoke(&server, r#"{"body":"text"}"#).await;
        assert_eq!(
            payload["errorMessage"],
            "'str' object has no attribute 'get'"
        );
    }

    #[tokio::test]
    async fn the_authorizer_endpoint_follows_the_reference_authorizer() {
        let server = EchoServer::start().await.unwrap();
        let call = |event: Value| {
            let url = format!("http://{}{AUTHORIZER_INVOKE_PATH}", server.authority());
            async move {
                let response = reqwest::Client::new()
                    .post(url)
                    .body(event.to_string())
                    .send()
                    .await
                    .unwrap();
                let failed = response.headers().contains_key(FUNCTION_ERROR_HEADER);
                let payload: Value =
                    serde_json::from_slice(&response.bytes().await.unwrap()).unwrap();
                (failed, payload)
            }
        };
        let arn = "arn:aws:execute-api:us-east-1:1:abc/ref/GET/x";
        let token = |credential: &str| json!({"type": "TOKEN", "authorizationToken": credential, "methodArn": arn});
        let (failed, allow) = call(token("allow")).await;
        assert!(!failed);
        let statement = &allow["policyDocument"]["Statement"][0];
        assert_eq!(statement["Effect"], "Allow");
        assert_eq!(
            statement["Resource"],
            "arn:aws:execute-api:us-east-1:1:abc/ref/*/*"
        );
        assert_eq!(allow["context"]["credential"], "allow");
        let (_, deny) = call(token("deny")).await;
        assert_eq!(deny["policyDocument"]["Statement"][0]["Effect"], "Deny");
        let (failed, error) = call(token("error")).await;
        assert!(failed);
        assert_eq!(error["errorMessage"], "Error: authorizer failure");
        let (failed, _) = call(json!({"version": "2.0", "headers": {"x-auth": "error"}})).await;
        assert!(failed);
        let (failed, malformed) = call(token("malformed")).await;
        assert!(!failed);
        assert!(malformed.get("policyDocument").is_none());
        assert_eq!(malformed["principalId"], "parity-user");
        let (failed, error) = call(token("other")).await;
        assert!(failed);
        assert_eq!(error["errorMessage"], "Unauthorized");
        let request = json!({"type": "REQUEST", "headers": {"X-Auth": "allow"}, "methodArn": arn});
        assert_eq!(
            call(request).await.1["policyDocument"]["Statement"][0]["Effect"],
            "Allow"
        );
        let v2 = json!({"version": "2.0", "headers": {"x-auth": "deny"}});
        assert_eq!(call(v2).await.1["isAuthorized"], false);
    }

    #[test]
    fn sorted_query_ignores_order_and_empty_pairs() {
        assert_eq!(sorted_query(""), "");
        assert_eq!(sorted_query("b=2&&a=1&a=0"), "a=0&a=1&b=2");
    }
}
