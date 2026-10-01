//! The echo backend: the wire format of the reference echo Lambda's function-URL
//! event, a parser for what it returns, and an in-process server that reproduces
//! it so replay can run without AWS.

use std::collections::BTreeMap;
use std::net::SocketAddr;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::Request;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::error::{ParityError, Result};

const SECRET_HEADER: &str = "x-echo-secret";
const REDACTED: &str = "[redacted]";
const MAX_ECHO_BODY: usize = 10 * 1024 * 1024;

/// The subset of a Lambda function-URL (payload 2.0) event the runner reads and
/// the in-process echo writes. Extra fields in a real event are ignored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EchoEvent {
    version: String,
    raw_path: String,
    raw_query_string: String,
    #[serde(default)]
    headers: BTreeMap<String, String>,
    request_context: RequestContext,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
/// base64 body decoded when it is text.
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
        let body = self.body.map(|text| {
            if self.is_base64_encoded {
                decode_body(&text)
            } else {
                text
            }
        });
        EchoReceived {
            method: self.request_context.http.method,
            path: self.raw_path,
            query: sorted_query(&self.raw_query_string),
            headers: self
                .headers
                .into_iter()
                .map(|(name, value)| (name.to_ascii_lowercase(), value))
                .collect(),
            body,
        }
    }
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
        let app = Router::new().fallback(respond);
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
    let steer = Steering::parse(query);

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
    let event = EchoEvent {
        version: "2.0".to_owned(),
        raw_path: parts.uri.path().to_owned(),
        raw_query_string: query.to_owned(),
        headers,
        request_context: RequestContext {
            http: HttpContext {
                method: parts.method.to_string(),
                path: parts.uri.path().to_owned(),
            },
        },
        body: body_field(&bytes),
        is_base64_encoded: std::str::from_utf8(&bytes).is_err() && !bytes.is_empty(),
    };
    json_response(steer.status, &event)
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
}

impl Steering {
    fn parse(query: &str) -> Self {
        let mut steer = Self {
            status: StatusCode::OK,
            binary: false,
            content_type: "image/png".to_owned(),
        };
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("echo_status", value)) => {
                    if let Some(status) = value
                        .parse::<u16>()
                        .ok()
                        .and_then(|code| StatusCode::from_u16(code).ok())
                    {
                        steer.status = status;
                    }
                }
                Some(("echo_binary", "1")) => steer.binary = true,
                Some(("echo_content_type", value)) => value.clone_into(&mut steer.content_type),
                Some(_) | None => {}
            }
        }
        steer
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
    fn sorted_query_ignores_order_and_empty_pairs() {
        assert_eq!(sorted_query(""), "");
        assert_eq!(sorted_query("b=2&&a=1&a=0"), "a=0&a=1&b=2");
    }
}
