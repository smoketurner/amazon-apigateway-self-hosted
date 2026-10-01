//! What a Lambda proxy integration's function returns, turned into the HTTP
//! response API Gateway would send: buffered responses (`Invoke`) and streamed
//! responses (`InvokeWithResponseStream`).

use std::collections::BTreeMap;
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hyper::body::{Body as HttpBody, Frame};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::aws::{InvokeError, ResponseStream};
use crate::gateway::HeaderNameExt as _;
use crate::model::PayloadVersion;

/// The streamed response's metadata must end with this delimiter.
const PRELUDE_DELIMITER: [u8; 8] = [0; 8];
/// The delimiter must appear within this many bytes of the stream.
const PRELUDE_LIMIT: usize = 16 * 1024;
/// A stream that stays silent this long is cut, as Regional endpoints do.
pub(crate) const STREAM_IDLE_LIMIT: std::time::Duration = std::time::Duration::from_mins(5);
/// Chunks buffered between the Lambda stream and the client.
const STREAM_BACKLOG: usize = 8;

/// Whether a `Content-Length` the function sets is kept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LengthHeader {
    /// Buffered responses get API Gateway's own length; the function's is dropped.
    Recompute,
    /// Streamed responses may declare a length up front.
    Honor,
}

/// The header-bearing fields common to buffered and streamed responses.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct HeaderFields {
    headers: Option<BTreeMap<String, Value>>,
    multi_value_headers: Option<BTreeMap<String, Vec<Value>>>,
    cookies: Option<Vec<String>>,
}

impl HeaderFields {
    /// Adds the headers to `target`. `multiValueHeaders` may repeat a pair that
    /// `headers` already gave; API Gateway lists such a pair once.
    fn apply_to(self, target: &mut HeaderMap, length: LengthHeader) -> Result<(), String> {
        let mut singles = HeaderMap::new();
        for (name, value) in self.headers.unwrap_or_default() {
            let (name, value) = Self::pair(&name, &value)?;
            singles.append(name, value);
        }
        let mut repeated = HeaderMap::new();
        for (name, values) in self.multi_value_headers.unwrap_or_default() {
            for value in values {
                let (name, value) = Self::pair(&name, &value)?;
                if !singles.get_all(&name).iter().any(|seen| *seen == value) {
                    repeated.append(name, value);
                }
            }
        }
        for (name, value) in singles.iter().chain(repeated.iter()) {
            let skipped = name.is_hop_by_hop()
                || (name == header::CONTENT_LENGTH && length == LengthHeader::Recompute);
            if !skipped {
                target.append(name.clone(), value.clone());
            }
        }
        for cookie in self.cookies.unwrap_or_default() {
            let value = HeaderValue::try_from(cookie).map_err(|e| e.to_string())?;
            target.append(header::SET_COOKIE, value);
        }
        Ok(())
    }

    fn pair(name: &str, value: &Value) -> Result<(HeaderName, HeaderValue), String> {
        let text = match value {
            Value::String(s) => s.clone(),
            Value::Number(_) | Value::Bool(_) => value.to_string(),
            Value::Null | Value::Array(_) | Value::Object(_) => {
                return Err(format!("header {name:?} has a non-scalar value"));
            }
        };
        let name = HeaderName::try_from(name).map_err(|e| e.to_string())?;
        let value = HeaderValue::try_from(text).map_err(|e| e.to_string())?;
        Ok((name, value))
    }
}

/// A structured Lambda proxy response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ProxyResponse {
    status_code: u16,
    #[serde(flatten)]
    fields: HeaderFields,
    body: Option<String>,
    is_base64_encoded: Option<bool>,
}

impl ProxyResponse {
    /// Turns a function's payload into the HTTP response API Gateway would
    /// send. Payload format 2.0 treats JSON without `statusCode` as a 200 JSON
    /// body.
    ///
    /// # Errors
    ///
    /// Describes why the payload is not a valid proxy response, which API
    /// Gateway answers with a `502`.
    pub(crate) fn into_http(payload: &[u8], version: PayloadVersion) -> Result<Response, String> {
        let value: Value = serde_json::from_slice(payload).map_err(|e| format!("not JSON: {e}"))?;
        if version == PayloadVersion::V2 && value.get("statusCode").is_none() {
            let mut response = Response::new(Body::from(value.to_string()));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return Ok(response);
        }
        let parsed = Self::deserialize(&value).map_err(|e| e.to_string())?;
        let status = StatusCode::from_u16(parsed.status_code).map_err(|e| e.to_string())?;
        let body = match (parsed.body, parsed.is_base64_encoded.unwrap_or(false)) {
            (Some(body), true) => BASE64
                .decode(body)
                .map_err(|e| format!("body is not base64: {e}"))?,
            (Some(body), false) => body.into_bytes(),
            (None, _) => Vec::new(),
        };
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = status;
        parsed
            .fields
            .apply_to(response.headers_mut(), LengthHeader::Recompute)?;
        Ok(response)
    }
}

/// Why a streamed response could not be started.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PreludeError {
    /// The invocation failed before the metadata arrived.
    #[error(transparent)]
    Invoke(#[from] InvokeError),
    /// The function's output doesn't follow the streaming format.
    #[error("{0}")]
    Format(String),
}

/// The metadata that opens a streamed response, before the 8-byte delimiter.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StreamPrelude {
    status_code: Option<u16>,
    #[serde(flatten)]
    fields: HeaderFields,
}

impl StreamPrelude {
    /// Reads the stream up to the delimiter, returning the metadata and any
    /// payload bytes that arrived with it.
    ///
    /// # Errors
    ///
    /// Fails when the invocation errors first, or when the metadata is not
    /// valid JSON, the delimiter is missing, or it comes after 16 KiB.
    pub(crate) async fn read(stream: &mut ResponseStream) -> Result<(Self, Bytes), PreludeError> {
        let mut buffer: Vec<u8> = Vec::new();
        loop {
            if let Some(at) = buffer
                .windows(PRELUDE_DELIMITER.len())
                .position(|window| window == PRELUDE_DELIMITER)
            {
                return Self::split(&buffer, at);
            }
            if buffer.len() > PRELUDE_LIMIT {
                return Err(PreludeError::Format(format!(
                    "no 8 null byte delimiter within the first {PRELUDE_LIMIT} bytes"
                )));
            }
            let Some(chunk) = stream.next_chunk().await? else {
                return Err(PreludeError::Format(
                    "the stream ended before the 8 null byte delimiter".to_owned(),
                ));
            };
            buffer.extend_from_slice(&chunk);
        }
    }

    fn split(buffer: &[u8], delimiter_at: usize) -> Result<(Self, Bytes), PreludeError> {
        if delimiter_at > PRELUDE_LIMIT {
            return Err(PreludeError::Format(format!(
                "the delimiter starts after the first {PRELUDE_LIMIT} bytes"
            )));
        }
        let (metadata, rest) = buffer.split_at(delimiter_at);
        let payload = rest.get(PRELUDE_DELIMITER.len()..).unwrap_or_default();
        let prelude = serde_json::from_slice(metadata)
            .map_err(|e| PreludeError::Format(format!("metadata is not valid: {e}")))?;
        Ok((prelude, Bytes::copy_from_slice(payload)))
    }

    /// The response head: status (200 unless given) and headers. API Gateway
    /// adds `Transfer-Encoding: chunked` when the function declares neither a
    /// length nor chunking, which hyper does for any body of unknown length.
    ///
    /// # Errors
    ///
    /// Fails when the status code or a header is not valid HTTP.
    pub(crate) fn into_head(self, response: &mut Response) -> Result<(), String> {
        let status =
            StatusCode::from_u16(self.status_code.unwrap_or(200)).map_err(|e| e.to_string())?;
        *response.status_mut() = status;
        self.fields
            .apply_to(response.headers_mut(), LengthHeader::Honor)
    }
}

/// A streamed response failed after it started; the connection is cut so the
/// client can tell the body is incomplete.
#[derive(Debug, thiserror::Error)]
#[error("Lambda response stream aborted: {0}")]
pub(crate) struct StreamAborted(String);

/// The client-facing body of a streamed response, fed by [`StreamBody::spawn`].
#[derive(Debug)]
pub(crate) struct StreamBody(mpsc::Receiver<Result<Bytes, StreamAborted>>);

impl StreamBody {
    /// Starts relaying `stream` (after `first`, payload bytes already read) and
    /// returns the body that yields it. The relay stops when the client goes
    /// away, the function finishes, `deadline` passes, or the stream goes quiet
    /// for [`STREAM_IDLE_LIMIT`]; dropping the stream ends the invocation's
    /// connection.
    pub(crate) fn spawn(stream: ResponseStream, first: Bytes, deadline: Instant) -> Body {
        let (sender, receiver) = mpsc::channel(STREAM_BACKLOG);
        tokio::spawn(Self::relay(stream, first, deadline, sender));
        Body::new(Self(receiver))
    }

    async fn relay(
        mut stream: ResponseStream,
        first: Bytes,
        deadline: Instant,
        sender: mpsc::Sender<Result<Bytes, StreamAborted>>,
    ) {
        if !first.is_empty() && sender.send(Ok(first)).await.is_err() {
            return;
        }
        loop {
            let limit = Instant::now()
                .checked_add(STREAM_IDLE_LIMIT)
                .map_or(deadline, |idle| idle.min(deadline));
            let aborted = match tokio::time::timeout_at(limit, stream.next_chunk()).await {
                Ok(Ok(Some(chunk))) => {
                    if sender.send(Ok(chunk)).await.is_err() {
                        return;
                    }
                    continue;
                }
                Ok(Ok(None)) => return,
                Ok(Err(err)) => StreamAborted(err.to_string()),
                Err(_) => StreamAborted("timed out".to_owned()),
            };
            tracing::warn!("{aborted}");
            if sender.send(Err(aborted)).await.is_err() {
                tracing::debug!("client left before the abort was delivered");
            }
            return;
        }
    }
}

impl HttpBody for StreamBody {
    type Data = Bytes;
    type Error = StreamAborted;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.get_mut()
            .0
            .poll_recv(cx)
            .map(|item| item.map(|chunk| chunk.map(Frame::data)))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use serde_json::json;

    use super::*;

    async fn body_of(response: Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn structured_response_maps_status_headers_and_cookies() {
        let payload = json!({
            "statusCode": 201,
            "headers": {"x-one": "1", "x-num": 2},
            "multiValueHeaders": {"x-many": ["a", "b"]},
            "cookies": ["c=1"],
            "body": "aGk=",
            "isBase64Encoded": true
        });
        let response =
            ProxyResponse::into_http(payload.to_string().as_bytes(), PayloadVersion::V2).unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-num"], "2");
        assert_eq!(response.headers().get_all("x-many").iter().count(), 2);
        assert_eq!(response.headers()["set-cookie"], "c=1");
        assert_eq!(&*body_of(response).await, b"hi");
    }

    #[tokio::test]
    async fn headers_repeated_in_multi_value_headers_are_listed_once() {
        let payload = json!({
            "statusCode": 200,
            "headers": {"X-A": "1", "X-B": "2"},
            "multiValueHeaders": {"x-a": ["1", "3"], "x-c": ["1", "1"]}
        });
        let response =
            ProxyResponse::into_http(payload.to_string().as_bytes(), PayloadVersion::V1).unwrap();
        let values = |name: &str| -> Vec<String> {
            response
                .headers()
                .get_all(name)
                .iter()
                .map(|v| v.to_str().unwrap().to_owned())
                .collect()
        };
        assert_eq!(values("x-a"), ["1", "3"]);
        assert_eq!(values("x-b"), ["2"]);
        assert_eq!(values("x-c"), ["1", "1"]);
    }

    #[tokio::test]
    async fn null_fields_and_missing_bodies_are_tolerated() {
        let payload = br#"{"statusCode": 204, "headers": null, "multiValueHeaders": null,
            "cookies": null, "body": null, "isBase64Encoded": null}"#;
        let response = ProxyResponse::into_http(payload, PayloadVersion::V1).unwrap();
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(body_of(response).await.is_empty());
    }

    #[tokio::test]
    async fn framing_headers_from_the_function_are_not_forwarded() {
        let payload = br#"{"statusCode": 200, "body": "hello",
            "headers": {"Content-Length": "999", "Transfer-Encoding": "chunked", "Connection": "close", "X-Keep": "1"}}"#;
        let response = ProxyResponse::into_http(payload, PayloadVersion::V1).unwrap();
        assert!(response.headers().get("content-length").is_none());
        assert!(response.headers().get("transfer-encoding").is_none());
        assert!(response.headers().get("connection").is_none());
        assert_eq!(response.headers()["x-keep"], "1");
        assert_eq!(&*body_of(response).await, b"hello");
    }

    #[tokio::test]
    async fn v2_infers_response_without_status_code() {
        for (payload, expected) in [
            (r#"{"hello":"world"}"#, r#"{"hello":"world"}"#),
            (r#""text""#, r#""text""#),
            ("[1,2]", "[1,2]"),
        ] {
            let response =
                ProxyResponse::into_http(payload.as_bytes(), PayloadVersion::V2).unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()["content-type"], "application/json");
            assert_eq!(&*body_of(response).await, expected.as_bytes());
        }
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let cases: [&[u8]; 12] = [
            b"not json",
            b"",
            br#"{"hello":"world"}"#,
            b"\"text\"",
            br#"{"statusCode": 99}"#,
            br#"{"statusCode": "200"}"#,
            br#"{"statusCode": 200, "body": 5}"#,
            br#"{"statusCode": 200, "body": {"a": 1}}"#,
            br#"{"statusCode": 200, "body": "!!", "isBase64Encoded": true}"#,
            br#"{"statusCode": 200, "headers": {"x": {"nested": 1}}}"#,
            br#"{"statusCode": 200, "headers": {"x": null}}"#,
            br#"{"statusCode": 200, "headers": {"bad header": "v"}}"#,
        ];
        for payload in cases {
            assert!(
                ProxyResponse::into_http(payload, PayloadVersion::V1).is_err(),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }

    #[test]
    fn prelude_splits_metadata_from_payload() {
        let mut wire =
            br#"{"statusCode": 202, "headers": {"x-a": "1"}, "cookies": ["c=1"]}"#.to_vec();
        wire.extend_from_slice(&PRELUDE_DELIMITER);
        wire.extend_from_slice(b"first");
        let (prelude, payload) = StreamPrelude::split(&wire, wire.len() - 5 - 8).unwrap();
        assert_eq!(&*payload, b"first");
        let mut response = Response::new(Body::empty());
        prelude.into_head(&mut response).unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["x-a"], "1");
        assert_eq!(response.headers()["set-cookie"], "c=1");
    }

    #[test]
    fn prelude_defaults_to_200_and_honors_content_length() {
        let wire = br#"{"headers": {"Content-Length": "5", "Transfer-Encoding": "chunked"}}"#;
        let (prelude, _) = StreamPrelude::split(wire, wire.len()).unwrap();
        let mut response = Response::new(Body::empty());
        prelude.into_head(&mut response).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-length"], "5");
        assert!(response.headers().get("transfer-encoding").is_none());
    }

    #[test]
    fn prelude_rejects_bad_metadata_and_late_delimiters() {
        assert!(matches!(
            StreamPrelude::split(b"not json", 8),
            Err(PreludeError::Format(_))
        ));
        assert!(matches!(
            StreamPrelude::split(b"", 0),
            Err(PreludeError::Format(_))
        ));
        assert!(matches!(
            StreamPrelude::split(&vec![b' '; PRELUDE_LIMIT + 10], PRELUDE_LIMIT + 1),
            Err(PreludeError::Format(_))
        ));
        let (prelude, _) = StreamPrelude::split(br#"{"statusCode": 1}"#, 17).unwrap();
        assert!(
            prelude
                .into_head(&mut Response::new(Body::empty()))
                .is_err()
        );
    }
}
