//! A local HTTP endpoint that stands in for AWS JSON-protocol services in
//! tests. Real SDK clients talk to it through an endpoint override, so the
//! requests under test are the ones the gateway would send to AWS.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use aws_sdk_cloudwatchlogs::config::{Credentials, SharedCredentialsProvider};
use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse as _, Response};
use serde_json::Value;

/// One request the mock received.
#[derive(Debug, Clone)]
pub(crate) struct Call {
    /// The `X-Amz-Target` header, e.g. `Logs_20140328.PutLogEvents`.
    pub(crate) target: String,
    pub(crate) body: Value,
}

/// What the mock answers with.
#[derive(Debug, Clone)]
pub(crate) struct Reply {
    status: StatusCode,
    body: String,
}

impl Reply {
    pub(crate) fn json(body: &str) -> Self {
        Self {
            status: StatusCode::OK,
            body: body.to_owned(),
        }
    }

    /// A 400 carrying the service error `kind`.
    pub(crate) fn error(kind: &str) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: format!(r#"{{"__type":"{kind}","message":"mock {kind}"}}"#),
        }
    }
}

#[derive(Default)]
struct Shared {
    calls: Mutex<Vec<Call>>,
    sticky: Mutex<HashMap<String, Reply>>,
    once: Mutex<HashMap<String, VecDeque<Reply>>>,
}

impl Shared {
    fn reply_for(&self, target: &str) -> Reply {
        let queued = self
            .once
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(target)
            .and_then(VecDeque::pop_front);
        if let Some(reply) = queued {
            return reply;
        }
        if let Some(reply) = self
            .sticky
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(target)
        {
            return reply.clone();
        }
        let body = match target {
            "Firehose_20150804.PutRecordBatch" => r#"{"FailedPutCount":0,"RequestResponses":[]}"#,
            _ => "{}",
        };
        Reply::json(body)
    }
}

async fn handle(State(shared): State<Arc<Shared>>, headers: HeaderMap, body: Bytes) -> Response {
    let target = headers
        .get("x-amz-target")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
    shared
        .calls
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(Call {
            target: target.clone(),
            body,
        });
    let reply = shared.reply_for(&target);
    (
        reply.status,
        [("content-type", "application/x-amz-json-1.1")],
        reply.body,
    )
        .into_response()
}

/// A running mock endpoint.
pub(crate) struct MockAws {
    endpoint: String,
    shared: Arc<Shared>,
}

#[expect(clippy::unwrap_used, reason = "test helper over a local socket")]
impl MockAws {
    pub(crate) async fn start() -> Self {
        let shared = Arc::new(Shared::default());
        let app = Router::new()
            .fallback(handle)
            .with_state(Arc::clone(&shared));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self {
            endpoint: format!("http://{addr}"),
            shared,
        }
    }

    /// An SDK configuration that sends every request to this mock.
    pub(crate) fn sdk_config(&self) -> aws_config::SdkConfig {
        aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(aws_config::Region::new("us-east-1"))
            .endpoint_url(&self.endpoint)
            .credentials_provider(SharedCredentialsProvider::new(Credentials::new(
                "AKID", "secret", None, None, "test",
            )))
            .build()
    }

    pub(crate) fn cloudwatch_logs(&self) -> aws_sdk_cloudwatchlogs::Client {
        aws_sdk_cloudwatchlogs::Client::new(&self.sdk_config())
    }

    pub(crate) fn firehose(&self) -> aws_sdk_firehose::Client {
        aws_sdk_firehose::Client::new(&self.sdk_config())
    }

    /// Answers every `target` request with `reply` from now on.
    pub(crate) fn reply(&self, target: &str, reply: Reply) {
        self.shared
            .sticky
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(target.to_owned(), reply);
    }

    /// Answers the next `target` request with `reply`, then goes back to the default.
    pub(crate) fn reply_once(&self, target: &str, reply: Reply) {
        self.shared
            .once
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(target.to_owned())
            .or_default()
            .push_back(reply);
    }

    pub(crate) fn calls(&self) -> Vec<Call> {
        self.shared
            .calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Waits until `count` requests for `target` have arrived.
    pub(crate) async fn wait_for(&self, target: &str, count: usize) {
        for _ in 0..500 {
            if self.calls().iter().filter(|c| c.target == target).count() >= count {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("no {count} requests for {target} within 5s");
    }
}
