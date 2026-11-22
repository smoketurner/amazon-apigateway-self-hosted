//! Execution logs: API Gateway's step-by-step trace of a request, written to
//! the stage's `API-Gateway-Execution-Logs_{apiId}/{stage}` log group.
//!
//! The wording follows API Gateway's execution logs. Only the steps this
//! gateway performs are logged: authorizer steps are not. With
//! `dataTraceEnabled` the method request (path parameters, query string,
//! headers, body), the endpoint request and response, and the method
//! response are logged as well; bodies of responses streamed to the client
//! are not, and every event is cut at 1 KB as API Gateway cuts them, ending
//! in `[TRUNCATED]` when a body did not fit.

use axum::body::Bytes;
use axum::http::HeaderMap;

use crate::model::{ExecutionLogging, LoggingLevel};
use crate::pipeline::{EndpointExchange, RequestContext};

/// API Gateway truncates each execution log event at 1 KB.
const MAX_EVENT_BYTES: usize = 1024;

/// What ends a body that did not fit in its event.
const TRUNCATED: &str = " [TRUNCATED]";

/// Headers whose values never appear in execution logs.
const REDACTED_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
];

/// How many characters of an API key execution logs show; the rest are masked.
const VISIBLE_KEY_CHARS: usize = 6;

/// What a request did that execution logs record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Outcome {
    pub(crate) status: u16,
    /// The integration's status and latency in milliseconds, when one was invoked.
    pub(crate) integration: Option<(u16, u64)>,
    /// The method requires an API key.
    pub(crate) api_key_required: bool,
}

/// The method response as the client receives it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseData<'a> {
    pub(crate) headers: &'a HeaderMap,
    /// Absent for streamed responses.
    pub(crate) body: Option<&'a Bytes>,
}

/// One line before it is prefixed and cut: a body line is cut with a marker.
enum Text {
    Plain(String),
    Body(&'static str, String),
}

impl ExecutionLogging {
    /// The log lines for one request, each prefixed `(requestId)` and cut to
    /// 1 KB, in the order API Gateway writes them.
    pub(crate) fn lines(
        self,
        ctx: &RequestContext,
        outcome: Outcome,
        response: &ResponseData<'_>,
    ) -> Vec<String> {
        let id = ctx.request_id;
        let info = |text: String| (LoggingLevel::Info, Text::Plain(text));
        let mut lines: Vec<(LoggingLevel, Text)> = vec![info(format!("Extended Request Id: {id}"))];
        lines.extend(Self::api_key_lines(ctx, outcome).into_iter().map(info));
        lines.push(info(format!("Starting execution for request: {id}")));
        lines.push(info(format!(
            "HTTP Method: {}, Resource Path: {}",
            ctx.method, ctx.resource_path
        )));
        let exchange = ctx.integration.exchange.as_ref();
        if self.data_trace {
            lines.extend(
                Self::method_request(ctx)
                    .into_iter()
                    .chain(exchange.map_or_else(Vec::new, Self::endpoint_request))
                    .map(|text| (LoggingLevel::Info, text)),
            );
        }
        if let Some(uri) = exchange.and_then(|e| e.uri.as_deref()) {
            lines.push(info(format!("Sending request to {uri}")));
        }
        if let Some((status, latency_ms)) = outcome.integration {
            lines.push(info(format!(
                "Received response. Status: {status}, Integration latency: {latency_ms} ms"
            )));
        }
        if self.data_trace {
            lines.extend(
                Self::responses(exchange, response)
                    .into_iter()
                    .map(|text| (LoggingLevel::Info, text)),
            );
        }
        if outcome.status >= 500 {
            lines.push((
                LoggingLevel::Error,
                Text::Plain(format!(
                    "Execution failed: the method completed with status {}",
                    outcome.status
                )),
            ));
        } else {
            lines.push(info("Successfully completed execution".to_owned()));
        }
        lines.push(info(format!(
            "Method completed with status: {}",
            outcome.status
        )));
        lines
            .into_iter()
            .filter(|(level, _)| *level <= self.level)
            .map(|(_, text)| Self::event(id, &text))
            .collect()
    }

    /// The method request as the client sent it.
    fn method_request(ctx: &RequestContext) -> Vec<Text> {
        vec![
            Text::Plain(format!(
                "Method request path: {}",
                Self::map(
                    ctx.path_params
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.as_str()))
                )
            )),
            Text::Plain(format!(
                "Method request query string: {}",
                Self::query_string(ctx)
            )),
            Text::Plain(format!(
                "Method request headers: {}",
                Self::headers(ctx.headers.iter().map(|(name, value)| {
                    (name.as_str(), String::from_utf8_lossy(value.as_bytes()))
                }))
            )),
            Text::Body(
                "Method request body before transformations: ",
                Self::body(
                    ctx.integration
                        .exchange
                        .as_ref()
                        .and_then(|e| e.method_request_body.as_ref())
                        .unwrap_or(&ctx.body),
                ),
            ),
        ]
    }

    /// The endpoint's response, then the method response the client got.
    fn responses(exchange: Option<&EndpointExchange>, response: &ResponseData<'_>) -> Vec<Text> {
        let mut lines = Vec::new();
        if let Some(exchange) = exchange {
            lines.push(Text::Plain(format!(
                "Endpoint response headers: {}",
                Self::headers(
                    exchange
                        .response_headers
                        .iter()
                        .map(|(k, v)| (k.as_str(), v.into()))
                )
            )));
            if let Some(ref body) = exchange.response_body {
                lines.push(Text::Body(
                    "Endpoint response body before transformations: ",
                    Self::body(body),
                ));
            }
        }
        if let Some(body) = response.body {
            lines.push(Text::Body(
                "Method response body after transformations: ",
                Self::body(body),
            ));
        }
        lines.push(Text::Plain(format!(
            "Method response headers: {}",
            Self::headers(response.headers.iter().map(|(name, value)| {
                (name.as_str(), String::from_utf8_lossy(value.as_bytes()))
            }))
        )));
        lines
    }

    fn endpoint_request(exchange: &EndpointExchange) -> Vec<Text> {
        let mut lines = Vec::new();
        if let Some(ref uri) = exchange.uri {
            lines.push(Text::Plain(format!("Endpoint request URI: {uri}")));
        }
        lines.push(Text::Plain(format!(
            "Endpoint request headers: {}",
            Self::headers(
                exchange
                    .request_headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.into()))
            )
        )));
        if let Some(ref body) = exchange.request_body {
            lines.push(Text::Body(
                "Endpoint request body after transformations: ",
                Self::body(body),
            ));
        }
        lines
    }

    /// API Gateway's usage plan steps: the key that was checked, or that the
    /// method needs none.
    fn api_key_lines(ctx: &RequestContext, outcome: Outcome) -> Vec<String> {
        let stage = format!("{}/{}", ctx.api.api_id, ctx.api.stage_name());
        if !outcome.api_key_required {
            return vec![format!(
                "API Key  authorized because method '{} {}' does not require API Key. Request will not contribute to throttle or quota limits",
                ctx.method, ctx.resource_path
            )];
        }
        let Some(ref key) = ctx.api_key else {
            return Vec::new();
        };
        let masked = Self::masked(key.value().unwrap_or_else(|| key.id()));
        vec![
            format!(
                "Verifying Usage Plan for request: {}. API Key: {masked} API Stage: {stage}",
                ctx.request_id
            ),
            format!("Usage Plan check succeeded for API Key {masked} and API Stage {stage}"),
        ]
    }

    fn masked(key: &str) -> String {
        let count = key.chars().count();
        let hidden = count.saturating_sub(VISIBLE_KEY_CHARS);
        key.chars()
            .enumerate()
            .map(|(i, c)| if i < hidden { '*' } else { c })
            .collect()
    }

    fn body(body: &Bytes) -> String {
        String::from_utf8_lossy(body).into_owned()
    }

    fn event(id: uuid::Uuid, text: &Text) -> String {
        match text {
            Text::Plain(text) => {
                let mut line = format!("({id}) {text}");
                if line.len() > MAX_EVENT_BYTES {
                    line.truncate(line.floor_char_boundary(MAX_EVENT_BYTES));
                }
                line
            }
            Text::Body(label, body) => {
                let mut line = format!("({id}) {label}{body}");
                if line.len() > MAX_EVENT_BYTES {
                    let room = MAX_EVENT_BYTES.saturating_sub(TRUNCATED.len());
                    line.truncate(line.floor_char_boundary(room));
                    line.push_str(TRUNCATED);
                }
                line
            }
        }
    }

    /// `{a=1, b=2}`, the way API Gateway prints parameter maps.
    fn map<'a>(pairs: impl Iterator<Item = (&'a str, &'a str)>) -> String {
        let pairs: Vec<String> = pairs
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        format!("{{{}}}", pairs.join(", "))
    }

    fn query_string(ctx: &RequestContext) -> String {
        let pairs = ctx.query.pairs();
        Self::map(
            pairs
                .iter()
                .map(|(name, value)| (name.as_ref(), value.as_ref())),
        )
    }

    fn headers<'a>(headers: impl Iterator<Item = (&'a str, std::borrow::Cow<'a, str>)>) -> String {
        let pairs: Vec<String> = headers
            .map(|(name, value)| {
                if REDACTED_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                    format!("{name}=[redacted]")
                } else {
                    format!("{name}={value}")
                }
            })
            .collect();
        format!("{{{}}}", pairs.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::*;
    use crate::model::ApiKind;
    use crate::pipeline::ApiKeyIdentity;
    use crate::pipeline::context::tests::request;

    const OK: Outcome = Outcome {
        status: 200,
        integration: Some((200, 12)),
        api_key_required: false,
    };

    fn logging(level: LoggingLevel, data_trace: bool) -> ExecutionLogging {
        ExecutionLogging { level, data_trace }
    }

    fn response<'a>(headers: &'a HeaderMap, body: Option<&'a Bytes>) -> ResponseData<'a> {
        ResponseData { headers, body }
    }

    #[test]
    fn info_level_traces_the_request_lifecycle() {
        let ctx = request(ApiKind::Rest);
        let id = ctx.request_id;
        let lines =
            logging(LoggingLevel::Info, false).lines(&ctx, OK, &response(&HeaderMap::new(), None));
        assert_eq!(
            lines,
            vec![
                format!("({id}) Extended Request Id: {id}"),
                format!(
                    "({id}) API Key  authorized because method 'POST /pets/{{petId}}' does not require API Key. Request will not contribute to throttle or quota limits"
                ),
                format!("({id}) Starting execution for request: {id}"),
                format!("({id}) HTTP Method: POST, Resource Path: /pets/{{petId}}"),
                format!("({id}) Received response. Status: 200, Integration latency: 12 ms"),
                format!("({id}) Successfully completed execution"),
                format!("({id}) Method completed with status: 200"),
            ]
        );
    }

    #[test]
    fn error_level_logs_only_failures() {
        let ctx = request(ApiKind::Rest);
        let level = logging(LoggingLevel::Error, true);
        let headers = HeaderMap::new();
        assert_eq!(
            level.lines(&ctx, OK, &response(&headers, None)),
            Vec::<String>::new()
        );
        let failed = level.lines(
            &ctx,
            Outcome {
                status: 502,
                integration: None,
                api_key_required: false,
            },
            &response(&headers, None),
        );
        assert_eq!(failed.len(), 1);
        assert!(failed.iter().all(|l| l.contains("Execution failed")));
    }

    #[test]
    fn a_checked_api_key_is_logged_masked() {
        let mut ctx = request(ApiKind::Rest);
        ctx.api_key = Some(ApiKeyIdentity::new(
            "keyid".to_owned(),
            Some("abcdefghij0123456789".to_owned()),
        ));
        let required = Outcome {
            api_key_required: true,
            ..OK
        };
        let lines = logging(LoggingLevel::Info, false)
            .lines(&ctx, required, &response(&HeaderMap::new(), None))
            .join("\n");
        assert!(
            lines.contains("API Key: **************456789 API Stage: abc123/prod"),
            "{lines}"
        );
        assert!(lines.contains(
            "Usage Plan check succeeded for API Key **************456789 and API Stage abc123/prod"
        ));
        assert!(!lines.contains("abcdefghij"));
        assert_eq!(ExecutionLogging::masked("abc"), "abc");
    }

    #[test]
    fn data_trace_adds_the_query_string_and_redacted_headers() {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers
            .insert("authorization", HeaderValue::from_static("Bearer secret"));
        ctx.headers
            .insert("x-api-key", HeaderValue::from_static("key"));
        let lines = logging(LoggingLevel::Info, true)
            .lines(&ctx, OK, &response(&HeaderMap::new(), None))
            .join("\n");
        assert!(lines.contains("Method request path: {petId=7}"));
        assert!(lines.contains("Method request query string: {q=1, q=2}"));
        assert!(lines.contains("user-agent=curl/8"));
        assert!(lines.contains("authorization=[redacted]"));
        assert!(lines.contains("x-api-key=[redacted]"));
        assert!(!lines.contains("secret"));
    }

    #[test]
    fn data_trace_logs_bodies_and_the_endpoint_exchange_in_api_gateways_order() {
        let mut ctx = request(ApiKind::Rest);
        ctx.body = Bytes::from_static(b"{\"name\":\"rex\"}");
        ctx.integration.exchange = Some(EndpointExchange {
            method_request_body: None,
            uri: Some("https://pets.internal/pets/7".to_owned()),
            request_headers: vec![
                ("Authorization".to_owned(), "Bearer secret".to_owned()),
                ("Accept".to_owned(), "application/json".to_owned()),
            ],
            request_body: Some(Bytes::from_static(b"{\"name\":\"REX\"}")),
            response_headers: vec![("content-type".to_owned(), "application/json".to_owned())],
            response_body: Some(Bytes::from_static(b"{\"id\":7}")),
        });
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let body = Bytes::from_static(b"{\"id\":7,\"ok\":true}");
        let id = ctx.request_id;
        let lines =
            logging(LoggingLevel::Info, true).lines(&ctx, OK, &response(&headers, Some(&body)));
        let expected = [
            "Method request body before transformations: {\"name\":\"rex\"}".to_owned(),
            "Endpoint request URI: https://pets.internal/pets/7".to_owned(),
            "Endpoint request headers: {Authorization=[redacted], Accept=application/json}"
                .to_owned(),
            "Endpoint request body after transformations: {\"name\":\"REX\"}".to_owned(),
            "Sending request to https://pets.internal/pets/7".to_owned(),
            "Received response. Status: 200, Integration latency: 12 ms".to_owned(),
            "Endpoint response headers: {content-type=application/json}".to_owned(),
            "Endpoint response body before transformations: {\"id\":7}".to_owned(),
            "Method response body after transformations: {\"id\":7,\"ok\":true}".to_owned(),
            "Method response headers: {content-type=application/json}".to_owned(),
            "Successfully completed execution".to_owned(),
        ];
        let mut positions = Vec::new();
        for text in &expected {
            let line = format!("({id}) {text}");
            let at = lines.iter().position(|l| *l == line);
            assert!(at.is_some(), "{line}\n{lines:#?}");
            positions.push(at);
        }
        assert!(positions.is_sorted(), "{lines:#?}");
    }

    #[test]
    fn events_are_cut_at_one_kilobyte_and_long_bodies_say_so() {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers.insert(
            "x-long",
            HeaderValue::from_str(&"a".repeat(3000))
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        ctx.body = Bytes::from("b".repeat(5000));
        let lines =
            logging(LoggingLevel::Info, true).lines(&ctx, OK, &response(&HeaderMap::new(), None));
        assert!(lines.iter().all(|l| l.len() <= MAX_EVENT_BYTES));
        assert!(lines.iter().any(|l| l.len() == MAX_EVENT_BYTES));
        let body = lines
            .iter()
            .find(|l| l.contains("Method request body before transformations"))
            .map_or("", String::as_str);
        assert!(body.ends_with(" [TRUNCATED]"), "{body}");
        assert!(body.len() <= MAX_EVENT_BYTES);
        let line = ExecutionLogging::event(ctx.request_id, &Text::Plain("\u{e9}".repeat(2000)));
        assert!(line.len() <= MAX_EVENT_BYTES);
        let short = ExecutionLogging::event(ctx.request_id, &Text::Body("b: ", "x".to_owned()));
        assert!(!short.contains("TRUNCATED"));
    }
}
