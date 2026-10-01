//! Execution logs: API Gateway's step-by-step trace of a request, written to
//! the stage's `API-Gateway-Execution-Logs_{apiId}/{stage}` log group.
//!
//! The wording follows API Gateway's execution logs. Only the steps this
//! gateway performs are logged, and request and response bodies are not
//! (they are streamed, not buffered), so `dataTraceEnabled` adds the request
//! query string and headers only.

use crate::model::{ExecutionLogging, LoggingLevel};
use crate::pipeline::RequestContext;

/// API Gateway truncates each execution log event at 1 KB.
const MAX_EVENT_BYTES: usize = 1024;

/// Headers whose values never appear in execution logs.
const REDACTED_HEADERS: [&str; 4] = [
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "cookie",
];

/// What a request did that execution logs record.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Outcome {
    pub(crate) status: u16,
    /// The integration's status and latency in milliseconds, when one was invoked.
    pub(crate) integration: Option<(u16, u64)>,
}

impl ExecutionLogging {
    /// The log lines for one request, each prefixed `(requestId)` and cut to
    /// 1 KB, in the order API Gateway writes them.
    pub(crate) fn lines(self, ctx: &RequestContext, outcome: Outcome) -> Vec<String> {
        let id = ctx.request_id;
        let mut lines: Vec<(LoggingLevel, String)> = vec![
            (LoggingLevel::Info, format!("Extended Request Id: {id}")),
            (
                LoggingLevel::Info,
                format!("Starting execution for request: {id}"),
            ),
            (
                LoggingLevel::Info,
                format!(
                    "HTTP Method: {}, Resource Path: {}",
                    ctx.method, ctx.resource_path
                ),
            ),
        ];
        if self.data_trace {
            lines.push((
                LoggingLevel::Info,
                format!("Method request query string: {}", Self::query_string(ctx)),
            ));
            lines.push((
                LoggingLevel::Info,
                format!("Method request headers: {}", Self::headers(ctx)),
            ));
        }
        if let Some((status, latency_ms)) = outcome.integration {
            lines.push((
                LoggingLevel::Info,
                format!(
                    "Received response. Status: {status}, Integration latency: {latency_ms} ms"
                ),
            ));
        }
        if outcome.status >= 500 {
            lines.push((
                LoggingLevel::Error,
                format!(
                    "Execution failed: the method completed with status {}",
                    outcome.status
                ),
            ));
        }
        lines.push((
            LoggingLevel::Info,
            format!("Method completed with status: {}", outcome.status),
        ));
        lines
            .into_iter()
            .filter(|(level, _)| *level <= self.level)
            .map(|(_, text)| Self::event(id, &text))
            .collect()
    }

    fn event(id: uuid::Uuid, text: &str) -> String {
        let mut line = format!("({id}) {text}");
        if line.len() > MAX_EVENT_BYTES {
            line.truncate(line.floor_char_boundary(MAX_EVENT_BYTES));
        }
        line
    }

    /// `{a=1, b=2}`, the way API Gateway prints parameter maps.
    fn query_string(ctx: &RequestContext) -> String {
        let pairs: Vec<String> = ctx
            .query
            .pairs()
            .into_iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect();
        format!("{{{}}}", pairs.join(", "))
    }

    fn headers(ctx: &RequestContext) -> String {
        let pairs: Vec<String> = ctx
            .headers
            .iter()
            .map(|(name, value)| {
                let value = if REDACTED_HEADERS.contains(&name.as_str()) {
                    "[redacted]"
                } else {
                    value.to_str().unwrap_or("[binary]")
                };
                format!("{name}={value}")
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
    use crate::pipeline::context::tests::request;

    const OK: Outcome = Outcome {
        status: 200,
        integration: Some((200, 12)),
    };

    fn logging(level: LoggingLevel, data_trace: bool) -> ExecutionLogging {
        ExecutionLogging { level, data_trace }
    }

    #[test]
    fn info_level_traces_the_request_lifecycle() {
        let ctx = request(ApiKind::Rest);
        let id = ctx.request_id;
        let lines = logging(LoggingLevel::Info, false).lines(&ctx, OK);
        assert_eq!(
            lines,
            vec![
                format!("({id}) Extended Request Id: {id}"),
                format!("({id}) Starting execution for request: {id}"),
                format!("({id}) HTTP Method: POST, Resource Path: /pets/{{petId}}"),
                format!("({id}) Received response. Status: 200, Integration latency: 12 ms"),
                format!("({id}) Method completed with status: 200"),
            ]
        );
    }

    #[test]
    fn error_level_logs_only_failures() {
        let ctx = request(ApiKind::Rest);
        let level = logging(LoggingLevel::Error, true);
        assert!(level.lines(&ctx, OK).is_empty());
        let failed = level.lines(
            &ctx,
            Outcome {
                status: 502,
                integration: None,
            },
        );
        assert_eq!(failed.len(), 1);
        assert!(failed.iter().all(|l| l.contains("Execution failed")));
    }

    #[test]
    fn data_trace_adds_the_query_string_and_redacted_headers() {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers
            .insert("authorization", HeaderValue::from_static("Bearer secret"));
        ctx.headers
            .insert("x-api-key", HeaderValue::from_static("key"));
        let lines = logging(LoggingLevel::Info, true).lines(&ctx, OK).join("\n");
        assert!(lines.contains("Method request query string: {q=1, q=2}"));
        assert!(lines.contains("user-agent=curl/8"));
        assert!(lines.contains("authorization=[redacted]"));
        assert!(lines.contains("x-api-key=[redacted]"));
        assert!(!lines.contains("secret"));
    }

    #[test]
    fn events_are_cut_at_one_kilobyte_on_a_character_boundary() {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers.insert(
            "x-long",
            HeaderValue::from_str(&"a".repeat(3000))
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        );
        let lines = logging(LoggingLevel::Info, true).lines(&ctx, OK);
        assert!(lines.iter().all(|l| l.len() <= MAX_EVENT_BYTES));
        assert!(lines.iter().any(|l| l.len() == MAX_EVENT_BYTES));
        let line = ExecutionLogging::event(ctx.request_id, &"\u{e9}".repeat(2000));
        assert!(line.len() <= MAX_EVENT_BYTES);
    }
}
