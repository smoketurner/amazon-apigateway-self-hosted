//! `OTEL_TRACES_EXPORTER=console`: each finished span as one JSON object per
//! line on standard output, with OTLP/JSON field names, for log collectors
//! that forward container output.

use std::fmt;
use std::io::Write;
use std::sync::{Mutex, PoisonError};
use std::time::SystemTime;

use opentelemetry::trace::{SpanKind, Status};
use opentelemetry::{Array, StringValue, Value as OtelValue};
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::trace::{SpanData, SpanExporter};
use serde_json::{Map, Value, json};

type Sink = Box<dyn Write + Send>;

pub(crate) struct JsonLines {
    out: Mutex<Sink>,
}

impl fmt::Debug for JsonLines {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JsonLines").finish_non_exhaustive()
    }
}

impl JsonLines {
    pub(crate) fn stdout() -> Self {
        Self::to(Box::new(std::io::stdout()))
    }

    fn to(out: Sink) -> Self {
        Self {
            out: Mutex::new(out),
        }
    }

    fn line(span: &SpanData) -> Value {
        let context = &span.span_context;
        let mut line = Map::new();
        line.insert("traceId".to_owned(), json!(context.trace_id().to_string()));
        line.insert("spanId".to_owned(), json!(context.span_id().to_string()));
        if span.parent_span_id != opentelemetry::trace::SpanId::INVALID {
            line.insert(
                "parentSpanId".to_owned(),
                json!(span.parent_span_id.to_string()),
            );
        }
        line.insert("name".to_owned(), json!(span.name));
        line.insert("kind".to_owned(), json!(Self::kind(&span.span_kind)));
        line.insert(
            "startTimeUnixNano".to_owned(),
            json!(Self::unix_nanos(span.start_time)),
        );
        line.insert(
            "endTimeUnixNano".to_owned(),
            json!(Self::unix_nanos(span.end_time)),
        );
        let attributes: Map<String, Value> = span
            .attributes
            .iter()
            .map(|kv| (kv.key.to_string(), Self::value(&kv.value)))
            .collect();
        line.insert("attributes".to_owned(), Value::Object(attributes));
        let status = match span.status {
            Status::Unset => json!({"code": "STATUS_CODE_UNSET"}),
            Status::Ok => json!({"code": "STATUS_CODE_OK"}),
            Status::Error { ref description } => {
                json!({"code": "STATUS_CODE_ERROR", "message": description})
            }
        };
        line.insert("status".to_owned(), status);
        line.insert("scope".to_owned(), json!(span.instrumentation_scope.name()));
        Value::Object(line)
    }

    fn kind(kind: &SpanKind) -> &'static str {
        match kind {
            SpanKind::Client => "SPAN_KIND_CLIENT",
            SpanKind::Server => "SPAN_KIND_SERVER",
            SpanKind::Producer => "SPAN_KIND_PRODUCER",
            SpanKind::Consumer => "SPAN_KIND_CONSUMER",
            SpanKind::Internal => "SPAN_KIND_INTERNAL",
        }
    }

    /// As a string, the way OTLP/JSON writes 64-bit integers.
    fn unix_nanos(at: SystemTime) -> String {
        at.duration_since(SystemTime::UNIX_EPOCH)
            .map_or_else(|_| "0".to_owned(), |since| since.as_nanos().to_string())
    }

    fn value(value: &OtelValue) -> Value {
        match value {
            OtelValue::Bool(b) => json!(b),
            OtelValue::I64(i) => json!(i),
            OtelValue::F64(f) => json!(f),
            OtelValue::String(s) => json!(s.as_str()),
            OtelValue::Array(Array::Bool(values)) => json!(values),
            OtelValue::Array(Array::I64(values)) => json!(values),
            OtelValue::Array(Array::F64(values)) => json!(values),
            OtelValue::Array(Array::String(values)) => {
                json!(values.iter().map(StringValue::as_str).collect::<Vec<_>>())
            }
            other => json!(other.to_string()),
        }
    }
}

impl SpanExporter for JsonLines {
    fn export(&self, batch: Vec<SpanData>) -> impl Future<Output = OTelSdkResult> + Send {
        let mut text = String::new();
        for span in &batch {
            text.push_str(&Self::line(span).to_string());
            text.push('\n');
        }
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        let written = out
            .write_all(text.as_bytes())
            .and_then(|()| out.flush())
            .map_err(|err| OTelSdkError::InternalFailure(err.to_string()));
        std::future::ready(written)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they parsed")]
mod tests {
    use std::sync::Arc;

    use opentelemetry::KeyValue;
    use opentelemetry::trace::{Span as _, Tracer as _, TracerProvider as _};
    use opentelemetry_sdk::trace::SdkTracerProvider;

    use super::*;

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn each_span_is_one_json_line_with_otlp_field_names() {
        let buffer = Buffer::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(JsonLines::to(Box::new(buffer.clone())))
            .build();
        let tracer = provider.tracer("apigw");
        let mut parent = tracer.start("GET /pets");
        parent.set_attribute(KeyValue::new("http.response.status_code", 200_i64));
        parent.set_attribute(KeyValue::new("ok", true));
        parent.set_attribute(KeyValue::new(
            "tags",
            OtelValue::Array(Array::String(vec!["a".into()])),
        ));
        parent.set_status(Status::error("boom"));
        parent.end();
        drop(provider);

        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 1, "{text}");
        let span: Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(span["name"], "GET /pets");
        assert_eq!(span["kind"], "SPAN_KIND_INTERNAL");
        assert_eq!(span["traceId"].as_str().unwrap().len(), 32);
        assert_eq!(span["spanId"].as_str().unwrap().len(), 16);
        assert!(span.get("parentSpanId").is_none());
        assert_eq!(span["attributes"]["http.response.status_code"], 200);
        assert_eq!(span["attributes"]["ok"], true);
        assert_eq!(span["attributes"]["tags"], json!(["a"]));
        assert_eq!(span["status"]["code"], "STATUS_CODE_ERROR");
        assert_eq!(span["status"]["message"], "boom");
        assert_eq!(span["scope"], "apigw");
        assert!(
            span["startTimeUnixNano"]
                .as_str()
                .unwrap()
                .parse::<u128>()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn span_kinds_use_otlp_names() {
        assert_eq!(JsonLines::kind(&SpanKind::Server), "SPAN_KIND_SERVER");
        assert_eq!(JsonLines::kind(&SpanKind::Client), "SPAN_KIND_CLIENT");
        assert_eq!(JsonLines::kind(&SpanKind::Producer), "SPAN_KIND_PRODUCER");
        assert_eq!(JsonLines::kind(&SpanKind::Consumer), "SPAN_KIND_CONSUMER");
        assert_eq!(JsonLines::unix_nanos(SystemTime::UNIX_EPOCH), "0");
    }
}
