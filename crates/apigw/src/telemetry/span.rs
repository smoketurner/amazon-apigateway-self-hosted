//! OpenTelemetry request spans: a server span per request (HTTP semantic
//! conventions), child spans for the authorizer and the integration, and W3C
//! Trace Context (`traceparent`, `tracestate`) extraction and injection.

use std::borrow::Cow;

use axum::http::{HeaderMap, HeaderName, HeaderValue, Method};
use opentelemetry::propagation::{Extractor, Injector, TextMapPropagator as _};
use opentelemetry::trace::{SpanKind, Status, TraceContextExt as _, Tracer as _};
use opentelemetry::{Context, KeyValue};
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::SdkTracer;

/// Methods reported as themselves in `http.request.method`; others are `_OTHER`.
const KNOWN_METHODS: [&str; 9] = [
    "GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS", "CONNECT", "TRACE",
];

struct HeaderExtractor<'a>(&'a HeaderMap);

impl Extractor for HeaderExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(HeaderName::as_str).collect()
    }
}

struct HeaderInjector<'a>(&'a mut HeaderMap);

impl Injector for HeaderInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(&value),
        ) {
            self.0.insert(name, value);
        }
    }
}

/// What the server span says about a request when it starts.
#[derive(Debug, Clone)]
pub(crate) struct ServerRequest<'a> {
    pub(crate) method: &'a Method,
    /// The route template, when a route matched.
    pub(crate) route: Option<&'a str>,
    pub(crate) path: &'a str,
    pub(crate) host: Option<&'a str>,
    pub(crate) user_agent: Option<&'a str>,
    pub(crate) client_address: Option<String>,
    pub(crate) api_id: &'a str,
    pub(crate) stage: &'a str,
    pub(crate) request_id: Option<String>,
}

/// Starts request spans. Cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct RequestTracer {
    tracer: SdkTracer,
}

impl RequestTracer {
    pub(crate) fn new(tracer: SdkTracer) -> Self {
        Self { tracer }
    }

    /// The parent a request names in `traceparent` and `tracestate`; the
    /// empty context when it names none or the header is malformed.
    pub(crate) fn extract(headers: &HeaderMap) -> Context {
        TraceContextPropagator::new().extract(&HeaderExtractor(headers))
    }

    /// Starts the server span for a request whose headers are `headers`.
    pub(crate) fn server(&self, headers: &HeaderMap, request: &ServerRequest<'_>) -> RequestSpan {
        let parent = Self::extract(headers);
        let method = if KNOWN_METHODS.contains(&request.method.as_str()) {
            request.method.as_str()
        } else {
            "_OTHER"
        };
        let name = match request.route {
            Some(route) => format!("{method} {route}"),
            None => method.to_owned(),
        };
        let mut attributes = vec![
            KeyValue::new("http.request.method", method.to_owned()),
            KeyValue::new("url.path", request.path.to_owned()),
            KeyValue::new("url.scheme", "https"),
            KeyValue::new("apigw.api_id", request.api_id.to_owned()),
            KeyValue::new("apigw.stage", request.stage.to_owned()),
        ];
        if method == "_OTHER" {
            attributes.push(KeyValue::new(
                "http.request.method_original",
                request.method.as_str().to_owned(),
            ));
        }
        let optional = [
            ("http.route", request.route.map(str::to_owned)),
            ("server.address", request.host.map(str::to_owned)),
            ("user_agent.original", request.user_agent.map(str::to_owned)),
            ("client.address", request.client_address.clone()),
            ("apigw.request_id", request.request_id.clone()),
        ];
        for (key, value) in optional {
            if let Some(value) = value {
                attributes.push(KeyValue::new(key, value));
            }
        }
        let span = self
            .tracer
            .span_builder(name)
            .with_kind(SpanKind::Server)
            .with_attributes(attributes)
            .start_with_context(&self.tracer, &parent);
        RequestSpan {
            cx: parent.with_span(span),
            tracer: self.clone(),
        }
    }
}

/// One request's server span, carried in the request's extensions so the
/// pipeline can start child spans beneath it. Cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct RequestSpan {
    cx: Context,
    tracer: RequestTracer,
}

/// What the integration span is about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpanTarget {
    /// `HTTP_PROXY`, `AWS_PROXY`, `HTTP`, `AWS`, `MOCK`, ...
    pub(crate) kind: &'static str,
    /// The backend URI, function, or service.
    pub(crate) target: Option<String>,
}

impl RequestSpan {
    /// Ends the span with the response status. Server spans are errors only
    /// for 5xx responses.
    pub(crate) fn finish(&self, status: u16, response_length: Option<u64>) {
        let span = self.cx.span();
        span.set_attribute(KeyValue::new(
            "http.response.status_code",
            i64::from(status),
        ));
        if let Some(length) = response_length.and_then(|l| i64::try_from(l).ok()) {
            span.set_attribute(KeyValue::new("http.response.body.size", length));
        }
        if status >= 500 {
            span.set_attribute(KeyValue::new("error.type", status.to_string()));
            span.set_status(Status::error(""));
        }
        span.end();
    }

    fn child(&self, name: String, kind: SpanKind, attributes: Vec<KeyValue>) -> ChildSpan {
        let span = self
            .tracer
            .tracer
            .span_builder(name)
            .with_kind(kind)
            .with_attributes(attributes)
            .start_with_context(&self.tracer.tracer, &self.cx);
        ChildSpan {
            cx: self.cx.with_span(span),
        }
    }

    /// A span for running the route's authorizer.
    pub(crate) fn authorizer(&self, kind: &'static str, name: &str) -> ChildSpan {
        self.child(
            format!("authorizer {name}"),
            SpanKind::Internal,
            vec![
                KeyValue::new("apigw.authorizer.type", kind),
                KeyValue::new("apigw.authorizer.name", name.to_owned()),
            ],
        )
    }

    /// A span for calling the integration.
    pub(crate) fn integration(&self, target: &SpanTarget) -> ChildSpan {
        let mut attributes = vec![KeyValue::new("apigw.integration.type", target.kind)];
        if let Some(ref value) = target.target {
            attributes.push(KeyValue::new("apigw.integration.target", value.clone()));
        }
        self.child(
            format!("integration {}", target.kind),
            SpanKind::Client,
            attributes,
        )
    }
}

/// An authorizer or integration span; ended by [`ChildSpan::end`] or dropping.
#[derive(Debug, Clone)]
pub(crate) struct ChildSpan {
    cx: Context,
}

impl ChildSpan {
    pub(crate) fn set(&self, key: &'static str, value: impl Into<opentelemetry::Value>) {
        self.cx.span().set_attribute(KeyValue::new(key, value));
    }

    pub(crate) fn fail(&self, description: impl Into<Cow<'static, str>>) {
        self.cx.span().set_status(Status::error(description));
    }

    /// Writes this span as the parent into `traceparent` and `tracestate`.
    pub(crate) fn inject(&self, headers: &mut HeaderMap) {
        TraceContextPropagator::new().inject_context(&self.cx, &mut HeaderInjector(headers));
    }

    pub(crate) fn end(&self) {
        self.cx.span().end();
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index spans they produced")]
pub(crate) mod tests {
    use opentelemetry::trace::{TraceId, TracerProvider as _};
    use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider, SpanData};

    use super::*;

    /// A tracer whose finished spans `exporter` holds.
    pub(crate) fn in_memory() -> (RequestTracer, InMemorySpanExporter, SdkTracerProvider) {
        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        (
            RequestTracer::new(provider.tracer("apigw")),
            exporter,
            provider,
        )
    }

    pub(crate) fn attribute(span: &SpanData, key: &str) -> Option<String> {
        span.attributes
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| kv.value.to_string())
    }

    fn request<'a>(method: &'a Method, route: Option<&'a str>) -> ServerRequest<'a> {
        ServerRequest {
            method,
            route,
            path: "/pets/7",
            host: Some("api.example.com"),
            user_agent: Some("curl/8"),
            client_address: Some("192.0.2.1".to_owned()),
            api_id: "abc",
            stage: "prod",
            request_id: Some("id-1".to_owned()),
        }
    }

    const TRACEPARENT: &str = "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01";

    #[test]
    fn server_spans_continue_the_callers_trace_and_follow_http_conventions() {
        let (tracer, exporter, _provider) = in_memory();
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
        headers.insert("tracestate", HeaderValue::from_static("vendor=x"));
        let span = tracer.server(&headers, &request(&Method::GET, Some("/pets/{petId}")));
        let integration = span.integration(&SpanTarget {
            kind: "HTTP_PROXY",
            target: Some("https://backend/pets".to_owned()),
        });
        let mut downstream = HeaderMap::new();
        integration.inject(&mut downstream);
        integration.set("http.response.status_code", 502_i64);
        integration.fail("bad gateway");
        integration.end();
        span.finish(502, Some(12));

        let spans = exporter.get_finished_spans().unwrap();
        assert_eq!(spans.len(), 2);
        let (client, server) = (&spans[0], &spans[1]);
        assert_eq!(server.name, "GET /pets/{petId}");
        assert_eq!(server.span_kind, SpanKind::Server);
        assert_eq!(
            server.span_context.trace_id(),
            TraceId::from_hex("4efaaf4d1e8720b39541901950019ee5").unwrap()
        );
        assert_eq!(server.parent_span_id.to_string(), "00f067aa0ba902b7");
        assert!(server.parent_span_is_remote);
        assert_eq!(server.span_context.trace_state().header(), "vendor=x");
        for (key, value) in [
            ("http.request.method", "GET"),
            ("http.route", "/pets/{petId}"),
            ("url.path", "/pets/7"),
            ("url.scheme", "https"),
            ("server.address", "api.example.com"),
            ("client.address", "192.0.2.1"),
            ("user_agent.original", "curl/8"),
            ("http.response.status_code", "502"),
            ("http.response.body.size", "12"),
            ("error.type", "502"),
            ("apigw.api_id", "abc"),
            ("apigw.stage", "prod"),
            ("apigw.request_id", "id-1"),
        ] {
            assert_eq!(attribute(server, key).as_deref(), Some(value), "{key}");
        }
        assert!(matches!(server.status, Status::Error { .. }));

        assert_eq!(client.name, "integration HTTP_PROXY");
        assert_eq!(client.span_kind, SpanKind::Client);
        assert_eq!(client.parent_span_id, server.span_context.span_id());
        assert_eq!(
            attribute(client, "apigw.integration.target").as_deref(),
            Some("https://backend/pets")
        );
        assert_eq!(
            downstream["traceparent"].to_str().unwrap(),
            format!(
                "00-4efaaf4d1e8720b39541901950019ee5-{}-01",
                client.span_context.span_id()
            )
        );
        assert_eq!(downstream["tracestate"].to_str().unwrap(), "vendor=x");
    }

    #[test]
    fn requests_without_a_parent_start_a_trace_and_odd_methods_are_bounded() {
        let (tracer, exporter, _provider) = in_memory();
        let mut headers = HeaderMap::new();
        headers.insert("traceparent", HeaderValue::from_static("garbage"));
        let propfind = Method::from_bytes(b"PROPFIND").unwrap();
        let span = tracer.server(&headers, &request(&propfind, None));
        span.authorizer("TOKEN", "auth").end();
        span.finish(404, None);
        let spans = exporter.get_finished_spans().unwrap();
        let server = &spans[1];
        assert_eq!(server.name, "_OTHER");
        assert_eq!(server.parent_span_id, opentelemetry::trace::SpanId::INVALID);
        assert_eq!(
            attribute(server, "http.request.method_original").as_deref(),
            Some("PROPFIND")
        );
        assert_eq!(attribute(server, "http.route"), None);
        assert!(
            matches!(server.status, Status::Unset),
            "4xx is not a server error"
        );
        let authorizer = &spans[0];
        assert_eq!(authorizer.name, "authorizer auth");
        assert_eq!(authorizer.span_kind, SpanKind::Internal);
        assert_eq!(
            attribute(authorizer, "apigw.authorizer.type").as_deref(),
            Some("TOKEN")
        );
    }

    #[test]
    fn extraction_ignores_requests_without_trace_context() {
        let cx = RequestTracer::extract(&HeaderMap::new());
        assert!(!cx.span().span_context().is_valid());
    }
}
