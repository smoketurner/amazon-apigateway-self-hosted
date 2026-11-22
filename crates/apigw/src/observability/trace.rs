//! Distributed tracing: the `X-Amzn-Trace-Id` header, W3C `traceparent`
//! interop, sampling, and X-Ray segment documents.
//!
//! <https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-tracingheader>
//! <https://docs.aws.amazon.com/xray/latest/devguide/xray-api-segmentdocuments.html>

use std::fmt;
use std::str::FromStr;

use serde_json::{Map, Number, Value, json};

use crate::entropy::Entropy;
use crate::pipeline::RequestContext;

/// Fixed-size identifier written as lowercase hexadecimal.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Hex<const N: usize>([u8; N]);

impl<const N: usize> Hex<N> {
    fn random() -> Option<Self> {
        Entropy::bytes().map(Self)
    }
}

impl<const N: usize> fmt::Display for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl<const N: usize> FromStr for Hex<N> {
    type Err = InvalidTrace;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidTrace(text.to_owned());
        if text.len() != N.saturating_mul(2) || !text.is_ascii() {
            return Err(invalid());
        }
        let mut bytes = [0_u8; N];
        let (pairs, _) = text.as_bytes().as_chunks::<2>();
        for (byte, pair) in bytes.iter_mut().zip(pairs) {
            let pair = std::str::from_utf8(pair).map_err(|_| invalid())?;
            if !pair.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid());
            }
            *byte = u8::from_str_radix(pair, 16).map_err(|_| invalid())?;
        }
        Ok(Self(bytes))
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0:?} is not a valid trace identifier")]
pub(crate) struct InvalidTrace(String);

/// An X-Ray trace ID: `1-{8 hex digits of epoch seconds}-{24 hex digits}`. The
/// 32 hex digits after the version are the W3C trace ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TraceId {
    epoch: Hex<4>,
    unique: Hex<12>,
}

impl TraceId {
    pub(crate) fn generate(now: jiff::Timestamp) -> Option<Self> {
        let seconds = u32::try_from(now.as_second()).unwrap_or_default();
        Some(Self {
            epoch: Hex(seconds.to_be_bytes()),
            unique: Hex::random()?,
        })
    }

    /// The trace ID as W3C Trace Context writes it: 32 hex digits.
    fn w3c(&self) -> String {
        format!("{}{}", self.epoch, self.unique)
    }

    fn from_w3c(text: &str) -> Result<Self, InvalidTrace> {
        let invalid = || InvalidTrace(text.to_owned());
        let epoch = text.get(..8).ok_or_else(invalid)?.parse()?;
        let unique = text.get(8..).ok_or_else(invalid)?.parse()?;
        let id = Self { epoch, unique };
        // An all-zero trace ID is invalid in W3C Trace Context.
        if id.w3c().bytes().all(|b| b == b'0') {
            return Err(invalid());
        }
        Ok(id)
    }
}

impl fmt::Display for TraceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "1-{}-{}", self.epoch, self.unique)
    }
}

impl FromStr for TraceId {
    type Err = InvalidTrace;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidTrace(text.to_owned());
        let mut parts = text.split('-');
        let (Some("1"), Some(epoch), Some(unique), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(invalid());
        };
        Ok(Self {
            epoch: epoch.parse().map_err(|_| invalid())?,
            unique: unique.parse().map_err(|_| invalid())?,
        })
    }
}

/// A 64-bit segment ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SegmentId(Hex<8>);

impl SegmentId {
    fn generate() -> Option<Self> {
        Hex::random().map(Self)
    }
}

impl fmt::Display for SegmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl FromStr for SegmentId {
    type Err = InvalidTrace;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        text.parse().map(Self)
    }
}

/// The `X-Amzn-Trace-Id` header: `Root=...;Parent=...;Sampled=1`. Fields this
/// gateway does not use (`Lineage`, `Self`, ...) are ignored when parsing, and
/// a field that is malformed is treated as absent so a bad header never fails a
/// request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TraceHeader {
    pub(crate) root: Option<TraceId>,
    pub(crate) parent: Option<SegmentId>,
    /// `Sampled=1` or `Sampled=0`; absent for no decision (or `Sampled=?`).
    pub(crate) sampled: Option<bool>,
}

impl FromStr for TraceHeader {
    type Err = std::convert::Infallible;

    fn from_str(header: &str) -> Result<Self, Self::Err> {
        let mut parsed = Self::default();
        for field in header.split(';') {
            let Some((name, value)) = field.split_once('=') else {
                continue;
            };
            match name.trim() {
                "Root" => parsed.root = value.trim().parse().ok(),
                "Parent" => parsed.parent = value.trim().parse().ok(),
                "Sampled" => {
                    parsed.sampled = match value.trim() {
                        "1" => Some(true),
                        "0" => Some(false),
                        _ => None,
                    };
                }
                _ => {}
            }
        }
        Ok(parsed)
    }
}

impl fmt::Display for TraceHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut separator = if let Some(root) = self.root {
            write!(f, "Root={root}")?;
            ";"
        } else {
            ""
        };
        if let Some(parent) = self.parent {
            write!(f, "{separator}Parent={parent}")?;
            separator = ";";
        }
        if let Some(sampled) = self.sampled {
            write!(f, "{separator}Sampled={}", u8::from(sampled))?;
        }
        Ok(())
    }
}

/// A W3C Trace Context `traceparent` header, version 00:
/// `00-{32 hex trace ID}-{16 hex parent ID}-{2 hex flags}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TraceParent {
    trace: TraceId,
    parent: SegmentId,
    sampled: bool,
}

impl FromStr for TraceParent {
    type Err = InvalidTrace;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidTrace(text.to_owned());
        let mut parts = text.split('-');
        let (Some("00"), Some(trace), Some(parent), Some(flags), None) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            return Err(invalid());
        };
        let parent: SegmentId = parent.parse()?;
        if parent.0.0 == [0; 8] {
            return Err(invalid());
        }
        let flags: Hex<1> = flags.parse()?;
        Ok(Self {
            trace: TraceId::from_w3c(trace)?,
            parent,
            sampled: flags.0.first().is_some_and(|flags| flags & 1 == 1),
        })
    }
}

/// One request's place in a trace, as this gateway's segment sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Trace {
    id: TraceId,
    segment: SegmentId,
    /// The subsegment for the integration call, which integrations name as
    /// their parent.
    integration: SegmentId,
    /// The caller's segment, when the request carried one.
    parent: Option<SegmentId>,
    sampled: bool,
}

impl Trace {
    /// Continues the trace in `x_amzn_trace_id` (or `traceparent`, for W3C
    /// clients) or starts one, taking the caller's sampling decision when it
    /// made one and asking `sample` otherwise. `None` when identifiers could
    /// not be generated.
    pub(crate) fn start(
        x_amzn_trace_id: Option<&str>,
        traceparent: Option<&str>,
        sample: impl FnOnce() -> bool,
        now: jiff::Timestamp,
    ) -> Option<Self> {
        let header: TraceHeader = x_amzn_trace_id
            .and_then(|h| h.parse().ok())
            .unwrap_or_default();
        let w3c: Option<TraceParent> = traceparent.and_then(|h| h.parse().ok());
        let (id, parent) = match (header.root, w3c) {
            (Some(root), _) => (root, header.parent),
            (None, Some(w3c)) => (w3c.trace, Some(w3c.parent)),
            (None, None) => (TraceId::generate(now)?, None),
        };
        let sampled = header
            .sampled
            .or_else(|| w3c.map(|w| w.sampled))
            .unwrap_or_else(sample);
        Some(Self {
            id,
            segment: SegmentId::generate()?,
            integration: SegmentId::generate()?,
            parent,
            sampled,
        })
    }

    /// X-Ray's passive mode: continues a trace the caller sampled, and starts
    /// none. `None` for a request without a sampled trace.
    pub(crate) fn continue_sampled(
        x_amzn_trace_id: Option<&str>,
        traceparent: Option<&str>,
        now: jiff::Timestamp,
    ) -> Option<Self> {
        let header: TraceHeader = x_amzn_trace_id
            .and_then(|h| h.parse().ok())
            .unwrap_or_default();
        let w3c: Option<TraceParent> = traceparent.and_then(|h| h.parse().ok());
        let caller_sampled = match (header.root, w3c) {
            (Some(_), _) => header.sampled == Some(true),
            (None, Some(w3c)) => w3c.sampled,
            (None, None) => false,
        };
        if !caller_sampled {
            return None;
        }
        Self::start(x_amzn_trace_id, traceparent, || false, now)
    }

    pub(crate) fn is_sampled(&self) -> bool {
        self.sampled
    }

    pub(crate) fn id(&self) -> TraceId {
        self.id
    }

    /// The `X-Amzn-Trace-Id` to send downstream: the integration subsegment
    /// of this gateway's segment is the parent.
    pub(crate) fn header(&self) -> TraceHeader {
        TraceHeader {
            root: Some(self.id),
            parent: Some(self.integration),
            sampled: Some(self.sampled),
        }
    }

    /// The `traceparent` to send downstream to W3C-aware backends.
    pub(crate) fn traceparent(&self) -> String {
        format!(
            "00-{}-{}-{}",
            self.id.w3c(),
            self.integration,
            if self.sampled { "01" } else { "00" }
        )
    }
}

/// What a finished request tells X-Ray.
#[derive(Debug, Clone)]
pub(crate) struct SegmentOutcome<'a> {
    pub(crate) started: jiff::Timestamp,
    pub(crate) ended: jiff::Timestamp,
    pub(crate) status: u16,
    pub(crate) content_length: Option<u64>,
    /// The integration call, when one was made to a backend.
    pub(crate) integration: Option<IntegrationCall<'a>>,
}

/// One integration call, recorded as a subsegment.
#[derive(Debug, Clone)]
pub(crate) struct IntegrationCall<'a> {
    /// `HTTP_PROXY`, `HTTP`, `AWS_PROXY`, or `AWS`.
    pub(crate) kind: &'static str,
    /// The backend URI, Lambda function, or AWS service.
    pub(crate) target: Option<&'a str>,
    pub(crate) method: &'a str,
    pub(crate) started: jiff::Timestamp,
    pub(crate) ended: jiff::Timestamp,
    /// The backend's status, when it answered.
    pub(crate) status: Option<u16>,
    /// The call failed without a usable answer.
    pub(crate) failed: bool,
}

impl Trace {
    const MAX_NAME_CHARS: usize = 200;
    const MAX_URL_CHARS: usize = 2048;
    const MAX_USER_AGENT_CHARS: usize = 512;

    /// The X-Ray segment document for this gateway's part of the request.
    pub(crate) fn segment(
        &self,
        name: &str,
        ctx: &RequestContext,
        outcome: &SegmentOutcome<'_>,
    ) -> String {
        let mut request = Map::new();
        request.insert("method".to_owned(), json!(ctx.method.as_str()));
        request.insert(
            "url".to_owned(),
            json!(Self::truncated(
                &format!("https://{}{}", ctx.domain_name(), ctx.path),
                Self::MAX_URL_CHARS
            )),
        );
        if let Some(agent) = ctx.header_str("user-agent") {
            request.insert(
                "user_agent".to_owned(),
                json!(Self::truncated(agent, Self::MAX_USER_AGENT_CHARS)),
            );
        }
        if let Some(ip) = ctx.source_ip() {
            request.insert("client_ip".to_owned(), json!(ip));
        }
        let mut response = Map::new();
        response.insert("status".to_owned(), json!(outcome.status));
        if let Some(length) = outcome.content_length {
            response.insert("content_length".to_owned(), json!(length));
        }
        let mut segment = json!({
            "name": Self::segment_name(name),
            "id": self.segment.to_string(),
            "trace_id": self.id.to_string(),
            "start_time": Self::epoch_seconds(outcome.started),
            "end_time": Self::epoch_seconds(outcome.ended),
            "origin": "AWS::ApiGateway::Stage",
            "http": {"request": request, "response": response},
        });
        if let Value::Object(ref mut fields) = segment {
            if let Some(parent) = self.parent {
                fields.insert("parent_id".to_owned(), json!(parent.to_string()));
            }
            Self::flag(fields, Some(outcome.status), false);
            if let Some(ref call) = outcome.integration {
                fields.insert("subsegments".to_owned(), json!([self.subsegment(call)]));
            }
        }
        segment.to_string()
    }

    /// `error` for 4xx, `throttle` too for 429, `fault` for 5xx or a call
    /// that failed.
    fn flag(fields: &mut Map<String, Value>, status: Option<u16>, failed: bool) {
        match status {
            Some(429) => {
                fields.insert("error".to_owned(), json!(true));
                fields.insert("throttle".to_owned(), json!(true));
            }
            Some(400..=499) => {
                fields.insert("error".to_owned(), json!(true));
            }
            Some(500..=599) => {
                fields.insert("fault".to_owned(), json!(true));
            }
            Some(_) | None if failed => {
                fields.insert("fault".to_owned(), json!(true));
            }
            Some(_) | None => {}
        }
    }

    /// The integration call: a `remote` subsegment named after the host for
    /// HTTP backends, an `aws` one for Lambda and other AWS services.
    fn subsegment(&self, call: &IntegrationCall<'_>) -> Value {
        let mut fields = Map::new();
        fields.insert("id".to_owned(), json!(self.integration.to_string()));
        fields.insert("start_time".to_owned(), Self::epoch_seconds(call.started));
        fields.insert("end_time".to_owned(), Self::epoch_seconds(call.ended));
        let target = call.target.unwrap_or_default();
        let url = reqwest::Url::parse(target)
            .ok()
            .filter(|url| matches!(url.scheme(), "http" | "https"));
        if let Some(url) = url {
            fields.insert(
                "name".to_owned(),
                json!(Self::segment_name(url.host_str().unwrap_or("remote"))),
            );
            fields.insert("namespace".to_owned(), json!("remote"));
            let mut response = Map::new();
            if let Some(status) = call.status {
                response.insert("status".to_owned(), json!(status));
            }
            fields.insert(
                "http".to_owned(),
                json!({"request": {"method": call.method,
                    "url": Self::truncated(target, Self::MAX_URL_CHARS)},
                    "response": response}),
            );
        } else if target.contains(":lambda:") || target.contains(":function:") {
            fields.insert("name".to_owned(), json!("Lambda"));
            fields.insert("namespace".to_owned(), json!("aws"));
            let mut aws = Map::new();
            aws.insert("operation".to_owned(), json!("Invoke"));
            aws.insert("function_name".to_owned(), json!(target));
            if let Some(region) = target.split(':').nth(3).filter(|r| !r.is_empty()) {
                aws.insert("region".to_owned(), json!(region));
            }
            fields.insert("aws".to_owned(), Value::Object(aws));
        } else {
            // `arn:aws:apigateway:{region}:{service}:...` for REST AWS
            // integrations, the subtype (`SQS-SendMessage`) for HTTP APIs.
            let service = target
                .strip_prefix("arn:")
                .and_then(|arn| arn.split(':').nth(3))
                .or_else(|| target.split('-').next())
                .filter(|s| !s.is_empty())
                .unwrap_or(call.kind);
            fields.insert("name".to_owned(), json!(Self::segment_name(service)));
            fields.insert("namespace".to_owned(), json!("aws"));
        }
        Self::flag(&mut fields, call.status, call.failed);
        Value::Object(fields)
    }

    /// Epoch seconds with microsecond resolution, as X-Ray wants them.
    fn epoch_seconds(at: jiff::Timestamp) -> Value {
        let micros = at.as_microsecond();
        let text = format!(
            "{}.{:06}",
            micros.div_euclid(1_000_000),
            micros.rem_euclid(1_000_000)
        );
        text.parse::<Number>().map_or(Value::Null, Value::Number)
    }

    /// Segment names allow letters, digits, whitespace, and `_ . : / % & # = + \ - @`.
    fn segment_name(name: &str) -> String {
        name.chars()
            .map(|c| {
                if c.is_alphanumeric() || c.is_whitespace() || "_.:/%&#=+\\-@".contains(c) {
                    c
                } else {
                    '_'
                }
            })
            .take(Self::MAX_NAME_CHARS)
            .collect()
    }

    fn truncated(text: &str, max_chars: usize) -> String {
        text.chars().take(max_chars).collect()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::model::ApiKind;
    use crate::pipeline::context::tests::request;

    const ROOT: &str = "1-5759e988-bd862e3fe1be46a994272793";
    const PARENT: &str = "53995c3f42cd8ad8";

    fn now() -> jiff::Timestamp {
        jiff::Timestamp::from_second(1_700_000_000).unwrap()
    }

    #[test]
    fn x_amzn_trace_ids_round_trip() {
        let header: TraceHeader = format!("Root={ROOT};Parent={PARENT};Sampled=1")
            .parse()
            .unwrap();
        assert_eq!(header.root.unwrap().to_string(), ROOT);
        assert_eq!(header.parent.unwrap().to_string(), PARENT);
        assert_eq!(header.sampled, Some(true));
        assert_eq!(
            header.to_string(),
            format!("Root={ROOT};Parent={PARENT};Sampled=1")
        );
    }

    #[test]
    fn unknown_and_malformed_header_fields_are_ignored() {
        let header: TraceHeader = format!("Root={ROOT};Lineage=25:a87bd80c:1;Parent=zz;Sampled=?")
            .parse()
            .unwrap();
        assert_eq!(header.root.unwrap().to_string(), ROOT);
        assert_eq!(header.parent, None);
        assert_eq!(header.sampled, None);
        let nothing: TraceHeader = "garbage;;=;Root=1-short".parse().unwrap();
        assert_eq!(nothing, TraceHeader::default());
        assert_eq!(nothing.to_string(), "");
    }

    #[test]
    fn trace_ids_reject_other_versions_and_lengths() {
        assert!(ROOT.parse::<TraceId>().is_ok());
        for bad in [
            "",
            "2-5759e988-bd862e3fe1be46a994272793",
            "1-5759e98-bd862e3fe1be46a994272793",
            "1-5759e988-bd862e3fe1be46a99427279",
            "1-5759e988-bd862e3fe1be46a99427279g",
            "1-5759e988-bd862e3fe1be46a994272793-x",
            "1-\u{e9}759e988-bd862e3fe1be46a994272793",
        ] {
            assert!(bad.parse::<TraceId>().is_err(), "{bad}");
        }
    }

    #[test]
    fn w3c_trace_ids_map_onto_x_ray_trace_ids() {
        let id = TraceId::from_w3c("4efaaf4d1e8720b39541901950019ee5").unwrap();
        assert_eq!(id.to_string(), "1-4efaaf4d-1e8720b39541901950019ee5");
        assert_eq!(id.w3c(), "4efaaf4d1e8720b39541901950019ee5");
        assert!(TraceId::from_w3c(&"0".repeat(32)).is_err());
        assert!(TraceId::from_w3c("abc").is_err());
    }

    #[test]
    fn traceparent_headers_parse_strictly() {
        let parsed: TraceParent = "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01"
            .parse()
            .unwrap();
        assert!(parsed.sampled);
        assert_eq!(parsed.parent.to_string(), "00f067aa0ba902b7");
        let unsampled: TraceParent = "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-00"
            .parse()
            .unwrap();
        assert!(!unsampled.sampled);
        for bad in [
            "",
            "01-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01",
            "00-4efaaf4d1e8720b39541901950019ee5-0000000000000000-01",
            "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
            "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7",
            "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01-extra",
            "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-zz",
        ] {
            assert!(bad.parse::<TraceParent>().is_err(), "{bad}");
        }
    }

    #[test]
    fn a_request_without_a_header_starts_a_new_trace() {
        let trace = Trace::start(None, None, || true, now()).unwrap();
        assert!(trace.is_sampled());
        assert!(
            trace.id().to_string().starts_with("1-655"),
            "{}",
            trace.id()
        );
        let header = trace.header();
        assert_eq!(header.root, Some(trace.id()));
        assert_eq!(header.sampled, Some(true));
        assert_eq!(header.parent, Some(trace.integration));
        assert_ne!(trace.integration, trace.segment);
        assert_eq!(trace.parent, None);
    }

    #[test]
    fn the_callers_sampling_decision_wins() {
        let sampled = Trace::start(
            Some(&format!("Root={ROOT};Parent={PARENT};Sampled=1")),
            None,
            || false,
            now(),
        )
        .unwrap();
        assert!(sampled.is_sampled());
        assert_eq!(sampled.id().to_string(), ROOT);
        assert_eq!(sampled.parent.unwrap().to_string(), PARENT);
        let declined = Trace::start(
            Some(&format!("Root={ROOT};Sampled=0")),
            None,
            || true,
            now(),
        )
        .unwrap();
        assert!(!declined.is_sampled());
        assert!(declined.header().to_string().ends_with("Sampled=0"));
    }

    #[test]
    fn w3c_clients_continue_their_trace() {
        let trace = Trace::start(
            None,
            Some("00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01"),
            || false,
            now(),
        )
        .unwrap();
        assert!(trace.is_sampled());
        assert_eq!(
            trace.id().to_string(),
            "1-4efaaf4d-1e8720b39541901950019ee5"
        );
        assert_eq!(trace.parent.unwrap().to_string(), "00f067aa0ba902b7");
        let traceparent = trace.traceparent();
        assert!(traceparent.starts_with("00-4efaaf4d1e8720b39541901950019ee5-"));
        assert!(traceparent.ends_with("-01"));
        assert!(traceparent.parse::<TraceParent>().is_ok());
    }

    #[test]
    fn a_w3c_client_that_declined_sampling_is_not_sampled() {
        let trace = Trace::start(
            None,
            Some("00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-00"),
            || true,
            now(),
        )
        .unwrap();
        assert!(!trace.is_sampled());
        assert!(trace.traceparent().ends_with("-00"));
    }

    #[test]
    fn an_invalid_header_is_replaced_by_a_new_trace() {
        let trace = Trace::start(Some("Root=nonsense"), Some("junk"), || true, now()).unwrap();
        assert!(trace.header().to_string().starts_with("Root=1-655"));
    }

    #[test]
    fn segments_describe_the_request_and_flag_errors() {
        let ctx = request(ApiKind::Rest);
        let trace = Trace::start(
            Some(&format!("Root={ROOT};Parent={PARENT};Sampled=1")),
            None,
            || false,
            now(),
        )
        .unwrap();
        let outcome = |status| SegmentOutcome {
            started: jiff::Timestamp::from_microsecond(1_700_000_000_250_000).unwrap(),
            ended: jiff::Timestamp::from_microsecond(1_700_000_000_750_500).unwrap(),
            status,
            content_length: Some(12),
            integration: None,
        };
        let ok: Value =
            serde_json::from_str(&trace.segment("pets/prod", &ctx, &outcome(200))).unwrap();
        assert_eq!(ok["name"], "pets/prod");
        assert_eq!(ok["trace_id"], ROOT);
        assert_eq!(ok["parent_id"], PARENT);
        assert_eq!(ok["origin"], "AWS::ApiGateway::Stage");
        assert_eq!(ok["start_time"], 1_700_000_000.25);
        assert_eq!(ok["end_time"], 1_700_000_000.750_5);
        assert_eq!(
            ok["http"]["request"]["url"],
            "https://api.example.com/pets/7"
        );
        assert_eq!(ok["http"]["request"]["method"], "POST");
        assert_eq!(ok["http"]["request"]["user_agent"], "curl/8");
        assert_eq!(ok["http"]["request"]["client_ip"], "192.0.2.1");
        assert_eq!(ok["http"]["response"]["status"], 200);
        assert_eq!(ok["http"]["response"]["content_length"], 12);
        for flag in ["error", "throttle", "fault"] {
            assert!(ok.get(flag).is_none(), "{flag}");
        }
        assert_eq!(ok["id"].as_str().unwrap().len(), 16);

        let flags = |status| -> Vec<&'static str> {
            let doc: Value =
                serde_json::from_str(&trace.segment("n", &ctx, &outcome(status))).unwrap();
            ["error", "throttle", "fault"]
                .into_iter()
                .filter(|f| doc.get(f) == Some(&json!(true)))
                .collect()
        };
        assert_eq!(flags(404), ["error"]);
        assert_eq!(flags(429), ["error", "throttle"]);
        assert_eq!(flags(503), ["fault"]);
    }

    fn with_call(
        trace: &Trace,
        kind: &'static str,
        target: &str,
        status: Option<u16>,
        failed: bool,
    ) -> Value {
        let ctx = request(ApiKind::Rest);
        let at = |micros| jiff::Timestamp::from_microsecond(micros).unwrap();
        let outcome = SegmentOutcome {
            started: at(1_700_000_000_000_000),
            ended: at(1_700_000_000_900_000),
            status: status.unwrap_or(502),
            content_length: None,
            integration: Some(IntegrationCall {
                kind,
                target: Some(target),
                method: "POST",
                started: at(1_700_000_000_100_000),
                ended: at(1_700_000_000_800_000),
                status,
                failed,
            }),
        };
        let segment: Value =
            serde_json::from_str(&trace.segment("pets/prod", &ctx, &outcome)).unwrap();
        segment["subsegments"][0].clone()
    }

    #[test]
    fn the_integration_call_is_a_subsegment_that_backends_name_as_their_parent() {
        let trace = Trace::start(None, None, || true, now()).unwrap();
        let http = with_call(
            &trace,
            "HTTP_PROXY",
            "https://pets.internal:8443/pets/{id}",
            Some(503),
            false,
        );
        assert_eq!(http["id"], trace.integration.to_string());
        assert_eq!(trace.header().parent, Some(trace.integration));
        assert!(trace.traceparent().contains(&trace.integration.to_string()));
        assert_eq!(http["name"], "pets.internal");
        assert_eq!(http["namespace"], "remote");
        assert_eq!(http["start_time"], 1_700_000_000.1);
        assert_eq!(http["end_time"], 1_700_000_000.8);
        assert_eq!(http["http"]["request"]["method"], "POST");
        assert_eq!(
            http["http"]["request"]["url"],
            "https://pets.internal:8443/pets/{id}"
        );
        assert_eq!(http["http"]["response"]["status"], 503);
        assert_eq!(http["fault"], true);

        let lambda = with_call(
            &trace,
            "AWS_PROXY",
            "arn:aws:lambda:eu-west-1:123456789012:function:pets",
            Some(200),
            false,
        );
        assert_eq!(lambda["name"], "Lambda");
        assert_eq!(lambda["namespace"], "aws");
        assert_eq!(lambda["aws"]["operation"], "Invoke");
        assert_eq!(lambda["aws"]["region"], "eu-west-1");
        assert!(lambda.get("fault").is_none() && lambda.get("error").is_none());

        let sqs = with_call(
            &trace,
            "AWS",
            "arn:aws:apigateway:us-east-1:sqs:path/1/queue",
            Some(429),
            false,
        );
        assert_eq!(sqs["name"], "sqs");
        assert_eq!(sqs["throttle"], true);
        let subtype = with_call(&trace, "AWS_PROXY", "SQS-SendMessage", None, true);
        assert_eq!(subtype["name"], "SQS");
        assert_eq!(subtype["fault"], true, "a call that failed is a fault");
    }

    #[test]
    fn passive_mode_continues_only_traces_the_caller_sampled() {
        let sampled = format!("Root={ROOT};Parent={PARENT};Sampled=1");
        let trace = Trace::continue_sampled(Some(&sampled), None, now()).unwrap();
        assert!(trace.is_sampled());
        assert_eq!(trace.id().to_string(), ROOT);
        assert_eq!(trace.parent.unwrap().to_string(), PARENT);
        let w3c = "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01";
        assert!(Trace::continue_sampled(None, Some(w3c), now()).is_some());
        for (x_amzn, traceparent) in [
            (None, None),
            (Some(format!("Root={ROOT};Sampled=0")), None),
            (Some(format!("Root={ROOT}")), None),
            (Some(format!("Root={ROOT};Sampled=0")), Some(w3c.to_owned())),
            (
                None,
                Some("00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-00".to_owned()),
            ),
        ] {
            assert!(
                Trace::continue_sampled(x_amzn.as_deref(), traceparent.as_deref(), now()).is_none(),
                "{x_amzn:?} {traceparent:?}"
            );
        }
    }

    #[test]
    fn segment_names_are_restricted_to_what_x_ray_accepts() {
        assert_eq!(Trace::segment_name("Pets API/prod"), "Pets API/prod");
        assert_eq!(Trace::segment_name("a{b}\"c\u{1f600}"), "a_b__c_");
        assert_eq!(Trace::segment_name(&"x".repeat(500)).len(), 200);
    }

    proptest! {
        #[test]
        fn parsing_arbitrary_headers_never_panics_and_output_reparses(text in "\\PC{0,80}") {
            let header: TraceHeader = text.parse().unwrap();
            let rendered = header.to_string();
            prop_assert_eq!(rendered.parse::<TraceHeader>().unwrap(), header);
            prop_assert!(text.parse::<TraceParent>().is_ok() || text.parse::<TraceParent>().is_err());
            prop_assert!(text.parse::<TraceId>().is_ok() || text.parse::<TraceId>().is_err());
        }

        #[test]
        fn generated_trace_ids_parse_back(seconds in 0_i64..4_000_000_000) {
            let id = TraceId::generate(jiff::Timestamp::from_second(seconds).unwrap()).unwrap();
            prop_assert_eq!(id.to_string().parse::<TraceId>().unwrap(), id);
            prop_assert_eq!(TraceId::from_w3c(&id.w3c()).unwrap(), id);
        }
    }
}
