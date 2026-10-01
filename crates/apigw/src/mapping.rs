//! HTTP API parameter mapping: `requestParameters` change the request before
//! it reaches the integration, `responseParameters` (per backend status code)
//! change the response before it reaches the client. See
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-parameter-mapping.html>.
//!
//! Every value is resolved against the request as the client sent it (and the
//! backend response as it came), never against changes made by other mappings,
//! so renaming a header (`append:header.b` from `$request.header.a` plus
//! `remove:header.a`) works whatever the order.

use std::collections::BTreeMap;

use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use serde_json::Value;

use crate::pipeline::RequestContext;
use crate::proxy::{QueryBuilder, UrlEncoder};

/// API Gateway reads at most this much of a body to evaluate a JSON path.
const BODY_JSON_LIMIT: usize = 100 * 1024;

/// What a mapping does to its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Action {
    Append,
    Overwrite,
    Remove,
}

impl Action {
    fn parse(text: &str) -> Option<Self> {
        match text {
            "append" => Some(Self::Append),
            "overwrite" => Some(Self::Overwrite),
            "remove" => Some(Self::Remove),
            _ => None,
        }
    }
}

/// Headers API Gateway does not let a mapping touch.
fn is_reserved(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with("access-control-")
        || name.starts_with("apigw-")
        || name.starts_with("x-amz-")
        || name.starts_with("x-amzn-")
        || matches!(
            name,
            "authorization"
                | "connection"
                | "content-encoding"
                | "content-length"
                | "content-location"
                | "forwarded"
                | "keep-alive"
                | "origin"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "te"
                | "trailers"
                | "transfer-encoding"
                | "upgrade"
                | "x-forwarded-for"
                | "x-forwarded-host"
                | "x-forwarded-proto"
                | "via"
        )
}

/// A JSON path into a body: `.name`, `.a.b`, `.items[0].id`. Recursive descent
/// and filters are not supported, as in API Gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
struct JsonPath(Vec<JsonStep>);

#[derive(Debug, Clone, PartialEq, Eq)]
enum JsonStep {
    Key(String),
    Index(usize),
}

impl JsonPath {
    /// `path` is what follows `body`: empty for the whole body, else `.a.b[0]`.
    fn parse(path: &str) -> Option<Self> {
        let mut steps = Vec::new();
        if path.is_empty() {
            return Some(Self(steps));
        }
        for part in path.strip_prefix('.')?.split('.') {
            let (key, mut indexes) = match part.split_once('[') {
                Some((key, rest)) => (key, Some(rest)),
                None => (part, None),
            };
            if key.is_empty() {
                return None;
            }
            steps.push(JsonStep::Key(key.to_owned()));
            while let Some(rest) = indexes {
                let (index, tail) = rest.split_once(']')?;
                steps.push(JsonStep::Index(index.parse().ok()?));
                indexes = tail.strip_prefix('[');
                if indexes.is_none() && !tail.is_empty() {
                    return None;
                }
            }
        }
        Some(Self(steps))
    }

    /// The selected value as text: strings as they are, other values as JSON.
    /// The whole body is returned as text without parsing it.
    fn select(&self, body: &[u8]) -> Option<String> {
        if self.0.is_empty() {
            return String::from_utf8(body.to_vec()).ok();
        }
        let limited = body.get(..BODY_JSON_LIMIT).unwrap_or(body);
        let document: Value = serde_json::from_slice(limited).ok()?;
        let mut value = &document;
        for step in &self.0 {
            value = match step {
                JsonStep::Key(key) => value.get(key)?,
                JsonStep::Index(index) => value.get(*index)?,
            };
        }
        match value {
            Value::Null => None,
            Value::String(text) => Some(text.clone()),
            Value::Bool(_) | Value::Number(_) | Value::Array(_) | Value::Object(_) => {
                Some(value.to_string())
            }
        }
    }
}

/// Where a mapped value comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Source {
    RequestHeader(String),
    RequestQuery(String),
    RequestPath,
    RequestPathParam(String),
    RequestBody(JsonPath),
    ResponseHeader(String),
    ResponseBody(JsonPath),
    Context(String),
    StageVariable(String),
}

impl Source {
    /// `reference` is the text after `$`, without braces: `request.header.x`.
    fn parse(reference: &str) -> Option<Self> {
        if reference == "request.path" {
            return Some(Self::RequestPath);
        }
        let prefixed = |prefix: &str| reference.strip_prefix(prefix).filter(|s| !s.is_empty());
        if let Some(name) = prefixed("request.header.") {
            return Some(Self::RequestHeader(name.to_owned()));
        }
        if let Some(name) = prefixed("request.querystring.") {
            return Some(Self::RequestQuery(name.to_owned()));
        }
        if let Some(name) = prefixed("request.path.") {
            return Some(Self::RequestPathParam(name.to_owned()));
        }
        if let Some(path) = reference.strip_prefix("request.body") {
            return JsonPath::parse(path).map(Self::RequestBody);
        }
        if let Some(name) = prefixed("response.header.") {
            return Some(Self::ResponseHeader(name.to_owned()));
        }
        if let Some(path) = reference.strip_prefix("response.body") {
            return JsonPath::parse(path).map(Self::ResponseBody);
        }
        if let Some(path) = prefixed("context.") {
            return Some(Self::Context(path.to_owned()));
        }
        prefixed("stageVariables.").map(|name| Self::StageVariable(name.to_owned()))
    }

    fn is_response(&self) -> bool {
        matches!(self, Self::ResponseHeader(_) | Self::ResponseBody(_))
    }

    fn is_request(&self) -> bool {
        matches!(
            self,
            Self::RequestHeader(_)
                | Self::RequestQuery(_)
                | Self::RequestPath
                | Self::RequestPathParam(_)
                | Self::RequestBody(_)
        )
    }

    fn reads_response_body(&self) -> bool {
        matches!(self, Self::ResponseBody(_))
    }

    fn resolve(&self, scope: &Scope<'_>) -> Option<String> {
        let ctx = scope.request;
        match self {
            Self::RequestHeader(name) => Self::join_header(&ctx.headers, name),
            Self::RequestQuery(name) => {
                let values: Vec<String> = ctx
                    .query
                    .pairs()
                    .into_iter()
                    .filter(|(key, _)| key == name)
                    .map(|(_, value)| value)
                    .collect();
                (!values.is_empty()).then(|| values.join(","))
            }
            Self::RequestPath => Some(ctx.path.clone()),
            Self::RequestPathParam(name) => ctx.path_param(name).map(str::to_owned),
            Self::RequestBody(path) => path.select(&ctx.body),
            Self::ResponseHeader(name) => scope
                .response
                .and_then(|response| Self::join_header(response.headers, name)),
            Self::ResponseBody(path) => scope
                .response
                .and_then(|response| response.body)
                .and_then(|body| path.select(body)),
            Self::Context(path) => ctx.context_value(path),
            Self::StageVariable(name) => ctx.stage_variables.get(name).map(str::to_owned),
        }
    }

    /// Repeated headers are combined with commas, as API Gateway does.
    fn join_header(headers: &HeaderMap, name: &str) -> Option<String> {
        let values: Vec<&str> = headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        (!values.is_empty()).then(|| values.join(","))
    }
}

/// The backend response a mapping may read.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ResponseView<'a> {
    pub(crate) headers: &'a HeaderMap,
    pub(crate) body: Option<&'a [u8]>,
}

struct Scope<'a> {
    request: &'a RequestContext,
    response: Option<ResponseView<'a>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Text(String),
    Source(Source),
}

/// The value of a mapping: a constant, one reference (`$request.header.x`),
/// or text with `${...}` references embedded.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MappedValue {
    parts: Vec<Part>,
    /// The whole value is one reference, so a missing source skips the mapping
    /// instead of mapping an empty string.
    single: bool,
}

impl MappedValue {
    /// Splits `raw` into text and references. A reference is `${request.x}`
    /// or a bare `$request.x`, which runs over letters, digits, `_`, `.`, and
    /// `-` (a trailing `.` or `-` is text). Anything that is not a known
    /// reference stays text.
    fn parse(raw: &str) -> Self {
        let mut parts = Vec::new();
        let mut text = String::new();
        let mut rest = raw;
        while let Some(start) = rest.find('$') {
            let (before, dollar_and_after) = rest.split_at(start);
            text.push_str(before);
            let after = dollar_and_after
                .strip_prefix('$')
                .unwrap_or(dollar_and_after);
            let (name, consumed) = Self::reference(after);
            let (written, tail) = after.split_at(consumed);
            if let Some(source) = Source::parse(name) {
                if !text.is_empty() {
                    parts.push(Part::Text(std::mem::take(&mut text)));
                }
                parts.push(Part::Source(source));
            } else {
                text.push('$');
                text.push_str(written);
            }
            rest = tail;
        }
        text.push_str(rest);
        if !text.is_empty() {
            parts.push(Part::Text(text));
        }
        let single = matches!(parts.as_slice(), [Part::Source(_)]);
        Self { parts, single }
    }

    /// The reference at the start of `text` (just after a `$`) and how many
    /// bytes it spans, braces included.
    fn reference(text: &str) -> (&str, usize) {
        if let Some(braced) = text.strip_prefix('{') {
            return match braced.split_once('}') {
                Some((name, _)) => (name, name.len().saturating_add(2)),
                None => ("", 0),
            };
        }
        let end = text
            .char_indices()
            .find(|&(_, c)| {
                !(c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-' | '[' | ']'))
            })
            .map_or(text.len(), |(index, _)| index);
        let name = text.split_at(end).0.trim_end_matches(['.', '-']);
        (name, name.len())
    }

    fn sources(&self) -> impl Iterator<Item = &Source> {
        self.parts.iter().filter_map(|part| match part {
            Part::Source(source) => Some(source),
            Part::Text(_) => None,
        })
    }

    fn resolve(&self, scope: &Scope<'_>) -> Option<String> {
        let mut out = String::new();
        for part in &self.parts {
            match part {
                Part::Text(text) => out.push_str(text),
                Part::Source(source) => match source.resolve(scope) {
                    Some(value) => out.push_str(&value),
                    None if self.single => return None,
                    None => {}
                },
            }
        }
        Some(out)
    }
}

/// The header or query-string name in a mapping key (`header.x-id`).
fn header_name(name: &str) -> Option<HeaderName> {
    let name = HeaderName::try_from(name).ok()?;
    if is_reserved(&name) {
        tracing::warn!(header = %name, "parameter mapping of a reserved header is ignored");
        return None;
    }
    Some(name)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RequestTarget {
    Header(HeaderName),
    Query(String),
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RequestOp {
    action: Action,
    target: RequestTarget,
    value: MappedValue,
}

/// The `requestParameters` of an AWS integration subtype: the service
/// operation's parameter names (`QueueUrl`) and the values mapped to them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServiceParameters(Vec<(String, MappedValue)>);

impl ServiceParameters {
    /// Mappings that read the backend response are skipped with a warning.
    pub(crate) fn compile(parameters: &BTreeMap<String, String>) -> Self {
        let mut compiled = Vec::new();
        for (name, value) in parameters {
            let value = MappedValue::parse(value);
            if value.sources().any(Source::is_response) {
                tracing::warn!(
                    name,
                    "service parameters cannot read the response; ignoring"
                );
                continue;
            }
            compiled.push((name.clone(), value));
        }
        Self(compiled)
    }

    /// The parameters that have a value for this request; one whose single
    /// reference is absent is left out.
    pub(crate) fn resolve(&self, ctx: &RequestContext) -> BTreeMap<String, String> {
        let scope = Scope {
            request: ctx,
            response: None,
        };
        self.0
            .iter()
            .filter_map(|(name, value)| Some((name.clone(), value.resolve(&scope)?)))
            .collect()
    }
}

/// An integration's `requestParameters`, compiled.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RequestMapping(Vec<RequestOp>);

impl RequestMapping {
    /// Keys without an action prefix (`integration.request.*`, the REST form)
    /// are not mappings and are skipped here. Invalid mappings are skipped
    /// with a warning.
    pub(crate) fn compile(parameters: &BTreeMap<String, String>) -> Self {
        let mut ops = Vec::new();
        for (key, value) in parameters {
            let Some((action, target)) = key.split_once(':') else {
                continue;
            };
            let Some(action) = Action::parse(action) else {
                tracing::warn!(
                    key,
                    "ignoring request parameter mapping with an unknown action"
                );
                continue;
            };
            let target = if let Some(name) = target.strip_prefix("header.") {
                header_name(name).map(RequestTarget::Header)
            } else if let Some(name) = target.strip_prefix("querystring.") {
                (!name.is_empty()).then(|| RequestTarget::Query(name.to_owned()))
            } else if target == "path" && action == Action::Overwrite {
                Some(RequestTarget::Path)
            } else {
                None
            };
            let Some(target) = target else {
                tracing::warn!(key, "ignoring unsupported request parameter mapping");
                continue;
            };
            let value = MappedValue::parse(value);
            if value.sources().any(Source::is_response) {
                tracing::warn!(key, "request mappings cannot read the response; ignoring");
                continue;
            }
            ops.push(RequestOp {
                action,
                target,
                value,
            });
        }
        Self(ops)
    }

    /// Applies the mappings to the outgoing headers and URL. Values come from
    /// the client's request in `ctx`.
    pub(crate) fn apply(
        &self,
        ctx: &RequestContext,
        headers: &mut HeaderMap,
        url: &mut reqwest::Url,
    ) {
        let scope = Scope {
            request: ctx,
            response: None,
        };
        let resolved: Vec<Option<String>> =
            self.0.iter().map(|op| op.value.resolve(&scope)).collect();
        for (op, value) in self.0.iter().zip(resolved) {
            match op.target {
                RequestTarget::Header(ref name) => {
                    Self::apply_header(op.action, name, value, headers);
                }
                RequestTarget::Query(ref name) => Self::apply_query(op.action, name, value, url),
                RequestTarget::Path => {
                    if let Some(path) = value {
                        url.set_path(&path);
                    }
                }
            }
        }
    }

    fn apply_header(
        action: Action,
        name: &HeaderName,
        value: Option<String>,
        headers: &mut HeaderMap,
    ) {
        if action == Action::Remove {
            headers.remove(name);
            return;
        }
        let Some(value) = value else {
            return;
        };
        let Ok(value) = HeaderValue::try_from(value) else {
            tracing::warn!(header = %name, "mapped header value is not valid");
            return;
        };
        if action == Action::Append {
            headers.append(name.clone(), value);
        } else {
            headers.insert(name.clone(), value);
        }
    }

    fn apply_query(action: Action, name: &str, value: Option<String>, url: &mut reqwest::Url) {
        let mut encoded_name = String::new();
        UrlEncoder(&mut encoded_name).component(name);
        let mut query = QueryBuilder::default();
        if action != Action::Append {
            for pair in url.query().unwrap_or_default().split('&') {
                let pair_name = pair.split_once('=').map_or(pair, |(name, _)| name);
                if pair_name != encoded_name {
                    query.append(pair);
                }
            }
        } else if let Some(existing) = url.query() {
            query.append(existing);
        }
        if action != Action::Remove
            && let Some(value) = value
        {
            let mut pair = encoded_name;
            pair.push('=');
            UrlEncoder(&mut pair).component(&value);
            query.append(&pair);
        }
        url.set_query((!query.is_empty()).then_some(query.as_str()));
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponseTarget {
    Header(HeaderName),
    StatusCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ResponseOp {
    action: Action,
    target: ResponseTarget,
    value: MappedValue,
}

/// The mappings for one backend status code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct StatusMapping(Vec<ResponseOp>);

impl StatusMapping {
    /// Whether any mapping reads the response body, which then has to be
    /// buffered rather than streamed.
    pub(crate) fn reads_body(&self) -> bool {
        self.0
            .iter()
            .any(|op| op.value.sources().any(Source::reads_response_body))
    }

    /// Applies the mappings to `response`, which carries the backend's status
    /// and headers. `body` is the buffered backend body when [`Self::reads_body`].
    pub(crate) fn apply(
        &self,
        ctx: &RequestContext,
        body: Option<&[u8]>,
        response: &mut axum::response::Response,
    ) {
        let original = response.headers().clone();
        let scope = Scope {
            request: ctx,
            response: Some(ResponseView {
                headers: &original,
                body,
            }),
        };
        let resolved: Vec<Option<String>> =
            self.0.iter().map(|op| op.value.resolve(&scope)).collect();
        for (op, value) in self.0.iter().zip(resolved) {
            match op.target {
                ResponseTarget::Header(ref name) => {
                    RequestMapping::apply_header(op.action, name, value, response.headers_mut());
                }
                ResponseTarget::StatusCode => {
                    let status = value
                        .and_then(|v| v.trim().parse::<u16>().ok())
                        .and_then(|code| StatusCode::from_u16(code).ok());
                    if let Some(status) = status {
                        *response.status_mut() = status;
                    } else {
                        tracing::warn!("ignoring a status code mapping that is not a valid status");
                    }
                }
            }
        }
    }
}

/// An integration's `responseParameters`: mappings by backend status code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ResponseMapping(BTreeMap<u16, StatusMapping>);

impl ResponseMapping {
    pub(crate) fn compile(parameters: &BTreeMap<String, BTreeMap<String, String>>) -> Self {
        let mut by_status = BTreeMap::new();
        for (status, entries) in parameters {
            let Ok(status) = status.parse::<u16>() else {
                tracing::warn!(
                    status,
                    "ignoring response parameters for an invalid status code"
                );
                continue;
            };
            let mut ops = Vec::new();
            for (key, value) in entries {
                if let Some(op) = Self::compile_op(key, value) {
                    ops.push(op);
                }
            }
            if !ops.is_empty() {
                by_status.insert(status, StatusMapping(ops));
            }
        }
        Self(by_status)
    }

    fn compile_op(key: &str, value: &str) -> Option<ResponseOp> {
        let (action, target) = key.split_once(':')?;
        let action = Action::parse(action)?;
        let target = if let Some(name) = target.strip_prefix("header.") {
            header_name(name).map(ResponseTarget::Header)
        } else if target == "statuscode" && action == Action::Overwrite {
            Some(ResponseTarget::StatusCode)
        } else {
            None
        };
        let Some(target) = target else {
            tracing::warn!(key, "ignoring unsupported response parameter mapping");
            return None;
        };
        let value = MappedValue::parse(value);
        if value.sources().any(Source::is_request) {
            tracing::warn!(key, "response mappings cannot read the request; ignoring");
            return None;
        }
        Some(ResponseOp {
            action,
            target,
            value,
        })
    }

    /// The mappings for a backend response with `status`.
    pub(crate) fn for_status(&self, status: StatusCode) -> Option<&StatusMapping> {
        self.0.get(&status.as_u16())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known headers")]
mod tests {
    use axum::body::{Body, Bytes};
    use axum::response::Response;
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;
    use crate::model::ApiKind;
    use crate::pipeline::context::{QueryString, tests::request};

    fn context() -> RequestContext {
        let mut ctx = request(ApiKind::Http);
        ctx.headers
            .insert("x-old", HeaderValue::from_static("old-value"));
        ctx.headers.append("x-multi", HeaderValue::from_static("a"));
        ctx.headers.append("x-multi", HeaderValue::from_static("b"));
        ctx.query = QueryString::new(Some("keep=1&drop=2&drop=3&multi=x&multi=y"));
        ctx.body = Bytes::from_static(br#"{"user":{"id":7,"tags":["a","b"]},"name":"n"}"#);
        ctx
    }

    fn params(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    fn run(pairs: &[(&str, &str)]) -> (HeaderMap, String) {
        let ctx = context();
        let mut headers = HeaderMap::new();
        for (name, value) in &ctx.headers {
            headers.append(name.clone(), value.clone());
        }
        let mut url =
            reqwest::Url::parse("https://backend.example/base?keep=1&drop=2&drop=3").unwrap();
        RequestMapping::compile(&params(pairs)).apply(&ctx, &mut headers, &mut url);
        (headers, url.to_string())
    }

    #[test]
    fn header_mappings_append_overwrite_and_remove() {
        let (headers, _) = run(&[
            ("append:header.x-new", "$context.requestId"),
            ("append:header.x-multi", "c"),
            ("overwrite:header.x-old", "replaced"),
            ("remove:header.user-agent", ""),
        ]);
        assert!(headers.get("x-new").is_some());
        assert_eq!(headers.get_all("x-multi").iter().count(), 3);
        assert_eq!(headers["x-old"], "replaced");
        assert!(headers.get("user-agent").is_none());
    }

    #[test]
    fn renaming_a_header_reads_the_original_request() {
        let (headers, _) = run(&[
            ("append:header.x-renamed", "$request.header.x-old"),
            ("remove:header.x-old", ""),
        ]);
        assert_eq!(headers["x-renamed"], "old-value");
        assert!(headers.get("x-old").is_none());
    }

    #[test]
    fn sources_resolve_from_the_request() {
        let (headers, _) = run(&[
            ("overwrite:header.x-q", "$request.querystring.multi"),
            ("overwrite:header.x-h", "$request.header.x-multi"),
            ("overwrite:header.x-id", "$request.path.petId"),
            ("overwrite:header.x-path", "$request.path"),
            ("overwrite:header.x-body", "$request.body.user.id"),
            ("overwrite:header.x-tag", "$request.body.user.tags[1]"),
            ("overwrite:header.x-obj", "$request.body.user"),
            ("overwrite:header.x-stage", "$context.stage"),
            ("overwrite:header.x-literal", "just text"),
            (
                "overwrite:header.x-braced",
                "${request.path.petId}-${context.stage}!",
            ),
        ]);
        assert_eq!(headers["x-q"], "x,y");
        assert_eq!(headers["x-h"], "a,b");
        assert_eq!(headers["x-id"], "7");
        assert_eq!(headers["x-path"], "/pets/7");
        assert_eq!(headers["x-body"], "7");
        assert_eq!(headers["x-tag"], "b");
        assert_eq!(headers["x-obj"], r#"{"id":7,"tags":["a","b"]}"#);
        assert_eq!(headers["x-stage"], "prod");
        assert_eq!(headers["x-literal"], "just text");
        assert_eq!(headers["x-braced"], "7-prod!");
    }

    #[test]
    fn a_missing_single_source_skips_the_mapping_but_interpolation_uses_empty() {
        let (headers, _) = run(&[
            ("overwrite:header.x-missing", "$request.header.nope"),
            ("overwrite:header.x-partial", "a${request.header.nope}b"),
            ("overwrite:header.x-null", "$request.body.missing"),
        ]);
        assert!(headers.get("x-missing").is_none());
        assert_eq!(headers["x-partial"], "ab");
        assert!(headers.get("x-null").is_none());
    }

    #[test]
    fn query_string_mappings() {
        let (_, url) = run(&[("append:querystring.added", "$context.stage")]);
        assert_eq!(
            url,
            "https://backend.example/base?keep=1&drop=2&drop=3&added=prod"
        );
        let (_, url) = run(&[("overwrite:querystring.drop", "x y")]);
        assert_eq!(url, "https://backend.example/base?keep=1&drop=x%20y");
        let (_, url) = run(&[("remove:querystring.drop", "")]);
        assert_eq!(url, "https://backend.example/base?keep=1");
        let (_, url) = run(&[
            ("remove:querystring.keep", ""),
            ("remove:querystring.drop", ""),
        ]);
        assert_eq!(url, "https://backend.example/base");
    }

    #[test]
    fn path_mapping_replaces_the_path() {
        let (_, url) = run(&[("overwrite:path", "/v2/$request.path.petId")]);
        assert_eq!(url, "https://backend.example/v2/7?keep=1&drop=2&drop=3");
        let (_, url) = run(&[("overwrite:path", "/v2/${request.path.petId}")]);
        assert_eq!(url, "https://backend.example/v2/7?keep=1&drop=2&drop=3");
        let (_, url) = run(&[("overwrite:path", "$request.path")]);
        assert_eq!(url, "https://backend.example/pets/7?keep=1&drop=2&drop=3");
    }

    #[test]
    fn reserved_headers_unsupported_keys_and_wrong_scopes_are_ignored() {
        let mapping = RequestMapping::compile(&params(&[
            ("overwrite:header.authorization", "x"),
            ("append:header.x-amzn-trace-id", "x"),
            ("append:header.Access-Control-Allow-Origin", "x"),
            ("append:path", "/x"),
            ("sing:header.x", "x"),
            ("overwrite:header.x-ok", "$response.header.x"),
            ("integration.request.header.x", "'v'"),
            ("overwrite:header.x-fine", "v"),
        ]));
        assert_eq!(mapping.0.len(), 1);
    }

    #[test]
    fn response_mappings_apply_by_backend_status() {
        let mapping = ResponseMapping::compile(&BTreeMap::from([
            (
                "500".to_owned(),
                params(&[
                    ("append:header.x-req", "$context.requestId"),
                    ("overwrite:statuscode", "403"),
                    ("remove:header.x-backend", ""),
                    (
                        "overwrite:header.x-from-backend",
                        "$response.header.x-backend",
                    ),
                    ("overwrite:header.x-code", "${response.body.code}"),
                ]),
            ),
            (
                "404".to_owned(),
                params(&[("append:header.error", "$stageVariables.env")]),
            ),
            ("nope".to_owned(), params(&[("append:header.a", "b")])),
        ]));
        assert!(mapping.for_status(StatusCode::OK).is_none());
        let ctx = context();
        let mut response = Response::new(Body::empty());
        *response.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
        response
            .headers_mut()
            .insert("x-backend", HeaderValue::from_static("kept?"));
        let status_mapping = mapping
            .for_status(StatusCode::INTERNAL_SERVER_ERROR)
            .unwrap();
        assert!(status_mapping.reads_body());
        status_mapping.apply(&ctx, Some(br#"{"code":"E7"}"#), &mut response);
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert!(response.headers().get("x-backend").is_none());
        assert_eq!(response.headers()["x-from-backend"], "kept?");
        assert_eq!(response.headers()["x-code"], "E7");
        assert!(response.headers().get("x-req").is_some());
        assert!(
            !mapping
                .for_status(StatusCode::NOT_FOUND)
                .unwrap()
                .reads_body()
        );
    }

    #[test]
    fn invalid_status_overrides_leave_the_status() {
        let mapping = ResponseMapping::compile(&BTreeMap::from([(
            "200".to_owned(),
            params(&[("overwrite:statuscode", "teapot")]),
        )]));
        let mut response = Response::new(Body::empty());
        mapping
            .for_status(StatusCode::OK)
            .unwrap()
            .apply(&context(), None, &mut response);
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn json_paths() {
        let path = |p: &str| JsonPath::parse(p);
        assert!(path("").is_some());
        assert!(path(".a.b[0][1]").is_some());
        assert!(path("a").is_none());
        assert!(path(".a[x]").is_none());
        assert!(path(".a[0]x").is_none());
        assert!(path("..a").is_none());
        let body = json!({"a": [[1, 2], [3]], "s": "text", "n": null}).to_string();
        assert_eq!(
            path(".a[0][1]").unwrap().select(body.as_bytes()).as_deref(),
            Some("2")
        );
        assert_eq!(
            path(".s").unwrap().select(body.as_bytes()).as_deref(),
            Some("text")
        );
        assert_eq!(path(".n").unwrap().select(body.as_bytes()), None);
        assert_eq!(path(".a[5]").unwrap().select(body.as_bytes()), None);
        assert_eq!(path(".s").unwrap().select(b"not json"), None);
        assert_eq!(
            path("").unwrap().select(b"raw body").as_deref(),
            Some("raw body")
        );
    }

    proptest! {
        #[test]
        fn value_parsing_and_resolution_never_panic(raw in ".*") {
            let ctx = context();
            let scope = Scope { request: &ctx, response: None };
            drop(MappedValue::parse(&raw).resolve(&scope));
        }

        #[test]
        fn json_path_parsing_never_panics(path in ".*") {
            drop(JsonPath::parse(&path).map(|p| p.select(b"{}")));
        }
    }
}
