//! The integration response of a non-proxy integration: which response
//! `selectionPattern` selects, how it maps headers, status, and body, and how
//! the method response check applies.

use std::collections::{BTreeMap, BTreeSet};

use apigw_regex::JavaRegex;
use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;

use crate::gateway::{ApiContext, GatewayError};
use crate::integration::ParamSource;
use crate::mapped::content::{self, DEFAULT_MEDIA_TYPE, MediaType};
use crate::mapped::vtl::{CompiledTemplate, GatewayInput, render};
use crate::model::{ContentHandling, IntegrationResponseSpec, IntegrationSpec};
use crate::pipeline::RequestContext;
use crate::pipeline::context::json_path_text;

/// What a backend answered, before an integration response maps it.
#[derive(Debug, Clone)]
pub(crate) struct BackendReply {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

/// The response side of a non-proxy integration.
#[derive(Debug, Clone)]
pub(crate) struct ResponseSide {
    /// Responses with a `selectionPattern`, in key order.
    patterns: Vec<IntegrationResponse>,
    /// The response used when no pattern matches.
    default: Option<IntegrationResponse>,
    /// The status codes the method declares; empty when the definition declares none.
    method_responses: BTreeSet<u16>,
}

#[derive(Debug, Clone)]
struct IntegrationResponse {
    selection: Selection,
    status: Option<u16>,
    parameters: Vec<(HeaderTarget, ResponseSource)>,
    /// Response templates by lowercase media type.
    templates: BTreeMap<String, CompiledTemplate>,
    content_handling: Option<ContentHandling>,
}

/// How an integration response is selected.
#[derive(Debug, Clone)]
enum Selection {
    /// No pattern: the response used when no other matches.
    Default,
    Pattern(JavaRegex),
    /// A pattern that does not compile never matches.
    Invalid(String),
}

/// `method.response.header.<name>` or `method.response.multivalueheader.<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderTarget(String);

/// The right-hand side of a response parameter mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ResponseSource {
    BackendHeader(String),
    BackendMultiHeader(String),
    Body,
    BodyPath(String),
    Request(ParamSource),
}

impl ResponseSource {
    fn parse(expression: &str) -> Option<Self> {
        if let Some(rest) = expression.strip_prefix("integration.response.") {
            if rest == "body" {
                return Some(Self::Body);
            }
            if let Some(path) = rest.strip_prefix("body.") {
                return Some(Self::BodyPath(path.to_owned()));
            }
            if let Some(name) = rest.strip_prefix("header.") {
                return Some(Self::BackendHeader(name.to_owned()));
            }
            return rest
                .strip_prefix("multivalueheader.")
                .map(|name| Self::BackendMultiHeader(name.to_owned()));
        }
        match ParamSource::parse(expression)? {
            source @ (ParamSource::Literal(_)
            | ParamSource::Context(_)
            | ParamSource::StageVariable(_)) => Some(Self::Request(source)),
            ParamSource::Path(_)
            | ParamSource::Query(_)
            | ParamSource::MultiQuery(_)
            | ParamSource::Header(_)
            | ParamSource::MultiHeader(_)
            | ParamSource::Body
            | ParamSource::BodyPath(_) => None,
        }
    }

    /// The values this source has for `reply`; none when the source is absent.
    fn values(&self, reply: &BackendReply, ctx: &RequestContext) -> Vec<String> {
        match *self {
            Self::BackendHeader(ref name) => reply
                .headers
                .get(name.as_str())
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
                .into_iter()
                .collect(),
            Self::BackendMultiHeader(ref name) => reply
                .headers
                .get_all(name.as_str())
                .iter()
                .filter_map(|value| value.to_str().ok())
                .map(str::to_owned)
                .collect(),
            Self::Body => {
                let text = String::from_utf8_lossy(&reply.body).into_owned();
                if text.is_empty() {
                    Vec::new()
                } else {
                    vec![text]
                }
            }
            Self::BodyPath(ref expression) => {
                json_path_text(&String::from_utf8_lossy(&reply.body), expression)
                    .into_iter()
                    .collect()
            }
            Self::Request(ref source) => source.values(ctx),
        }
    }
}

impl ResponseSide {
    pub(crate) fn compile(spec: &IntegrationSpec) -> Self {
        let mut patterns = Vec::new();
        let mut default = None;
        for (key, response) in &spec.responses {
            let compiled = IntegrationResponse::compile(key, response);
            if matches!(compiled.selection, Selection::Default) {
                default = Some(compiled);
            } else {
                patterns.push(compiled);
            }
        }
        Self {
            patterns,
            default,
            method_responses: spec.method_responses.clone(),
        }
    }

    /// Why a response cannot be selected or rendered, for `/routes`.
    pub(crate) fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for response in self.patterns.iter().chain(&self.default) {
            if let Selection::Invalid(ref reason) = response.selection {
                problems.push(format!("selectionPattern is invalid: {reason}"));
            }
            for (content_type, template) in &response.templates {
                if let Some(reason) = template.problem() {
                    problems.push(format!(
                        "response template for {content_type} is invalid: {reason}"
                    ));
                }
            }
        }
        problems
    }

    /// The first response whose pattern matches `text` (a status code or an
    /// error message), else the default.
    fn select(&self, text: &str) -> Option<&IntegrationResponse> {
        let matched = self.patterns.iter().find(|response| match response.selection {
            Selection::Pattern(ref pattern) => pattern.matches(text).unwrap_or_else(|err| {
                tracing::warn!(%err, pattern = pattern.as_str(), "selectionPattern could not be evaluated");
                false
            }),
            Selection::Default | Selection::Invalid(_) => false,
        });
        matched.or(self.default.as_ref())
    }

    /// Selects the integration response for `reply`, maps it, and builds the
    /// client's response.
    pub(crate) fn finish(
        &self,
        api: &ApiContext,
        ctx: &RequestContext,
        reply: &BackendReply,
    ) -> Result<Response, GatewayError> {
        let selected = self.select(&reply.status.to_string()).ok_or_else(|| {
            tracing::warn!(
                status = reply.status,
                "no integration response matches and none is the default"
            );
            GatewayError::ApiConfiguration
        })?;
        let status = selected.status.ok_or_else(|| {
            tracing::error!("the selected integration response has no statusCode");
            GatewayError::ApiConfiguration
        })?;
        if !self.method_responses.is_empty() && !self.method_responses.contains(&status) {
            tracing::error!(
                status,
                "output mapping refers to an invalid method response"
            );
            return Err(GatewayError::ApiConfiguration);
        }
        selected.build(api, ctx, reply, status)
    }
}

impl IntegrationResponse {
    fn compile(key: &str, spec: &IntegrationResponseSpec) -> Self {
        let selection = if key == "default" || key.is_empty() {
            Selection::Default
        } else {
            match JavaRegex::new(key) {
                Ok(pattern) => Selection::Pattern(pattern),
                Err(err) => Selection::Invalid(err.to_string()),
            }
        };
        let mut parameters = Vec::new();
        for (target, source) in &spec.response_parameters {
            let name = target
                .strip_prefix("method.response.header.")
                .or_else(|| target.strip_prefix("method.response.multivalueheader."));
            let (Some(name), Some(source)) = (name, ResponseSource::parse(source)) else {
                tracing::warn!(
                    target,
                    source,
                    "ignoring unsupported response parameter mapping"
                );
                continue;
            };
            parameters.push((HeaderTarget(name.to_owned()), source));
        }
        let templates = spec
            .response_templates
            .iter()
            .filter_map(|(content_type, source)| {
                let source = source.as_deref()?;
                Some((
                    MediaType::of(content_type).0,
                    CompiledTemplate::compile(source),
                ))
            })
            .collect();
        Self {
            selection,
            status: spec.status(),
            parameters,
            templates,
            content_handling: spec.content_handling,
        }
    }

    /// The template for the client's `Accept` header, falling back to the
    /// `application/json` template.
    fn template_for(&self, accept: Option<&str>) -> Option<&CompiledTemplate> {
        let preferred = accept.into_iter().flat_map(|accept| {
            accept
                .split(',')
                .map(|media_type| MediaType::of(media_type).0)
        });
        for media_type in preferred {
            if let Some(template) = self.templates.get(&media_type) {
                return Some(template);
            }
        }
        self.templates.get(DEFAULT_MEDIA_TYPE)
    }

    fn build(
        &self,
        api: &ApiContext,
        ctx: &RequestContext,
        reply: &BackendReply,
        status: u16,
    ) -> Result<Response, GatewayError> {
        let backend_type = reply
            .headers
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        let payload = api.binary_media_types.payload(backend_type);
        let body =
            content::apply(self.content_handling, reply.body.clone(), payload).map_err(|err| {
                tracing::warn!(%err, "integration response payload could not be converted");
                GatewayError::ApiConfiguration
            })?;
        let mut headers = HeaderMap::new();
        for (target, source) in &self.parameters {
            Self::set_header(&mut headers, target, source.values(reply, ctx));
        }
        let (body, override_status) = match self.template_for(ctx.header_str("accept")) {
            None => (body, None),
            Some(CompiledTemplate::Invalid(reason)) => {
                tracing::error!(reason, "response template is invalid");
                return Err(GatewayError::ApiConfiguration);
            }
            Some(CompiledTemplate::Ready(template)) => {
                let input = GatewayInput::new(String::from_utf8_lossy(&body).into_owned(), ctx);
                let rendered = render(template, &input, ctx).map_err(|err| {
                    tracing::warn!(%err, "response template failed");
                    GatewayError::ApiConfiguration
                })?;
                for (name, value) in rendered.response_headers() {
                    Self::set_header(&mut headers, &HeaderTarget(name), vec![value]);
                }
                let status = rendered.response_status();
                (Bytes::from(rendered.output), status)
            }
        };
        if !headers.contains_key(header::CONTENT_TYPE) {
            headers.insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static(DEFAULT_MEDIA_TYPE),
            );
        }
        let final_status = override_status.unwrap_or(status);
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = StatusCode::from_u16(final_status).map_err(|_| {
            tracing::error!(
                status = final_status,
                "integration response status is not a valid HTTP status"
            );
            GatewayError::ApiConfiguration
        })?;
        *response.headers_mut() = headers;
        Ok(response)
    }

    /// Sets a header from every value the mapping produced, replacing what an
    /// earlier mapping set for the name.
    fn set_header(headers: &mut HeaderMap, target: &HeaderTarget, values: Vec<String>) {
        let Ok(name) = HeaderName::try_from(target.0.as_str()) else {
            tracing::warn!(
                header = target.0,
                "mapped response header has an invalid name"
            );
            return;
        };
        let mut replaced = false;
        for value in values {
            let Ok(value) = HeaderValue::try_from(value) else {
                tracing::warn!(
                    header = target.0,
                    "mapped response header has an invalid value"
                );
                continue;
            };
            if replaced {
                headers.append(name.clone(), value);
            } else {
                headers.insert(name.clone(), value);
                replaced = true;
            }
        }
    }
}
