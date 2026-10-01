//! Rendering mapping templates against a request: the `$input`, `$context`, and
//! `$stageVariables` objects API Gateway gives them, and what a template leaves
//! behind in `$context.requestOverride` and `$context.responseOverride`.

use std::collections::BTreeMap;

use apigw_vtl::{
    InputParams, Limits, Map, RenderError, Renderer, Template, TemplateInput, Value as VtlValue,
};

use crate::integration::StageVariables;
use crate::pipeline::RequestContext;

/// What `$input` reads: a body (the request's, or the integration response's)
/// and the method request's parameters.
#[derive(Debug, Clone)]
pub(crate) struct GatewayInput {
    body: String,
    params: InputParams,
}

impl GatewayInput {
    pub(crate) fn new(body: String, ctx: &RequestContext) -> Self {
        Self {
            body,
            params: Self::params_of(ctx),
        }
    }

    /// `$input.params()`: path parameters, query string parameters (the last
    /// value of a repeated one), and headers in the client's spelling.
    fn params_of(ctx: &RequestContext) -> InputParams {
        let path = Map::new();
        for (name, value) in &ctx.path_params {
            path.insert(name.as_str(), VtlValue::string(value.as_str()));
        }
        let querystring = Map::new();
        for (name, value) in ctx.query.pairs() {
            querystring.insert(name, VtlValue::string(value));
        }
        let header = Map::new();
        for name in ctx.headers.keys() {
            let values: Vec<&str> = ctx
                .headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            let spelling = ctx.header_case.spelling(name.as_str());
            header.insert(spelling, VtlValue::string(values.join(",")));
        }
        InputParams {
            path,
            querystring,
            header,
        }
    }
}

impl TemplateInput for GatewayInput {
    fn body(&self) -> &str {
        &self.body
    }

    fn params(&self) -> &InputParams {
        &self.params
    }
}

/// A parsed mapping template, or why it did not parse.
#[derive(Debug, Clone)]
pub(crate) enum CompiledTemplate {
    Ready(Template),
    Invalid(String),
}

impl CompiledTemplate {
    pub(crate) fn compile(source: &str) -> Self {
        match Template::parse(source) {
            Ok(template) => Self::Ready(template),
            Err(err) => Self::Invalid(err.to_string()),
        }
    }

    pub(crate) fn problem(&self) -> Option<&str> {
        match self {
            Self::Ready(_) => None,
            Self::Invalid(reason) => Some(reason),
        }
    }
}

/// What a render produced: the output and the `$context` map after the
/// template ran, which holds the overrides it set.
#[derive(Debug)]
pub(crate) struct Rendered {
    pub(crate) output: String,
    context: Map,
}

impl Rendered {
    /// `$context.requestOverride.{path,querystring,header}`.
    pub(crate) fn request_overrides(&self) -> RequestOverrides {
        let group = |name: &str| self.override_group("requestOverride", name);
        RequestOverrides {
            path: group("path"),
            query: group("querystring"),
            header: group("header"),
        }
    }

    /// `$context.responseOverride.status`.
    pub(crate) fn response_status(&self) -> Option<u16> {
        let Some(VtlValue::Map(overrides)) = self.context.get("responseOverride") else {
            return None;
        };
        let status = overrides.get("status")?;
        status.to_java_string().ok()?.trim().parse().ok()
    }

    /// `$context.responseOverride.header`.
    pub(crate) fn response_headers(&self) -> BTreeMap<String, String> {
        self.override_group("responseOverride", "header")
    }

    fn override_group(&self, owner: &str, group: &str) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        let Some(VtlValue::Map(owner)) = self.context.get(owner) else {
            return out;
        };
        let Some(VtlValue::Map(group)) = owner.get(group) else {
            return out;
        };
        for (name, value) in group.entries() {
            if let Ok(text) = value.to_java_string() {
                out.insert(name.to_string(), text);
            }
        }
        out
    }
}

/// What a request template set through `$context.requestOverride`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RequestOverrides {
    pub(crate) path: BTreeMap<String, String>,
    pub(crate) query: BTreeMap<String, String>,
    pub(crate) header: BTreeMap<String, String>,
}

/// Renders `template` against `input` with `$context` and `$stageVariables`
/// taken from the request.
pub(crate) fn render(
    template: &Template,
    input: &GatewayInput,
    ctx: &RequestContext,
) -> Result<Rendered, RenderError> {
    let context = context_map(ctx);
    let output = Renderer::new(input)
        .with_context(context.clone())
        .with_stage_variables(stage_variables_map(&ctx.stage_variables))
        .with_limits(Limits::default())
        .render(template)?;
    Ok(Rendered { output, context })
}

/// `$context`: the request's variables plus empty override maps for the
/// template to fill.
fn context_map(ctx: &RequestContext) -> Map {
    let VtlValue::Map(context) = VtlValue::from(&ctx.variables()) else {
        return Map::new();
    };
    let request_override = Map::new();
    for group in ["header", "querystring", "path"] {
        request_override.insert(group, VtlValue::Map(Map::new()));
    }
    context.insert("requestOverride", VtlValue::Map(request_override));
    let response_override = Map::new();
    response_override.insert("header", VtlValue::Map(Map::new()));
    context.insert("responseOverride", VtlValue::Map(response_override));
    context
}

fn stage_variables_map(variables: &StageVariables) -> Map {
    let map = Map::new();
    for (name, value) in variables {
        map.insert(name.as_str(), VtlValue::string(value.as_str()));
    }
    map
}
