//! An integration request's `requestParameters` (the REST `integration.request.*`
//! targets), compiled, and what they contribute to a request to the backend:
//! path placeholder values, query string parameters, and headers.

use std::collections::{BTreeMap, HashSet};

use axum::http::{HeaderMap, HeaderName, HeaderValue};

use crate::integration::ParamSource;
use crate::mapped::RequestOverrides;
use crate::model::ApiKind;
use crate::pipeline::RequestContext;
use crate::proxy::UrlEncoder;

/// The path, query string, and header mappings of an integration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct RequestParameters {
    /// `integration.request.path.<name>`: the value of the URI's `{name}`.
    pub(crate) path: BTreeMap<String, ParamSource>,
    /// `integration.request.querystring.<name>` and the `multivaluequerystring` form.
    pub(crate) query: BTreeMap<String, ParamSource>,
    /// `integration.request.header.<name>` and the `multivalueheader` form.
    pub(crate) headers: BTreeMap<String, ParamSource>,
}

impl RequestParameters {
    /// Compiles `parameters`, skipping (with a warning) mappings this gateway
    /// cannot read. HTTP APIs' `action:target` keys are not REST mappings.
    pub(crate) fn compile(parameters: &BTreeMap<String, String>, kind: ApiKind) -> Self {
        let mut compiled = Self::default();
        for (target, source) in parameters {
            if kind == ApiKind::Http && target.contains(':') {
                continue;
            }
            let Some(source) = ParamSource::parse(source) else {
                tracing::warn!(
                    target,
                    source,
                    "ignoring unsupported request parameter mapping"
                );
                continue;
            };
            if let Some(name) = target.strip_prefix("integration.request.path.") {
                compiled.path.insert(name.to_owned(), source);
            } else if let Some(name) = target
                .strip_prefix("integration.request.querystring.")
                .or_else(|| target.strip_prefix("integration.request.multivaluequerystring."))
            {
                compiled.query.insert(name.to_owned(), source);
            } else if let Some(name) = target
                .strip_prefix("integration.request.header.")
                .or_else(|| target.strip_prefix("integration.request.multivalueheader."))
            {
                compiled.headers.insert(name.to_owned(), source);
            } else {
                tracing::warn!(target, "ignoring unsupported request parameter mapping");
            }
        }
        compiled
    }

    /// The mapped query string parameters, then the ones the request template
    /// set through `$context.requestOverride.querystring`, which replace a
    /// mapped parameter of the same name.
    pub(crate) fn query_pairs(
        &self,
        ctx: &RequestContext,
        overrides: &RequestOverrides,
    ) -> Vec<(String, String)> {
        Self::pairs(&self.query, &overrides.query, ctx)
    }

    /// The mapped headers, then the overridden ones, which replace a mapped
    /// header of the same name.
    pub(crate) fn header_pairs(
        &self,
        ctx: &RequestContext,
        overrides: &RequestOverrides,
    ) -> Vec<(String, String)> {
        Self::pairs(&self.headers, &overrides.header, ctx)
    }

    fn pairs(
        mapped: &BTreeMap<String, ParamSource>,
        overridden: &BTreeMap<String, String>,
        ctx: &RequestContext,
    ) -> Vec<(String, String)> {
        let mut pairs = Vec::new();
        for (name, source) in mapped {
            if overridden.contains_key(name) {
                continue;
            }
            for value in source.values(ctx) {
                pairs.push((name.clone(), value));
            }
        }
        for (name, value) in overridden {
            pairs.push((name.clone(), value.clone()));
        }
        pairs
    }

    /// Inserts the mapped headers into `headers`; repeated names are appended.
    pub(crate) fn add_headers(
        &self,
        headers: &mut HeaderMap,
        ctx: &RequestContext,
        overrides: &RequestOverrides,
    ) {
        let mut first_of_name = HashSet::new();
        for (name, value) in self.header_pairs(ctx, overrides) {
            match (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(value),
            ) {
                (Ok(name), Ok(value)) => {
                    if first_of_name.insert(name.clone()) {
                        headers.insert(name, value);
                    } else {
                        headers.append(name, value);
                    }
                }
                (Err(_), _) | (_, Err(_)) => {
                    tracing::warn!(header = name, "mapped header is not a valid HTTP header");
                }
            }
        }
    }

    /// Fills the `{name}` placeholders of `template` with percent-encoded
    /// values: the request template's path override, the mapped value, or the
    /// method request's path parameter of that name. The value of the greedy
    /// parameter `greedy` keeps its `/`s.
    ///
    /// # Errors
    ///
    /// Fails when a placeholder is unterminated or has no value.
    pub(crate) fn expand(
        &self,
        template: &str,
        ctx: &RequestContext,
        overrides: &RequestOverrides,
        greedy: Option<&str>,
    ) -> Result<String, String> {
        let mut out = String::with_capacity(template.len());
        let mut rest = template;
        while let Some(open) = rest.find('{') {
            let (before, after) = rest.split_at(open);
            out.push_str(before);
            let Some((name, tail)) = after.trim_start_matches('{').split_once('}') else {
                return Err("unterminated placeholder".to_owned());
            };
            let value = match (overrides.path.get(name), self.path.get(name)) {
                (Some(value), _) => Some(value.clone()),
                (None, Some(source)) => source.resolve(ctx),
                (None, None) => ctx.path_param(name).map(str::to_owned),
            };
            let Some(value) = value else {
                return Err(format!("no value for placeholder {{{name}}}"));
            };
            UrlEncoder(&mut out).path_value(&value, greedy == Some(name));
            rest = tail;
        }
        out.push_str(rest);
        Ok(out)
    }
}
