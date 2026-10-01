//! Where an authorizer reads the caller's credentials from.
//!
//! REST APIs write identity sources as `method.request.header.Authorization`,
//! HTTP APIs as `$request.header.Authorization`; both forms are accepted for
//! headers, query string parameters, `$context` variables, and stage variables.

use std::str::FromStr;

use axum::http::HeaderName;
use serde_json::Value;

use crate::integration::StageVariables;
use crate::pipeline::RequestContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IdentitySource {
    /// A request header; names are case-insensitive.
    Header(HeaderName),
    /// A query string parameter; names are case-sensitive.
    Query(String),
    /// A `$context` variable such as `routeKey` or `identity.sourceIp`.
    Context(String),
    StageVariable(String),
}

#[derive(Debug, Clone, Copy)]
enum SourceKind {
    Header,
    Query,
    Context,
    StageVariable,
}

#[derive(Debug, thiserror::Error)]
#[error("{0:?} is not a supported identity source")]
pub(crate) struct UnsupportedIdentitySource(String);

impl IdentitySource {
    /// The prefixes each kind of source can be written with.
    const PREFIXES: [(&'static str, SourceKind); 8] = [
        ("method.request.header.", SourceKind::Header),
        ("$request.header.", SourceKind::Header),
        ("method.request.querystring.", SourceKind::Query),
        ("$request.querystring.", SourceKind::Query),
        ("context.", SourceKind::Context),
        ("$context.", SourceKind::Context),
        ("stageVariables.", SourceKind::StageVariable),
        ("$stageVariables.", SourceKind::StageVariable),
    ];

    fn named(kind: SourceKind, name: &str) -> Option<Self> {
        match kind {
            SourceKind::Header => HeaderName::from_str(name).ok().map(Self::Header),
            SourceKind::Query => Some(Self::Query(name.to_owned())),
            SourceKind::Context => Some(Self::Context(name.to_owned())),
            SourceKind::StageVariable => Some(Self::StageVariable(name.to_owned())),
        }
    }

    /// The value in this request, if present and not empty.
    fn value(&self, ctx: &RequestContext, stage_variables: &StageVariables) -> Option<String> {
        let value = match *self {
            Self::Header(ref name) => ctx.headers.get(name)?.to_str().ok()?.to_owned(),
            Self::Query(ref name) => ctx
                .query
                .pairs()
                .into_iter()
                .find_map(|(key, value)| (key == *name).then_some(value))?,
            Self::Context(ref path) => {
                let pointer = format!("/{}", path.replace('.', "/"));
                match ctx.variables().pointer(&pointer)? {
                    Value::String(text) => text.clone(),
                    scalar @ (Value::Number(_) | Value::Bool(_)) => scalar.to_string(),
                    Value::Null | Value::Array(_) | Value::Object(_) => return None,
                }
            }
            Self::StageVariable(ref name) => stage_variables.get(name)?.to_owned(),
        };
        (!value.is_empty()).then_some(value)
    }
}

impl FromStr for IdentitySource {
    type Err = UnsupportedIdentitySource;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let raw = raw.trim();
        Self::PREFIXES
            .iter()
            .find_map(|&(prefix, kind)| {
                raw.strip_prefix(prefix)
                    .filter(|name| !name.is_empty())
                    .and_then(|name| Self::named(kind, name))
            })
            .ok_or_else(|| UnsupportedIdentitySource(raw.to_owned()))
    }
}

/// The identity sources of one authorizer, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct IdentitySources(Vec<IdentitySource>);

impl IdentitySources {
    /// Reads the `identitySource` of an authorizer definition: a comma-separated
    /// string, or (HTTP APIs) an array of strings. Absent means none.
    pub(crate) fn from_config(config: Option<&Value>) -> Result<Self, UnsupportedIdentitySource> {
        let sources = match config {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::String(list)) => list
                .split(',')
                .map(str::trim)
                .filter(|part| !part.is_empty())
                .map(str::to_owned)
                .collect(),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| item.as_str().map(str::to_owned).unwrap_or_default())
                .collect(),
            Some(other) => return Err(UnsupportedIdentitySource(other.to_string())),
        };
        sources
            .iter()
            .map(|source| source.parse())
            .collect::<Result<_, _>>()
            .map(Self)
    }

    pub(crate) fn single(source: IdentitySource) -> Self {
        Self(vec![source])
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    /// Every source's value, or `None` when any is missing or empty: API
    /// Gateway then answers 401 without invoking the authorizer.
    pub(crate) fn extract(
        &self,
        ctx: &RequestContext,
        stage_variables: &StageVariables,
    ) -> Option<Vec<String>> {
        self.0
            .iter()
            .map(|source| source.value(ctx, stage_variables))
            .collect()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::http::HeaderValue;
    use serde_json::json;

    use super::*;
    use crate::model::ApiKind;
    use crate::pipeline::context::tests::request;

    fn extract(config: &Value, ctx: &RequestContext) -> Option<Vec<String>> {
        let variables = StageVariables::new([("env".to_owned(), "prod".to_owned())].into());
        IdentitySources::from_config(Some(config))
            .unwrap()
            .extract(ctx, &variables)
    }

    #[test]
    fn both_notations_parse() {
        for (raw, expected) in [
            (
                "method.request.header.Authorization",
                IdentitySource::Header(HeaderName::from_static("authorization")),
            ),
            (
                "$request.header.X-Key",
                IdentitySource::Header(HeaderName::from_static("x-key")),
            ),
            (
                "method.request.querystring.token",
                IdentitySource::Query("token".to_owned()),
            ),
            ("$request.querystring.t", IdentitySource::Query("t".to_owned())),
            ("context.identity.sourceIp", IdentitySource::Context("identity.sourceIp".to_owned())),
            ("$context.routeKey", IdentitySource::Context("routeKey".to_owned())),
            ("stageVariables.env", IdentitySource::StageVariable("env".to_owned())),
            ("$stageVariables.env", IdentitySource::StageVariable("env".to_owned())),
        ] {
            assert_eq!(raw.parse::<IdentitySource>().unwrap(), expected, "{raw}");
        }
    }

    #[test]
    fn unknown_or_empty_sources_are_rejected() {
        for raw in [
            "",
            "Authorization",
            "method.request.header.",
            "method.request.path.id",
            "$request.body.x",
            "method.request.header.bad name",
        ] {
            assert!(raw.parse::<IdentitySource>().is_err(), "{raw:?}");
        }
    }

    #[test]
    fn config_accepts_lists_arrays_and_absence() {
        let from = |v: Option<Value>| IdentitySources::from_config(v.as_ref());
        assert!(from(None).unwrap().is_empty());
        assert!(from(Some(json!(""))).unwrap().is_empty());
        assert_eq!(
            from(Some(json!("method.request.header.A, method.request.querystring.b")))
                .unwrap()
                .0
                .len(),
            2
        );
        assert_eq!(from(Some(json!(["$request.header.A", "$context.routeKey"]))).unwrap().0.len(), 2);
        assert!(from(Some(json!(["$request.header.A", 7]))).is_err());
        assert!(from(Some(json!(7))).is_err());
        assert!(from(Some(json!("bogus"))).is_err());
    }

    #[test]
    fn values_come_from_headers_queries_context_and_stage_variables() {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers
            .insert("authorization", HeaderValue::from_static("Bearer t"));
        let got = extract(
            &json!([
                "$request.header.AUTHORIZATION",
                "$request.querystring.q",
                "$context.resourcePath",
                "$context.identity.sourceIp",
                "$stageVariables.env"
            ]),
            &ctx,
        );
        assert_eq!(
            got.unwrap(),
            ["Bearer t", "1", "/pets/{petId}", "192.0.2.1", "prod"]
        );
    }

    #[test]
    fn any_missing_or_empty_source_fails_the_extraction() {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers
            .insert("authorization", HeaderValue::from_static("x"));
        ctx.headers.insert("empty", HeaderValue::from_static(""));
        assert!(extract(&json!(["$request.header.Authorization"]), &ctx).is_some());
        for missing in [
            "$request.header.Other",
            "$request.header.Empty",
            "$request.querystring.absent",
            "$request.querystring.Q",
            "$context.nonexistent",
            "$context.integration",
            "$stageVariables.nope",
        ] {
            assert!(
                extract(&json!(["$request.header.Authorization", missing]), &ctx).is_none(),
                "{missing}"
            );
        }
    }
}
