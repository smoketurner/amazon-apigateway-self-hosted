//! Routing rules: conditions on request headers and base path that choose the
//! API stage, evaluated from the lowest priority number up.

use std::collections::BTreeSet;

use axum::http::HeaderMap;

use super::{ApiMappings, Routed, StageRef};

/// How a domain chooses an API stage.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum RoutingMode {
    #[default]
    ApiMappingOnly,
    RoutingRuleOnly,
    RoutingRuleThenApiMapping,
}

impl From<&aws_sdk_apigatewayv2::types::RoutingMode> for RoutingMode {
    fn from(mode: &aws_sdk_apigatewayv2::types::RoutingMode) -> Self {
        use aws_sdk_apigatewayv2::types::RoutingMode as Sdk;
        match mode {
            Sdk::RoutingRuleOnly => Self::RoutingRuleOnly,
            Sdk::RoutingRuleThenApiMapping => Self::RoutingRuleThenApiMapping,
            // Unknown modes fall back to the default, which every domain supports.
            _ => Self::ApiMappingOnly,
        }
    }
}

/// A header value pattern: literal, or with one wildcard at the start, the end,
/// or both. Case sensitive.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ValueGlob {
    Any,
    Exact(String),
    StartsWith(String),
    EndsWith(String),
    Contains(String),
}

impl ValueGlob {
    fn parse(glob: &str) -> Option<Self> {
        if glob == "*" {
            return Some(Self::Any);
        }
        let inner = |text: &str| {
            let text = text.to_owned();
            (!text.contains('*')).then_some(text)
        };
        match (glob.strip_prefix('*'), glob.strip_suffix('*')) {
            (Some(rest), _) if rest.ends_with('*') => {
                inner(rest.strip_suffix('*')?).map(Self::Contains)
            }
            (Some(rest), _) => inner(rest).map(Self::EndsWith),
            (None, Some(rest)) => inner(rest).map(Self::StartsWith),
            (None, None) => inner(glob).map(Self::Exact),
        }
    }

    fn matches(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Exact(text) => value == text,
            Self::StartsWith(text) => value.starts_with(text.as_str()),
            Self::EndsWith(text) => value.ends_with(text.as_str()),
            Self::Contains(text) => value.contains(text.as_str()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeaderMatch {
    /// Lowercase: header names are case insensitive.
    name: String,
    glob: ValueGlob,
}

impl HeaderMatch {
    fn matches(&self, headers: &HeaderMap) -> bool {
        headers
            .get_all(self.name.as_str())
            .iter()
            .any(|v| v.to_str().is_ok_and(|v| self.glob.matches(v)))
    }
}

/// One condition of a rule; a rule matches when all its conditions do.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Condition {
    /// Any of these header matches.
    Headers(Vec<HeaderMatch>),
    /// Any of these base paths (no leading slash).
    BasePaths(Vec<String>),
}

/// A routing rule: where matching requests go and what is stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RoutingRule {
    priority: u32,
    conditions: Vec<Condition>,
    target: StageRef,
    strip_base_path: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum InvalidRule {
    #[error("rule has no priority")]
    NoPriority,
    #[error("rule has no action that invokes an API stage")]
    NoAction,
    #[error("header pattern {0:?} may only have a wildcard at its start or end")]
    BadGlob(String),
}

impl TryFrom<&aws_sdk_apigatewayv2::types::RoutingRule> for RoutingRule {
    type Error = InvalidRule;

    fn try_from(rule: &aws_sdk_apigatewayv2::types::RoutingRule) -> Result<Self, Self::Error> {
        let priority = rule
            .priority()
            .and_then(|p| u32::try_from(p).ok())
            .ok_or(InvalidRule::NoPriority)?;
        let invoke = rule
            .actions()
            .iter()
            .find_map(|a| a.invoke_api())
            .ok_or(InvalidRule::NoAction)?;
        let (Some(api_id), Some(stage)) = (invoke.api_id(), invoke.stage()) else {
            return Err(InvalidRule::NoAction);
        };
        let mut conditions = Vec::new();
        for condition in rule.conditions() {
            if let Some(headers) = condition.match_headers() {
                let mut matches = Vec::new();
                for value in headers.any_of() {
                    let (Some(name), Some(glob)) = (value.header(), value.value_glob()) else {
                        continue;
                    };
                    matches.push(HeaderMatch {
                        name: name.to_ascii_lowercase(),
                        glob: ValueGlob::parse(glob)
                            .ok_or_else(|| InvalidRule::BadGlob(glob.to_owned()))?,
                    });
                }
                conditions.push(Condition::Headers(matches));
            }
            if let Some(paths) = condition.match_base_paths() {
                conditions.push(Condition::BasePaths(
                    paths
                        .any_of()
                        .iter()
                        .map(|p| p.trim_matches('/').to_owned())
                        .collect(),
                ));
            }
        }
        Ok(Self {
            priority,
            conditions,
            target: StageRef {
                api_id: api_id.to_owned(),
                stage: stage.to_owned(),
            },
            strip_base_path: invoke.strip_base_path().unwrap_or(false),
        })
    }
}

impl RoutingRule {
    /// The path left after the matched base path, which is the whole path when
    /// the rule has no base path condition.
    fn matches(&self, path: &str, headers: &HeaderMap) -> Option<String> {
        let trimmed = path.trim_start_matches('/');
        let mut matched_base = None;
        for condition in &self.conditions {
            match condition {
                Condition::Headers(any_of) => {
                    if !any_of.iter().any(|m| m.matches(headers)) {
                        return None;
                    }
                }
                Condition::BasePaths(any_of) => {
                    let base = any_of.iter().find(|base| Self::has_base(trimmed, base))?;
                    matched_base = Some(base.as_str());
                }
            }
        }
        let forwarded = match matched_base.filter(|_| self.strip_base_path) {
            Some(base) => trimmed.get(base.len()..).unwrap_or_default(),
            None => trimmed,
        };
        Some(format!("/{}", forwarded.trim_start_matches('/')))
    }

    fn has_base(path: &str, base: &str) -> bool {
        base.is_empty()
            || path == base
            || path
                .strip_prefix(base)
                .is_some_and(|rest| rest.starts_with('/'))
    }
}

/// A domain's routing configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Routing {
    pub(crate) mode: RoutingMode,
    rules: Vec<RoutingRule>,
    pub(crate) mappings: ApiMappings,
}

impl Routing {
    pub(crate) fn new(
        mode: RoutingMode,
        mut rules: Vec<RoutingRule>,
        mappings: ApiMappings,
    ) -> Self {
        rules.sort_by_key(|rule| rule.priority);
        Self {
            mode,
            rules,
            mappings,
        }
    }

    pub(crate) fn rules(&self) -> &[RoutingRule] {
        &self.rules
    }

    /// Every stage a request could be sent to.
    pub(crate) fn targets(&self) -> BTreeSet<StageRef> {
        let mut targets = BTreeSet::new();
        if self.mode != RoutingMode::RoutingRuleOnly {
            targets.extend(self.mappings.iter().map(|m| m.target.clone()));
        }
        if self.mode != RoutingMode::ApiMappingOnly {
            targets.extend(self.rules.iter().map(|r| r.target.clone()));
        }
        targets
    }

    /// Where a request for `path` with `headers` goes.
    pub(crate) fn select(&self, path: &str, headers: &HeaderMap) -> Option<Routed> {
        let by_rule = || {
            self.rules.iter().find_map(|rule| {
                rule.matches(path, headers).map(|path| Routed {
                    target: rule.target.clone(),
                    path,
                })
            })
        };
        match self.mode {
            RoutingMode::ApiMappingOnly => self.mappings.select(path),
            RoutingMode::RoutingRuleOnly => by_rule(),
            RoutingMode::RoutingRuleThenApiMapping => {
                by_rule().or_else(|| self.mappings.select(path))
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use aws_sdk_apigatewayv2::types as sdk;
    use axum::http::HeaderValue;

    use super::*;
    use crate::domain::{ApiMapping, MappingKey};

    fn rule(
        priority: i32,
        headers: &[(&str, &str)],
        base: Option<&str>,
        api: &str,
        strip: bool,
    ) -> sdk::RoutingRule {
        let mut builder = sdk::RoutingRule::builder().priority(priority).actions(
            sdk::RoutingRuleAction::builder()
                .invoke_api(
                    sdk::RoutingRuleActionInvokeApi::builder()
                        .api_id(api)
                        .stage("prod")
                        .strip_base_path(strip)
                        .build(),
                )
                .build(),
        );
        for (name, glob) in headers {
            builder = builder.conditions(
                sdk::RoutingRuleCondition::builder()
                    .match_headers(
                        sdk::RoutingRuleMatchHeaders::builder()
                            .any_of(
                                sdk::RoutingRuleMatchHeaderValue::builder()
                                    .header(*name)
                                    .value_glob(*glob)
                                    .build(),
                            )
                            .build(),
                    )
                    .build(),
            );
        }
        if let Some(base) = base {
            builder = builder.conditions(
                sdk::RoutingRuleCondition::builder()
                    .match_base_paths(
                        sdk::RoutingRuleMatchBasePaths::builder()
                            .any_of(base)
                            .build(),
                    )
                    .build(),
            );
        }
        builder.build()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn routing(mode: RoutingMode, rules: &[sdk::RoutingRule], mapped: &[(&str, &str)]) -> Routing {
        Routing::new(
            mode,
            rules
                .iter()
                .map(|r| RoutingRule::try_from(r).unwrap())
                .collect(),
            ApiMappings::new(
                mapped
                    .iter()
                    .map(|(key, api)| ApiMapping {
                        key: MappingKey::from(*key),
                        target: StageRef {
                            api_id: (*api).to_owned(),
                            stage: "prod".to_owned(),
                        },
                    })
                    .collect(),
            ),
        )
    }

    fn pick(routing: &Routing, path: &str, h: &[(&str, &str)]) -> Option<(String, String)> {
        routing
            .select(path, &headers(h))
            .map(|r| (r.target.api_id, r.path))
    }

    #[test]
    fn header_globs_follow_the_documented_wildcard_forms() {
        let glob = |g: &str| ValueGlob::parse(g).unwrap();
        assert!(glob("a*").matches("account"));
        assert!(!glob("a*").matches("beta"));
        assert!(glob("*a").matches("beta"));
        assert!(!glob("*a").matches("account"));
        assert!(glob("*a*").matches("backup"));
        assert!(!glob("*a*").matches("users"));
        assert!(glob("*").matches("anything"));
        assert!(glob("World").matches("World"));
        assert!(!glob("World").matches("world"));
        assert_eq!(ValueGlob::parse("a*b"), None);
        assert_eq!(
            ValueGlob::parse("**"),
            Some(ValueGlob::Contains(String::new()))
        );
    }

    #[test]
    fn rules_match_headers_case_insensitively_by_name_and_sensitively_by_value() {
        let routing = routing(
            RoutingMode::RoutingRuleOnly,
            &[rule(10, &[("Hello", "World")], None, "hw", false)],
            &[],
        );
        assert!(pick(&routing, "/x", &[("hello", "World")]).is_some());
        assert!(pick(&routing, "/x", &[("Hello", "world")]).is_none());
        assert!(pick(&routing, "/x", &[]).is_none());
    }

    #[test]
    fn all_conditions_must_hold_and_priority_decides() {
        let routing = routing(
            RoutingMode::RoutingRuleOnly,
            &[
                rule(100, &[], None, "catch-all", false),
                rule(5, &[("x-version", "b*")], Some("users"), "beta-users", true),
                rule(50, &[("x-version", "b*")], None, "beta", false),
            ],
            &[],
        );
        assert_eq!(
            pick(&routing, "/users/7", &[("x-version", "beta")]),
            Some(("beta-users".to_owned(), "/7".to_owned()))
        );
        assert_eq!(
            pick(&routing, "/orders", &[("x-version", "beta")]),
            Some(("beta".to_owned(), "/orders".to_owned()))
        );
        assert_eq!(
            pick(&routing, "/users/7", &[]),
            Some(("catch-all".to_owned(), "/users/7".to_owned()))
        );
    }

    #[test]
    fn base_path_stripping_follows_the_documented_examples() {
        let strip = |s| {
            routing(
                RoutingMode::RoutingRuleOnly,
                &[rule(1, &[], Some("PetStoreShopper"), "pets", s)],
                &[],
            )
        };
        let path = |r: &Routing, p: &str| pick(r, p, &[]).map(|(_, path)| path);
        assert_eq!(
            path(&strip(true), "/PetStoreShopper/dogs"),
            Some("/dogs".to_owned())
        );
        assert_eq!(
            path(&strip(false), "/PetStoreShopper/dogs"),
            Some("/PetStoreShopper/dogs".to_owned())
        );
        assert_eq!(path(&strip(true), "/PetStoreShopper"), Some("/".to_owned()));
        assert_eq!(
            path(&strip(true), "/petstoreshopper/dogs"),
            None,
            "case sensitive"
        );
        assert_eq!(
            path(&strip(true), "/PetStoreShopperX"),
            None,
            "whole segments"
        );
    }

    #[test]
    fn routing_modes_decide_what_is_consulted() {
        let rules = [rule(1, &[("x-beta", "*")], None, "rule", false)];
        let mapped = [("(none)", "mapped")];
        let api = |mode, h: &[(&str, &str)]| {
            pick(&routing(mode, &rules, &mapped), "/p", h).map(|(api, _)| api)
        };
        let beta = [("x-beta", "1")];
        assert_eq!(
            api(RoutingMode::ApiMappingOnly, &beta),
            Some("mapped".to_owned())
        );
        assert_eq!(
            api(RoutingMode::RoutingRuleOnly, &beta),
            Some("rule".to_owned())
        );
        assert_eq!(api(RoutingMode::RoutingRuleOnly, &[]), None);
        assert_eq!(
            api(RoutingMode::RoutingRuleThenApiMapping, &beta),
            Some("rule".to_owned())
        );
        assert_eq!(
            api(RoutingMode::RoutingRuleThenApiMapping, &[]),
            Some("mapped".to_owned())
        );
    }

    #[test]
    fn only_the_consulted_sources_contribute_targets() {
        let rules = [rule(1, &[], None, "rule", false)];
        let mapped = [("a", "mapped")];
        let apis = |mode| -> Vec<String> {
            routing(mode, &rules, &mapped)
                .targets()
                .into_iter()
                .map(|t| t.api_id)
                .collect()
        };
        assert_eq!(apis(RoutingMode::ApiMappingOnly), ["mapped"]);
        assert_eq!(apis(RoutingMode::RoutingRuleOnly), ["rule"]);
        assert_eq!(
            apis(RoutingMode::RoutingRuleThenApiMapping),
            ["mapped", "rule"]
        );
    }

    #[test]
    fn invalid_rules_are_reported() {
        assert_eq!(
            RoutingRule::try_from(&sdk::RoutingRule::builder().build()),
            Err(InvalidRule::NoPriority)
        );
        assert_eq!(
            RoutingRule::try_from(&sdk::RoutingRule::builder().priority(1).build()),
            Err(InvalidRule::NoAction)
        );
        assert_eq!(
            RoutingRule::try_from(&rule(1, &[("h", "a*b")], None, "api", false)),
            Err(InvalidRule::BadGlob("a*b".to_owned()))
        );
    }

    #[test]
    fn sdk_routing_modes_convert() {
        assert_eq!(
            RoutingMode::from(&sdk::RoutingMode::RoutingRuleOnly),
            RoutingMode::RoutingRuleOnly
        );
        assert_eq!(
            RoutingMode::from(&sdk::RoutingMode::RoutingRuleThenApiMapping),
            RoutingMode::RoutingRuleThenApiMapping
        );
        assert_eq!(
            RoutingMode::from(&sdk::RoutingMode::ApiMappingOnly),
            RoutingMode::ApiMappingOnly
        );
    }
}
