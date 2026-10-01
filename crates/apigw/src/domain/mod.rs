//! Custom domain names: which API stage serves a request to a domain.
//!
//! A custom domain maps request paths to API stages in one of two ways, chosen
//! by the domain's routing mode: API mappings (a path prefix such as
//! `orders/v1` per stage) and routing rules (conditions on headers and the base
//! path, evaluated in priority order). Both strip the matched prefix before the
//! request reaches the API, as API Gateway does.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mappings.html>
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-routing-rules.html>

mod rules;
mod runtime;
mod truststore;

use std::fmt;
use std::str::FromStr;

pub(crate) use rules::{RoutingMode, RoutingRule};
pub(crate) use runtime::{DomainRegistry, DomainSummary, DomainSupervisor, Resolution};
#[cfg(test)]
pub(crate) use truststore::Truststore;

/// A custom domain name, lowercase. `*.example.com` matches any single label
/// in front of `example.com`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct DomainName(String);

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error(
    "{0:?} is not a domain name (labels of letters, digits, and hyphens; a leading `*.` for a wildcard)"
)]
pub(crate) struct InvalidDomainName(String);

impl DomainName {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether a request for `host` (no port) is for this domain.
    pub(crate) fn matches(&self, host: &str) -> bool {
        let host = host.to_ascii_lowercase();
        match self.0.strip_prefix("*.") {
            Some(suffix) => host
                .split_once('.')
                .is_some_and(|(label, rest)| !label.is_empty() && rest == suffix),
            None => host == self.0,
        }
    }

    /// The host of a `Host` header: lowercase, without a port.
    pub(crate) fn host_of(authority: &str) -> String {
        let authority = authority.trim();
        let host = match authority.strip_prefix('[') {
            Some(v6) => v6.split_once(']').map_or(v6, |(addr, _)| addr),
            None => authority
                .split_once(':')
                .map_or(authority, |(host, _)| host),
        };
        host.to_ascii_lowercase()
    }
}

impl FromStr for DomainName {
    type Err = InvalidDomainName;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidDomainName(raw.to_owned());
        let name = raw.to_ascii_lowercase();
        let labels = name.strip_prefix("*.").unwrap_or(&name);
        let valid_label = |label: &str| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        };
        if labels.is_empty() || labels.len() > 253 || !labels.split('.').all(valid_label) {
            return Err(invalid());
        }
        Ok(Self(name))
    }
}

impl fmt::Display for DomainName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An API stage a request can be sent to.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct StageRef {
    pub(crate) api_id: String,
    pub(crate) stage: String,
}

impl fmt::Display for StageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.api_id, self.stage)
    }
}

/// The path of an API mapping, without leading or trailing slashes. Empty is
/// the mapping API Gateway writes as `(none)`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct MappingKey(String);

impl MappingKey {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    fn is_multi_level(&self) -> bool {
        self.0.contains('/')
    }
}

impl From<&str> for MappingKey {
    fn from(raw: &str) -> Self {
        if raw == "(none)" {
            return Self(String::new());
        }
        Self(raw.trim_matches('/').to_owned())
    }
}

/// One API mapping of a domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiMapping {
    pub(crate) key: MappingKey,
    pub(crate) target: StageRef,
}

/// A request path with the matched mapping removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Routed {
    pub(crate) target: StageRef,
    /// The path the API sees, starting with `/`.
    pub(crate) path: String,
}

/// All of a domain's API mappings.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ApiMappings(Vec<ApiMapping>);

impl ApiMappings {
    pub(crate) fn new(mut mappings: Vec<ApiMapping>) -> Self {
        mappings.sort_by(|a, b| {
            b.key
                .as_str()
                .len()
                .cmp(&a.key.as_str().len())
                .then_with(|| a.key.cmp(&b.key))
        });
        Self(mappings)
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ApiMapping> {
        self.0.iter()
    }

    /// The mapping that serves `path`, and the path left after removing it.
    ///
    /// With only single-level mappings a request matches the mapping named by
    /// its first path segment, else the empty mapping. When any mapping has
    /// several levels, API Gateway picks the mapping with the longest matching
    /// path prefix, so `/ordersandmore` goes to the `orders` mapping.
    pub(crate) fn select(&self, path: &str) -> Option<Routed> {
        let trimmed = path.trim_start_matches('/');
        let multi_level = self.0.iter().any(|m| m.key.is_multi_level());
        let mapping = self.0.iter().find(|mapping| {
            let key = mapping.key.as_str();
            if key.is_empty() {
                return true;
            }
            if multi_level {
                trimmed.starts_with(key)
            } else {
                let first = trimmed.split('/').next().unwrap_or_default();
                first == key
            }
        })?;
        let rest = trimmed
            .get(mapping.key.as_str().len()..)
            .unwrap_or_default();
        Some(Routed {
            target: mapping.target.clone(),
            path: format!("/{}", rest.trim_start_matches('/')),
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn stage(api: &str) -> StageRef {
        StageRef {
            api_id: api.to_owned(),
            stage: "prod".to_owned(),
        }
    }

    fn mappings(keys: &[(&str, &str)]) -> ApiMappings {
        ApiMappings::new(
            keys.iter()
                .map(|(key, api)| ApiMapping {
                    key: MappingKey::from(*key),
                    target: stage(api),
                })
                .collect(),
        )
    }

    fn route(mappings: &ApiMappings, path: &str) -> Option<(String, String)> {
        mappings.select(path).map(|r| (r.target.api_id, r.path))
    }

    #[test]
    fn domain_names_parse_and_match() {
        let exact: DomainName = "Api.Example.COM".parse().unwrap();
        assert_eq!(exact.as_str(), "api.example.com");
        assert!(exact.matches("API.example.com"));
        assert!(!exact.matches("other.example.com"));
        assert!(!exact.matches("x.api.example.com"));
        let wildcard: DomainName = "*.example.com".parse().unwrap();
        assert!(wildcard.matches("a.example.com"));
        assert!(!wildcard.matches("example.com"));
        assert!(!wildcard.matches("a.b.example.com"));
        assert!(!wildcard.matches(".example.com"));
        for bad in [
            "", "-a.com", "a..com", "a_b.com", "*", "*.", "a b.com", "a.com/x",
        ] {
            assert!(bad.parse::<DomainName>().is_err(), "{bad}");
        }
    }

    #[test]
    fn hosts_lose_their_port_and_case() {
        assert_eq!(
            DomainName::host_of("API.example.com:8443"),
            "api.example.com"
        );
        assert_eq!(DomainName::host_of("api.example.com"), "api.example.com");
        assert_eq!(DomainName::host_of("[::1]:8443"), "::1");
        assert_eq!(DomainName::host_of(""), "");
    }

    #[test]
    fn api_gateways_documented_mapping_examples_route_as_documented() {
        let table = mappings(&[
            ("(none)", "api1"),
            ("orders", "api2"),
            ("orders/v1/items", "api3"),
            ("orders/v2/items", "api4"),
            ("orders/v1/items/categories", "api5"),
        ]);
        let api = |path| route(&table, path).map(|(api, _)| api).unwrap();
        assert_eq!(api("/orders"), "api2");
        assert_eq!(api("/orders/v1/items"), "api3");
        assert_eq!(api("/orders/v2/items"), "api4");
        assert_eq!(api("/orders/v1/items/123"), "api3");
        assert_eq!(api("/orders/v1/items/categories/5"), "api5");
        assert_eq!(api("/customers"), "api1");
        assert_eq!(api("/ordersandmore"), "api2");
    }

    #[test]
    fn single_level_mappings_match_whole_segments() {
        let table = mappings(&[("(none)", "api1"), ("orders", "api2")]);
        assert_eq!(
            route(&table, "/orders/7"),
            Some(("api2".to_owned(), "/7".to_owned()))
        );
        assert_eq!(
            route(&table, "/ordersandmore"),
            Some(("api1".to_owned(), "/ordersandmore".to_owned()))
        );
    }

    #[test]
    fn the_matched_prefix_is_stripped_from_the_path() {
        let table = mappings(&[("orders/shop/5", "api"), ("(none)", "root")]);
        assert_eq!(
            route(&table, "/orders/shop/5/hats"),
            Some(("api".to_owned(), "/hats".to_owned()))
        );
        assert_eq!(
            route(&table, "/orders/shop/5"),
            Some(("api".to_owned(), "/".to_owned()))
        );
        assert_eq!(
            route(&table, "/hats"),
            Some(("root".to_owned(), "/hats".to_owned()))
        );
        assert_eq!(
            route(&table, "/"),
            Some(("root".to_owned(), "/".to_owned()))
        );
    }

    #[test]
    fn without_a_matching_or_empty_mapping_nothing_is_selected() {
        let table = mappings(&[("orders", "api")]);
        assert_eq!(route(&table, "/customers"), None);
        assert_eq!(route(&table, "/"), None);
        assert_eq!(ApiMappings::default().select("/x"), None);
    }

    #[test]
    fn mapping_keys_normalize_slashes() {
        assert_eq!(MappingKey::from("/orders/").as_str(), "orders");
        assert_eq!(MappingKey::from("(none)").as_str(), "");
        assert_eq!(MappingKey::from("").as_str(), "");
    }

    proptest! {
        #[test]
        fn selection_never_panics_and_the_remainder_is_a_path(path in "[ -~]{0,40}") {
            let table = mappings(&[("(none)", "a"), ("x", "b"), ("x/y/z", "c")]);
            if let Some(routed) = table.select(&path) {
                prop_assert!(routed.path.starts_with('/'));
            }
        }

        #[test]
        fn the_longest_matching_prefix_wins(suffix in "[a-z0-9]{0,8}") {
            let table = mappings(&[("(none)", "root"), ("a/b", "ab"), ("a/b/c", "abc")]);
            let routed = table.select(&format!("/a/b/c/{suffix}")).unwrap();
            prop_assert_eq!(routed.target.api_id, "abc");
        }
    }
}
