//! VPC links: private integrations reach load balancers and Cloud Map services
//! inside a VPC, which are not reachable from outside AWS. `--vpc-link
//! <connectionId>=<url>` maps a VPC link's connection ID to the in-cluster base
//! URL that serves the same backend.
//!
//! Resolving NLB/ALB DNS names or Cloud Map instances automatically is not
//! done: those names and the instance addresses they return are private to the
//! VPC, so resolving them from another network either fails or reaches the
//! wrong place. An explicit mapping cannot.

use std::collections::BTreeMap;
use std::str::FromStr;

/// Why a `--vpc-link` value was rejected.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum InvalidVpcLink {
    #[error("expected CONNECTION_ID=URL, got {0:?}")]
    Shape(String),
    #[error("invalid URL in {0:?}: {1}")]
    Url(String, String),
    #[error("{0} must be an http or https URL with a host, and no query string or fragment")]
    Unsupported(String),
}

/// One `--vpc-link CONNECTION_ID=URL` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VpcLinkTarget {
    connection_id: String,
    base: reqwest::Url,
}

impl FromStr for VpcLinkTarget {
    type Err = InvalidVpcLink;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (connection_id, url) = raw
            .split_once('=')
            .filter(|(id, _)| !id.is_empty())
            .ok_or_else(|| InvalidVpcLink::Shape(raw.to_owned()))?;
        let base = reqwest::Url::parse(url)
            .map_err(|error| InvalidVpcLink::Url(raw.to_owned(), error.to_string()))?;
        let usable = matches!(base.scheme(), "http" | "https")
            && base.has_host()
            && base.query().is_none()
            && base.fragment().is_none();
        if !usable {
            return Err(InvalidVpcLink::Unsupported(url.to_owned()));
        }
        Ok(Self {
            connection_id: connection_id.to_owned(),
            base,
        })
    }
}

/// The configured VPC link mappings, by connection ID.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct VpcLinks(BTreeMap<String, reqwest::Url>);

impl VpcLinks {
    pub(crate) fn new(targets: impl IntoIterator<Item = VpcLinkTarget>) -> Self {
        Self(
            targets
                .into_iter()
                .map(|target| (target.connection_id, target.base))
                .collect(),
        )
    }

    /// The base URL mapped to `connection_id`, without a trailing slash.
    pub(crate) fn base(&self, connection_id: &str) -> Option<String> {
        self.0
            .get(connection_id)
            .map(|url| url.as_str().trim_end_matches('/').to_owned())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    fn links(values: &[&str]) -> VpcLinks {
        VpcLinks::new(values.iter().map(|v| v.parse::<VpcLinkTarget>().unwrap()))
    }

    #[test]
    fn parses_connection_id_and_base_url() {
        let links = links(&[
            "abc123=http://pets.default.svc:8080",
            "def=https://api.internal/base/",
        ]);
        assert_eq!(
            links.base("abc123").as_deref(),
            Some("http://pets.default.svc:8080")
        );
        assert_eq!(
            links.base("def").as_deref(),
            Some("https://api.internal/base")
        );
        assert_eq!(links.base("other"), None);
    }

    #[test]
    fn rejects_malformed_values() {
        let parse = |raw: &str| raw.parse::<VpcLinkTarget>();
        assert!(matches!(parse("nourl"), Err(InvalidVpcLink::Shape(_))));
        assert!(matches!(parse("=http://x"), Err(InvalidVpcLink::Shape(_))));
        assert!(matches!(
            parse("id=not a url"),
            Err(InvalidVpcLink::Url(..))
        ));
        assert!(matches!(
            parse("id=ftp://x"),
            Err(InvalidVpcLink::Unsupported(_))
        ));
        assert!(matches!(
            parse("id=http://x/?q=1"),
            Err(InvalidVpcLink::Unsupported(_))
        ));
        assert!(matches!(
            parse("id=http://x/#f"),
            Err(InvalidVpcLink::Unsupported(_))
        ));
        assert!(matches!(
            parse("id=mailto:a@b"),
            Err(InvalidVpcLink::Unsupported(_))
        ));
    }

    #[test]
    fn later_mappings_for_the_same_id_win() {
        let links = links(&["a=http://first", "a=http://second"]);
        assert_eq!(links.base("a").as_deref(), Some("http://second"));
    }
}
