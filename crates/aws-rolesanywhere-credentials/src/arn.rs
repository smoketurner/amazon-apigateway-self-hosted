//! Trust anchor and profile ARNs.

use std::fmt;
use std::str::FromStr;

/// Why a string was rejected as a trust anchor or profile ARN.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{arn:?} is not an IAM Roles Anywhere {kind} ARN")]
pub struct ArnError {
    arn: String,
    kind: &'static str,
}

/// The parts of an `arn:{partition}:rolesanywhere:{region}:{account}:{kind}/{id}` ARN that
/// the provider uses.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Arn {
    raw: String,
    partition: String,
    region: String,
}

impl Arn {
    fn parse(raw: &str, kind: &'static str) -> Result<Self, ArnError> {
        let error = || ArnError {
            arn: raw.to_owned(),
            kind,
        };
        let mut parts = raw.splitn(6, ':');
        let (
            Some("arn"),
            Some(partition),
            Some("rolesanywhere"),
            Some(region),
            Some(account),
            Some(resource),
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Err(error());
        };
        let id = resource
            .strip_prefix(kind)
            .and_then(|rest| rest.strip_prefix('/'));
        if partition.is_empty()
            || region.is_empty()
            || account.is_empty()
            || id.is_none_or(str::is_empty)
        {
            return Err(error());
        }
        Ok(Self {
            raw: raw.to_owned(),
            partition: partition.to_owned(),
            region: region.to_owned(),
        })
    }
}

/// The ARN of a Roles Anywhere trust anchor: the CA that issued the certificate.
///
/// The provider signs for the trust anchor's region, as the AWS credential helper does.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TrustAnchorArn(Arn);

impl TrustAnchorArn {
    /// The ARN as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0.raw
    }

    /// The region the trust anchor lives in.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.0.region
    }

    /// The AWS partition, such as `aws` or `aws-cn`.
    #[must_use]
    pub fn partition(&self) -> &str {
        &self.0.partition
    }
}

impl FromStr for TrustAnchorArn {
    type Err = ArnError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Arn::parse(raw, "trust-anchor").map(Self)
    }
}

impl fmt::Display for TrustAnchorArn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The ARN of a Roles Anywhere profile: the roles a session may assume and their limits.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileArn(Arn);

impl ProfileArn {
    /// The ARN as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0.raw
    }

    /// The region the profile lives in.
    #[must_use]
    pub fn region(&self) -> &str {
        &self.0.region
    }
}

impl FromStr for ProfileArn {
    type Err = ArnError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        Arn::parse(raw, "profile").map(Self)
    }
}

impl fmt::Display for ProfileArn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The Roles Anywhere endpoint of a region, or `None` for a partition whose DNS suffix is not
/// known here.
pub(crate) fn default_endpoint(partition: &str, region: &str) -> Option<String> {
    let suffix = match partition {
        "aws" | "aws-us-gov" => "amazonaws.com",
        "aws-cn" => "amazonaws.com.cn",
        _ => return None,
    };
    Some(format!("https://rolesanywhere.{region}.{suffix}"))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    const ANCHOR: &str = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/0a1b2c3d-1111-2222-3333-444455556666";
    const PROFILE: &str =
        "arn:aws:rolesanywhere:us-east-1:123456789012:profile/9f8e7d6c-1111-2222-3333-444455556666";

    #[test]
    fn trust_anchor_and_profile_arns_expose_their_region_and_partition() {
        let anchor: TrustAnchorArn = ANCHOR.parse().unwrap();
        assert_eq!(anchor.as_str(), ANCHOR);
        assert_eq!(anchor.region(), "us-east-1");
        assert_eq!(anchor.partition(), "aws");
        assert_eq!(anchor.to_string(), ANCHOR);
        let profile: ProfileArn = PROFILE.parse().unwrap();
        assert_eq!(profile.as_str(), PROFILE);
        assert_eq!(profile.region(), "us-east-1");
        assert_eq!(profile.to_string(), PROFILE);
        let china: TrustAnchorArn = "arn:aws-cn:rolesanywhere:cn-north-1:1:trust-anchor/a"
            .parse()
            .unwrap();
        assert_eq!(china.partition(), "aws-cn");
        assert_eq!(china.region(), "cn-north-1");
    }

    #[test]
    fn anything_else_is_rejected() {
        for bad in [
            "",
            "arn",
            "arn:aws:rolesanywhere:us-east-1:123456789012",
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/",
            "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor",
            "arn:aws:rolesanywhere:us-east-1:123456789012:profile/x",
            "arn:aws:iam:us-east-1:123456789012:trust-anchor/x",
            "arn::rolesanywhere:us-east-1:123456789012:trust-anchor/x",
            "arn:aws:rolesanywhere::123456789012:trust-anchor/x",
            "arn:aws:rolesanywhere:us-east-1::trust-anchor/x",
            "urn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/x",
        ] {
            let error = bad.parse::<TrustAnchorArn>().unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("{bad:?} is not an IAM Roles Anywhere trust-anchor ARN")
            );
        }
        assert!(ANCHOR.parse::<ProfileArn>().is_err());
    }

    #[test]
    fn known_partitions_have_a_default_endpoint() {
        assert_eq!(
            default_endpoint("aws", "eu-west-1").as_deref(),
            Some("https://rolesanywhere.eu-west-1.amazonaws.com")
        );
        assert_eq!(
            default_endpoint("aws-us-gov", "us-gov-west-1").as_deref(),
            Some("https://rolesanywhere.us-gov-west-1.amazonaws.com")
        );
        assert_eq!(
            default_endpoint("aws-cn", "cn-north-1").as_deref(),
            Some("https://rolesanywhere.cn-north-1.amazonaws.com.cn")
        );
        assert_eq!(default_endpoint("aws-iso", "us-iso-east-1"), None);
    }
}
