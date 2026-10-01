//! Where log events are delivered, parsed from the ARNs API Gateway stores in
//! a stage's access log settings.

use std::fmt;
use std::str::FromStr;

/// A CloudWatch Logs log group name.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct LogGroup(String);

impl LogGroup {
    pub(crate) fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    /// The log group API Gateway writes a stage's execution logs to.
    pub(crate) fn execution_logs(api_id: &str, stage: &str) -> Self {
        Self(format!("API-Gateway-Execution-Logs_{api_id}/{stage}"))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LogGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Where a batch of log events goes.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Destination {
    /// A CloudWatch Logs log group, written through this pod's own log stream.
    CloudWatch {
        /// `None` uses the process's default region.
        region: Option<String>,
        group: LogGroup,
        /// Create the log group when it does not exist. API Gateway creates a
        /// stage's execution log group itself, so only that one is created here.
        create_group: bool,
    },
    /// A Firehose delivery stream.
    Firehose {
        region: Option<String>,
        stream: String,
    },
    /// The process's standard output, one event per line.
    Stdout,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0:?} is not a CloudWatch Logs log group ARN or a Firehose delivery stream ARN")]
pub(crate) struct InvalidDestination(String);

impl FromStr for Destination {
    type Err = InvalidDestination;

    /// Parses `arn:aws:logs:{region}:{account}:log-group:{name}[:*]` and
    /// `arn:aws:firehose:{region}:{account}:deliverystream/{name}`.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidDestination(raw.to_owned());
        let mut parts = raw.splitn(6, ':');
        let (
            Some("arn"),
            Some(_partition),
            Some(service),
            Some(region),
            Some(_account),
            Some(rest),
        ) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        )
        else {
            return Err(invalid());
        };
        let region = (!region.is_empty()).then(|| region.to_owned());
        match service {
            "logs" => {
                let name = rest.strip_prefix("log-group:").ok_or_else(invalid)?;
                let name = name.strip_suffix(":*").unwrap_or(name);
                if name.is_empty() {
                    return Err(invalid());
                }
                Ok(Self::CloudWatch {
                    region,
                    group: LogGroup::new(name),
                    create_group: false,
                })
            }
            "firehose" => {
                let stream = rest
                    .strip_prefix("deliverystream/")
                    .filter(|name| !name.is_empty())
                    .ok_or_else(invalid)?;
                Ok(Self::Firehose {
                    region,
                    stream: stream.to_owned(),
                })
            }
            _ => Err(invalid()),
        }
    }
}

/// The log stream this pod writes to in every CloudWatch Logs log group:
/// `{pod name}/{start time}/{random suffix}`, so streams from restarted or
/// concurrent pods never collide and sort by start time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StreamName(String);

impl StreamName {
    /// Uses `override_name` when given. Otherwise the pod name (`HOSTNAME`, which
    /// Kubernetes sets to the pod name) with the start time and a short random
    /// suffix.
    pub(crate) fn for_pod(
        override_name: Option<&str>,
        hostname: Option<&str>,
        started: jiff::Timestamp,
        unique: uuid::Uuid,
    ) -> Self {
        if let Some(name) = override_name {
            return Self(name.to_owned());
        }
        let host = hostname
            .filter(|h| !h.is_empty())
            .unwrap_or("apigw")
            .replace([':', '*'], "-");
        let suffix = unique.simple().to_string();
        let suffix = suffix
            .get(suffix.len().saturating_sub(8)..)
            .unwrap_or_default();
        Self(format!(
            "{host}/{}/{suffix}",
            started.strftime("%Y-%m-%dT%H-%M-%SZ")
        ))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    #[test]
    fn log_group_arns_parse_with_and_without_wildcard_suffix() {
        for arn in [
            "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/apigw/access",
            "arn:aws:logs:eu-west-1:123456789012:log-group:/aws/apigw/access:*",
        ] {
            assert_eq!(
                arn.parse::<Destination>().unwrap(),
                Destination::CloudWatch {
                    region: Some("eu-west-1".to_owned()),
                    group: LogGroup::new("/aws/apigw/access"),
                    create_group: false,
                },
                "{arn}"
            );
        }
    }

    #[test]
    fn firehose_arns_parse() {
        assert_eq!(
            "arn:aws-us-gov:firehose:us-gov-west-1:1:deliverystream/amazon-apigateway-logs"
                .parse::<Destination>()
                .unwrap(),
            Destination::Firehose {
                region: Some("us-gov-west-1".to_owned()),
                stream: "amazon-apigateway-logs".to_owned()
            }
        );
    }

    #[test]
    fn other_arns_are_rejected() {
        for bad in [
            "",
            "my-log-group",
            "arn:aws:s3:::bucket",
            "arn:aws:logs:us-east-1:1:log-group:",
            "arn:aws:logs:us-east-1:1:destination:x",
            "arn:aws:firehose:us-east-1:1:deliverystream/",
            "arn:aws:firehose:us-east-1:1:other/x",
        ] {
            assert!(bad.parse::<Destination>().is_err(), "{bad}");
        }
    }

    #[test]
    fn execution_log_group_follows_api_gateways_naming() {
        assert_eq!(
            LogGroup::execution_logs("abc123", "prod").as_str(),
            "API-Gateway-Execution-Logs_abc123/prod"
        );
    }

    #[test]
    fn stream_names_identify_the_pod_and_never_contain_forbidden_characters() {
        let started = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        let unique = uuid::Uuid::from_u128(0xabcd_ef01);
        let name = StreamName::for_pod(None, Some("apigw-7d9:x*"), started, unique);
        assert_eq!(name.as_str(), "apigw-7d9-x-/2023-11-14T22-13-20Z/abcdef01");
        assert!(!name.as_str().contains([':', '*']));
        assert_eq!(
            StreamName::for_pod(None, None, started, unique).as_str(),
            "apigw/2023-11-14T22-13-20Z/abcdef01"
        );
        assert_eq!(
            StreamName::for_pod(Some("fixed"), Some("h"), started, unique).as_str(),
            "fixed"
        );
    }
}
