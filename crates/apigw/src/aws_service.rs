//! Calls to AWS services made on behalf of integrations: which services API
//! Gateway can call and how their requests are shaped, SigV4 signing with the
//! integration role's credentials, and sending.
//!
//! REST `AWS` integrations name a service and an action or path in their URI
//! (`arn:aws:apigateway:us-east-1:sqs:path/123456789012/queue`,
//! `arn:aws:apigateway:us-east-1:dynamodb:action/PutItem`); HTTP API
//! integration subtypes (`SQS-SendMessage`) name an operation and map its
//! parameters. Both end up as a [`ServiceCall`].
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/integrating-api-with-aws-services.html>

use std::str::FromStr;
use std::time::{Duration, SystemTime};

use aws_sdk_lambda::config::Credentials;
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, header};

use crate::aws::{AwsClients, InvokeError, RoleArn};
use crate::gateway::{GatewayError, MAX_BODY_BYTES};
use crate::mapped::BackendReply;
use crate::proxy::{QueryBuilder, UrlEncoder};

/// How a service takes requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// The query protocol: `Action` and the parameters, form-encoded (SQS, SNS).
    Query,
    /// The JSON protocol: the action in `X-Amz-Target` and a JSON body.
    Json {
        content_type: &'static str,
        target_prefix: &'static str,
    },
    /// REST: the method, path, query string, and body say it all (S3, AppConfig).
    Rest,
}

/// An AWS service API Gateway integrates with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Service {
    /// The name in an integration URI (`arn:aws:apigateway:{region}:{name}:...`).
    pub(crate) name: &'static str,
    endpoint_prefix: &'static str,
    signing_name: &'static str,
    pub(crate) protocol: Protocol,
}

impl Service {
    pub(crate) const SQS: Self = Self::new("sqs", Protocol::Query);
    pub(crate) const SNS: Self = Self::new("sns", Protocol::Query);
    pub(crate) const DYNAMODB: Self = Self::new(
        "dynamodb",
        Protocol::Json {
            content_type: "application/x-amz-json-1.0",
            target_prefix: "DynamoDB_20120810",
        },
    );
    pub(crate) const STATES: Self = Self::new(
        "states",
        Protocol::Json {
            content_type: "application/x-amz-json-1.0",
            target_prefix: "AWSStepFunctions",
        },
    );
    pub(crate) const KINESIS: Self = Self::new(
        "kinesis",
        Protocol::Json {
            content_type: "application/x-amz-json-1.1",
            target_prefix: "Kinesis_20131202",
        },
    );
    pub(crate) const EVENTS: Self = Self::new(
        "events",
        Protocol::Json {
            content_type: "application/x-amz-json-1.1",
            target_prefix: "AWSEvents",
        },
    );
    pub(crate) const S3: Self = Self::new("s3", Protocol::Rest);
    pub(crate) const APPCONFIG: Self = Self::new("appconfig", Protocol::Rest);

    /// Services a REST `AWS` integration can name, besides Lambda.
    const REST_SERVICES: [Self; 7] = [
        Self::SQS,
        Self::SNS,
        Self::DYNAMODB,
        Self::STATES,
        Self::KINESIS,
        Self::EVENTS,
        Self::S3,
    ];

    const fn new(name: &'static str, protocol: Protocol) -> Self {
        Self {
            name,
            endpoint_prefix: name,
            signing_name: name,
            protocol,
        }
    }

    /// The names a REST `AWS` integration URI may use, for error messages.
    pub(crate) fn supported_names() -> String {
        let mut names: Vec<&str> = Self::REST_SERVICES.iter().map(|s| s.name).collect();
        names.push("lambda");
        names.join(", ")
    }

    fn by_name(name: &str) -> Option<Self> {
        Self::REST_SERVICES
            .iter()
            .find(|service| service.name == name)
            .copied()
    }

    /// The service's endpoint host in `region`. Step Functions answers
    /// synchronous executions at its own `sync-states` endpoint.
    fn host(&self, partition: &str, region: &str, action: Option<&str>) -> String {
        let prefix = if self.name == "states" && action == Some("StartSyncExecution") {
            "sync-states"
        } else {
            self.endpoint_prefix
        };
        let suffix = match partition {
            "aws-cn" => "amazonaws.com.cn",
            _ => "amazonaws.com",
        };
        format!("{prefix}.{region}.{suffix}")
    }
}

/// What an integration URI points at inside the service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UriTarget {
    /// `action/PutItem`: an API action.
    Action(String),
    /// `path/123456789012/queue`: a path, which may hold `{placeholders}`.
    Path(String),
}

/// A REST `AWS` integration URI:
/// `arn:{partition}:apigateway:{region}:{service}:{action|path}/{rest}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceUri {
    pub(crate) partition: String,
    pub(crate) region: String,
    pub(crate) service: Service,
    pub(crate) target: UriTarget,
}

impl FromStr for ServiceUri {
    type Err = String;

    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = uri.splitn(6, ':').collect();
        let [
            "arn",
            partition,
            "apigateway",
            region,
            service,
            target,
        ] = parts.as_slice()
        else {
            return Err(format!(
                "{uri:?} is not an AWS service integration URI (arn:aws:apigateway:REGION:SERVICE:action/NAME or path/PATH)"
            ));
        };
        if region.is_empty() {
            return Err(format!("{uri:?} names no region"));
        }
        let service = Service::by_name(service).ok_or_else(|| {
            format!(
                "AWS service {service:?} is not supported (supported: {})",
                Service::supported_names()
            )
        })?;
        let target = match target.split_once('/') {
            Some(("action", action)) if !action.is_empty() => UriTarget::Action(action.to_owned()),
            Some(("path", path)) if !path.is_empty() => UriTarget::Path(path.to_owned()),
            Some(_) | None => {
                return Err(format!(
                    "{uri:?} must end in action/NAME or path/PATH, not {target:?}"
                ));
            }
        };
        if service.protocol_needs_action() && matches!(target, UriTarget::Path(_)) {
            return Err(format!(
                "{} integrations take an action (action/NAME), not a path",
                service.name
            ));
        }
        Ok(Self {
            partition: (*partition).to_owned(),
            region: (*region).to_owned(),
            service,
            target,
        })
    }
}

impl Service {
    /// Whether the service identifies the operation by an action only. JSON
    /// services have no paths.
    fn protocol_needs_action(&self) -> bool {
        matches!(self.protocol, Protocol::Json { .. })
    }
}

/// A request to an AWS service, before it is turned into an HTTP request.
#[derive(Debug, Clone)]
pub(crate) struct ServiceCall {
    pub(crate) service: Service,
    pub(crate) partition: String,
    pub(crate) region: String,
    pub(crate) method: Method,
    /// The path as it goes on the wire: percent-encoded, starting with `/`.
    pub(crate) path: String,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
    pub(crate) action: Option<String>,
}

/// Why a call to an AWS service could not be made or did not complete.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ServiceError {
    #[error("the request could not be built: {0}")]
    Request(String),
    #[error("could not get credentials: {0}")]
    Credentials(InvokeError),
    #[error("the request could not be signed: {0}")]
    Signing(String),
    #[error("the service timed out")]
    Timeout,
    #[error("the service could not be reached: {0}")]
    Unreachable(String),
    #[error("the response could not be read: {0}")]
    Response(String),
}

impl From<&ServiceError> for GatewayError {
    fn from(error: &ServiceError) -> Self {
        match *error {
            ServiceError::Request(_)
            | ServiceError::Credentials(InvokeError::AssumeRole { .. } | InvokeError::Credentials(_)) => {
                Self::ApiConfiguration
            }
            ServiceError::Timeout => Self::IntegrationTimeout,
            ServiceError::Unreachable(_) => Self::IntegrationUnreachable,
            ServiceError::Credentials(_) | ServiceError::Signing(_) | ServiceError::Response(_) => {
                Self::IntegrationFailure
            }
        }
    }
}

/// An HTTP request ready to send.
struct Prepared {
    url: reqwest::Url,
    headers: HeaderMap,
}

impl ServiceCall {
    /// Calls the service, signing with `role`'s credentials (or the gateway's)
    /// and reading the whole response.
    ///
    /// # Errors
    ///
    /// Fails when the request cannot be built or signed, credentials cannot be
    /// had, or the service cannot be reached in time.
    pub(crate) async fn execute(
        self,
        aws: &AwsClients,
        http: &reqwest::Client,
        role: Option<&RoleArn>,
        timeout: Duration,
    ) -> Result<BackendReply, ServiceError> {
        let credentials = aws
            .credentials(role)
            .await
            .map_err(ServiceError::Credentials)?;
        let now = SystemTime::from(jiff::Timestamp::now());
        let method = self.method.clone();
        let body = self.body.clone();
        let prepared = self.prepare(aws, &credentials, now)?;
        let response = http
            .request(method, prepared.url)
            .headers(prepared.headers)
            .body(body)
            .timeout(timeout)
            .send()
            .await
            .map_err(|err| {
                if err.is_timeout() {
                    ServiceError::Timeout
                } else {
                    ServiceError::Unreachable(err.to_string())
                }
            })?;
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(|err| {
            if err.is_timeout() {
                ServiceError::Timeout
            } else {
                ServiceError::Response(err.to_string())
            }
        })?;
        if body.len() > MAX_BODY_BYTES {
            return Err(ServiceError::Response(format!(
                "{} bytes is more than the {MAX_BODY_BYTES} byte limit",
                body.len()
            )));
        }
        Ok(BackendReply::new(status, headers, body))
    }

    /// Shapes the request for the service's protocol, builds the URL, and signs.
    fn prepare(
        mut self,
        aws: &AwsClients,
        credentials: &Credentials,
        now: SystemTime,
    ) -> Result<Prepared, ServiceError> {
        self.apply_protocol()?;
        let url = self.url(aws.service_endpoint(self.service.name))?;
        let signature = self.sign(&url, credentials, now)?;
        let mut headers = self.headers;
        for (name, value) in signature {
            let name = HeaderName::try_from(name.as_str())
                .map_err(|err| ServiceError::Signing(err.to_string()))?;
            let value = HeaderValue::try_from(value)
                .map_err(|err| ServiceError::Signing(err.to_string()))?;
            headers.insert(name, value);
        }
        Ok(Prepared { url, headers })
    }

    /// Adds what the protocol needs: the `Action` of a query-protocol call, the
    /// target and content type of a JSON-protocol call.
    fn apply_protocol(&mut self) -> Result<(), ServiceError> {
        match self.service.protocol {
            Protocol::Query => {
                if let Some(ref action) = self.action {
                    self.query.push(("Action".to_owned(), action.clone()));
                }
            }
            Protocol::Json {
                content_type,
                target_prefix,
            } => {
                let action = self.action.as_deref().ok_or_else(|| {
                    ServiceError::Request(format!("{} calls need an action", self.service.name))
                })?;
                let target = HeaderValue::try_from(format!("{target_prefix}.{action}"))
                    .map_err(|err| ServiceError::Request(err.to_string()))?;
                self.headers
                    .insert(HeaderName::from_static("x-amz-target"), target);
                self.headers
                    .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            }
            Protocol::Rest => {}
        }
        Ok(())
    }

    /// The service's URL, or the `--aws-endpoint` override's host with the
    /// request's path after the override's own path.
    fn url(&self, endpoint: Option<&reqwest::Url>) -> Result<reqwest::Url, ServiceError> {
        let mut query = QueryBuilder::default();
        for (name, value) in &self.query {
            let mut pair = String::new();
            UrlEncoder(&mut pair).component(name);
            pair.push('=');
            UrlEncoder(&mut pair).component(value);
            query.append(&pair);
        }
        let origin = match endpoint {
            Some(base) => base.as_str().trim_end_matches('/').to_owned(),
            None => format!(
                "https://{}",
                self.service
                    .host(&self.partition, &self.region, self.action.as_deref())
            ),
        };
        let mut url = reqwest::Url::parse(&format!("{origin}{}", self.path))
            .map_err(|err| ServiceError::Request(err.to_string()))?;
        url.set_query((!query.is_empty()).then(|| query.as_str()));
        Ok(url)
    }

    /// The headers a SigV4 signature adds (`Authorization`, `X-Amz-Date`, and
    /// the session token) for this request.
    fn sign(
        &self,
        url: &reqwest::Url,
        credentials: &Credentials,
        now: SystemTime,
    ) -> Result<Vec<(String, String)>, ServiceError> {
        let mut settings = SigningSettings::default();
        if self.service.name == "s3" {
            settings.percent_encoding_mode = PercentEncodingMode::Single;
            settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
            settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
        }
        let identity = credentials.clone().into();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(&self.region)
            .name(self.service.signing_name)
            .time(now)
            .settings(settings)
            .build()
            .map_err(|err| ServiceError::Signing(err.to_string()))?
            .into();
        let authority = match (url.host_str(), url.port()) {
            (Some(host), Some(port)) => format!("{host}:{port}"),
            (Some(host), None) => host.to_owned(),
            (None, _) => return Err(ServiceError::Request("the URL has no host".to_owned())),
        };
        let mut signed: Vec<(&str, &str)> = vec![("host", authority.as_str())];
        for (name, value) in &self.headers {
            if let Ok(value) = value.to_str() {
                signed.push((name.as_str(), value));
            }
        }
        let request = SignableRequest::new(
            self.method.as_str(),
            url.as_str(),
            signed.into_iter(),
            SignableBody::Bytes(&self.body),
        )
        .map_err(|err| ServiceError::Signing(err.to_string()))?;
        let (instructions, _) = sign(request, &params)
            .map_err(|err| ServiceError::Signing(err.to_string()))?
            .into_parts();
        Ok(instructions
            .headers()
            .map(|(name, value)| (name.to_owned(), value.to_owned()))
            .collect())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    #[test]
    fn service_uris_split_region_service_and_target() {
        let uri: ServiceUri = "arn:aws:apigateway:us-east-1:sqs:path/123456789012/orders"
            .parse()
            .unwrap();
        assert_eq!(uri.region, "us-east-1");
        assert_eq!(uri.service, Service::SQS);
        assert_eq!(
            uri.target,
            UriTarget::Path("123456789012/orders".to_owned())
        );
        let action: ServiceUri = "arn:aws-cn:apigateway:cn-north-1:dynamodb:action/PutItem"
            .parse()
            .unwrap();
        assert_eq!(action.partition, "aws-cn");
        assert_eq!(action.target, UriTarget::Action("PutItem".to_owned()));
    }

    #[test]
    fn unusable_service_uris_say_why() {
        for (uri, reason) in [
            ("https://sqs.us-east-1.amazonaws.com/", "not an AWS service integration URI"),
            ("arn:aws:apigateway:us-east-1:ses:action/SendEmail", "not supported"),
            ("arn:aws:apigateway::sqs:action/SendMessage", "no region"),
            ("arn:aws:apigateway:us-east-1:sqs:queue/q", "must end in"),
            ("arn:aws:apigateway:us-east-1:sqs:action/", "must end in"),
            ("arn:aws:apigateway:us-east-1:dynamodb:path/x", "take an action"),
        ] {
            let err = uri.parse::<ServiceUri>().unwrap_err();
            assert!(err.contains(reason), "{uri}: {err}");
        }
    }

    #[test]
    fn hosts_follow_the_partition_and_step_functions_sync_endpoint() {
        assert_eq!(
            Service::SQS.host("aws", "eu-west-1", None),
            "sqs.eu-west-1.amazonaws.com"
        );
        assert_eq!(
            Service::SQS.host("aws-cn", "cn-north-1", None),
            "sqs.cn-north-1.amazonaws.com.cn"
        );
        assert_eq!(
            Service::STATES.host("aws", "us-east-1", Some("StartSyncExecution")),
            "sync-states.us-east-1.amazonaws.com"
        );
        assert_eq!(
            Service::STATES.host("aws", "us-east-1", Some("StartExecution")),
            "states.us-east-1.amazonaws.com"
        );
    }
}
