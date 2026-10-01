//! AWS clients for integrations: per-region Lambda clients, optional
//! credentials assumed from integration roles, and endpoint overrides.
//!
//! In AWS, integrations run with the integration's `credentials` role, which
//! API Gateway assumes on the caller's behalf. Outside AWS the gateway's own
//! identity must assume that role, so its trust policy has to name the gateway's
//! principal (see docs/deployment.md); `--integration-credentials=gateway` uses
//! the gateway's credentials instead.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use aws_sdk_lambda::config::{Credentials, ProvideCredentials as _, Region};
use aws_sdk_lambda::error::DisplayErrorContext;
use aws_sdk_lambda::primitives::Blob;
use aws_sdk_lambda::primitives::event_stream::EventReceiver;
use aws_sdk_lambda::types::InvokeWithResponseStreamResponseEvent;
use aws_sdk_lambda::types::error::InvokeWithResponseStreamResponseEventError;
use axum::body::Bytes;
use serde::Serialize;

/// A Lambda function ARN, optionally qualified with a version or alias:
/// `arn:aws:lambda:{region}:{account}:function:{name}[:{qualifier}]`. A bare
/// function name (`name` or `name:qualifier`) is accepted too and invoked in the
/// default region.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct FunctionArn {
    raw: String,
    scope: Option<ArnScope>,
    name: String,
    qualifier: Option<String>,
}

/// The partition, region, and account of an ARN: the part of an
/// `execute-api` method ARN that does not depend on the request.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct ArnScope {
    pub(crate) partition: String,
    pub(crate) region: String,
    pub(crate) account: String,
}

impl FunctionArn {
    pub(crate) fn as_str(&self) -> &str {
        &self.raw
    }

    pub(crate) fn region(&self) -> Option<&str> {
        self.scope.as_ref().map(|scope| scope.region.as_str())
    }

    /// Where the function lives, unless it was given as a bare name.
    pub(crate) fn scope(&self) -> Option<ArnScope> {
        self.scope.clone()
    }

    /// The account that owns the function, when the ARN says.
    pub(crate) fn account(&self) -> Option<&str> {
        self.scope.as_ref().map(|scope| scope.account.as_str())
    }

    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    /// The version or alias the ARN pins, if any.
    pub(crate) fn qualifier(&self) -> Option<&str> {
        self.qualifier.as_deref()
    }

    /// The names an endpoint override may use for this function, most specific
    /// first: the ARN as written, `name:qualifier`, the ARN without its
    /// qualifier, and the bare name.
    fn override_keys(&self) -> Vec<String> {
        let mut keys = vec![self.raw.clone()];
        if let Some(qualifier) = self.qualifier() {
            keys.push(format!("{}:{qualifier}", self.name()));
            if let Some(unqualified) = self.raw.strip_suffix(&format!(":{qualifier}")) {
                keys.push(unqualified.to_owned());
            }
        }
        keys.push(self.name().to_owned());
        keys
    }
}

impl FromStr for FunctionArn {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = raw.split(':').collect();
        let (scope, name, qualifier) = match parts.as_slice() {
            [
                "arn",
                partition,
                "lambda",
                region,
                account,
                "function",
                name,
                rest @ ..,
            ] if !region.is_empty() && !name.is_empty() && rest.len() <= 1 => (
                Some(ArnScope {
                    partition: (*partition).to_owned(),
                    region: (*region).to_owned(),
                    account: (*account).to_owned(),
                }),
                *name,
                rest.first().copied(),
            ),
            [name] if !name.is_empty() && !raw.contains('/') => (None, *name, None),
            [name, qualifier]
                if !name.is_empty()
                    && *name != "arn"
                    && !qualifier.is_empty()
                    && !raw.contains('/') =>
            {
                (None, *name, Some(*qualifier))
            }
            _ => return Err(format!("{raw:?} is not a Lambda function ARN")),
        };
        if qualifier.is_some_and(str::is_empty) {
            return Err(format!("{raw:?} has an empty qualifier"));
        }
        Ok(Self {
            raw: raw.to_owned(),
            scope,
            name: name.to_owned(),
            qualifier: qualifier.map(str::to_owned),
        })
    }
}

impl fmt::Display for FunctionArn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

/// An IAM role ARN from an integration's or authorizer's `credentials`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub(crate) struct RoleArn(String);

impl RoleArn {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// What an integration's `credentials` field asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum IntegrationCredentials {
    /// Run as this role.
    Role(RoleArn),
    /// `arn:aws:iam::*:user/*`: run as the caller, which needs IAM-authenticated
    /// callers and so cannot work outside AWS.
    Caller,
}

impl FromStr for IntegrationCredentials {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw == "arn:aws:iam::*:user/*" {
            return Ok(Self::Caller);
        }
        let is_role = raw
            .strip_prefix("arn:")
            .and_then(|rest| rest.split_once(":iam::"))
            .is_some_and(|(_, rest)| {
                rest.split_once(":role/")
                    .is_some_and(|(account, name)| !account.is_empty() && !name.is_empty())
            });
        if is_role {
            Ok(Self::Role(RoleArn(raw.to_owned())))
        } else {
            Err(format!("{raw:?} is not an IAM role ARN"))
        }
    }
}

/// Whose credentials integrations use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum CredentialsMode {
    /// Assume the integration's `credentials` role (its trust policy must allow
    /// the gateway's principal).
    Assume,
    /// Ignore integration roles and use the gateway's own credentials.
    Gateway,
}

/// Lambda functions served from a URL speaking Lambda's Invoke protocol (for
/// example the Lambda Runtime Interface Emulator running in-cluster), keyed by
/// function name or ARN.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LambdaEndpoints(BTreeMap<String, reqwest::Url>);

impl LambdaEndpoints {
    fn get(&self, function: &FunctionArn) -> Option<&reqwest::Url> {
        function
            .override_keys()
            .iter()
            .find_map(|key| self.0.get(key))
    }
}

impl FromIterator<(String, reqwest::Url)> for LambdaEndpoints {
    fn from_iter<I: IntoIterator<Item = (String, reqwest::Url)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Parses one `--lambda-endpoint FUNCTION=URL` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LambdaEndpoint(pub(crate) String, pub(crate) reqwest::Url);

impl FromStr for LambdaEndpoint {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (function, url) = raw
            .split_once('=')
            .ok_or_else(|| format!("expected FUNCTION=URL, got {raw:?}"))?;
        if function.is_empty() {
            return Err(format!("expected FUNCTION=URL, got {raw:?}"));
        }
        let url = reqwest::Url::parse(url).map_err(|e| format!("invalid URL in {raw:?}: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("{url} must be an http or https URL"));
        }
        Ok(Self(function.to_owned(), url))
    }
}

/// How Lambda runs an invocation: `X-Amz-Invocation-Type` of a non-proxy Lambda
/// integration, set with an `integration.request.header` mapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum InvocationType {
    /// Wait for the function's result.
    #[default]
    RequestResponse,
    /// Queue the event and answer `202` at once.
    Event,
    /// Validate the request and permissions without running the function.
    DryRun,
}

impl InvocationType {
    pub(crate) const fn header_value(self) -> &'static str {
        match self {
            Self::RequestResponse => "RequestResponse",
            Self::Event => "Event",
            Self::DryRun => "DryRun",
        }
    }

    fn sdk(self) -> aws_sdk_lambda::types::InvocationType {
        match self {
            Self::RequestResponse => aws_sdk_lambda::types::InvocationType::RequestResponse,
            Self::Event => aws_sdk_lambda::types::InvocationType::Event,
            Self::DryRun => aws_sdk_lambda::types::InvocationType::DryRun,
        }
    }
}

impl FromStr for InvocationType {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim() {
            "RequestResponse" => Ok(Self::RequestResponse),
            "Event" => Ok(Self::Event),
            "DryRun" => Ok(Self::DryRun),
            other => Err(format!(
                "{other:?} is not a Lambda invocation type (RequestResponse, Event, or DryRun)"
            )),
        }
    }
}

/// AWS services served from a URL instead of the service's own endpoint, for
/// local emulators and in-cluster mocks, keyed by the service name in the
/// integration URI (`sqs`, `dynamodb`, `states`, ...).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ServiceEndpoints(BTreeMap<String, reqwest::Url>);

impl ServiceEndpoints {
    pub(crate) fn get(&self, service: &str) -> Option<&reqwest::Url> {
        self.0.get(service)
    }
}

impl FromIterator<(String, reqwest::Url)> for ServiceEndpoints {
    fn from_iter<I: IntoIterator<Item = (String, reqwest::Url)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

/// Parses one `--aws-endpoint SERVICE=URL` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServiceEndpoint(pub(crate) String, pub(crate) reqwest::Url);

impl FromStr for ServiceEndpoint {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (service, url) = raw
            .split_once('=')
            .ok_or_else(|| format!("expected SERVICE=URL, got {raw:?}"))?;
        if service.is_empty() {
            return Err(format!("expected SERVICE=URL, got {raw:?}"));
        }
        let url = reqwest::Url::parse(url).map_err(|e| format!("invalid URL in {raw:?}: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("{url} must be an http or https URL"));
        }
        Ok(Self(service.to_owned(), url))
    }
}

/// How the last attempt to assume a role went, for `/routes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", content = "error", rename_all = "snake_case")]
pub(crate) enum RoleStatus {
    Assumed,
    Failed(String),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum InvokeError {
    #[error("Lambda invocation failed: {0}")]
    Aws(String),
    #[error("Lambda endpoint request failed: {0}")]
    Endpoint(String),
    #[error("could not assume {role}: {reason}")]
    AssumeRole { role: String, reason: String },
    #[error("Lambda function failed mid-stream: {0}")]
    FunctionStream(String),
    #[error("could not load AWS credentials: {0}")]
    Credentials(String),
}

/// What a Lambda invocation returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Invocation {
    /// `200` when the function ran, `202` for an `Event` invocation.
    pub(crate) status: u16,
    pub(crate) payload: Vec<u8>,
    /// `Unhandled`/`Handled` when the function raised an error.
    pub(crate) function_error: Option<String>,
}

/// The payload of a streaming invocation (`InvokeWithResponseStream`), read
/// chunk by chunk.
pub(crate) struct ResponseStream(StreamSource);

enum StreamSource {
    Lambda(
        Box<
            EventReceiver<
                InvokeWithResponseStreamResponseEvent,
                InvokeWithResponseStreamResponseEventError,
            >,
        >,
    ),
    Endpoint(reqwest::Response),
}

impl fmt::Debug for ResponseStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ResponseStream")
    }
}

impl ResponseStream {
    /// The next non-empty chunk of the function's output, or `None` once the
    /// function has finished cleanly.
    ///
    /// # Errors
    ///
    /// Fails when the transport breaks or the function reports an error after
    /// it started streaming.
    pub(crate) async fn next_chunk(&mut self) -> Result<Option<Bytes>, InvokeError> {
        match self.0 {
            StreamSource::Lambda(ref mut events) => loop {
                let event = events
                    .recv()
                    .await
                    .map_err(|err| InvokeError::Aws(DisplayErrorContext(err).to_string()))?;
                match event {
                    None => return Ok(None),
                    Some(InvokeWithResponseStreamResponseEvent::PayloadChunk(update)) => {
                        let chunk = update.payload.map(Blob::into_inner).unwrap_or_default();
                        if !chunk.is_empty() {
                            return Ok(Some(Bytes::from(chunk)));
                        }
                    }
                    Some(InvokeWithResponseStreamResponseEvent::InvokeComplete(done)) => {
                        return match done.error_code {
                            Some(code) => Err(InvokeError::FunctionStream(
                                done.error_details.unwrap_or(code),
                            )),
                            None => Ok(None),
                        };
                    }
                    // The union is non-exhaustive; skip events from newer Lambda versions.
                    Some(_) => {}
                }
            },
            StreamSource::Endpoint(ref mut response) => loop {
                let chunk = response
                    .chunk()
                    .await
                    .map_err(|e| InvokeError::Endpoint(e.to_string()))?;
                match chunk {
                    Some(chunk) if chunk.is_empty() => {}
                    other => return Ok(other),
                }
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ClientKey {
    region: Option<String>,
    role: Option<RoleArn>,
}

/// How long credentials with no expiry are reused, and how long before their
/// expiry credentials are replaced.
const CREDENTIALS_REFRESH: Duration = Duration::from_secs(300);

/// Credentials and when they were loaded.
#[derive(Debug, Clone)]
struct CachedCredentials {
    credentials: Credentials,
    loaded: jiff::Timestamp,
}

impl CachedCredentials {
    fn is_fresh(&self, now: jiff::Timestamp) -> bool {
        let refresh = jiff::SignedDuration::try_from(CREDENTIALS_REFRESH).unwrap_or_default();
        let expiry = self
            .credentials
            .expiry()
            .and_then(|expiry| jiff::Timestamp::try_from(expiry).ok());
        match expiry {
            Some(expiry) => now.checked_add(refresh).is_ok_and(|later| later < expiry),
            None => self
                .loaded
                .checked_add(refresh)
                .is_ok_and(|reload| now < reload),
        }
    }
}

/// Shared AWS clients, created lazily per region and role.
pub(crate) struct AwsClients {
    sdk_config: aws_config::SdkConfig,
    credentials_mode: CredentialsMode,
    lambda_endpoints: LambdaEndpoints,
    service_endpoints: ServiceEndpoints,
    http: reqwest::Client,
    lambda: Mutex<HashMap<ClientKey, aws_sdk_lambda::Client>>,
    roles: Mutex<BTreeMap<RoleArn, RoleStatus>>,
    credentials: tokio::sync::Mutex<HashMap<Option<RoleArn>, CachedCredentials>>,
}

impl AwsClients {
    pub(crate) fn new(
        sdk_config: aws_config::SdkConfig,
        credentials_mode: CredentialsMode,
        lambda_endpoints: LambdaEndpoints,
        http: reqwest::Client,
    ) -> Self {
        Self {
            sdk_config,
            credentials_mode,
            lambda_endpoints,
            service_endpoints: ServiceEndpoints::default(),
            http,
            lambda: Mutex::new(HashMap::new()),
            roles: Mutex::new(BTreeMap::new()),
            credentials: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Sends AWS service integrations for the named services to `endpoints`
    /// instead of the services' own endpoints.
    #[must_use]
    pub(crate) fn with_service_endpoints(mut self, endpoints: ServiceEndpoints) -> Self {
        self.service_endpoints = endpoints;
        self
    }

    /// The region the gateway's own configuration names, for calls that do not
    /// say which region they are for.
    pub(crate) fn default_region(&self) -> Option<String> {
        self.sdk_config.region().map(ToString::to_string)
    }

    pub(crate) fn service_endpoint(&self, service: &str) -> Option<&reqwest::Url> {
        self.service_endpoints.get(service)
    }

    /// Credentials to sign a request to an AWS service with: the integration's
    /// role when one applies, else the gateway's own. They are reused until
    /// shortly before they expire.
    ///
    /// # Errors
    ///
    /// Fails when the role cannot be assumed or the gateway has no credentials.
    pub(crate) async fn credentials(
        &self,
        role: Option<&RoleArn>,
    ) -> Result<Credentials, InvokeError> {
        let role = role.filter(|_| self.credentials_mode == CredentialsMode::Assume);
        let mut cache = self.credentials.lock().await;
        let now = jiff::Timestamp::now();
        let key = role.cloned();
        if let Some(cached) = cache.get(&key).filter(|cached| cached.is_fresh(now)) {
            return Ok(cached.credentials.clone());
        }
        let credentials = match role {
            Some(role) => Box::pin(self.assume(role)).await?.1,
            None => self.gateway_credentials().await?,
        };
        cache.insert(
            key,
            CachedCredentials {
                credentials: credentials.clone(),
                loaded: now,
            },
        );
        Ok(credentials)
    }

    async fn gateway_credentials(&self) -> Result<Credentials, InvokeError> {
        let provider = self
            .sdk_config
            .credentials_provider()
            .ok_or_else(|| InvokeError::Credentials("none are configured".to_owned()))?;
        provider
            .provide_credentials()
            .await
            .map_err(|err| InvokeError::Credentials(DisplayErrorContext(err).to_string()))
    }

    /// The outcome of the most recent attempt to assume each role.
    pub(crate) fn role_status(&self) -> BTreeMap<RoleArn, RoleStatus> {
        self.roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Invokes `function` synchronously with `payload`, as the integration's
    /// role when one applies. `trace_header` is forwarded as `X-Amzn-Trace-Id`.
    pub(crate) async fn invoke_lambda(
        &self,
        function: &FunctionArn,
        role: Option<&RoleArn>,
        payload: Vec<u8>,
        trace_header: Option<String>,
    ) -> Result<Invocation, InvokeError> {
        self.invoke_lambda_as(
            function,
            role,
            payload,
            trace_header,
            InvocationType::RequestResponse,
        )
        .await
    }

    /// Invokes `function` the way `invocation_type` says.
    pub(crate) async fn invoke_lambda_as(
        &self,
        function: &FunctionArn,
        role: Option<&RoleArn>,
        payload: Vec<u8>,
        trace_header: Option<String>,
        invocation_type: InvocationType,
    ) -> Result<Invocation, InvokeError> {
        if let Some(url) = self.lambda_endpoints.get(function) {
            return self
                .invoke_endpoint(url, payload, trace_header, invocation_type)
                .await;
        }
        let client = self.lambda_client(function.region(), role).await?;
        let mut call = client
            .invoke()
            .function_name(function.as_str())
            .invocation_type(invocation_type.sdk())
            .payload(Blob::new(payload))
            .customize();
        if let Some(trace) = trace_header {
            call = call.mutate_request(move |request| {
                request
                    .headers_mut()
                    .insert("X-Amzn-Trace-Id", trace.clone());
            });
        }
        let output = call
            .send()
            .await
            .map_err(|err| InvokeError::Aws(DisplayErrorContext(err).to_string()))?;
        Ok(Invocation {
            status: u16::try_from(output.status_code).unwrap_or(200),
            payload: output.payload.map(Blob::into_inner).unwrap_or_default(),
            function_error: output.function_error,
        })
    }

    /// Invokes `function` with `InvokeWithResponseStream`, returning once the
    /// invocation has started; the output is read from the returned stream.
    pub(crate) async fn invoke_lambda_stream(
        &self,
        function: &FunctionArn,
        role: Option<&RoleArn>,
        payload: Vec<u8>,
        trace_header: Option<String>,
    ) -> Result<ResponseStream, InvokeError> {
        if let Some(url) = self.lambda_endpoints.get(function) {
            let response = self.endpoint_response(url, payload, trace_header).await?;
            return Ok(ResponseStream(StreamSource::Endpoint(response)));
        }
        let client = self.lambda_client(function.region(), role).await?;
        let mut call = client
            .invoke_with_response_stream()
            .function_name(function.as_str())
            .payload(Blob::new(payload))
            .customize();
        if let Some(trace) = trace_header {
            call = call.mutate_request(move |request| {
                request
                    .headers_mut()
                    .insert("X-Amzn-Trace-Id", trace.clone());
            });
        }
        let output = call
            .send()
            .await
            .map_err(|err| InvokeError::Aws(DisplayErrorContext(err).to_string()))?;
        Ok(ResponseStream(StreamSource::Lambda(Box::new(
            output.event_stream,
        ))))
    }

    /// Lambda's Invoke protocol over plain HTTP: the response body is the
    /// payload, and `X-Amz-Function-Error` marks a function error.
    async fn invoke_endpoint(
        &self,
        url: &reqwest::Url,
        payload: Vec<u8>,
        trace_header: Option<String>,
        invocation_type: InvocationType,
    ) -> Result<Invocation, InvokeError> {
        let request = self
            .http
            .post(url.clone())
            .header("X-Amz-Invocation-Type", invocation_type.header_value());
        let response = self
            .send_endpoint_request(request, url, payload, trace_header)
            .await?;
        let status = response.status().as_u16();
        let function_error = response
            .headers()
            .get("X-Amz-Function-Error")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let payload = response
            .bytes()
            .await
            .map_err(|e| InvokeError::Endpoint(e.to_string()))?;
        Ok(Invocation {
            status,
            payload: payload.to_vec(),
            function_error,
        })
    }

    async fn endpoint_response(
        &self,
        url: &reqwest::Url,
        payload: Vec<u8>,
        trace_header: Option<String>,
    ) -> Result<reqwest::Response, InvokeError> {
        let request = self.http.post(url.clone());
        self.send_endpoint_request(request, url, payload, trace_header)
            .await
    }

    async fn send_endpoint_request(
        &self,
        request: reqwest::RequestBuilder,
        url: &reqwest::Url,
        payload: Vec<u8>,
        trace_header: Option<String>,
    ) -> Result<reqwest::Response, InvokeError> {
        let mut request = request.body(payload);
        if let Some(trace) = trace_header {
            request = request.header("X-Amzn-Trace-Id", trace);
        }
        let response = request
            .send()
            .await
            .map_err(|e| InvokeError::Endpoint(e.to_string()))?;
        if !response.status().is_success() {
            return Err(InvokeError::Endpoint(format!(
                "{url} answered {}",
                response.status()
            )));
        }
        Ok(response)
    }

    async fn lambda_client(
        &self,
        region: Option<&str>,
        role: Option<&RoleArn>,
    ) -> Result<aws_sdk_lambda::Client, InvokeError> {
        let role = role.filter(|_| self.credentials_mode == CredentialsMode::Assume);
        let key = ClientKey {
            region: region.map(str::to_owned),
            role: role.cloned(),
        };
        if let Some(client) = self
            .lambda
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Ok(client.clone());
        }
        let mut config = aws_sdk_lambda::config::Builder::from(&self.sdk_config);
        if let Some(region) = region {
            config = config.region(Region::new(region.to_owned()));
        }
        if let Some(role) = role {
            config = config.credentials_provider(Box::pin(self.assume(role)).await?.0);
        }
        let client = aws_sdk_lambda::Client::from_conf(config.build());
        self.lambda
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(key, client.clone());
        Ok(client)
    }

    /// Builds a provider for `role` and checks it can fetch credentials, so a
    /// trust-policy problem surfaces on `/routes` instead of as opaque 500s.
    /// Returns the provider and the credentials the check fetched.
    async fn assume(
        &self,
        role: &RoleArn,
    ) -> Result<(aws_config::sts::AssumeRoleProvider, Credentials), InvokeError> {
        const CHECK_TIMEOUT: Duration = Duration::from_secs(10);
        let provider = aws_config::sts::AssumeRoleProvider::builder(role.as_str())
            .session_name("apigw")
            .configure(&self.sdk_config)
            .build()
            .await;
        let check = tokio::time::timeout(CHECK_TIMEOUT, provider.provide_credentials()).await;
        let (status, credentials) = match check {
            Ok(Ok(credentials)) => (RoleStatus::Assumed, Ok(credentials)),
            Ok(Err(err)) => {
                let reason = DisplayErrorContext(err).to_string();
                (RoleStatus::Failed(reason.clone()), Err(reason))
            }
            Err(_) => (
                RoleStatus::Failed("timed out".to_owned()),
                Err("timed out".to_owned()),
            ),
        };
        self.roles
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(role.clone(), status);
        match credentials {
            Ok(credentials) => Ok((provider, credentials)),
            Err(reason) => Err(InvokeError::AssumeRole {
                role: role.as_str().to_owned(),
                reason,
            }),
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known fixtures")]
mod tests {
    use std::time::SystemTime;

    use axum::http::{HeaderMap, StatusCode};
    use axum::routing::post;

    use super::*;

    #[test]
    fn function_arns_parse_region_and_qualifiers() {
        let arn: FunctionArn = "arn:aws:lambda:eu-west-1:123456789012:function:pets"
            .parse()
            .unwrap();
        assert_eq!(arn.region(), Some("eu-west-1"));
        assert_eq!(arn.name(), "pets");
        let qualified: FunctionArn = "arn:aws:lambda:us-east-1:1:function:pets:live"
            .parse()
            .unwrap();
        assert_eq!(qualified.region(), Some("us-east-1"));
        assert_eq!(
            qualified.as_str(),
            "arn:aws:lambda:us-east-1:1:function:pets:live"
        );
        let gov: FunctionArn = "arn:aws-us-gov:lambda:us-gov-west-1:1:function:f"
            .parse()
            .unwrap();
        assert_eq!(gov.region(), Some("us-gov-west-1"));
        let bare: FunctionArn = "pets".parse().unwrap();
        assert_eq!(bare.region(), None);
        for bad in [
            "",
            "arn:aws:s3:::bucket",
            "arn:aws:lambda::1:function:f",
            "arn:aws:lambda:us-east-1:1:layer:l",
            "a/b",
        ] {
            assert!(bad.parse::<FunctionArn>().is_err(), "{bad}");
        }
    }

    #[test]
    fn function_arns_expose_account_qualifier_and_override_keys() {
        let arn: FunctionArn = "arn:aws:lambda:us-east-1:123456789012:function:pets:live"
            .parse()
            .unwrap();
        assert_eq!(arn.account(), Some("123456789012"));
        assert_eq!(arn.qualifier(), Some("live"));
        assert_eq!(
            arn.override_keys(),
            [
                "arn:aws:lambda:us-east-1:123456789012:function:pets:live",
                "pets:live",
                "arn:aws:lambda:us-east-1:123456789012:function:pets",
                "pets"
            ]
        );
        let unqualified: FunctionArn = "arn:aws:lambda:us-east-1:1:function:pets".parse().unwrap();
        assert_eq!(unqualified.qualifier(), None);
        assert_eq!(unqualified.override_keys().len(), 2);
        let partial: FunctionArn = "pets:3".parse().unwrap();
        assert_eq!((partial.name(), partial.qualifier()), ("pets", Some("3")));
        assert_eq!(partial.account(), None);
        for bad in [
            "pets:",
            "arn:aws:lambda:us-east-1:1:function:pets:live:extra",
            "arn:x",
        ] {
            assert!(bad.parse::<FunctionArn>().is_err(), "{bad}");
        }
    }

    #[test]
    fn integration_credentials_distinguish_roles_and_caller_passthrough() {
        assert_eq!(
            "arn:aws:iam::*:user/*".parse(),
            Ok(IntegrationCredentials::Caller)
        );
        assert_eq!(
            "arn:aws:iam::123456789012:role/apigw".parse(),
            Ok(IntegrationCredentials::Role(RoleArn(
                "arn:aws:iam::123456789012:role/apigw".to_owned()
            )))
        );
        for bad in [
            "",
            "arn:aws:iam::123:user/bob",
            "arn:aws:iam:::role/x",
            "arn:aws:iam::1:role/",
            "role",
        ] {
            assert!(bad.parse::<IntegrationCredentials>().is_err(), "{bad}");
        }
    }

    #[test]
    fn lambda_endpoint_flags_parse() {
        let LambdaEndpoint(function, url) =
            "pets=http://pets:8080/2015-03-31/functions/function/invocations"
                .parse()
                .unwrap();
        assert_eq!(function, "pets");
        assert_eq!(url.host_str(), Some("pets"));
        for bad in ["pets", "=http://x", "pets=not a url", "pets=ftp://x"] {
            assert!(bad.parse::<LambdaEndpoint>().is_err(), "{bad}");
        }
    }

    fn clients(endpoints: LambdaEndpoints) -> AwsClients {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        AwsClients::new(
            config,
            CredentialsMode::Assume,
            endpoints,
            reqwest::Client::new(),
        )
    }

    async fn emulator() -> reqwest::Url {
        let app = axum::Router::new()
            .route(
                "/ok",
                post(|headers: HeaderMap, body: Bytes| async move {
                    let trace = headers
                        .get("x-amzn-trace-id")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_owned();
                    format!(
                        "{{\"echo\":{},\"trace\":\"{trace}\"}}",
                        String::from_utf8_lossy(&body)
                    )
                }),
            )
            .route(
                "/error",
                post(|| async {
                    (
                        [("X-Amz-Function-Error", "Unhandled")],
                        "{\"errorMessage\":\"boom\"}",
                    )
                }),
            )
            .route("/down", post(|| async { StatusCode::BAD_GATEWAY }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        reqwest::Url::parse(&format!("http://{addr}/")).unwrap()
    }

    #[tokio::test]
    async fn endpoint_overrides_speak_the_invoke_protocol() {
        let base = emulator().await;
        let endpoints = LambdaEndpoints::from_iter([
            ("ok".to_owned(), base.join("ok").unwrap()),
            (
                "arn:aws:lambda:us-east-1:1:function:err".to_owned(),
                base.join("error").unwrap(),
            ),
            ("down".to_owned(), base.join("down").unwrap()),
        ]);
        let aws = clients(endpoints);
        let ok: FunctionArn = "arn:aws:lambda:us-east-1:1:function:ok".parse().unwrap();
        let result = aws
            .invoke_lambda(
                &ok,
                None,
                b"{\"a\":1}".to_vec(),
                Some("Root=1-abc".to_owned()),
            )
            .await
            .unwrap();
        assert_eq!(result.function_error, None);
        assert_eq!(
            String::from_utf8(result.payload).unwrap(),
            r#"{"echo":{"a":1},"trace":"Root=1-abc"}"#
        );

        let err: FunctionArn = "arn:aws:lambda:us-east-1:1:function:err".parse().unwrap();
        let result = aws
            .invoke_lambda(&err, None, Vec::new(), None)
            .await
            .unwrap();
        assert_eq!(result.function_error.as_deref(), Some("Unhandled"));

        let down: FunctionArn = "down".parse().unwrap();
        assert!(matches!(
            aws.invoke_lambda(&down, None, Vec::new(), None).await,
            Err(InvokeError::Endpoint(_))
        ));
    }

    #[tokio::test]
    async fn endpoint_overrides_match_aliases_by_most_specific_key() {
        let base = emulator().await;
        let endpoints = LambdaEndpoints::from_iter([
            ("pets:live".to_owned(), base.join("error").unwrap()),
            ("pets".to_owned(), base.join("ok").unwrap()),
        ]);
        let aws = clients(endpoints);
        let live: FunctionArn = "arn:aws:lambda:us-east-1:1:function:pets:live"
            .parse()
            .unwrap();
        let result = aws
            .invoke_lambda(&live, None, Vec::new(), None)
            .await
            .unwrap();
        assert_eq!(result.function_error.as_deref(), Some("Unhandled"));
        let other: FunctionArn = "arn:aws:lambda:us-east-1:1:function:pets:v2"
            .parse()
            .unwrap();
        let result = aws
            .invoke_lambda(&other, None, b"1".to_vec(), None)
            .await
            .unwrap();
        assert_eq!(result.function_error, None);
    }

    #[tokio::test]
    async fn streaming_endpoint_chunks_arrive_in_order() {
        let base = emulator().await;
        let aws = clients(LambdaEndpoints::from_iter([(
            "ok".to_owned(),
            base.join("ok").unwrap(),
        )]));
        let function: FunctionArn = "ok".parse().unwrap();
        let mut stream = aws
            .invoke_lambda_stream(&function, None, b"{}".to_vec(), None)
            .await
            .unwrap();
        let mut all = Vec::new();
        while let Some(chunk) = stream.next_chunk().await.unwrap() {
            all.extend_from_slice(&chunk);
        }
        assert_eq!(String::from_utf8(all).unwrap(), r#"{"echo":{},"trace":""}"#);

        let down: FunctionArn = "down".parse().unwrap();
        let aws = clients(LambdaEndpoints::from_iter([(
            "down".to_owned(),
            base.join("down").unwrap(),
        )]));
        assert!(matches!(
            aws.invoke_lambda_stream(&down, None, Vec::new(), None)
                .await,
            Err(InvokeError::Endpoint(_))
        ));
    }

    #[tokio::test]
    async fn invocations_carry_the_alias_in_the_function_name() {
        use std::sync::Arc;

        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorder = Arc::clone(&seen);
        let app = axum::Router::new().fallback(move |request: axum::extract::Request| {
            let recorder = Arc::clone(&recorder);
            async move {
                recorder
                    .lock()
                    .unwrap()
                    .push(request.uri().path().to_owned());
                "{}"
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(format!("http://{addr}"))
            .credentials_provider(aws_sdk_lambda::config::SharedCredentialsProvider::new(
                Credentials::new("id", "secret", None, None, "test"),
            ))
            .build();
        let aws = AwsClients::new(
            config,
            CredentialsMode::Assume,
            LambdaEndpoints::default(),
            reqwest::Client::new(),
        );
        let function: FunctionArn = "arn:aws:lambda:us-east-1:123456789012:function:pets:live"
            .parse()
            .unwrap();
        aws.invoke_lambda(&function, None, b"{}".to_vec(), None)
            .await
            .unwrap();
        let paths = seen.lock().unwrap().clone();
        assert_eq!(paths.len(), 1, "{paths:?}");
        let path = paths[0].replace("%3A", ":");
        assert_eq!(
            path,
            "/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:pets:live/invocations"
        );
    }

    #[tokio::test]
    async fn gateway_credentials_mode_never_assumes_roles() {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        let aws = AwsClients::new(
            config,
            CredentialsMode::Gateway,
            LambdaEndpoints::default(),
            reqwest::Client::new(),
        );
        let role = RoleArn("arn:aws:iam::1:role/r".to_owned());
        aws.lambda_client(Some("us-east-1"), Some(&role))
            .await
            .unwrap();
        assert!(aws.role_status().is_empty());
    }

    #[tokio::test]
    async fn clients_are_cached_per_region() {
        let aws = clients(LambdaEndpoints::default());
        aws.lambda_client(Some("us-east-1"), None).await.unwrap();
        aws.lambda_client(Some("us-east-1"), None).await.unwrap();
        aws.lambda_client(Some("eu-west-1"), None).await.unwrap();
        assert_eq!(aws.lambda.lock().unwrap().len(), 2);
    }

    fn credentials_expiring(expiry: Option<jiff::Timestamp>) -> Credentials {
        Credentials::new("id", "secret", None, expiry.map(SystemTime::from), "test")
    }

    fn after(now: jiff::Timestamp, seconds: i64) -> jiff::Timestamp {
        now.checked_add(jiff::SignedDuration::from_secs(seconds))
            .unwrap()
    }

    #[test]
    fn credentials_are_reused_until_shortly_before_they_expire() {
        let now = jiff::Timestamp::from_second(1_700_000_000).unwrap();
        let cached = |expiry| CachedCredentials {
            credentials: credentials_expiring(expiry),
            loaded: now,
        };
        assert!(cached(Some(after(now, 600))).is_fresh(now));
        assert!(!cached(Some(after(now, 240))).is_fresh(now));
        assert!(!cached(Some(after(now, -1))).is_fresh(now));
        assert!(cached(None).is_fresh(after(now, 299)));
        assert!(!cached(None).is_fresh(after(now, 301)));
    }

    #[tokio::test]
    async fn gateway_credentials_come_from_the_sdk_config_and_are_cached() {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .credentials_provider(aws_sdk_lambda::config::SharedCredentialsProvider::new(
                Credentials::new("id", "secret", None, None, "test"),
            ))
            .build();
        let aws = AwsClients::new(
            config,
            CredentialsMode::Gateway,
            LambdaEndpoints::default(),
            reqwest::Client::new(),
        );
        let role = RoleArn("arn:aws:iam::1:role/r".to_owned());
        let first = aws.credentials(Some(&role)).await.unwrap();
        assert_eq!(first.access_key_id(), "id");
        let second = aws.credentials(None).await.unwrap();
        assert_eq!(second.secret_access_key(), "secret");
        assert_eq!(aws.credentials.lock().await.len(), 1);
        assert!(aws.role_status().is_empty());
    }

    #[tokio::test]
    async fn missing_gateway_credentials_are_an_error() {
        let aws = clients(LambdaEndpoints::default());
        let credentials = aws.credentials(None).await;
        assert!(matches!(credentials, Err(InvokeError::Credentials(_))));
    }

    #[test]
    fn invocation_types_parse_exactly() {
        assert_eq!("Event".parse(), Ok(InvocationType::Event));
        assert_eq!(
            " RequestResponse ".parse(),
            Ok(InvocationType::RequestResponse)
        );
        assert_eq!("DryRun".parse(), Ok(InvocationType::DryRun));
        assert!("event".parse::<InvocationType>().is_err());
        assert_eq!(InvocationType::default().header_value(), "RequestResponse");
    }

    #[test]
    fn service_endpoints_parse_a_service_and_an_http_url() {
        let endpoint: ServiceEndpoint = "sqs=http://localstack:4566".parse().unwrap();
        assert_eq!(endpoint.0, "sqs");
        assert_eq!(endpoint.1.as_str(), "http://localstack:4566/");
        let endpoints: ServiceEndpoints = std::iter::once((endpoint.0, endpoint.1)).collect();
        assert!(endpoints.get("sqs").is_some());
        assert!(endpoints.get("sns").is_none());
        for bad in ["sqs", "=http://x", "sqs=not a url", "sqs=ftp://x"] {
            assert!(bad.parse::<ServiceEndpoint>().is_err(), "{bad}");
        }
    }
}
