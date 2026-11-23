//! AWS credentials from [IAM Roles Anywhere] for `aws-config` and the AWS SDK for Rust.
//!
//! Roles Anywhere exchanges an X.509 certificate, issued by a CA registered as a trust anchor,
//! for temporary credentials of an IAM role. AWS ships this exchange as a separate program, the
//! credential helper (`aws_signing_helper`), which the SDK runs through `credential_process`.
//! This crate does the same exchange in process: it signs a `CreateSession` request with the
//! certificate's private key and returns the session's credentials, so no helper binary, shell,
//! or C library has to be installed next to the application.
//!
//! [`RolesAnywhereCredentialsProvider`] implements [`ProvideCredentials`] and plugs in like any
//! other credentials provider:
//!
//! ```no_run
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! use std::time::Duration;
//!
//! use aws_rolesanywhere_credentials::RolesAnywhereCredentialsProvider;
//!
//! let provider = RolesAnywhereCredentialsProvider::builder()
//!     .certificate_path("/etc/rolesanywhere/tls.crt")
//!     .private_key_path("/etc/rolesanywhere/tls.key")
//!     .trust_anchor_arn("arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/a1b2".parse()?)
//!     .profile_arn("arn:aws:rolesanywhere:us-east-1:111122223333:profile/c3d4".parse()?)
//!     .role_arn("arn:aws:iam::111122223333:role/gateway")
//!     .session_duration(Duration::from_hours(1))
//!     .build()?;
//! // let config = aws_config::defaults(BehaviorVersion::latest())
//! //     .credentials_provider(provider)
//! //     .load()
//! //     .await;
//! # drop(provider);
//! # Ok(())
//! # }
//! ```
//!
//! # Behavior
//!
//! - The certificate file holds the end-entity certificate first, then any intermediates, as
//!   cert-manager writes `tls.crt`. The private key is PKCS#8, PKCS#1 (RSA), or SEC1 (EC), not
//!   encrypted. RSA, P-256, P-384, and P-521 keys are supported.
//! - Both files are read on every refresh, so a renewed certificate is used from the next
//!   refresh on. [`Builder::build`] reads them once and fails if they can't be used.
//! - The request is signed for the trust anchor's region and sent to that region's Roles
//!   Anywhere endpoint unless [`Builder::endpoint_url`] says otherwise.
//! - HTTP goes through the SDK's own client stack, with its retries and timeouts.
//!   [`Builder::configure`] takes the HTTP client, sleep, time source, retry configuration, and
//!   behavior version from an [`SdkConfig`]; without it, the SDK defaults apply (the
//!   `default-https-client` and `rt-tokio` features provide them).
//! - Credentials carry the session's expiration; the SDK's identity cache refreshes them before
//!   they expire.
//!
//! The signing follows AWS's [signing process] and is checked against the requests the AWS
//! credential helper sends. Signatures use aws-lc-rs, except for P-384 keys: aws-lc-rs cannot
//! sign a SHA-256 digest with a P-384 key, so those use `RustCrypto`'s `p384`.
//!
//! [IAM Roles Anywhere]: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/introduction.html
//! [signing process]: https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html

mod arn;
mod identity;
mod key;
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures"
)]
mod oracle_tests;
mod session;
mod signing;
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::unreachable,
    reason = "test fixtures are known-good"
)]
mod testing;
#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::panic,
    reason = "tests assert on known-good fixtures"
)]
mod tests;

use std::path::PathBuf;
use std::time::Duration;

use aws_credential_types::Credentials;
use aws_credential_types::provider::error::CredentialsError;
use aws_credential_types::provider::{self, ProvideCredentials, future};
use aws_smithy_async::rt::sleep::{SharedAsyncSleep, default_async_sleep};
use aws_smithy_async::time::SharedTimeSource;
use aws_smithy_runtime::client::orchestrator::operation::Operation;
use aws_smithy_runtime::client::retries::classifiers::{
    HttpStatusCodeClassifier, TransientErrorClassifier,
};
use aws_smithy_runtime_api::client::behavior_version::BehaviorVersion;
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use aws_smithy_runtime_api::client::interceptors::context::Error;
use aws_smithy_runtime_api::client::orchestrator::{
    HttpRequest, HttpResponse, OrchestratorError, SensitiveOutput,
};
use aws_smithy_runtime_api::client::result::SdkError;
use aws_smithy_runtime_api::client::runtime_plugin::StaticRuntimePlugin;
use aws_smithy_types::body::SdkBody;
use aws_smithy_types::config_bag::Layer;
use aws_smithy_types::retry::RetryConfig;
use aws_smithy_types::timeout::TimeoutConfig;
use aws_types::SdkConfig;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HOST};

pub use self::arn::{ArnError, ProfileArn, TrustAnchorArn};
pub use self::identity::IdentityError;
pub use self::session::SessionError;

use self::identity::Identity;
use self::session::CreateSessionBody;
use self::signing::SignedHeaders;

const DEFAULT_SESSION_DURATION: Duration = Duration::from_hours(1);
const MIN_SESSION_DURATION: Duration = Duration::from_mins(15);
const MAX_SESSION_DURATION: Duration = Duration::from_hours(12);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Why a [`RolesAnywhereCredentialsProvider`] could not be built.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BuildError {
    /// A required setting was not given.
    #[error("{0} is required")]
    Missing(&'static str),
    /// The trust anchor and profile are in different regions.
    #[error("the trust anchor is in {trust_anchor} but the profile is in {profile}")]
    RegionMismatch {
        /// The trust anchor's region.
        trust_anchor: String,
        /// The profile's region.
        profile: String,
    },
    /// The session duration is outside the 15 minutes to 12 hours Roles Anywhere allows.
    #[error("the session duration must be 900 to 43200 seconds, not {}", .0.as_secs())]
    SessionDuration(Duration),
    /// There is no default endpoint for the trust anchor's partition.
    #[error("no Roles Anywhere endpoint is known for partition {0:?}; set an endpoint URL")]
    UnknownPartition(String),
    /// The endpoint URL has no host.
    #[error("{0:?} is not an http or https URL with a host")]
    Endpoint(String),
    /// No HTTP client is configured and the `default-https-client` feature is off.
    #[error(
        "no HTTP client: configure one through an SdkConfig or enable the default-https-client feature"
    )]
    NoHttpClient,
    /// The certificate or private key can't be used.
    #[error(transparent)]
    Identity(#[from] IdentityError),
}

/// Configures a [`RolesAnywhereCredentialsProvider`].
#[derive(Debug, Default)]
pub struct Builder {
    certificate: Option<PathBuf>,
    private_key: Option<PathBuf>,
    trust_anchor: Option<TrustAnchorArn>,
    profile: Option<ProfileArn>,
    role: Option<String>,
    session_duration: Option<Duration>,
    endpoint_url: Option<String>,
    sdk_config: Option<SdkConfig>,
}

impl Builder {
    /// The PEM file with the end-entity certificate, followed by any intermediates. Required.
    #[must_use]
    pub fn certificate_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.certificate = Some(path.into());
        self
    }

    /// The PEM file with the certificate's private key. Required.
    #[must_use]
    pub fn private_key_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.private_key = Some(path.into());
        self
    }

    /// The trust anchor the certificate chains to. Required.
    #[must_use]
    pub fn trust_anchor_arn(mut self, arn: TrustAnchorArn) -> Self {
        self.trust_anchor = Some(arn);
        self
    }

    /// The profile that allows the role. Required; it must be in the trust anchor's region.
    #[must_use]
    pub fn profile_arn(mut self, arn: ProfileArn) -> Self {
        self.profile = Some(arn);
        self
    }

    /// The IAM role to assume. Required.
    #[must_use]
    pub fn role_arn(mut self, arn: impl Into<String>) -> Self {
        self.role = Some(arn.into());
        self
    }

    /// How long each session's credentials last, from 15 minutes to 12 hours (the profile can
    /// lower the maximum). Defaults to one hour.
    #[must_use]
    pub fn session_duration(mut self, duration: Duration) -> Self {
        self.session_duration = Some(duration);
        self
    }

    /// Sends `CreateSession` to this URL instead of the region's endpoint, for a partition
    /// this crate has no endpoint for, a VPC endpoint, or a test double. Only the scheme,
    /// host, and port are used.
    #[must_use]
    pub fn endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// Uses the HTTP client, sleep, time source, retry configuration, and behavior version of
    /// `config`.
    #[must_use]
    pub fn configure(mut self, config: &SdkConfig) -> Self {
        self.sdk_config = Some(config.clone());
        self
    }

    /// Builds the provider, reading the certificate and key once to check them.
    ///
    /// # Errors
    ///
    /// [`BuildError`] if a required setting is missing, the trust anchor and profile are in
    /// different regions, the session duration or endpoint is unusable, or the certificate
    /// and key can't be used.
    pub fn build(self) -> Result<RolesAnywhereCredentialsProvider, BuildError> {
        let certificate = self
            .certificate
            .ok_or(BuildError::Missing("a certificate path"))?;
        let private_key = self
            .private_key
            .ok_or(BuildError::Missing("a private key path"))?;
        let trust_anchor = self
            .trust_anchor
            .ok_or(BuildError::Missing("a trust anchor ARN"))?;
        let profile = self.profile.ok_or(BuildError::Missing("a profile ARN"))?;
        let role = self.role.ok_or(BuildError::Missing("a role ARN"))?;
        if trust_anchor.region() != profile.region() {
            return Err(BuildError::RegionMismatch {
                trust_anchor: trust_anchor.region().to_owned(),
                profile: profile.region().to_owned(),
            });
        }
        let session_duration = self.session_duration.unwrap_or(DEFAULT_SESSION_DURATION);
        let Some(session_seconds) = (MIN_SESSION_DURATION..=MAX_SESSION_DURATION)
            .contains(&session_duration)
            .then(|| u32::try_from(session_duration.as_secs()).ok())
            .flatten()
        else {
            return Err(BuildError::SessionDuration(session_duration));
        };
        let endpoint = match self.endpoint_url {
            Some(url) => url,
            None => arn::default_endpoint(trust_anchor.partition(), trust_anchor.region())
                .ok_or_else(|| BuildError::UnknownPartition(trust_anchor.partition().to_owned()))?,
        };
        let (endpoint, host) =
            endpoint_origin(&endpoint).ok_or_else(|| BuildError::Endpoint(endpoint.clone()))?;
        Identity::load(&certificate, &private_key)?;

        let sdk_config = self.sdk_config.as_ref();
        let http_client = sdk_config.and_then(SdkConfig::http_client);
        if http_client.is_none() && !cfg!(feature = "default-https-client") {
            return Err(BuildError::NoHttpClient);
        }
        let time_source = sdk_config
            .and_then(SdkConfig::time_source)
            .unwrap_or_default();
        let operation = create_session_operation(
            &endpoint,
            http_client,
            sdk_config
                .and_then(SdkConfig::sleep_impl)
                .or_else(default_async_sleep),
            &sdk_config
                .and_then(SdkConfig::retry_config)
                .cloned()
                .unwrap_or_else(RetryConfig::standard),
            sdk_config
                .and_then(SdkConfig::behavior_version)
                .unwrap_or_else(BehaviorVersion::latest),
            time_source.clone(),
        );
        Ok(RolesAnywhereCredentialsProvider {
            certificate,
            private_key,
            trust_anchor,
            profile,
            role,
            session_seconds,
            host,
            time_source,
            operation,
        })
    }
}

/// The `scheme://authority` of an `http` or `https` URL, which the request path is appended
/// to, and the authority alone: the `Host` header that is signed and sent. Any path is dropped,
/// because the signed path is always `/sessions`.
fn endpoint_origin(endpoint: &str) -> Option<(String, String)> {
    let uri = endpoint.parse::<http::Uri>().ok()?;
    let scheme = uri.scheme_str()?;
    if scheme != "https" && scheme != "http" {
        return None;
    }
    let authority = uri.authority()?;
    if authority.host().is_empty() || authority.as_str().contains('@') {
        return None;
    }
    Some((
        format!("{scheme}://{authority}"),
        authority.as_str().to_owned(),
    ))
}

/// A signed `CreateSession` request, the input of the operation.
#[derive(Debug)]
struct SignedSession {
    host: String,
    query: String,
    headers: SignedHeaders,
    body: Vec<u8>,
}

fn create_session_operation(
    endpoint: &str,
    http_client: Option<SharedHttpClient>,
    sleep: Option<SharedAsyncSleep>,
    retry: &RetryConfig,
    behavior_version: BehaviorVersion,
    time_source: SharedTimeSource,
) -> Operation<SignedSession, Credentials, SessionError> {
    let mut builder = Operation::builder()
        .service_name(signing::SERVICE)
        .operation_name("CreateSession")
        .behavior_version(behavior_version)
        .with_connection_poisoning()
        .endpoint_url(endpoint)
        .no_auth()
        .timeout_config(
            TimeoutConfig::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .read_timeout(READ_TIMEOUT)
                .build(),
        )
        .time_source(time_source)
        .runtime_plugin(StaticRuntimePlugin::new().with_config({
            let mut layer = Layer::new("SensitiveOutput");
            layer.store_put(SensitiveOutput);
            layer.freeze()
        }));
    if let Some(http_client) = http_client {
        builder = builder.http_client(http_client);
    }
    builder = match sleep {
        Some(sleep) => builder
            .standard_retry(retry)
            .retry_classifier(TransientErrorClassifier::<Error>::new())
            .retry_classifier(HttpStatusCodeClassifier::default())
            .sleep_impl(sleep),
        None => builder.no_retry(),
    };
    builder
        .serializer(|session: SignedSession| {
            let mut request = http::Request::builder()
                .method("POST")
                .uri(format!("{}?{}", signing::PATH, session.query))
                .header(CONTENT_TYPE, signing::CONTENT_TYPE)
                .header(HOST, session.host)
                .header("x-amz-date", session.headers.date)
                .header("x-amz-x509", session.headers.certificate);
            if let Some(chain) = session.headers.chain {
                request = request.header("x-amz-x509-chain", chain);
            }
            let request = request
                .header(AUTHORIZATION, session.headers.authorization)
                .body(SdkBody::from(session.body))?;
            Ok(HttpRequest::try_from(request)?)
        })
        .deserializer(|response: &HttpResponse| {
            let body = response.body().bytes().unwrap_or_default();
            session::parse_response(response.status().as_u16(), body)
                .map_err(OrchestratorError::operation)
        })
        .build()
}

/// Credentials from IAM Roles Anywhere, signed with a certificate's private key.
///
/// Build one with [`RolesAnywhereCredentialsProvider::builder`].
#[derive(Debug)]
pub struct RolesAnywhereCredentialsProvider {
    certificate: PathBuf,
    private_key: PathBuf,
    trust_anchor: TrustAnchorArn,
    profile: ProfileArn,
    role: String,
    session_seconds: u32,
    host: String,
    time_source: SharedTimeSource,
    operation: Operation<SignedSession, Credentials, SessionError>,
}

impl RolesAnywhereCredentialsProvider {
    /// A builder for the provider.
    #[must_use]
    pub fn builder() -> Builder {
        Builder::default()
    }

    async fn credentials(&self) -> provider::Result {
        let identity = Identity::load(&self.certificate, &self.private_key)
            .map_err(CredentialsError::invalid_configuration)?;
        let now = jiff::Timestamp::try_from(self.time_source.now())
            .map_err(CredentialsError::unhandled)?;
        let body = serde_json::to_vec(&CreateSessionBody {
            duration_seconds: self.session_seconds,
        })
        .map_err(CredentialsError::unhandled)?;
        let query = signing::canonical_query(&[
            ("profileArn", self.profile.as_str()),
            ("roleArn", &self.role),
            ("trustAnchorArn", self.trust_anchor.as_str()),
        ]);
        let headers = signing::sign(
            &identity,
            self.trust_anchor.region(),
            &self.host,
            &query,
            now,
            &body,
        )
        .ok_or_else(|| CredentialsError::unhandled("the private key failed to sign"))?;
        let session = SignedSession {
            host: self.host.clone(),
            query,
            headers,
            body,
        };
        match self.operation.invoke(session).await {
            Ok(credentials) => {
                tracing::debug!(
                    expiry = ?credentials.expiry(),
                    "loaded IAM Roles Anywhere credentials"
                );
                Ok(credentials)
            }
            Err(SdkError::ServiceError(context)) => {
                Err(CredentialsError::provider_error(context.into_err()))
            }
            Err(error) => Err(CredentialsError::provider_error(error)),
        }
    }
}

impl ProvideCredentials for RolesAnywhereCredentialsProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(self.credentials())
    }
}
