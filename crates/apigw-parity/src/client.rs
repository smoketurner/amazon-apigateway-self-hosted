//! Sends case requests over HTTPS and captures the raw response.

use std::net::SocketAddr;
use std::time::Duration;

use crate::case::{CaseName, RequestSpec};
use crate::error::{ParityError, Result};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const USER_AGENT: &str = "apigw-parity";

/// A response as received, before normalization. Header names are lowercase and
/// repeated headers stay as separate entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

/// An HTTP client for case requests: no redirects, bounded time.
#[derive(Debug, Clone)]
pub(crate) struct Requester {
    client: reqwest::Client,
}

/// How a [`Requester`] reaches and authenticates to the endpoints, beyond the defaults.
#[derive(Debug, Clone, Default)]
pub(crate) struct ClientOptions {
    /// PEM certificate chain and key to present in the handshake.
    pub(crate) identity: Option<Vec<u8>>,
    /// Host names to connect to at a given address instead of resolving them,
    /// keeping the name for SNI and `Host`.
    pub(crate) resolve: Vec<(String, SocketAddr)>,
    /// Accept any server certificate: only for a self-hosted gateway under test,
    /// whose certificate is self-signed.
    pub(crate) insecure: bool,
}

impl Requester {
    /// A client with `options` applied, trusting the platform's root certificates.
    ///
    /// # Errors
    /// Fails when the identity is not a PEM certificate and key, or the TLS
    /// backend cannot be initialized.
    pub(crate) fn with_options(options: &ClientOptions) -> Result<Self> {
        let mut builder = reqwest::Client::builder();
        if let Some(ref pem) = options.identity {
            let identity = reqwest::Identity::from_pem(pem).map_err(|e| ParityError::Start {
                what: "client certificate",
                reason: e.to_string(),
            })?;
            builder = builder.identity(identity);
        }
        for (name, address) in &options.resolve {
            builder = builder.resolve(name, *address);
        }
        if options.insecure {
            builder = builder.danger_accept_invalid_certs(true);
        }
        Self::with_builder(builder)
    }

    /// A client that additionally trusts the PEM certificate in `pem`.
    ///
    /// # Errors
    /// Fails when `pem` is not a certificate or the TLS backend cannot be initialized.
    pub(crate) fn trusting(pem: &[u8]) -> Result<Self> {
        let certificate = reqwest::Certificate::from_pem(pem).map_err(|e| ParityError::Start {
            what: "HTTP client",
            reason: e.to_string(),
        })?;
        Self::with_builder(reqwest::Client::builder().add_root_certificate(certificate))
    }

    fn with_builder(builder: reqwest::ClientBuilder) -> Result<Self> {
        // HTTP/1.1 against both sides: a recording and its replay must reach
        // the gateway the same way, and header-name case only exists there.
        let client = builder
            .http1_only()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(REQUEST_TIMEOUT)
            .user_agent(USER_AGENT)
            .build()
            .map_err(|e| ParityError::Start {
                what: "HTTP client",
                reason: e.to_string(),
            })?;
        Ok(Self { client })
    }

    /// Whether a GET of `url` answers with a success status.
    pub(crate) async fn probe(&self, url: &str) -> bool {
        self.client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
    }

    /// Sends `spec` to `base_url` (a URL up to and including the stage prefix).
    ///
    /// # Errors
    /// [`ParityError::Request`] when the request cannot be completed.
    pub(crate) async fn send(
        &self,
        case: &CaseName,
        base_url: &str,
        spec: &RequestSpec,
    ) -> Result<RawResponse> {
        let mut url =
            reqwest::Url::parse(&format!("{}{}", base_url.trim_end_matches('/'), spec.path))
                .map_err(|e| ParityError::Start {
                    what: "request URL",
                    reason: e.to_string(),
                })?;
        if !spec.query.is_empty() {
            url.query_pairs_mut().extend_pairs(&spec.query);
        }
        let mut request = self.client.request(spec.method.clone(), url);
        for (name, value) in &spec.headers {
            request = request.header(name, value);
        }
        if let Some(ref body) = spec.body {
            request = request.body(body.clone());
        }
        let request_error = |source| ParityError::Request {
            case: case.clone(),
            source,
        };
        let response = request.send().await.map_err(request_error)?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    String::from_utf8_lossy(value.as_bytes()).into_owned(),
                )
            })
            .collect();
        let body = response.bytes().await.map_err(request_error)?.to_vec();
        Ok(RawResponse {
            status,
            headers,
            body,
        })
    }
}
