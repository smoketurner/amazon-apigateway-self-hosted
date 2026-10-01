//! HTTP clients for `HTTP_PROXY` integrations, including the ones whose
//! `tlsConfig` changes how the backend's certificate is verified:
//!
//! - `insecureSkipVerification` accepts any certificate the backend presents.
//! - `serverNameToVerify` is the host name the certificate must be valid for,
//!   and the name sent in the TLS handshake (SNI). reqwest has no such setting,
//!   so the request goes to the server name with that name resolved to the
//!   backend's real addresses, and the `Host` header keeps the integration's own
//!   host.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::http::HeaderValue;

use crate::model::TlsConfig;

/// Distinct (server name, addresses) clients kept per integration. A backend
/// whose addresses keep changing would otherwise grow the cache without bound.
const MAX_CACHED_CLIENTS: usize = 16;
/// How long resolving the backend's addresses may take.
const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// The builder every integration client starts from: proxies never follow
/// redirects.
pub(crate) fn client_builder() -> reqwest::ClientBuilder {
    reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum TlsClientError {
    #[error("could not resolve {host}: {reason}")]
    Resolve { host: String, reason: String },
    #[error("serverNameToVerify {0:?} is not a valid host name")]
    ServerName(String),
    #[error("the integration URI has no host")]
    NoHost,
    #[error("could not build the HTTP client: {0}")]
    Build(#[source] reqwest::Error),
}

/// A request ready to send: the client to use, the URL (its host replaced by the
/// server name when one is verified), and the `Host` header to set when the URL
/// no longer names the integration's host.
#[derive(Debug)]
pub(crate) struct Prepared {
    pub(crate) client: reqwest::Client,
    pub(crate) url: reqwest::Url,
    pub(crate) host: Option<HeaderValue>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClientKey {
    server_name: Option<String>,
    addrs: Vec<SocketAddr>,
}

/// The clients of one integration with a `tlsConfig`, built on first use and
/// cached per distinct (server name, backend addresses).
#[derive(Debug, Clone)]
pub(crate) struct TlsClient {
    insecure: bool,
    server_name: Option<String>,
    clients: Arc<Mutex<BTreeMap<ClientKey, reqwest::Client>>>,
}

impl TlsClient {
    /// `None` when the config changes nothing.
    pub(crate) fn new(config: &TlsConfig) -> Option<Self> {
        let server_name = config
            .server_name_to_verify
            .clone()
            .filter(|_| !config.insecure_skip_verification);
        if !config.insecure_skip_verification && server_name.is_none() {
            return None;
        }
        Some(Self {
            insecure: config.insecure_skip_verification,
            server_name,
            clients: Arc::default(),
        })
    }

    /// Chooses the client and rewrites `url` for this integration.
    ///
    /// # Errors
    ///
    /// Fails when the backend's host cannot be resolved or the configured server
    /// name is not a host name.
    pub(crate) async fn prepare(&self, mut url: reqwest::Url) -> Result<Prepared, TlsClientError> {
        let Some(server_name) = self.server_name.clone() else {
            let client = self.client(ClientKey {
                server_name: None,
                addrs: Vec::new(),
            })?;
            return Ok(Prepared {
                client,
                url,
                host: None,
            });
        };
        let host = url.host_str().ok_or(TlsClientError::NoHost)?.to_owned();
        let port = url.port_or_known_default().ok_or(TlsClientError::NoHost)?;
        let host_header = match url.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.clone(),
        };
        let mut addrs: Vec<SocketAddr> = tokio::time::timeout(
            RESOLVE_TIMEOUT,
            tokio::net::lookup_host((host.as_str(), port)),
        )
        .await
        .map_err(|_| TlsClientError::Resolve {
            host: host.clone(),
            reason: "timed out".to_owned(),
        })?
        .map_err(|e| TlsClientError::Resolve {
            host: host.clone(),
            reason: e.to_string(),
        })?
        .collect();
        addrs.sort_unstable();
        url.set_host(Some(&server_name))
            .map_err(|_| TlsClientError::ServerName(server_name.clone()))?;
        let client = self.client(ClientKey {
            server_name: Some(server_name),
            addrs,
        })?;
        Ok(Prepared {
            client,
            url,
            host: HeaderValue::try_from(host_header).ok(),
        })
    }

    fn client(&self, key: ClientKey) -> Result<reqwest::Client, TlsClientError> {
        let mut clients = self.clients.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(client) = clients.get(&key) {
            return Ok(client.clone());
        }
        let mut builder = client_builder();
        if self.insecure {
            builder = builder
                .tls_danger_accept_invalid_certs(true)
                .tls_danger_accept_invalid_hostnames(true);
        }
        if let Some(ref name) = key.server_name {
            builder = builder.resolve_to_addrs(name, &key.addrs);
        }
        let client = builder.build().map_err(TlsClientError::Build)?;
        if clients.len() >= MAX_CACHED_CLIENTS {
            clients.clear();
        }
        clients.insert(key, client.clone());
        Ok(client)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    fn config(insecure: bool, server_name: Option<&str>) -> TlsConfig {
        TlsConfig {
            insecure_skip_verification: insecure,
            server_name_to_verify: server_name.map(str::to_owned),
        }
    }

    #[test]
    fn configs_that_change_nothing_need_no_client() {
        assert!(TlsClient::new(&config(false, None)).is_none());
        assert!(TlsClient::new(&config(true, None)).is_some());
        assert!(TlsClient::new(&config(false, Some("api.internal"))).is_some());
    }

    #[tokio::test]
    async fn a_verified_server_name_replaces_the_url_host_and_keeps_the_original_host_header() {
        let client = TlsClient::new(&config(false, Some("api.internal"))).unwrap();
        let url = reqwest::Url::parse("https://127.0.0.1:8443/v1/pets?x=1").unwrap();
        let prepared = client.prepare(url).await.unwrap();
        assert_eq!(
            prepared.url.as_str(),
            "https://api.internal:8443/v1/pets?x=1"
        );
        assert_eq!(prepared.host.unwrap(), "127.0.0.1:8443");

        let default_port = reqwest::Url::parse("https://127.0.0.1/").unwrap();
        let prepared = client.prepare(default_port).await.unwrap();
        assert_eq!(prepared.url.as_str(), "https://api.internal/");
        assert_eq!(prepared.host.unwrap(), "127.0.0.1");
    }

    #[tokio::test]
    async fn clients_are_cached_per_server_name_and_addresses() {
        let client = TlsClient::new(&config(false, Some("api.internal"))).unwrap();
        for host in ["127.0.0.1", "127.0.0.1", "127.0.0.2"] {
            let url = reqwest::Url::parse(&format!("https://{host}/")).unwrap();
            client.prepare(url).await.unwrap();
        }
        assert_eq!(client.clients.lock().unwrap().len(), 2);

        let insecure = TlsClient::new(&config(true, None)).unwrap();
        for _ in 0..3 {
            let url = reqwest::Url::parse("https://127.0.0.1/").unwrap();
            let prepared = insecure.prepare(url).await.unwrap();
            assert!(prepared.host.is_none());
            assert_eq!(prepared.url.host_str(), Some("127.0.0.1"));
        }
        assert_eq!(insecure.clients.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn invalid_server_names_and_unresolvable_hosts_are_errors() {
        let client = TlsClient::new(&config(false, Some("bad name"))).unwrap();
        let url = reqwest::Url::parse("https://127.0.0.1/").unwrap();
        assert!(matches!(
            client.prepare(url).await,
            Err(TlsClientError::ServerName(_))
        ));
        let client = TlsClient::new(&config(false, Some("api.internal"))).unwrap();
        let url = reqwest::Url::parse("https://does-not-exist.invalid/").unwrap();
        assert!(matches!(
            client.prepare(url).await,
            Err(TlsClientError::Resolve { .. })
        ));
    }
}
