//! The public keys tokens are verified with: fetched from each configured
//! issuer, cached, and refreshed when a token names a key that is not cached.
//!
//! Only issuers named by an authorizer's definition are ever contacted. A token
//! cannot make the gateway fetch from a host of its choosing.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet, PublicKeyUse};
use reqwest::Url;
use serde::Deserialize;
use tokio::sync::{Mutex as AsyncMutex, RwLock};
use tokio::time::Instant;

/// How long API Gateway waits for an identity provider.
const FETCH_TIMEOUT: Duration = Duration::from_millis(1500);
/// The most the gateway reads from an identity provider in one response.
const MAX_RESPONSE_BYTES: usize = 150 * 1024;
/// API Gateway caches an issuer's keys for two hours.
const KEY_TTL: Duration = Duration::from_hours(2);
/// The soonest the keys of one issuer are fetched again, so tokens naming
/// unknown keys cannot turn the gateway into a request amplifier.
const MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(30);

/// A token issuer, exactly as an authorizer's definition spells it: tokens
/// must carry this string as `iss`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct Issuer(String);

impl Issuer {
    pub(super) fn new(url: impl Into<String>) -> Self {
        Self(url.into())
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

/// How an issuer's keys are located.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyLocation {
    /// `OpenID` Connect discovery (`/.well-known/openid-configuration`), which
    /// names the key set: HTTP API JWT authorizers.
    Discovery,
    /// The key set at `/.well-known/jwks.json`: Cognito user pools.
    WellKnownJwks,
}

#[derive(Debug, thiserror::Error)]
pub(super) enum KeyError {
    #[error("fetching {url} failed: {reason}")]
    Fetch { url: String, reason: String },
    #[error("{url} answered {status}")]
    Status { url: String, status: u16 },
    #[error("{url} sent more than {MAX_RESPONSE_BYTES} bytes")]
    TooLarge { url: String },
    #[error("{url} sent an unusable document: {reason}")]
    Malformed { url: String, reason: String },
    #[error("{0} is not an acceptable key location")]
    Location(String),
    #[error("the issuer has no usable key with id {0:?}")]
    UnknownKey(String),
    #[error("keys were fetched too recently to fetch them again")]
    Throttled,
}

/// Where to fetch an issuer's keys from instead of the issuer itself, for an
/// in-cluster mirror of the identity provider or for tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IssuerEndpoint(String, Url);

impl FromStr for IssuerEndpoint {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let (issuer, url) = raw
            .split_once('=')
            .ok_or_else(|| format!("expected ISSUER=URL, got {raw:?}"))?;
        if issuer.is_empty() {
            return Err(format!("expected ISSUER=URL, got {raw:?}"));
        }
        let url = Url::parse(url).map_err(|e| format!("invalid URL in {raw:?}: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err(format!("{url} must be an http or https URL"));
        }
        Ok(Self(issuer.to_owned(), url))
    }
}

impl IssuerEndpoint {
    /// Whether keys are fetched over plain HTTP, which the operator should know.
    pub(crate) fn is_plaintext(&self) -> bool {
        self.1.scheme() == "http"
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct IssuerEndpoints(BTreeMap<String, Url>);

impl FromIterator<IssuerEndpoint> for IssuerEndpoints {
    fn from_iter<I: IntoIterator<Item = IssuerEndpoint>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(|IssuerEndpoint(issuer, url)| (issuer, url))
                .collect(),
        )
    }
}

/// Timing of key caching, adjustable so tests need not wait.
#[derive(Debug, Clone, Copy)]
struct KeyTiming {
    ttl: Duration,
    min_refresh_interval: Duration,
}

impl Default for KeyTiming {
    fn default() -> Self {
        Self {
            ttl: KEY_TTL,
            min_refresh_interval: MIN_REFRESH_INTERVAL,
        }
    }
}

#[derive(Debug)]
struct CachedKeys {
    keys: Vec<Jwk>,
    fetched: Instant,
}

/// One issuer's cache. Readers never wait for a fetch: one task at a time
/// refreshes (`refresh` holds the time of the last attempt) while the others
/// keep reading the keys that are still fresh.
#[derive(Debug, Default)]
struct IssuerKeys {
    cache: RwLock<Option<CachedKeys>>,
    refresh: AsyncMutex<Option<Instant>>,
}

impl IssuerKeys {
    async fn fresh_key(&self, kid: &str, ttl: Duration) -> Option<Jwk> {
        let cache = self.cache.read().await;
        let cached = cache
            .as_ref()
            .filter(|cached| cached.fetched.elapsed() < ttl)?;
        cached
            .keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .cloned()
    }
}

#[derive(Deserialize)]
struct DiscoveryDocument {
    issuer: Option<String>,
    jwks_uri: String,
}

/// The fetched and cached keys of every issuer a loaded API uses. Shared by
/// every API definition so a refresh of the API does not refetch keys.
#[derive(Debug)]
pub(crate) struct KeyStore {
    http: reqwest::Client,
    endpoints: IssuerEndpoints,
    timing: KeyTiming,
    issuers: Mutex<HashMap<Issuer, Arc<IssuerKeys>>>,
}

impl KeyStore {
    pub(crate) fn new(
        http: reqwest::Client,
        endpoints: impl IntoIterator<Item = IssuerEndpoint>,
    ) -> Self {
        Self {
            http,
            endpoints: endpoints.into_iter().collect(),
            timing: KeyTiming::default(),
            issuers: Mutex::new(HashMap::new()),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_timing(mut self, ttl: Duration, min_refresh_interval: Duration) -> Self {
        self.timing = KeyTiming {
            ttl,
            min_refresh_interval,
        };
        self
    }

    fn issuer_keys(&self, issuer: &Issuer) -> Arc<IssuerKeys> {
        let mut issuers = self.issuers.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(issuers.entry(issuer.clone()).or_default())
    }

    /// The key `kid` of `issuer`. A key that is not cached triggers a fetch,
    /// at most once per refresh interval, so rotated keys are picked up.
    ///
    /// # Errors
    ///
    /// When the issuer's keys cannot be fetched or hold no usable key `kid`.
    pub(super) async fn key(
        &self,
        issuer: &Issuer,
        location: KeyLocation,
        kid: &str,
    ) -> Result<Jwk, KeyError> {
        let entry = self.issuer_keys(issuer);
        if let Some(jwk) = entry.fresh_key(kid, self.timing.ttl).await {
            return Ok(jwk);
        }
        let mut last_attempt = entry.refresh.lock().await;
        // Another task may have refreshed while this one waited.
        if let Some(jwk) = entry.fresh_key(kid, self.timing.ttl).await {
            return Ok(jwk);
        }
        let now = Instant::now();
        if last_attempt.is_some_and(|at| now.duration_since(at) < self.timing.min_refresh_interval)
        {
            return Err(KeyError::Throttled);
        }
        *last_attempt = Some(now);
        let keys = self.fetch(issuer, location).await?;
        let found = keys
            .iter()
            .find(|jwk| jwk.common.key_id.as_deref() == Some(kid))
            .cloned();
        *entry.cache.write().await = Some(CachedKeys {
            keys,
            fetched: Instant::now(),
        });
        found.ok_or_else(|| KeyError::UnknownKey(kid.to_owned()))
    }

    /// Where requests for `issuer` go: its override if it has one.
    pub(super) fn base(&self, issuer: &Issuer) -> Result<Url, KeyError> {
        match self.endpoints.0.get(issuer.as_str()) {
            Some(url) => Ok(url.clone()),
            None => Url::parse(issuer.as_str())
                .ok()
                .filter(|url| url.scheme() == "https")
                .ok_or_else(|| KeyError::Location(issuer.as_str().to_owned())),
        }
    }

    async fn fetch(&self, issuer: &Issuer, location: KeyLocation) -> Result<Vec<Jwk>, KeyError> {
        let base = self.base(issuer)?;
        let well_known = |name: &str| {
            let path = format!("{}/.well-known/{name}", base.as_str().trim_end_matches('/'));
            Url::parse(&path).map_err(|_| KeyError::Location(path))
        };
        let jwks_url = match location {
            KeyLocation::WellKnownJwks => well_known("jwks.json")?,
            KeyLocation::Discovery => {
                let url = well_known("openid-configuration")?;
                let document: DiscoveryDocument = self.get_json(&url).await?;
                if document
                    .issuer
                    .as_deref()
                    .is_some_and(|i| i != issuer.as_str())
                {
                    return Err(KeyError::Malformed {
                        url: url.to_string(),
                        reason: "the document names a different issuer".to_owned(),
                    });
                }
                let jwks_url = Url::parse(&document.jwks_uri)
                    .map_err(|_| KeyError::Location(document.jwks_uri.clone()))?;
                if !Self::jwks_uri_allowed(&jwks_url, &base) {
                    return Err(KeyError::Location(document.jwks_uri));
                }
                jwks_url
            }
        };
        let set: JwkSet = self.get_json(&jwks_url).await?;
        Ok(set
            .keys
            .into_iter()
            .filter(|jwk| {
                matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
                    && jwk.common.key_id.is_some()
                    && jwk
                        .common
                        .public_key_use
                        .as_ref()
                        .is_none_or(|usage| *usage == PublicKeyUse::Signature)
            })
            .collect())
    }

    /// Keys travel over TLS unless the operator pointed this issuer at a
    /// plaintext mirror, in which case a plaintext key set is fine too.
    pub(super) fn jwks_uri_allowed(jwks_uri: &Url, base: &Url) -> bool {
        jwks_uri.scheme() == "https" || (jwks_uri.scheme() == "http" && base.scheme() == "http")
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, url: &Url) -> Result<T, KeyError> {
        let body = self.get_limited(url).await?;
        serde_json::from_slice(&body).map_err(|e| KeyError::Malformed {
            url: url.to_string(),
            reason: e.to_string(),
        })
    }

    /// A GET that gives up after 1.5 s and refuses a body over 150 KB.
    async fn get_limited(&self, url: &Url) -> Result<Vec<u8>, KeyError> {
        let fail = |reason: String| KeyError::Fetch {
            url: url.to_string(),
            reason,
        };
        let mut response = self
            .http
            .get(url.clone())
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|e| fail(e.to_string()))?;
        if !response.status().is_success() {
            return Err(KeyError::Status {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }
        let too_large = || KeyError::TooLarge {
            url: url.to_string(),
        };
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(too_large());
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| fail(e.to_string()))? {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}
