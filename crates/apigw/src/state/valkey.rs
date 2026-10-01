//! A Valkey (or Redis-compatible) backend: state shared by every replica, so
//! throttles and quotas are exact across the fleet and cached authorizer
//! results are computed once.
//!
//! Every operation is one command or one script on one key, so it is atomic and
//! needs no cross-key coordination (it works against a single endpoint,
//! including `ElastiCache` serverless, but does not follow cluster redirects).
//! Bucket refills use the server's clock, so replicas with skewed clocks agree.
//! Every call has a timeout: a slow server answers
//! [`StateError::Unavailable`] and callers degrade (requests are admitted,
//! cache lookups miss) instead of queueing behind it.
//!
//! Use `rediss://`: the connection carries credentials and caller identities.

use std::fmt;
use std::time::Duration;

use axum::body::Bytes;
use jiff::Timestamp;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use redis::{AsyncCommands as _, Client, Script, TlsCertificates};

use super::bucket::{Admission, BucketLimits};
use super::cache::CacheStore;
use super::quota::{QuotaDecision, QuotaLimit};
use super::{StateError, StateKey};

/// How long any one call may take.
const COMMAND_TIMEOUT: Duration = Duration::from_millis(500);
/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The largest value cached; anything bigger is not stored.
const MAX_CACHED_BYTES: usize = 4 * 1024 * 1024;
/// A bucket that is not touched for this long is dropped by the server. A
/// bucket idle long enough to be full again behaves as a new one.
const MAX_BUCKET_TTL: Duration = Duration::from_hours(24);
/// How long past the end of its period a quota counter is kept.
const QUOTA_GRACE: Duration = Duration::from_hours(24);

/// Takes a token from the bucket at KEYS[1], refilling it first.
/// ARGV: tokens per second, capacity, time-to-live in milliseconds.
/// Returns 1 when a token was taken and 0 when the bucket is empty.
const TAKE_TOKEN: &str = "
local time = redis.call('TIME')
local now = time[1] * 1000 + math.floor(time[2] / 1000)
local rate = tonumber(ARGV[1])
local capacity = tonumber(ARGV[2])
local state = redis.call('HMGET', KEYS[1], 'tokens', 'at')
local tokens = tonumber(state[1])
local at = tonumber(state[2])
if tokens == nil or at == nil then
  tokens = capacity
  at = now
end
local elapsed = math.max(0, now - at)
tokens = math.min(capacity, tokens + elapsed * rate / 1000)
local admitted = 0
if tokens >= 1 then
  tokens = tokens - 1
  admitted = 1
end
redis.call('HSET', KEYS[1], 'tokens', tostring(tokens), 'at', tostring(now))
redis.call('PEXPIRE', KEYS[1], ARGV[3])
return admitted
";

/// Counts one request in the counter at KEYS[1] unless it has reached the limit.
/// ARGV: limit, time-to-live in milliseconds.
/// Returns the requests remaining after this one, or -1 when the limit was reached.
const CONSUME_QUOTA: &str = "
local limit = tonumber(ARGV[1])
local used = tonumber(redis.call('GET', KEYS[1]) or '0')
if used >= limit then
  return -1
end
used = redis.call('INCR', KEYS[1])
if used == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[2])
end
return limit - used
";

#[derive(Debug, thiserror::Error)]
pub(crate) enum ValkeyError {
    #[error("the Valkey URL must look like rediss://host:port")]
    InvalidUrl,
    #[error("could not use the CA certificate: {0}")]
    CaCertificate(String),
    #[error("could not connect to {server}: {reason}")]
    Connect { server: String, reason: String },
}

/// Where the server is. The URL may carry a password, so it is never shown
/// whole: [`fmt::Display`] and [`fmt::Debug`] omit the credentials.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ValkeyUrl(String);

impl ValkeyUrl {
    const PLAIN: &'static str = "redis://";
    const TLS: &'static str = "rediss://";

    fn scheme(&self) -> &'static str {
        if self.0.starts_with(Self::TLS) {
            Self::TLS
        } else {
            Self::PLAIN
        }
    }

    fn authority_and_tail(&self) -> (&str, &str) {
        let rest = self.0.get(self.scheme().len()..).unwrap_or_default();
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        rest.split_at_checked(end).unwrap_or((rest, ""))
    }

    fn host(&self) -> &str {
        let (authority, _) = self.authority_and_tail();
        authority
            .rsplit_once('@')
            .map_or(authority, |(_, host)| host)
    }

    /// The URL without credentials, for logs.
    fn redacted(&self) -> String {
        let (_, tail) = self.authority_and_tail();
        format!("{}{}{tail}", self.scheme(), self.host())
    }

    /// Whether the connection is not encrypted.
    pub(crate) fn is_plaintext(&self) -> bool {
        self.scheme() == Self::PLAIN
    }

    fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::str::FromStr for ValkeyUrl {
    type Err = ValkeyError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        let url = Self(raw.to_owned());
        let has_scheme = raw.starts_with(Self::PLAIN) || raw.starts_with(Self::TLS);
        if has_scheme && !url.host().is_empty() {
            Ok(url)
        } else {
            Err(ValkeyError::InvalidUrl)
        }
    }
}

impl fmt::Display for ValkeyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.redacted())
    }
}

impl fmt::Debug for ValkeyUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("ValkeyUrl").field(&self.redacted()).finish()
    }
}

/// The state kept in Valkey.
pub(crate) struct Valkey {
    connection: ConnectionManager,
    take_token: Script,
    consume_quota: Script,
    timeout: Duration,
}

impl fmt::Debug for Valkey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Valkey")
    }
}

impl Valkey {
    /// Connects to the server. `ca_pem` adds a root certificate to trust for a
    /// `rediss://` server whose certificate the system roots do not cover.
    ///
    /// # Errors
    ///
    /// When the CA certificate is unusable or the server cannot be reached.
    pub(crate) async fn connect(
        url: &ValkeyUrl,
        ca_pem: Option<&[u8]>,
    ) -> Result<Self, ValkeyError> {
        let server = url.redacted();
        let client = match ca_pem {
            Some(pem) => Client::build_with_tls(
                url.as_str(),
                TlsCertificates {
                    client_tls: None,
                    root_cert: Some(pem.to_vec()),
                },
            )
            .map_err(|e| ValkeyError::CaCertificate(e.to_string()))?,
            None => Client::open(url.as_str()).map_err(|e| ValkeyError::Connect {
                server: server.clone(),
                reason: e.to_string(),
            })?,
        };
        let config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(CONNECT_TIMEOUT))
            .set_response_timeout(Some(COMMAND_TIMEOUT));
        let connection = tokio::time::timeout(
            CONNECT_TIMEOUT,
            ConnectionManager::new_with_config(client, config),
        )
        .await
        .map_err(|_| ValkeyError::Connect {
            server: server.clone(),
            reason: "timed out".to_owned(),
        })?
        .map_err(|e| ValkeyError::Connect {
            server,
            reason: e.to_string(),
        })?;
        Ok(Self {
            connection,
            take_token: Script::new(TAKE_TOKEN),
            consume_quota: Script::new(CONSUME_QUOTA),
            timeout: COMMAND_TIMEOUT,
        })
    }

    fn unavailable(error: impl fmt::Display) -> StateError {
        StateError::Unavailable(error.to_string())
    }

    /// Runs `call` with the command timeout.
    async fn timed<T>(
        &self,
        call: impl Future<Output = redis::RedisResult<T>>,
    ) -> Result<T, StateError> {
        match tokio::time::timeout(self.timeout, call).await {
            Ok(Ok(value)) => Ok(value),
            Ok(Err(error)) => Err(Self::unavailable(error)),
            Err(_) => Err(Self::unavailable("timed out")),
        }
    }

    fn name(key: &StateKey) -> String {
        format!("apigw:{}", key.as_str())
    }

    /// Milliseconds, at least one.
    fn millis(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis())
            .unwrap_or(u64::MAX)
            .max(1)
    }

    /// How long a bucket must outlive its last use: the time to refill from
    /// empty, plus a minute, at most a day.
    fn bucket_ttl(limits: BucketLimits) -> Duration {
        let refill = if limits.rate_per_second() > 0.0 {
            Duration::try_from_secs_f64(limits.capacity() / limits.rate_per_second())
                .unwrap_or(MAX_BUCKET_TTL)
        } else {
            MAX_BUCKET_TTL
        };
        refill
            .saturating_add(Duration::from_mins(1))
            .min(MAX_BUCKET_TTL)
    }

    pub(crate) async fn take_token(
        &self,
        key: &StateKey,
        limits: BucketLimits,
    ) -> Result<Admission, StateError> {
        let mut connection = self.connection.clone();
        let admitted: i64 = self
            .timed(
                self.take_token
                    .key(Self::name(key))
                    .arg(limits.rate_per_second())
                    .arg(limits.capacity())
                    .arg(Self::millis(Self::bucket_ttl(limits)))
                    .invoke_async(&mut connection),
            )
            .await?;
        Ok(if admitted == 1 {
            Admission::Admitted
        } else {
            Admission::Throttled
        })
    }

    pub(crate) async fn consume_quota(
        &self,
        key: &StateKey,
        quota: QuotaLimit,
        now: Timestamp,
    ) -> Result<QuotaDecision, StateError> {
        let window = quota
            .period
            .window(now)
            .ok_or(StateError::ClockOutOfRange)?;
        // One counter per window, so a new window starts from zero.
        let name = format!("{}:{}", Self::name(key), window.start.as_second());
        let remaining_in_window = window
            .end
            .duration_since(now)
            .try_into()
            .unwrap_or(Duration::ZERO);
        let ttl = remaining_in_window.saturating_add(QUOTA_GRACE);
        let mut connection = self.connection.clone();
        let remaining: i64 = self
            .timed(
                self.consume_quota
                    .key(name)
                    .arg(quota.limit)
                    .arg(Self::millis(ttl))
                    .invoke_async(&mut connection),
            )
            .await?;
        Ok(match u64::try_from(remaining) {
            Ok(remaining) => QuotaDecision::Allowed { remaining },
            Err(_) => QuotaDecision::Exceeded {
                resets_at: window.end,
            },
        })
    }

    pub(crate) async fn cache_get(&self, key: &StateKey) -> Result<Option<Bytes>, StateError> {
        let mut connection = self.connection.clone();
        let value: Option<Vec<u8>> = self.timed(connection.get(Self::name(key))).await?;
        Ok(value.map(Bytes::from))
    }

    pub(crate) async fn cache_put(
        &self,
        key: &StateKey,
        value: &Bytes,
        ttl: Duration,
    ) -> Result<CacheStore, StateError> {
        if ttl.is_zero() || value.len() > MAX_CACHED_BYTES {
            return Ok(CacheStore::Rejected);
        }
        let mut connection = self.connection.clone();
        self.timed(connection.set_options::<_, _, ()>(
            Self::name(key),
            value.as_ref(),
            redis::SetOptions::default().with_expiration(redis::SetExpiry::PX(Self::millis(ttl))),
        ))
        .await?;
        Ok(CacheStore::Stored)
    }

    pub(crate) async fn cache_invalidate(&self, key: &StateKey) -> Result<(), StateError> {
        let mut connection = self.connection.clone();
        self.timed(connection.del::<_, ()>(Self::name(key))).await
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests;
