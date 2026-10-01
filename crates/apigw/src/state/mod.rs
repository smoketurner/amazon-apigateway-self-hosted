//! State that outlives a request: throttling buckets, usage-plan quotas, and
//! the response cache.
//!
//! [`StateBackend`] is an enum rather than a trait object: the set of backends
//! is closed (in memory, and a Valkey backend that shares state between
//! replicas), an enum keeps the async methods without boxing or an
//! `async-trait` dependency, and every `match` over it is checked for
//! exhaustiveness when a backend is added. To add one, add a variant, one arm
//! per method, and a module next to [`memory`].
#![expect(
    dead_code,
    reason = "quota counters, the cache, and networked-backend errors are consumed by usage plans, response caching, and the Valkey backend, which build on this module"
)]

mod bucket;
pub(crate) mod cache;
mod lru;
mod memory;
pub(crate) mod quota;

use std::sync::Arc;
use std::time::Duration;

use axum::body::Bytes;
use jiff::Timestamp;

pub(crate) use bucket::{Admission, BucketLimits};
pub(crate) use memory::{InMemory, InMemoryLimits};

use cache::CacheStore;
use quota::{QuotaDecision, QuotaLimit};

/// Identifies one bucket, counter, or cache entry. Parts are joined with `:`;
/// only the last part may itself contain a `:`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct StateKey(Arc<str>);

impl StateKey {
    pub(crate) fn new(namespace: &str, parts: &[&str]) -> Self {
        let mut key = String::from(namespace);
        for part in parts {
            key.push(':');
            key.push_str(part);
        }
        Self(key.into())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why a backend could not answer.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StateError {
    /// A timestamp is outside the range quota windows can be computed for.
    #[error("the clock is outside the supported date range")]
    ClockOutOfRange,
    /// A networked backend could not be reached.
    #[error("state backend unavailable: {0}")]
    Unavailable(String),
}

/// Where throttling, quota, and cache state lives.
#[derive(Debug)]
pub(crate) enum StateBackend {
    /// Per replica, in this process.
    InMemory(InMemory),
}

impl StateBackend {
    /// An in-memory backend with the default bounds, shared between requests.
    pub(crate) fn in_memory() -> Arc<Self> {
        Arc::new(Self::InMemory(InMemory::new(InMemoryLimits::default())))
    }
}

impl StateBackend {
    /// Whether every replica sees the same state, so limits are exact rather
    /// than shared out between replicas.
    pub(crate) fn is_shared(&self) -> bool {
        match self {
            Self::InMemory(_) => false,
        }
    }
}

#[expect(
    clippy::unused_async,
    clippy::unused_async_trait_impl,
    reason = "every method is async for networked backends; the in-memory one never awaits"
)]
impl StateBackend {
    /// Takes one token from the bucket at `key`, creating it full.
    ///
    /// # Errors
    /// When the backend cannot answer.
    pub(crate) async fn take_token(
        &self,
        key: &StateKey,
        limits: BucketLimits,
    ) -> Result<Admission, StateError> {
        match self {
            Self::InMemory(memory) => Ok(memory.take_token(key, limits, Timestamp::now())),
        }
    }

    /// Counts one request against the quota at `key`.
    ///
    /// # Errors
    /// When the backend cannot answer.
    pub(crate) async fn consume_quota(
        &self,
        key: &StateKey,
        quota: QuotaLimit,
    ) -> Result<QuotaDecision, StateError> {
        match self {
            Self::InMemory(memory) => memory.consume_quota(key, quota, Timestamp::now()),
        }
    }

    /// The cached value at `key`, unless it has expired.
    ///
    /// # Errors
    /// When the backend cannot answer.
    pub(crate) async fn cache_get(&self, key: &StateKey) -> Result<Option<Bytes>, StateError> {
        match self {
            Self::InMemory(memory) => Ok(memory.cache_get(key, Timestamp::now())),
        }
    }

    /// Caches `value` at `key` for `ttl`.
    ///
    /// # Errors
    /// When the backend cannot answer.
    pub(crate) async fn cache_put(
        &self,
        key: StateKey,
        value: Bytes,
        ttl: Duration,
    ) -> Result<CacheStore, StateError> {
        match self {
            Self::InMemory(memory) => Ok(memory.cache_put(key, value, ttl, Timestamp::now())),
        }
    }

    /// Drops the cached value at `key`.
    ///
    /// # Errors
    /// When the backend cannot answer.
    pub(crate) async fn cache_invalidate(&self, key: &StateKey) -> Result<(), StateError> {
        match self {
            Self::InMemory(memory) => {
                memory.cache_invalidate(key);
                Ok(())
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;
    use crate::state::quota::QuotaPeriod;

    #[test]
    fn keys_join_parts_with_colons() {
        let key = StateKey::new("throttle", &["abc", "prod", "GET /a:b"]);
        assert_eq!(key.as_str(), "throttle:abc:prod:GET /a:b");
    }

    #[tokio::test]
    async fn backend_dispatches_each_operation() {
        let backend = StateBackend::InMemory(InMemory::new(InMemoryLimits::default()));
        let key = StateKey::new("t", &["k"]);
        let limits = BucketLimits::new(0.0, 2.0).unwrap();
        assert_eq!(
            backend.take_token(&key, limits).await.unwrap(),
            Admission::Admitted
        );
        assert_eq!(
            backend.take_token(&key, limits).await.unwrap(),
            Admission::Admitted
        );
        assert_eq!(
            backend.take_token(&key, limits).await.unwrap(),
            Admission::Throttled
        );

        let quota = QuotaLimit {
            limit: 1,
            period: QuotaPeriod::Month,
        };
        assert!(matches!(
            backend.consume_quota(&key, quota).await.unwrap(),
            QuotaDecision::Allowed { remaining: 0 }
        ));
        assert!(matches!(
            backend.consume_quota(&key, quota).await.unwrap(),
            QuotaDecision::Exceeded { .. }
        ));

        let value = Bytes::from_static(b"cached");
        assert_eq!(backend.cache_get(&key).await.unwrap(), None);
        assert_eq!(
            backend
                .cache_put(key.clone(), value.clone(), Duration::from_secs(60))
                .await
                .unwrap(),
            CacheStore::Stored
        );
        assert_eq!(backend.cache_get(&key).await.unwrap(), Some(value));
        backend.cache_invalidate(&key).await.unwrap();
        assert_eq!(backend.cache_get(&key).await.unwrap(), None);
    }
}
