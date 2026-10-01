//! The per-replica backend: everything lives in this process, bounded by
//! [`InMemoryLimits`].

use std::num::NonZeroUsize;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::body::Bytes;
use jiff::Timestamp;

use super::StateError;
use super::StateKey;
use super::bucket::{Admission, BucketLimits, TokenBucket};
use super::cache::{CacheLimits, CacheStore, TtlCache};
use super::lru::Lru;
use super::quota::{QuotaCounter, QuotaDecision, QuotaLimit};

/// A mutex whose protected state stays usable if a holder panicked: nothing
/// in this module panics while holding one, and a bucket or counter is valid
/// after any complete update.
#[derive(Debug)]
struct Guarded<T>(Mutex<T>);

impl<T> Guarded<T> {
    fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How much the in-memory backend may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct InMemoryLimits {
    pub(crate) max_buckets: NonZeroUsize,
    pub(crate) max_quota_counters: NonZeroUsize,
    pub(crate) cache: CacheLimits,
}

impl Default for InMemoryLimits {
    /// 100,000 buckets and counters, and a cache of up to 10,000 entries and
    /// 256 MiB.
    fn default() -> Self {
        let count = |n: usize| NonZeroUsize::new(n).unwrap_or(NonZeroUsize::MIN);
        Self {
            max_buckets: count(100_000),
            max_quota_counters: count(100_000),
            cache: CacheLimits {
                max_entries: count(10_000),
                max_bytes: 256 * 1024 * 1024,
            },
        }
    }
}

/// Token buckets, quota counters, and a TTL cache held in this process.
#[derive(Debug)]
pub(crate) struct InMemory {
    buckets: Guarded<Lru<TokenBucket>>,
    quotas: Guarded<Lru<QuotaCounter>>,
    cache: Guarded<TtlCache>,
}

impl InMemory {
    pub(crate) fn new(limits: InMemoryLimits) -> Self {
        Self {
            buckets: Guarded::new(Lru::new(limits.max_buckets)),
            quotas: Guarded::new(Lru::new(limits.max_quota_counters)),
            cache: Guarded::new(TtlCache::new(limits.cache)),
        }
    }

    pub(crate) fn take_token(
        &self,
        key: &StateKey,
        limits: BucketLimits,
        now: Timestamp,
    ) -> Admission {
        let mut buckets = self.buckets.lock();
        if let Some(bucket) = buckets.get_mut(key) {
            return bucket.take(limits, now);
        }
        let mut bucket = TokenBucket::full(limits, now);
        let admission = bucket.take(limits, now);
        buckets.insert(key.clone(), bucket);
        admission
    }

    pub(crate) fn consume_quota(
        &self,
        key: &StateKey,
        quota: QuotaLimit,
        now: Timestamp,
    ) -> Result<QuotaDecision, StateError> {
        let window = quota
            .period
            .window(now)
            .ok_or(StateError::ClockOutOfRange)?;
        let mut quotas = self.quotas.lock();
        if let Some(counter) = quotas.get_mut(key) {
            return Ok(counter.consume(quota.limit, window));
        }
        let mut counter = QuotaCounter::new(window);
        let decision = counter.consume(quota.limit, window);
        quotas.insert(key.clone(), counter);
        Ok(decision)
    }

    pub(crate) fn cache_get(&self, key: &StateKey, now: Timestamp) -> Option<Bytes> {
        self.cache.lock().get(key, now)
    }

    pub(crate) fn cache_put(
        &self,
        key: StateKey,
        value: Bytes,
        ttl: Duration,
        now: Timestamp,
    ) -> CacheStore {
        self.cache.lock().put(key, value, ttl, now)
    }

    pub(crate) fn cache_invalidate(&self, key: &StateKey) {
        self.cache.lock().remove(key);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;
    use crate::state::quota::QuotaPeriod;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    fn small() -> InMemory {
        InMemory::new(InMemoryLimits {
            max_buckets: NonZeroUsize::new(2).unwrap(),
            max_quota_counters: NonZeroUsize::new(2).unwrap(),
            cache: CacheLimits {
                max_entries: NonZeroUsize::new(2).unwrap(),
                max_bytes: 8,
            },
        })
    }

    #[test]
    fn buckets_are_independent_per_key() {
        let memory = small();
        let limits = BucketLimits::new(0.0, 1.0).unwrap();
        let (a, b) = (StateKey::new("t", &["a"]), StateKey::new("t", &["b"]));
        assert_eq!(memory.take_token(&a, limits, at(0)), Admission::Admitted);
        assert_eq!(memory.take_token(&a, limits, at(0)), Admission::Throttled);
        assert_eq!(memory.take_token(&b, limits, at(0)), Admission::Admitted);
    }

    #[test]
    fn a_new_bucket_with_zero_burst_throttles_its_first_request() {
        let memory = small();
        let limits = BucketLimits::new(10.0, 0.0).unwrap();
        let key = StateKey::new("t", &["zero"]);
        assert_eq!(memory.take_token(&key, limits, at(0)), Admission::Throttled);
    }

    #[test]
    fn idle_buckets_are_evicted_to_bound_memory() {
        let memory = small();
        let limits = BucketLimits::new(0.0, 1.0).unwrap();
        for name in ["a", "b", "c"] {
            memory.take_token(&StateKey::new("t", &[name]), limits, at(0));
        }
        assert_eq!(memory.buckets.lock().len(), 2);
        let a = StateKey::new("t", &["a"]);
        assert_eq!(memory.take_token(&a, limits, at(0)), Admission::Admitted);
    }

    #[test]
    fn quotas_count_per_key_and_bound_memory() {
        let memory = small();
        let quota = QuotaLimit {
            limit: 1,
            period: QuotaPeriod::Day,
        };
        let key = StateKey::new("q", &["k"]);
        assert!(matches!(
            memory.consume_quota(&key, quota, at(0)).unwrap(),
            QuotaDecision::Allowed { remaining: 0 }
        ));
        assert!(matches!(
            memory.consume_quota(&key, quota, at(1)).unwrap(),
            QuotaDecision::Exceeded { .. }
        ));
        assert!(matches!(
            memory.consume_quota(&key, quota, at(86_400)).unwrap(),
            QuotaDecision::Allowed { .. }
        ));
        for name in ["x", "y", "z"] {
            memory
                .consume_quota(&StateKey::new("q", &[name]), quota, at(0))
                .unwrap();
        }
        assert_eq!(memory.quotas.lock().len(), 2);
    }

    #[test]
    fn cache_expires_and_invalidates() {
        let memory = small();
        let key = StateKey::new("c", &["k"]);
        let ttl = Duration::from_secs(10);
        let value = Bytes::from_static(b"abc");
        assert_eq!(
            memory.cache_put(key.clone(), value.clone(), ttl, at(0)),
            CacheStore::Stored
        );
        assert_eq!(memory.cache_get(&key, at(5)), Some(value));
        assert_eq!(memory.cache_get(&key, at(10)), None);
        memory.cache_put(key.clone(), Bytes::from_static(b"abc"), ttl, at(0));
        memory.cache_invalidate(&key);
        assert_eq!(memory.cache_get(&key, at(1)), None);
    }
}
