//! A time-to-live cache with bounded entries and bytes, evicting the least
//! recently used entry first. Backs API Gateway's response cache.

use std::num::NonZeroUsize;
use std::time::Duration;

use axum::body::Bytes;
use jiff::{SignedDuration, Timestamp};

use super::StateKey;
use super::lru::Lru;

/// How much a [`TtlCache`] may hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CacheLimits {
    pub(crate) max_entries: NonZeroUsize,
    pub(crate) max_bytes: usize,
}

#[derive(Debug)]
struct Entry {
    value: Bytes,
    expires: Timestamp,
}

/// Whether [`TtlCache::put`] stored the value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheStore {
    Stored,
    /// The value alone exceeds the cache's byte limit, or its expiry is not
    /// representable.
    Rejected,
}

#[derive(Debug)]
pub(crate) struct TtlCache {
    entries: Lru<Entry>,
    bytes: usize,
    max_bytes: usize,
}

impl TtlCache {
    pub(crate) fn new(limits: CacheLimits) -> Self {
        Self {
            entries: Lru::new(limits.max_entries),
            bytes: 0,
            max_bytes: limits.max_bytes,
        }
    }

    /// The value for `key` if it has not expired. An expired entry is dropped.
    pub(crate) fn get(&mut self, key: &StateKey, now: Timestamp) -> Option<Bytes> {
        let entry = self.entries.get_mut(key)?;
        if entry.expires > now {
            return Some(entry.value.clone());
        }
        self.remove(key);
        None
    }

    /// Stores `value` for `ttl`, evicting least recently used entries to stay
    /// within the limits.
    pub(crate) fn put(
        &mut self,
        key: StateKey,
        value: Bytes,
        ttl: Duration,
        now: Timestamp,
    ) -> CacheStore {
        let expires = SignedDuration::try_from(ttl)
            .ok()
            .and_then(|ttl| now.checked_add(ttl).ok());
        let Some(expires) = expires else {
            return CacheStore::Rejected;
        };
        if value.len() > self.max_bytes {
            return CacheStore::Rejected;
        }
        self.bytes = self.bytes.saturating_add(value.len());
        let displaced = self.entries.insert(key, Entry { value, expires });
        for entry in displaced {
            self.bytes = self.bytes.saturating_sub(entry.value.len());
        }
        while self.bytes > self.max_bytes {
            let Some(evicted) = self.entries.pop_oldest() else {
                break;
            };
            self.bytes = self.bytes.saturating_sub(evicted.value.len());
        }
        CacheStore::Stored
    }

    /// Drops `key`, as a cache invalidation does.
    pub(crate) fn remove(&mut self, key: &StateKey) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(entry.value.len());
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn at(seconds: i64) -> Timestamp {
        Timestamp::from_second(seconds).unwrap()
    }

    fn key(name: &str) -> StateKey {
        StateKey::new("c", &[name])
    }

    fn cache(entries: usize, bytes: usize) -> TtlCache {
        TtlCache::new(CacheLimits {
            max_entries: NonZeroUsize::new(entries).unwrap(),
            max_bytes: bytes,
        })
    }

    #[test]
    fn entries_expire_after_their_ttl() {
        let mut cache = cache(4, 100);
        let ttl = Duration::from_secs(10);
        assert_eq!(
            cache.put(key("a"), Bytes::from_static(b"v"), ttl, at(0)),
            CacheStore::Stored
        );
        assert_eq!(cache.get(&key("a"), at(9)), Some(Bytes::from_static(b"v")));
        assert_eq!(cache.get(&key("a"), at(10)), None);
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.bytes, 0);
    }

    #[test]
    fn oversized_values_and_unrepresentable_ttls_are_rejected() {
        let mut cache = cache(4, 3);
        let ttl = Duration::from_secs(10);
        assert_eq!(
            cache.put(key("big"), Bytes::from_static(b"1234"), ttl, at(0)),
            CacheStore::Rejected
        );
        assert_eq!(
            cache.put(key("a"), Bytes::new(), Duration::MAX, at(0)),
            CacheStore::Rejected
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn byte_limit_evicts_least_recently_used() {
        let mut cache = cache(10, 4);
        let ttl = Duration::from_secs(100);
        cache.put(key("a"), Bytes::from_static(b"12"), ttl, at(0));
        cache.put(key("b"), Bytes::from_static(b"12"), ttl, at(0));
        assert!(cache.get(&key("a"), at(1)).is_some());
        cache.put(key("c"), Bytes::from_static(b"12"), ttl, at(1));
        assert!(cache.get(&key("b"), at(2)).is_none());
        assert!(cache.get(&key("a"), at(2)).is_some());
        assert!(cache.get(&key("c"), at(2)).is_some());
        assert_eq!(cache.bytes, 4);
    }

    #[test]
    fn replacing_and_removing_keep_the_byte_count_exact() {
        let mut cache = cache(4, 100);
        let ttl = Duration::from_secs(100);
        cache.put(key("a"), Bytes::from_static(b"1234"), ttl, at(0));
        cache.put(key("a"), Bytes::from_static(b"12"), ttl, at(0));
        assert_eq!(cache.bytes, 2);
        cache.remove(&key("a"));
        cache.remove(&key("a"));
        assert_eq!(cache.bytes, 0);
    }

    proptest! {
        /// Whatever is stored, the cache stays within its entry and byte
        /// limits and its byte count matches what it holds.
        #[test]
        fn stays_within_limits(
            max_entries in 1_usize..6,
            max_bytes in 0_usize..32,
            ops in proptest::collection::vec((0_u8..8, 0_usize..40, 0_i64..30), 0..100),
        ) {
            let mut cache = cache(max_entries, max_bytes);
            for (name, size, second) in ops {
                let key = key(&name.to_string());
                if size.is_multiple_of(5) {
                    cache.get(&key, at(second));
                } else {
                    cache.put(key, Bytes::from(vec![0_u8; size]), Duration::from_secs(10), at(second));
                }
                prop_assert!(cache.len() <= max_entries);
                prop_assert!(cache.bytes <= max_bytes);
            }
        }

        /// A value is never returned at or after its expiry.
        #[test]
        fn never_returns_expired_values(ttl in 1_u64..100, read in 0_i64..300) {
            let mut cache = cache(2, 16);
            cache.put(key("a"), Bytes::from_static(b"v"), Duration::from_secs(ttl), at(0));
            let hit = cache.get(&key("a"), at(read)).is_some();
            let live = u64::try_from(read).is_ok_and(|read| read < ttl);
            prop_assert_eq!(hit, live);
        }
    }
}
