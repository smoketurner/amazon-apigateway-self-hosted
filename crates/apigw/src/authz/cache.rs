//! A bounded in-memory cache with per-entry expiry, for authorizer results.
//!
//! TODO(#21): move onto the shared `StateBackend` TTL cache once it lands, so
//! replicas can share results.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug)]
struct Entry<V> {
    value: Arc<V>,
    expires: Instant,
}

/// A cache holding at most `capacity` unexpired entries. Callers choose each
/// entry's lifetime; an entry is never returned after it expires. When full,
/// expired entries are dropped first, then the entry closest to expiring, so a
/// client sending endless distinct credentials cannot grow memory.
#[derive(Debug)]
pub(crate) struct TtlCache<K, V> {
    entries: Mutex<HashMap<K, Entry<V>>>,
    capacity: usize,
}

impl<K: Eq + Hash + Clone, V> TtlCache<K, V> {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    pub(crate) fn get(&self, key: &K) -> Option<Arc<V>> {
        let now = Instant::now();
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        match entries.get(key) {
            Some(entry) if entry.expires > now => Some(Arc::clone(&entry.value)),
            Some(_) => {
                entries.remove(key);
                None
            }
            None => None,
        }
    }

    pub(crate) fn insert(&self, key: K, value: V, ttl: Duration) {
        let now = Instant::now();
        let Some(expires) = now.checked_add(ttl) else {
            return;
        };
        let mut entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        if entries.len() >= self.capacity && !entries.contains_key(&key) {
            entries.retain(|_, entry| entry.expires > now);
            if entries.len() >= self.capacity {
                let soonest = entries
                    .iter()
                    .min_by_key(|(_, entry)| entry.expires)
                    .map(|(key, _)| key.clone());
                if let Some(soonest) = soonest {
                    entries.remove(&soonest);
                }
            }
        }
        entries.insert(
            key,
            Entry {
                value: Arc::new(value),
                expires,
            },
        );
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(10);

    #[tokio::test(start_paused = true)]
    async fn entries_expire_exactly_at_their_ttl() {
        let cache = TtlCache::new(8);
        cache.insert("k", 1, TTL);
        assert_eq!(cache.get(&"k").as_deref(), Some(&1));
        tokio::time::advance(TTL.saturating_sub(Duration::from_millis(1))).await;
        assert_eq!(cache.get(&"k").as_deref(), Some(&1));
        tokio::time::advance(Duration::from_millis(1)).await;
        assert_eq!(cache.get(&"k"), None);
        assert_eq!(cache.len(), 0, "an expired entry is dropped when seen");
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_ttl_entry_is_never_returned() {
        let cache = TtlCache::new(8);
        cache.insert("k", 1, Duration::ZERO);
        assert_eq!(cache.get(&"k"), None);
    }

    #[tokio::test(start_paused = true)]
    async fn reinserting_replaces_the_value_and_lifetime() {
        let cache = TtlCache::new(8);
        cache.insert("k", 1, TTL);
        tokio::time::advance(Duration::from_secs(9)).await;
        cache.insert("k", 2, TTL);
        tokio::time::advance(Duration::from_secs(9)).await;
        assert_eq!(cache.get(&"k").as_deref(), Some(&2));
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_cache_drops_expired_entries_before_live_ones() {
        let cache = TtlCache::new(2);
        cache.insert("short", 1, Duration::from_secs(1));
        cache.insert("long", 2, Duration::from_secs(100));
        tokio::time::advance(Duration::from_secs(2)).await;
        cache.insert("new", 3, TTL);
        assert_eq!(cache.get(&"long").as_deref(), Some(&2));
        assert_eq!(cache.get(&"new").as_deref(), Some(&3));
        assert_eq!(cache.len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_full_cache_of_live_entries_evicts_the_soonest_to_expire() {
        let cache = TtlCache::new(2);
        cache.insert("soon", 1, Duration::from_secs(5));
        cache.insert("later", 2, Duration::from_secs(50));
        cache.insert("new", 3, Duration::from_secs(20));
        assert_eq!(cache.get(&"soon"), None);
        assert_eq!(cache.get(&"later").as_deref(), Some(&2));
        assert_eq!(cache.get(&"new").as_deref(), Some(&3));
    }

    #[tokio::test(start_paused = true)]
    async fn memory_stays_bounded_under_endless_distinct_keys() {
        let cache = TtlCache::new(16);
        for key in 0..1000_u32 {
            cache.insert(key, key, TTL);
        }
        assert_eq!(cache.len(), 16);
    }
}
