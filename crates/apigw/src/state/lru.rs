//! A bounded map that evicts the least recently used entry, shared by the
//! in-memory buckets, quota counters, and cache.

use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;

use super::StateKey;

#[derive(Debug)]
struct Slot<V> {
    value: V,
    tick: u64,
}

/// A map holding at most `capacity` entries. Every access stamps the entry
/// with a fresh tick; the entry with the oldest tick is evicted first.
#[derive(Debug)]
pub(super) struct Lru<V> {
    entries: HashMap<StateKey, Slot<V>>,
    order: BTreeMap<u64, StateKey>,
    tick: u64,
    capacity: NonZeroUsize,
}

impl<V> Lru<V> {
    pub(super) fn new(capacity: NonZeroUsize) -> Self {
        Self {
            entries: HashMap::new(),
            order: BTreeMap::new(),
            tick: 0,
            capacity,
        }
    }

    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    // 2^64 accesses cannot happen, so saturating never merges two ticks.
    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.saturating_add(1);
        self.tick
    }

    /// The value for `key`, marking it most recently used.
    pub(super) fn get_mut(&mut self, key: &StateKey) -> Option<&mut V> {
        let tick = self.next_tick();
        let slot = self.entries.get_mut(key)?;
        self.order.remove(&slot.tick);
        self.order.insert(tick, key.clone());
        slot.tick = tick;
        Some(&mut slot.value)
    }

    /// Stores `value` as the most recently used entry and returns every value
    /// that left the map to make room: the one `key` previously held, then
    /// evictions, oldest first.
    pub(super) fn insert(&mut self, key: StateKey, value: V) -> Vec<V> {
        let mut displaced = Vec::new();
        let tick = self.next_tick();
        if let Some(old) = self.entries.insert(key.clone(), Slot { value, tick }) {
            self.order.remove(&old.tick);
            displaced.push(old.value);
        }
        self.order.insert(tick, key);
        while self.entries.len() > self.capacity.get() {
            match self.pop_oldest() {
                Some(evicted) => displaced.push(evicted),
                None => break,
            }
        }
        displaced
    }

    pub(super) fn remove(&mut self, key: &StateKey) -> Option<V> {
        let slot = self.entries.remove(key)?;
        self.order.remove(&slot.tick);
        Some(slot.value)
    }

    /// Removes and returns the least recently used value.
    pub(super) fn pop_oldest(&mut self) -> Option<V> {
        let (_, key) = self.order.pop_first()?;
        self.entries.remove(&key).map(|slot| slot.value)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn key(name: &str) -> StateKey {
        StateKey::new("t", &[name])
    }

    fn lru(capacity: usize) -> Lru<u32> {
        Lru::new(NonZeroUsize::new(capacity).unwrap())
    }

    #[test]
    fn evicts_the_least_recently_used_entry() {
        let mut map = lru(2);
        assert!(map.insert(key("a"), 1).is_empty());
        assert!(map.insert(key("b"), 2).is_empty());
        assert_eq!(map.get_mut(&key("a")), Some(&mut 1));
        assert_eq!(map.insert(key("c"), 3), vec![2]);
        assert!(map.get_mut(&key("b")).is_none());
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn replacing_a_key_returns_the_old_value() {
        let mut map = lru(2);
        map.insert(key("a"), 1);
        assert_eq!(map.insert(key("a"), 5), vec![1]);
        assert_eq!(map.len(), 1);
        assert_eq!(map.remove(&key("a")), Some(5));
        assert_eq!(map.remove(&key("a")), None);
        assert_eq!(map.pop_oldest(), None);
    }

    proptest! {
        #[test]
        fn never_exceeds_capacity_and_indexes_stay_consistent(
            capacity in 1_usize..8,
            ops in proptest::collection::vec((0_u8..12, any::<bool>()), 0..200),
        ) {
            let mut map = lru(capacity);
            for (name, insert) in ops {
                let key = key(&name.to_string());
                if insert {
                    map.insert(key, u32::from(name));
                } else {
                    map.get_mut(&key);
                }
                prop_assert!(map.len() <= capacity);
                prop_assert_eq!(map.entries.len(), map.order.len());
            }
        }
    }
}
