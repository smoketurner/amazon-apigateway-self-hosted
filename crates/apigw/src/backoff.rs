//! Exponential backoff with jitter, for work repeated against the control plane.

use std::time::Duration;

/// Spaces out refreshes after failures: the delay doubles per consecutive
/// failure up to [`Backoff::MAX`], with +/-20% jitter so replicas that failed
/// together don't retry together against the shared control-plane limit.
#[derive(Debug, Default)]
pub(crate) struct Backoff {
    failures: u32,
}

impl Backoff {
    pub(crate) const MAX: Duration = Duration::from_mins(15);

    pub(crate) fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    pub(crate) fn reset(&mut self) {
        self.failures = 0;
    }

    pub(crate) fn delay(&self, interval: Duration) -> Duration {
        let factor = 1_u32.checked_shl(self.failures).unwrap_or(u32::MAX);
        let base = interval
            .checked_mul(factor)
            .unwrap_or(Self::MAX)
            .min(Self::MAX);
        Self::jitter(base, Self::random())
    }

    /// Scales `base` into [80%, 120%] using `random`.
    pub(crate) fn jitter(base: Duration, random: u64) -> Duration {
        let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
        let spread = millis.checked_div(5).unwrap_or(0);
        let span = spread.saturating_mul(2).saturating_add(1);
        let offset = random.checked_rem(span).unwrap_or(0);
        Duration::from_millis(millis.saturating_sub(spread).saturating_add(offset))
    }

    /// `base` scaled by a random factor between 80% and 120%.
    pub(crate) fn jittered(base: Duration) -> Duration {
        Self::jitter(base, Self::random())
    }

    fn random() -> u64 {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(jiff::Timestamp::now().as_nanosecond().unsigned_abs());
        hasher.finish()
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn backoff_grows_per_failure_and_is_capped() {
        let interval = Duration::from_secs(60);
        let mut backoff = Backoff::default();
        let within = |delay: Duration, base: Duration| {
            delay >= base.mul_f64(0.8)
                && delay <= base.mul_f64(1.2).saturating_add(Duration::from_millis(1))
        };
        assert!(within(backoff.delay(interval), interval));
        backoff.record_failure();
        assert!(within(backoff.delay(interval), Duration::from_secs(120)));
        for _ in 0..100 {
            backoff.record_failure();
        }
        assert!(within(backoff.delay(interval), Backoff::MAX));
        backoff.reset();
        assert!(within(backoff.delay(interval), interval));
    }

    proptest! {
        #[test]
        fn jitter_stays_within_twenty_percent(millis in 0_u64..10_000_000, random: u64) {
            let base = Duration::from_millis(millis);
            let jittered = Backoff::jitter(base, random).as_millis();
            let millis = u128::from(millis);
            prop_assert!(jittered.saturating_mul(5) >= millis.saturating_mul(4), "{jittered} < 80% of {millis}");
            prop_assert!(jittered.saturating_mul(5) <= millis.saturating_mul(6), "{jittered} > 120% of {millis}");
        }
    }
}
