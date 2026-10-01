//! Token buckets: API Gateway's throttling algorithm. The bucket holds up to
//! `burst` tokens and gains `rate` tokens per second; a request takes one.
//! See
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html>.

use std::num::NonZeroU32;

use jiff::Timestamp;

/// The steady-state rate and burst size of one bucket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct BucketLimits {
    rate_per_second: f64,
    burst: f64,
}

impl BucketLimits {
    /// `None` unless both numbers are finite and not negative. A burst of zero
    /// admits nothing.
    pub(crate) fn new(rate_per_second: f64, burst: f64) -> Option<Self> {
        let valid = |n: f64| n.is_finite() && n >= 0.0;
        (valid(rate_per_second) && valid(burst)).then_some(Self {
            rate_per_second,
            burst,
        })
    }

    /// This replica's share of limits that apply to the API as a whole. Each
    /// replica keeps its own bucket, so the limits are divided evenly. The
    /// capacity never drops below one token (a bucket that cannot hold one
    /// would reject everything), so with more replicas than burst tokens the
    /// API-wide burst is larger than configured.
    #[must_use]
    pub(crate) fn per_replica(self, replicas: NonZeroU32) -> Self {
        let share = f64::from(replicas.get());
        Self {
            rate_per_second: self.rate_per_second / share,
            burst: self.burst / share,
        }
    }

    /// Tokens the bucket can hold.
    fn capacity(self) -> f64 {
        if self.burst == 0.0 {
            0.0
        } else {
            self.burst.max(1.0)
        }
    }
}

/// Whether a request may proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Admission {
    Admitted,
    Throttled,
}

/// One bucket's state. Limits are passed to every call, so a changed
/// definition takes effect without resetting the bucket.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct TokenBucket {
    tokens: f64,
    updated: Timestamp,
}

impl TokenBucket {
    /// A full bucket.
    pub(crate) fn full(limits: BucketLimits, now: Timestamp) -> Self {
        Self {
            tokens: limits.capacity(),
            updated: now,
        }
    }

    /// Adds the tokens earned since the last call, then takes one if there is
    /// one. A clock that steps backwards earns nothing.
    pub(crate) fn take(&mut self, limits: BucketLimits, now: Timestamp) -> Admission {
        let elapsed = now.duration_since(self.updated).as_secs_f64().max(0.0);
        self.updated = now;
        self.tokens = elapsed
            .mul_add(limits.rate_per_second, self.tokens)
            .min(limits.capacity());
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Admission::Admitted
        } else {
            Admission::Throttled
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn at(millis: i64) -> Timestamp {
        Timestamp::from_millisecond(millis).unwrap()
    }

    fn limits(rate: f64, burst: f64) -> BucketLimits {
        BucketLimits::new(rate, burst).unwrap()
    }

    #[test]
    fn rejects_invalid_limits() {
        assert!(BucketLimits::new(-1.0, 5.0).is_none());
        assert!(BucketLimits::new(1.0, -1.0).is_none());
        assert!(BucketLimits::new(f64::NAN, 1.0).is_none());
        assert!(BucketLimits::new(1.0, f64::INFINITY).is_none());
        assert!(BucketLimits::new(0.0, 0.0).is_some());
    }

    #[test]
    fn a_full_bucket_admits_its_burst_then_refills_at_the_rate() {
        let limits = limits(2.0, 3.0);
        let mut bucket = TokenBucket::full(limits, at(0));
        for _ in 0..3 {
            assert_eq!(bucket.take(limits, at(0)), Admission::Admitted);
        }
        assert_eq!(bucket.take(limits, at(0)), Admission::Throttled);
        assert_eq!(bucket.take(limits, at(400)), Admission::Throttled);
        assert_eq!(bucket.take(limits, at(500)), Admission::Admitted);
        assert_eq!(bucket.take(limits, at(500)), Admission::Throttled);
    }

    #[test]
    fn zero_burst_admits_nothing() {
        let limits = limits(100.0, 0.0);
        let mut bucket = TokenBucket::full(limits, at(0));
        assert_eq!(bucket.take(limits, at(10_000)), Admission::Throttled);
    }

    #[test]
    fn a_clock_stepping_backwards_earns_nothing() {
        let limits = limits(1.0, 1.0);
        let mut bucket = TokenBucket::full(limits, at(10_000));
        assert_eq!(bucket.take(limits, at(10_000)), Admission::Admitted);
        assert_eq!(bucket.take(limits, at(0)), Admission::Throttled);
        assert_eq!(bucket.take(limits, at(900)), Admission::Throttled);
        assert_eq!(bucket.take(limits, at(1_000)), Admission::Admitted);
    }

    #[test]
    fn replicas_divide_limits_but_keep_one_token_of_capacity() {
        let divided = limits(100.0, 10.0).per_replica(NonZeroU32::new(4).unwrap());
        assert_eq!(divided, limits(25.0, 2.5));
        let tiny = limits(10.0, 2.0).per_replica(NonZeroU32::new(10).unwrap());
        assert!((tiny.capacity() - 1.0).abs() < f64::EPSILON);
        let blocked = limits(10.0, 0.0).per_replica(NonZeroU32::new(10).unwrap());
        assert!(blocked.capacity().abs() < f64::EPSILON);
    }

    proptest! {
        /// Over any sequence of requests the bucket never admits more than its
        /// burst plus what the rate earns in the elapsed time.
        #[test]
        fn admissions_never_exceed_burst_plus_rate_times_time(
            rate in 0.0_f64..50.0,
            burst in 0.0_f64..20.0,
            gaps in proptest::collection::vec(0_i64..2_000, 1..200),
        ) {
            let limits = limits(rate, burst);
            let mut bucket = TokenBucket::full(limits, at(0));
            let mut now = 0_i64;
            let mut admitted = 0_u32;
            for gap in gaps {
                now = now.saturating_add(gap);
                if bucket.take(limits, at(now)) == Admission::Admitted {
                    admitted = admitted.saturating_add(1);
                }
                #[expect(clippy::cast_precision_loss, reason = "test millisecond counts are small")]
                let seconds = now as f64 / 1000.0;
                prop_assert!(f64::from(admitted) <= limits.capacity() + rate * seconds + 1e-6);
                prop_assert!(bucket.tokens >= 0.0);
                prop_assert!(bucket.tokens <= limits.capacity() + 1e-9);
            }
        }

        /// Requests all at one instant admit exactly the whole tokens in the bucket.
        #[test]
        fn a_simultaneous_burst_admits_floor_of_the_capacity(
            rate in 0.0_f64..50.0,
            burst in 0.0_f64..20.0,
        ) {
            let limits = limits(rate, burst);
            let mut bucket = TokenBucket::full(limits, at(0));
            let mut admitted = 0_u32;
            for _ in 0..64 {
                if bucket.take(limits, at(0)) == Admission::Admitted {
                    admitted = admitted.saturating_add(1);
                }
            }
            #[expect(clippy::cast_possible_truncation, clippy::cast_sign_loss, reason = "capacity is at most 20")]
            let whole = limits.capacity().floor() as u32;
            prop_assert_eq!(admitted, whole);
        }

        /// Waiting long enough for one token always admits a request.
        #[test]
        fn waiting_one_token_interval_admits(rate in 0.5_f64..50.0, burst in 1.0_f64..20.0) {
            let limits = limits(rate, burst);
            let mut bucket = TokenBucket::full(limits, at(0));
            while bucket.take(limits, at(0)) == Admission::Admitted {}
            #[expect(clippy::cast_possible_truncation, reason = "wait is a few seconds")]
            let wait_ms = ((1000.0 / rate).ceil() as i64).saturating_add(1);
            prop_assert_eq!(bucket.take(limits, at(wait_ms)), Admission::Admitted);
        }
    }
}
