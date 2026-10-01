//! Fixed-window request quotas, as usage plans define them: a limit per day,
//! week, or month, counted from the start of the calendar period in UTC.
//! The week starts on Monday.

use jiff::civil::Weekday;
use jiff::tz::TimeZone;
use jiff::{Timestamp, ToSpan as _};

/// How long a quota window lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaPeriod {
    Day,
    Week,
    Month,
}

/// A quota: at most `limit` requests per `period`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuotaLimit {
    pub(crate) limit: u64,
    pub(crate) period: QuotaPeriod,
}

/// One calendar period, `start` inclusive and `end` exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuotaWindow {
    pub(crate) start: Timestamp,
    pub(crate) end: Timestamp,
}

impl QuotaPeriod {
    /// The window containing `now`; `None` only at the ends of the supported
    /// date range.
    pub(crate) fn window(self, now: Timestamp) -> Option<QuotaWindow> {
        let date = now.to_zoned(TimeZone::UTC).date();
        let (first, next) = match self {
            Self::Day => (date, date.tomorrow().ok()?),
            Self::Week => {
                let since_monday = i64::from(date.weekday().since(Weekday::Monday));
                let first = date.checked_sub(since_monday.days()).ok()?;
                (first, first.checked_add(7.days()).ok()?)
            }
            Self::Month => {
                let first = date.first_of_month();
                (first, first.checked_add(1.month()).ok()?)
            }
        };
        let midnight = |date: jiff::civil::Date| {
            date.to_zoned(TimeZone::UTC)
                .ok()
                .map(|zoned| zoned.timestamp())
        };
        Some(QuotaWindow {
            start: midnight(first)?,
            end: midnight(next)?,
        })
    }
}

/// The outcome of counting one request against a quota.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum QuotaDecision {
    Allowed {
        remaining: u64,
    },
    /// The window is used up until `resets_at`.
    Exceeded {
        resets_at: Timestamp,
    },
}

/// Requests counted in one window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct QuotaCounter {
    window_start: Timestamp,
    used: u64,
}

impl QuotaCounter {
    pub(crate) fn new(window: QuotaWindow) -> Self {
        Self {
            window_start: window.start,
            used: 0,
        }
    }

    /// Counts one request in `window` against `limit`. A counter from an
    /// earlier window starts again from zero.
    pub(crate) fn consume(&mut self, limit: u64, window: QuotaWindow) -> QuotaDecision {
        if self.window_start != window.start {
            *self = Self::new(window);
        }
        if self.used < limit {
            self.used = self.used.saturating_add(1);
            QuotaDecision::Allowed {
                remaining: limit.saturating_sub(self.used),
            }
        } else {
            QuotaDecision::Exceeded {
                resets_at: window.end,
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn ts(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    #[test]
    fn windows_align_to_utc_calendar_periods() {
        // 2026-10-01 is a Thursday.
        let now = ts("2026-10-01T15:30:00Z");
        let cases = [
            (
                QuotaPeriod::Day,
                "2026-10-01T00:00:00Z",
                "2026-10-02T00:00:00Z",
            ),
            (
                QuotaPeriod::Week,
                "2026-09-28T00:00:00Z",
                "2026-10-05T00:00:00Z",
            ),
            (
                QuotaPeriod::Month,
                "2026-10-01T00:00:00Z",
                "2026-11-01T00:00:00Z",
            ),
        ];
        for (period, start, end) in cases {
            let window = period.window(now).unwrap();
            assert_eq!(window.start, ts(start), "{period:?}");
            assert_eq!(window.end, ts(end), "{period:?}");
        }
    }

    #[test]
    fn boundaries_belong_to_the_new_window() {
        let monday = QuotaPeriod::Week
            .window(ts("2026-09-28T00:00:00Z"))
            .unwrap();
        assert_eq!(monday.start, ts("2026-09-28T00:00:00Z"));
        let sunday = QuotaPeriod::Week
            .window(ts("2026-09-27T23:59:59Z"))
            .unwrap();
        assert_eq!(sunday.end, monday.start);
        let december = QuotaPeriod::Month
            .window(ts("2026-12-31T23:59:59Z"))
            .unwrap();
        assert_eq!(december.end, ts("2027-01-01T00:00:00Z"));
        let leap = QuotaPeriod::Month
            .window(ts("2028-02-10T00:00:00Z"))
            .unwrap();
        assert_eq!(leap.end, ts("2028-03-01T00:00:00Z"));
    }

    #[test]
    fn counter_allows_up_to_the_limit_then_resets_in_the_next_window() {
        let day = QuotaPeriod::Day;
        let first = day.window(ts("2026-10-01T10:00:00Z")).unwrap();
        let second = day.window(ts("2026-10-02T10:00:00Z")).unwrap();
        let mut counter = QuotaCounter::new(first);
        assert_eq!(
            counter.consume(2, first),
            QuotaDecision::Allowed { remaining: 1 }
        );
        assert_eq!(
            counter.consume(2, first),
            QuotaDecision::Allowed { remaining: 0 }
        );
        assert_eq!(
            counter.consume(2, first),
            QuotaDecision::Exceeded {
                resets_at: first.end
            }
        );
        assert_eq!(
            counter.consume(2, second),
            QuotaDecision::Allowed { remaining: 1 }
        );
    }

    #[test]
    fn zero_limit_allows_nothing() {
        let window = QuotaPeriod::Day.window(ts("2026-10-01T10:00:00Z")).unwrap();
        let mut counter = QuotaCounter::new(window);
        assert!(matches!(
            counter.consume(0, window),
            QuotaDecision::Exceeded { .. }
        ));
    }

    proptest! {
        /// Every instant falls in exactly one window of each period, and the
        /// window starts at UTC midnight.
        #[test]
        fn windows_contain_their_instant(seconds in 0_i64..4_000_000_000) {
            let now = Timestamp::from_second(seconds).unwrap();
            for period in [QuotaPeriod::Day, QuotaPeriod::Week, QuotaPeriod::Month] {
                let window = period.window(now).unwrap();
                prop_assert!(window.start <= now && now < window.end);
                prop_assert_eq!(window.start.as_second().rem_euclid(86_400), 0);
                let next = period.window(window.end).unwrap();
                prop_assert_eq!(next.start, window.end);
            }
        }

        /// A window never admits more than its limit.
        #[test]
        fn counter_never_exceeds_the_limit(limit in 0_u64..50, attempts in 0_u32..100) {
            let window = QuotaPeriod::Day.window(Timestamp::from_second(0).unwrap()).unwrap();
            let mut counter = QuotaCounter::new(window);
            let mut allowed = 0_u64;
            for _ in 0..attempts {
                if matches!(counter.consume(limit, window), QuotaDecision::Allowed { .. }) {
                    allowed = allowed.saturating_add(1);
                }
            }
            prop_assert_eq!(allowed, limit.min(u64::from(attempts)));
        }
    }
}
