//! Canary releases.
//!
//! A REST stage with canary settings serves two releases: the stage's
//! deployment (production) and the canary deployment, which receives
//! `percentTraffic` percent of requests, chosen at random per request, with the
//! canary's stage variable overrides applied. Stage variables are substituted
//! when routes are compiled, so the canary gets its own compiled route set and
//! the dispatcher picks one per request.
//!
//! API Gateway cannot export a canary deployment, so by default the canary
//! release has the stage's structure and differs only in its stage variables.
//! `--canary-export-stage` names a stage that holds the canary deployment, and
//! the canary release is built from that stage's export instead.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/canary-release.html>

use std::collections::BTreeMap;

use axum::Router;
use serde::Serialize;

use crate::entropy::Entropy;
use crate::router::RouteSummary;

/// Which release of a stage that has a canary a router serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Release {
    Production,
    Canary,
}

impl Release {
    /// `$context.isCanaryRequest`.
    pub(crate) fn is_canary(self) -> bool {
        self == Self::Canary
    }
}

/// The share of requests that go to the canary, in hundredths of a percent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TrafficShare(u32);

impl TrafficShare {
    const FULL: u32 = 10_000;

    pub(crate) const NONE: Self = Self(0);

    /// The share for `percentTraffic`: 0.0 to 100.0, kept to two decimals.
    /// Values outside the range and non-numbers clamp to 0 and 100 percent
    /// (API Gateway rejects them when the stage is updated).
    pub(crate) fn from_percent(percent: f64) -> Self {
        if !percent.is_finite() || percent <= 0.0 {
            return Self::NONE;
        }
        if percent >= 100.0 {
            return Self(Self::FULL);
        }
        let text = format!("{percent:.2}");
        let hundredths = text.split_once('.').and_then(|(whole, fraction)| {
            let whole: u32 = whole.parse().ok()?;
            let fraction: u32 = fraction.parse().ok()?;
            whole.checked_mul(100)?.checked_add(fraction)
        });
        Self(hundredths.unwrap_or(0).min(Self::FULL))
    }

    pub(crate) fn is_none(self) -> bool {
        self.0 == 0
    }

    /// Whether a request whose uniformly random `roll` is given goes to the canary.
    pub(crate) fn selects(self, roll: u64) -> bool {
        roll.checked_rem(u64::from(Self::FULL))
            .is_some_and(|slot| slot < u64::from(self.0))
    }

    /// Chooses for one request. Without randomness the request goes to
    /// production, so a broken entropy source never moves traffic.
    pub(crate) fn picks_canary(self) -> bool {
        Entropy::u64().is_some_and(|roll| self.selects(roll))
    }
}

/// Where the canary release's structure comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "source", content = "stage")]
pub(crate) enum CanaryStructure {
    /// The stage's own export: only stage variables differ from production.
    StageExport,
    /// The export of the stage named by `--canary-export-stage`.
    ShadowStage(String),
}

/// The canary release as reported on `/routes`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct CanarySummary {
    pub(crate) percent_traffic: f64,
    pub(crate) deployment_id: Option<String>,
    pub(crate) use_stage_cache: bool,
    pub(crate) structure: CanaryStructure,
    pub(crate) stage_variable_overrides: BTreeMap<String, String>,
    pub(crate) routes: Vec<RouteSummary>,
}

/// A built canary release.
pub(crate) struct CanaryRelease {
    pub(crate) router: Router,
    pub(crate) share: TrafficShare,
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn percentages_become_hundredths_of_a_percent() {
        let share = |p| TrafficShare::from_percent(p).0;
        assert_eq!(share(0.0), 0);
        assert_eq!(share(10.0), 1000);
        assert_eq!(share(10.5), 1050);
        assert_eq!(share(0.01), 1);
        assert_eq!(share(33.333), 3333);
        assert_eq!(share(99.999), 10_000);
        assert_eq!(share(100.0), 10_000);
    }

    #[test]
    fn out_of_range_and_invalid_percentages_clamp() {
        let share = |p| TrafficShare::from_percent(p).0;
        assert_eq!(share(-5.0), 0);
        assert_eq!(share(250.0), 10_000);
        assert_eq!(share(f64::NAN), 0);
        assert_eq!(share(f64::INFINITY), 0);
        assert_eq!(share(f64::NEG_INFINITY), 0);
        assert!(TrafficShare::from_percent(0.0).is_none());
        assert!(!TrafficShare::from_percent(0.01).is_none());
    }

    #[test]
    fn rolls_select_exactly_the_share() {
        let ten = TrafficShare::from_percent(10.0);
        let selected = (0..10_000_u64).filter(|&roll| ten.selects(roll)).count();
        assert_eq!(selected, 1000);
        assert!(ten.selects(0));
        assert!(ten.selects(999));
        assert!(!ten.selects(1000));
        assert!(!TrafficShare::NONE.selects(0));
        assert!(TrafficShare::from_percent(100.0).selects(u64::MAX));
    }

    #[test]
    fn random_selection_follows_the_configured_share() {
        const REQUESTS: u32 = 20_000;
        let share = TrafficShare::from_percent(10.0);
        let canary = (0..REQUESTS).filter(|_| share.picks_canary()).count();
        // 10% of 20,000 is 2,000 with a standard deviation of about 42; five
        // deviations leave a one in a million chance of a false failure.
        assert!(
            (1790..=2210).contains(&canary),
            "{canary} of {REQUESTS} requests went to the canary"
        );
        assert_eq!(
            (0..1000)
                .filter(|_| TrafficShare::NONE.picks_canary())
                .count(),
            0
        );
        let all = TrafficShare::from_percent(100.0);
        assert_eq!((0..1000).filter(|_| all.picks_canary()).count(), 1000);
    }

    #[test]
    fn only_the_canary_release_reports_canary_requests() {
        assert!(Release::Canary.is_canary());
        assert!(!Release::Production.is_canary());
    }

    proptest! {
        #[test]
        fn shares_never_exceed_the_whole(percent in proptest::num::f64::ANY) {
            prop_assert!(TrafficShare::from_percent(percent).0 <= 10_000);
        }

        #[test]
        fn shares_match_the_percentage_to_two_decimals(hundredths in 0_u32..=10_000) {
            let percent = f64::from(hundredths) / 100.0;
            prop_assert_eq!(TrafficShare::from_percent(percent).0, hundredths);
            let share = TrafficShare(hundredths);
            let hits = (0..10_000_u64).filter(|&roll| share.selects(roll)).count();
            prop_assert_eq!(hits, usize::try_from(hundredths).unwrap());
        }
    }
}
