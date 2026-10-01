//! A usage plan's throttle and quota, applied to one key.
//!
//! The plan's default throttle limits a key across the stage; a per-method
//! entry (`/pets/GET`, or `*/*` for every method of the stage) limits it on
//! that method with its own bucket, and the most specific entry applies. The
//! quota counts every request of the key in the plan, in calendar periods.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use super::{KeyId, PlanId};
use crate::state::quota::{QuotaDecision, QuotaLimit};
use crate::state::{Admission, BucketLimits, StateBackend, StateKey};

/// The key of a usage plan's per-method throttle that applies to every method.
const ALL_METHODS: &str = "*/*";

/// What a plan limits.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct PlanLimits {
    /// The plan-wide throttle, per key.
    pub(crate) throttle: Option<BucketLimits>,
    /// Throttles of single methods, by `{resource path}/{METHOD}`.
    pub(crate) methods: BTreeMap<String, BucketLimits>,
    pub(crate) quota: Option<QuotaLimit>,
}

/// What stands between a request and the usage plan's verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UsageOutcome {
    Admitted,
    Throttled,
    QuotaExceeded,
}

/// Where a plan is applied: which API and stage, and how many gateways share
/// the work when their state is not shared.
#[derive(Debug, Clone)]
pub(crate) struct UsageChecker {
    api_id: String,
    stage: String,
    replicas: NonZeroU32,
}

impl UsageChecker {
    /// `replicas` is how many gateways count separately: 1 with a shared state
    /// backend, otherwise the number of replicas, each taking its share of every
    /// limit.
    pub(crate) fn new(api_id: &str, stage: &str, replicas: NonZeroU32) -> Self {
        Self {
            api_id: api_id.to_owned(),
            stage: stage.to_owned(),
            replicas,
        }
    }

    fn key(&self, kind: &str, plan: &PlanId, key: &KeyId, extra: &str) -> StateKey {
        StateKey::new(kind, &[&self.api_id, &self.stage, &plan.0, &key.0, extra])
    }

    /// The throttle that governs `method` (`{resource path}/{METHOD}`), and
    /// the bucket it draws from.
    fn throttle_for<'a>(
        &self,
        limits: &'a PlanLimits,
        plan: &PlanId,
        key: &KeyId,
        method: &str,
    ) -> Option<(&'a BucketLimits, StateKey)> {
        if let Some(found) = limits.methods.get(method) {
            return Some((found, self.key("usage-throttle", plan, key, method)));
        }
        if let Some(found) = limits.methods.get(ALL_METHODS) {
            return Some((found, self.key("usage-throttle", plan, key, ALL_METHODS)));
        }
        limits
            .throttle
            .as_ref()
            .map(|found| (found, self.key("usage-throttle", plan, key, "")))
    }

    /// Counts one request of `key` under `plan` on `method`. A throttled
    /// request does not use up quota. If the state backend cannot answer, the
    /// request is admitted: the limits protect capacity and bill, and refusing
    /// all keyed traffic because shared state is down would take the API down.
    pub(crate) async fn admit(
        &self,
        backend: &StateBackend,
        limits: &PlanLimits,
        plan: &PlanId,
        key: &KeyId,
        method: &str,
    ) -> UsageOutcome {
        if let Some((bucket, state_key)) = self.throttle_for(limits, plan, key, method) {
            match backend
                .take_token(&state_key, bucket.per_replica(self.replicas))
                .await
            {
                Ok(Admission::Admitted) => {}
                Ok(Admission::Throttled) => return UsageOutcome::Throttled,
                Err(error) => {
                    tracing::warn!(%error, "usage plan throttle state unavailable; admitting the request");
                }
            }
        }
        let Some(quota) = limits.quota else {
            return UsageOutcome::Admitted;
        };
        let share = QuotaLimit {
            limit: quota.limit.div_ceil(u64::from(self.replicas.get())),
            period: quota.period,
        };
        match backend
            .consume_quota(&self.key("usage-quota", plan, key, ""), share)
            .await
        {
            Ok(QuotaDecision::Allowed { .. }) => UsageOutcome::Admitted,
            Ok(QuotaDecision::Exceeded { .. }) => UsageOutcome::QuotaExceeded,
            Err(error) => {
                tracing::warn!(%error, "usage plan quota state unavailable; admitting the request");
                UsageOutcome::Admitted
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::state::quota::QuotaPeriod;
    use crate::state::{InMemory, InMemoryLimits};

    fn backend() -> StateBackend {
        StateBackend::InMemory(InMemory::new(InMemoryLimits::default()))
    }

    fn checker(replicas: u32) -> UsageChecker {
        UsageChecker::new("abc", "prod", NonZeroU32::new(replicas).unwrap())
    }

    fn bucket(rate: f64, burst: f64) -> BucketLimits {
        BucketLimits::new(rate, burst).unwrap()
    }

    fn plan(id: &str) -> PlanId {
        PlanId(id.to_owned())
    }

    fn key(id: &str) -> KeyId {
        KeyId(id.to_owned())
    }

    fn quota(limit: u64) -> QuotaLimit {
        QuotaLimit {
            limit,
            period: QuotaPeriod::Day,
        }
    }

    async fn admit(
        checker: &UsageChecker,
        backend: &StateBackend,
        limits: &PlanLimits,
        key_id: &str,
        method: &str,
    ) -> UsageOutcome {
        checker
            .admit(backend, limits, &plan("p"), &key(key_id), method)
            .await
    }

    #[tokio::test]
    async fn a_plan_with_no_limits_admits_everything() {
        let (backend, checker) = (backend(), checker(1));
        for _ in 0..50 {
            assert_eq!(
                admit(&checker, &backend, &PlanLimits::default(), "k", "/a/GET").await,
                UsageOutcome::Admitted
            );
        }
    }

    #[tokio::test]
    async fn the_plan_throttle_limits_a_key_across_methods() {
        let (backend, checker) = (backend(), checker(1));
        let limits = PlanLimits {
            throttle: Some(bucket(0.0, 2.0)),
            ..PlanLimits::default()
        };
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/b/POST").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::Throttled
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "other", "/a/GET").await,
            UsageOutcome::Admitted,
            "another key has its own bucket"
        );
    }

    #[tokio::test]
    async fn a_method_throttle_overrides_the_plan_throttle_with_its_own_bucket() {
        let (backend, checker) = (backend(), checker(1));
        let limits = PlanLimits {
            throttle: Some(bucket(0.0, 1.0)),
            methods: BTreeMap::from([("/slow/GET".to_owned(), bucket(0.0, 3.0))]),
            quota: None,
        };
        for _ in 0..3 {
            assert_eq!(
                admit(&checker, &backend, &limits, "k", "/slow/GET").await,
                UsageOutcome::Admitted
            );
        }
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/slow/GET").await,
            UsageOutcome::Throttled
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/other/GET").await,
            UsageOutcome::Admitted,
            "the plan throttle's bucket was not touched"
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/other/GET").await,
            UsageOutcome::Throttled
        );
    }

    #[tokio::test]
    async fn the_all_methods_entry_sits_between_a_method_entry_and_the_plan_default() {
        let (backend, checker) = (backend(), checker(1));
        let limits = PlanLimits {
            throttle: Some(bucket(0.0, 100.0)),
            methods: BTreeMap::from([
                ("*/*".to_owned(), bucket(0.0, 1.0)),
                ("/vip/GET".to_owned(), bucket(0.0, 5.0)),
            ]),
            quota: None,
        };
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/b/GET").await,
            UsageOutcome::Throttled,
            "*/* is shared by methods"
        );
        for _ in 0..5 {
            assert_eq!(
                admit(&checker, &backend, &limits, "k", "/vip/GET").await,
                UsageOutcome::Admitted
            );
        }
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/vip/GET").await,
            UsageOutcome::Throttled
        );
    }

    #[tokio::test]
    async fn the_quota_counts_every_method_and_is_per_key() {
        let (backend, checker) = (backend(), checker(1));
        let limits = PlanLimits {
            quota: Some(quota(3)),
            ..PlanLimits::default()
        };
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/b/POST").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/c/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::QuotaExceeded
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::QuotaExceeded
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "other", "/a/GET").await,
            UsageOutcome::Admitted
        );
    }

    #[tokio::test]
    async fn plans_and_stages_do_not_share_state() {
        let backend = backend();
        let limits = PlanLimits {
            quota: Some(quota(1)),
            ..PlanLimits::default()
        };
        let prod = checker(1);
        let dev = UsageChecker::new("abc", "dev", NonZeroU32::MIN);
        let other_api = UsageChecker::new("xyz", "prod", NonZeroU32::MIN);
        let (k, p1, p2) = (key("k"), plan("p1"), plan("p2"));
        assert_eq!(
            prod.admit(&backend, &limits, &p1, &k, "/a/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            prod.admit(&backend, &limits, &p1, &k, "/a/GET").await,
            UsageOutcome::QuotaExceeded
        );
        assert_eq!(
            prod.admit(&backend, &limits, &p2, &k, "/a/GET").await,
            UsageOutcome::Admitted,
            "another plan"
        );
        assert_eq!(
            dev.admit(&backend, &limits, &p1, &k, "/a/GET").await,
            UsageOutcome::Admitted,
            "another stage"
        );
        assert_eq!(
            other_api.admit(&backend, &limits, &p1, &k, "/a/GET").await,
            UsageOutcome::Admitted,
            "another API"
        );
    }

    #[tokio::test]
    async fn a_throttled_request_does_not_use_up_quota() {
        let (backend, checker) = (backend(), checker(1));
        let limits = PlanLimits {
            throttle: Some(bucket(0.0, 1.0)),
            methods: BTreeMap::new(),
            quota: Some(quota(2)),
        };
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::Admitted
        );
        for _ in 0..5 {
            assert_eq!(
                admit(&checker, &backend, &limits, "k", "/a/GET").await,
                UsageOutcome::Throttled
            );
        }
        // One of the two quota units is still unspent: lift the throttle.
        let lifted = PlanLimits {
            throttle: None,
            ..limits
        };
        assert_eq!(
            admit(&checker, &backend, &lifted, "k", "/a/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &lifted, "k", "/a/GET").await,
            UsageOutcome::QuotaExceeded
        );
    }

    #[tokio::test]
    async fn throttles_are_shared_between_replicas_that_do_not_share_state() {
        let backend = backend();
        let limits = PlanLimits {
            throttle: Some(bucket(0.0, 8.0)),
            ..PlanLimits::default()
        };
        let checker = checker(4);
        let mut admitted = 0_u32;
        for _ in 0..20 {
            if admit(&checker, &backend, &limits, "k", "/a/GET").await == UsageOutcome::Admitted {
                admitted = admitted.saturating_add(1);
            }
        }
        assert_eq!(admitted, 2, "a burst of 8 split four ways");
    }

    #[tokio::test]
    async fn the_quota_is_counted_per_key_not_per_method() {
        let (backend, checker) = (backend(), checker(1));
        let limits = PlanLimits {
            quota: Some(quota(2)),
            ..PlanLimits::default()
        };
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/a/GET").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/b/POST").await,
            UsageOutcome::Admitted
        );
        assert_eq!(
            admit(&checker, &backend, &limits, "k", "/c/GET").await,
            UsageOutcome::QuotaExceeded
        );
    }

    #[tokio::test]
    async fn limits_are_shared_between_replicas_that_do_not_share_state() {
        let backend = backend();
        let limits = PlanLimits {
            quota: Some(quota(10)),
            ..PlanLimits::default()
        };
        let checker = checker(4);
        let mut admitted = 0_u32;
        for _ in 0..20 {
            if admit(&checker, &backend, &limits, "k", "/a/GET").await == UsageOutcome::Admitted {
                admitted = admitted.saturating_add(1);
            }
        }
        assert_eq!(admitted, 3, "ceil(10 / 4) requests per replica");
    }

    proptest! {
        #[test]
        fn a_quota_admits_exactly_its_limit_in_a_period(limit in 0_u64..40, extra in 0_u64..10) {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            let admitted = runtime.block_on(async {
                let (backend, checker) = (backend(), checker(1));
                let limits = PlanLimits { quota: Some(quota(limit)), ..PlanLimits::default() };
                let mut admitted = 0_u64;
                for _ in 0..limit.saturating_add(extra) {
                    if admit(&checker, &backend, &limits, "k", "/a/GET").await == UsageOutcome::Admitted {
                        admitted = admitted.saturating_add(1);
                    }
                }
                admitted
            });
            prop_assert_eq!(admitted, limit);
        }
    }
}
