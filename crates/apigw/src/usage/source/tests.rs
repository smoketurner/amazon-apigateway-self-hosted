use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

use aws_sdk_apigateway::types::{ApiStage, QuotaSettings, ThrottleSettings};
use tokio::time::Instant;

use super::*;

/// One page of canned results, and the call that fetches the next.
fn page<T: Clone>(pages: &[Vec<T>], position: Option<&str>) -> Page<T> {
    let index: usize = position.map_or(0, |p| p.parse().unwrap());
    Page {
        items: pages.get(index).cloned().unwrap_or_default(),
        next: (index.saturating_add(1) < pages.len()).then(|| index.saturating_add(1).to_string()),
    }
}

/// A control plane serving canned pages and recording every call.
#[derive(Default)]
struct Fake {
    plans: Vec<Vec<PlanRecord>>,
    members: BTreeMap<&'static str, Vec<Vec<&'static str>>>,
    keys: Vec<Vec<(&'static str, bool, &'static str)>>,
    calls: Mutex<Vec<String>>,
    fail_on: Option<&'static str>,
}

impl Fake {
    fn note(&self, call: &str) -> Result<(), UsageError> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(call.to_owned());
        if self.fail_on == Some(call) {
            Err(UsageError::Aws(format!("{call} failed")))
        } else {
            Ok(())
        }
    }

    fn calls(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ControlPlane for &Fake {
    fn usage_plans(
        &self,
        position: Option<&str>,
    ) -> impl Future<Output = Result<Page<PlanRecord>, UsageError>> + Send {
        std::future::ready(
            self.note(&format!("plans@{}", position.unwrap_or("-")))
                .map(|()| page(&self.plans, position)),
        )
    }

    fn api_keys(
        &self,
        position: Option<&str>,
    ) -> impl Future<Output = Result<Page<RawKey>, UsageError>> + Send {
        std::future::ready(
            self.note(&format!("keys@{}", position.unwrap_or("-")))
                .map(|()| {
                    let canned = page(&self.keys, position);
                    Page {
                        items: canned
                            .items
                            .into_iter()
                            .map(|(id, enabled, value)| RawKey {
                                id: KeyId(id.to_owned()),
                                enabled,
                                value: KeyValue::new(value.to_owned()),
                            })
                            .collect(),
                        next: canned.next,
                    }
                }),
        )
    }

    fn plan_keys(
        &self,
        plan: &PlanId,
        position: Option<&str>,
    ) -> impl Future<Output = Result<Page<KeyId>, UsageError>> + Send {
        std::future::ready(
            self.note(&format!("members({})@{}", plan.0, position.unwrap_or("-")))
                .map(|()| {
                    let pages = self
                        .members
                        .get(plan.0.as_str())
                        .cloned()
                        .unwrap_or_default();
                    let canned = page(&pages, position);
                    Page {
                        items: canned
                            .items
                            .into_iter()
                            .map(|id| KeyId(id.to_owned()))
                            .collect(),
                        next: canned.next,
                    }
                }),
        )
    }
}

fn stage(api: &str, stage: &str) -> StageRecord {
    StageRecord {
        api_id: api.to_owned(),
        stage: stage.to_owned(),
        methods: BTreeMap::new(),
    }
}

fn plan(id: &str, stages: Vec<StageRecord>) -> PlanRecord {
    PlanRecord {
        id: PlanId(id.to_owned()),
        stages,
        throttle: None,
        quota: Some(QuotaLimit {
            limit: 10,
            period: QuotaPeriod::Day,
        }),
    }
}

fn reader(fake: &Fake, pause: Duration) -> UsageReader<&Fake> {
    UsageReader::new(fake, "abc", "prod", Pacing::of(pause))
}

#[tokio::test]
async fn only_plans_of_the_stage_and_their_enabled_keys_are_read() {
    let fake = Fake {
        plans: vec![vec![
            plan("mine", vec![stage("abc", "prod")]),
            plan("other-stage", vec![stage("abc", "dev")]),
            plan("other-api", vec![stage("xyz", "prod")]),
            plan("both", vec![stage("xyz", "prod"), stage("abc", "prod")]),
        ]],
        members: BTreeMap::from([
            ("mine", vec![vec!["k1", "k2"]]),
            ("both", vec![vec!["k1"]]),
            ("other-stage", vec![vec!["k3"]]),
        ]),
        keys: vec![vec![
            ("k1", true, "value-one"),
            ("k2", false, "value-two"),
            ("k3", true, "value-three"),
            ("k4", true, "value-four"),
        ]],
        ..Fake::default()
    };
    let data = reader(&fake, Duration::ZERO).read().await.unwrap();
    assert_eq!(data.plan_count(), 2);
    assert_eq!(
        data.key_count(),
        2,
        "k3 and k4 belong to no plan of the stage"
    );
    let one = data.lookup("value-one").unwrap();
    assert_eq!(one.key, &KeyId("k1".to_owned()));
    let plans: Vec<&str> = one.plans.iter().map(|p| p.id.0.as_str()).collect();
    assert_eq!(plans, ["both", "mine"]);
    assert!(data.lookup("value-two").is_none(), "disabled");
    assert!(data.lookup("value-three").is_none());
    assert!(data.lookup("value-four").is_none());
    assert_eq!(
        one.plans.last().unwrap().limits.quota,
        Some(QuotaLimit {
            limit: 10,
            period: QuotaPeriod::Day
        })
    );
}

#[tokio::test]
async fn every_page_of_every_list_is_read_once() {
    let fake = Fake {
        plans: vec![
            vec![plan("p1", vec![stage("abc", "prod")])],
            vec![plan("p2", vec![stage("abc", "prod")])],
            vec![],
        ],
        members: BTreeMap::from([("p1", vec![vec!["a"], vec!["b"]]), ("p2", vec![vec!["c"]])]),
        keys: vec![
            vec![("a", true, "va")],
            vec![("b", true, "vb")],
            vec![("c", true, "vc")],
        ],
        ..Fake::default()
    };
    let data = reader(&fake, Duration::ZERO).read().await.unwrap();
    assert_eq!(data.key_count(), 3);
    assert_eq!(
        fake.calls(),
        [
            "plans@-",
            "plans@1",
            "plans@2",
            "members(p1)@-",
            "members(p1)@1",
            "members(p2)@-",
            "keys@-",
            "keys@1",
            "keys@2",
        ]
    );
}

#[tokio::test]
async fn keys_are_not_read_when_no_plan_includes_the_stage() {
    let fake = Fake {
        plans: vec![vec![plan("elsewhere", vec![stage("xyz", "prod")])]],
        keys: vec![vec![("a", true, "va")]],
        ..Fake::default()
    };
    let data = reader(&fake, Duration::ZERO).read().await.unwrap();
    assert_eq!((data.plan_count(), data.key_count()), (0, 0));
    assert_eq!(fake.calls(), ["plans@-"]);
}

#[tokio::test]
async fn plans_without_members_read_no_keys() {
    let fake = Fake {
        plans: vec![vec![plan("empty", vec![stage("abc", "prod")])]],
        keys: vec![vec![("a", true, "va")]],
        ..Fake::default()
    };
    let data = reader(&fake, Duration::ZERO).read().await.unwrap();
    assert_eq!((data.plan_count(), data.key_count()), (1, 0));
    assert_eq!(fake.calls(), ["plans@-", "members(empty)@-"]);
}

#[tokio::test]
async fn a_failed_call_fails_the_whole_read() {
    for failing in ["plans@-", "members(p1)@-", "keys@-"] {
        let fake = Fake {
            plans: vec![vec![plan("p1", vec![stage("abc", "prod")])]],
            members: BTreeMap::from([("p1", vec![vec!["a"]])]),
            keys: vec![vec![("a", true, "va")]],
            fail_on: Some(failing),
            ..Fake::default()
        };
        let error = reader(&fake, Duration::ZERO)
            .read()
            .await
            .map(|_| ())
            .unwrap_err();
        assert!(error.to_string().contains(failing), "{error}");
    }
}

#[tokio::test(start_paused = true)]
async fn calls_are_paced() {
    let fake = Fake {
        plans: vec![
            vec![plan("p1", vec![stage("abc", "prod")])],
            vec![plan("p2", vec![stage("abc", "prod")])],
        ],
        members: BTreeMap::from([("p1", vec![vec!["a"]]), ("p2", vec![vec!["b"]])]),
        keys: vec![vec![("a", true, "va"), ("b", true, "vb")]],
        ..Fake::default()
    };
    let pause = Duration::from_secs(10);
    let started = Instant::now();
    reader(&fake, pause).read().await.unwrap();
    let calls = u32::try_from(fake.calls().len()).unwrap();
    let elapsed = started.elapsed();
    // One pause between consecutive calls, each within 20% of the pacing.
    let between = calls - 1;
    assert!(
        elapsed >= pause.mul_f64(0.8) * between,
        "{elapsed:?} over {calls} calls"
    );
    assert!(
        elapsed <= pause.mul_f64(1.2) * between,
        "{elapsed:?} over {calls} calls"
    );
}

#[test]
fn pacing_keeps_all_replicas_within_the_budget() {
    let pause = |replicas: u32| Pacing::for_replicas(NonZeroU32::new(replicas).unwrap());
    assert_eq!(pause(1), Pacing::of(Duration::from_millis(200)));
    assert_eq!(pause(5), Pacing::of(Duration::from_secs(1)));
    assert_eq!(pause(50), Pacing::of(Duration::from_secs(10)));
    // N replicas each making one call per N/5 s make 5 calls a second together.
}

fn aws_plan() -> aws_sdk_apigateway::types::UsagePlan {
    let throttle = |rate: f64, burst: i32| {
        ThrottleSettings::builder()
            .rate_limit(rate)
            .burst_limit(burst)
            .build()
    };
    aws_sdk_apigateway::types::UsagePlan::builder()
        .id("plan-1")
        .api_stages(
            ApiStage::builder()
                .api_id("abc")
                .stage("prod")
                .throttle("/pets/GET", throttle(5.0, 10))
                .throttle("*/*", throttle(1.0, 2))
                .build(),
        )
        .api_stages(ApiStage::builder().api_id("abc").stage("dev").build())
        .throttle(throttle(100.0, 200))
        .quota(
            QuotaSettings::builder()
                .limit(1000)
                .offset(0)
                .period(QuotaPeriodType::Week)
                .build(),
        )
        .build()
}

#[test]
fn aws_plans_are_read_with_their_limits() {
    let record = AwsUsageSource::plan(&aws_plan()).unwrap();
    assert_eq!(record.id, PlanId("plan-1".to_owned()));
    assert_eq!(record.throttle, BucketLimits::new(100.0, 200.0));
    assert_eq!(
        record.quota,
        Some(QuotaLimit {
            limit: 1000,
            period: QuotaPeriod::Week
        })
    );
    assert_eq!(record.stages.len(), 2);
    let prod = record.stages.first().unwrap();
    assert_eq!((prod.api_id.as_str(), prod.stage.as_str()), ("abc", "prod"));
    assert_eq!(
        prod.methods.get("/pets/GET"),
        Some(&BucketLimits::new(5.0, 10.0).unwrap())
    );
    assert_eq!(
        prod.methods.get("*/*"),
        Some(&BucketLimits::new(1.0, 2.0).unwrap())
    );
}

#[test]
fn a_plan_with_no_limits_has_none() {
    let bare = aws_sdk_apigateway::types::UsagePlan::builder()
        .id("p")
        .build();
    let record = AwsUsageSource::plan(&bare).unwrap();
    assert_eq!((record.throttle, record.quota), (None, None));
    assert!(record.stages.is_empty());
}

#[test]
fn a_plan_with_a_limit_that_cannot_be_read_is_dropped_not_unlimited() {
    let with = |apply: &dyn Fn(
        aws_sdk_apigateway::types::builders::UsagePlanBuilder,
    ) -> aws_sdk_apigateway::types::builders::UsagePlanBuilder| {
        apply(aws_sdk_apigateway::types::UsagePlan::builder().id("p")).build()
    };
    let cases = [
        with(&|b| {
            b.quota(
                QuotaSettings::builder()
                    .limit(5)
                    .period(QuotaPeriodType::from("FORTNIGHT"))
                    .build(),
            )
        }),
        with(&|b| b.quota(QuotaSettings::builder().limit(5).build())),
        with(&|b| {
            b.quota(
                QuotaSettings::builder()
                    .limit(-1)
                    .period(QuotaPeriodType::Day)
                    .build(),
            )
        }),
        with(&|b| {
            b.throttle(
                ThrottleSettings::builder()
                    .rate_limit(-1.0)
                    .burst_limit(5)
                    .build(),
            )
        }),
        with(&|b| {
            b.throttle(
                ThrottleSettings::builder()
                    .rate_limit(f64::NAN)
                    .burst_limit(5)
                    .build(),
            )
        }),
        with(&|b| {
            b.api_stages(
                ApiStage::builder()
                    .api_id("abc")
                    .stage("prod")
                    .throttle(
                        "/a/GET",
                        ThrottleSettings::builder()
                            .rate_limit(1.0)
                            .burst_limit(-3)
                            .build(),
                    )
                    .build(),
            )
        }),
    ];
    for (index, case) in cases.iter().enumerate() {
        assert!(AwsUsageSource::plan(case).is_none(), "case {index}");
    }
    assert!(
        AwsUsageSource::plan(&aws_sdk_apigateway::types::UsagePlan::builder().build()).is_none(),
        "no id"
    );
}
