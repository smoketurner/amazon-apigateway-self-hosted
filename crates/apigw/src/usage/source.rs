//! Reading API keys and usage plans from API Gateway's control plane.
//!
//! The control plane allows 10 requests per second per account, shared by every
//! replica and every other tool. Reads are therefore paced: one page at a time,
//! with a pause between calls sized by the number of replicas, so a fleet that
//! refreshes together stays well under the limit. Pages are 500 items, the
//! largest the API returns.

use std::collections::BTreeMap;
use std::future::Future;
use std::num::NonZeroU32;
use std::time::Duration;

use aws_sdk_apigateway::types::{QuotaPeriodType, UsagePlan as AwsUsagePlan};

use super::plan::PlanLimits;
use super::{KeyId, KeyRecord, KeyValue, PlanId, UsageData, UsagePlan};
use crate::backoff::Backoff;
use crate::digest::Sha256Digest;
use crate::state::BucketLimits;
use crate::state::quota::{QuotaLimit, QuotaPeriod};

/// The page size to ask for: API Gateway's maximum.
const PAGE_SIZE: i32 = 500;
/// How many control-plane calls per second all replicas together may make for
/// this: half of the account limit, leaving the rest to everything else.
const BUDGET_CALLS_PER_SECOND: u32 = 5;

#[derive(Debug, thiserror::Error)]
pub(crate) enum UsageError {
    #[error("API Gateway request failed: {0}")]
    Aws(String),
}

impl UsageError {
    fn aws(error: impl std::error::Error) -> Self {
        Self::Aws(aws_sdk_apigateway::error::DisplayErrorContext(error).to_string())
    }
}

/// One page of results, and where the next starts.
#[derive(Debug)]
pub(crate) struct Page<T> {
    pub(crate) items: Vec<T>,
    pub(crate) next: Option<String>,
}

/// A usage plan's association with a stage, with its per-method throttles.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct StageRecord {
    pub(crate) api_id: String,
    pub(crate) stage: String,
    pub(crate) methods: BTreeMap<String, BucketLimits>,
}

/// A usage plan as read.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PlanRecord {
    pub(crate) id: PlanId,
    pub(crate) stages: Vec<StageRecord>,
    pub(crate) throttle: Option<BucketLimits>,
    pub(crate) quota: Option<QuotaLimit>,
}

/// An API key as read, with its value.
pub(crate) struct RawKey {
    pub(crate) id: KeyId,
    pub(crate) enabled: bool,
    pub(crate) value: KeyValue,
}

/// The reads the gateway needs from the control plane.
pub(crate) trait ControlPlane {
    fn usage_plans(
        &self,
        position: Option<&str>,
    ) -> impl Future<Output = Result<Page<PlanRecord>, UsageError>> + Send;

    fn api_keys(
        &self,
        position: Option<&str>,
    ) -> impl Future<Output = Result<Page<RawKey>, UsageError>> + Send;

    fn plan_keys(
        &self,
        plan: &PlanId,
        position: Option<&str>,
    ) -> impl Future<Output = Result<Page<KeyId>, UsageError>> + Send;
}

/// API Gateway.
pub(crate) struct AwsUsageSource {
    client: aws_sdk_apigateway::Client,
}

impl AwsUsageSource {
    pub(crate) fn new(client: aws_sdk_apigateway::Client) -> Self {
        Self { client }
    }

    fn bucket(rate: f64, burst: i32) -> Option<BucketLimits> {
        BucketLimits::new(rate, f64::from(burst))
    }

    fn quota(quota: &aws_sdk_apigateway::types::QuotaSettings) -> Option<QuotaLimit> {
        let period = match quota.period()? {
            QuotaPeriodType::Day => QuotaPeriod::Day,
            QuotaPeriodType::Week => QuotaPeriod::Week,
            QuotaPeriodType::Month => QuotaPeriod::Month,
            _ => return None,
        };
        Some(QuotaLimit {
            limit: u64::try_from(quota.limit()).ok()?,
            period,
        })
    }

    /// The plan, or `None` when it has no id or a limit this gateway cannot
    /// read. A plan whose limit is unreadable is dropped rather than applied
    /// without it: its keys are then refused, never admitted unlimited.
    pub(super) fn plan(plan: &AwsUsagePlan) -> Option<PlanRecord> {
        let id = PlanId(plan.id()?.to_owned());
        let readable = Self::readable(plan, &id);
        if readable.is_none() {
            tracing::warn!(
                plan = id.0,
                "usage plan has limits this gateway cannot read; its keys are refused"
            );
        }
        readable
    }

    fn readable(plan: &AwsUsagePlan, id: &PlanId) -> Option<PlanRecord> {
        let mut stages = Vec::new();
        for stage in plan.api_stages() {
            let (Some(api_id), Some(name)) = (stage.api_id(), stage.stage()) else {
                continue;
            };
            let mut methods = BTreeMap::new();
            for (path, settings) in stage.throttle().into_iter().flatten() {
                methods.insert(
                    path.clone(),
                    Self::bucket(settings.rate_limit(), settings.burst_limit())?,
                );
            }
            stages.push(StageRecord {
                api_id: api_id.to_owned(),
                stage: name.to_owned(),
                methods,
            });
        }
        let throttle = plan.throttle().map_or(Some(None), |settings| {
            Self::bucket(settings.rate_limit(), settings.burst_limit()).map(Some)
        })?;
        let quota = plan
            .quota()
            .map_or(Some(None), |quota| Self::quota(quota).map(Some))?;
        Some(PlanRecord {
            id: id.clone(),
            stages,
            throttle,
            quota,
        })
    }
}

impl ControlPlane for AwsUsageSource {
    async fn usage_plans(&self, position: Option<&str>) -> Result<Page<PlanRecord>, UsageError> {
        let mut call = self.client.get_usage_plans().limit(PAGE_SIZE);
        if let Some(position) = position {
            call = call.position(position);
        }
        let output = call.send().await.map_err(UsageError::aws)?;
        Ok(Page {
            items: output.items().iter().filter_map(Self::plan).collect(),
            next: output.position().map(str::to_owned),
        })
    }

    async fn api_keys(&self, position: Option<&str>) -> Result<Page<RawKey>, UsageError> {
        let mut call = self
            .client
            .get_api_keys()
            .include_values(true)
            .limit(PAGE_SIZE);
        if let Some(position) = position {
            call = call.position(position);
        }
        let output = call.send().await.map_err(UsageError::aws)?;
        let items = output
            .items()
            .iter()
            .filter_map(|key| {
                Some(RawKey {
                    id: KeyId(key.id()?.to_owned()),
                    enabled: key.enabled(),
                    value: KeyValue::new(key.value()?.to_owned()),
                })
            })
            .collect();
        Ok(Page {
            items,
            next: output.position().map(str::to_owned),
        })
    }

    async fn plan_keys(
        &self,
        plan: &PlanId,
        position: Option<&str>,
    ) -> Result<Page<KeyId>, UsageError> {
        let mut call = self
            .client
            .get_usage_plan_keys()
            .usage_plan_id(&plan.0)
            .limit(PAGE_SIZE);
        if let Some(position) = position {
            call = call.position(position);
        }
        let output = call.send().await.map_err(UsageError::aws)?;
        Ok(Page {
            items: output
                .items()
                .iter()
                .filter_map(|key| key.id().map(|id| KeyId(id.to_owned())))
                .collect(),
            next: output.position().map(str::to_owned),
        })
    }
}

/// The pause between control-plane calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Pacing(Duration);

impl Pacing {
    /// Long enough that `replicas` gateways reading at once stay within the
    /// budget: each waits `replicas / budget` seconds between calls.
    pub(crate) fn for_replicas(replicas: NonZeroU32) -> Self {
        Self(
            Duration::from_secs(1)
                .saturating_mul(replicas.get())
                .checked_div(BUDGET_CALLS_PER_SECOND)
                .unwrap_or(Duration::ZERO),
        )
    }

    #[cfg(test)]
    pub(crate) const fn of(pause: Duration) -> Self {
        Self(pause)
    }

    async fn pause(self) {
        if !self.0.is_zero() {
            tokio::time::sleep(Backoff::jittered(self.0)).await;
        }
    }
}

/// Reads the keys and usage plans of one stage.
pub(crate) struct UsageReader<S> {
    source: S,
    api_id: String,
    stage: String,
    pacing: Pacing,
}

impl<S: ControlPlane> UsageReader<S> {
    pub(crate) fn new(source: S, api_id: &str, stage: &str, pacing: Pacing) -> Self {
        Self {
            source,
            api_id: api_id.to_owned(),
            stage: stage.to_owned(),
            pacing,
        }
    }

    fn limits(plan: &PlanRecord, stage: &StageRecord) -> PlanLimits {
        PlanLimits {
            throttle: plan.throttle,
            methods: stage.methods.clone(),
            quota: plan.quota,
        }
    }

    /// The usage plans that include the stage.
    async fn plans(&self) -> Result<Vec<UsagePlan>, UsageError> {
        let mut plans = Vec::new();
        let mut position: Option<String> = None;
        loop {
            let page = self.source.usage_plans(position.as_deref()).await?;
            for plan in &page.items {
                if let Some(stage) = plan
                    .stages
                    .iter()
                    .find(|s| s.api_id == self.api_id && s.stage == self.stage)
                {
                    plans.push(UsagePlan {
                        id: plan.id.clone(),
                        limits: Self::limits(plan, stage),
                    });
                }
            }
            match page.next {
                Some(next) => {
                    position = Some(next);
                    self.pacing.pause().await;
                }
                None => return Ok(plans),
            }
        }
    }

    async fn members(&self, plan: &PlanId) -> Result<Vec<KeyId>, UsageError> {
        let mut members = Vec::new();
        let mut position: Option<String> = None;
        loop {
            let page = self.source.plan_keys(plan, position.as_deref()).await?;
            members.extend(page.items);
            match page.next {
                Some(next) => {
                    position = Some(next);
                    self.pacing.pause().await;
                }
                None => return Ok(members),
            }
        }
    }

    /// The enabled state and value digest of every key in `wanted`.
    async fn keys(
        &self,
        wanted: &std::collections::HashSet<KeyId>,
    ) -> Result<Vec<(Sha256Digest, KeyRecord)>, UsageError> {
        let mut keys = Vec::new();
        let mut position: Option<String> = None;
        loop {
            let page = self.source.api_keys(position.as_deref()).await?;
            for key in page.items {
                if wanted.contains(&key.id) {
                    keys.push((
                        key.value.into_digest(),
                        KeyRecord {
                            id: key.id,
                            enabled: key.enabled,
                        },
                    ));
                }
            }
            match page.next {
                Some(next) => {
                    position = Some(next);
                    self.pacing.pause().await;
                }
                None => return Ok(keys),
            }
        }
    }

    /// Reads the plans of the stage, their keys, and the keys' values and
    /// state. When no plan includes the stage, the account's keys are not read.
    ///
    /// # Errors
    ///
    /// When any call fails; a partial read is never returned.
    pub(crate) async fn read(&self) -> Result<UsageData, UsageError> {
        let plans = self.plans().await?;
        let mut memberships = Vec::new();
        for plan in &plans {
            self.pacing.pause().await;
            for key in self.members(&plan.id).await? {
                memberships.push((plan.id.clone(), key));
            }
        }
        let wanted: std::collections::HashSet<KeyId> =
            memberships.iter().map(|(_, key)| key.clone()).collect();
        let keys = if wanted.is_empty() {
            Vec::new()
        } else {
            self.pacing.pause().await;
            self.keys(&wanted).await?
        };
        Ok(UsageData::new(keys, plans, memberships))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests;
