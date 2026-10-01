//! API keys and usage plans of a REST API stage.
//!
//! A method that requires an API key admits a request only when the key is
//! enabled and belongs to a usage plan that includes the stage; the plan's
//! throttle and quota then apply to that key. Keys, plans, and their
//! associations are read live from API Gateway ([`source`]) because they change
//! independently of deployments ([`store`] keeps them fresh).
//!
//! Key values are never kept: each is hashed with SHA-256 the moment it is read,
//! and a presented key is hashed the same way for lookup.
//! See <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html>.

mod plan;
mod source;
mod store;

use std::collections::{BTreeMap, HashMap};

pub(crate) use plan::{PlanLimits, UsageChecker, UsageOutcome};
pub(crate) use source::{AwsUsageSource, Pacing, UsageReader};
pub(crate) use store::UsageStore;

use crate::digest::Sha256Digest;
use crate::model::{ApiKeySource, ApiModel, Operation, Protection};

/// How a route relates to API keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RouteApiKey {
    NotRequired,
    /// The method requires a key, found where the API says.
    Required(ApiKeySource),
    /// The method requires a key this gateway cannot check, for the reason
    /// given, so the route refuses requests.
    Unevaluable(String),
}

impl RouteApiKey {
    pub(crate) fn is_unevaluable(&self) -> bool {
        matches!(self, Self::Unevaluable(_))
    }

    pub(crate) fn unevaluable_reason(&self) -> Option<&str> {
        match *self {
            Self::Unevaluable(ref reason) => Some(reason),
            Self::NotRequired | Self::Required(_) => None,
        }
    }
}

/// Where the API says keys are, and whether keys can be checked at all.
#[derive(Debug, Clone)]
pub(crate) struct ApiKeyRules {
    source: ApiKeySource,
    /// Keys are only read from a REST API stage in API Gateway.
    available: bool,
}

impl ApiKeyRules {
    pub(crate) fn compile(model: &ApiModel, usage: Option<&UsageStore>) -> Self {
        Self {
            source: model
                .settings
                .api_key_source
                .unwrap_or(ApiKeySource::Header),
            available: usage.is_some(),
        }
    }

    pub(crate) fn for_route(&self, operation: &Operation) -> RouteApiKey {
        if !operation.protections.contains(Protection::ApiKey) {
            return RouteApiKey::NotRequired;
        }
        if self.available {
            RouteApiKey::Required(self.source)
        } else {
            RouteApiKey::Unevaluable(
                "API keys and usage plans are only read from a REST API stage in API Gateway"
                    .to_owned(),
            )
        }
    }
}

/// A usage plan's identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct PlanId(pub(crate) String);

/// An API key's identifier (not its value).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct KeyId(pub(crate) String);

/// A key value as read from API Gateway. It is secret: it has no `Debug` and
/// cannot be cloned, and exists only to be hashed.
pub(crate) struct KeyValue(String);

impl KeyValue {
    pub(crate) fn new(value: String) -> Self {
        Self(value)
    }

    /// The lookup form of a key value, presented or read.
    pub(crate) fn digest(value: &str) -> Sha256Digest {
        Sha256Digest::of_parts(&[value])
    }

    pub(crate) fn into_digest(self) -> Sha256Digest {
        Self::digest(&self.0)
    }
}

/// What the gateway knows about one API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeyRecord {
    pub(crate) id: KeyId,
    pub(crate) enabled: bool,
}

/// The keys and usage plans of one stage at one point in time.
#[derive(Debug, Clone, Default)]
pub(crate) struct UsageData {
    keys: HashMap<Sha256Digest, KeyRecord>,
    plans: BTreeMap<PlanId, UsagePlan>,
    /// The plans each key belongs to, among those that include the stage.
    memberships: HashMap<KeyId, Vec<PlanId>>,
}

/// A usage plan that includes the stage.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UsagePlan {
    pub(crate) id: PlanId,
    pub(crate) limits: PlanLimits,
}

/// A key that may be used, with the plans that govern it.
#[derive(Debug)]
pub(crate) struct KeyAccess<'a> {
    pub(crate) key: &'a KeyId,
    pub(crate) plans: Vec<&'a UsagePlan>,
}

impl UsageData {
    /// Builds the data from what API Gateway returned.
    pub(crate) fn new(
        keys: impl IntoIterator<Item = (Sha256Digest, KeyRecord)>,
        plans: impl IntoIterator<Item = UsagePlan>,
        memberships: impl IntoIterator<Item = (PlanId, KeyId)>,
    ) -> Self {
        let plans: BTreeMap<PlanId, UsagePlan> = plans
            .into_iter()
            .map(|plan| (plan.id.clone(), plan))
            .collect();
        let mut by_key: HashMap<KeyId, Vec<PlanId>> = HashMap::new();
        for (plan, key) in memberships {
            if plans.contains_key(&plan) {
                by_key.entry(key).or_default().push(plan);
            }
        }
        for members in by_key.values_mut() {
            members.sort();
            members.dedup();
        }
        Self {
            keys: keys.into_iter().collect(),
            plans,
            memberships: by_key,
        }
    }

    /// The key `value`, if it exists, is enabled, and belongs to a usage plan
    /// that includes the stage. Anything else is not a valid key.
    #[cfg(test)]
    pub(crate) fn lookup(&self, value: &str) -> Option<KeyAccess<'_>> {
        self.lookup_digest(&KeyValue::digest(value))
    }

    /// [`UsageData::lookup`] for a key already hashed.
    pub(crate) fn lookup_digest(&self, digest: &Sha256Digest) -> Option<KeyAccess<'_>> {
        let record = self.keys.get(digest)?;
        if !record.enabled {
            return None;
        }
        let plans: Vec<&UsagePlan> = self
            .memberships
            .get(&record.id)?
            .iter()
            .filter_map(|plan| self.plans.get(plan))
            .collect();
        (!plans.is_empty()).then_some(KeyAccess {
            key: &record.id,
            plans,
        })
    }

    pub(crate) fn plan_count(&self) -> usize {
        self.plans.len()
    }

    pub(crate) fn key_count(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    pub(super) fn plan(id: &str) -> UsagePlan {
        UsagePlan {
            id: PlanId(id.to_owned()),
            limits: PlanLimits::default(),
        }
    }

    fn key(value: &str, id: &str, enabled: bool) -> (Sha256Digest, KeyRecord) {
        (
            KeyValue::digest(value),
            KeyRecord {
                id: KeyId(id.to_owned()),
                enabled,
            },
        )
    }

    fn member(plan: &str, key: &str) -> (PlanId, KeyId) {
        (PlanId(plan.to_owned()), KeyId(key.to_owned()))
    }

    fn data() -> UsageData {
        UsageData::new(
            [
                key("secret-a", "k1", true),
                key("secret-b", "k2", false),
                key("secret-c", "k3", true),
                key("secret-d", "k4", true),
            ],
            [plan("p1"), plan("p2")],
            [
                member("p1", "k1"),
                member("p1", "k2"),
                member("p2", "k1"),
                member("p1", "k4"),
                member("p1", "k4"),
                member("elsewhere", "k3"),
            ],
        )
    }

    #[test]
    fn a_key_is_valid_when_enabled_and_in_a_plan_of_the_stage() {
        let data = data();
        let access = data.lookup("secret-a").unwrap();
        assert_eq!(access.key, &KeyId("k1".to_owned()));
        let plans: Vec<&str> = access.plans.iter().map(|p| p.id.0.as_str()).collect();
        assert_eq!(plans, ["p1", "p2"], "every plan of the key applies");
    }

    #[test]
    fn disabled_unknown_and_unplanned_keys_are_not_valid() {
        let data = data();
        assert!(data.lookup("secret-b").is_none(), "disabled");
        assert!(
            data.lookup("secret-c").is_none(),
            "only in a plan of another stage"
        );
        assert!(data.lookup("nope").is_none(), "unknown");
        assert!(data.lookup("").is_none());
        assert!(data.lookup("SECRET-A").is_none(), "keys are case-sensitive");
        assert!(data.lookup("secret-a ").is_none());
    }

    #[test]
    fn duplicate_memberships_count_once() {
        let data = data();
        assert_eq!(data.lookup("secret-d").unwrap().plans.len(), 1);
    }

    #[test]
    fn key_values_are_hashed_and_never_stored() {
        let data = data();
        let debug = format!("{data:?}");
        assert!(!debug.contains("secret-a"), "{debug}");
        assert_eq!((data.key_count(), data.plan_count()), (4, 2));
    }

    #[test]
    fn empty_data_admits_no_key() {
        assert!(UsageData::default().lookup("anything").is_none());
    }
}
