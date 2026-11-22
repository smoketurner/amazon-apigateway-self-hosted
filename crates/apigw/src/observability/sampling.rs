//! X-Ray sampling for requests whose caller made no decision: the rules and
//! reservoir quotas X-Ray serves (`GetSamplingRules`, `GetSamplingTargets`),
//! as the X-Ray SDKs apply them, with X-Ray's default rule (the first request
//! each second, then a percentage) until rules are read or when they cannot be.
//!
//! <https://docs.aws.amazon.com/xray/latest/devguide/xray-console-sampling.html>
//! <https://docs.aws.amazon.com/xray/latest/api/API_GetSamplingTargets.html>

use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::Duration;

use aws_sdk_xray::primitives::DateTime;
use aws_sdk_xray::types::{SamplingRule, SamplingStatisticsDocument, SamplingTargetDocument};
use tokio_util::sync::CancellationToken;

use crate::authz::{CaseSensitivity, Glob};
use crate::entropy::Entropy;

/// What sampling rules match a request on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SamplingRequest<'a> {
    /// The segment name, `{api name}/{stage}`.
    pub(crate) service_name: &'a str,
    pub(crate) host: &'a str,
    pub(crate) method: &'a str,
    pub(crate) url_path: &'a str,
    /// `arn:{partition}:apigateway:{region}::/restapis/{id}/stages/{stage}`.
    pub(crate) resource_arn: &'a str,
}

/// The service type API Gateway segments report, which rules may name.
const SERVICE_TYPE: &str = "AWS::ApiGateway::Stage";

/// A reservoir quota X-Ray assigned to this client.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Quota {
    per_second: u32,
    expires: jiff::Timestamp,
}

/// What one rule counts between reports, and the reservoir it draws from.
#[derive(Debug, Default)]
struct RuleState {
    requests: u32,
    sampled: u32,
    borrowed: u32,
    quota: Option<Quota>,
    /// The fixed rate from the latest target, which replaces the rule's.
    fixed_rate: Option<f64>,
    second: i64,
    taken_this_second: u32,
}

#[derive(Debug)]
struct Rule {
    name: String,
    priority: i32,
    fixed_rate: f64,
    service_name: Glob,
    service_type: Glob,
    host: Glob,
    http_method: Glob,
    url_path: Glob,
    resource_arn: Glob,
    state: Mutex<RuleState>,
}

impl Rule {
    /// Rules with attributes match on request attributes this gateway does not
    /// have, so they never match; version 1 is the only rule format.
    fn from_sdk(rule: &SamplingRule) -> Option<Self> {
        if rule.version() != 1 || rule.attributes().is_some_and(|a| !a.is_empty()) {
            return None;
        }
        let glob = |pattern: &str| Glob::new(pattern, CaseSensitivity::Insensitive);
        Some(Self {
            name: rule.rule_name()?.to_owned(),
            priority: rule.priority(),
            fixed_rate: rule.fixed_rate(),
            service_name: glob(rule.service_name()),
            service_type: glob(rule.service_type()),
            host: glob(rule.host()),
            http_method: glob(rule.http_method()),
            url_path: glob(rule.url_path()),
            resource_arn: glob(rule.resource_arn()),
            state: Mutex::new(RuleState::default()),
        })
    }

    fn matches(&self, request: &SamplingRequest<'_>) -> bool {
        self.service_name.matches(request.service_name)
            && self.service_type.matches(SERVICE_TYPE)
            && self.host.matches(request.host)
            && self.http_method.matches(request.method)
            && self.url_path.matches(request.url_path)
            && self.resource_arn.matches(request.resource_arn)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, RuleState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The reservoir first: the quota X-Ray assigned while it is valid, else
    /// one borrowed request per second; then the fixed rate.
    fn sample(&self, now: jiff::Timestamp, roll: f64) -> bool {
        let mut state = self.state();
        state.requests = state.requests.saturating_add(1);
        let second = now.as_second();
        if state.second != second {
            state.second = second;
            state.taken_this_second = 0;
        }
        let quota = state.quota.filter(|quota| quota.expires > now);
        let reservoir = quota.map_or(1, |quota| quota.per_second);
        if state.taken_this_second < reservoir {
            state.taken_this_second = state.taken_this_second.saturating_add(1);
            state.sampled = state.sampled.saturating_add(1);
            if quota.is_none() {
                state.borrowed = state.borrowed.saturating_add(1);
            }
            return true;
        }
        let rate = state.fixed_rate.unwrap_or(self.fixed_rate);
        if roll < rate {
            state.sampled = state.sampled.saturating_add(1);
            return true;
        }
        false
    }
}

/// Decides which requests are traced when the caller did not say.
#[derive(Debug)]
pub(crate) struct Sampler {
    percent: u8,
    last_reservoir_second: Mutex<i64>,
    /// X-Ray's rules, by ascending priority then name, once read.
    rules: RwLock<Option<Arc<[Rule]>>>,
}

impl Sampler {
    /// `percent` is clamped to 0..=100.
    pub(crate) fn new(percent: u8) -> Self {
        Self {
            percent: percent.min(100),
            last_reservoir_second: Mutex::new(i64::MIN),
            rules: RwLock::new(None),
        }
    }

    /// A uniform number in `[0, 1)`; `1.0` (never below a rate) when no
    /// randomness is available.
    fn roll() -> f64 {
        Entropy::bytes::<4>().map_or(1.0, |bytes| {
            f64::from(u32::from_be_bytes(bytes)) / 4_294_967_296.0
        })
    }

    pub(crate) fn sample(&self, request: &SamplingRequest<'_>, now: jiff::Timestamp) -> bool {
        let rules = self
            .rules
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Some(rule) = rules
            .as_deref()
            .and_then(|rules| rules.iter().find(|rule| rule.matches(request)))
        {
            return rule.sample(now, Self::roll());
        }
        self.sample_by_default(now)
    }

    /// X-Ray's default rule: the first request each second, then `percent`.
    fn sample_by_default(&self, now: jiff::Timestamp) -> bool {
        let second = now.as_second();
        {
            let mut last = self
                .last_reservoir_second
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            if *last != second {
                *last = second;
                return true;
            }
        }
        Self::roll() < f64::from(self.percent) / 100.0
    }

    /// Replaces the rules, keeping the quota of rules that are still there.
    fn set_rules(&self, rules: &[SamplingRule]) {
        let previous = self
            .rules
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let mut next: Vec<Rule> = rules.iter().filter_map(Rule::from_sdk).collect();
        next.sort_by(|a, b| {
            a.priority
                .cmp(&b.priority)
                .then_with(|| a.name.cmp(&b.name))
        });
        if let Some(previous) = previous {
            for rule in &next {
                if let Some(old) = previous.iter().find(|old| old.name == rule.name) {
                    let old = old.state();
                    let mut state = rule.state();
                    state.quota = old.quota;
                    state.fixed_rate = old.fixed_rate;
                }
            }
        }
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Some(Arc::from(next));
    }

    /// Every rule's counts since the last report, which are reset.
    fn statistics(&self, client_id: &str, now: jiff::Timestamp) -> Vec<SamplingStatisticsDocument> {
        let rules = self
            .rules
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(rules) = rules else {
            return Vec::new();
        };
        let mut documents = Vec::new();
        for rule in rules.iter() {
            let mut state = rule.state();
            let counts = (
                std::mem::take(&mut state.requests),
                std::mem::take(&mut state.sampled),
                std::mem::take(&mut state.borrowed),
            );
            drop(state);
            let (requests, sampled, borrowed) = counts;
            if requests == 0 {
                continue;
            }
            let document = SamplingStatisticsDocument::builder()
                .rule_name(&rule.name)
                .client_id(client_id)
                .timestamp(DateTime::from_secs(now.as_second()))
                .request_count(i32::try_from(requests).unwrap_or(i32::MAX))
                .sampled_count(i32::try_from(sampled).unwrap_or(i32::MAX))
                .borrow_count(i32::try_from(borrowed).unwrap_or(i32::MAX))
                .build();
            match document {
                Ok(document) => documents.push(document),
                Err(err) => tracing::warn!(%err, "could not report sampling statistics"),
            }
        }
        documents
    }

    fn apply_targets(&self, targets: &[SamplingTargetDocument]) {
        let rules = self
            .rules
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let Some(rules) = rules else {
            return;
        };
        for target in targets {
            let Some(rule) = rules
                .iter()
                .find(|r| Some(r.name.as_str()) == target.rule_name())
            else {
                continue;
            };
            let mut state = rule.state();
            state.fixed_rate = Some(target.fixed_rate());
            if let (Some(quota), Some(ttl)) =
                (target.reservoir_quota(), target.reservoir_quota_ttl())
                && let Ok(expires) = jiff::Timestamp::from_second(ttl.secs())
            {
                state.quota = Some(Quota {
                    per_second: u32::try_from(quota).unwrap_or(0),
                    expires,
                });
            }
        }
    }
}

/// Reads X-Ray's sampling rules every five minutes and reports statistics for
/// reservoir quotas every ten seconds, as the X-Ray SDKs do.
pub(crate) struct RulePoller {
    client: aws_sdk_xray::Client,
    sampler: Arc<Sampler>,
    /// Identifies this process to X-Ray: 24 hex digits.
    client_id: String,
}

impl RulePoller {
    const RULES_INTERVAL: Duration = Duration::from_mins(5);
    const TARGETS_INTERVAL: Duration = Duration::from_secs(10);
    const CALL_TIMEOUT: Duration = Duration::from_secs(10);

    pub(crate) fn new(client: aws_sdk_xray::Client, sampler: Arc<Sampler>) -> Self {
        let id = Entropy::bytes::<12>().unwrap_or_default();
        let client_id = id
            .iter()
            .flat_map(|byte| [byte >> 4, byte & 0x0f])
            .filter_map(|nibble| char::from_digit(u32::from(nibble), 16))
            .collect();
        Self {
            client,
            sampler,
            client_id,
        }
    }

    pub(crate) async fn run(self, closed: CancellationToken) {
        let mut rules = tokio::time::interval(Self::RULES_INTERVAL);
        let mut targets = tokio::time::interval(Self::TARGETS_INTERVAL);
        targets.tick().await;
        let mut rules_read_at = None;
        loop {
            tokio::select! {
                biased;
                () = closed.cancelled() => return,
                _ = rules.tick() => {
                    if self.read_rules().await {
                        rules_read_at = Some(jiff::Timestamp::now());
                    }
                }
                _ = targets.tick() => {
                    if let Some(modified) = self.report().await
                        && rules_read_at.is_none_or(|read| modified > read)
                        && self.read_rules().await
                    {
                        rules_read_at = Some(jiff::Timestamp::now());
                    }
                }
            }
        }
    }

    /// Reads every rule; `false` keeps the rules in use.
    async fn read_rules(&self) -> bool {
        let mut all = Vec::new();
        let mut token = None;
        loop {
            let call = self
                .client
                .get_sampling_rules()
                .set_next_token(token.take())
                .send();
            let page = match tokio::time::timeout(Self::CALL_TIMEOUT, call).await {
                Ok(Ok(page)) => page,
                Ok(Err(err)) => {
                    tracing::warn!(
                        err = %aws_sdk_xray::error::DisplayErrorContext(err),
                        "could not read X-Ray sampling rules; keeping the rules in use"
                    );
                    return false;
                }
                Err(_) => {
                    tracing::warn!("reading X-Ray sampling rules timed out");
                    return false;
                }
            };
            all.extend(
                page.sampling_rule_records()
                    .iter()
                    .filter_map(|record| record.sampling_rule().cloned()),
            );
            match page.next_token() {
                Some(next) if !next.is_empty() => token = Some(next.to_owned()),
                Some(_) | None => break,
            }
        }
        tracing::debug!(rules = all.len(), "read X-Ray sampling rules");
        self.sampler.set_rules(&all);
        true
    }

    /// Reports statistics and applies the targets X-Ray answers with. Returns
    /// when the rules were last modified, so changed rules are read again.
    async fn report(&self) -> Option<jiff::Timestamp> {
        let statistics = self
            .sampler
            .statistics(&self.client_id, jiff::Timestamp::now());
        if statistics.is_empty() {
            return None;
        }
        let call = self
            .client
            .get_sampling_targets()
            .set_sampling_statistics_documents(Some(statistics))
            .send();
        let output = match tokio::time::timeout(Self::CALL_TIMEOUT, call).await {
            Ok(Ok(output)) => output,
            Ok(Err(err)) => {
                tracing::warn!(
                    err = %aws_sdk_xray::error::DisplayErrorContext(err),
                    "could not report X-Ray sampling statistics"
                );
                return None;
            }
            Err(_) => {
                tracing::warn!("reporting X-Ray sampling statistics timed out");
                return None;
            }
        };
        self.sampler
            .apply_targets(output.sampling_target_documents());
        output
            .last_rule_modification()
            .and_then(|at| jiff::Timestamp::from_second(at.secs()).ok())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::observability::testing::{MockAws, Reply};

    const REQUEST: SamplingRequest<'static> = SamplingRequest {
        service_name: "Pets/prod",
        host: "api.example.com",
        method: "GET",
        url_path: "/pets/7",
        resource_arn: "arn:aws:apigateway:us-east-1::/restapis/abc/stages/prod",
    };

    fn now() -> jiff::Timestamp {
        jiff::Timestamp::from_second(1_700_000_000).unwrap()
    }

    fn rule(name: &str, priority: i32, fixed_rate: f64, url_path: &str) -> SamplingRule {
        SamplingRule::builder()
            .rule_name(name)
            .resource_arn("*")
            .priority(priority)
            .fixed_rate(fixed_rate)
            .reservoir_size(1)
            .service_name("*")
            .service_type("*")
            .host("*")
            .http_method("*")
            .url_path(url_path)
            .version(1)
            .build()
            .unwrap()
    }

    #[test]
    fn without_rules_the_default_rule_applies() {
        let sampler = Sampler::new(0);
        assert!(
            sampler.sample(&REQUEST, now()),
            "the first request each second"
        );
        assert!(!sampler.sample(&REQUEST, now()), "then 0%");
        assert!(sampler.sample(&REQUEST, now() + jiff::SignedDuration::from_secs(1)));
        let always = Sampler::new(100);
        assert!(always.sample(&REQUEST, now()));
        assert!(always.sample(&REQUEST, now()));
        assert_eq!(Sampler::new(250).percent, 100);
    }

    #[test]
    fn the_highest_priority_matching_rule_decides() {
        let sampler = Sampler::new(100);
        sampler.set_rules(&[
            rule("Default", 10_000, 1.0, "*"),
            rule("never-pets", 1, 0.0, "/pets/*"),
            rule("with-attributes", 0, 1.0, "*").to_builder_with_attributes(),
        ]);
        assert!(
            sampler.sample(&REQUEST, now()),
            "the borrowed request of the second"
        );
        assert!(!sampler.sample(&REQUEST, now()), "never-pets has a 0 rate");
        let other = SamplingRequest {
            url_path: "/owners",
            ..REQUEST
        };
        assert!(sampler.sample(&other, now()));
        assert!(sampler.sample(&other, now()), "Default samples everything");
        let stats = sampler.statistics("client", now());
        let pets = stats
            .iter()
            .find(|s| s.rule_name() == "never-pets")
            .unwrap();
        assert_eq!(
            (
                pets.request_count(),
                pets.sampled_count(),
                pets.borrow_count()
            ),
            (2, 1, 1)
        );
        let default = stats.iter().find(|s| s.rule_name() == "Default").unwrap();
        assert_eq!(default.request_count(), 2);
        assert!(stats.iter().all(|s| s.rule_name() != "with-attributes"));
        assert!(
            sampler.statistics("client", now()).is_empty(),
            "counts reset once reported"
        );
    }

    #[test]
    fn a_reservoir_quota_replaces_borrowing_until_it_expires() {
        let sampler = Sampler::new(0);
        sampler.set_rules(&[rule("r", 1, 0.0, "*")]);
        sampler.apply_targets(&[SamplingTargetDocument::builder()
            .rule_name("r")
            .fixed_rate(0.0)
            .reservoir_quota(2)
            .reservoir_quota_ttl(DateTime::from_secs(now().as_second() + 60))
            .build()]);
        let decisions: Vec<bool> = (0..3).map(|_| sampler.sample(&REQUEST, now())).collect();
        assert_eq!(decisions, [true, true, false]);
        let later = now() + jiff::SignedDuration::from_secs(120);
        let decisions: Vec<bool> = (0..2).map(|_| sampler.sample(&REQUEST, later)).collect();
        assert_eq!(
            decisions,
            [true, false],
            "an expired quota borrows one a second"
        );
        let stats = sampler.statistics("client", later);
        assert_eq!(stats[0].borrow_count(), 1);
        sampler.set_rules(&[rule("r", 1, 0.0, "*")]);
        let kept = sampler.rules.read().unwrap().clone().unwrap();
        assert!(
            kept[0].state().quota.is_some(),
            "quotas survive a rule refresh"
        );
    }

    #[test]
    fn a_target_fixed_rate_replaces_the_rules() {
        let sampler = Sampler::new(0);
        sampler.set_rules(&[rule("r", 1, 0.0, "*")]);
        sampler.apply_targets(&[SamplingTargetDocument::builder()
            .rule_name("r")
            .fixed_rate(1.0)
            .build()]);
        assert!(sampler.sample(&REQUEST, now()));
        assert!(sampler.sample(&REQUEST, now()));
    }

    #[test]
    fn rules_match_case_insensitively_with_wildcards() {
        let mut matching = rule("r", 1, 0.0, "/PETS/?");
        matching = SamplingRule::builder()
            .rule_name(matching.rule_name().unwrap())
            .resource_arn("arn:aws:apigateway:*::/restapis/abc/stages/prod")
            .priority(1)
            .fixed_rate(0.0)
            .reservoir_size(1)
            .service_name("pets/*")
            .service_type("AWS::ApiGateway::*")
            .host("*.example.com")
            .http_method("get")
            .url_path("/PETS/?")
            .version(1)
            .build()
            .unwrap();
        let compiled = Rule::from_sdk(&matching).unwrap();
        assert!(compiled.matches(&REQUEST));
        assert!(!compiled.matches(&SamplingRequest {
            method: "POST",
            ..REQUEST
        }));
        assert!(!compiled.matches(&SamplingRequest {
            url_path: "/pets/77",
            ..REQUEST
        }));
        let v2 = SamplingRule::builder()
            .rule_name("v2")
            .resource_arn("*")
            .priority(1)
            .fixed_rate(0.0)
            .reservoir_size(1)
            .service_name("*")
            .service_type("*")
            .host("*")
            .http_method("*")
            .url_path("*")
            .version(2)
            .build()
            .unwrap();
        assert!(Rule::from_sdk(&v2).is_none());
    }

    trait WithAttributes {
        fn to_builder_with_attributes(self) -> SamplingRule;
    }

    impl WithAttributes for SamplingRule {
        fn to_builder_with_attributes(self) -> SamplingRule {
            Self::builder()
                .rule_name(self.rule_name().unwrap())
                .resource_arn("*")
                .priority(self.priority())
                .fixed_rate(self.fixed_rate())
                .reservoir_size(1)
                .service_name("*")
                .service_type("*")
                .host("*")
                .http_method("*")
                .url_path("*")
                .version(1)
                .attributes("customer", "x")
                .build()
                .unwrap()
        }
    }

    #[tokio::test]
    async fn the_poller_reads_rules_and_reports_statistics_to_x_ray() {
        let aws = MockAws::start().await;
        aws.reply(
            "/GetSamplingRules",
            Reply::json(
                &json!({"SamplingRuleRecords": [{"SamplingRule": {
                    "RuleName": "r", "ResourceARN": "*", "Priority": 1, "FixedRate": 0.0,
                    "ReservoirSize": 1, "ServiceName": "*", "ServiceType": "*", "Host": "*",
                    "HTTPMethod": "*", "URLPath": "*", "Version": 1}}]})
                .to_string(),
            ),
        );
        aws.reply(
            "/SamplingTargets",
            Reply::json(
                &json!({"SamplingTargetDocuments": [{"RuleName": "r", "FixedRate": 0.0,
                    "ReservoirQuota": 5, "ReservoirQuotaTTL": now().as_second() + 600}]})
                .to_string(),
            ),
        );
        let sampler = Arc::new(Sampler::new(100));
        let poller = RulePoller::new(
            aws_sdk_xray::Client::new(&aws.sdk_config()),
            Arc::clone(&sampler),
        );
        assert_eq!(poller.client_id.len(), 24);
        assert!(poller.read_rules().await);
        assert!(sampler.sample(&REQUEST, now()));
        assert!(
            !sampler.sample(&REQUEST, now()),
            "the rule's 0 rate, not 100%"
        );
        assert_eq!(poller.report().await, None);
        let reported: Vec<_> = aws
            .calls()
            .into_iter()
            .filter(|c| c.target == "/SamplingTargets")
            .collect();
        assert_eq!(reported.len(), 1);
        let document = &reported[0].body["SamplingStatisticsDocuments"][0];
        assert_eq!(document["RuleName"], "r");
        assert_eq!(document["RequestCount"], 2);
        assert_eq!(document["SampledCount"], 1);
        assert_eq!(document["BorrowCount"], 1);
        let rule = &sampler.rules.read().unwrap().clone().unwrap()[0];
        assert_eq!(rule.state().quota.map(|q| q.per_second), Some(5));
    }

    #[tokio::test]
    async fn a_failed_read_keeps_the_default_rule() {
        let aws = MockAws::start().await;
        aws.reply("/GetSamplingRules", Reply::error("ThrottledException"));
        let sampler = Arc::new(Sampler::new(100));
        let poller = RulePoller::new(
            aws_sdk_xray::Client::new(&aws.sdk_config()),
            Arc::clone(&sampler),
        );
        assert!(!poller.read_rules().await);
        assert!(sampler.rules.read().unwrap().is_none());
        assert!(sampler.sample(&REQUEST, now()));
        assert!(sampler.sample(&REQUEST, now()), "100% by default");
    }
}
