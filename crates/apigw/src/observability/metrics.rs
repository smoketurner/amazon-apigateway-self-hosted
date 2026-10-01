//! API Gateway's CloudWatch metrics, published as CloudWatch embedded metric
//! format (EMF) log events.
//!
//! `AWS/ApiGateway` is reserved for API Gateway itself, so the same metric
//! names are published under a configurable custom namespace. Requests are
//! aggregated in memory and written once a minute: one EMF document per
//! (API, stage, route) with the minute's totals, instead of one per request.
//!
//! Per-request metrics are not reproducible from an aggregate, so what each
//! statistic means differs from API Gateway's:
//! - `Count`, `4XXError`/`5XXError` (`4xx`/`5xx` for HTTP APIs) are published
//!   as one value per minute, so use the `Sum` statistic. `SampleCount` and
//!   `Average` do not mean what they do for `AWS/ApiGateway`.
//! - `Latency` and `IntegrationLatency` are published as up to
//!   [`Reservoir::CAPACITY`] values drawn uniformly from the minute's
//!   requests, so averages and percentiles are estimates and the true maximum
//!   may be missed.
//!
//! <https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format_Specification.html>

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio_util::sync::CancellationToken;

use super::queue::{LogEvent, LogQueue};
use crate::cache::CacheOutcome;
use crate::model::ApiKind;

/// The namespace published metrics go under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MetricsNamespace(String);

impl MetricsNamespace {
    pub(crate) const DEFAULT: &'static str = "ApiGatewaySelfHosted";

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for MetricsNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Default for MetricsNamespace {
    fn default() -> Self {
        Self(Self::DEFAULT.to_owned())
    }
}

impl FromStr for MetricsNamespace {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        if raw.is_empty() || raw.len() > 255 {
            return Err("a namespace is 1 to 255 characters".to_owned());
        }
        if raw.to_ascii_uppercase().starts_with("AWS/") {
            return Err("namespaces starting with `AWS/` are reserved for AWS".to_owned());
        }
        if !raw
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".-_/#:".contains(c) || c == ' ')
        {
            return Err(
                "a namespace may contain letters, digits, spaces, and . - _ / # :".to_owned(),
            );
        }
        Ok(Self(raw.to_owned()))
    }
}

/// The method and resource of a route with detailed metrics.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RouteDimensions {
    pub(crate) method: String,
    pub(crate) resource: String,
}

/// Which series a request counts toward.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct MetricKey {
    pub(crate) kind: ApiKind,
    /// `ApiName` for REST APIs, the API ID for HTTP APIs.
    pub(crate) api: String,
    pub(crate) stage: String,
    pub(crate) route: Option<RouteDimensions>,
}

/// What one finished request contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RequestMetrics {
    /// Whether the response came from the response cache, for routes that use it.
    pub(crate) cache: Option<CacheOutcome>,
    pub(crate) status: u16,
    pub(crate) latency_ms: u64,
    pub(crate) integration_latency_ms: Option<u64>,
}

/// A uniform random sample of at most [`Reservoir::CAPACITY`] values
/// (Vitter's algorithm R).
#[derive(Debug, Clone)]
struct Reservoir {
    seen: u64,
    values: Vec<u64>,
    rng: u64,
}

impl Reservoir {
    /// EMF allows at most 100 values per metric.
    const CAPACITY: usize = 100;

    fn new() -> Self {
        Self {
            seen: 0,
            values: Vec::new(),
            rng: 0x9E37_79B9_7F4A_7C15,
        }
    }

    /// xorshift64*: replacement choices need to be spread evenly, not secret.
    fn next_random(&mut self) -> u64 {
        let mut x = self.rng;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.rng = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn record(&mut self, value: u64) {
        self.seen = self.seen.saturating_add(1);
        if self.values.len() < Self::CAPACITY {
            self.values.push(value);
            return;
        }
        let slot = self.next_random().checked_rem(self.seen).unwrap_or(0);
        if let Some(existing) = usize::try_from(slot)
            .ok()
            .and_then(|slot| self.values.get_mut(slot))
        {
            *existing = value;
        }
    }
}

#[derive(Debug, Clone)]
struct Series {
    count: u64,
    client_errors: u64,
    server_errors: u64,
    latency: Reservoir,
    integration_latency: Reservoir,
    /// Cache hits and misses; `None` until a request consults the cache.
    cache: Option<(u64, u64)>,
}

impl Series {
    fn new() -> Self {
        Self {
            count: 0,
            client_errors: 0,
            server_errors: 0,
            latency: Reservoir::new(),
            integration_latency: Reservoir::new(),
            cache: None,
        }
    }

    fn record(&mut self, request: RequestMetrics) {
        if let Some(outcome) = request.cache {
            let (hits, misses) = self.cache.unwrap_or_default();
            self.cache = Some(match outcome {
                CacheOutcome::Hit => (hits.saturating_add(1), misses),
                CacheOutcome::Miss => (hits, misses.saturating_add(1)),
            });
        }
        self.count = self.count.saturating_add(1);
        match request.status {
            400..=499 => self.client_errors = self.client_errors.saturating_add(1),
            500..=599 => self.server_errors = self.server_errors.saturating_add(1),
            _ => {}
        }
        self.latency.record(request.latency_ms);
        if let Some(latency) = request.integration_latency_ms {
            self.integration_latency.record(latency);
        }
    }
}

impl MetricKey {
    /// `(count, client error, server error)` metric names.
    fn counter_names(&self) -> [&'static str; 3] {
        match self.kind {
            ApiKind::Rest => ["Count", "4XXError", "5XXError"],
            ApiKind::Http => ["Count", "4xx", "5xx"],
        }
    }

    fn api_dimension(&self) -> &'static str {
        match self.kind {
            ApiKind::Rest => "ApiName",
            ApiKind::Http => "ApiId",
        }
    }

    /// The dimension sets one document carries: always the stage's, plus the
    /// route's when detailed metrics are on. CloudWatch adds up documents that
    /// share dimensions, so the stage's series is the sum over its routes.
    fn dimension_sets(&self) -> Vec<Vec<&'static str>> {
        let api = self.api_dimension();
        let mut sets = vec![vec![api, "Stage"]];
        if self.route.is_some() {
            sets.push(vec![api, "Method", "Resource", "Stage"]);
        }
        sets
    }
}

/// Per-minute aggregation of request metrics.
#[derive(Debug)]
pub(crate) struct MetricsAggregator {
    namespace: MetricsNamespace,
    window: Mutex<BTreeMap<MetricKey, Series>>,
}

impl MetricsAggregator {
    pub(crate) fn new(namespace: MetricsNamespace) -> Self {
        Self {
            namespace,
            window: Mutex::new(BTreeMap::new()),
        }
    }

    pub(crate) fn record(&self, key: &MetricKey, request: RequestMetrics) {
        let mut window = self.window.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(series) = window.get_mut(key) {
            series.record(request);
            return;
        }
        let mut series = Series::new();
        series.record(request);
        window.insert(key.clone(), series);
    }

    /// Takes the aggregated window and renders it as EMF documents stamped
    /// `timestamp_ms`, the start of the minute they cover.
    pub(crate) fn drain(&self, timestamp_ms: i64) -> Vec<String> {
        let window =
            std::mem::take(&mut *self.window.lock().unwrap_or_else(PoisonError::into_inner));
        window
            .iter()
            .map(|(key, series)| self.document(key, series, timestamp_ms).to_string())
            .collect()
    }

    fn document(&self, key: &MetricKey, series: &Series, timestamp_ms: i64) -> Value {
        let [count, client, server] = key.counter_names();
        let mut metrics = vec![
            json!({"Name": count, "Unit": "Count"}),
            json!({"Name": client, "Unit": "Count"}),
            json!({"Name": server, "Unit": "Count"}),
            json!({"Name": "Latency", "Unit": "Milliseconds"}),
        ];
        let mut body = Map::new();
        body.insert(count.to_owned(), json!(series.count));
        body.insert(client.to_owned(), json!(series.client_errors));
        body.insert(server.to_owned(), json!(series.server_errors));
        body.insert("Latency".to_owned(), json!(series.latency.values));
        if !series.integration_latency.values.is_empty() {
            metrics.push(json!({"Name": "IntegrationLatency", "Unit": "Milliseconds"}));
            body.insert(
                "IntegrationLatency".to_owned(),
                json!(series.integration_latency.values),
            );
        }
        if let Some((hits, misses)) = series.cache {
            metrics.push(json!({"Name": "CacheHitCount", "Unit": "Count"}));
            metrics.push(json!({"Name": "CacheMissCount", "Unit": "Count"}));
            body.insert("CacheHitCount".to_owned(), json!(hits));
            body.insert("CacheMissCount".to_owned(), json!(misses));
        }
        body.insert(key.api_dimension().to_owned(), json!(key.api));
        body.insert("Stage".to_owned(), json!(key.stage));
        if let Some(ref route) = key.route {
            body.insert("Method".to_owned(), json!(route.method));
            body.insert("Resource".to_owned(), json!(route.resource));
        }
        body.insert(
            "_aws".to_owned(),
            json!({
                "Timestamp": timestamp_ms,
                "CloudWatchMetrics": [{
                    "Namespace": self.namespace.as_str(),
                    "Dimensions": key.dimension_sets(),
                    "Metrics": metrics,
                }],
            }),
        );
        Value::Object(body)
    }

    /// Publishes the window to `queue` at every minute boundary, and the
    /// partial minute at shutdown, until `closed` is cancelled.
    pub(crate) async fn run(&self, queue: LogQueue, closed: CancellationToken) {
        loop {
            let now = jiff::Timestamp::now();
            let wait = Self::until_next_minute(now);
            tokio::select! {
                biased;
                () = closed.cancelled() => break,
                () = tokio::time::sleep(wait) => {}
            }
            let window_start = Self::minute_start(now);
            self.publish(&queue, window_start);
        }
        self.publish(&queue, Self::minute_start(jiff::Timestamp::now()));
    }

    fn publish(&self, queue: &LogQueue, window_start_ms: i64) {
        for document in self.drain(window_start_ms) {
            queue.push(LogEvent::now(document));
        }
    }

    fn minute_start(at: jiff::Timestamp) -> i64 {
        at.as_millisecond()
            .saturating_sub(at.as_millisecond().rem_euclid(60_000))
    }

    fn until_next_minute(at: jiff::Timestamp) -> Duration {
        let into_minute = at.as_millisecond().rem_euclid(60_000);
        let remaining = 60_000_i64.saturating_sub(into_minute);
        Duration::from_millis(u64::try_from(remaining).unwrap_or(60_000))
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn key(kind: ApiKind, route: Option<(&str, &str)>) -> MetricKey {
        MetricKey {
            kind,
            api: "pets".to_owned(),
            stage: "prod".to_owned(),
            route: route.map(|(method, resource)| RouteDimensions {
                method: method.to_owned(),
                resource: resource.to_owned(),
            }),
        }
    }

    fn request(status: u16, latency_ms: u64, integration: Option<u64>) -> RequestMetrics {
        RequestMetrics {
            cache: None,
            status,
            latency_ms,
            integration_latency_ms: integration,
        }
    }

    fn drained(aggregator: &MetricsAggregator) -> Vec<Value> {
        aggregator
            .drain(1_700_000_040_000)
            .iter()
            .map(|d| serde_json::from_str(d).unwrap())
            .collect()
    }

    #[test]
    fn requests_aggregate_into_one_rest_document_per_series() {
        let aggregator = MetricsAggregator::new(MetricsNamespace::default());
        let stage = key(ApiKind::Rest, None);
        aggregator.record(&stage, request(200, 10, Some(8)));
        aggregator.record(&stage, request(404, 2, None));
        aggregator.record(&stage, request(502, 30, Some(25)));
        aggregator.record(&stage, request(200, 4, Some(3)));

        let docs = drained(&aggregator);
        assert_eq!(docs.len(), 1);
        let doc = &docs[0];
        assert_eq!(doc["Count"], 4);
        assert_eq!(doc["4XXError"], 1);
        assert_eq!(doc["5XXError"], 1);
        assert_eq!(doc["ApiName"], "pets");
        assert_eq!(doc["Stage"], "prod");
        assert_eq!(doc["Latency"], json!([10, 2, 30, 4]));
        assert_eq!(doc["IntegrationLatency"], json!([8, 25, 3]));
        let directive = &doc["_aws"]["CloudWatchMetrics"][0];
        assert_eq!(doc["_aws"]["Timestamp"], 1_700_000_040_000_i64);
        assert_eq!(directive["Namespace"], "ApiGatewaySelfHosted");
        assert_eq!(directive["Dimensions"], json!([["ApiName", "Stage"]]));
        let names: Vec<&str> = directive["Metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["Name"].as_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "Count",
                "4XXError",
                "5XXError",
                "Latency",
                "IntegrationLatency"
            ]
        );
        assert!(
            aggregator.drain(0).is_empty(),
            "draining empties the window"
        );
    }

    #[test]
    fn cache_hits_and_misses_are_published_once_the_cache_is_consulted() {
        let aggregator = MetricsAggregator::new(MetricsNamespace::default());
        let stage = key(ApiKind::Rest, None);
        let cached = |outcome| RequestMetrics {
            cache: Some(outcome),
            ..request(200, 1, None)
        };
        aggregator.record(&stage, cached(CacheOutcome::Hit));
        aggregator.record(&stage, cached(CacheOutcome::Hit));
        aggregator.record(&stage, cached(CacheOutcome::Miss));
        aggregator.record(&stage, request(200, 1, None));
        let docs = drained(&aggregator);
        assert_eq!(docs[0]["CacheHitCount"], 2);
        assert_eq!(docs[0]["CacheMissCount"], 1);
        assert_eq!(docs[0]["Count"], 4);
        let names: Vec<&str> = docs[0]["_aws"]["CloudWatchMetrics"][0]["Metrics"]
            .as_array()
            .unwrap()
            .iter()
            .map(|m| m["Name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"CacheHitCount") && names.contains(&"CacheMissCount"));
    }

    #[test]
    fn series_that_never_consult_the_cache_publish_no_cache_metrics() {
        let aggregator = MetricsAggregator::new(MetricsNamespace::default());
        aggregator.record(&key(ApiKind::Rest, None), request(200, 1, None));
        let docs = drained(&aggregator);
        assert!(docs[0].get("CacheHitCount").is_none());
        assert!(docs[0].get("CacheMissCount").is_none());
    }

    #[test]
    fn detailed_routes_add_the_method_and_resource_dimension_set() {
        let aggregator = MetricsAggregator::new(MetricsNamespace::default());
        aggregator.record(
            &key(ApiKind::Rest, Some(("GET", "/pets/{petId}"))),
            request(200, 5, None),
        );
        let docs = drained(&aggregator);
        let doc = &docs[0];
        assert_eq!(doc["Method"], "GET");
        assert_eq!(doc["Resource"], "/pets/{petId}");
        assert_eq!(
            doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"],
            json!([
                ["ApiName", "Stage"],
                ["ApiName", "Method", "Resource", "Stage"]
            ])
        );
        assert!(doc.get("IntegrationLatency").is_none());
    }

    #[test]
    fn http_apis_use_their_own_metric_and_dimension_names() {
        let aggregator = MetricsAggregator::new("Custom/Ns".parse().unwrap());
        aggregator.record(&key(ApiKind::Http, None), request(500, 1, None));
        let docs = drained(&aggregator);
        let doc = &docs[0];
        assert_eq!(doc["5xx"], 1);
        assert_eq!(doc["4xx"], 0);
        assert_eq!(doc["Count"], 1);
        assert_eq!(doc["ApiId"], "pets");
        assert!(doc.get("ApiName").is_none());
        assert_eq!(
            doc["_aws"]["CloudWatchMetrics"][0]["Namespace"],
            "Custom/Ns"
        );
        assert_eq!(
            doc["_aws"]["CloudWatchMetrics"][0]["Dimensions"],
            json!([["ApiId", "Stage"]])
        );
    }

    #[test]
    fn series_are_kept_apart_by_route() {
        let aggregator = MetricsAggregator::new(MetricsNamespace::default());
        aggregator.record(
            &key(ApiKind::Rest, Some(("GET", "/a"))),
            request(200, 1, None),
        );
        aggregator.record(
            &key(ApiKind::Rest, Some(("GET", "/b"))),
            request(200, 1, None),
        );
        aggregator.record(&key(ApiKind::Rest, None), request(200, 1, None));
        assert_eq!(drained(&aggregator).len(), 3);
    }

    #[test]
    fn namespaces_reject_the_reserved_prefix_and_bad_characters() {
        assert!("ApiGatewaySelfHosted".parse::<MetricsNamespace>().is_ok());
        assert!("My Team/Api-GW_1".parse::<MetricsNamespace>().is_ok());
        for bad in [
            "",
            "AWS/ApiGateway",
            "aws/apigateway",
            "bad$name",
            &"x".repeat(256),
        ] {
            assert!(bad.parse::<MetricsNamespace>().is_err(), "{bad}");
        }
    }

    #[test]
    fn minute_boundaries_are_computed_from_the_wall_clock() {
        let at = jiff::Timestamp::from_millisecond(1_700_000_012_345).unwrap();
        assert_eq!(MetricsAggregator::minute_start(at), 1_699_999_980_000);
        assert_eq!(
            MetricsAggregator::until_next_minute(at),
            Duration::from_millis(60_000 - 32_345)
        );
    }

    #[tokio::test]
    async fn shutdown_publishes_the_partial_minute() {
        use crate::observability::queue::{Shipper, Worker};
        let aggregator = std::sync::Arc::new(MetricsAggregator::new(MetricsNamespace::default()));
        aggregator.record(&key(ApiKind::Rest, None), request(200, 1, None));
        let (queue, _worker) = Worker::new(Shipper::Stdout, CancellationToken::new());
        let closed = CancellationToken::new();
        closed.cancel();
        aggregator.run(queue.clone(), closed).await;
        assert!(aggregator.drain(0).is_empty());
    }

    proptest! {
        #[test]
        fn reservoirs_never_exceed_the_emf_value_limit(values in proptest::collection::vec(0_u64..10_000, 0..500)) {
            let mut reservoir = Reservoir::new();
            for value in &values {
                reservoir.record(*value);
            }
            prop_assert!(reservoir.values.len() <= Reservoir::CAPACITY);
            prop_assert_eq!(reservoir.values.len(), values.len().min(Reservoir::CAPACITY));
            prop_assert!(reservoir.values.iter().all(|v| values.contains(v)));
            prop_assert_eq!(reservoir.seen, u64::try_from(values.len()).unwrap());
        }
    }
}
