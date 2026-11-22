//! The gateway's own metrics: API traffic and the health of the process
//! (configuration refreshes, certificates, usage plans, the state backend,
//! authorizer caches, and token signing keys).
//!
//! Instruments are created once from an OpenTelemetry [`Meter`], so the same
//! metrics reach Prometheus (`/metrics` on the admin listener) and, when
//! enabled, OTLP. Every label is bounded: route templates, never raw paths;
//! methods outside the standard set are reported as `OTHER`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram, Meter, MeterProvider as _, UpDownCounter};

/// Histogram boundaries, in seconds, for request and integration latency.
/// API Gateway's integration timeout is at most 29 seconds.
const LATENCY_BOUNDARIES: [f64; 13] = [
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 15.0, 30.0,
];

/// Methods that may appear as the `method` label.
const STANDARD_METHODS: [&str; 7] = ["GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"];

/// The API stage a metric is about.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ApiStage {
    pub(crate) api_id: String,
    pub(crate) stage: String,
}

impl ApiStage {
    pub(crate) fn new(api_id: &str, stage: Option<&str>) -> Self {
        Self {
            api_id: api_id.to_owned(),
            stage: stage.unwrap_or("$default").to_owned(),
        }
    }

    fn labels(&self) -> [KeyValue; 2] {
        [
            KeyValue::new("api_id", self.api_id.clone()),
            KeyValue::new("stage", self.stage.clone()),
        ]
    }
}

/// The labels of one request's metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestLabels {
    api: ApiStage,
    method: String,
    /// The route template (`/pets/{petId}`), `$default`, or `(none)` for a
    /// request no route matched.
    route: String,
}

impl RequestLabels {
    pub(crate) const UNMATCHED: &'static str = "(none)";

    pub(crate) fn new(api: ApiStage, method: &str, route: &str) -> Self {
        let method = if STANDARD_METHODS.contains(&method) {
            method.to_owned()
        } else {
            "OTHER".to_owned()
        };
        Self {
            api,
            method,
            route: route.to_owned(),
        }
    }

    fn attributes(&self) -> Vec<KeyValue> {
        let [api_id, stage] = self.api.labels();
        vec![
            api_id,
            stage,
            KeyValue::new("method", self.method.clone()),
            KeyValue::new("route", self.route.clone()),
        ]
    }
}

/// What one finished request contributes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct RequestOutcome {
    pub(crate) status: u16,
    pub(crate) latency: Duration,
    pub(crate) integration_latency: Option<Duration>,
    /// `Some(true)` for a response cache hit, `Some(false)` for a miss.
    pub(crate) cache_hit: Option<bool>,
    /// Request and response bytes, when known.
    pub(crate) data_processed: u64,
}

/// How one configuration refresh ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefreshOutcome {
    /// The source reported nothing new.
    Unchanged,
    /// A new definition was built and is being served.
    Swapped,
    /// The source could not be read.
    FetchFailed,
    /// The definition could not be built; the previous one keeps serving.
    Rejected,
}

impl RefreshOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Unchanged => "unchanged",
            Self::Swapped => "swapped",
            Self::FetchFailed => "fetch_failed",
            Self::Rejected => "rejected",
        }
    }

    /// Whether the served routes reflect the source afterwards.
    fn is_success(self) -> bool {
        match self {
            Self::Unchanged | Self::Swapped => true,
            Self::FetchFailed | Self::Rejected => false,
        }
    }
}

/// Success or failure of a background operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Outcome {
    Success,
    Failure,
}

impl Outcome {
    fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

impl<T, E> From<&Result<T, E>> for Outcome {
    fn from(result: &Result<T, E>) -> Self {
        if result.is_ok() {
            Self::Success
        } else {
            Self::Failure
        }
    }
}

/// What a loaded API stage looks like, for the info and route gauges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LoadedApi {
    deployment_id: Option<String>,
    routes: u64,
    unservable: u64,
    last_refresh: Option<jiff::Timestamp>,
}

/// State the gauges report when they are collected.
#[derive(Debug, Default)]
struct Health {
    apis: BTreeMap<ApiStage, LoadedApi>,
    usage: BTreeMap<ApiStage, jiff::Timestamp>,
    certificates: BTreeMap<String, jiff::Timestamp>,
}

#[derive(Debug, Default)]
struct SharedHealth(Mutex<Health>);

impl SharedHealth {
    fn with<T>(&self, f: impl FnOnce(&mut Health) -> T) -> T {
        f(&mut self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[derive(Debug)]
struct Instruments {
    requests: Counter<u64>,
    request_duration: Histogram<f64>,
    integration_duration: Histogram<f64>,
    cache_hits: Counter<u64>,
    cache_misses: Counter<u64>,
    data_processed: Counter<u64>,
    in_flight: UpDownCounter<i64>,
    config_refreshes: Counter<u64>,
    usage_refreshes: Counter<u64>,
    tls_reloads: Counter<u64>,
    state_errors: Counter<u64>,
    authorizer_cache_hits: Counter<u64>,
    authorizer_cache_misses: Counter<u64>,
    jwks_fetches: Counter<u64>,
}

/// The gateway's instruments. Cheap to clone.
#[derive(Debug, Clone)]
pub(crate) struct GatewayMetrics {
    instruments: Arc<Instruments>,
    health: Arc<SharedHealth>,
}

static GLOBAL: OnceLock<GatewayMetrics> = OnceLock::new();

/// The version this binary reports; `APIGW_GIT_COMMIT` is set by the image
/// builds.
const VERSION: &str = env!("CARGO_PKG_VERSION");
const COMMIT: Option<&str> = option_env!("APIGW_GIT_COMMIT");

impl GatewayMetrics {
    /// Creates every instrument on `meter`.
    pub(crate) fn new(meter: &Meter) -> Self {
        let health = Arc::new(SharedHealth::default());
        let counter = |name: &'static str, unit: &'static str, description: &'static str| {
            meter
                .u64_counter(name)
                .with_unit(unit)
                .with_description(description)
                .build()
        };
        let latency = |name: &'static str, description: &'static str| {
            meter
                .f64_histogram(name)
                .with_unit("s")
                .with_description(description)
                .with_boundaries(LATENCY_BOUNDARIES.to_vec())
                .build()
        };
        let instruments = Instruments {
            requests: counter("apigw.requests", "", "Requests answered, by status class."),
            request_duration: latency(
                "apigw.request.duration",
                "Time from receiving a request to sending its response headers (API Gateway's Latency).",
            ),
            integration_duration: latency(
                "apigw.integration.duration",
                "Time spent in the integration (API Gateway's IntegrationLatency).",
            ),
            cache_hits: counter(
                "apigw.cache.hits",
                "",
                "Requests answered from the response cache.",
            ),
            cache_misses: counter(
                "apigw.cache.misses",
                "",
                "Requests to cached routes that the cache could not answer.",
            ),
            data_processed: counter(
                "apigw.data.processed",
                "By",
                "Request and response bytes of known length (API Gateway's DataProcessed).",
            ),
            in_flight: meter
                .i64_up_down_counter("apigw.requests.in_flight")
                .with_description("Requests being handled.")
                .build(),
            config_refreshes: counter(
                "apigw.config.refreshes",
                "",
                "API definition refresh attempts, by outcome.",
            ),
            usage_refreshes: counter(
                "apigw.usage.refreshes",
                "",
                "API key and usage plan reads, by outcome.",
            ),
            tls_reloads: counter(
                "apigw.tls.reloads",
                "",
                "Reloads of changed certificate files, by outcome.",
            ),
            state_errors: counter(
                "apigw.state.errors",
                "",
                "State backend (Valkey) calls that failed or timed out, by operation.",
            ),
            authorizer_cache_hits: counter(
                "apigw.authorizer.cache.hits",
                "",
                "Lambda authorizer results answered from the cache.",
            ),
            authorizer_cache_misses: counter(
                "apigw.authorizer.cache.misses",
                "",
                "Lambda authorizer invocations for identities that were not cached.",
            ),
            jwks_fetches: counter(
                "apigw.jwks.fetches",
                "",
                "Token signing key fetches, by outcome.",
            ),
        };
        Self::register_gauges(meter, &health);
        Self {
            instruments: Arc::new(instruments),
            health,
        }
    }

    /// Gauges read their value when collected; their instruments live as long
    /// as the meter provider.
    #[expect(
        clippy::too_many_lines,
        reason = "one declaration per gauge, read top to bottom"
    )]
    fn register_gauges(meter: &Meter, health: &Arc<SharedHealth>) {
        meter
            .u64_observable_gauge("apigw.build.info")
            .with_description("Always 1; the labels name the running build.")
            .with_callback(|observer| {
                observer.observe(
                    1,
                    &[
                        KeyValue::new("version", VERSION),
                        KeyValue::new(
                            "commit",
                            COMMIT.filter(|c| !c.is_empty()).unwrap_or("unknown"),
                        ),
                    ],
                );
            })
            .build();
        let state = Arc::clone(health);
        meter
            .u64_observable_gauge("apigw.api.info")
            .with_description("Always 1 per loaded API stage; the labels name its deployment.")
            .with_callback(move |observer| {
                state.with(|health| {
                    for (api, loaded) in &health.apis {
                        let [api_id, stage] = api.labels();
                        let deployment = loaded.deployment_id.clone().unwrap_or_default();
                        observer.observe(
                            1,
                            &[api_id, stage, KeyValue::new("deployment_id", deployment)],
                        );
                    }
                });
            })
            .build();
        let state = Arc::clone(health);
        meter
            .u64_observable_gauge("apigw.routes")
            .with_description("Routes of each loaded API stage.")
            .with_callback(move |observer| {
                state.with(|health| {
                    for (api, loaded) in &health.apis {
                        observer.observe(loaded.routes, &api.labels());
                    }
                });
            })
            .build();
        let state = Arc::clone(health);
        meter
            .u64_observable_gauge("apigw.routes.unservable")
            .with_description(
                "Routes of each loaded API stage whose integration cannot be served (501).",
            )
            .with_callback(move |observer| {
                state.with(|health| {
                    for (api, loaded) in &health.apis {
                        observer.observe(loaded.unservable, &api.labels());
                    }
                });
            })
            .build();
        let state = Arc::clone(health);
        meter
            .f64_observable_gauge("apigw.config.last_success_timestamp")
            .with_unit("s")
            .with_description(
                "When each API stage's definition was last read successfully, in Unix seconds.",
            )
            .with_callback(move |observer| {
                state.with(|health| {
                    for (api, loaded) in &health.apis {
                        if let Some(at) = loaded.last_refresh {
                            observer.observe(Self::unix_seconds(at), &api.labels());
                        }
                    }
                });
            })
            .build();
        let state = Arc::clone(health);
        meter
            .f64_observable_gauge("apigw.usage.last_success_timestamp")
            .with_unit("s")
            .with_description(
                "When each stage's API keys and usage plans were last read, in Unix seconds.",
            )
            .with_callback(move |observer| {
                state.with(|health| {
                    for (api, at) in &health.usage {
                        observer.observe(Self::unix_seconds(*at), &api.labels());
                    }
                });
            })
            .build();
        let state = Arc::clone(health);
        meter
            .f64_observable_gauge("apigw.tls.certificate.expiry")
            .with_unit("s")
            .with_description(
                "Seconds until each served certificate's notAfter; negative once it has expired.",
            )
            .with_callback(move |observer| {
                let now = jiff::Timestamp::now();
                state.with(|health| {
                    for (name, not_after) in &health.certificates {
                        observer.observe(
                            now.duration_until(*not_after).as_secs_f64(),
                            &[KeyValue::new("certificate", name.clone())],
                        );
                    }
                });
            })
            .build();
    }

    fn unix_seconds(at: jiff::Timestamp) -> f64 {
        at.as_duration().as_secs_f64()
    }

    /// The process's instruments: those [`Self::install`] set, else instruments
    /// that record nothing.
    pub(crate) fn global() -> &'static Self {
        GLOBAL.get_or_init(|| {
            Self::new(&opentelemetry::metrics::noop::NoopMeterProvider::new().meter("apigw"))
        })
    }

    /// Makes these the instruments [`Self::global`] returns. Only the first
    /// call has an effect.
    pub(crate) fn install(&self) {
        if GLOBAL.set(self.clone()).is_err() {
            tracing::warn!("gateway metrics were already installed");
        }
    }

    pub(crate) fn request(&self, labels: &RequestLabels, outcome: RequestOutcome) {
        let attributes = labels.attributes();
        let mut with_status = attributes.clone();
        with_status.push(KeyValue::new(
            "status_class",
            Self::status_class(outcome.status),
        ));
        let i = &self.instruments;
        i.requests.add(1, &with_status);
        i.request_duration
            .record(outcome.latency.as_secs_f64(), &attributes);
        if let Some(latency) = outcome.integration_latency {
            i.integration_duration
                .record(latency.as_secs_f64(), &attributes);
        }
        match outcome.cache_hit {
            Some(true) => i.cache_hits.add(1, &attributes),
            Some(false) => i.cache_misses.add(1, &attributes),
            None => {}
        }
        if outcome.data_processed > 0 {
            i.data_processed.add(outcome.data_processed, &attributes);
        }
    }

    fn status_class(status: u16) -> &'static str {
        match status {
            100..=199 => "1xx",
            200..=299 => "2xx",
            300..=399 => "3xx",
            400..=499 => "4xx",
            _ => "5xx",
        }
    }

    /// Counts a request as in flight until the returned guard is dropped.
    pub(crate) fn in_flight(&self) -> InFlight {
        self.instruments.in_flight.add(1, &[]);
        InFlight(Arc::clone(&self.instruments))
    }

    /// Records a definition that is now being served.
    pub(crate) fn loaded(
        &self,
        api: &ApiStage,
        deployment_id: Option<&str>,
        routes: usize,
        unservable: usize,
    ) {
        let now = jiff::Timestamp::now();
        self.health.with(|health| {
            health.apis.insert(
                api.clone(),
                LoadedApi {
                    deployment_id: deployment_id.map(str::to_owned),
                    routes: u64::try_from(routes).unwrap_or(u64::MAX),
                    unservable: u64::try_from(unservable).unwrap_or(u64::MAX),
                    last_refresh: Some(now),
                },
            );
        });
    }

    /// Forgets a stage that is no longer served.
    pub(crate) fn unloaded(&self, api: &ApiStage) {
        self.health.with(|health| {
            health.apis.remove(api);
            health.usage.remove(api);
        });
    }

    pub(crate) fn refresh(&self, api: &ApiStage, outcome: RefreshOutcome) {
        let [api_id, stage] = api.labels();
        self.instruments.config_refreshes.add(
            1,
            &[api_id, stage, KeyValue::new("outcome", outcome.label())],
        );
        if outcome.is_success() {
            let now = jiff::Timestamp::now();
            self.health.with(|health| {
                if let Some(loaded) = health.apis.get_mut(api) {
                    loaded.last_refresh = Some(now);
                }
            });
        }
    }

    pub(crate) fn usage_refresh(&self, api: &ApiStage, outcome: Outcome) {
        let [api_id, stage] = api.labels();
        self.instruments.usage_refreshes.add(
            1,
            &[api_id, stage, KeyValue::new("outcome", outcome.label())],
        );
        if outcome == Outcome::Success {
            let now = jiff::Timestamp::now();
            self.health.with(|health| {
                health.usage.insert(api.clone(), now);
            });
        }
    }

    /// Records the certificate served as `name` (`default` or a custom domain).
    pub(crate) fn certificate(&self, name: &str, not_after: Option<jiff::Timestamp>) {
        self.health.with(|health| match not_after {
            Some(at) => {
                health.certificates.insert(name.to_owned(), at);
            }
            None => {
                health.certificates.remove(name);
            }
        });
    }

    pub(crate) fn tls_reload(&self, outcome: Outcome) {
        self.instruments
            .tls_reloads
            .add(1, &[KeyValue::new("outcome", outcome.label())]);
    }

    pub(crate) fn state_error(&self, operation: &'static str) {
        self.instruments
            .state_errors
            .add(1, &[KeyValue::new("operation", operation)]);
    }

    pub(crate) fn authorizer_cache(&self, api: &ApiStage, authorizer: &str, hit: bool) {
        let [api_id, stage] = api.labels();
        let labels = [
            api_id,
            stage,
            KeyValue::new("authorizer", authorizer.to_owned()),
        ];
        if hit {
            self.instruments.authorizer_cache_hits.add(1, &labels);
        } else {
            self.instruments.authorizer_cache_misses.add(1, &labels);
        }
    }

    pub(crate) fn jwks_fetch(&self, issuer: &str, outcome: Outcome) {
        self.instruments.jwks_fetches.add(
            1,
            &[
                KeyValue::new("issuer", issuer.to_owned()),
                KeyValue::new("outcome", outcome.label()),
            ],
        );
    }
}

/// A request being handled; dropping it ends the count.
#[derive(Debug)]
pub(crate) struct InFlight(Arc<Instruments>);

impl Drop for InFlight {
    fn drop(&mut self) {
        self.0.in_flight.add(-1, &[]);
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use opentelemetry_sdk::metrics::SdkMeterProvider;

    use super::*;
    use crate::telemetry::PrometheusRegistry;

    /// Instruments, the registry that renders them, and the provider that
    /// must outlive every render.
    fn metrics() -> (GatewayMetrics, PrometheusRegistry, SdkMeterProvider) {
        let registry = PrometheusRegistry::new();
        let provider = registry.meter_provider_builder().unwrap().build();
        let metrics = GatewayMetrics::new(&provider.meter("apigw"));
        (metrics, registry, provider)
    }

    fn api() -> ApiStage {
        ApiStage::new("abc123", Some("prod"))
    }

    fn line<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
        text.lines().find(|l| l.starts_with(prefix))
    }

    #[test]
    fn requests_are_counted_by_status_class_with_bounded_labels() {
        let (metrics, registry, _provider) = metrics();
        let labels = RequestLabels::new(api(), "GET", "/pets/{petId}");
        let ok = RequestOutcome {
            status: 200,
            latency: Duration::from_millis(30),
            integration_latency: Some(Duration::from_millis(20)),
            cache_hit: Some(true),
            data_processed: 120,
        };
        metrics.request(&labels, ok);
        metrics.request(
            &labels,
            RequestOutcome {
                status: 404,
                cache_hit: Some(false),
                ..ok
            },
        );
        metrics.request(&labels, RequestOutcome { status: 502, ..ok });
        metrics.request(
            &RequestLabels::new(api(), "PROPFIND", RequestLabels::UNMATCHED),
            RequestOutcome {
                status: 403,
                integration_latency: None,
                cache_hit: None,
                data_processed: 0,
                ..ok
            },
        );
        let text = registry.render();
        let base = r#"api_id="abc123",method="GET",route="/pets/{petId}",stage="prod""#;
        for class in ["2xx", "4xx", "5xx"] {
            let series = format!("apigw_requests_total{{{base},status_class=\"{class}\"}} 1");
            assert!(text.contains(&series), "{series}\n{text}");
        }
        assert!(text.contains(r#"apigw_requests_total{api_id="abc123",method="OTHER",route="(none)",stage="prod",status_class="4xx"} 1"#), "{text}");
        assert!(
            text.contains(&format!("apigw_request_duration_seconds_count{{{base}}} 3")),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "apigw_request_duration_seconds_bucket{{{base},le=\"0.05\"}} 3"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!(
                "apigw_integration_duration_seconds_sum{{{base}}} 0.06"
            )),
            "{text}"
        );
        assert!(
            text.contains(&format!("apigw_cache_hits_total{{{base}}} 2")),
            "{text}"
        );
        assert!(
            text.contains(&format!("apigw_cache_misses_total{{{base}}} 1")),
            "{text}"
        );
        assert!(
            text.contains(&format!("apigw_data_processed_bytes_total{{{base}}} 360")),
            "{text}"
        );
        assert!(text.contains("# TYPE apigw_requests_total counter"));
        assert!(text.contains("# TYPE apigw_request_duration_seconds histogram"));
        assert!(!text.contains("otel_scope"), "no scope labels: {text}");
    }

    #[test]
    fn in_flight_requests_rise_and_fall() {
        let (metrics, registry, _provider) = metrics();
        let first = metrics.in_flight();
        let second = metrics.in_flight();
        assert_eq!(
            line(&registry.render(), "apigw_requests_in_flight "),
            Some("apigw_requests_in_flight 2")
        );
        drop(first);
        drop(second);
        assert_eq!(
            line(&registry.render(), "apigw_requests_in_flight "),
            Some("apigw_requests_in_flight 0")
        );
    }

    #[test]
    fn refreshes_report_outcomes_the_deployment_and_the_last_success() {
        let (metrics, registry, _provider) = metrics();
        let api = api();
        metrics.loaded(&api, Some("dep1"), 5, 1);
        metrics.refresh(&api, RefreshOutcome::Unchanged);
        metrics.refresh(&api, RefreshOutcome::FetchFailed);
        metrics.refresh(&api, RefreshOutcome::FetchFailed);
        metrics.refresh(&api, RefreshOutcome::Rejected);
        metrics.loaded(&api, Some("dep2"), 6, 0);
        metrics.refresh(&api, RefreshOutcome::Swapped);
        let text = registry.render();
        for (outcome, count) in [
            ("unchanged", 1),
            ("fetch_failed", 2),
            ("rejected", 1),
            ("swapped", 1),
        ] {
            let series = format!(
                r#"apigw_config_refreshes_total{{api_id="abc123",outcome="{outcome}",stage="prod"}} {count}"#
            );
            assert!(text.contains(&series), "{series}\n{text}");
        }
        assert!(
            text.contains(r#"apigw_api_info{api_id="abc123",deployment_id="dep2",stage="prod"} 1"#),
            "{text}"
        );
        assert!(!text.contains("dep1"), "the old deployment is gone: {text}");
        assert!(text.contains(r#"apigw_routes{api_id="abc123",stage="prod"} 6"#));
        assert!(text.contains(r#"apigw_routes_unservable{api_id="abc123",stage="prod"} 0"#));
        let last = line(&text, "apigw_config_last_success_timestamp_seconds{").unwrap();
        let seconds: f64 = last.rsplit(' ').next().unwrap().parse().unwrap();
        let now = jiff::Timestamp::now().as_duration().as_secs_f64();
        assert!((now - seconds).abs() < 60.0, "{last}");
        metrics.unloaded(&api);
        assert!(!registry.render().contains("apigw_api_info{"));
    }

    #[test]
    fn a_failed_refresh_does_not_move_the_last_success() {
        let (metrics, registry, _provider) = metrics();
        let api = api();
        metrics.loaded(&api, None, 1, 0);
        metrics.health.with(|h| {
            h.apis.get_mut(&api).unwrap().last_refresh =
                Some(jiff::Timestamp::from_second(1_000).unwrap());
        });
        metrics.refresh(&api, RefreshOutcome::FetchFailed);
        metrics.refresh(&api, RefreshOutcome::Rejected);
        assert!(registry.render().contains(
            r#"apigw_config_last_success_timestamp_seconds{api_id="abc123",stage="prod"} 1000"#
        ));
        metrics.refresh(&api, RefreshOutcome::Unchanged);
        assert!(!registry.render().contains("} 1000\n"));
    }

    #[test]
    fn usage_tls_state_authorizer_and_key_metrics_are_reported() {
        let (metrics, registry, _provider) = metrics();
        let api = api();
        metrics.usage_refresh(&api, Outcome::Success);
        metrics.usage_refresh(&api, Outcome::Failure);
        let expires = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(48);
        metrics.certificate("default", Some(expires));
        metrics.certificate(
            "api.example.com",
            Some(jiff::Timestamp::from_second(0).unwrap()),
        );
        metrics.tls_reload(Outcome::Success);
        metrics.tls_reload(Outcome::Failure);
        metrics.state_error("take_token");
        metrics.authorizer_cache(&api, "auth", true);
        metrics.authorizer_cache(&api, "auth", false);
        metrics.jwks_fetch("https://issuer.example.com", Outcome::Failure);
        let text = registry.render();
        for series in [
            r#"apigw_usage_refreshes_total{api_id="abc123",outcome="success",stage="prod"} 1"#,
            r#"apigw_usage_refreshes_total{api_id="abc123",outcome="failure",stage="prod"} 1"#,
            r#"apigw_tls_reloads_total{outcome="success"} 1"#,
            r#"apigw_tls_reloads_total{outcome="failure"} 1"#,
            r#"apigw_state_errors_total{operation="take_token"} 1"#,
            r#"apigw_authorizer_cache_hits_total{api_id="abc123",authorizer="auth",stage="prod"} 1"#,
            r#"apigw_authorizer_cache_misses_total{api_id="abc123",authorizer="auth",stage="prod"} 1"#,
            r#"apigw_jwks_fetches_total{issuer="https://issuer.example.com",outcome="failure"} 1"#,
            "apigw_usage_last_success_timestamp_seconds{",
        ] {
            assert!(text.contains(series), "{series}\n{text}");
        }
        let default = line(
            &text,
            r#"apigw_tls_certificate_expiry_seconds{certificate="default"}"#,
        )
        .unwrap();
        let seconds: f64 = default.rsplit(' ').next().unwrap().parse().unwrap();
        assert!(
            seconds > 47.0 * 3600.0 && seconds <= 48.0 * 3600.0,
            "{default}"
        );
        let expired = line(
            &text,
            r#"apigw_tls_certificate_expiry_seconds{certificate="api.example.com"}"#,
        )
        .unwrap();
        assert!(
            expired.contains(" -"),
            "an expired certificate is negative: {expired}"
        );
        assert!(
            line(&text, "apigw_build_info{")
                .unwrap()
                .contains(&format!("version=\"{VERSION}\""))
        );
    }

    #[test]
    fn the_global_instruments_record_nothing_until_installed() {
        let metrics = GatewayMetrics::global();
        metrics.state_error("cache_get");
        let _guard = metrics.in_flight();
    }

    #[test]
    fn status_classes_cover_every_status() {
        assert_eq!(GatewayMetrics::status_class(101), "1xx");
        assert_eq!(GatewayMetrics::status_class(304), "3xx");
        assert_eq!(GatewayMetrics::status_class(599), "5xx");
        assert_eq!(GatewayMetrics::status_class(0), "5xx");
    }
}
