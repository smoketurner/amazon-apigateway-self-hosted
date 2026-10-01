//! What the gateway records about each request of one loaded API stage:
//! access log lines, metrics, execution logs, and X-Ray segments.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::HttpBody as _;
use axum::extract::Request;
use axum::http::{HeaderName, HeaderValue, Method, header};
use axum::response::Response;
use serde_json::{Value, json};

use super::Observability;
use super::exec::Outcome;
use super::format::AccessLogFormat;
use super::metrics::{MetricKey, MetricsAggregator, RequestMetrics, RouteDimensions};
use super::queue::{LogEvent, LogQueue};
use super::trace::{Sampler, SegmentOutcome, Trace};
use crate::canary::Release;
use crate::gateway::ApiContext;
use crate::model::{ApiKind, ApiModel, ExecutionLogging, MethodMatch, RouteKey};
use crate::pipeline::RequestContext;
use crate::pipeline::context::{ApiInfo, IntegrationOutcome};
use crate::route::Route;

/// How long the integration of a request took, attached to the response by the
/// pipeline so the observer can report `$context.integrationLatency`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct IntegrationTiming(pub(crate) Duration);

/// Methods that may appear as the `Method` metric dimension. A route that
/// accepts any method would otherwise let clients create a metric per
/// invented method name.
const STANDARD_METHODS: [&str; 7] = ["GET", "PUT", "POST", "DELETE", "PATCH", "HEAD", "OPTIONS"];

#[derive(Debug)]
struct AccessLog {
    format: AccessLogFormat,
    /// Every queue a line goes to: the stage's destination, plus the canary
    /// destination for canary requests.
    queues: Vec<LogQueue>,
}

#[derive(Debug)]
struct Metrics {
    aggregator: Arc<MetricsAggregator>,
    api: String,
}

/// X-Ray tracing for the stage.
#[derive(Debug)]
struct Tracing {
    sampler: Arc<Sampler>,
    queue: LogQueue,
    /// The segment name, `{api name}/{stage}`.
    segment_name: String,
}

impl Tracing {
    const TRACE_HEADER: HeaderName = HeaderName::from_static("x-amzn-trace-id");
    const TRACEPARENT: HeaderName = HeaderName::from_static("traceparent");

    /// Continues or starts the request's trace and stamps the request with it:
    /// `X-Amzn-Trace-Id` names this gateway's segment as the parent, so
    /// integrations and Lambda attach their segments beneath it. Requests with
    /// an unusable header get a new trace.
    fn start(&self, request: &mut Request) -> Option<Trace> {
        let header = |name: &HeaderName| request.headers().get(name).and_then(|v| v.to_str().ok());
        let trace = Trace::start(
            header(&Self::TRACE_HEADER),
            header(&Self::TRACEPARENT),
            &self.sampler,
            jiff::Timestamp::now(),
        )?;
        match HeaderValue::try_from(trace.header().to_string()) {
            Ok(value) => {
                request.headers_mut().insert(Self::TRACE_HEADER, value);
            }
            Err(err) => tracing::warn!(%err, "could not set the trace header"),
        }
        request.extensions_mut().insert(trace);
        Some(trace)
    }
}

/// How a route is observed beyond the stage-wide settings.
#[derive(Debug, Default)]
struct RouteSettings {
    execution_logging: Option<ExecutionLogging>,
    /// The route's `Method` and `Resource` dimensions when detailed metrics are
    /// on. The method is `None` for routes that accept any method.
    detailed: Option<(Option<String>, String)>,
}

#[derive(Debug)]
struct Inner {
    api: ApiInfo,
    access_log: Option<AccessLog>,
    execution_queues: Vec<LogQueue>,
    metrics: Option<Metrics>,
    tracing: Option<Tracing>,
    routes: BTreeMap<RouteKey, RouteSettings>,
}

/// The observation settings of one loaded stage. Cheap to clone; a disabled
/// observer does no work per request.
#[derive(Debug, Clone, Default)]
pub(crate) struct StageObserver(Option<Arc<Inner>>);

/// A request that has been started and not finished.
pub(crate) struct Pending {
    started: Instant,
    started_at: jiff::Timestamp,
    trace: Option<Trace>,
    method: Method,
    route: Option<RouteKey>,
    context: Option<RequestContext>,
}

impl StageObserver {
    pub(crate) fn disabled() -> Self {
        Self(None)
    }

    /// Resolves each route's settings from the stage and connects the stage to
    /// the shared delivery queues.
    pub(crate) fn new(
        observability: &Observability,
        model: &ApiModel,
        api_id: &str,
        stage: Option<&str>,
        release: Option<Release>,
    ) -> Self {
        let api = ApiInfo {
            kind: model.kind,
            api_id: api_id.to_owned(),
            stage: stage.map(str::to_owned),
            release,
        };
        let access_log = model.stage.access_log.as_ref().and_then(|settings| {
            let format = settings.format.as_deref().filter(|f| !f.is_empty())?;
            let queues =
                observability.access_log_queues(settings.destination_arn.as_deref(), release);
            (!queues.is_empty()).then(|| AccessLog {
                format: AccessLogFormat::from(format),
                queues,
            })
        });

        let mut routes = BTreeMap::new();
        for operation in &model.operations {
            let settings = model.stage.settings_for(&operation.method, &operation.path);
            // Execution logs are a REST API feature: HTTP APIs only support
            // logging levels on WebSocket APIs.
            let execution_logging = (model.kind == ApiKind::Rest)
                .then(|| settings.execution_logging())
                .flatten();
            let detailed = settings.detailed_metrics().then(|| {
                let method = match operation.method {
                    MethodMatch::Any => None,
                    MethodMatch::Exact(ref method) => Some(method.to_string()),
                };
                (method, operation.path.to_string())
            });
            routes.insert(
                operation.route_key.clone(),
                RouteSettings {
                    execution_logging,
                    detailed,
                },
            );
        }
        let execution_queues = if routes.values().any(|r| r.execution_logging.is_some()) {
            observability.execution_queues(api_id, api.stage_name(), release)
        } else {
            Vec::new()
        };
        let metrics = observability.metrics().map(|aggregator| Metrics {
            aggregator,
            api: Self::api_dimension(model, api_id),
        });

        let tracing = model
            .stage
            .tracing_enabled
            .then(|| observability.trace_queue())
            .flatten()
            .map(|queue| Tracing {
                sampler: observability.sampler(),
                queue,
                segment_name: format!(
                    "{}/{}",
                    Self::api_dimension(model, api_id),
                    api.stage_name()
                ),
            });

        if access_log.is_none()
            && execution_queues.is_empty()
            && metrics.is_none()
            && tracing.is_none()
        {
            return Self::disabled();
        }
        Self(Some(Arc::new(Inner {
            api,
            access_log,
            execution_queues,
            metrics,
            tracing,
            routes,
        })))
    }

    /// REST metrics are keyed by API name (ASCII only, as API Gateway strips
    /// other characters, falling back to the API ID); HTTP metrics by API ID.
    fn api_dimension(model: &ApiModel, api_id: &str) -> String {
        match model.kind {
            ApiKind::Http => api_id.to_owned(),
            ApiKind::Rest => {
                let name: String = model
                    .settings
                    .title
                    .as_deref()
                    .unwrap_or_default()
                    .chars()
                    .filter(char::is_ascii)
                    .collect();
                if name.is_empty() {
                    api_id.to_owned()
                } else {
                    name
                }
            }
        }
    }

    /// Starts observing `request`, which `route` will handle (`None` when no
    /// route matches). Returns `None` when there is nothing to record.
    pub(crate) fn begin(
        &self,
        api: &ApiContext,
        request: &mut Request,
        route: Option<&Route>,
    ) -> Option<Pending> {
        let inner = self.0.as_ref()?;
        let started_at = jiff::Timestamp::now();
        let trace = inner.tracing.as_ref().and_then(|t| t.start(request));
        let route_key = route.map(|r| r.key.clone());
        let settings = route_key.as_ref().and_then(|key| inner.routes.get(key));
        let wants_context = inner.access_log.is_some()
            || settings.is_some_and(|s| s.execution_logging.is_some())
            || trace.is_some_and(|t| t.is_sampled());
        Some(Pending {
            started: Instant::now(),
            started_at,
            trace,
            method: request.method().clone(),
            route: route_key,
            context: wants_context.then(|| RequestContext::observed(api, route, request)),
        })
    }

    /// Records the finished request and returns the response unchanged.
    pub(crate) fn finish(&self, pending: Option<Pending>, mut response: Response) -> Response {
        let (Some(inner), Some(pending)) = (self.0.as_ref(), pending) else {
            return response;
        };
        let timing = response.extensions_mut().remove::<IntegrationTiming>();
        let latency_ms = Self::millis(pending.started.elapsed());
        let integration_ms = timing.map(|t| Self::millis(t.0));
        let status = response.status().as_u16();
        let settings = pending.route.as_ref().and_then(|key| inner.routes.get(key));

        if let Some(ref metrics) = inner.metrics {
            let request = RequestMetrics {
                status,
                latency_ms,
                integration_latency_ms: integration_ms,
            };
            for key in inner.metric_keys(metrics, settings, &pending.method) {
                metrics.aggregator.record(&key, request);
            }
        }
        let Some(mut context) = pending.context else {
            return response;
        };
        context.integration = IntegrationOutcome {
            status: integration_ms.map(|_| status),
            latency_ms: integration_ms,
            error: None,
            ..IntegrationOutcome::default()
        };
        if let Some(logging) = settings
            .and_then(|s| s.execution_logging)
            .filter(|_| !inner.execution_queues.is_empty())
        {
            let outcome = Outcome {
                status,
                integration: integration_ms.map(|ms| (status, ms)),
            };
            for line in logging.lines(&context, outcome) {
                let event = LogEvent::now(line);
                for queue in &inner.execution_queues {
                    queue.push(event.clone());
                }
            }
        }
        if let (Some(trace), Some(tracing)) = (
            pending.trace.filter(Trace::is_sampled),
            inner.tracing.as_ref(),
        ) {
            let segment = trace.segment(
                &tracing.segment_name,
                &context,
                SegmentOutcome {
                    started: pending.started_at,
                    ended: jiff::Timestamp::now(),
                    status,
                    content_length: Self::response_length(&response),
                },
            );
            tracing.queue.push(LogEvent::now(segment));
        }
        if let Some(ref access_log) = inner.access_log {
            let variables = Self::access_log_variables(
                &context,
                status,
                Self::response_length(&response),
                latency_ms,
            );
            let event = LogEvent::now(access_log.format.render(&variables));
            for queue in &access_log.queues {
                queue.push(event.clone());
            }
        }
        response
    }

    /// The request's `$context` plus what is only known once the response is.
    fn access_log_variables(
        context: &RequestContext,
        status: u16,
        response_length: Option<u64>,
        latency_ms: u64,
    ) -> Value {
        let mut variables = context.variables();
        if let Value::Object(ref mut fields) = variables {
            fields.insert("status".to_owned(), json!(status));
            fields.insert("responseLatency".to_owned(), json!(latency_ms));
            if let Some(length) = response_length {
                fields.insert("responseLength".to_owned(), json!(length));
            }
            if let Some(latency) = context.integration.latency_ms {
                fields.insert("integrationLatency".to_owned(), json!(latency));
            }
            if let Some(status) = context.integration.status {
                fields.insert("integrationStatus".to_owned(), json!(status));
            }
        }
        variables
    }

    /// The body length when it is known without reading the body: streamed
    /// responses of unknown length have none.
    fn response_length(response: &Response) -> Option<u64> {
        response
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse().ok())
            .or_else(|| response.body().size_hint().exact())
    }

    fn millis(duration: Duration) -> u64 {
        u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
    }
}

impl Inner {
    /// The series a request counts toward: its stage's, and for canary
    /// requests also the canary's own, whose `Stage` is `{stage}/Canary`.
    fn metric_keys(
        &self,
        metrics: &Metrics,
        settings: Option<&RouteSettings>,
        method: &Method,
    ) -> Vec<MetricKey> {
        let stage = self.metric_key(metrics, settings, method);
        match self.api.release {
            Some(Release::Canary) => {
                let canary = MetricKey {
                    stage: format!("{}/Canary", stage.stage),
                    ..stage.clone()
                };
                vec![stage, canary]
            }
            Some(Release::Production) | None => vec![stage],
        }
    }

    fn metric_key(
        &self,
        metrics: &Metrics,
        settings: Option<&RouteSettings>,
        method: &Method,
    ) -> MetricKey {
        let route = settings
            .and_then(|s| s.detailed.as_ref())
            .map(|(fixed, resource)| RouteDimensions {
                method: fixed.clone().unwrap_or_else(|| {
                    if STANDARD_METHODS.contains(&method.as_str()) {
                        method.as_str().to_owned()
                    } else {
                        "OTHER".to_owned()
                    }
                }),
                resource: resource.clone(),
            });
        MetricKey {
            kind: self.api.kind,
            api: metrics.api.clone(),
            stage: self.api.stage_name().to_owned(),
            route,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
mod tests {
    use axum::body::Body;
    use axum::http::StatusCode;
    use tower::ServiceExt as _;

    use super::*;
    use crate::aws::{AwsClients, CredentialsMode, LambdaEndpoints};
    use crate::gateway::{ApiContext, AuthorizationMode, Enforcement, RequestId, Unsupported};
    use crate::gateway_response::GatewayResponses;
    use crate::model::{
        AccessLogSettings, IntegrationOverrides, MethodSettings, SettingsScope, StageSettings,
    };
    use crate::observability::testing::MockAws;
    use crate::observability::{
        Delivery, LogGroup, MetricsNamespace, MetricsSettings, Settings, StreamName, TraceDelivery,
    };
    use crate::router::{BasePath, build};
    use crate::state::{InMemory, InMemoryLimits, StateBackend};
    use crate::vpc_link::VpcLinks;
    use std::num::NonZeroU32;

    const ACCESS_GROUP: &str = "/aws/apigw/access";
    const EXECUTION_GROUP: &str = "API-Gateway-Execution-Logs_abc/prod";

    fn doc() -> Value {
        let mock = |status: u16| {
            json!({"x-amazon-apigateway-integration": {"type": "mock",
                "requestTemplates": {"application/json": format!("{{\"statusCode\": {status}}}")},
                "responses": {"default": {"statusCode": status.to_string(),
                    "responseTemplates": {"application/json": "{}"}}}}})
        };
        json!({
            "info": {"title": "Pets \u{e9}API"},
            "paths": {"/pets": {"get": mock(200)}, "/boom": {"get": mock(500)}}
        })
    }

    fn stage_settings(detailed: bool, logging: Option<&str>) -> StageSettings {
        let mut stage = StageSettings {
            access_log: Some(AccessLogSettings {
                destination_arn: Some(format!("arn:aws:logs:us-east-1:1:log-group:{ACCESS_GROUP}")),
                format: Some(
                    r#"{"id":"$context.requestId","m":"$context.httpMethod","p":"$context.resourcePath","s":"$context.status","l":"$context.integrationLatency","ip":"$context.identity.sourceIp"}"#
                        .to_owned(),
                ),
            }),
            ..StageSettings::default()
        };
        stage.method_settings.insert(
            SettingsScope::All,
            MethodSettings {
                metrics_enabled: Some(detailed),
                logging_level: logging.map(str::to_owned),
                data_trace_enabled: Some(true),
                ..MethodSettings::default()
            },
        );
        stage
    }

    fn settings(access: Delivery, execution: Delivery, metrics: bool) -> Settings {
        Settings {
            access_logs: access,
            execution_logs: execution,
            tracing: TraceDelivery::Aws,
            sampling_percent: 100,
            metrics: metrics.then(|| MetricsSettings {
                group: LogGroup::new("metrics-group"),
                namespace: MetricsNamespace::default(),
            }),
            stream: StreamName::for_pod(
                Some("pod-1"),
                None,
                jiff::Timestamp::UNIX_EPOCH,
                uuid::Uuid::nil(),
            ),
        }
    }

    fn serve(
        aws: &MockAws,
        kind: ApiKind,
        stage: StageSettings,
        settings: Settings,
    ) -> (axum::Router, Arc<Observability>) {
        serve_doc(aws, &doc(), kind, stage, settings)
    }

    fn serve_doc(
        aws: &MockAws,
        doc: &Value,
        kind: ApiKind,
        stage: StageSettings,
        settings: Settings,
    ) -> (axum::Router, Arc<Observability>) {
        let observability = Observability::start(aws.sdk_config(), settings);
        let model = ApiModel::import(doc, kind, stage, &IntegrationOverrides::default()).unwrap();
        let clients = Arc::new(AwsClients::new(
            aws.sdk_config(),
            CredentialsMode::Assume,
            LambdaEndpoints::default(),
            reqwest::Client::new(),
        ));
        let ctx = Arc::new(ApiContext {
            kind,
            api_id: "abc".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: Arc::default(),
            responses: GatewayResponses::default(),
            cors: None,
            state: Arc::new(StateBackend::InMemory(InMemory::new(
                InMemoryLimits::default(),
            ))),
            replicas: NonZeroU32::MIN,
            vpc_links: VpcLinks::default(),
            enforcement: Enforcement {
                authorization: AuthorizationMode::Enforce,
                resource_policy: Unsupported::Reject,
                request_validation: Unsupported::Reject,
            },
            http: reqwest::Client::new(),
            aws: clients,
            observer: StageObserver::new(&observability, &model, "abc", Some("prod"), None),
            release: None,
        });
        let (router, _) = build(&model, &ctx, &BasePath::default());
        (router, observability)
    }

    async fn get(router: &axum::Router, path: &str) -> StatusCode {
        let mut request = Request::builder()
            .uri(path)
            .header("host", "abc.example.com")
            .body(Body::empty())
            .unwrap();
        request
            .extensions_mut()
            .insert(RequestId(uuid::Uuid::nil()));
        router.clone().oneshot(request).await.unwrap().status()
    }

    fn messages(aws: &MockAws, group: &str) -> Vec<String> {
        aws.calls()
            .into_iter()
            .filter(|c| c.target == "Logs_20140328.PutLogEvents" && c.body["logGroupName"] == group)
            .flat_map(|c| c.body["logEvents"].as_array().cloned().unwrap_or_default())
            .map(|e| e["message"].as_str().unwrap().to_owned())
            .collect()
    }

    fn metric_documents(aws: &MockAws) -> Vec<Value> {
        messages(aws, "metrics-group")
            .iter()
            .map(|m| serde_json::from_str(m).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn requests_produce_access_logs_execution_logs_and_metrics() {
        let aws = MockAws::start().await;
        let (router, observability) = serve(
            &aws,
            ApiKind::Rest,
            stage_settings(true, Some("INFO")),
            settings(Delivery::Aws, Delivery::Aws, true),
        );
        assert_eq!(get(&router, "/pets").await, StatusCode::OK);
        assert_eq!(
            get(&router, "/boom").await,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(get(&router, "/missing").await, StatusCode::FORBIDDEN);
        observability.close().await;

        let access = messages(&aws, ACCESS_GROUP);
        assert_eq!(access.len(), 3, "{access:?}");
        let first: Value = serde_json::from_str(&access[0]).unwrap();
        assert_eq!(first["id"], uuid::Uuid::nil().to_string());
        assert_eq!(first["m"], "GET");
        assert_eq!(first["p"], "/pets");
        assert_eq!(first["s"], "200");
        assert_eq!(first["ip"], "-");
        assert_ne!(first["l"], "-", "mock integrations report a latency");
        let unmatched: Value = serde_json::from_str(&access[2]).unwrap();
        assert_eq!(unmatched["s"], "403");
        assert_eq!(unmatched["l"], "-");

        let execution = messages(&aws, EXECUTION_GROUP);
        assert!(
            execution
                .iter()
                .any(|l| l.contains("HTTP Method: GET, Resource Path: /pets")),
            "{execution:?}"
        );
        assert!(
            execution
                .iter()
                .any(|l| l.contains("Method completed with status: 500"))
        );
        assert!(execution.iter().any(|l| l.contains("Execution failed")));
        assert!(
            execution
                .iter()
                .any(|l| l.contains("Method request headers:"))
        );
        let created: Vec<Value> = aws
            .calls()
            .into_iter()
            .filter(|c| c.target == "Logs_20140328.CreateLogGroup")
            .map(|c| c.body["logGroupName"].clone())
            .collect();
        assert_eq!(
            created,
            [json!(EXECUTION_GROUP)],
            "only the execution log group is ever created"
        );

        let metrics = metric_documents(&aws);
        let total: u64 = metrics.iter().map(|m| m["Count"].as_u64().unwrap()).sum();
        assert_eq!(total, 3);
        let pets = metrics.iter().find(|m| m["Resource"] == "/pets").unwrap();
        assert_eq!(pets["ApiName"], "Pets API");
        assert_eq!(pets["Method"], "GET");
        let boom = metrics.iter().find(|m| m["Resource"] == "/boom").unwrap();
        assert_eq!(boom["5XXError"], 1);
        let stage_only = metrics
            .iter()
            .find(|m| m.get("Resource").is_none())
            .unwrap();
        assert_eq!(
            stage_only["4XXError"], 1,
            "the unmatched request counts as a 4XX"
        );
        assert_eq!(stage_only["Stage"], "prod");
    }

    #[tokio::test]
    async fn stage_metrics_have_no_route_dimensions_unless_detailed() {
        let aws = MockAws::start().await;
        let (router, observability) = serve(
            &aws,
            ApiKind::Rest,
            stage_settings(false, None),
            settings(Delivery::Off, Delivery::Off, true),
        );
        get(&router, "/pets").await;
        get(&router, "/boom").await;
        observability.close().await;
        let metrics = metric_documents(&aws);
        assert_eq!(metrics.len(), 1);
        assert_eq!(metrics[0]["Count"], 2);
        assert!(metrics[0].get("Resource").is_none());
        assert!(messages(&aws, ACCESS_GROUP).is_empty());
    }

    #[tokio::test]
    async fn http_apis_use_http_metric_names_and_skip_execution_logs() {
        let aws = MockAws::start().await;
        let (router, observability) = serve(
            &aws,
            ApiKind::Http,
            stage_settings(true, Some("INFO")),
            settings(Delivery::Off, Delivery::Aws, true),
        );
        get(&router, "/boom").await;
        observability.close().await;
        let metrics = metric_documents(&aws);
        assert!(
            metrics
                .iter()
                .all(|m| m["ApiId"] == "abc" && m.get("ApiName").is_none())
        );
        assert!(metrics.iter().any(|m| m["5xx"] == 1));
        assert!(
            aws.calls()
                .iter()
                .all(|c| c.body["logGroupName"] != EXECUTION_GROUP)
        );
    }

    #[tokio::test]
    async fn stages_without_settings_leave_the_observer_disabled() {
        let aws = MockAws::start().await;
        let (router, observability) = serve(
            &aws,
            ApiKind::Rest,
            StageSettings::default(),
            settings(Delivery::Aws, Delivery::Aws, false),
        );
        get(&router, "/pets").await;
        observability.close().await;
        assert!(aws.calls().is_empty());
    }

    #[test]
    fn rest_api_names_lose_non_ascii_characters_and_fall_back_to_the_id() {
        let model = |title: &str| {
            let mut doc = doc();
            doc["info"]["title"] = json!(title);
            ApiModel::import(
                &doc,
                ApiKind::Rest,
                StageSettings::default(),
                &IntegrationOverrides::default(),
            )
            .unwrap()
        };
        let name = |title: &str, id: &str| StageObserver::api_dimension(&model(title), id);
        assert_eq!(name("Pets \u{e9}API", "abc"), "Pets API");
        assert_eq!(name("\u{1f600}", "abc"), "abc");
        assert_eq!(name("x", "abc"), "x");
    }

    #[test]
    fn methods_of_any_routes_are_bounded_in_the_metric_dimensions() {
        let inner = Inner {
            api: ApiInfo {
                kind: ApiKind::Rest,
                api_id: "abc".to_owned(),
                stage: Some("prod".to_owned()),
                release: None,
            },
            access_log: None,
            execution_queues: Vec::new(),
            metrics: None,
            tracing: None,
            routes: BTreeMap::new(),
        };
        let metrics = Metrics {
            aggregator: Arc::new(MetricsAggregator::new(MetricsNamespace::default())),
            api: "api".to_owned(),
        };
        let settings = RouteSettings {
            execution_logging: None,
            detailed: Some((None, "/x".to_owned())),
        };
        let method_of = |method: &str| {
            inner
                .metric_key(
                    &metrics,
                    Some(&settings),
                    &Method::from_bytes(method.as_bytes()).unwrap(),
                )
                .route
                .unwrap()
                .method
        };
        assert_eq!(method_of("PATCH"), "PATCH");
        assert_eq!(method_of("PROPFIND"), "OTHER");
    }

    async fn upstream() -> std::net::SocketAddr {
        let app = axum::Router::new().fallback(|headers: axum::http::HeaderMap| async move {
            let seen: serde_json::Map<String, Value> = ["x-amzn-trace-id", "traceparent"]
                .into_iter()
                .filter_map(|name| {
                    let value = headers.get(name)?.to_str().ok()?;
                    Some((name.to_owned(), json!(value)))
                })
                .collect();
            axum::Json(Value::Object(seen))
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    fn proxy_doc(addr: std::net::SocketAddr) -> Value {
        json!({
            "info": {"title": "Traced"},
            "paths": {"/echo": {"get": {"x-amazon-apigateway-integration": {
                "type": "http_proxy", "httpMethod": "GET", "uri": format!("http://{addr}/")}}}}
        })
    }

    async fn traced_get(router: &axum::Router, headers: &[(&str, &str)]) -> (StatusCode, Value) {
        let mut request = Request::builder()
            .uri("/echo")
            .header("host", "abc.example.com");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let mut request = request.body(Body::empty()).unwrap();
        request
            .extensions_mut()
            .insert(RequestId(uuid::Uuid::nil()));
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or(Value::Null))
    }

    fn segments(aws: &MockAws) -> Vec<Value> {
        aws.calls()
            .into_iter()
            .filter(|c| c.target == "/TraceSegments")
            .flat_map(|c| {
                c.body["TraceSegmentDocuments"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .map(|d| serde_json::from_str(d.as_str().unwrap()).unwrap())
            .collect()
    }

    fn tracing_stage() -> StageSettings {
        StageSettings {
            tracing_enabled: true,
            ..StageSettings::default()
        }
    }

    const ROOT: &str = "1-5759e988-bd862e3fe1be46a994272793";
    const PARENT: &str = "53995c3f42cd8ad8";

    #[tokio::test]
    async fn traced_requests_reach_backends_with_trace_headers_and_send_a_segment() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let (router, observability) = serve_doc(
            &aws,
            &proxy_doc(addr),
            ApiKind::Rest,
            tracing_stage(),
            settings(Delivery::Off, Delivery::Off, false),
        );
        let (status, seen) = traced_get(&router, &[("user-agent", "curl/8")]).await;
        assert_eq!(status, StatusCode::OK);
        observability.close().await;

        let segments = segments(&aws);
        assert_eq!(segments.len(), 1);
        let segment = &segments[0];
        assert_eq!(segment["name"], "Traced/prod");
        assert_eq!(segment["origin"], "AWS::ApiGateway::Stage");
        assert_eq!(segment["http"]["response"]["status"], 200);
        assert_eq!(segment["http"]["request"]["user_agent"], "curl/8");
        assert!(segment.get("parent_id").is_none());
        let trace_id = segment["trace_id"].as_str().unwrap();
        let segment_id = segment["id"].as_str().unwrap();
        assert_eq!(
            seen["x-amzn-trace-id"],
            format!("Root={trace_id};Parent={segment_id};Sampled=1")
        );
        let traceparent = seen["traceparent"].as_str().unwrap();
        assert_eq!(
            traceparent,
            format!(
                "00-{}-{segment_id}-01",
                trace_id.strip_prefix("1-").unwrap().replace('-', "")
            )
        );
    }

    #[tokio::test]
    async fn an_incoming_trace_is_continued_beneath_its_parent() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let (router, observability) = serve_doc(
            &aws,
            &proxy_doc(addr),
            ApiKind::Rest,
            tracing_stage(),
            settings(Delivery::Off, Delivery::Off, false),
        );
        let incoming = format!("Root={ROOT};Parent={PARENT};Sampled=1");
        let (_, seen) = traced_get(&router, &[("x-amzn-trace-id", &incoming)]).await;
        observability.close().await;
        let segments = segments(&aws);
        assert_eq!(segments[0]["trace_id"], ROOT);
        assert_eq!(segments[0]["parent_id"], PARENT);
        let forwarded = seen["x-amzn-trace-id"].as_str().unwrap();
        assert!(forwarded.starts_with(&format!("Root={ROOT};Parent=")));
        assert!(
            !forwarded.contains(PARENT),
            "the gateway's segment replaces the caller's as the parent"
        );
    }

    #[tokio::test]
    async fn w3c_clients_are_traced_too() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let (router, observability) = serve_doc(
            &aws,
            &proxy_doc(addr),
            ApiKind::Rest,
            tracing_stage(),
            settings(Delivery::Off, Delivery::Off, false),
        );
        let (_, seen) = traced_get(
            &router,
            &[(
                "traceparent",
                "00-4efaaf4d1e8720b39541901950019ee5-00f067aa0ba902b7-01",
            )],
        )
        .await;
        observability.close().await;
        let segments = segments(&aws);
        assert_eq!(
            segments[0]["trace_id"],
            "1-4efaaf4d-1e8720b39541901950019ee5"
        );
        assert_eq!(segments[0]["parent_id"], "00f067aa0ba902b7");
        assert!(
            seen["traceparent"]
                .as_str()
                .unwrap()
                .starts_with("00-4efaaf4d1e8720b39541901950019ee5-")
        );
        assert!(
            seen["x-amzn-trace-id"]
                .as_str()
                .unwrap()
                .starts_with("Root=1-4efaaf4d-1e8720b39541901950019ee5;Parent=")
        );
    }

    #[tokio::test]
    async fn unsampled_requests_send_no_segment_but_keep_the_decision_downstream() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let (router, observability) = serve_doc(
            &aws,
            &proxy_doc(addr),
            ApiKind::Rest,
            tracing_stage(),
            settings(Delivery::Off, Delivery::Off, false),
        );
        let incoming = format!("Root={ROOT};Sampled=0");
        let (_, seen) = traced_get(&router, &[("x-amzn-trace-id", &incoming)]).await;
        observability.close().await;
        assert!(segments(&aws).is_empty());
        assert!(
            seen["x-amzn-trace-id"]
                .as_str()
                .unwrap()
                .ends_with("Sampled=0")
        );
        assert!(seen["traceparent"].as_str().unwrap().ends_with("-00"));
    }

    #[tokio::test]
    async fn stages_without_tracing_leave_trace_headers_alone() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let (router, observability) = serve_doc(
            &aws,
            &proxy_doc(addr),
            ApiKind::Rest,
            StageSettings::default(),
            settings(Delivery::Off, Delivery::Off, false),
        );
        let (_, none) = traced_get(&router, &[]).await;
        assert!(none.get("x-amzn-trace-id").is_none());
        assert!(none.get("traceparent").is_none());
        let incoming = format!("Root={ROOT};Parent={PARENT};Sampled=1");
        let (_, passed) = traced_get(&router, &[("x-amzn-trace-id", &incoming)]).await;
        assert_eq!(passed["x-amzn-trace-id"], incoming);
        observability.close().await;
        assert!(segments(&aws).is_empty());
    }

    #[tokio::test]
    async fn the_tracing_flag_turns_everything_off() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let mut off = settings(Delivery::Off, Delivery::Off, false);
        off.tracing = TraceDelivery::Off;
        let (router, observability) =
            serve_doc(&aws, &proxy_doc(addr), ApiKind::Rest, tracing_stage(), off);
        let (_, seen) = traced_get(&router, &[]).await;
        observability.close().await;
        assert!(seen.get("x-amzn-trace-id").is_none());
        assert!(segments(&aws).is_empty());
    }

    #[tokio::test]
    async fn access_logs_can_log_the_trace_id() {
        let aws = MockAws::start().await;
        let addr = upstream().await;
        let mut stage = tracing_stage();
        stage.access_log = Some(AccessLogSettings {
            destination_arn: Some(format!("arn:aws:logs:us-east-1:1:log-group:{ACCESS_GROUP}")),
            format: Some("$context.xrayTraceId".to_owned()),
        });
        let (router, observability) = serve_doc(
            &aws,
            &proxy_doc(addr),
            ApiKind::Rest,
            stage,
            settings(Delivery::Aws, Delivery::Off, false),
        );
        let incoming = format!("Root={ROOT};Sampled=0");
        traced_get(&router, &[("x-amzn-trace-id", &incoming)]).await;
        observability.close().await;
        assert_eq!(messages(&aws, ACCESS_GROUP), [ROOT]);
    }
}
