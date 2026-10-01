//! What the gateway records about each request of one loaded API stage:
//! access log lines, metrics, and execution logs.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::HttpBody as _;
use axum::extract::Request;
use axum::http::{Method, header};
use axum::response::Response;
use serde_json::{Value, json};

use super::Observability;
use super::exec::Outcome;
use super::format::AccessLogFormat;
use super::metrics::{MetricKey, MetricsAggregator, RequestMetrics, RouteDimensions};
use super::queue::{LogEvent, LogQueue};
use crate::gateway::ApiContext;
use crate::model::{ApiKind, ApiModel, ExecutionLogging, RouteKey};
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
    queue: LogQueue,
}

#[derive(Debug)]
struct Metrics {
    aggregator: Arc<MetricsAggregator>,
    api: String,
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
    execution_queue: Option<LogQueue>,
    metrics: Option<Metrics>,
    routes: BTreeMap<RouteKey, RouteSettings>,
}

/// The observation settings of one loaded stage. Cheap to clone; a disabled
/// observer does no work per request.
#[derive(Debug, Clone, Default)]
pub(crate) struct StageObserver(Option<Arc<Inner>>);

/// A request that has been started and not finished.
pub(crate) struct Pending {
    started: Instant,
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
    ) -> Self {
        let api = ApiInfo {
            kind: model.kind,
            api_id: api_id.to_owned(),
            stage: stage.map(str::to_owned),
        };
        let access_log = model.stage.access_log.as_ref().and_then(|settings| {
            let format = settings.format.as_deref().filter(|f| !f.is_empty())?;
            let queue = observability.access_log_queue(settings.destination_arn.as_deref())?;
            Some(AccessLog {
                format: AccessLogFormat::from(format),
                queue,
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
                    crate::model::MethodMatch::Any => None,
                    crate::model::MethodMatch::Exact(ref method) => Some(method.to_string()),
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
        let execution_queue = routes
            .values()
            .any(|r| r.execution_logging.is_some())
            .then(|| observability.execution_queue(api_id, api.stage_name()))
            .flatten();
        let metrics = observability.metrics().map(|aggregator| Metrics {
            aggregator,
            api: Self::api_dimension(model, api_id),
        });

        if access_log.is_none() && execution_queue.is_none() && metrics.is_none() {
            return Self::disabled();
        }
        Self(Some(Arc::new(Inner {
            api,
            access_log,
            execution_queue,
            metrics,
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
        request: &Request,
        route: Option<&Route>,
    ) -> Option<Pending> {
        let inner = self.0.as_ref()?;
        let route_key = route.map(|r| r.key.clone());
        let settings = route_key.as_ref().and_then(|key| inner.routes.get(key));
        let wants_context =
            inner.access_log.is_some() || settings.is_some_and(|s| s.execution_logging.is_some());
        Some(Pending {
            started: Instant::now(),
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
            metrics.aggregator.record(
                &inner.metric_key(metrics, settings, &pending.method),
                RequestMetrics {
                    status,
                    latency_ms,
                    integration_latency_ms: integration_ms,
                },
            );
        }
        let Some(mut context) = pending.context else {
            return response;
        };
        context.integration = IntegrationOutcome {
            status: integration_ms.map(|_| status),
            latency_ms: integration_ms,
            error: None,
        };
        if let (Some(settings), Some(queue)) = (
            settings.and_then(|s| s.execution_logging),
            inner.execution_queue.as_ref(),
        ) {
            let outcome = Outcome {
                status,
                integration: integration_ms.map(|ms| (status, ms)),
            };
            for line in settings.lines(&context, outcome) {
                queue.push(LogEvent::now(line));
            }
        }
        if let Some(ref access_log) = inner.access_log {
            let variables = Self::access_log_variables(
                &context,
                status,
                Self::response_length(&response),
                latency_ms,
            );
            access_log
                .queue
                .push(LogEvent::now(access_log.format.render(&variables)));
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
    use crate::model::{IntegrationOverrides, MethodSettings, SettingsScope, StageSettings};
    use crate::observability::testing::MockAws;
    use crate::observability::{Delivery, LogGroup, MetricsNamespace, MetricsSettings, Settings};
    use crate::router::{BasePath, build};

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
            access_log: Some(crate::model::AccessLogSettings {
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
            metrics: metrics.then(|| MetricsSettings {
                group: LogGroup::new("metrics-group"),
                namespace: MetricsNamespace::default(),
            }),
            stream: crate::observability::StreamName::for_pod(
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
        let observability = Observability::start(aws.sdk_config(), settings);
        let model =
            ApiModel::import(&doc(), kind, stage, &IntegrationOverrides::default()).unwrap();
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
            enforcement: Enforcement {
                authorization: AuthorizationMode::Enforce,
                resource_policy: Unsupported::Reject,
                request_validation: Unsupported::Reject,
            },
            http: reqwest::Client::new(),
            aws: clients,
            keys: Arc::new(crate::authz::KeyStore::new(reqwest::Client::new(), [])),
            observer: StageObserver::new(&observability, &model, "abc", Some("prod")),
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
            },
            access_log: None,
            execution_queue: None,
            metrics: None,
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
}
