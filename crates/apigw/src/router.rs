//! Builds an axum [`Router`] from an [`ApiDefinition`] and swaps it in place
//! when the definition changes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde::Serialize;
use tokio::sync::watch;
use tower::ServiceExt as _;
use uuid::Uuid;

use crate::authz::Authorizers;
use crate::aws::{AwsClients, RoleArn, RoleStatus};
use crate::canary::{CanaryRelease, CanarySummary};
use crate::domain::{DomainName, DomainRegistry, DomainSummary, Resolution};
use crate::gateway::{ApiContext, Enforcement, GatewayError, RequestId};
use crate::http_routes::{HttpRoutes, PathPattern};
use crate::integration::Integration;
use crate::model::{ApiKind, ApiModel, Feature, MethodMatch, Protections, RouteKey, RoutePath};
use crate::pipeline::Pipeline;
use crate::route::Route;
use crate::throttle::ThrottleSettings;

/// A stage prefix such as `/prod` that every route is served under, as on an
/// `execute-api` endpoint. Empty serves routes at the root, as on a custom domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BasePath(Option<String>);

#[derive(Debug, thiserror::Error)]
#[error(
    "base path {0:?} must start with '/', must not end with '/', and must not contain '{{' or '}}'"
)]
pub(crate) struct InvalidBasePath(String);

impl BasePath {
    /// Serves `router` under this prefix; requests outside it are answered as
    /// unrouted.
    fn mount(&self, router: Router, ctx: &Arc<ApiContext>) -> Router {
        let Some(ref prefix) = self.0 else {
            return router;
        };
        let ctx = Arc::clone(ctx);
        Router::new()
            .without_v07_checks()
            .nest(prefix, router)
            .fallback(move |mut request: Request| {
                let ctx = Arc::clone(&ctx);
                async move {
                    let pending = ctx.observer.begin(&ctx, &mut request, None);
                    let response = ctx.reject(request, GatewayError::NoRoute);
                    ctx.observer.finish(pending, response)
                }
            })
    }
}

impl std::str::FromStr for BasePath {
    type Err = InvalidBasePath;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() || s == "/" {
            return Ok(Self(None));
        }
        if !s.starts_with('/') || s.ends_with('/') || s.contains(['{', '}', '*']) {
            return Err(InvalidBasePath(s.to_owned()));
        }
        Ok(Self(Some(s.to_owned())))
    }
}

/// One loaded API definition, as served and as reported on the admin listener.
pub(crate) struct Loaded {
    pub(crate) router: Router,
    /// The canary release of the stage, when it has one that receives traffic.
    pub(crate) canary: Option<CanaryRelease>,
    pub(crate) kind: ApiKind,
    pub(crate) summary: LoadSummary,
}

impl Loaded {
    /// The router for one request: the canary's for the share of requests the
    /// stage's canary settings send there, the stage's otherwise.
    fn router_for_request(&self) -> &Router {
        match self.canary {
            Some(ref canary) if canary.share.picks_canary() => &canary.router,
            Some(_) | None => &self.router,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LoadSummary {
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
    pub(crate) deployment_id: Option<String>,
    pub(crate) loaded_at: String,
    /// API- and stage-level features imported but not enforced yet.
    pub(crate) unenforced: Vec<Feature>,
    pub(crate) routes: Vec<RouteSummary>,
    /// The canary release, when the stage has one that receives traffic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) canary: Option<CanarySummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RouteSummary {
    pub(crate) route_key: RouteKey,
    pub(crate) integration: &'static str,
    pub(crate) target: Option<String>,
    /// The role the integration runs as, when it has one.
    pub(crate) credentials: Option<RoleArn>,
    pub(crate) protections: Protections,
    /// Why the route is not being served as API Gateway would serve it.
    pub(crate) problems: Vec<String>,
    /// Settings on this route that are imported but not enforced yet.
    pub(crate) unenforced: Vec<Feature>,
}

impl RouteSummary {
    fn new(route: &Route, enforcement: Enforcement) -> Self {
        let mut problems: Vec<String> = enforcement
            .refusals(route)
            .map(|protection| protection.refusal_reason(route))
            .collect();
        let target = match route.integration {
            Integration::HttpProxy(ref proxy) => Some(proxy.uri.clone()),
            Integration::Lambda(ref lambda) => Some(lambda.function.to_string()),
            Integration::Mock(_) => None,
            Integration::Unsupported { ref reason } => {
                problems.push(reason.clone());
                None
            }
        };
        let credentials = match route.integration {
            Integration::Lambda(ref lambda) => lambda.credentials.clone(),
            Integration::HttpProxy(_) | Integration::Mock(_) | Integration::Unsupported { .. } => {
                None
            }
        };
        Self {
            route_key: route.key.clone(),
            credentials,
            integration: route.integration.kind(),
            target,
            protections: route.protections.clone(),
            problems,
            unenforced: route.unenforced.clone(),
        }
    }
}

/// Groups routes by path: one axum route per path, with method selection done
/// here so `ANY` and explicit methods can coexist the way API Gateway allows.
struct PathRoutes {
    ctx: Arc<ApiContext>,
    methods: BTreeMap<MethodMatch, Route>,
    default: Option<Arc<Route>>,
}

impl PathRoutes {
    fn select(&self, method: &Method) -> Option<&Route> {
        self.methods
            .get(&MethodMatch::Exact(method.clone()))
            .or_else(|| self.methods.get(&MethodMatch::Any))
            .or(self.default.as_deref())
    }

    async fn handle(&self, mut request: Request) -> Response {
        self.ctx.kind.override_method(&mut request);
        let route = self.select(request.method());
        let pending = self.ctx.observer.begin(&self.ctx, &mut request, route);
        let response = match (self.ctx.kind.request_limits().check(&request), route) {
            (Err(exceeded), _) => self.ctx.reject(request, exceeded.into()),
            // The pipeline future holds whole SDK calls; box it once here.
            (Ok(()), Some(route)) => Box::pin(Pipeline::new(&self.ctx, route).run(request)).await,
            (Ok(()), None) => self.ctx.reject(request, GatewayError::NoRoute),
        };
        self.ctx.observer.finish(pending, response)
    }
}

/// Serves an HTTP API: route selection is by path and method together, so
/// the router has no per-path entries ([`HttpRoutes`]).
struct HttpHandler {
    ctx: Arc<ApiContext>,
    routes: HttpRoutes,
}

impl HttpHandler {
    async fn handle(&self, mut request: Request) -> Response {
        let selection = self.routes.select(request.uri().path(), request.method());
        let pending =
            self.ctx
                .observer
                .begin(&self.ctx, &mut request, selection.as_ref().map(|s| s.route));
        let response = match (self.ctx.kind.request_limits().check(&request), selection) {
            (Err(exceeded), _) => self.ctx.reject(request, exceeded.into()),
            (Ok(()), Some(selection)) => {
                let pipeline =
                    Pipeline::new(&self.ctx, selection.route).with_path_params(selection.params);
                Box::pin(pipeline.run(request)).await
            }
            (Ok(()), None) => self.ctx.reject(request, GatewayError::NoRoute),
        };
        self.ctx.observer.finish(pending, response)
    }
}

/// API Gateway's `{name}` and greedy `{name+}` become axum's `{name}` and `{*name}`.
fn axum_path(path: &str) -> Result<String, String> {
    if !path.starts_with('/') {
        return Err("path must start with '/'".to_owned());
    }
    let segments: Vec<&str> = path.split('/').skip(1).collect();
    let last = segments.len().saturating_sub(1);
    let mut out = String::with_capacity(path.len().saturating_add(1));
    for (index, segment) in segments.iter().enumerate() {
        out.push('/');
        if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix("+}")) {
            if index != last {
                return Err("greedy parameter must be the last segment".to_owned());
            }
            out.push_str("{*");
            out.push_str(name);
            out.push('}');
        } else {
            out.push_str(segment);
        }
    }
    Ok(out)
}

pub(crate) fn build(
    model: &ApiModel,
    ctx: &Arc<ApiContext>,
    base: &BasePath,
) -> (Router, Vec<RouteSummary>) {
    let authorizers = Authorizers::compile(model, &ctx.stage_variables);
    let throttling = ThrottleSettings::new(
        &ctx.api_id,
        ctx.stage.as_deref(),
        model.stage.clone(),
        ctx.replicas,
    );
    let routes: Vec<Route> = model
        .operations
        .iter()
        .map(|operation| {
            Route::compile(
                operation,
                model.kind,
                &ctx.stage_variables,
                &authorizers,
                &throttling,
                &ctx.vpc_links,
            )
        })
        .collect();
    let mut summaries = Vec::with_capacity(routes.len());
    let mut default = None;
    let mut by_path: BTreeMap<String, BTreeMap<MethodMatch, Route>> = BTreeMap::new();
    for route in &routes {
        let mut summary = RouteSummary::new(route, ctx.enforcement);
        match route.path {
            RoutePath::Default => default = Some(Arc::new(route.clone())),
            RoutePath::Resource(ref path) => match axum_path(path) {
                Ok(path) => {
                    by_path
                        .entry(path)
                        .or_default()
                        .insert(route.method.clone(), route.clone());
                }
                Err(reason) => summary.problems.push(format!("not served: {reason}")),
            },
        }
        summaries.push(summary);
    }

    // axum panics on conflicting routes; check each path with the matchit
    // version axum uses so a conflict skips that path instead of aborting.
    // API Gateway paths may have segments starting with `:` or `*`, which axum's
    // checks for 0.7-style syntax would reject with a panic.
    let mut matcher = matchit::Router::new();
    let mut router = Router::new().without_v07_checks();
    let mut http_routes = HttpRoutes::default();
    for (path, methods) in by_path {
        if let Err(err) = matcher.insert(path.as_str(), ()) {
            tracing::error!(path, %err, "route conflicts with another route; skipping it");
            for summary in &mut summaries {
                if methods.values().any(|r| r.key == summary.route_key) {
                    summary.problems.push(format!("not served: {err}"));
                }
            }
            continue;
        }
        if model.kind == ApiKind::Http {
            if let Some(pattern) = PathPattern::parse(&path) {
                http_routes.insert(pattern, methods);
            } else {
                tracing::error!(path, "route path is not a valid pattern; skipping it");
            }
            continue;
        }
        let entry = Arc::new(PathRoutes {
            ctx: Arc::clone(ctx),
            methods,
            default: default.clone(),
        });
        router = router.route(
            &path,
            any(move |request: Request| {
                let entry = Arc::clone(&entry);
                async move { entry.handle(request).await }
            }),
        );
    }

    let router = if model.kind == ApiKind::Http {
        if let Some(default) = default {
            http_routes.set_default(default);
        }
        let handler = Arc::new(HttpHandler {
            ctx: Arc::clone(ctx),
            routes: http_routes,
        });
        router.fallback(move |request: Request| {
            let handler = Arc::clone(&handler);
            async move { handler.handle(request).await }
        })
    } else {
        let fallback = Arc::new(PathRoutes {
            ctx: Arc::clone(ctx),
            methods: BTreeMap::new(),
            default,
        });
        router.fallback(move |request: Request| {
            let fallback = Arc::clone(&fallback);
            async move { fallback.handle(request).await }
        })
    };
    (base.mount(router, ctx), summaries)
}

/// Serves every request through whichever [`Loaded`] router is current, so a
/// refreshed definition takes effect without restarting the listener. Requests
/// already in flight finish on the router they started with.
pub(crate) fn dispatcher(current: watch::Receiver<Arc<Loaded>>) -> Router {
    Router::new().fallback(move |request: Request| {
        let loaded = Arc::clone(&current.borrow());
        async move { loaded.serve(request).await }
    })
}

impl Loaded {
    /// Runs `request` through this definition: assigns the request ID, picks the
    /// release, and logs the outcome.
    async fn serve(&self, mut request: Request) -> Response {
        let started = Instant::now();
        let request_id = Uuid::now_v7();
        request.extensions_mut().insert(RequestId(request_id));
        let method = request.method().clone();
        let path = request.uri().path().to_owned();
        let mut response = self
            .router_for_request()
            .clone()
            .oneshot(request)
            .await
            .into_response();
        if let Ok(value) = HeaderValue::try_from(request_id.to_string()) {
            response
                .headers_mut()
                .insert(self.kind.request_id_header(), value);
        }
        tracing::info!(
            request_id = %request_id,
            %method,
            path,
            status = response.status().as_u16(),
            latency_ms = started.elapsed().as_millis(),
            "request"
        );
        response
    }
}

/// What the domain dispatcher does to requests and how it refuses them.
struct CustomDomain;

impl CustomDomain {
    /// API Gateway's `{"message": ...}` error body.
    fn error(status: StatusCode, message: &'static str) -> Response {
        (
            status,
            axum::Json(serde_json::json!({ "message": message })),
        )
            .into_response()
    }

    /// Replaces the path of `request`, keeping its query string.
    fn rewrite_path(request: &mut Request, path: &str) -> Result<(), axum::http::uri::InvalidUri> {
        let target = match request.uri().query() {
            Some(query) => format!("{path}?{query}"),
            None => path.to_owned(),
        };
        let mut parts = request.uri().clone().into_parts();
        parts.path_and_query = Some(target.parse()?);
        if let Ok(uri) = axum::http::Uri::from_parts(parts) {
            *request.uri_mut() = uri;
        }
        Ok(())
    }
}

/// Paths API Gateway reserves on every custom domain for its own health checks.
const RESERVED_HEALTH_PATHS: [&str; 2] = ["/ping", "/sping"];

/// Serves requests to custom domains: the `Host` header picks the domain, the
/// domain's API mappings or routing rules pick the API stage, and the matched
/// prefix is removed from the path before the stage's router sees the request.
pub(crate) fn domain_dispatcher(domains: DomainRegistry) -> Router {
    Router::new().fallback(move |mut request: Request| {
        let domains = domains.clone();
        async move {
            let path = request.uri().path().to_owned();
            if RESERVED_HEALTH_PATHS.contains(&path.as_str()) {
                return (StatusCode::OK, "healthy").into_response();
            }
            let host = request
                .headers()
                .get(axum::http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .or_else(|| {
                    request
                        .uri()
                        .authority()
                        .map(axum::http::uri::Authority::as_str)
                })
                .map(DomainName::host_of)
                .unwrap_or_default();
            let Some(state) = domains.find(&host) else {
                return CustomDomain::error(StatusCode::FORBIDDEN, "Forbidden");
            };
            match state.resolve(&path, request.headers()) {
                Resolution::Matched(loaded, routed_path) => {
                    if CustomDomain::rewrite_path(&mut request, &routed_path).is_err() {
                        return CustomDomain::error(StatusCode::BAD_REQUEST, "Bad Request");
                    }
                    loaded.serve(request).await
                }
                Resolution::Unavailable(stage) => {
                    tracing::warn!(%stage, host, "request for an API stage that has not loaded");
                    CustomDomain::error(StatusCode::SERVICE_UNAVAILABLE, "Service Unavailable")
                }
                Resolution::NoMatch => CustomDomain::error(StatusCode::FORBIDDEN, "Forbidden"),
            }
        }
    })
}

/// Health and introspection routes for the admin listener.
/// The `/routes` document: the loaded API plus the current state of every
/// integration role the gateway has tried to assume.
#[derive(Serialize)]
struct RoutesReport {
    #[serde(flatten)]
    summary: LoadSummary,
    credentials: BTreeMap<RoleArn, RoleStatus>,
}

/// The `/routes` document of a process serving custom domains.
#[derive(Serialize)]
struct DomainsReport {
    domains: Vec<DomainSummary>,
    credentials: BTreeMap<RoleArn, RoleStatus>,
}

/// Health and introspection routes for the admin listener of a process serving
/// custom domains.
pub(crate) fn admin_domains(domains: DomainRegistry, aws: Arc<AwsClients>) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route(
            "/routes",
            axum::routing::get(move || {
                let report = DomainsReport {
                    domains: domains.summaries(),
                    credentials: aws.role_status(),
                };
                async move { axum::Json(report) }
            }),
        )
}

/// Health and introspection routes for the admin listener.
pub(crate) fn admin(current: watch::Receiver<Arc<Loaded>>, aws: Arc<AwsClients>) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route(
            "/routes",
            axum::routing::get(move || {
                let report = RoutesReport {
                    summary: current.borrow().summary.clone(),
                    credentials: aws.role_status(),
                };
                async move { axum::Json(report) }
            }),
        )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::body::Body;
    use axum::http::StatusCode;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::*;
    use crate::authz::KeyStore;
    use crate::aws::{CredentialsMode, LambdaEndpoints};
    use crate::cors::Cors;
    use crate::gateway::{AuthorizationMode, Unsupported};
    use crate::gateway_response::GatewayResponses;
    use crate::model::{IntegrationOverrides, Protection, StageSettings};
    use crate::model::{MethodSettings, SettingsScope};
    use crate::observability::StageObserver;
    use crate::state::{InMemory, InMemoryLimits, StateBackend};
    use crate::vpc_link::VpcLinks;
    use std::num::NonZeroU32;

    const STRICT: Enforcement = Enforcement {
        authorization: AuthorizationMode::Enforce,
        resource_policy: Unsupported::Reject,
        request_validation: Unsupported::Reject,
    };

    fn test_state() -> Arc<StateBackend> {
        Arc::new(StateBackend::InMemory(InMemory::new(
            InMemoryLimits::default(),
        )))
    }

    fn aws() -> Arc<AwsClients> {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        Arc::new(AwsClients::new(
            config,
            CredentialsMode::Assume,
            LambdaEndpoints::default(),
            reqwest::Client::new(),
        ))
    }

    fn ctx(
        kind: ApiKind,
        enforcement: Enforcement,
        responses: GatewayResponses,
        cors: Option<Cors>,
    ) -> Arc<ApiContext> {
        Arc::new(ApiContext {
            kind,
            api_id: "abc".to_owned(),
            stage: None,
            stage_variables: Arc::default(),
            responses,
            cors,
            state: test_state(),
            replicas: NonZeroU32::MIN,
            vpc_links: VpcLinks::default(),
            enforcement,
            http: reqwest::Client::new(),
            aws: aws(),
            keys: Arc::new(KeyStore::new(reqwest::Client::new(), [])),
            observer: StageObserver::disabled(),
            release: None,
        })
    }

    fn mock(status: u16) -> Value {
        json!({"type": "mock",
            "requestTemplates": {"application/json": format!("{{\"statusCode\": {status}}}")},
            "responses": {"default": {"statusCode": status.to_string(),
                "responseTemplates": {"application/json": format!("{{\"status\":{status}}}")}}}})
    }

    fn router(
        doc: &Value,
        kind: ApiKind,
        mode: AuthorizationMode,
        base: &str,
    ) -> (Router, Vec<RouteSummary>) {
        router_with(
            doc,
            kind,
            Enforcement {
                authorization: mode,
                ..STRICT
            },
            base,
        )
    }

    fn router_with(
        doc: &Value,
        kind: ApiKind,
        enforcement: Enforcement,
        base: &str,
    ) -> (Router, Vec<RouteSummary>) {
        router_for_stage(doc, kind, enforcement, StageSettings::default(), base)
    }

    fn router_for_stage(
        doc: &Value,
        kind: ApiKind,
        enforcement: Enforcement,
        stage: StageSettings,
        base: &str,
    ) -> (Router, Vec<RouteSummary>) {
        let model = ApiModel::import(doc, kind, stage, &IntegrationOverrides::default()).unwrap();
        let responses = GatewayResponses::compile(kind, &model.gateway_responses);
        let cors = model.settings.cors.as_ref().map(Cors::compile);
        build(
            &model,
            &ctx(kind, enforcement, responses, cors),
            &base.parse().unwrap(),
        )
    }

    fn protected_doc() -> Value {
        let op = |extra: Value| {
            let mut op = json!({"x-amazon-apigateway-integration": mock(200)});
            if let (Some(op), Some(extra)) = (op.as_object_mut(), extra.as_object()) {
                op.extend(extra.clone());
            }
            op
        };
        json!({
            "components": {"securitySchemes": {
                "sigv4": {"type": "apiKey", "name": "Authorization", "in": "header", "x-amazon-apigateway-authtype": "awsSigv4"},
                "api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"}
            }},
            "x-amazon-apigateway-request-validators": {"all": {"validateRequestBody": true, "validateRequestParameters": true}},
            "paths": {
                "/open": {"get": op(json!({}))},
                "/iam": {"get": op(json!({"security": [{"sigv4": []}]}))},
                "/key": {"get": op(json!({"security": [{"api_key": []}]}))},
                "/validated": {"get": op(json!({"x-amazon-apigateway-request-validator": "all"}))},
                "/key-and-validated": {"get": op(json!({"security": [{"api_key": []}], "x-amazon-apigateway-request-validator": "all"}))}
            }
        })
    }

    fn throttled_stage(entries: &[(SettingsScope, f64, i32)]) -> StageSettings {
        let mut stage = StageSettings::default();
        for (scope, rate, burst) in entries {
            stage.method_settings.insert(
                scope.clone(),
                MethodSettings {
                    throttling_rate_limit: Some(*rate),
                    throttling_burst_limit: Some(*burst),
                    ..MethodSettings::default()
                },
            );
        }
        stage
    }

    fn route_scope(path: &str, method: &str) -> SettingsScope {
        SettingsScope::Method {
            path: path.to_owned(),
            method: method.to_owned(),
        }
    }

    #[tokio::test]
    async fn rest_method_throttling_answers_429_after_the_burst() {
        let doc = json!({"paths": {
            "/a": {"get": {"x-amazon-apigateway-integration": mock(200)}},
            "/b": {"get": {"x-amazon-apigateway-integration": mock(200)}}
        }});
        let stage = throttled_stage(&[
            (SettingsScope::All, 0.0, 2),
            (route_scope("/b", "GET"), 0.0, 0),
        ]);
        let (rest, summaries) = router_for_stage(&doc, ApiKind::Rest, STRICT, stage, "");
        assert!(summaries.iter().all(|s| s.problems.is_empty()));
        for _ in 0..2 {
            assert_eq!(call(&rest, Method::GET, "/a").await.0, StatusCode::OK);
        }
        let response = call_full(&rest, Method::GET, "/a").await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            response.headers()["x-amzn-errortype"],
            "ThrottlingException"
        );
        assert_eq!(response.body, r#"{"message":"Too Many Requests"}"#);
        assert_eq!(
            call(&rest, Method::GET, "/b").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn http_route_throttling_answers_429_and_ignores_customization() {
        let doc = json!({"paths": {
            "/a": {"get": {"x-amazon-apigateway-integration": mock(200)}},
            "/$default": {"x-amazon-apigateway-any-method": {"x-amazon-apigateway-integration": mock(200)}}
        }});
        let stage = throttled_stage(&[
            (SettingsScope::All, 0.0, 100),
            (route_scope("/a", "GET"), 0.0, 1),
            (route_scope("$default", "*"), 0.0, 0),
        ]);
        let (http, _) = router_for_stage(&doc, ApiKind::Http, STRICT, stage, "");
        assert_eq!(call(&http, Method::GET, "/a").await.0, StatusCode::OK);
        assert_eq!(
            call(&http, Method::GET, "/a").await,
            (
                StatusCode::TOO_MANY_REQUESTS,
                r#"{"message":"Too Many Requests"}"#.to_owned()
            )
        );
        assert_eq!(
            call(&http, Method::GET, "/other").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }

    #[tokio::test]
    async fn throttled_responses_use_the_customized_gateway_response() {
        let doc = json!({
            "x-amazon-apigateway-gateway-responses": {"THROTTLED": {
                "statusCode": "503",
                "responseTemplates": {"application/json": "{\"retry\": true}"}
            }},
            "paths": {"/a": {"get": {"x-amazon-apigateway-integration": mock(200)}}}
        });
        let stage = throttled_stage(&[(SettingsScope::All, 0.0, 0)]);
        let (rest, _) = router_for_stage(&doc, ApiKind::Rest, STRICT, stage, "");
        assert_eq!(
            call(&rest, Method::GET, "/a").await,
            (
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"retry": true}"#.to_owned()
            )
        );
    }

    #[tokio::test]
    async fn throttling_runs_before_the_body_is_read_and_after_refusals() {
        let doc = json!({"paths": {"/key": {"get": {
            "x-amazon-apigateway-integration": mock(200),
            "security": [{"api_key": []}]
        }}}, "components": {"securitySchemes": {
            "api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"}
        }}});
        let stage = throttled_stage(&[(SettingsScope::All, 0.0, 0)]);
        let (rest, _) = router_for_stage(&doc, ApiKind::Rest, STRICT, stage, "");
        assert_eq!(
            call(&rest, Method::GET, "/key").await.0,
            StatusCode::FORBIDDEN
        );
    }

    fn cors_doc() -> Value {
        json!({
            "x-amazon-apigateway-cors": {
                "allowOrigins": ["https://app.example"],
                "allowMethods": ["GET", "POST"],
                "allowHeaders": ["authorization"],
                "exposeHeaders": ["x-id"],
                "maxAge": 300
            },
            "components": {"securitySchemes": {
                "sigv4": {"type": "apiKey", "name": "Authorization", "in": "header", "x-amazon-apigateway-authtype": "awsSigv4"}
            }},
            "paths": {
                "/pets": {"get": {"x-amazon-apigateway-integration": mock(200)}},
                "/iam": {"options": {"security": [{"sigv4": []}], "x-amazon-apigateway-integration": mock(200)}},
                "/opts": {"options": {"x-amazon-apigateway-integration": mock(418)}}
            }
        })
    }

    async fn call_with(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> Reply {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, *value);
        }
        let response = router
            .clone()
            .oneshot(builder.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8(body.to_vec()).unwrap(),
        }
    }

    #[tokio::test]
    async fn http_api_cors_preflight_is_answered_without_the_integration() {
        let (http, _) = router_with(&cors_doc(), ApiKind::Http, STRICT, "");
        let preflight = [
            ("origin", "https://app.example"),
            ("access-control-request-method", "GET"),
        ];
        // A route with its own OPTIONS integration still gets the gateway's answer.
        for path in ["/pets", "/opts", "/nowhere"] {
            let reply = call_with(&http, Method::OPTIONS, path, &preflight).await;
            assert_eq!(reply.status(), StatusCode::NO_CONTENT, "{path}");
            assert_eq!(
                reply.headers()["access-control-allow-origin"],
                "https://app.example"
            );
            assert_eq!(reply.headers()["access-control-allow-methods"], "GET, POST");
            assert_eq!(reply.headers()["access-control-max-age"], "300");
        }
        let blocked = call_with(
            &http,
            Method::OPTIONS,
            "/pets",
            &[
                ("origin", "https://evil.example"),
                ("access-control-request-method", "GET"),
            ],
        )
        .await;
        assert_eq!(blocked.status(), StatusCode::NO_CONTENT);
        assert!(
            blocked
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
        // Without the preflight headers an OPTIONS request is an ordinary request.
        let plain = call_with(
            &http,
            Method::OPTIONS,
            "/opts",
            &[("origin", "https://app.example")],
        )
        .await;
        assert_eq!(plain.status(), StatusCode::IM_A_TEAPOT);
    }

    #[tokio::test]
    async fn http_api_cors_preflight_follows_route_protections() {
        let (http, _) = router_with(&cors_doc(), ApiKind::Http, STRICT, "");
        let reply = call_with(
            &http,
            Method::OPTIONS,
            "/iam",
            &[
                ("origin", "https://app.example"),
                ("access-control-request-method", "GET"),
            ],
        )
        .await;
        assert_eq!(reply.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn http_api_cors_headers_are_added_to_responses() {
        let (http, _) = router_with(&cors_doc(), ApiKind::Http, STRICT, "");
        let reply = call_with(
            &http,
            Method::GET,
            "/pets",
            &[("origin", "https://app.example")],
        )
        .await;
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(
            reply.headers()["access-control-allow-origin"],
            "https://app.example"
        );
        assert_eq!(reply.headers()["access-control-expose-headers"], "x-id");
        let other = call_with(
            &http,
            Method::GET,
            "/pets",
            &[("origin", "https://evil.example")],
        )
        .await;
        assert!(other.headers().get("access-control-allow-origin").is_none());
        let missing = call_with(
            &http,
            Method::GET,
            "/nope",
            &[("origin", "https://app.example")],
        )
        .await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            missing.headers()["access-control-allow-origin"],
            "https://app.example"
        );
        let (no_cors, _) = router_with(&sample(), ApiKind::Http, STRICT, "");
        let reply = call_with(
            &no_cors,
            Method::GET,
            "/pets",
            &[("origin", "https://app.example")],
        )
        .await;
        assert!(reply.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn http_routes_fall_back_to_a_less_specific_route_that_serves_the_method() {
        let doc = json!({"paths": {
            "/pets/dog/1": {"get": {"x-amazon-apigateway-integration": mock(201)}},
            "/pets/dog/{id}": {"get": {"x-amazon-apigateway-integration": mock(203)}},
            "/pets/{proxy+}": {"get": {"x-amazon-apigateway-integration": mock(204)}},
            "/{proxy+}": {"x-amazon-apigateway-any-method": {"x-amazon-apigateway-integration": mock(202)}},
            "/$default": {"x-amazon-apigateway-any-method": {"x-amazon-apigateway-integration": mock(418)}}
        }});
        let (http, _) = router_with(&doc, ApiKind::Http, STRICT, "");
        let status = |method, path| {
            let http = http.clone();
            async move { call(&http, method, path).await.0.as_u16() }
        };
        assert_eq!(status(Method::GET, "/pets/dog/1").await, 201);
        assert_eq!(status(Method::GET, "/pets/dog/2").await, 203);
        assert_eq!(status(Method::GET, "/pets/cat/1").await, 204);
        assert_eq!(status(Method::POST, "/pets/dog/1").await, 202);
        assert_eq!(status(Method::POST, "/test/5").await, 202);
        assert_eq!(status(Method::GET, "/").await, 418);
    }

    #[tokio::test]
    async fn customized_gateway_responses_apply_to_router_errors() {
        let mut doc = protected_doc();
        doc.as_object_mut().unwrap().insert("x-amazon-apigateway-gateway-responses".to_owned(), json!({
            "MISSING_AUTHENTICATION_TOKEN": {
                "statusCode": "404",
                "responseTemplates": {"application/json": "{\"hint\": \"$context.error.message\", \"path\": \"$context.resourcePath\"}"}
            },
            "INVALID_API_KEY": {"statusCode": "401"}
        }));
        let (rest, _) = router_with(&doc, ApiKind::Rest, STRICT, "/prod");
        assert_eq!(
            call(&rest, Method::GET, "/prod/nope").await,
            (
                StatusCode::NOT_FOUND,
                r#"{"hint": "Missing Authentication Token", "path": "/nope"}"#.to_owned()
            )
        );
        assert_eq!(
            call(&rest, Method::GET, "/outside").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&rest, Method::GET, "/prod/iam").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&rest, Method::GET, "/prod/key").await,
            (
                StatusCode::UNAUTHORIZED,
                r#"{"message":"Forbidden"}"#.to_owned()
            )
        );
        let (http, _) = router_with(&doc, ApiKind::Http, STRICT, "");
        assert_eq!(
            call(&http, Method::GET, "/nope").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            call(&http, Method::GET, "/key").await,
            (
                StatusCode::FORBIDDEN,
                r#"{"message":"Forbidden"}"#.to_owned()
            )
        );
    }

    #[tokio::test]
    async fn unsupported_protections_fail_closed_with_api_gateway_responses() {
        let (rest, summaries) = router_with(&protected_doc(), ApiKind::Rest, STRICT, "");
        assert_eq!(call(&rest, Method::GET, "/open").await.0, StatusCode::OK);
        assert_eq!(
            call(&rest, Method::GET, "/iam").await,
            (
                StatusCode::FORBIDDEN,
                r#"{"message":"Missing Authentication Token"}"#.to_owned()
            )
        );
        assert_eq!(
            call(&rest, Method::GET, "/key").await,
            (
                StatusCode::FORBIDDEN,
                r#"{"message":"Forbidden"}"#.to_owned()
            )
        );
        assert_eq!(
            call(&rest, Method::GET, "/validated").await.0,
            StatusCode::NOT_IMPLEMENTED
        );
        // API Gateway checks the API key before running the validator.
        assert_eq!(
            call(&rest, Method::GET, "/key-and-validated").await.0,
            StatusCode::FORBIDDEN
        );
        let both = summaries
            .iter()
            .find(|s| s.route_key == "GET /key-and-validated")
            .unwrap();
        assert_eq!(both.problems.len(), 2, "{both:?}");

        let (http, _) = router_with(&protected_doc(), ApiKind::Http, STRICT, "");
        assert_eq!(
            call(&http, Method::GET, "/iam").await,
            (
                StatusCode::FORBIDDEN,
                r#"{"message":"Forbidden"}"#.to_owned()
            )
        );

        let relaxed = Enforcement {
            authorization: AuthorizationMode::Skip,
            request_validation: Unsupported::Ignore,
            ..STRICT
        };
        let (rest, summaries) = router_with(&protected_doc(), ApiKind::Rest, relaxed, "");
        for path in ["/iam", "/key", "/validated", "/key-and-validated"] {
            assert_eq!(
                call(&rest, Method::GET, path).await.0,
                StatusCode::OK,
                "{path}"
            );
        }
        assert!(
            summaries.iter().all(|s| s.problems.is_empty()),
            "{summaries:?}"
        );
    }

    #[tokio::test]
    async fn resource_policies_are_not_skipped_by_skip_authorization() {
        let mut doc = protected_doc();
        if let Some(doc) = doc.as_object_mut() {
            doc.insert(
                "x-amazon-apigateway-policy".to_owned(),
                json!({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": "*",
                    "Action": "execute-api:Invoke", "Resource": "execute-api:/*",
                    "Condition": {"IpAddress": {"aws:SourceIp": "203.0.113.0/24"}}}]}),
            );
        }
        let skip_auth = Enforcement {
            authorization: AuthorizationMode::Skip,
            ..STRICT
        };
        let (rest, summaries) = router_with(&doc, ApiKind::Rest, skip_auth, "");
        assert_eq!(
            call(&rest, Method::GET, "/open").await,
            (
                StatusCode::FORBIDDEN,
                r#"{"message":"Forbidden"}"#.to_owned()
            )
        );
        assert!(
            summaries
                .iter()
                .all(|s| s.protections.contains(Protection::ResourcePolicy))
        );
        let ignore = Enforcement {
            resource_policy: Unsupported::Ignore,
            ..skip_auth
        };
        let (rest, _) = router_with(&doc, ApiKind::Rest, ignore, "");
        assert_eq!(call(&rest, Method::GET, "/open").await.0, StatusCode::OK);
    }

    async fn status_with(
        router: &Router,
        method: Method,
        uri: &str,
        headers: &[(&str, String)],
    ) -> StatusCode {
        let mut builder = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            builder = builder.header(*name, value);
        }
        let request = builder.body(Body::empty()).unwrap();
        router.clone().oneshot(request).await.unwrap().status()
    }

    #[tokio::test]
    async fn rest_apis_honor_method_override_and_enforce_request_limits() {
        let (rest, _) = router(&sample(), ApiKind::Rest, AuthorizationMode::Enforce, "");
        assert_eq!(
            status_with(&rest, Method::POST, "/pets", &[]).await,
            StatusCode::ACCEPTED
        );
        let override_get = [("x-http-method-override", "GET".to_owned())];
        assert_eq!(
            status_with(&rest, Method::POST, "/pets", &override_get).await,
            StatusCode::OK,
            "the header replaces the method before routing"
        );

        let at_limit = format!("/pets?q={}", "a".repeat(10_240 - "/pets?q=".len()));
        assert_eq!(
            status_with(&rest, Method::GET, &at_limit, &[]).await,
            StatusCode::OK
        );
        assert_eq!(
            status_with(&rest, Method::GET, &format!("{at_limit}a"), &[]).await,
            StatusCode::URI_TOO_LONG
        );
        let big_header = [("x-pad", "a".repeat(20_480 - "x-pad: \r\n".len()))];
        assert_eq!(
            status_with(&rest, Method::GET, "/pets", &big_header).await,
            StatusCode::OK
        );
        let bigger = [("x-pad", "a".repeat(20_481 - "x-pad: \r\n".len()))];
        assert_eq!(
            status_with(&rest, Method::GET, "/pets", &bigger).await,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
        assert_eq!(
            status_with(&rest, Method::GET, "/missing", &bigger).await,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            "unrouted requests are measured too"
        );

        let (http, _) = router(&sample(), ApiKind::Http, AuthorizationMode::Enforce, "");
        assert_eq!(
            status_with(&http, Method::POST, "/pets", &override_get).await,
            StatusCode::ACCEPTED,
            "HTTP APIs ignore the override header"
        );
        let http_limit = [(
            "x-pad",
            "a".repeat(10_240 - "GET /pets HTTP/1.1\r\nx-pad: \r\n".len()),
        )];
        assert_eq!(
            status_with(&http, Method::GET, "/pets", &http_limit).await,
            StatusCode::OK
        );
        let http_over = [(
            "x-pad",
            "a".repeat(10_241 - "GET /pets HTTP/1.1\r\nx-pad: \r\n".len()),
        )];
        assert_eq!(
            status_with(&http, Method::GET, "/pets", &http_over).await,
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE
        );
    }

    struct Reply {
        status: StatusCode,
        headers: axum::http::HeaderMap,
        body: String,
    }

    impl Reply {
        fn status(&self) -> StatusCode {
            self.status
        }

        fn headers(&self) -> &axum::http::HeaderMap {
            &self.headers
        }
    }

    async fn call_full(router: &Router, method: Method, uri: &str) -> Reply {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: String::from_utf8(body.to_vec()).unwrap(),
        }
    }

    async fn call(router: &Router, method: Method, uri: &str) -> (StatusCode, String) {
        let request = Request::builder()
            .method(method)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        let response = router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    fn sample() -> Value {
        json!({"paths": {
            "/pets": {"get": {"x-amazon-apigateway-integration": mock(200)},
                      "x-amazon-apigateway-any-method": {"x-amazon-apigateway-integration": mock(202)}},
            "/pets/{petId}": {"get": {"x-amazon-apigateway-integration": mock(201)}},
            "/files/{proxy+}": {"put": {"x-amazon-apigateway-integration": mock(204)}},
            "/secure": {"get": {"security": [{"jwt": []}], "x-amazon-apigateway-integration": mock(200)}},
            "/legacy": {"get": {"x-amazon-apigateway-integration": {"type": "aws", "uri": "arn:aws:apigateway:us-east-1:sqs:path/q"}}}
        }})
    }

    #[tokio::test]
    async fn routes_by_method_with_any_fallback() {
        let (router, _) = router(&sample(), ApiKind::Rest, AuthorizationMode::Enforce, "");
        assert_eq!(call(&router, Method::GET, "/pets").await.0, StatusCode::OK);
        assert_eq!(
            call(&router, Method::DELETE, "/pets").await.0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call(&router, Method::GET, "/pets/7").await.0,
            StatusCode::CREATED
        );
        assert_eq!(
            call(&router, Method::PUT, "/files/a/b/c").await.0,
            StatusCode::NO_CONTENT
        );
    }

    #[tokio::test]
    async fn unmatched_requests_get_api_gateway_errors() {
        let (rest, _) = router(&sample(), ApiKind::Rest, AuthorizationMode::Enforce, "");
        let (status, body) = call(&rest, Method::POST, "/pets/7").await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body, r#"{"message":"Missing Authentication Token"}"#);
        assert_eq!(
            call(&rest, Method::GET, "/nope").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&rest, Method::PUT, "/files").await.0,
            StatusCode::FORBIDDEN
        );
        let (http, _) = router(&sample(), ApiKind::Http, AuthorizationMode::Enforce, "");
        assert_eq!(
            call(&http, Method::GET, "/nope").await.0,
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn protected_routes_depend_on_authorization_mode() {
        let (enforce, summaries) = router(&sample(), ApiKind::Rest, AuthorizationMode::Enforce, "");
        assert_eq!(
            call(&enforce, Method::GET, "/secure").await.0,
            StatusCode::UNAUTHORIZED
        );
        let secure = summaries
            .iter()
            .find(|s| s.route_key == "GET /secure")
            .unwrap();
        assert!(secure.protections.contains(Protection::Authorizer) && !secure.problems.is_empty());
        let (skip, summaries) = router(&sample(), ApiKind::Rest, AuthorizationMode::Skip, "");
        assert_eq!(call(&skip, Method::GET, "/secure").await.0, StatusCode::OK);
        assert!(
            summaries
                .iter()
                .find(|s| s.route_key == "GET /secure")
                .unwrap()
                .problems
                .is_empty()
        );
    }

    #[tokio::test]
    async fn unmapped_vpc_links_answer_501_with_the_reason_on_routes() {
        let doc = json!({"paths": {"/private": {"get": {"x-amazon-apigateway-integration": {
            "type": "http_proxy", "httpMethod": "GET", "connectionType": "VPC_LINK",
            "connectionId": "vl1", "uri": "http://nlb.internal/x"}}}}});
        let (router, summaries) = router(&doc, ApiKind::Rest, AuthorizationMode::Enforce, "");
        assert_eq!(
            call(&router, Method::GET, "/private").await.0,
            StatusCode::NOT_IMPLEMENTED
        );
        let problems = &summaries.first().unwrap().problems;
        assert!(
            problems.iter().any(|p| p.contains("--vpc-link vl1=<url>")),
            "{problems:?}"
        );
    }

    #[tokio::test]
    async fn unsupported_integrations_answer_501_and_are_reported() {
        let (router, summaries) = router(&sample(), ApiKind::Rest, AuthorizationMode::Enforce, "");
        assert_eq!(
            call(&router, Method::GET, "/legacy").await.0,
            StatusCode::NOT_IMPLEMENTED
        );
        let legacy = summaries
            .iter()
            .find(|s| s.route_key == "GET /legacy")
            .unwrap();
        assert_eq!(legacy.integration, "UNSUPPORTED");
        assert!(!legacy.problems.is_empty());
    }

    #[tokio::test]
    async fn base_path_prefixes_every_route() {
        let (router, _) = router(
            &sample(),
            ApiKind::Rest,
            AuthorizationMode::Enforce,
            "/prod",
        );
        assert_eq!(
            call(&router, Method::GET, "/prod/pets").await.0,
            StatusCode::OK
        );
        assert_eq!(
            call(&router, Method::GET, "/pets").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            call(&router, Method::GET, "/prod/nope").await.0,
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn default_route_catches_unmatched_paths_and_methods() {
        let doc = json!({"paths": {
            "/pets": {"get": {"x-amazon-apigateway-integration": mock(200)}},
            "/$default": {"x-amazon-apigateway-any-method": {"x-amazon-apigateway-integration": mock(418)}}
        }});
        let (router, _) = router(&doc, ApiKind::Http, AuthorizationMode::Enforce, "");
        assert_eq!(call(&router, Method::GET, "/pets").await.0, StatusCode::OK);
        assert_eq!(
            call(&router, Method::POST, "/pets").await.0,
            StatusCode::IM_A_TEAPOT
        );
        assert_eq!(
            call(&router, Method::GET, "/anything/else").await.0,
            StatusCode::IM_A_TEAPOT
        );
    }

    #[tokio::test]
    async fn conflicting_paths_are_skipped_not_fatal() {
        let doc = json!({"paths": {
            "/a/{x}": {"get": {"x-amazon-apigateway-integration": mock(200)}},
            "/a/{y}": {"get": {"x-amazon-apigateway-integration": mock(201)}},
            "/a/{z}/b": {"get": {"x-amazon-apigateway-integration": mock(202)}},
            "/bad/{p+}/tail": {"get": {"x-amazon-apigateway-integration": mock(200)}},
            "/v1/:batch/*star": {"get": {"x-amazon-apigateway-integration": mock(203)}}
        }});
        let (router, summaries) = router(&doc, ApiKind::Http, AuthorizationMode::Enforce, "");
        let served: Vec<&str> = summaries
            .iter()
            .filter(|s| s.problems.is_empty())
            .map(|s| s.route_key.as_str())
            .collect();
        assert_eq!(
            served,
            vec!["GET /a/{x}", "GET /a/{z}/b", "GET /v1/:batch/*star"],
            "{summaries:?}"
        );
        assert_eq!(call(&router, Method::GET, "/a/1").await.0, StatusCode::OK);
        assert_eq!(
            call(&router, Method::GET, "/a/1/b").await.0,
            StatusCode::ACCEPTED
        );
        assert_eq!(
            call(&router, Method::GET, "/v1/:batch/*star").await.0,
            StatusCode::NON_AUTHORITATIVE_INFORMATION
        );
    }

    #[tokio::test]
    async fn dispatcher_switches_routers_and_sets_request_id() {
        let (first, summary) = router(&sample(), ApiKind::Rest, AuthorizationMode::Enforce, "");
        let loaded = |router, summary| {
            Arc::new(Loaded {
                router,
                kind: ApiKind::Rest,
                summary: LoadSummary {
                    api_id: "abc".to_owned(),
                    stage: None,
                    deployment_id: None,
                    loaded_at: String::new(),
                    unenforced: Vec::new(),
                    routes: summary,
                    canary: None,
                },
                canary: None,
            })
        };
        let (tx, rx) = watch::channel(loaded(first, summary));
        let app = dispatcher(rx.clone());
        let response = app
            .clone()
            .oneshot(Request::builder().uri("/pets").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().contains_key("x-amzn-requestid"));

        let doc =
            json!({"paths": {"/pets": {"get": {"x-amazon-apigateway-integration": mock(203)}}}});
        let (second, summary) = router(&doc, ApiKind::Rest, AuthorizationMode::Enforce, "");
        tx.send(loaded(second, summary)).unwrap();
        assert_eq!(
            call(&app, Method::GET, "/pets").await.0,
            StatusCode::NON_AUTHORITATIVE_INFORMATION
        );

        let (status, body) = call(&admin(rx, aws()), Method::GET, "/routes").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("GET /pets"), "{body}");
    }

    #[tokio::test]
    async fn lambda_routes_invoke_through_endpoint_overrides() {
        let app = Router::new().route(
            "/invoke",
            axum::routing::post(|headers: axum::http::HeaderMap, body: axum::body::Bytes| async move {
                let event: Value = serde_json::from_slice(&body).unwrap();
                let trace = headers.get("x-amzn-trace-id").and_then(|v| v.to_str().ok()).unwrap_or("none").to_owned();
                json!({
                    "statusCode": 201,
                    "headers": {"x-trace": trace},
                    "body": format!("{} {}", event.pointer("/httpMethod").and_then(Value::as_str).unwrap_or("?"), event.pointer("/pathParameters/id").and_then(Value::as_str).unwrap_or("?")),
                })
                .to_string()
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        let endpoint = reqwest::Url::parse(&format!("http://{addr}/invoke")).unwrap();
        let aws = Arc::new(AwsClients::new(
            config,
            CredentialsMode::Assume,
            LambdaEndpoints::from_iter([("items".to_owned(), endpoint)]),
            reqwest::Client::new(),
        ));
        let doc = json!({"paths": {"/items/{id}": {"put": {"x-amazon-apigateway-integration": {
            "type": "aws_proxy", "httpMethod": "POST",
            "uri": "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:items/invocations"
        }}}}});
        let model = ApiModel::import(
            &doc,
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        )
        .unwrap();
        let api = Arc::new(ApiContext {
            kind: ApiKind::Rest,
            api_id: "abc".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: Arc::default(),
            responses: GatewayResponses::default(),
            cors: None,
            state: test_state(),
            replicas: NonZeroU32::MIN,
            vpc_links: VpcLinks::default(),
            enforcement: STRICT,
            http: reqwest::Client::new(),
            aws,
            keys: Arc::new(KeyStore::new(reqwest::Client::new(), [])),
            observer: StageObserver::disabled(),
            release: None,
        });
        let (router, _) = build(&model, &api, &BasePath::default());
        let request = Request::builder()
            .method(Method::PUT)
            .uri("/items/42")
            .header("x-amzn-trace-id", "Root=1-test")
            .body(Body::empty())
            .unwrap();
        let response = router.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-trace"], "Root=1-test");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(&*body, b"PUT 42");
    }

    #[test]
    fn base_path_validation() {
        assert_eq!("".parse::<BasePath>().unwrap(), BasePath(None));
        assert_eq!("/".parse::<BasePath>().unwrap(), BasePath(None));
        assert_eq!(
            "/prod".parse::<BasePath>().unwrap(),
            BasePath(Some("/prod".to_owned()))
        );
        for bad in ["prod", "/prod/", "/{stage}", "/*x"] {
            assert!(bad.parse::<BasePath>().is_err(), "{bad}");
        }
    }

    #[test]
    fn axum_path_translation() {
        assert_eq!(axum_path("/").unwrap(), "/");
        assert_eq!(axum_path("/pets/{petId}").unwrap(), "/pets/{petId}");
        assert_eq!(axum_path("/{proxy+}").unwrap(), "/{*proxy}");
        assert!(axum_path("/{proxy+}/x").is_err());
        assert!(axum_path("pets").is_err());
    }

    proptest! {
        /// Whatever path the export contains, building the router never panics:
        /// invalid or conflicting paths are reported and skipped.
        #[test]
        fn build_never_panics(paths in proptest::collection::vec("/[a-z{}+*:/]{0,12}", 1..6)) {
            let mut doc_paths = serde_json::Map::new();
            for path in paths {
                doc_paths.insert(path, json!({"get": {"x-amazon-apigateway-integration": {"type": "mock"}}}));
            }
            let doc = json!({"paths": doc_paths});
            drop(router(&doc, ApiKind::Http, AuthorizationMode::Enforce, ""));
        }
    }
}
