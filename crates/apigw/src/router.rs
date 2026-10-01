//! Builds an axum [`Router`] from an [`ApiDefinition`] and swaps it in place
//! when the definition changes.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use axum::Router;
use axum::extract::Request;
use axum::http::{HeaderValue, Method};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde::Serialize;
use tokio::sync::watch;
use tower::ServiceExt as _;
use uuid::Uuid;

use crate::gateway::{self, ApiContext, RequestId, request_id_header};
use crate::spec::{
    ApiDefinition, ApiKind, Authorization, Integration, MethodMatch, Route, RoutePath,
};

/// A stage prefix such as `/prod` that every route is served under, as on an
/// `execute-api` endpoint. Empty serves routes at the root, as on a custom domain.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct BasePath(Option<String>);

#[derive(Debug, thiserror::Error)]
#[error(
    "base path {0:?} must start with '/', must not end with '/', and must not contain '{{' or '}}'"
)]
pub(crate) struct InvalidBasePath(String);

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
    pub(crate) kind: ApiKind,
    pub(crate) summary: LoadSummary,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LoadSummary {
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
    pub(crate) loaded_at: String,
    pub(crate) routes: Vec<RouteSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RouteSummary {
    pub(crate) route_key: String,
    pub(crate) integration: &'static str,
    pub(crate) target: Option<String>,
    pub(crate) authorization_required: bool,
    /// Why the route is not being served as API Gateway would serve it.
    pub(crate) problem: Option<String>,
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

    async fn handle(&self, request: Request) -> Response {
        match self.select(request.method()) {
            Some(route) => gateway::handle(&self.ctx, route, request).await,
            None => gateway::not_found(self.ctx.kind),
        }
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
    definition: &ApiDefinition,
    ctx: &Arc<ApiContext>,
    base: &BasePath,
) -> (Router, Vec<RouteSummary>) {
    let mut summaries = Vec::with_capacity(definition.routes.len());
    let mut default = None;
    let mut by_path: BTreeMap<String, BTreeMap<MethodMatch, Route>> = BTreeMap::new();
    for route in &definition.routes {
        let mut summary = summarize(route, ctx.authorization);
        match route.path {
            RoutePath::Default => default = Some(Arc::new(route.clone())),
            RoutePath::Resource(ref path) => match axum_path(path) {
                Ok(path) => {
                    by_path
                        .entry(path)
                        .or_default()
                        .insert(route.method.clone(), route.clone());
                }
                Err(reason) => summary.problem = Some(format!("not served: {reason}")),
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
    for (path, methods) in by_path {
        if let Err(err) = matcher.insert(path.as_str(), ()) {
            tracing::error!(path, %err, "route conflicts with another route; skipping it");
            for summary in &mut summaries {
                if methods.values().any(|r| r.route_key() == summary.route_key) {
                    summary.problem = Some(format!("not served: {err}"));
                }
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

    let fallback = Arc::new(PathRoutes {
        ctx: Arc::clone(ctx),
        methods: BTreeMap::new(),
        default,
    });
    let router = router.fallback(move |request: Request| {
        let fallback = Arc::clone(&fallback);
        async move { fallback.handle(request).await }
    });
    let router = match base.0 {
        Some(ref prefix) => {
            let kind = ctx.kind;
            Router::new()
                .without_v07_checks()
                .nest(prefix, router)
                .fallback(move || async move { gateway::not_found(kind) })
        }
        None => router,
    };
    (router, summaries)
}

fn summarize(route: &Route, mode: gateway::AuthorizationMode) -> RouteSummary {
    let (target, mut problem) = match route.integration {
        Integration::HttpProxy(ref proxy) => (Some(proxy.uri.clone()), None),
        Integration::Lambda(ref lambda) => (Some(lambda.function.clone()), None),
        Integration::Mock(_) => (None, None),
        Integration::Unsupported { ref reason } => (None, Some(reason.clone())),
    };
    let authorization_required = route.authorization == Authorization::Required;
    if authorization_required && mode == gateway::AuthorizationMode::Enforce && problem.is_none() {
        problem = Some(
            "requires authorization, which this gateway does not evaluate; answering 401"
                .to_owned(),
        );
    }
    RouteSummary {
        route_key: route.route_key(),
        integration: route.integration.kind(),
        target,
        authorization_required,
        problem,
    }
}

/// Serves every request through whichever [`Loaded`] router is current, so a
/// refreshed definition takes effect without restarting the listener. Requests
/// already in flight finish on the router they started with.
pub(crate) fn dispatcher(current: watch::Receiver<Arc<Loaded>>) -> Router {
    Router::new().fallback(move |mut request: Request| {
        let loaded = Arc::clone(&current.borrow());
        async move {
            let started = Instant::now();
            let request_id = Uuid::now_v7();
            request.extensions_mut().insert(RequestId(request_id));
            let method = request.method().clone();
            let path = request.uri().path().to_owned();
            let mut response = loaded.router.clone().oneshot(request).await.into_response();
            if let Ok(value) = HeaderValue::try_from(request_id.to_string()) {
                response
                    .headers_mut()
                    .insert(request_id_header(loaded.kind), value);
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
    })
}

/// Health and introspection routes for the admin listener.
pub(crate) fn admin(current: watch::Receiver<Arc<Loaded>>) -> Router {
    Router::new()
        .route("/healthz", axum::routing::get(|| async { "ok" }))
        .route(
            "/routes",
            axum::routing::get(move || {
                let summary = current.borrow().summary.clone();
                async move { axum::Json(summary) }
            }),
        )
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use std::collections::BTreeMap;

    use axum::body::Body;
    use axum::http::StatusCode;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    use super::*;
    use crate::gateway::AuthorizationMode;
    use crate::spec::IntegrationOverrides;

    fn ctx(kind: ApiKind, authorization: AuthorizationMode) -> Arc<ApiContext> {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        Arc::new(ApiContext {
            kind,
            api_id: "abc".to_owned(),
            stage: None,
            stage_variables: BTreeMap::new(),
            authorization,
            http: reqwest::Client::new(),
            lambda: aws_sdk_lambda::Client::new(&config),
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
        let def =
            ApiDefinition::from_openapi(doc, kind, &BTreeMap::new(), &IntegrationOverrides::new())
                .unwrap();
        build(&def, &ctx(kind, mode), &base.parse().unwrap())
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
        assert!(secure.authorization_required && secure.problem.is_some());
        let (skip, summaries) = router(&sample(), ApiKind::Rest, AuthorizationMode::Skip, "");
        assert_eq!(call(&skip, Method::GET, "/secure").await.0, StatusCode::OK);
        assert!(
            summaries
                .iter()
                .find(|s| s.route_key == "GET /secure")
                .unwrap()
                .problem
                .is_none()
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
        assert!(legacy.problem.is_some());
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
            .filter(|s| s.problem.is_none())
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
                    loaded_at: String::new(),
                    routes: summary,
                },
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

        let (status, body) = call(&admin(rx), Method::GET, "/routes").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("GET /pets"), "{body}");
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
