//! Response caching for REST APIs.
//!
//! A stage with `cacheClusterEnabled` can cache the responses of methods whose
//! method settings enable caching, in the [`StateBackend`] cache. As in API
//! Gateway:
//!
//! - only `GET` methods are cached unless the method has its own caching
//!   setting (the stage-wide `*/*` entry does not enable other methods);
//! - the TTL is the method setting's, 300 seconds by default and at most
//!   3,600, and 0 turns caching off;
//! - entries are keyed by the method and the values of the integration's cache
//!   key parameters, so responses for different values are cached separately
//!   and a request that differs only in other parameters hits the same entry;
//! - a response larger than 1,048,576 bytes is not cached.
//!
//! Differences: only successful (2xx) responses are cached; cache data
//! encryption is not applicable to the state backend; and a client can never
//! be authorized to invalidate an entry with `Cache-Control: max-age=0`
//! because this gateway cannot verify the IAM permission
//! (`execute-api:InvalidateCache`) API Gateway checks, so a method that
//! requires that authorization (the default) handles every such request as an
//! unauthorized one.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html>

use std::collections::VecDeque;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hyper::body::{Body as HttpBody, Frame, SizeHint};
use serde::{Deserialize, Serialize};

use crate::canary::Release;
use crate::gateway::HeaderNameExt as _;
use crate::gateway_response::Failure;
use crate::model::{
    CanarySettings, IntegrationSpec, MethodMatch, MethodSettings, Operation, ResponseType,
    RoutePath, StageSettings,
};
use crate::pipeline::RequestContext;
use crate::state::{StateBackend, StateKey};

/// The largest response API Gateway caches.
pub(crate) const MAX_ENTRY_BYTES: usize = 1_048_576;

const DEFAULT_TTL_SECONDS: i32 = 300;
const MAX_TTL_SECONDS: i32 = 3600;

/// The warning API Gateway adds when it ignores `Cache-Control` from an
/// unauthorized client.
const UNAUTHORIZED_WARNING: &str =
    "199 Cache-control headers were ignored because the caller was unauthorized.";

/// Whether, and in which cache namespace, a release of a stage caches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CacheScope {
    /// The stage has no cache cluster, or this release does not use it.
    Off,
    /// Entries live under this partition; releases that share a partition
    /// share entries.
    On { partition: String },
}

impl CacheScope {
    /// The scope of the stage's own release, and of a canary release.
    ///
    /// A canary uses the stage cache only with `useStageCache`, and shares the
    /// production entries only when it runs the same deployment.
    pub(crate) fn of(
        cluster_enabled: bool,
        release: Option<Release>,
        canary: Option<&CanarySettings>,
        stage_deployment: Option<&str>,
    ) -> Self {
        if !cluster_enabled {
            return Self::Off;
        }
        match (release, canary) {
            (Some(Release::Canary), Some(canary)) if canary.use_stage_cache => {
                let same = canary.deployment_id.as_deref() == stage_deployment;
                Self::On {
                    partition: if same { "stage" } else { "canary" }.to_owned(),
                }
            }
            (Some(Release::Canary), _) => Self::Off,
            (Some(Release::Production) | None, _) => Self::On {
                partition: "stage".to_owned(),
            },
        }
    }
}

/// What API Gateway does with a request that asks to bypass the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnauthorizedStrategy {
    FailWith403,
    SucceedWithWarning,
    Succeed,
}

impl UnauthorizedStrategy {
    fn parse(raw: Option<&str>) -> Self {
        match raw {
            Some("FAIL_WITH_403") => Self::FailWith403,
            Some("SUCCEED_WITHOUT_RESPONSE_HEADER") => Self::Succeed,
            // The default.
            Some(_) | None => Self::SucceedWithWarning,
        }
    }
}

/// One header, query string, or path parameter that is part of the cache key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyParameter {
    Header(String),
    Query(String),
    Path(String),
    /// A fixed value (an integration parameter mapped to a literal).
    Literal(String),
}

impl KeyParameter {
    /// `method.request.{header|querystring|path}.name`, or an integration
    /// request parameter, which is resolved through the integration's own
    /// mapping from method request parameters.
    fn parse(name: &str, spec: &IntegrationSpec) -> Option<Self> {
        if let Some(rest) = name.strip_prefix("method.request.") {
            return Self::method_parameter(rest);
        }
        let mapped = spec.request_parameters.get(name)?;
        match mapped.strip_prefix("method.request.") {
            Some(rest) => Self::method_parameter(rest),
            None => mapped
                .strip_prefix('\'')
                .and_then(|literal| literal.strip_suffix('\''))
                .map(|literal| Self::Literal(literal.to_owned())),
        }
    }

    fn method_parameter(rest: &str) -> Option<Self> {
        let (location, name) = rest.split_once('.')?;
        let name = name.to_owned();
        match location {
            "header" => Some(Self::Header(name.to_ascii_lowercase())),
            "querystring" => Some(Self::Query(name)),
            "path" => Some(Self::Path(name)),
            _ => None,
        }
    }

    fn value(&self, ctx: &RequestContext) -> String {
        match self {
            Self::Header(name) => ctx.header_str(name).unwrap_or_default().to_owned(),
            Self::Query(name) => ctx
                .query
                .pairs()
                .into_iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value)
                .collect::<Vec<_>>()
                .join(","),
            Self::Path(name) => ctx.path_param(name).unwrap_or_default().to_owned(),
            Self::Literal(value) => value.clone(),
        }
    }
}

/// How the stage's cache settings apply to its routes.
#[derive(Debug, Clone)]
pub(crate) struct CacheSettings {
    stage: StageSettings,
    api_id: String,
    stage_name: String,
    scope: CacheScope,
}

impl CacheSettings {
    pub(crate) fn new(
        api_id: &str,
        stage_name: Option<&str>,
        stage: StageSettings,
        scope: CacheScope,
    ) -> Self {
        Self {
            stage,
            api_id: api_id.to_owned(),
            stage_name: stage_name.unwrap_or("$default").to_owned(),
            scope,
        }
    }

    /// The cache of a route, or `None` when nothing about it is cached.
    pub(crate) fn for_route(&self, operation: &Operation) -> Option<RouteCache> {
        let CacheScope::On { ref partition } = self.scope else {
            return None;
        };
        let layered = self.stage.settings_for(&operation.method, &operation.path);
        let own = self
            .stage
            .method_specific_settings(&operation.method, &operation.path);
        let serves_get = match operation.method {
            MethodMatch::Any => true,
            MethodMatch::Exact(ref method) => *method == Method::GET,
        };
        let for_get = serves_get && layered.caching_enabled == Some(true);
        let for_other = own.caching_enabled == Some(true);
        if !for_get && !for_other {
            return None;
        }
        let ttl = layered.cache_ttl_seconds.unwrap_or(DEFAULT_TTL_SECONDS);
        let ttl = u64::try_from(ttl.min(MAX_TTL_SECONDS))
            .ok()
            .filter(|ttl| *ttl > 0)?;
        let integration = operation.integration.as_ref();
        let parameters = integration
            .map(|spec| {
                spec.cache_key_parameters
                    .iter()
                    .filter_map(|name| KeyParameter::parse(name, spec))
                    .collect()
            })
            .unwrap_or_default();
        let route = integration
            .and_then(|spec| spec.cache_namespace.clone())
            .unwrap_or_else(|| match operation.path {
                RoutePath::Default => "$default".to_owned(),
                RoutePath::Resource(ref path) => path.clone(),
            });
        Some(RouteCache {
            scope: [
                self.api_id.clone(),
                self.stage_name.clone(),
                partition.clone(),
                route,
            ]
            .map(|part| part.replace(':', "%3A")),
            method: operation.method.clone(),
            ttl: Duration::from_secs(ttl),
            parameters,
            for_get,
            for_other,
            settings: Self::invalidation(&layered),
        })
    }

    fn invalidation(settings: &MethodSettings) -> Invalidation {
        Invalidation {
            require_authorization: settings
                .require_authorization_for_cache_control
                .unwrap_or(true),
            strategy: UnauthorizedStrategy::parse(
                settings
                    .unauthorized_cache_control_header_strategy
                    .as_deref(),
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Invalidation {
    require_authorization: bool,
    strategy: UnauthorizedStrategy,
}

/// One route's cache configuration.
#[derive(Debug, Clone)]
pub(crate) struct RouteCache {
    /// API, stage, partition, and route (or `cacheNamespace`), escaped so a
    /// `:` never appears inside a part.
    scope: [String; 4],
    method: MethodMatch,
    ttl: Duration,
    parameters: Vec<KeyParameter>,
    for_get: bool,
    for_other: bool,
    settings: Invalidation,
}

/// How a request interacts with the cache.
#[derive(Debug, Clone)]
pub(crate) struct CachePlan {
    key: StateKey,
    ttl: Duration,
    /// Whether a stored response may answer this request.
    read: bool,
    /// Whether to add the unauthorized-invalidation warning to the response.
    warn: bool,
}

/// Whether a response came from the cache, reported on responses of cached
/// routes for the `CacheHitCount` and `CacheMissCount` metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CacheOutcome {
    Hit,
    Miss,
}

impl RouteCache {
    /// Whether requests with `method` use the cache.
    fn caches(&self, method: &Method) -> bool {
        let matches_route = match self.method {
            MethodMatch::Any => true,
            MethodMatch::Exact(ref exact) => exact == method,
        };
        matches_route
            && if *method == Method::GET {
                self.for_get
            } else {
                self.for_other
            }
    }

    /// How `ctx` uses the cache, or `None` when it does not (`Ok`), or the
    /// failure to answer it with.
    ///
    /// # Errors
    ///
    /// When the request asks to bypass the cache, the method requires
    /// authorization for that, and the strategy is `FAIL_WITH_403`.
    pub(crate) fn plan(&self, ctx: &RequestContext) -> Result<Option<CachePlan>, Failure> {
        if !self.caches(&ctx.method) {
            return Ok(None);
        }
        let mut read = true;
        let mut warn = false;
        if CacheControl::asks_for_fresh(&ctx.headers) {
            if self.settings.require_authorization {
                match self.settings.strategy {
                    UnauthorizedStrategy::FailWith403 => {
                        return Err(Failure::new(ResponseType::AccessDenied));
                    }
                    UnauthorizedStrategy::SucceedWithWarning => warn = true,
                    UnauthorizedStrategy::Succeed => {}
                }
            } else {
                read = false;
            }
        }
        Ok(Some(CachePlan {
            key: self.key(ctx),
            ttl: self.ttl,
            read,
            warn,
        }))
    }

    fn key(&self, ctx: &RequestContext) -> StateKey {
        let values: Vec<String> = self
            .parameters
            .iter()
            .map(|parameter| Self::escaped(&parameter.value(ctx)))
            .collect();
        let [api, stage, partition, route] = &self.scope;
        let method = match self.method {
            MethodMatch::Any => ctx.method.as_str().to_owned(),
            MethodMatch::Exact(ref method) => method.to_string(),
        };
        StateKey::new(
            "cache",
            &[
                api,
                stage,
                partition,
                &route.replace(' ', "%20"),
                &method,
                &values.join("\u{1f}"),
            ],
        )
    }

    /// Keeps `\u{1f}` (the separator) out of values, so two different sets of
    /// values can never produce the same key.
    fn escaped(value: &str) -> String {
        value.replace('%', "%25").replace('\u{1f}', "%1F")
    }
}

/// The request's `Cache-Control` header.
struct CacheControl;

impl CacheControl {
    /// Whether the client sent `Cache-Control: max-age=0`.
    fn asks_for_fresh(headers: &HeaderMap) -> bool {
        headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .any(|directive| directive.trim().eq_ignore_ascii_case("max-age=0"))
    }
}

/// A response as stored: status, headers, and body.
#[derive(Debug, Serialize, Deserialize)]
struct CachedResponse {
    status: u16,
    headers: Vec<(String, String)>,
    body: String,
}

impl CachedResponse {
    fn encode(status: StatusCode, headers: &HeaderMap, body: &Bytes) -> Option<Bytes> {
        let headers = headers
            .iter()
            .filter(|(name, _)| !name.is_hop_by_hop())
            .filter_map(|(name, value)| {
                Some((name.as_str().to_owned(), value.to_str().ok()?.to_owned()))
            })
            .collect();
        let stored = Self {
            status: status.as_u16(),
            headers,
            body: BASE64.encode(body),
        };
        serde_json::to_vec(&stored).ok().map(Bytes::from)
    }

    fn into_response(self) -> Option<Response> {
        let body = BASE64.decode(self.body).ok()?;
        let mut response = Response::new(Body::from(body));
        *response.status_mut() = StatusCode::from_u16(self.status).ok()?;
        for (name, value) in self.headers {
            if let (Ok(name), Ok(value)) =
                (HeaderName::try_from(name), HeaderValue::try_from(value))
            {
                response.headers_mut().append(name, value);
            }
        }
        Some(response)
    }

    /// The size the response counts as against [`MAX_ENTRY_BYTES`].
    fn size(headers: &HeaderMap, body: &Bytes) -> usize {
        headers
            .iter()
            .map(|(name, value)| name.as_str().len().saturating_add(value.len()))
            .fold(body.len(), usize::saturating_add)
    }
}

impl CachePlan {
    /// The stored response for the request, if there is one and the request
    /// may use it.
    pub(crate) async fn lookup(&self, state: &StateBackend) -> Option<Response> {
        if !self.read {
            return None;
        }
        let stored = match state.cache_get(&self.key).await {
            Ok(stored) => stored?,
            Err(error) => {
                tracing::warn!(%error, "cache unavailable; serving from the integration");
                return None;
            }
        };
        let mut response = serde_json::from_slice::<CachedResponse>(&stored)
            .ok()
            .and_then(CachedResponse::into_response)?;
        self.finish(&mut response, CacheOutcome::Hit);
        Some(response)
    }

    /// Stores `response` if it is cacheable, and returns it either way.
    ///
    /// # Errors
    ///
    /// When the response body fails while it is being read.
    pub(crate) async fn store(
        &self,
        state: &StateBackend,
        response: Response,
    ) -> Result<Response, axum::Error> {
        let (parts, body) = response.into_parts();
        let cacheable = parts.status.is_success();
        if !cacheable {
            let mut response = Response::from_parts(parts, body);
            self.finish(&mut response, CacheOutcome::Miss);
            return Ok(response);
        }
        let collected = BodyBuffer::collect(body, MAX_ENTRY_BYTES).await?;
        let (body, whole) = match collected {
            Collected::Whole(bytes) => (Body::from(bytes.clone()), Some(bytes)),
            Collected::TooLarge(body) => (body, None),
        };
        if let Some(ref bytes) = whole
            && CachedResponse::size(&parts.headers, bytes) <= MAX_ENTRY_BYTES
            && let Some(entry) = CachedResponse::encode(parts.status, &parts.headers, bytes)
            && let Err(error) = state.cache_put(self.key.clone(), entry, self.ttl).await
        {
            tracing::warn!(%error, "cache unavailable; the response was not stored");
        }
        let mut response = Response::from_parts(parts, body);
        self.finish(&mut response, CacheOutcome::Miss);
        Ok(response)
    }

    /// Records the outcome on `response` and adds the warning when the
    /// client's `Cache-Control` was ignored.
    pub(crate) fn finish(&self, response: &mut Response, outcome: CacheOutcome) {
        response.extensions_mut().insert(outcome);
        if self.warn {
            response.headers_mut().insert(
                HeaderName::from_static("warning"),
                HeaderValue::from_static(UNAUTHORIZED_WARNING),
            );
        }
    }
}

/// A response body read up to a limit.
enum Collected {
    Whole(Bytes),
    /// The body exceeded the limit; what was read is put back in front of the
    /// rest.
    TooLarge(Body),
}

struct BodyBuffer;

impl BodyBuffer {
    async fn collect(mut body: Body, limit: usize) -> Result<Collected, axum::Error> {
        let mut chunks: VecDeque<Bytes> = VecDeque::new();
        let mut total = 0_usize;
        loop {
            let frame = std::future::poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
            let Some(frame) = frame else {
                let mut whole = Vec::with_capacity(total);
                for chunk in chunks {
                    whole.extend_from_slice(&chunk);
                }
                return Ok(Collected::Whole(Bytes::from(whole)));
            };
            let Ok(data) = frame?.into_data() else {
                continue;
            };
            total = total.saturating_add(data.len());
            chunks.push_back(data);
            if total > limit {
                return Ok(Collected::TooLarge(Body::new(Prefixed {
                    chunks,
                    rest: body,
                })));
            }
        }
    }
}

/// Chunks already read, then the rest of the body.
struct Prefixed {
    chunks: VecDeque<Bytes>,
    rest: Body,
}

impl HttpBody for Prefixed {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if let Some(chunk) = self.chunks.pop_front() {
            return Poll::Ready(Some(Ok(Frame::data(chunk))));
        }
        Pin::new(&mut self.rest).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty() && self.rest.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::Router;
    use axum::body::Body;
    use axum::extract::Request;
    use axum::response::IntoResponse as _;
    use proptest::prelude::*;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::*;
    use crate::authz::KeyStore;
    use crate::aws::{AwsClients, CredentialsMode, LambdaEndpoints};
    use crate::gateway::{ApiContext, AuthorizationMode, Enforcement, Unsupported};
    use crate::gateway_response::GatewayResponses;
    use crate::integration::StageVariables;
    use crate::model::{ApiKind, ApiModel, IntegrationOverrides, SettingsScope};
    use crate::observability::StageObserver;
    use crate::pipeline::context::QueryString;
    use crate::pipeline::context::tests::request;
    use crate::router::{BasePath, build};
    use crate::vpc_link::VpcLinks;

    fn settings(entries: &[(SettingsScope, MethodSettings)]) -> StageSettings {
        StageSettings {
            cache_cluster_enabled: true,
            method_settings: entries.iter().cloned().collect(),
            ..StageSettings::default()
        }
    }

    fn caching(ttl: Option<i32>) -> MethodSettings {
        MethodSettings {
            caching_enabled: Some(true),
            cache_ttl_seconds: ttl,
            ..MethodSettings::default()
        }
    }

    fn scope(path: &str, method: &str) -> SettingsScope {
        SettingsScope::Method {
            path: path.to_owned(),
            method: method.to_owned(),
        }
    }

    fn operation(method: &Method, path: &str, params: &[&str]) -> Operation {
        let doc = json!({"paths": {path: {method.as_str().to_ascii_lowercase(): {
            "x-amazon-apigateway-integration": {
                "type": "http_proxy", "httpMethod": method.as_str(), "uri": "http://localhost/",
                "cacheKeyParameters": params}}}}});
        let model = ApiModel::import(
            &doc,
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        )
        .unwrap();
        model.operations.into_iter().next().unwrap()
    }

    fn route_cache(stage: StageSettings, operation: &Operation) -> Option<RouteCache> {
        CacheSettings::new(
            "abc",
            Some("prod"),
            stage,
            CacheScope::On {
                partition: "stage".to_owned(),
            },
        )
        .for_route(operation)
    }

    #[test]
    fn the_stage_wide_setting_enables_get_methods_only() {
        let stage = settings(&[(SettingsScope::All, caching(None))]);
        assert!(route_cache(stage.clone(), &operation(&Method::GET, "/pets", &[])).is_some());
        assert!(route_cache(stage.clone(), &operation(&Method::POST, "/pets", &[])).is_none());
        assert!(route_cache(stage, &operation(&Method::PUT, "/pets", &[])).is_none());
    }

    #[test]
    fn methods_can_enable_or_disable_caching_themselves() {
        let stage = settings(&[
            (SettingsScope::All, caching(None)),
            (scope("/pets", "POST"), caching(None)),
            (
                scope("/pets", "GET"),
                MethodSettings {
                    caching_enabled: Some(false),
                    ..MethodSettings::default()
                },
            ),
        ]);
        assert!(route_cache(stage.clone(), &operation(&Method::POST, "/pets", &[])).is_some());
        assert!(route_cache(stage, &operation(&Method::GET, "/pets", &[])).is_none());
    }

    #[test]
    fn ttls_default_to_300_seconds_and_stop_at_an_hour() {
        let ttl = |setting: Option<i32>| {
            route_cache(
                settings(&[(SettingsScope::All, caching(setting))]),
                &operation(&Method::GET, "/pets", &[]),
            )
            .map(|c| c.ttl.as_secs())
        };
        assert_eq!(ttl(None), Some(300));
        assert_eq!(ttl(Some(60)), Some(60));
        assert_eq!(ttl(Some(99_999)), Some(3600));
        assert_eq!(ttl(Some(0)), None, "a TTL of 0 turns caching off");
    }

    #[test]
    fn a_stage_without_a_cache_cluster_caches_nothing() {
        let mut stage = settings(&[(SettingsScope::All, caching(None))]);
        stage.cache_cluster_enabled = true;
        let off = CacheSettings::new("abc", Some("prod"), stage, CacheScope::Off);
        assert!(
            off.for_route(&operation(&Method::GET, "/pets", &[]))
                .is_none()
        );
    }

    #[test]
    fn canary_releases_use_the_stage_cache_only_when_asked() {
        let canary = |use_stage_cache, deployment: &str| CanarySettings {
            percent_traffic: 10.0,
            deployment_id: Some(deployment.to_owned()),
            stage_variable_overrides: BTreeMap::default(),
            use_stage_cache,
        };
        let on = |partition: &str| CacheScope::On {
            partition: partition.to_owned(),
        };
        let of = |cluster, release, settings: Option<&CanarySettings>| {
            CacheScope::of(cluster, release, settings, Some("d1"))
        };
        assert_eq!(of(false, None, None), CacheScope::Off);
        assert_eq!(of(true, None, None), on("stage"));
        assert_eq!(
            of(true, Some(Release::Production), Some(&canary(true, "d2"))),
            on("stage")
        );
        assert_eq!(
            of(true, Some(Release::Canary), Some(&canary(false, "d2"))),
            CacheScope::Off
        );
        assert_eq!(
            of(true, Some(Release::Canary), Some(&canary(true, "d2"))),
            on("canary"),
            "different deployments are cached separately"
        );
        assert_eq!(
            of(true, Some(Release::Canary), Some(&canary(true, "d1"))),
            on("stage"),
            "the same deployment shares entries"
        );
    }

    fn context(query: &str, headers: &[(&str, &str)]) -> RequestContext {
        let mut ctx = request(ApiKind::Rest);
        ctx.method = Method::GET;
        ctx.query = QueryString::new(Some(query));
        for (name, value) in headers {
            ctx.headers.insert(
                HeaderName::try_from(*name).unwrap(),
                HeaderValue::try_from(*value).unwrap(),
            );
        }
        ctx
    }

    fn cache_for(params: &[&str], extra: MethodSettings) -> RouteCache {
        let method = MethodSettings {
            caching_enabled: Some(true),
            ..extra
        };
        route_cache(
            settings(&[(SettingsScope::All, method)]),
            &operation(&Method::GET, "/pets/{petId}", params),
        )
        .unwrap()
    }

    #[test]
    fn keys_use_only_the_cache_key_parameters() {
        let cache = cache_for(
            &[
                "method.request.querystring.page",
                "method.request.header.Accept",
            ],
            MethodSettings::default(),
        );
        let key = |query: &str, headers: &[(&str, &str)]| {
            cache
                .plan(&context(query, headers))
                .unwrap()
                .unwrap()
                .key
                .as_str()
                .to_owned()
        };
        let base = key("page=1&other=a", &[("accept", "json")]);
        assert_eq!(base, key("page=1&other=b", &[("accept", "json")]));
        assert_ne!(base, key("page=2&other=a", &[("accept", "json")]));
        assert_ne!(base, key("page=1", &[("accept", "xml")]));
        assert_ne!(base, key("page=1", &[]), "an absent value is its own entry");
        assert_eq!(key("page=1", &[]), key("page=1&x=1", &[]));
    }

    #[test]
    fn keys_with_no_parameters_share_one_entry_per_route_and_method() {
        let cache = cache_for(&[], MethodSettings::default());
        let key = |query: &str| {
            cache
                .plan(&context(query, &[]))
                .unwrap()
                .unwrap()
                .key
                .as_str()
                .to_owned()
        };
        assert_eq!(key("a=1"), key("b=2"));
    }

    #[test]
    fn values_cannot_forge_other_keys() {
        let cache = cache_for(
            &[
                "method.request.querystring.a",
                "method.request.querystring.b",
            ],
            MethodSettings::default(),
        );
        let key = |query: &str| {
            cache
                .plan(&context(query, &[]))
                .unwrap()
                .unwrap()
                .key
                .as_str()
                .to_owned()
        };
        assert_ne!(key("a=x%1Fy&b=z"), key("a=x&b=y%1Fz"));
    }

    #[test]
    fn integration_parameters_resolve_through_their_mapping() {
        let doc = json!({"paths": {"/p": {"get": {"x-amazon-apigateway-integration": {
            "type": "http_proxy", "httpMethod": "GET", "uri": "http://localhost/",
            "requestParameters": {
                "integration.request.header.X-Page": "method.request.querystring.page",
                "integration.request.header.X-Fixed": "'constant'",
                "integration.request.header.X-Other": "context.requestId"},
            "cacheKeyParameters": ["integration.request.header.X-Page",
                "integration.request.header.X-Fixed", "integration.request.header.X-Other",
                "integration.request.header.X-Unmapped", "garbage"]}}}}});
        let model = ApiModel::import(
            &doc,
            ApiKind::Rest,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        )
        .unwrap();
        let spec = model.operations[0].integration.as_ref().unwrap();
        let parsed: Vec<_> = spec
            .cache_key_parameters
            .iter()
            .filter_map(|n| KeyParameter::parse(n, spec))
            .collect();
        assert_eq!(
            parsed,
            [
                KeyParameter::Query("page".to_owned()),
                KeyParameter::Literal("constant".to_owned())
            ]
        );
    }

    #[test]
    fn cache_control_max_age_zero_is_recognized_among_directives() {
        let asks = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert(header::CACHE_CONTROL, HeaderValue::try_from(value).unwrap());
            CacheControl::asks_for_fresh(&headers)
        };
        assert!(asks("max-age=0"));
        assert!(asks("no-store, Max-Age=0"));
        assert!(!asks("max-age=60"));
        assert!(!asks("max-age=00x"));
        assert!(!asks("no-cache"));
        assert!(!CacheControl::asks_for_fresh(&HeaderMap::new()));
    }

    fn invalidation(
        require: Option<bool>,
        strategy: Option<&str>,
    ) -> Result<Option<CachePlan>, Failure> {
        let cache = cache_for(
            &[],
            MethodSettings {
                require_authorization_for_cache_control: require,
                unauthorized_cache_control_header_strategy: strategy.map(str::to_owned),
                ..MethodSettings::default()
            },
        );
        cache.plan(&context("", &[("cache-control", "max-age=0")]))
    }

    #[test]
    fn unauthorized_invalidation_follows_the_strategy() {
        let ignored = invalidation(Some(true), Some("SUCCEED_WITH_RESPONSE_HEADER"))
            .unwrap()
            .unwrap();
        assert!(ignored.read && ignored.warn);
        let silent = invalidation(None, Some("SUCCEED_WITHOUT_RESPONSE_HEADER"))
            .unwrap()
            .unwrap();
        assert!(silent.read && !silent.warn);
        let default = invalidation(None, None).unwrap().unwrap();
        assert!(default.read && default.warn, "the default is to warn");
        let failure = invalidation(Some(true), Some("FAIL_WITH_403")).unwrap_err();
        assert_eq!(failure.status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn without_required_authorization_any_client_refreshes_the_entry() {
        let plan = invalidation(Some(false), Some("FAIL_WITH_403"))
            .unwrap()
            .unwrap();
        assert!(!plan.read, "the stored response is bypassed");
        assert!(!plan.warn);
    }

    #[test]
    fn requests_without_cache_control_read_the_cache_silently() {
        let cache = cache_for(&[], MethodSettings::default());
        let plan = cache.plan(&context("", &[])).unwrap().unwrap();
        assert!(plan.read && !plan.warn);
    }

    proptest! {
        #[test]
        fn buffering_never_loses_or_reorders_bytes(
            chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..40), 0..12),
            limit in 1_usize..200,
        ) {
            let expected: Vec<u8> = chunks.concat();
            let runtime = tokio::runtime::Builder::new_current_thread().build().unwrap();
            let rebuilt = runtime.block_on(async {
                let stream = tokio_util::io::ReaderStream::new(std::io::Cursor::new(expected.clone()));
                let body = Body::from_stream(stream);
                match BodyBuffer::collect(body, limit).await.unwrap() {
                    Collected::Whole(bytes) => {
                        assert!(bytes.len() <= limit);
                        bytes
                    }
                    Collected::TooLarge(body) => {
                        assert!(expected.len() > limit);
                        axum::body::to_bytes(body, usize::MAX).await.unwrap()
                    }
                }
            });
            prop_assert_eq!(rebuilt.to_vec(), expected);
        }
    }

    #[test]
    fn stored_responses_round_trip_without_hop_by_hop_headers() {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.insert("connection", HeaderValue::from_static("keep-alive"));
        headers.append("x-multi", HeaderValue::from_static("a"));
        headers.append("x-multi", HeaderValue::from_static("b"));
        let body = Bytes::from_static(b"{\"a\":1}\xff");
        let entry = CachedResponse::encode(StatusCode::CREATED, &headers, &body).unwrap();
        let response = serde_json::from_slice::<CachedResponse>(&entry)
            .unwrap()
            .into_response()
            .unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert!(response.headers().get("connection").is_none());
        assert_eq!(response.headers().get_all("x-multi").iter().count(), 2);
        assert!(CachedResponse::size(&headers, &body) > body.len());
    }

    /// An upstream that counts calls and answers `n={calls}` for `/pets`, `500`
    /// for `/boom`, and a body of `size` bytes for `/big`.
    struct Upstream {
        addr: std::net::SocketAddr,
        calls: Arc<AtomicUsize>,
    }

    async fn upstream() -> Upstream {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let app = Router::new().fallback(move |uri: axum::http::Uri| {
            let n = counter.fetch_add(1, Ordering::SeqCst).saturating_add(1);
            async move {
                match uri.path() {
                    "/boom" => {
                        (StatusCode::INTERNAL_SERVER_ERROR, format!("n={n}")).into_response()
                    }
                    "/big" => (
                        [("x-big", "yes")],
                        vec![b'x'; MAX_ENTRY_BYTES.saturating_add(10)],
                    )
                        .into_response(),
                    _ => ([("x-upstream", "1")], format!("n={n}")).into_response(),
                }
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Upstream { addr, calls }
    }

    fn api(up: &Upstream, stage: StageSettings, scope: CacheScope) -> Router {
        let route = |method: &str, path: &str, params: &[&str]| {
            json!({method: {"x-amazon-apigateway-integration": {
                "type": "http_proxy", "httpMethod": method.to_ascii_uppercase(),
                "uri": format!("http://{}{path}", up.addr), "cacheKeyParameters": params}}})
        };
        let doc = json!({"paths": {
            "/pets": route("get", "/pets", &["method.request.querystring.page"]),
            "/boom": route("get", "/boom", &[]),
            "/big": route("get", "/big", &[]),
            "/items": {"post": {"x-amazon-apigateway-integration": {
                "type": "http_proxy", "httpMethod": "POST",
                "uri": format!("http://{}/items", up.addr)}}},
        }});
        let model =
            ApiModel::import(&doc, ApiKind::Rest, stage, &IntegrationOverrides::default()).unwrap();
        let ctx = Arc::new(ApiContext {
            kind: ApiKind::Rest,
            api_id: "abc".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: Arc::new(StageVariables::default()),
            enforcement: Enforcement {
                authorization: AuthorizationMode::Enforce,
                request_validation: Unsupported::Reject,
            },
            responses: GatewayResponses::default(),
            cors: None,
            state: StateBackend::in_memory(),
            replicas: std::num::NonZeroU32::MIN,
            vpc_links: VpcLinks::default(),
            observer: StageObserver::disabled(),
            release: None,
            cache: scope,
            payload: Arc::default(),
            http: reqwest::Client::new(),
            aws: Arc::new(AwsClients::new(
                aws_config::SdkConfig::builder()
                    .behavior_version(aws_config::BehaviorVersion::latest())
                    .build(),
                CredentialsMode::Assume,
                LambdaEndpoints::default(),
                reqwest::Client::new(),
            )),
            keys: Arc::new(KeyStore::new(reqwest::Client::new(), [])),
            usage: None,
        });
        build(&model, &ctx, &BasePath::default()).0
    }

    fn on() -> CacheScope {
        CacheScope::On {
            partition: "stage".to_owned(),
        }
    }

    struct Reply {
        status: StatusCode,
        body: String,
        outcome: Option<CacheOutcome>,
        headers: HeaderMap,
    }

    async fn call(router: &Router, method: Method, uri: &str, headers: &[(&str, &str)]) -> Reply {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (parts, body) = response.into_parts();
        let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
        Reply {
            status: parts.status,
            body: String::from_utf8_lossy(&bytes[..bytes.len().min(16)]).into_owned(),
            outcome: parts.extensions.get::<CacheOutcome>().copied(),
            headers: parts.headers,
        }
    }

    fn get_cached() -> StageSettings {
        settings(&[(SettingsScope::All, caching(None))])
    }

    #[tokio::test]
    async fn the_second_identical_get_is_served_from_the_cache() {
        let up = upstream().await;
        let router = api(&up, get_cached(), on());
        let first = call(&router, Method::GET, "/pets?page=1", &[]).await;
        let second = call(&router, Method::GET, "/pets?page=1", &[]).await;
        assert_eq!(
            (first.body.as_str(), first.outcome),
            ("n=1", Some(CacheOutcome::Miss))
        );
        assert_eq!(
            (second.body.as_str(), second.outcome),
            ("n=1", Some(CacheOutcome::Hit))
        );
        assert_eq!(second.headers["x-upstream"], "1");
        assert_eq!(up.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn key_parameters_separate_entries_and_other_parameters_do_not() {
        let up = upstream().await;
        let router = api(&up, get_cached(), on());
        call(&router, Method::GET, "/pets?page=1&x=a", &[]).await;
        let other_page = call(&router, Method::GET, "/pets?page=2", &[]).await;
        let same_page = call(&router, Method::GET, "/pets?page=1&x=b", &[]).await;
        assert_eq!(other_page.outcome, Some(CacheOutcome::Miss));
        assert_eq!(same_page.outcome, Some(CacheOutcome::Hit));
        assert_eq!(same_page.body, "n=1");
        assert_eq!(up.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn only_get_is_cached_unless_the_method_enables_caching() {
        let up = upstream().await;
        let router = api(&up, get_cached(), on());
        for _ in 0..2 {
            let reply = call(&router, Method::POST, "/items", &[]).await;
            assert_eq!(reply.outcome, None);
        }
        assert_eq!(up.calls.load(Ordering::SeqCst), 2);

        let up = upstream().await;
        let stage = settings(&[
            (SettingsScope::All, caching(None)),
            (scope("/items", "POST"), caching(None)),
        ]);
        let router = api(&up, stage, on());
        call(&router, Method::POST, "/items", &[]).await;
        let second = call(&router, Method::POST, "/items", &[]).await;
        assert_eq!(second.outcome, Some(CacheOutcome::Hit));
        assert_eq!(up.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failures_and_oversized_responses_are_not_cached() {
        let up = upstream().await;
        let router = api(&up, get_cached(), on());
        for _ in 0..2 {
            let reply = call(&router, Method::GET, "/boom", &[]).await;
            assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
            assert_eq!(reply.outcome, Some(CacheOutcome::Miss));
        }
        assert_eq!(up.calls.load(Ordering::SeqCst), 2);

        let big = call(&router, Method::GET, "/big", &[]).await;
        assert_eq!(big.status, StatusCode::OK);
        assert_eq!(big.headers["x-big"], "yes");
        let again = call(&router, Method::GET, "/big", &[]).await;
        assert_eq!(
            again.outcome,
            Some(CacheOutcome::Miss),
            "too large to cache"
        );
        assert_eq!(up.calls.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn oversized_bodies_reach_the_client_whole() {
        let up = upstream().await;
        let router = api(&up, get_cached(), on());
        let response = router
            .clone()
            .oneshot(Request::builder().uri("/big").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(bytes.len(), MAX_ENTRY_BYTES + 10);
        assert!(bytes.iter().all(|b| *b == b'x'));
    }

    #[tokio::test]
    async fn entries_expire_after_the_ttl() {
        let up = upstream().await;
        let stage = settings(&[(SettingsScope::All, caching(Some(1)))]);
        let router = api(&up, stage, on());
        call(&router, Method::GET, "/pets", &[]).await;
        assert_eq!(
            call(&router, Method::GET, "/pets", &[]).await.outcome,
            Some(CacheOutcome::Hit)
        );
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let after = call(&router, Method::GET, "/pets", &[]).await;
        assert_eq!(
            (after.outcome, after.body.as_str()),
            (Some(CacheOutcome::Miss), "n=2")
        );
    }

    #[tokio::test]
    async fn without_a_cache_cluster_nothing_is_cached() {
        let up = upstream().await;
        let router = api(&up, get_cached(), CacheScope::Off);
        for _ in 0..2 {
            assert_eq!(call(&router, Method::GET, "/pets", &[]).await.outcome, None);
        }
        assert_eq!(up.calls.load(Ordering::SeqCst), 2);
    }

    fn with_strategy(require: Option<bool>, strategy: Option<&str>) -> StageSettings {
        settings(&[(
            SettingsScope::All,
            MethodSettings {
                require_authorization_for_cache_control: require,
                unauthorized_cache_control_header_strategy: strategy.map(str::to_owned),
                ..caching(None)
            },
        )])
    }

    #[tokio::test]
    async fn unauthorized_cache_control_is_ignored_with_a_warning_by_default() {
        let up = upstream().await;
        let router = api(&up, with_strategy(None, None), on());
        call(&router, Method::GET, "/pets", &[]).await;
        let reply = call(
            &router,
            Method::GET,
            "/pets",
            &[("cache-control", "max-age=0")],
        )
        .await;
        assert_eq!(
            (reply.outcome, reply.body.as_str()),
            (Some(CacheOutcome::Hit), "n=1")
        );
        assert_eq!(
            reply.headers["warning"],
            "199 Cache-control headers were ignored because the caller was unauthorized."
        );
        assert_eq!(up.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_silent_strategy_ignores_the_header_without_a_warning() {
        let up = upstream().await;
        let router = api(
            &up,
            with_strategy(Some(true), Some("SUCCEED_WITHOUT_RESPONSE_HEADER")),
            on(),
        );
        call(&router, Method::GET, "/pets", &[]).await;
        let reply = call(
            &router,
            Method::GET,
            "/pets",
            &[("cache-control", "max-age=0")],
        )
        .await;
        assert_eq!(reply.outcome, Some(CacheOutcome::Hit));
        assert!(reply.headers.get("warning").is_none());
    }

    #[tokio::test]
    async fn the_fail_strategy_answers_403_without_calling_the_integration() {
        let up = upstream().await;
        let router = api(&up, with_strategy(Some(true), Some("FAIL_WITH_403")), on());
        let reply = call(
            &router,
            Method::GET,
            "/pets",
            &[("cache-control", "max-age=0")],
        )
        .await;
        assert_eq!(reply.status, StatusCode::FORBIDDEN);
        assert_eq!(up.calls.load(Ordering::SeqCst), 0);
        let plain = call(&router, Method::GET, "/pets", &[]).await;
        assert_eq!(
            plain.status,
            StatusCode::OK,
            "requests that do not ask are unaffected"
        );
    }

    #[tokio::test]
    async fn when_authorization_is_not_required_clients_refresh_the_entry() {
        let up = upstream().await;
        let router = api(&up, with_strategy(Some(false), None), on());
        call(&router, Method::GET, "/pets", &[]).await;
        let refreshed = call(
            &router,
            Method::GET,
            "/pets",
            &[("cache-control", "max-age=0")],
        )
        .await;
        assert_eq!(
            (refreshed.outcome, refreshed.body.as_str()),
            (Some(CacheOutcome::Miss), "n=2")
        );
        assert!(refreshed.headers.get("warning").is_none());
        let after = call(&router, Method::GET, "/pets", &[]).await;
        assert_eq!(
            (after.outcome, after.body.as_str()),
            (Some(CacheOutcome::Hit), "n=2")
        );
    }
}
