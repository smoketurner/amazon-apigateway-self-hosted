//! Serving a custom domain: reading its mappings and routing rules from API
//! Gateway, running one [`ApiRuntime`] per API stage they name, and keeping the
//! set current as the domain changes.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use axum::http::HeaderMap;
use serde::Serialize;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::rules::Routing;
use super::{ApiMapping, ApiMappings, DomainName, MappingKey, RoutingMode, RoutingRule, StageRef};
use crate::app::{ApiRuntime, Builder};
use crate::model::ApiKind;
use crate::router::{LoadSummary, Loaded};
use crate::source::Source;

#[derive(Debug, thiserror::Error)]
pub(crate) enum DomainError {
    #[error("API Gateway request for domain {domain} failed: {reason}")]
    Aws { domain: DomainName, reason: String },
    #[error("could not tell whether {api_id} is a REST or an HTTP API: {reason}")]
    UnknownApi { api_id: String, reason: String },
}

impl DomainError {
    fn aws(domain: &DomainName, err: impl std::error::Error) -> Self {
        Self::Aws {
            domain: domain.clone(),
            reason: aws_sdk_apigatewayv2::error::DisplayErrorContext(err).to_string(),
        }
    }
}

/// What a request to the domain resolved to.
pub(crate) enum Resolution {
    /// The API stage serving it and the path the API sees.
    Matched(Arc<Loaded>, String),
    /// A mapping or rule names this stage, but it has not loaded yet.
    Unavailable(StageRef),
    /// No mapping or rule matches.
    NoMatch,
}

/// The routing configuration of a domain and the APIs it serves.
pub(crate) struct DomainState {
    routing: Routing,
    apis: BTreeMap<StageRef, watch::Receiver<Arc<Loaded>>>,
}

impl DomainState {
    pub(crate) fn resolve(&self, path: &str, headers: &HeaderMap) -> Resolution {
        let Some(routed) = self.routing.select(path, headers) else {
            return Resolution::NoMatch;
        };
        match self.apis.get(&routed.target) {
            Some(api) => Resolution::Matched(Arc::clone(&api.borrow()), routed.path),
            None => Resolution::Unavailable(routed.target),
        }
    }
}

/// A domain as reported on `/routes`.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct DomainSummary {
    domain: String,
    routing_mode: &'static str,
    mappings: Vec<MappingSummary>,
    rules: usize,
    apis: Vec<ApiSummary>,
}

#[derive(Debug, Clone, Serialize)]
struct MappingSummary {
    key: String,
    api_id: String,
    stage: String,
}

#[derive(Debug, Clone, Serialize)]
struct ApiSummary {
    api_id: String,
    stage: String,
    #[serde(flatten)]
    summary: LoadSummary,
}

impl RoutingMode {
    fn as_str(self) -> &'static str {
        match self {
            Self::ApiMappingOnly => "api_mapping_only",
            Self::RoutingRuleOnly => "routing_rule_only",
            Self::RoutingRuleThenApiMapping => "routing_rule_then_api_mapping",
        }
    }
}

impl DomainState {
    fn summary(&self, domain: &DomainName) -> DomainSummary {
        DomainSummary {
            domain: domain.to_string(),
            routing_mode: self.routing.mode.as_str(),
            mappings: self
                .routing
                .mappings
                .iter()
                .map(|m| MappingSummary {
                    key: m.key.as_str().to_owned(),
                    api_id: m.target.api_id.clone(),
                    stage: m.target.stage.clone(),
                })
                .collect(),
            rules: self.routing.rules().len(),
            apis: self
                .apis
                .iter()
                .map(|(stage, api)| ApiSummary {
                    api_id: stage.api_id.clone(),
                    stage: stage.stage.clone(),
                    summary: api.borrow().summary.clone(),
                })
                .collect(),
        }
    }
}

/// The domains this process serves, looked up by the `Host` of a request.
#[derive(Clone, Default)]
pub(crate) struct DomainRegistry {
    domains: Vec<(DomainName, watch::Receiver<Arc<DomainState>>)>,
}

impl DomainRegistry {
    pub(crate) fn new(domains: Vec<(DomainName, watch::Receiver<Arc<DomainState>>)>) -> Self {
        Self { domains }
    }

    /// The domain a request for `host` is for. An exact name wins over a
    /// wildcard that also matches.
    pub(crate) fn find(&self, host: &str) -> Option<Arc<DomainState>> {
        let exact = self
            .domains
            .iter()
            .find(|(name, _)| !name.as_str().starts_with("*.") && name.matches(host));
        let found = exact.or_else(|| self.domains.iter().find(|(name, _)| name.matches(host)));
        found.map(|(_, state)| Arc::clone(&state.borrow()))
    }

    pub(crate) fn summaries(&self) -> Vec<DomainSummary> {
        self.domains
            .iter()
            .map(|(name, state)| state.borrow().summary(name))
            .collect()
    }
}

/// Keeps one domain's routing and API runtimes current.
pub(crate) struct DomainSupervisor {
    domain: DomainName,
    v2: aws_sdk_apigatewayv2::Client,
    rest: aws_sdk_apigateway::Client,
    builder: Builder,
    sdk_config: aws_config::SdkConfig,
    interval: Option<Duration>,
    runtimes: BTreeMap<StageRef, ApiRuntime>,
    kinds: BTreeMap<String, ApiKind>,
    shutdown: CancellationToken,
    published: Option<(Routing, BTreeSet<StageRef>)>,
}

impl DomainSupervisor {
    pub(crate) fn new(
        domain: DomainName,
        builder: Builder,
        sdk_config: &aws_config::SdkConfig,
        interval: Option<Duration>,
        shutdown: &CancellationToken,
    ) -> Self {
        Self {
            domain,
            v2: aws_sdk_apigatewayv2::Client::new(sdk_config),
            rest: aws_sdk_apigateway::Client::new(sdk_config),
            builder,
            sdk_config: sdk_config.clone(),
            interval,
            runtimes: BTreeMap::new(),
            kinds: BTreeMap::new(),
            shutdown: shutdown.clone(),
            published: None,
        }
    }

    /// Reads the domain, loads every API it routes to, and starts refreshing.
    /// Returns the state to serve and the task that keeps it current.
    ///
    /// # Errors
    ///
    /// When the domain's mappings cannot be read.
    pub(crate) async fn start(
        mut self,
    ) -> Result<(watch::Receiver<Arc<DomainState>>, JoinHandle<()>), DomainError> {
        let routing = self.fetch_routing().await?;
        let state = self.reconcile(routing).await;
        let (publish, state) = watch::channel(Arc::new(state));
        let task = tokio::spawn(self.run(publish));
        Ok((state, task))
    }

    async fn run(mut self, publish: watch::Sender<Arc<DomainState>>) {
        let Some(interval) = self.interval else {
            self.shutdown.cancelled().await;
            self.stop_all().await;
            return;
        };
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => break,
                () = tokio::time::sleep(interval) => {}
            }
            let routing = match self.fetch_routing().await {
                Ok(routing) => routing,
                Err(err) => {
                    tracing::warn!(%err, domain = %self.domain, "domain refresh failed; keeping the current routing");
                    continue;
                }
            };
            let before = self.published.clone();
            let state = self.reconcile(routing).await;
            if self.published != before {
                publish.send_replace(Arc::new(state));
            }
        }
        self.stop_all().await;
    }

    async fn stop_all(&mut self) {
        for (_, runtime) in std::mem::take(&mut self.runtimes) {
            runtime.stop().await;
        }
    }

    async fn fetch_routing(&self) -> Result<Routing, DomainError> {
        let domain = self
            .v2
            .get_domain_name()
            .domain_name(self.domain.as_str())
            .send()
            .await
            .map_err(|err| DomainError::aws(&self.domain, err))?;
        let mode = domain
            .routing_mode()
            .map(RoutingMode::from)
            .unwrap_or_default();
        let mappings = self.fetch_mappings().await?;
        let rules = if mode == RoutingMode::ApiMappingOnly {
            Vec::new()
        } else {
            self.fetch_rules().await?
        };
        Ok(Routing::new(mode, rules, mappings))
    }

    async fn fetch_mappings(&self) -> Result<ApiMappings, DomainError> {
        let mut mappings = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .v2
                .get_api_mappings()
                .domain_name(self.domain.as_str())
                .set_next_token(token.take())
                .send()
                .await
                .map_err(|err| DomainError::aws(&self.domain, err))?;
            for mapping in page.items() {
                let (Some(api_id), Some(stage)) = (mapping.api_id(), mapping.stage()) else {
                    continue;
                };
                mappings.push(ApiMapping {
                    key: MappingKey::from(mapping.api_mapping_key().unwrap_or_default()),
                    target: StageRef {
                        api_id: api_id.to_owned(),
                        stage: stage.to_owned(),
                    },
                });
            }
            token = page.next_token().map(str::to_owned);
            if token.is_none() {
                return Ok(ApiMappings::new(mappings));
            }
        }
    }

    async fn fetch_rules(&self) -> Result<Vec<RoutingRule>, DomainError> {
        let mut rules = Vec::new();
        let mut token: Option<String> = None;
        loop {
            let page = self
                .v2
                .list_routing_rules()
                .domain_name(self.domain.as_str())
                .set_next_token(token.take())
                .send()
                .await
                .map_err(|err| DomainError::aws(&self.domain, err))?;
            for rule in page.routing_rules() {
                match RoutingRule::try_from(rule) {
                    Ok(rule) => rules.push(rule),
                    Err(err) => {
                        tracing::warn!(%err, domain = %self.domain, "ignoring a routing rule");
                    }
                }
            }
            token = page.next_token().map(str::to_owned);
            if token.is_none() {
                return Ok(rules);
            }
        }
    }

    /// Makes the running API stages the ones `routing` names: starts missing
    /// ones (a stage that fails to load is retried on the next refresh) and
    /// stops the ones no longer named.
    async fn reconcile(&mut self, routing: Routing) -> DomainState {
        let wanted: BTreeSet<StageRef> = routing.targets();
        let stale: Vec<StageRef> = self
            .runtimes
            .keys()
            .filter(|stage| !wanted.contains(*stage))
            .cloned()
            .collect();
        for stage in stale {
            if let Some(runtime) = self.runtimes.remove(&stage) {
                tracing::info!(domain = %self.domain, %stage, "no longer mapped; stopping");
                runtime.stop().await;
            }
        }
        for stage in &wanted {
            if self.runtimes.contains_key(stage) {
                continue;
            }
            match self.start_api(stage).await {
                Ok(runtime) => {
                    self.runtimes.insert(stage.clone(), runtime);
                }
                Err(err) => {
                    tracing::error!(domain = %self.domain, %stage, err = format!("{err:#}"), "failed to load a mapped API; it is not served until the next refresh");
                }
            }
        }
        let running: BTreeSet<StageRef> = self.runtimes.keys().cloned().collect();
        self.published = Some((routing.clone(), running));
        DomainState {
            routing,
            apis: self
                .runtimes
                .iter()
                .map(|(stage, runtime)| (stage.clone(), runtime.loaded()))
                .collect(),
        }
    }

    async fn start_api(&mut self, stage: &StageRef) -> anyhow::Result<ApiRuntime> {
        let kind = self.kind_of(&stage.api_id).await?;
        let source = match kind {
            ApiKind::Rest => Source::RestApi {
                api_id: stage.api_id.clone(),
                stage: stage.stage.clone(),
                canary_stage: None,
            },
            ApiKind::Http => Source::HttpApi {
                api_id: stage.api_id.clone(),
                stage: stage.stage.clone(),
            },
        };
        ApiRuntime::start(
            source,
            self.builder.clone(),
            None,
            self.interval,
            &self.sdk_config,
            &self.shutdown,
        )
        .await
    }

    /// API mappings name an API ID without saying which API type it is.
    async fn kind_of(&mut self, api_id: &str) -> Result<ApiKind, DomainError> {
        if let Some(kind) = self.kinds.get(api_id) {
            return Ok(*kind);
        }
        let kind = match self.rest.get_rest_api().rest_api_id(api_id).send().await {
            Ok(_) => ApiKind::Rest,
            Err(err)
                if err
                    .as_service_error()
                    .is_some_and(aws_sdk_apigateway::operation::get_rest_api::GetRestApiError::is_not_found_exception) =>
            {
                ApiKind::Http
            }
            Err(err) => {
                return Err(DomainError::UnknownApi {
                    api_id: api_id.to_owned(),
                    reason: aws_sdk_apigateway::error::DisplayErrorContext(err).to_string(),
                });
            }
        };
        self.kinds.insert(api_id.to_owned(), kind);
        Ok(kind)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they built")]
#[expect(clippy::panic, reason = "tests fail loudly when polling times out")]
mod tests {
    use axum::body::Body;
    use axum::http::Request;
    use serde_json::json;
    use tower::ServiceExt as _;

    use super::*;
    use crate::observability::testing::{MockAws, Reply};
    use crate::router::domain_dispatcher;

    const DOMAIN: &str = "api.example.com";

    /// An upstream that answers with the path and a label, so a test can tell
    /// which API served a request and what path it saw.
    async fn upstream(label: &'static str) -> std::net::SocketAddr {
        let app = axum::Router::new().fallback(move |uri: axum::http::Uri| async move {
            format!(
                "{label}:{}",
                uri.path_and_query().map_or("", |p| p.as_str())
            )
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    fn proxy_export(addr: std::net::SocketAddr) -> String {
        json!({"paths": {"/{proxy+}": {"x-amazon-apigateway-any-method": {
            "x-amazon-apigateway-integration": {
                "type": "http_proxy", "httpMethod": "ANY",
                "uri": format!("http://{addr}/{{proxy}}")}}}}})
        .to_string()
    }

    fn rest(aws: &MockAws, id: &str, addr: std::net::SocketAddr) {
        aws.reply(
            &format!("/restapis/{id}"),
            Reply::json(&format!(r#"{{"id":"{id}"}}"#)),
        );
        aws.reply(
            &format!("/restapis/{id}/stages/prod"),
            Reply::json(r#"{"stageName":"prod","deploymentId":"d1","lastUpdatedDate":1700000000}"#),
        );
        aws.reply(
            &format!("/restapis/{id}/stages/prod/exports/oas30"),
            Reply::json(&proxy_export(addr)),
        );
    }

    fn http(aws: &MockAws, id: &str, addr: std::net::SocketAddr) {
        aws.reply(
            &format!("/restapis/{id}"),
            Reply::error("NotFoundException"),
        );
        aws.reply(
            &format!("/v2/apis/{id}/stages/prod"),
            Reply::json(r#"{"stageName":"prod","deploymentId":"d1"}"#),
        );
        aws.reply(
            &format!("/v2/apis/{id}/exports/OAS30"),
            Reply::json(
                &json!({"paths": {"/{proxy+}": {"x-amazon-apigateway-any-method": {
                "x-amazon-apigateway-integration": {
                    "type": "http_proxy", "httpMethod": "ANY", "payloadFormatVersion": "1.0",
                    "uri": format!("http://{addr}/{{proxy}}")}}}}})
                .to_string(),
            ),
        );
    }

    fn domain(aws: &MockAws, mode: &str, mappings: &str, rules: &str) {
        aws.reply(
            &format!("/v2/domainnames/{DOMAIN}"),
            Reply::json(&format!(
                r#"{{"domainName":"{DOMAIN}","routingMode":"{mode}"}}"#
            )),
        );
        aws.reply(
            &format!("/v2/domainnames/{DOMAIN}/apimappings"),
            Reply::json(&format!(r#"{{"items":{mappings}}}"#)),
        );
        aws.reply(
            &format!("/v2/domainnames/{DOMAIN}/routingrules"),
            Reply::json(&format!(r#"{{"routingRules":{rules}}}"#)),
        );
    }

    async fn serve(
        aws: &MockAws,
        interval: Option<Duration>,
    ) -> (DomainRegistry, CancellationToken, JoinHandle<()>) {
        let shutdown = CancellationToken::new();
        let supervisor = DomainSupervisor::new(
            DOMAIN.parse().unwrap(),
            Builder::for_tests(aws.sdk_config()),
            &aws.sdk_config(),
            interval,
            &shutdown,
        );
        let (state, task) = supervisor.start().await.unwrap();
        (
            DomainRegistry::new(vec![(DOMAIN.parse().unwrap(), state)]),
            shutdown,
            task,
        )
    }

    async fn get(
        registry: &DomainRegistry,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> (u16, String) {
        let mut request = Request::builder().uri(path).header("host", host);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = domain_dispatcher(registry.clone())
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status().as_u16();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn one_domain_serves_rest_and_http_apis_by_mapping_with_the_prefix_stripped() {
        let aws = MockAws::start().await;
        let (rest_up, http_up) = (upstream("rest").await, upstream("http").await);
        rest(&aws, "r1", rest_up);
        http(&aws, "h1", http_up);
        domain(
            &aws,
            "API_MAPPING_ONLY",
            r#"[{"apiId":"r1","apiMappingKey":"(none)","stage":"prod"},
                {"apiId":"h1","apiMappingKey":"v2/items","stage":"prod"}]"#,
            "[]",
        );
        let (registry, shutdown, _task) = serve(&aws, None).await;
        assert_eq!(
            get(&registry, DOMAIN, "/pets?x=1", &[]).await,
            (200, "rest:/pets?x=1".to_owned())
        );
        assert_eq!(
            get(&registry, DOMAIN, "/v2/items/42", &[]).await,
            (200, "http:/42".to_owned()),
            "the multi-level mapping is stripped"
        );
        assert_eq!(
            get(&registry, "API.example.com:8443", "/pets", &[]).await.0,
            200,
            "the host is case insensitive and its port ignored"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn reserved_health_paths_and_unrouted_requests_answer_like_api_gateway() {
        let aws = MockAws::start().await;
        let up = upstream("rest").await;
        rest(&aws, "r1", up);
        domain(
            &aws,
            "API_MAPPING_ONLY",
            r#"[{"apiId":"r1","apiMappingKey":"orders","stage":"prod"}]"#,
            "[]",
        );
        let (registry, shutdown, _task) = serve(&aws, None).await;
        assert_eq!(
            get(&registry, DOMAIN, "/ping", &[]).await,
            (200, "healthy".to_owned())
        );
        assert_eq!(get(&registry, DOMAIN, "/sping", &[]).await.0, 200);
        let (status, body) = get(&registry, DOMAIN, "/customers", &[]).await;
        assert_eq!((status, body.as_str()), (403, r#"{"message":"Forbidden"}"#));
        assert_eq!(
            get(&registry, "other.example.com", "/orders", &[]).await.0,
            403
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn routing_rules_choose_the_api_in_priority_order() {
        let aws = MockAws::start().await;
        let (rest_up, http_up) = (upstream("rest").await, upstream("http").await);
        rest(&aws, "r1", rest_up);
        http(&aws, "h1", http_up);
        domain(
            &aws,
            "ROUTING_RULE_THEN_API_MAPPING",
            r#"[{"apiId":"r1","apiMappingKey":"(none)","stage":"prod"}]"#,
            r#"[{"priority":10,"routingRuleId":"a",
                 "conditions":[{"matchHeaders":{"anyOf":[{"header":"X-Beta","valueGlob":"y*"}]}},
                               {"matchBasePaths":{"anyOf":["beta"]}}],
                 "actions":[{"invokeApi":{"apiId":"h1","stage":"prod","stripBasePath":true}}]}]"#,
        );
        let (registry, shutdown, _task) = serve(&aws, None).await;
        assert_eq!(
            get(&registry, DOMAIN, "/beta/x", &[("x-beta", "yes")]).await,
            (200, "http:/x".to_owned())
        );
        assert_eq!(
            get(&registry, DOMAIN, "/beta/x", &[("x-beta", "no")]).await,
            (200, "rest:/beta/x".to_owned()),
            "an unmatched rule falls through to the mappings"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn rule_only_domains_ignore_api_mappings() {
        let aws = MockAws::start().await;
        let up = upstream("rest").await;
        rest(&aws, "r1", up);
        domain(
            &aws,
            "ROUTING_RULE_ONLY",
            r#"[{"apiId":"r1","apiMappingKey":"(none)","stage":"prod"}]"#,
            "[]",
        );
        let (registry, shutdown, _task) = serve(&aws, None).await;
        assert_eq!(get(&registry, DOMAIN, "/pets", &[]).await.0, 403);
        assert!(
            aws.calls()
                .iter()
                .all(|c| !c.target.starts_with("/restapis/r1")),
            "an API only reachable through ignored mappings is never loaded"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn an_api_that_fails_to_load_is_unavailable_until_it_loads() {
        let aws = MockAws::start().await;
        let up = upstream("rest").await;
        rest(&aws, "r1", up);
        aws.reply(
            "/restapis/r1/stages/prod",
            Reply::error("NotFoundException"),
        );
        domain(
            &aws,
            "API_MAPPING_ONLY",
            r#"[{"apiId":"r1","apiMappingKey":"(none)","stage":"prod"}]"#,
            "[]",
        );
        let (registry, shutdown, _task) = serve(&aws, Some(Duration::from_millis(50))).await;
        assert_eq!(get(&registry, DOMAIN, "/pets", &[]).await.0, 503);
        rest(&aws, "r1", up);
        for _ in 0..100 {
            if get(&registry, DOMAIN, "/pets", &[]).await.0 == 200 {
                shutdown.cancel();
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        shutdown.cancel();
        panic!("the API never loaded");
    }

    #[tokio::test]
    async fn mapping_changes_start_new_apis_and_stop_removed_ones() {
        let aws = MockAws::start().await;
        let (first_up, second_up) = (upstream("first").await, upstream("second").await);
        rest(&aws, "r1", first_up);
        rest(&aws, "r2", second_up);
        domain(
            &aws,
            "API_MAPPING_ONLY",
            r#"[{"apiId":"r1","apiMappingKey":"(none)","stage":"prod"}]"#,
            "[]",
        );
        let (registry, shutdown, _task) = serve(&aws, Some(Duration::from_millis(50))).await;
        assert_eq!(get(&registry, DOMAIN, "/p", &[]).await.1, "first:/p");
        domain(
            &aws,
            "API_MAPPING_ONLY",
            r#"[{"apiId":"r2","apiMappingKey":"(none)","stage":"prod"}]"#,
            "[]",
        );
        for _ in 0..100 {
            if get(&registry, DOMAIN, "/p", &[]).await.1 == "second:/p" {
                let summaries = serde_json::to_value(registry.summaries()).unwrap();
                let apis = summaries[0]["apis"].as_array().unwrap();
                assert_eq!(apis.len(), 1, "the unmapped API is no longer served");
                assert_eq!(apis[0]["api_id"], "r2");
                shutdown.cancel();
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        shutdown.cancel();
        panic!("the new mapping was never picked up");
    }

    #[tokio::test]
    async fn the_domain_summary_lists_mappings_and_apis() {
        let aws = MockAws::start().await;
        let up = upstream("rest").await;
        rest(&aws, "r1", up);
        domain(
            &aws,
            "API_MAPPING_ONLY",
            r#"[{"apiId":"r1","apiMappingKey":"v1","stage":"prod"}]"#,
            "[]",
        );
        let (registry, shutdown, _task) = serve(&aws, None).await;
        let summary = serde_json::to_value(registry.summaries()).unwrap();
        assert_eq!(summary[0]["domain"], DOMAIN);
        assert_eq!(summary[0]["routing_mode"], "api_mapping_only");
        assert_eq!(summary[0]["mappings"][0]["key"], "v1");
        assert_eq!(summary[0]["apis"][0]["api_id"], "r1");
        assert_eq!(
            summary[0]["apis"][0]["routes"][0]["route_key"],
            "ANY /{proxy+}"
        );
        shutdown.cancel();
    }

    #[tokio::test]
    async fn reading_a_missing_domain_fails_startup() {
        let aws = MockAws::start().await;
        aws.reply(
            &format!("/v2/domainnames/{DOMAIN}"),
            Reply::error("NotFoundException"),
        );
        let shutdown = CancellationToken::new();
        let supervisor = DomainSupervisor::new(
            DOMAIN.parse().unwrap(),
            Builder::for_tests(aws.sdk_config()),
            &aws.sdk_config(),
            None,
            &shutdown,
        );
        assert!(supervisor.start().await.is_err());
    }

    #[test]
    fn registries_prefer_exact_names_over_wildcards() {
        let state = |mappings: Vec<ApiMapping>| {
            watch::channel(Arc::new(DomainState {
                routing: Routing::new(
                    RoutingMode::ApiMappingOnly,
                    Vec::new(),
                    ApiMappings::new(mappings),
                ),
                apis: BTreeMap::new(),
            }))
        };
        let exact_mapping = ApiMapping {
            key: MappingKey::from("exact"),
            target: StageRef {
                api_id: "a".to_owned(),
                stage: "prod".to_owned(),
            },
        };
        let (_wild_tx, wild) = state(Vec::new());
        let (_exact_tx, exact) = state(vec![exact_mapping]);
        let registry = DomainRegistry::new(vec![
            ("*.example.com".parse().unwrap(), wild),
            ("api.example.com".parse().unwrap(), exact),
        ]);
        let mappings = |host: &str| {
            registry
                .find(host)
                .map(|s| s.routing.mappings.iter().count())
        };
        assert_eq!(mappings("api.example.com"), Some(1));
        assert_eq!(mappings("other.example.com"), Some(0));
        assert_eq!(mappings("example.org"), None);
    }
}
