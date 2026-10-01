//! Startup, configuration refresh, and shutdown.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::aws::AwsClients;
use crate::config::Config;
use crate::cors::Cors;
use crate::gateway::{ApiContext, Enforcement};
use crate::gateway_response::GatewayResponses;
use crate::integration::StageVariables;
use crate::listener::{self, ConnLimits, Edge, Tls};
use crate::model::{ApiModel, DeploymentStamp, IntegrationOverrides};
use crate::observability::{Observability, StageObserver};
use crate::router::{self, BasePath, LoadSummary, Loaded};
use crate::source::{Fetch, Fetcher, Snapshot, SourceError};
use crate::state::{InMemory, InMemoryLimits, StateBackend};

const CERT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Everything a definition is built from besides the snapshot itself.
struct Builder {
    base_path: BasePath,
    enforcement: Enforcement,
    stage_variable_overrides: BTreeMap<String, String>,
    overrides_path: Option<PathBuf>,
    http: reqwest::Client,
    aws: Arc<AwsClients>,
    state: Arc<StateBackend>,
    replicas: NonZeroU32,
    observability: Arc<Observability>,
}

/// The inputs a router was built from; a refresh rebuilds only when they change.
#[derive(Clone, PartialEq)]
struct Inputs {
    snapshot: Snapshot,
    overrides: IntegrationOverrides,
}

impl Builder {
    async fn overrides(&self) -> anyhow::Result<IntegrationOverrides> {
        let Some(ref path) = self.overrides_path else {
            return Ok(IntegrationOverrides::default());
        };
        let bytes = tokio::fs::read(path)
            .await
            .with_context(|| format!("failed to read integration overrides {}", path.display()))?;
        serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "{} is not a JSON object of route keys to integrations",
                path.display()
            )
        })
    }

    fn build(&self, inputs: &Inputs) -> anyhow::Result<Loaded> {
        let snapshot = &inputs.snapshot;
        let mut stage = snapshot.stage_settings.clone();
        stage
            .variables
            .extend(self.stage_variable_overrides.clone());
        let model = ApiModel::import(&snapshot.openapi, snapshot.kind, stage, &inputs.overrides)?;
        let ctx = Arc::new(ApiContext {
            kind: snapshot.kind,
            api_id: snapshot.api_id.clone(),
            stage: snapshot.stage.clone(),
            stage_variables: Arc::new(StageVariables::new(model.stage.variables.clone())),
            responses: GatewayResponses::compile(model.kind, &model.gateway_responses),
            cors: model.settings.cors.as_ref().map(Cors::compile),
            state: Arc::clone(&self.state),
            replicas: self.replicas,
            enforcement: self.enforcement,
            http: self.http.clone(),
            aws: Arc::clone(&self.aws),
            observer: StageObserver::new(
                &self.observability,
                &model,
                &snapshot.api_id,
                snapshot.stage.as_deref(),
            ),
        });
        let (router, routes) = router::build(&model, &ctx, &self.base_path);
        for route in &routes {
            if route.problems.is_empty() {
                tracing::debug!(
                    route = %route.route_key,
                    integration = route.integration,
                    target = route.target,
                    "route loaded"
                );
            } else {
                tracing::warn!(
                    route = %route.route_key,
                    integration = route.integration,
                    problems = route.problems.join("; "),
                    "route loaded with problems"
                );
            }
        }
        let unenforced = model.unenforced();
        if !unenforced.is_empty() {
            tracing::warn!(
                features = unenforced
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(", "),
                "API uses features this gateway does not enforce yet"
            );
        }
        tracing::info!(
            api_id = snapshot.api_id,
            stage = snapshot.stage,
            deployment = snapshot.stamp.deployment_id,
            routes = routes.len(),
            "API definition loaded"
        );
        Ok(Loaded {
            router,
            kind: snapshot.kind,
            summary: LoadSummary {
                api_id: snapshot.api_id.clone(),
                stage: snapshot.stage.clone(),
                deployment_id: snapshot.stamp.deployment_id.clone(),
                loaded_at: jiff::Timestamp::now().to_string(),
                unenforced,
                routes,
            },
        })
    }
}

/// Fetches configurations and keeps the last-known-good copy on disk.
struct Loader {
    fetcher: Fetcher,
    cache: Option<PathBuf>,
}

impl Loader {
    async fn fetch(&self, current: Option<&DeploymentStamp>) -> Result<Fetch, SourceError> {
        let fetched = self.fetcher.fetch(current).await?;
        if let (Fetch::Changed(snapshot), Some(cache)) = (&fetched, &self.cache)
            && let Err(err) = snapshot.store(cache).await
        {
            tracing::warn!(%err, "failed to update the configuration cache");
        }
        Ok(fetched)
    }

    /// The configuration to start with: a fresh download, or the cache when
    /// API Gateway is unreachable.
    async fn initial(&self) -> anyhow::Result<Snapshot> {
        let err = match self.fetch(None).await {
            Ok(Fetch::Changed(snapshot)) => return Ok(*snapshot),
            Ok(Fetch::Unchanged) => anyhow::anyhow!("the source reported no configuration"),
            Err(err) => anyhow::Error::new(err),
        };
        let Some(ref cache) = self.cache else {
            return Err(err).context("failed to load the API definition");
        };
        tracing::warn!(err = format!("{err:#}"), cache = %cache.display(), "API Gateway unreachable; starting from the cached configuration");
        Snapshot::load(cache).await.with_context(|| {
            format!("failed to load the API definition, and the cache is unusable ({err:#})")
        })
    }
}

/// Spaces out refreshes after failures: the delay doubles per consecutive
/// failure up to [`Backoff::MAX`], with +/-20% jitter so replicas that failed
/// together don't retry together against the shared control-plane limit.
#[derive(Debug, Default)]
struct Backoff {
    failures: u32,
}

impl Backoff {
    const MAX: Duration = Duration::from_mins(15);

    fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
    }

    fn reset(&mut self) {
        self.failures = 0;
    }

    fn delay(&self, interval: Duration) -> Duration {
        let factor = 1_u32.checked_shl(self.failures).unwrap_or(u32::MAX);
        let base = interval
            .checked_mul(factor)
            .unwrap_or(Self::MAX)
            .min(Self::MAX);
        Self::jitter(base, Self::random())
    }

    /// Scales `base` into [80%, 120%] using `random`.
    fn jitter(base: Duration, random: u64) -> Duration {
        let millis = u64::try_from(base.as_millis()).unwrap_or(u64::MAX);
        let spread = millis.checked_div(5).unwrap_or(0);
        let span = spread.saturating_mul(2).saturating_add(1);
        let offset = random.checked_rem(span).unwrap_or(0);
        Duration::from_millis(millis.saturating_sub(spread).saturating_add(offset))
    }

    fn random() -> u64 {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
        hasher.write_u128(jiff::Timestamp::now().as_nanosecond().unsigned_abs());
        hasher.finish()
    }
}

/// Periodically re-checks the source and swaps in a new router when the
/// deployment or the override file changes.
struct Refresher {
    loader: Loader,
    builder: Builder,
    inputs: Inputs,
    rejected: Option<Inputs>,
    backoff: Backoff,
}

impl Refresher {
    async fn run(
        mut self,
        interval: Duration,
        current: watch::Sender<Arc<Loaded>>,
        shutdown: CancellationToken,
    ) {
        loop {
            let delay = self.backoff.delay(interval);
            tokio::select! {
                () = shutdown.cancelled() => return,
                () = tokio::time::sleep(delay) => {}
            }
            match self.next_inputs().await {
                Ok(next) => {
                    self.backoff.reset();
                    if let Some(loaded) = self.consider(next) {
                        current.send_replace(Arc::new(loaded));
                    }
                }
                Err(err) => {
                    self.backoff.record_failure();
                    tracing::warn!(
                        err = format!("{err:#}"),
                        retry_in_secs = self.backoff.delay(interval).as_secs(),
                        "configuration refresh failed; keeping the current routes"
                    );
                }
            }
        }
    }

    async fn next_inputs(&self) -> anyhow::Result<Inputs> {
        let snapshot = match self.loader.fetch(Some(&self.inputs.snapshot.stamp)).await? {
            Fetch::Unchanged => self.inputs.snapshot.clone(),
            Fetch::Changed(snapshot) => *snapshot,
        };
        Ok(Inputs {
            snapshot,
            overrides: self.builder.overrides().await?,
        })
    }

    /// Builds `next` if it differs from what is loaded and from the last
    /// rejected input, so a broken definition is logged once, not every tick.
    fn consider(&mut self, next: Inputs) -> Option<Loaded> {
        if next == self.inputs || self.rejected.as_ref() == Some(&next) {
            return None;
        }
        match self.builder.build(&next) {
            Ok(loaded) => {
                self.inputs = next;
                self.rejected = None;
                Some(loaded)
            }
            Err(err) => {
                tracing::error!(
                    err = format!("{err:#}"),
                    "new API definition rejected; keeping the current routes"
                );
                self.rejected = Some(next);
                None
            }
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = tokio::signal::ctrl_c().await {
            tracing::error!(%err, "failed to listen for Ctrl-C");
            std::future::pending::<()>().await;
        }
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(err) => {
                tracing::error!(%err, "failed to listen for SIGTERM");
                std::future::pending::<()>().await;
            }
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = terminate => {},
    }
}

pub(crate) async fn run(config: Config) -> anyhow::Result<()> {
    let tls = Tls::from_pem_files(&config.tls_cert, &config.tls_key)
        .context("failed to load the TLS certificate")?;
    let sdk_config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("failed to build the HTTP client")?;
    let aws = Arc::new(AwsClients::new(
        sdk_config.clone(),
        config.integration_credentials,
        config.lambda_endpoints(),
        http.clone(),
    ));
    let observability = Observability::start(
        sdk_config.clone(),
        config.observability(std::env::var("HOSTNAME").ok().as_deref()),
    );
    let builder = Builder {
        observability: Arc::clone(&observability),
        base_path: config.base_path.clone(),
        enforcement: config.enforcement(),
        stage_variable_overrides: config.stage_variable_overrides(std::env::vars()),
        overrides_path: config.integration_overrides.clone(),
        aws: Arc::clone(&aws),
        http,
        state: Arc::new(StateBackend::InMemory(InMemory::new(
            InMemoryLimits::default(),
        ))),
        replicas: config.replicas,
    };
    builder.enforcement.warn_if_relaxed();
    let loader = Loader {
        fetcher: Fetcher::new(config.source(), &sdk_config),
        cache: config.cache.clone(),
    };
    tracing::info!(source = ?loader.fetcher.source(), "loading API definition");

    let snapshot = loader.initial().await?;
    let inputs = Inputs {
        snapshot,
        overrides: builder.overrides().await?,
    };
    let loaded = builder.build(&inputs)?;
    let (current, routes) = watch::channel(Arc::new(loaded));

    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    tracing::info!(addr = %config.listen, "serving API traffic over TLS");
    tasks.spawn(listener::serve(
        listener,
        tls.clone(),
        router::dispatcher(routes.clone()),
        ConnLimits::DEFAULT,
        config.max_connections,
        config.api_edge(),
        shutdown.clone(),
    ));
    if let Some(addr) = config.admin_listen {
        let admin = TcpListener::bind(addr)
            .await
            .with_context(|| format!("failed to bind admin listener {addr}"))?;
        tracing::info!(%addr, "serving admin endpoints over TLS");
        tasks.spawn(listener::serve(
            admin,
            tls.clone(),
            router::admin(routes, Arc::clone(&aws)),
            ConnLimits::DEFAULT,
            config.max_connections,
            Edge::direct(),
            shutdown.clone(),
        ));
    }
    tasks.spawn(tls.watch(CERT_POLL_INTERVAL, shutdown.clone()));
    if let Some(interval) = config.refresh_interval() {
        let refresher = Refresher {
            loader,
            builder,
            inputs,
            rejected: None,
            backoff: Backoff::default(),
        };
        tasks.spawn(refresher.run(interval, current, shutdown.clone()));
    }

    shutdown_signal().await;
    tracing::info!("shutting down; draining connections");
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    observability.close().await;
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known length"
)]
#[expect(clippy::panic, reason = "tests fail loudly on unexpected variants")]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;
    use crate::aws::{CredentialsMode, LambdaEndpoints};
    use crate::gateway::{AuthorizationMode, Unsupported};
    use crate::model::{ApiKind, StageSettings};
    use crate::source::Source;

    fn sdk_config() -> aws_config::SdkConfig {
        aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build()
    }

    fn builder(overrides_path: Option<PathBuf>) -> Builder {
        Builder {
            observability: Observability::off(),
            base_path: BasePath::default(),
            enforcement: Enforcement {
                authorization: AuthorizationMode::Enforce,
                resource_policy: Unsupported::Reject,
                request_validation: Unsupported::Reject,
            },
            stage_variable_overrides: BTreeMap::from([(
                "host".to_owned(),
                "local.internal".to_owned(),
            )]),
            overrides_path,
            state: Arc::new(StateBackend::InMemory(InMemory::new(
                InMemoryLimits::default(),
            ))),
            replicas: NonZeroU32::MIN,
            http: reqwest::Client::new(),
            aws: Arc::new(AwsClients::new(
                sdk_config(),
                CredentialsMode::Assume,
                LambdaEndpoints::default(),
                reqwest::Client::new(),
            )),
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            kind: ApiKind::Rest,
            api_id: "abc".to_owned(),
            stage: Some("prod".to_owned()),
            stamp: DeploymentStamp {
                deployment_id: Some("d1".to_owned()),
                last_updated_epoch_ms: None,
            },
            stage_settings: StageSettings {
                variables: BTreeMap::from([("host".to_owned(), "aws.example".to_owned())]),
                ..StageSettings::default()
            },
            openapi: json!({"paths": {"/pets": {"get": {"x-amazon-apigateway-integration":
                {"type": "http_proxy", "uri": "https://${stageVariables.host}/pets"}}}}}),
        }
    }

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("apigw-app-{}-{name}", uuid::Uuid::now_v7()))
    }

    fn file_loader(path: PathBuf, cache: Option<PathBuf>) -> Loader {
        Loader {
            fetcher: Fetcher::new(
                Source::File {
                    path,
                    kind: ApiKind::Rest,
                    stage: None,
                },
                &sdk_config(),
            ),
            cache,
        }
    }

    #[tokio::test]
    async fn local_stage_variables_override_the_exported_ones() {
        let builder = builder(None);
        let inputs = Inputs {
            snapshot: snapshot(),
            overrides: builder.overrides().await.unwrap(),
        };
        let loaded = builder.build(&inputs).unwrap();
        assert_eq!(
            loaded.summary.routes[0].target.as_deref(),
            Some("https://local.internal/pets")
        );
        assert_eq!(loaded.summary.deployment_id.as_deref(), Some("d1"));
    }

    #[tokio::test]
    async fn unenforced_features_are_summarized() {
        let mut snapshot = snapshot();
        snapshot.openapi =
            json!({"x-amazon-apigateway-binary-media-types": ["image/png"], "paths": {}});
        snapshot.stage_settings.tracing_enabled = true;
        let inputs = Inputs {
            snapshot,
            overrides: IntegrationOverrides::default(),
        };
        let loaded = builder(None).build(&inputs).unwrap();
        let rendered = serde_json::to_value(&loaded.summary).unwrap();
        assert_eq!(
            rendered["unenforced"],
            json!(["binary_media_types", "tracing"])
        );
    }

    #[tokio::test]
    async fn override_file_errors_are_reported() {
        let missing = builder(Some(scratch("missing.json")));
        assert!(missing.overrides().await.is_err());
        let path = scratch("bad.json");
        tokio::fs::write(&path, b"[1,2]").await.unwrap();
        assert!(builder(Some(path.clone())).overrides().await.is_err());
        tokio::fs::write(&path, br#"{"GET /nope": {"type": "mock"}}"#)
            .await
            .unwrap();
        let unknown = builder(Some(path.clone()));
        let inputs = Inputs {
            snapshot: snapshot(),
            overrides: unknown.overrides().await.unwrap(),
        };
        assert!(unknown.build(&inputs).is_err());
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn initial_load_falls_back_to_cache() {
        let absent = scratch("absent.json");
        assert!(file_loader(absent.clone(), None).initial().await.is_err());
        let cache = scratch("cache.json");
        let loader = file_loader(absent, Some(cache.clone()));
        assert!(loader.initial().await.is_err());
        snapshot().store(&cache).await.unwrap();
        assert_eq!(loader.initial().await.unwrap(), snapshot());
        tokio::fs::remove_file(&cache).await.unwrap();
    }

    #[tokio::test]
    async fn successful_fetch_updates_cache() {
        let doc = scratch("api.json");
        tokio::fs::write(&doc, br#"{"paths": {}}"#).await.unwrap();
        let cache = scratch("cache.json");
        let snapshot = file_loader(doc.clone(), Some(cache.clone()))
            .initial()
            .await
            .unwrap();
        assert_eq!(Snapshot::load(&cache).await.unwrap(), snapshot);
        tokio::fs::remove_file(&doc).await.unwrap();
        tokio::fs::remove_file(&cache).await.unwrap();
    }

    #[test]
    fn same_deployment_requires_a_known_deployment_id() {
        let known = DeploymentStamp {
            deployment_id: Some("d".to_owned()),
            last_updated_epoch_ms: Some(1),
        };
        assert!(known.is_same_deployment(&known.clone()));
        let moved = DeploymentStamp {
            last_updated_epoch_ms: Some(2),
            ..known.clone()
        };
        assert!(!known.is_same_deployment(&moved));
        let unknown = DeploymentStamp::default();
        assert!(!unknown.is_same_deployment(&unknown.clone()));
    }

    #[test]
    fn backoff_grows_per_failure_and_is_capped() {
        let interval = Duration::from_secs(60);
        let mut backoff = Backoff::default();
        let within = |delay: Duration, base: Duration| {
            delay >= base.mul_f64(0.8)
                && delay <= base.mul_f64(1.2).saturating_add(Duration::from_millis(1))
        };
        assert!(within(backoff.delay(interval), interval));
        backoff.record_failure();
        assert!(within(backoff.delay(interval), Duration::from_secs(120)));
        for _ in 0..100 {
            backoff.record_failure();
        }
        assert!(within(backoff.delay(interval), Backoff::MAX));
        backoff.reset();
        assert!(within(backoff.delay(interval), interval));
    }

    proptest! {
        #[test]
        fn jitter_stays_within_twenty_percent(millis in 0_u64..10_000_000, random: u64) {
            let base = Duration::from_millis(millis);
            let jittered = Backoff::jitter(base, random).as_millis();
            let millis = u128::from(millis);
            prop_assert!(jittered.saturating_mul(5) >= millis.saturating_mul(4), "{jittered} < 80% of {millis}");
            prop_assert!(jittered.saturating_mul(5) <= millis.saturating_mul(6), "{jittered} > 120% of {millis}");
        }
    }

    #[tokio::test]
    async fn refresh_swaps_routes_when_the_definition_changes() {
        let doc = scratch("api.json");
        let write = |status: u16| {
            json!({"paths": {"/pets": {"get": {"x-amazon-apigateway-integration": {"type": "mock",
                "requestTemplates": {"application/json": format!("{{\"statusCode\": {status}}}")}}}}}})
            .to_string()
        };
        tokio::fs::write(&doc, write(200)).await.unwrap();
        let loader = file_loader(doc.clone(), None);
        let builder = builder(None);
        let Fetch::Changed(snapshot) = loader.fetch(None).await.unwrap() else {
            panic!("file sources always report a change");
        };
        let inputs = Inputs {
            snapshot: *snapshot,
            overrides: IntegrationOverrides::default(),
        };
        let (current, routes) = watch::channel(Arc::new(builder.build(&inputs).unwrap()));
        let shutdown = CancellationToken::new();
        let refresher = Refresher {
            loader,
            builder,
            inputs,
            rejected: None,
            backoff: Backoff::default(),
        };
        let task =
            tokio::spawn(refresher.run(Duration::from_millis(50), current, shutdown.clone()));

        let app = router::dispatcher(routes.clone());
        let status = |app: axum::Router| async move {
            use tower::ServiceExt as _;
            let request = axum::http::Request::builder()
                .uri("/pets")
                .body(axum::body::Body::empty())
                .unwrap();
            app.oneshot(request).await.unwrap().status().as_u16()
        };
        assert_eq!(status(app.clone()).await, 200);

        // A broken definition is rejected and the current routes keep serving.
        tokio::fs::write(&doc, b"{\"paths\": []}").await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert_eq!(status(app.clone()).await, 200);

        tokio::fs::write(&doc, write(201)).await.unwrap();
        let mut changed = false;
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            if status(app.clone()).await == 201 {
                changed = true;
                break;
            }
        }
        assert!(changed, "refresh did not swap in the new definition");
        shutdown.cancel();
        task.await.unwrap();
        tokio::fs::remove_file(&doc).await.unwrap();
    }
}
