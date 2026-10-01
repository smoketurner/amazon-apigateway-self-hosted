//! Startup, configuration refresh, and shutdown.

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use serde_json::Value;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::authz::KeyStore;
use crate::aws::AwsClients;
#[cfg(test)]
use crate::aws::{CredentialsMode, LambdaEndpoints};
use crate::canary::{CanaryRelease, CanaryStructure, CanarySummary, Release, TrafficShare};
use crate::config::Config;
use crate::cors::Cors;
use crate::domain::{DomainRegistry, DomainSupervisor};
use crate::gateway::{ApiContext, Enforcement};
#[cfg(test)]
use crate::gateway::{AuthorizationMode, Unsupported};
use crate::gateway_response::GatewayResponses;
use crate::integration::StageVariables;
use crate::listener::{self, ConnLimits, Edge, Tls};
use crate::model::{ApiModel, Feature, IntegrationOverrides, StageSettings};
use crate::observability::{Observability, StageObserver};
use crate::router::{self, BasePath, LoadSummary, Loaded, RouteSummary};
use crate::source::{Fetch, Fetcher, Snapshot, Source, SourceError};
use crate::state::StateBackend;
use crate::vpc_link::VpcLinks;

const CERT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Everything a definition is built from besides the snapshot itself.
#[derive(Clone)]
pub(crate) struct Builder {
    base_path: BasePath,
    enforcement: Enforcement,
    stage_variable_overrides: BTreeMap<String, String>,
    overrides_path: Option<PathBuf>,
    http: reqwest::Client,
    aws: Arc<AwsClients>,
    keys: Arc<KeyStore>,
    state: Arc<StateBackend>,
    replicas: NonZeroU32,
    vpc_links: VpcLinks,
    observability: Arc<Observability>,
}

#[cfg(test)]
impl Builder {
    /// A builder with strict enforcement and no overrides or observability, for
    /// tests that load APIs through it.
    pub(crate) fn for_tests(sdk_config: aws_config::SdkConfig) -> Self {
        Self {
            observability: Observability::off(),
            base_path: BasePath::default(),
            enforcement: Enforcement {
                authorization: AuthorizationMode::Enforce,
                request_validation: Unsupported::Reject,
            },
            stage_variable_overrides: BTreeMap::new(),
            overrides_path: None,
            state: StateBackend::in_memory(),
            replicas: NonZeroU32::MIN,
            http: reqwest::Client::new(),
            aws: Arc::new(AwsClients::new(
                sdk_config,
                CredentialsMode::Assume,
                LambdaEndpoints::default(),
                reqwest::Client::new(),
            )),
            keys: Arc::new(KeyStore::new(reqwest::Client::new(), [])),
            vpc_links: VpcLinks::default(),
        }
    }
}

/// One release's router and what to report about it.
struct BuiltRelease {
    router: Router,
    routes: Vec<RouteSummary>,
    unenforced: Vec<Feature>,
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

    /// Builds one release of the stage: `openapi` imported with `stage` settings
    /// (local stage variable overrides applied on top).
    fn build_release(
        &self,
        inputs: &Inputs,
        openapi: &Value,
        mut stage: StageSettings,
        release: Option<Release>,
    ) -> anyhow::Result<BuiltRelease> {
        let snapshot = &inputs.snapshot;
        stage
            .variables
            .extend(self.stage_variable_overrides.clone());
        let model = ApiModel::import(openapi, snapshot.kind, stage, &inputs.overrides)?;
        let ctx = Arc::new(ApiContext {
            kind: snapshot.kind,
            api_id: snapshot.api_id.clone(),
            stage: snapshot.stage.clone(),
            stage_variables: Arc::new(StageVariables::new(model.stage.variables.clone())),
            responses: GatewayResponses::compile(model.kind, &model.gateway_responses),
            cors: model.settings.cors.as_ref().map(Cors::compile),
            state: Arc::clone(&self.state),
            replicas: self.replicas,
            vpc_links: self.vpc_links.clone(),
            enforcement: self.enforcement,
            http: self.http.clone(),
            aws: Arc::clone(&self.aws),
            keys: Arc::clone(&self.keys),
            observer: StageObserver::new(
                &self.observability,
                &model,
                &snapshot.api_id,
                snapshot.stage.as_deref(),
                release,
            ),
            release,
        });
        let (router, routes) = router::build(&model, &ctx, &self.base_path);
        Ok(BuiltRelease {
            router,
            routes,
            unenforced: model.unenforced(),
        })
    }

    /// The canary release, when the stage has one that receives traffic: the
    /// stage's routes (or the shadow stage's, when `--canary-export-stage`
    /// supplied them) with the canary's stage variable overrides applied.
    fn build_canary(
        &self,
        inputs: &Inputs,
    ) -> anyhow::Result<Option<(CanaryRelease, CanarySummary)>> {
        let snapshot = &inputs.snapshot;
        let Some(ref settings) = snapshot.stage_settings.canary else {
            return Ok(None);
        };
        let share = TrafficShare::from_percent(settings.percent_traffic);
        if share.is_none() {
            return Ok(None);
        }
        let (openapi, structure) = if let Some(ref shadow) = snapshot.canary {
            (
                &shadow.openapi,
                CanaryStructure::ShadowStage(shadow.stage.clone()),
            )
        } else {
            tracing::warn!(
                "the canary release serves the stage's routes with the canary's stage variables; set --canary-export-stage to a stage holding the canary deployment to serve its routes"
            );
            (&snapshot.openapi, CanaryStructure::StageExport)
        };
        let mut stage = snapshot.stage_settings.clone();
        stage
            .variables
            .extend(settings.stage_variable_overrides.clone());
        let built = self.build_release(inputs, openapi, stage, Some(Release::Canary))?;
        Ok(Some((
            CanaryRelease {
                router: built.router,
                share,
            },
            CanarySummary {
                percent_traffic: settings.percent_traffic,
                deployment_id: settings.deployment_id.clone(),
                use_stage_cache: settings.use_stage_cache,
                structure,
                stage_variable_overrides: settings.stage_variable_overrides.clone(),
                routes: built.routes,
            },
        )))
    }

    fn build(&self, inputs: &Inputs) -> anyhow::Result<Loaded> {
        let snapshot = &inputs.snapshot;
        let release = snapshot
            .stage_settings
            .canary
            .as_ref()
            .map(|_| Release::Production);
        let BuiltRelease {
            router,
            routes,
            unenforced,
        } = self.build_release(
            inputs,
            &snapshot.openapi,
            snapshot.stage_settings.clone(),
            release,
        )?;
        let canary = self.build_canary(inputs)?;
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
        let (canary, canary_summary) = match canary {
            Some((release, summary)) => (Some(release), Some(summary)),
            None => (None, None),
        };
        Ok(Loaded {
            router,
            canary,
            kind: snapshot.kind,
            summary: LoadSummary {
                canary: canary_summary,
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
    async fn fetch(&self, current: Option<&Snapshot>) -> Result<Fetch, SourceError> {
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
        let snapshot = match self.loader.fetch(Some(&self.inputs.snapshot)).await? {
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

/// One API stage being served and kept current: its latest definition, and the
/// task that refreshes it.
pub(crate) struct ApiRuntime {
    loaded: watch::Receiver<Arc<Loaded>>,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ApiRuntime {
    /// Loads the API once (from `cache` when the source is unreachable) and,
    /// when `interval` is set, refreshes it until `shutdown` is cancelled or
    /// [`ApiRuntime::stop`] is called.
    ///
    /// # Errors
    ///
    /// When the definition cannot be loaded or built.
    pub(crate) async fn start(
        source: Source,
        builder: Builder,
        cache: Option<PathBuf>,
        interval: Option<Duration>,
        sdk_config: &aws_config::SdkConfig,
        shutdown: &CancellationToken,
    ) -> anyhow::Result<Self> {
        let loader = Loader {
            fetcher: Fetcher::new(source, sdk_config),
            cache,
        };
        tracing::info!(source = ?loader.fetcher.source(), "loading API definition");
        let snapshot = loader.initial().await?;
        let inputs = Inputs {
            snapshot,
            overrides: builder.overrides().await?,
        };
        let loaded = builder.build(&inputs)?;
        let (current, loaded) = watch::channel(Arc::new(loaded));
        let stop = shutdown.child_token();
        let task = interval.map(|interval| {
            let refresher = Refresher {
                loader,
                builder,
                inputs,
                rejected: None,
                backoff: Backoff::default(),
            };
            tokio::spawn(refresher.run(interval, current, stop.clone()))
        });
        Ok(Self { loaded, stop, task })
    }

    pub(crate) fn loaded(&self) -> watch::Receiver<Arc<Loaded>> {
        self.loaded.clone()
    }

    /// Stops refreshing and waits for the refresh task to end.
    pub(crate) async fn stop(self) {
        self.stop.cancel();
        if let Some(task) = self.task
            && let Err(err) = task.await
        {
            tracing::error!(%err, "an API refresh task failed");
        }
    }
}

/// Loads what `config` says to serve (one API, or every API of the custom
/// domains) and returns the routers for the API listener and the admin listener.
/// Background tasks are added to `tasks`.
async fn serve_apis(
    config: &Config,
    builder: Builder,
    sdk_config: &aws_config::SdkConfig,
    aws: &Arc<AwsClients>,
    tls: &Tls,
    shutdown: &CancellationToken,
    tasks: &mut JoinSet<()>,
) -> anyhow::Result<(Router, Router)> {
    if config.domain_names.is_empty() {
        let runtime = ApiRuntime::start(
            config.source(),
            builder,
            config.cache.clone(),
            config.refresh_interval(),
            sdk_config,
            shutdown,
        )
        .await?;
        let routes = runtime.loaded();
        tasks.spawn(async move { runtime.stop().await });
        return Ok((
            router::dispatcher(routes.clone()),
            router::admin(routes, Arc::clone(aws)),
        ));
    }
    let mut registry = Vec::new();
    for domain in &config.domain_names {
        let supervisor = DomainSupervisor::new(
            domain.clone(),
            builder.clone(),
            sdk_config,
            config.refresh_interval(),
            shutdown,
            tls.domain(domain),
        );
        tracing::info!(%domain, "loading custom domain");
        let (state, task) = supervisor
            .start()
            .await
            .with_context(|| format!("failed to load custom domain {domain}"))?;
        registry.push((domain.clone(), state));
        tasks.spawn(async move {
            if let Err(err) = task.await {
                tracing::error!(%err, "a custom domain task failed");
            }
        });
    }
    let registry = DomainRegistry::new(registry);
    Ok((
        router::domain_dispatcher(registry.clone()),
        router::admin_domains(registry, Arc::clone(aws)),
    ))
}

pub(crate) async fn run(config: Config) -> anyhow::Result<()> {
    let tls = Tls::with_domains(
        &config.tls_cert,
        &config.tls_key,
        &config.domain_names,
        &config.domain_certs(),
    )
    .context("failed to load the TLS certificates")?;
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
    for endpoint in config.issuer_endpoints.iter().filter(|e| e.is_plaintext()) {
        tracing::warn!(?endpoint, "token signing keys are fetched over plain HTTP");
    }
    let keys = Arc::new(KeyStore::new(
        http.clone(),
        config.issuer_endpoints.iter().cloned(),
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
        keys,
        http,
        state: StateBackend::in_memory(),
        replicas: config.replicas,
        vpc_links: config.vpc_links(),
    };
    builder.enforcement.warn_if_relaxed();
    let shutdown = CancellationToken::new();
    let mut tasks = JoinSet::new();
    let (app, admin_app) = serve_apis(
        &config,
        builder,
        &sdk_config,
        &aws,
        &tls,
        &shutdown,
        &mut tasks,
    )
    .await?;
    let listener = TcpListener::bind(config.listen)
        .await
        .with_context(|| format!("failed to bind {}", config.listen))?;
    tracing::info!(addr = %config.listen, "serving API traffic over TLS");
    tasks.spawn(listener::serve(
        listener,
        tls.clone(),
        app,
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
            admin_app,
            ConnLimits::DEFAULT,
            config.max_connections,
            Edge::direct(),
            shutdown.clone(),
        ));
    }
    tasks.spawn(tls.watch(CERT_POLL_INTERVAL, shutdown.clone()));

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
    use crate::model::{ApiKind, CanarySettings, DeploymentStamp, StageSettings};
    use crate::source::CanarySnapshot;

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
                request_validation: Unsupported::Reject,
            },
            stage_variable_overrides: BTreeMap::from([(
                "host".to_owned(),
                "local.internal".to_owned(),
            )]),
            overrides_path,
            state: StateBackend::in_memory(),
            replicas: NonZeroU32::MIN,
            vpc_links: VpcLinks::default(),
            http: reqwest::Client::new(),
            aws: Arc::new(AwsClients::new(
                sdk_config(),
                CredentialsMode::Assume,
                LambdaEndpoints::default(),
                reqwest::Client::new(),
            )),
            keys: Arc::new(KeyStore::new(reqwest::Client::new(), [])),
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
            canary: None,
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
        snapshot.stage_settings.cache_cluster_enabled = true;
        let inputs = Inputs {
            snapshot,
            overrides: IntegrationOverrides::default(),
        };
        let loaded = builder(None).build(&inputs).unwrap();
        let rendered = serde_json::to_value(&loaded.summary).unwrap();
        assert_eq!(
            rendered["unenforced"],
            json!(["binary_media_types", "response_caching"])
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
        let status = |app: Router| async move {
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

    fn canary_snapshot(percent: f64, overrides: &[(&str, &str)]) -> Snapshot {
        let mut snapshot = snapshot();
        snapshot.stage_settings.variables =
            BTreeMap::from([("backend".to_owned(), "prod.internal".to_owned())]);
        snapshot.openapi = json!({"paths": {"/pets": {"get": {"x-amazon-apigateway-integration":
            {"type": "http_proxy", "uri": "https://${stageVariables.backend}/pets"}}}}});
        snapshot.stage_settings.canary = Some(CanarySettings {
            percent_traffic: percent,
            deployment_id: Some("d2".to_owned()),
            stage_variable_overrides: overrides
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            use_stage_cache: false,
        });
        snapshot
    }

    fn build(snapshot: Snapshot) -> Loaded {
        let inputs = Inputs {
            snapshot,
            overrides: IntegrationOverrides::default(),
        };
        builder(None).build(&inputs).unwrap()
    }

    #[tokio::test]
    async fn the_canary_release_has_its_own_stage_variables() {
        let loaded = build(canary_snapshot(25.0, &[("backend", "canary.internal")]));
        assert_eq!(
            loaded.summary.routes[0].target.as_deref(),
            Some("https://prod.internal/pets")
        );
        let canary = loaded.summary.canary.as_ref().unwrap();
        assert_eq!(
            canary.routes[0].target.as_deref(),
            Some("https://canary.internal/pets")
        );
        assert_eq!(canary.percent_traffic.to_bits(), 25.0_f64.to_bits());
        assert_eq!(canary.deployment_id.as_deref(), Some("d2"));
        assert!(loaded.canary.is_some());
        let rendered = serde_json::to_value(&loaded.summary).unwrap();
        assert_eq!(
            rendered["canary"]["structure"],
            json!({"source": "stage_export"})
        );
        assert_eq!(
            rendered["canary"]["stage_variable_overrides"]["backend"],
            "canary.internal"
        );
    }

    #[tokio::test]
    async fn local_stage_variable_overrides_win_over_the_canarys() {
        let mut snapshot = snapshot();
        snapshot.stage_settings.canary = Some(CanarySettings {
            percent_traffic: 25.0,
            deployment_id: None,
            stage_variable_overrides: BTreeMap::from([(
                "host".to_owned(),
                "canary.example".to_owned(),
            )]),
            use_stage_cache: false,
        });
        let loaded = build(snapshot);
        let canary = loaded.summary.canary.as_ref().unwrap();
        assert_eq!(
            canary.routes[0].target.as_deref(),
            Some("https://local.internal/pets")
        );
    }

    #[tokio::test]
    async fn a_shadow_stage_supplies_the_canary_routes() {
        let mut snapshot = canary_snapshot(10.0, &[]);
        snapshot.canary = Some(CanarySnapshot {
            stage: "shadow".to_owned(),
            stamp: DeploymentStamp {
                deployment_id: Some("d2".to_owned()),
                last_updated_epoch_ms: None,
            },
            openapi: json!({"paths": {
                "/pets": {"get": {"x-amazon-apigateway-integration":
                    {"type": "http_proxy", "uri": "https://${stageVariables.backend}/pets"}}},
                "/new": {"get": {"x-amazon-apigateway-integration":
                    {"type": "http_proxy", "uri": "https://${stageVariables.backend}/new"}}}}}),
        });
        let loaded = build(snapshot);
        let routes: Vec<&str> = loaded
            .summary
            .routes
            .iter()
            .map(|r| r.route_key.as_str())
            .collect();
        assert_eq!(routes, ["GET /pets"]);
        let canary = loaded.summary.canary.as_ref().unwrap();
        let canary_routes: Vec<&str> = canary.routes.iter().map(|r| r.route_key.as_str()).collect();
        assert_eq!(canary_routes, ["GET /new", "GET /pets"]);
        let rendered = serde_json::to_value(&loaded.summary).unwrap();
        assert_eq!(
            rendered["canary"]["structure"],
            json!({"source": "shadow_stage", "stage": "shadow"})
        );
    }

    #[tokio::test]
    async fn a_canary_without_traffic_builds_nothing() {
        let loaded = build(canary_snapshot(0.0, &[("backend", "canary.internal")]));
        assert!(loaded.canary.is_none());
        assert!(loaded.summary.canary.is_none());
        let rendered = serde_json::to_value(&loaded.summary).unwrap();
        assert!(rendered.get("canary").is_none());
    }

    #[tokio::test]
    async fn stages_without_canary_settings_are_unchanged() {
        let loaded = build(snapshot());
        assert!(loaded.canary.is_none());
        assert!(loaded.summary.canary.is_none());
    }

    mod traffic {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt as _;

        use super::*;
        use crate::model::{AccessLogSettings, MethodSettings, SettingsScope};
        use crate::observability::testing::MockAws;
        use crate::observability::{
            Delivery, LogGroup, MetricsNamespace, MetricsSettings, Settings, StreamName,
            TraceDelivery,
        };

        const ACCESS_GROUP: &str = "/aws/apigw/access";

        fn observed_snapshot(percent: f64) -> Snapshot {
            let mut snapshot = canary_snapshot(percent, &[]);
            snapshot.openapi = json!({"paths": {"/pets": {"get": {"x-amazon-apigateway-integration":
                {"type": "mock",
                 "requestTemplates": {"application/json": "{\"statusCode\": 200}"},
                 "responses": {"default": {"statusCode": "200",
                    "responseTemplates": {"application/json": "{}"}}}}}}}});
            snapshot.stage_settings.access_log = Some(AccessLogSettings {
                destination_arn: Some(format!("arn:aws:logs:us-east-1:1:log-group:{ACCESS_GROUP}")),
                format: Some("$context.stage $context.isCanaryRequest".to_owned()),
            });
            snapshot.stage_settings.method_settings.insert(
                SettingsScope::All,
                MethodSettings {
                    metrics_enabled: Some(false),
                    ..MethodSettings::default()
                },
            );
            snapshot
        }

        async fn run(aws: &MockAws, snapshot: Snapshot, requests: usize) {
            let observability = Observability::start(
                aws.sdk_config(),
                Settings {
                    access_logs: Delivery::Aws,
                    execution_logs: Delivery::Off,
                    metrics: Some(MetricsSettings {
                        group: LogGroup::new("metrics-group"),
                        namespace: MetricsNamespace::default(),
                    }),
                    tracing: TraceDelivery::Off,
                    sampling_percent: 0,
                    stream: StreamName::for_pod(
                        Some("pod"),
                        None,
                        jiff::Timestamp::UNIX_EPOCH,
                        uuid::Uuid::nil(),
                    ),
                },
            );
            let mut builder = builder(None);
            builder.observability = Arc::clone(&observability);
            let loaded = builder
                .build(&Inputs {
                    snapshot,
                    overrides: IntegrationOverrides::default(),
                })
                .unwrap();
            let (_tx, rx) = watch::channel(Arc::new(loaded));
            let app = router::dispatcher(rx);
            for _ in 0..requests {
                let request = Request::builder()
                    .uri("/pets")
                    .header("host", "h")
                    .body(Body::empty())
                    .unwrap();
                assert_eq!(app.clone().oneshot(request).await.unwrap().status(), 200);
            }
            observability.close().await;
        }

        fn lines(aws: &MockAws, group: &str) -> Vec<String> {
            aws.calls()
                .into_iter()
                .filter(|c| {
                    c.target == "Logs_20140328.PutLogEvents" && c.body["logGroupName"] == group
                })
                .flat_map(|c| c.body["logEvents"].as_array().cloned().unwrap_or_default())
                .map(|e| e["message"].as_str().unwrap().to_owned())
                .collect()
        }

        fn stages(aws: &MockAws) -> Vec<String> {
            lines(aws, "metrics-group")
                .iter()
                .map(|m| {
                    let doc: Value = serde_json::from_str(m).unwrap();
                    doc["Stage"].as_str().unwrap().to_owned()
                })
                .collect()
        }

        #[tokio::test]
        async fn canary_requests_are_logged_and_counted_for_the_canary_too() {
            let aws = MockAws::start().await;
            run(&aws, observed_snapshot(100.0), 3).await;
            assert_eq!(lines(&aws, ACCESS_GROUP), ["prod true"; 3]);
            assert_eq!(
                lines(&aws, &format!("{ACCESS_GROUP}/Canary")),
                ["prod true"; 3]
            );
            let mut stages = stages(&aws);
            stages.sort();
            assert_eq!(stages, ["prod", "prod/Canary"]);
        }

        #[tokio::test]
        async fn production_requests_report_that_they_are_not_canary_requests() {
            let aws = MockAws::start().await;
            run(&aws, observed_snapshot(0.0), 2).await;
            assert_eq!(lines(&aws, ACCESS_GROUP), ["prod false"; 2]);
            assert!(lines(&aws, &format!("{ACCESS_GROUP}/Canary")).is_empty());
            assert_eq!(stages(&aws), ["prod"]);
        }

        #[tokio::test]
        async fn stages_without_a_canary_leave_the_variable_unset() {
            let aws = MockAws::start().await;
            let mut snapshot = observed_snapshot(0.0);
            snapshot.stage_settings.canary = None;
            run(&aws, snapshot, 1).await;
            assert_eq!(lines(&aws, ACCESS_GROUP), ["prod -"]);
        }
    }
}
