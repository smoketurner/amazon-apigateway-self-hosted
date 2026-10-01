//! Startup, configuration refresh, and shutdown.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::gateway::{ApiContext, Enforcement};
use crate::listener::{self, ConnLimits, Tls};
use crate::router::{self, BasePath, LoadSummary, Loaded};
use crate::source::{self, Fetcher, Snapshot};
use crate::spec::{ApiDefinition, IntegrationOverrides};

const CERT_POLL_INTERVAL: Duration = Duration::from_secs(30);

/// Everything a definition is built from besides the snapshot itself.
struct Builder {
    base_path: BasePath,
    enforcement: Enforcement,
    stage_variable_overrides: BTreeMap<String, String>,
    overrides_path: Option<std::path::PathBuf>,
    http: reqwest::Client,
    lambda: aws_sdk_lambda::Client,
}

/// The inputs a router was built from; a refresh rebuilds only when they change.
#[derive(PartialEq)]
struct Inputs {
    snapshot: Snapshot,
    overrides: IntegrationOverrides,
}

impl Builder {
    async fn overrides(&self) -> anyhow::Result<IntegrationOverrides> {
        let Some(ref path) = self.overrides_path else {
            return Ok(IntegrationOverrides::new());
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
        let mut stage_variables = snapshot.stage_variables.clone();
        stage_variables.extend(self.stage_variable_overrides.clone());
        let definition = ApiDefinition::from_openapi(
            &snapshot.openapi,
            snapshot.kind,
            &stage_variables,
            &inputs.overrides,
        )?;
        let ctx = Arc::new(ApiContext {
            kind: snapshot.kind,
            api_id: snapshot.api_id.clone(),
            stage: snapshot.stage.clone(),
            stage_variables,
            enforcement: self.enforcement,
            http: self.http.clone(),
            lambda: self.lambda.clone(),
        });
        let (router, routes) = router::build(&definition, &ctx, &self.base_path);
        for route in &routes {
            if route.problems.is_empty() {
                tracing::debug!(
                    route = route.route_key,
                    integration = route.integration,
                    target = route.target,
                    "route loaded"
                );
            } else {
                tracing::warn!(
                    route = route.route_key,
                    integration = route.integration,
                    problems = route.problems.join("; "),
                    "route loaded with problems"
                );
            }
        }
        tracing::info!(
            api_id = snapshot.api_id,
            stage = snapshot.stage,
            routes = routes.len(),
            "API definition loaded"
        );
        Ok(Loaded {
            router,
            kind: snapshot.kind,
            summary: LoadSummary {
                api_id: snapshot.api_id.clone(),
                stage: snapshot.stage.clone(),
                loaded_at: jiff::Timestamp::now().to_string(),
                routes,
            },
        })
    }
}

async fn fetch_and_cache(
    fetcher: &Fetcher,
    cache: Option<&Path>,
) -> Result<Snapshot, source::SourceError> {
    let snapshot = fetcher.fetch().await?;
    if let Some(cache) = cache
        && let Err(err) = source::store_cache(cache, &snapshot).await
    {
        tracing::warn!(%err, "failed to update the configuration cache");
    }
    Ok(snapshot)
}

async fn initial_snapshot(fetcher: &Fetcher, cache: Option<&Path>) -> anyhow::Result<Snapshot> {
    match fetch_and_cache(fetcher, cache).await {
        Ok(snapshot) => Ok(snapshot),
        Err(err) => {
            let Some(cache) = cache else {
                return Err(err).context("failed to load the API definition");
            };
            tracing::warn!(%err, cache = %cache.display(), "API Gateway unreachable; starting from the cached configuration");
            source::load_cache(cache).await.with_context(|| {
                format!("failed to load the API definition, and the cache is unusable ({err})")
            })
        }
    }
}

async fn refresh_loop(
    fetcher: Fetcher,
    builder: Builder,
    cache: Option<std::path::PathBuf>,
    mut inputs: Inputs,
    interval: Duration,
    current: watch::Sender<Arc<Loaded>>,
    shutdown: CancellationToken,
) {
    let now = tokio::time::Instant::now();
    let mut ticker = tokio::time::interval_at(now.checked_add(interval).unwrap_or(now), interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut rejected: Option<Inputs> = None;
    loop {
        tokio::select! {
            () = shutdown.cancelled() => return,
            _ = ticker.tick() => {}
        }
        let snapshot = match fetch_and_cache(&fetcher, cache.as_deref()).await {
            Ok(snapshot) => snapshot,
            Err(err) => {
                tracing::warn!(%err, "configuration refresh failed; keeping the current routes");
                continue;
            }
        };
        let overrides = match builder.overrides().await {
            Ok(overrides) => overrides,
            Err(err) => {
                tracing::warn!(
                    err = format!("{err:#}"),
                    "configuration refresh failed; keeping the current routes"
                );
                continue;
            }
        };
        let next = Inputs {
            snapshot,
            overrides,
        };
        if next == inputs || rejected.as_ref() == Some(&next) {
            continue;
        }
        match builder.build(&next) {
            Ok(loaded) => {
                current.send_replace(Arc::new(loaded));
                inputs = next;
                rejected = None;
            }
            Err(err) => {
                tracing::error!(
                    err = format!("{err:#}"),
                    "new API definition rejected; keeping the current routes"
                );
                rejected = Some(next);
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
    let builder = Builder {
        base_path: config.base_path.clone(),
        enforcement: config.enforcement(),
        stage_variable_overrides: config.stage_variable_overrides(std::env::vars()),
        overrides_path: config.integration_overrides.clone(),
        http,
        lambda: aws_sdk_lambda::Client::new(&sdk_config),
    };
    builder.enforcement.warn_if_relaxed();
    let fetcher = Fetcher::new(config.source(), &sdk_config);
    tracing::info!(source = ?fetcher.source(), "loading API definition");

    let snapshot = initial_snapshot(&fetcher, config.cache.as_deref()).await?;
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
            router::admin(routes),
            ConnLimits::DEFAULT,
            config.max_connections,
            shutdown.clone(),
        ));
    }
    tasks.spawn(tls.watch(CERT_POLL_INTERVAL, shutdown.clone()));
    if let Some(interval) = config.refresh_interval() {
        tasks.spawn(refresh_loop(
            fetcher,
            builder,
            config.cache.clone(),
            inputs,
            interval,
            current,
            shutdown.clone(),
        ));
    }

    shutdown_signal().await;
    tracing::info!("shutting down; draining connections");
    shutdown.cancel();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known length"
)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::gateway::{AuthorizationMode, Unsupported};
    use crate::source::Source;
    use crate::spec::ApiKind;

    fn sdk_config() -> aws_config::SdkConfig {
        aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build()
    }

    fn builder(overrides_path: Option<std::path::PathBuf>) -> Builder {
        Builder {
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
            http: reqwest::Client::new(),
            lambda: aws_sdk_lambda::Client::new(&sdk_config()),
        }
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            kind: ApiKind::Rest,
            api_id: "abc".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: BTreeMap::from([("host".to_owned(), "aws.example".to_owned())]),
            openapi: json!({"paths": {"/pets": {"get": {"x-amazon-apigateway-integration":
                {"type": "http_proxy", "uri": "https://${stageVariables.host}/pets"}}}}}),
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("apigw-app-{}-{name}", uuid::Uuid::now_v7()))
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
    async fn initial_snapshot_falls_back_to_cache() {
        let fetcher = Fetcher::new(
            Source::File {
                path: scratch("absent.json"),
                kind: ApiKind::Rest,
            },
            &sdk_config(),
        );
        assert!(initial_snapshot(&fetcher, None).await.is_err());
        let cache = scratch("cache.json");
        assert!(initial_snapshot(&fetcher, Some(&cache)).await.is_err());
        source::store_cache(&cache, &snapshot()).await.unwrap();
        assert_eq!(
            initial_snapshot(&fetcher, Some(&cache)).await.unwrap(),
            snapshot()
        );
        tokio::fs::remove_file(&cache).await.unwrap();
    }

    #[tokio::test]
    async fn successful_fetch_updates_cache() {
        let doc = scratch("api.json");
        tokio::fs::write(&doc, br#"{"paths": {}}"#).await.unwrap();
        let cache = scratch("cache.json");
        let fetcher = Fetcher::new(
            Source::File {
                path: doc.clone(),
                kind: ApiKind::Http,
            },
            &sdk_config(),
        );
        let snapshot = initial_snapshot(&fetcher, Some(&cache)).await.unwrap();
        assert_eq!(source::load_cache(&cache).await.unwrap(), snapshot);
        tokio::fs::remove_file(&doc).await.unwrap();
        tokio::fs::remove_file(&cache).await.unwrap();
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
        let fetcher = Fetcher::new(
            Source::File {
                path: doc.clone(),
                kind: ApiKind::Rest,
            },
            &sdk_config(),
        );
        let builder = builder(None);
        let inputs = Inputs {
            snapshot: fetcher.fetch().await.unwrap(),
            overrides: IntegrationOverrides::new(),
        };
        let (current, routes) = watch::channel(Arc::new(builder.build(&inputs).unwrap()));
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(refresh_loop(
            fetcher,
            builder,
            None,
            inputs,
            Duration::from_millis(50),
            current,
            shutdown.clone(),
        ));

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
