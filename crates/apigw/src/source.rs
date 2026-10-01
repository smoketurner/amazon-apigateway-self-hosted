//! Downloads an API definition from API Gateway (or reads it from disk) and keeps
//! a last-known-good copy so the gateway can start while AWS is unreachable.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{ApiKind, DeploymentStamp, StageSettings};

/// `apigateway` includes every API Gateway extension (integrations, request
/// validators, resource policy, gateway responses, ...); `authorizers` adds the
/// authorizer definitions.
const REST_EXPORT_EXTENSIONS: &str = "apigateway,authorizers";

#[derive(Debug, Clone)]
pub(crate) enum Source {
    RestApi {
        api_id: String,
        stage: String,
        /// A stage that holds the canary deployment, exported to build the
        /// canary release when the stage has canary settings.
        canary_stage: Option<String>,
    },
    HttpApi {
        api_id: String,
        stage: String,
    },
    /// An export on disk. `stage` names the stage for `$context.stage`.
    File {
        path: PathBuf,
        kind: ApiKind,
        stage: Option<String>,
    },
}

/// Everything needed to rebuild the routes. The cache stores the raw export
/// rather than the imported model, so importer improvements apply to cached
/// configurations too.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) kind: ApiKind,
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
    #[serde(default)]
    pub(crate) stamp: DeploymentStamp,
    #[serde(default)]
    pub(crate) stage_settings: StageSettings,
    pub(crate) openapi: Value,
    /// The canary deployment's export, when `--canary-export-stage` supplies one.
    #[serde(default)]
    pub(crate) canary: Option<CanarySnapshot>,
}

/// What a shadow stage contributes to a canary release.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct CanarySnapshot {
    pub(crate) stage: String,
    pub(crate) stamp: DeploymentStamp,
    pub(crate) openapi: Value,
}

/// The result of checking the source for a newer configuration.
#[derive(Debug)]
pub(crate) enum Fetch {
    /// The deployment is the one already loaded; nothing was downloaded.
    Unchanged,
    Changed(Box<Snapshot>),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum SourceError {
    #[error("API Gateway request failed: {0}")]
    Aws(String),
    #[error("API Gateway returned an empty export")]
    EmptyExport,
    #[error("failed to read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{0} is not valid JSON: {1}")]
    Json(String, serde_json::Error),
}

impl SourceError {
    fn aws(err: impl std::error::Error) -> Self {
        Self::Aws(aws_sdk_apigateway::error::DisplayErrorContext(err).to_string())
    }
}

/// An `OpenAPI` export as returned by API Gateway or read from disk.
struct Export(Value);

impl Export {
    fn parse(body: &[u8]) -> Result<Self, SourceError> {
        if body.is_empty() {
            return Err(SourceError::EmptyExport);
        }
        serde_json::from_slice(body)
            .map(Self)
            .map_err(|e| SourceError::Json("API Gateway export".to_owned(), e))
    }

    async fn read(path: &Path) -> Result<Value, SourceError> {
        let bytes = tokio::fs::read(path)
            .await
            .map_err(|source| SourceError::Read {
                path: path.to_owned(),
                source,
            })?;
        serde_json::from_slice(&bytes).map_err(|e| SourceError::Json(path.display().to_string(), e))
    }
}

pub(crate) struct Fetcher {
    source: Source,
    rest: aws_sdk_apigateway::Client,
    http: aws_sdk_apigatewayv2::Client,
}

impl Fetcher {
    pub(crate) fn new(source: Source, sdk_config: &aws_config::SdkConfig) -> Self {
        Self {
            source,
            rest: aws_sdk_apigateway::Client::new(sdk_config),
            http: aws_sdk_apigatewayv2::Client::new(sdk_config),
        }
    }

    pub(crate) fn source(&self) -> &Source {
        &self.source
    }

    /// Checks the stage with the cheap `GetStage` call and downloads the export
    /// only when the deployment differs from `current`. Control-plane calls
    /// share a 10 req/s account limit, so replicas must not re-export on every
    /// refresh.
    pub(crate) async fn fetch(&self, current: Option<&Snapshot>) -> Result<Fetch, SourceError> {
        match self.source {
            Source::RestApi {
                ref api_id,
                ref stage,
                ref canary_stage,
            } => {
                self.fetch_rest(api_id, stage, canary_stage.as_deref(), current)
                    .await
            }
            Source::HttpApi {
                ref api_id,
                ref stage,
            } => self.fetch_http(api_id, stage, current).await,
            Source::File {
                ref path,
                kind,
                ref stage,
            } => Ok(Fetch::Changed(Box::new(Snapshot {
                kind,
                api_id: path.display().to_string(),
                stage: stage.clone(),
                stamp: DeploymentStamp::default(),
                stage_settings: StageSettings::default(),
                openapi: Export::read(path).await?,
                canary: None,
            }))),
        }
    }

    async fn rest_stage(
        &self,
        api_id: &str,
        stage: &str,
    ) -> Result<aws_sdk_apigateway::operation::get_stage::GetStageOutput, SourceError> {
        self.rest
            .get_stage()
            .rest_api_id(api_id)
            .stage_name(stage)
            .send()
            .await
            .map_err(SourceError::aws)
    }

    async fn rest_export(&self, api_id: &str, stage: &str) -> Result<Value, SourceError> {
        let export = self
            .rest
            .get_export()
            .rest_api_id(api_id)
            .stage_name(stage)
            .export_type("oas30")
            .accepts("application/json")
            .parameters("extensions", REST_EXPORT_EXTENSIONS)
            .send()
            .await
            .map_err(SourceError::aws)?;
        let body = export.body.ok_or(SourceError::EmptyExport)?;
        Ok(Export::parse(body.as_ref())?.0)
    }

    async fn fetch_rest(
        &self,
        api_id: &str,
        stage: &str,
        canary_stage: Option<&str>,
        current: Option<&Snapshot>,
    ) -> Result<Fetch, SourceError> {
        let stage_info = self.rest_stage(api_id, stage).await?;
        let stamp = DeploymentStamp::from(&stage_info);
        let stage_settings = StageSettings::from(&stage_info);
        let shadow = match canary_stage.filter(|_| stage_settings.canary.is_some()) {
            Some(shadow) => Some((
                shadow,
                DeploymentStamp::from(&self.rest_stage(api_id, shadow).await?),
            )),
            None => None,
        };
        if let Some(current) = current
            && current.stamp.is_same_deployment(&stamp)
            && current.canary_is_current(shadow.as_ref().map(|(_, stamp)| stamp))
        {
            return Ok(Fetch::Unchanged);
        }
        let canary = match shadow {
            Some((shadow, stamp)) => Some(CanarySnapshot {
                stage: shadow.to_owned(),
                stamp,
                openapi: self.rest_export(api_id, shadow).await?,
            }),
            None => None,
        };
        Ok(Fetch::Changed(Box::new(Snapshot {
            kind: ApiKind::Rest,
            api_id: api_id.to_owned(),
            stage: Some(stage.to_owned()),
            stamp,
            stage_settings,
            openapi: self.rest_export(api_id, stage).await?,
            canary,
        })))
    }

    /// Exports the stage's deployed configuration; without a stage, `ExportApi`
    /// would return the latest, possibly undeployed, configuration.
    async fn fetch_http(
        &self,
        api_id: &str,
        stage: &str,
        current: Option<&Snapshot>,
    ) -> Result<Fetch, SourceError> {
        let stage_info = self
            .http
            .get_stage()
            .api_id(api_id)
            .stage_name(stage)
            .send()
            .await
            .map_err(SourceError::aws)?;
        let stamp = DeploymentStamp::from(&stage_info);
        if current.is_some_and(|current| current.stamp.is_same_deployment(&stamp)) {
            return Ok(Fetch::Unchanged);
        }
        let export = self
            .http
            .export_api()
            .api_id(api_id)
            .specification("OAS30")
            .output_type("JSON")
            .include_extensions(true)
            .stage_name(stage)
            .send()
            .await
            .map_err(SourceError::aws)?;
        let body = export.body.ok_or(SourceError::EmptyExport)?;
        Ok(Fetch::Changed(Box::new(Snapshot {
            kind: ApiKind::Http,
            api_id: api_id.to_owned(),
            stage: Some(stage.to_owned()),
            stamp,
            stage_settings: StageSettings::from(&stage_info),
            openapi: Export::parse(body.as_ref())?.0,
            canary: None,
        })))
    }
}

impl Snapshot {
    /// Whether the canary export this snapshot holds is the one `shadow`
    /// describes: both absent, or the same deployment of the same stage.
    fn canary_is_current(&self, shadow: Option<&DeploymentStamp>) -> bool {
        match (self.canary.as_ref(), shadow) {
            (None, None) => true,
            (Some(held), Some(stamp)) => held.stamp.is_same_deployment(stamp),
            (Some(_), None) | (None, Some(_)) => false,
        }
    }
}

impl Snapshot {
    /// # Errors
    ///
    /// When the cache file can't be read or isn't a snapshot.
    pub(crate) async fn load(path: &Path) -> Result<Self, SourceError> {
        let value = Export::read(path).await?;
        serde_json::from_value(value).map_err(|e| SourceError::Json(path.display().to_string(), e))
    }

    /// Writes via a temporary file and rename so a crash never leaves a
    /// truncated cache.
    ///
    /// # Errors
    ///
    /// When the file can't be written.
    pub(crate) async fn store(&self, path: &Path) -> Result<(), SourceError> {
        let write_err = |source| SourceError::Write {
            path: path.to_owned(),
            source,
        };
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|e| SourceError::Json(path.display().to_string(), e))?;
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        tokio::fs::write(&tmp, bytes).await.map_err(write_err)?;
        tokio::fs::rename(&tmp, path).await.map_err(write_err)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::panic, reason = "tests fail loudly on unexpected variants")]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("apigw-{}-{name}", uuid::Uuid::now_v7()))
    }

    fn snapshot() -> Snapshot {
        Snapshot {
            kind: ApiKind::Rest,
            api_id: "abc123".to_owned(),
            stage: Some("prod".to_owned()),
            stamp: DeploymentStamp {
                deployment_id: Some("d1".to_owned()),
                last_updated_epoch_ms: Some(1),
            },
            stage_settings: StageSettings {
                variables: BTreeMap::from([("k".to_owned(), "v".to_owned())]),
                ..StageSettings::default()
            },
            openapi: json!({"paths": {}}),
            canary: None,
        }
    }

    #[tokio::test]
    async fn cache_round_trips() {
        let path = scratch("cache.json");
        snapshot().store(&path).await.unwrap();
        assert_eq!(Snapshot::load(&path).await.unwrap(), snapshot());
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn caches_without_stage_fields_still_load() {
        let path = scratch("old.json");
        tokio::fs::write(
            &path,
            br#"{"kind":"http","api_id":"a","stage":null,"openapi":{}}"#,
        )
        .await
        .unwrap();
        let loaded = Snapshot::load(&path).await.unwrap();
        assert_eq!(loaded.stamp, DeploymentStamp::default());
        assert_eq!(loaded.stage_settings, StageSettings::default());
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn missing_and_corrupt_caches_are_errors() {
        let path = scratch("missing.json");
        assert!(matches!(
            Snapshot::load(&path).await,
            Err(SourceError::Read { .. })
        ));
        tokio::fs::write(&path, b"{not json").await.unwrap();
        assert!(matches!(
            Snapshot::load(&path).await,
            Err(SourceError::Json(..))
        ));
        tokio::fs::write(&path, b"{\"kind\": \"rest\"}")
            .await
            .unwrap();
        assert!(matches!(
            Snapshot::load(&path).await,
            Err(SourceError::Json(..))
        ));
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn store_reports_unwritable_paths() {
        let path = scratch("no-such-dir").join("cache.json");
        assert!(matches!(
            snapshot().store(&path).await,
            Err(SourceError::Write { .. })
        ));
    }

    #[test]
    fn exports_reject_empty_and_invalid_bodies() {
        assert!(matches!(Export::parse(b""), Err(SourceError::EmptyExport)));
        assert!(matches!(
            Export::parse(b"openapi: 3.0.1"),
            Err(SourceError::Json(..))
        ));
        assert_eq!(Export::parse(b"{\"a\":1}").unwrap().0, json!({"a": 1}));
    }

    #[tokio::test]
    async fn file_source_reads_document_every_time() {
        let path = scratch("api.json");
        tokio::fs::write(&path, b"{\"paths\":{}}").await.unwrap();
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        let fetcher = Fetcher::new(
            Source::File {
                path: path.clone(),
                kind: ApiKind::Http,
                stage: None,
            },
            &config,
        );
        let Fetch::Changed(snapshot) = fetcher.fetch(Some(&snapshot())).await.unwrap() else {
            panic!("a file source always re-reads");
        };
        assert_eq!(snapshot.kind, ApiKind::Http);
        assert_eq!(snapshot.openapi, json!({"paths": {}}));
        tokio::fs::remove_file(&path).await.unwrap();
    }

    mod shadow_stage {
        use super::*;
        use crate::observability::testing::{MockAws, Reply};

        const MAIN_STAGE: &str = "/restapis/abc/stages/prod";
        const SHADOW_STAGE: &str = "/restapis/abc/stages/shadow";

        fn stage_json(deployment: &str, canary: bool) -> Reply {
            let canary = if canary {
                r#","canarySettings":{"percentTraffic":10.0,"deploymentId":"c1"}"#
            } else {
                ""
            };
            Reply::json(&format!(
                r#"{{"deploymentId":"{deployment}","lastUpdatedDate":1700000000{canary}}}"#
            ))
        }

        fn fetcher(aws: &MockAws, canary_stage: Option<&str>) -> Fetcher {
            Fetcher::new(
                Source::RestApi {
                    api_id: "abc".to_owned(),
                    stage: "prod".to_owned(),
                    canary_stage: canary_stage.map(str::to_owned),
                },
                &aws.sdk_config(),
            )
        }

        fn exports(aws: &MockAws) -> Vec<String> {
            aws.calls()
                .into_iter()
                .map(|c| c.target)
                .filter(|t| t.ends_with("/exports/oas30"))
                .collect()
        }

        async fn changed(fetcher: &Fetcher, current: Option<&Snapshot>) -> Snapshot {
            match fetcher.fetch(current).await.unwrap() {
                Fetch::Changed(snapshot) => *snapshot,
                Fetch::Unchanged => panic!("expected a new snapshot"),
            }
        }

        fn serve(aws: &MockAws, main_has_canary: bool) {
            aws.reply(MAIN_STAGE, stage_json("d1", main_has_canary));
            aws.reply(SHADOW_STAGE, stage_json("s1", false));
            aws.reply(
                &format!("{MAIN_STAGE}/exports/oas30"),
                Reply::json(r#"{"paths":{"/main":{}}}"#),
            );
            aws.reply(
                &format!("{SHADOW_STAGE}/exports/oas30"),
                Reply::json(r#"{"paths":{"/shadow":{}}}"#),
            );
        }

        #[tokio::test]
        async fn the_shadow_stage_is_exported_for_a_canary_stage() {
            let aws = MockAws::start().await;
            serve(&aws, true);
            let snapshot = changed(&fetcher(&aws, Some("shadow")), None).await;
            assert_eq!(snapshot.openapi, json!({"paths": {"/main": {}}}));
            let canary = snapshot.canary.unwrap();
            assert_eq!(canary.stage, "shadow");
            assert_eq!(canary.stamp.deployment_id.as_deref(), Some("s1"));
            assert_eq!(canary.openapi, json!({"paths": {"/shadow": {}}}));
            assert!(snapshot.stage_settings.canary.is_some());
        }

        #[tokio::test]
        async fn nothing_is_exported_while_both_deployments_are_unchanged() {
            let aws = MockAws::start().await;
            serve(&aws, true);
            let fetcher = fetcher(&aws, Some("shadow"));
            let first = changed(&fetcher, None).await;
            let before = exports(&aws).len();
            assert!(matches!(
                fetcher.fetch(Some(&first)).await.unwrap(),
                Fetch::Unchanged
            ));
            assert_eq!(exports(&aws).len(), before);
        }

        #[tokio::test]
        async fn a_new_shadow_deployment_triggers_a_reload() {
            let aws = MockAws::start().await;
            serve(&aws, true);
            let fetcher = fetcher(&aws, Some("shadow"));
            let first = changed(&fetcher, None).await;
            aws.reply(SHADOW_STAGE, stage_json("s2", false));
            let second = changed(&fetcher, Some(&first)).await;
            assert_eq!(
                second.canary.unwrap().stamp.deployment_id.as_deref(),
                Some("s2")
            );
        }

        #[tokio::test]
        async fn the_shadow_stage_is_ignored_when_the_stage_has_no_canary() {
            let aws = MockAws::start().await;
            serve(&aws, false);
            let fetcher = fetcher(&aws, Some("shadow"));
            let snapshot = changed(&fetcher, None).await;
            assert!(snapshot.canary.is_none());
            assert!(
                aws.calls().iter().all(|c| !c.target.contains("shadow")),
                "no calls for the shadow stage"
            );
            assert!(matches!(
                fetcher.fetch(Some(&snapshot)).await.unwrap(),
                Fetch::Unchanged
            ));
        }

        #[tokio::test]
        async fn without_the_flag_no_shadow_stage_is_read() {
            let aws = MockAws::start().await;
            serve(&aws, true);
            let snapshot = changed(&fetcher(&aws, None), None).await;
            assert!(snapshot.canary.is_none());
            assert!(aws.calls().iter().all(|c| !c.target.contains("shadow")));
        }

        #[tokio::test]
        async fn a_missing_shadow_stage_fails_the_fetch() {
            let aws = MockAws::start().await;
            serve(&aws, true);
            aws.reply(SHADOW_STAGE, Reply::error("NotFoundException"));
            assert!(fetcher(&aws, Some("shadow")).fetch(None).await.is_err());
        }
    }
}
