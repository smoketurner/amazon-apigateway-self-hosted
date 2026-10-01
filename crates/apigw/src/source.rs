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
    RestApi { api_id: String, stage: String },
    HttpApi { api_id: String, stage: String },
    File { path: PathBuf, kind: ApiKind },
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
    pub(crate) async fn fetch(
        &self,
        current: Option<&DeploymentStamp>,
    ) -> Result<Fetch, SourceError> {
        match self.source {
            Source::RestApi {
                ref api_id,
                ref stage,
            } => self.fetch_rest(api_id, stage, current).await,
            Source::HttpApi {
                ref api_id,
                ref stage,
            } => self.fetch_http(api_id, stage, current).await,
            Source::File { ref path, kind } => Ok(Fetch::Changed(Box::new(Snapshot {
                kind,
                api_id: path.display().to_string(),
                stage: None,
                stamp: DeploymentStamp::default(),
                stage_settings: StageSettings::default(),
                openapi: Export::read(path).await?,
            }))),
        }
    }

    async fn fetch_rest(
        &self,
        api_id: &str,
        stage: &str,
        current: Option<&DeploymentStamp>,
    ) -> Result<Fetch, SourceError> {
        let stage_info = self
            .rest
            .get_stage()
            .rest_api_id(api_id)
            .stage_name(stage)
            .send()
            .await
            .map_err(SourceError::aws)?;
        let stamp = DeploymentStamp::from(&stage_info);
        if current.is_some_and(|current| current.is_same_deployment(&stamp)) {
            return Ok(Fetch::Unchanged);
        }
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
        Ok(Fetch::Changed(Box::new(Snapshot {
            kind: ApiKind::Rest,
            api_id: api_id.to_owned(),
            stage: Some(stage.to_owned()),
            stamp,
            stage_settings: StageSettings::from(&stage_info),
            openapi: Export::parse(body.as_ref())?.0,
        })))
    }

    /// Exports the stage's deployed configuration; without a stage, `ExportApi`
    /// would return the latest, possibly undeployed, configuration.
    async fn fetch_http(
        &self,
        api_id: &str,
        stage: &str,
        current: Option<&DeploymentStamp>,
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
        if current.is_some_and(|current| current.is_same_deployment(&stamp)) {
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
        })))
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
            },
            &config,
        );
        let Fetch::Changed(snapshot) = fetcher
            .fetch(Some(&DeploymentStamp::default()))
            .await
            .unwrap()
        else {
            panic!("a file source always re-reads");
        };
        assert_eq!(snapshot.kind, ApiKind::Http);
        assert_eq!(snapshot.openapi, json!({"paths": {}}));
        tokio::fs::remove_file(&path).await.unwrap();
    }
}
