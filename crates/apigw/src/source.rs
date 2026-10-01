//! Downloads an API definition from API Gateway (or reads it from disk) and keeps
//! a last-known-good copy so the gateway can start while AWS is unreachable.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::spec::ApiKind;

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

/// Everything needed to rebuild the routes, in a form that round-trips through
/// the on-disk cache.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Snapshot {
    pub(crate) kind: ApiKind,
    pub(crate) api_id: String,
    pub(crate) stage: Option<String>,
    #[serde(default)]
    pub(crate) stage_variables: BTreeMap<String, String>,
    pub(crate) openapi: Value,
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

fn aws_error(err: impl std::error::Error) -> SourceError {
    SourceError::Aws(aws_sdk_apigateway::error::DisplayErrorContext(err).to_string())
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

    pub(crate) async fn fetch(&self) -> Result<Snapshot, SourceError> {
        match self.source {
            Source::RestApi {
                ref api_id,
                ref stage,
            } => self.fetch_rest(api_id, stage).await,
            Source::HttpApi {
                ref api_id,
                ref stage,
            } => self.fetch_http(api_id, stage).await,
            Source::File { ref path, kind } => {
                let openapi = read_json(path).await?;
                Ok(Snapshot {
                    kind,
                    api_id: path.display().to_string(),
                    stage: None,
                    stage_variables: BTreeMap::new(),
                    openapi,
                })
            }
        }
    }

    async fn fetch_rest(&self, api_id: &str, stage: &str) -> Result<Snapshot, SourceError> {
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
            .map_err(aws_error)?;
        let body = export.body.ok_or(SourceError::EmptyExport)?;
        let openapi = parse_export(body.as_ref())?;
        let stage_info = self
            .rest
            .get_stage()
            .rest_api_id(api_id)
            .stage_name(stage)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(Snapshot {
            kind: ApiKind::Rest,
            api_id: api_id.to_owned(),
            stage: Some(stage.to_owned()),
            stage_variables: into_sorted(stage_info.variables),
            openapi,
        })
    }

    /// Exports the stage's deployed configuration; without a stage, `ExportApi`
    /// would return the latest, possibly undeployed, configuration.
    async fn fetch_http(&self, api_id: &str, stage: &str) -> Result<Snapshot, SourceError> {
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
            .map_err(aws_error)?;
        let body = export.body.ok_or(SourceError::EmptyExport)?;
        let openapi = parse_export(body.as_ref())?;
        let stage_info = self
            .http
            .get_stage()
            .api_id(api_id)
            .stage_name(stage)
            .send()
            .await
            .map_err(aws_error)?;
        Ok(Snapshot {
            kind: ApiKind::Http,
            api_id: api_id.to_owned(),
            stage: Some(stage.to_owned()),
            stage_variables: into_sorted(stage_info.stage_variables),
            openapi,
        })
    }
}

fn into_sorted(map: Option<HashMap<String, String>>) -> BTreeMap<String, String> {
    map.map(|m| m.into_iter().collect()).unwrap_or_default()
}

fn parse_export(body: &[u8]) -> Result<Value, SourceError> {
    if body.is_empty() {
        return Err(SourceError::EmptyExport);
    }
    serde_json::from_slice(body).map_err(|e| SourceError::Json("API Gateway export".to_owned(), e))
}

async fn read_json(path: &Path) -> Result<Value, SourceError> {
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|source| SourceError::Read {
            path: path.to_owned(),
            source,
        })?;
    serde_json::from_slice(&bytes).map_err(|e| SourceError::Json(path.display().to_string(), e))
}

pub(crate) async fn load_cache(path: &Path) -> Result<Snapshot, SourceError> {
    let value = read_json(path).await?;
    serde_json::from_value(value).map_err(|e| SourceError::Json(path.display().to_string(), e))
}

/// Writes via a temporary file and rename so a crash never leaves a truncated cache.
pub(crate) async fn store_cache(path: &Path, snapshot: &Snapshot) -> Result<(), SourceError> {
    let write_err = |source| SourceError::Write {
        path: path.to_owned(),
        source,
    };
    let bytes = serde_json::to_vec_pretty(snapshot)
        .map_err(|e| SourceError::Json(path.display().to_string(), e))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    tokio::fs::write(&tmp, bytes).await.map_err(write_err)?;
    tokio::fs::rename(&tmp, path).await.map_err(write_err)
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use serde_json::json;

    use super::*;

    fn scratch(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("apigw-{}-{name}", uuid::Uuid::now_v7()))
    }

    #[tokio::test]
    async fn cache_round_trips() {
        let path = scratch("cache.json");
        let snapshot = Snapshot {
            kind: ApiKind::Rest,
            api_id: "abc123".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: BTreeMap::from([("k".to_owned(), "v".to_owned())]),
            openapi: json!({"paths": {}}),
        };
        store_cache(&path, &snapshot).await.unwrap();
        assert_eq!(load_cache(&path).await.unwrap(), snapshot);
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn missing_and_corrupt_caches_are_errors() {
        let path = scratch("missing.json");
        assert!(matches!(
            load_cache(&path).await,
            Err(SourceError::Read { .. })
        ));
        tokio::fs::write(&path, b"{not json").await.unwrap();
        assert!(matches!(
            load_cache(&path).await,
            Err(SourceError::Json(..))
        ));
        tokio::fs::write(&path, b"{\"kind\": \"rest\"}")
            .await
            .unwrap();
        assert!(matches!(
            load_cache(&path).await,
            Err(SourceError::Json(..))
        ));
        tokio::fs::remove_file(&path).await.unwrap();
    }

    #[tokio::test]
    async fn store_cache_reports_unwritable_paths() {
        let path = scratch("no-such-dir").join("cache.json");
        let snapshot = Snapshot {
            kind: ApiKind::Http,
            api_id: "x".to_owned(),
            stage: None,
            stage_variables: BTreeMap::new(),
            openapi: json!({}),
        };
        assert!(matches!(
            store_cache(&path, &snapshot).await,
            Err(SourceError::Write { .. })
        ));
    }

    #[test]
    fn parse_export_rejects_empty_and_invalid_bodies() {
        assert!(matches!(parse_export(b""), Err(SourceError::EmptyExport)));
        assert!(matches!(
            parse_export(b"openapi: 3.0.1"),
            Err(SourceError::Json(..))
        ));
        assert_eq!(parse_export(b"{\"a\":1}").unwrap(), json!({"a": 1}));
    }

    #[tokio::test]
    async fn file_source_reads_document() {
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
        let snapshot = fetcher.fetch().await.unwrap();
        assert_eq!(snapshot.kind, ApiKind::Http);
        assert_eq!(snapshot.openapi, json!({"paths": {}}));
        tokio::fs::remove_file(&path).await.unwrap();
    }
}
