//! The raw `OpenAPI` export of a reference API plus its stage variables, stored with
//! the fixtures so replay can serve exactly the definition that was recorded.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::case::ApiName;
use crate::error::{ParityError, Result};
use crate::fixture::{FixtureSource, write_json};
use crate::normalize::Redactor;

const ANY_METHOD_KEY: &str = "x-amazon-apigateway-any-method";
const INTEGRATION_KEY: &str = "x-amazon-apigateway-integration";
const HTTP_API_DEFAULT_PATH: &str = "/$default";
const HTTP_METHODS: [&str; 7] = ["get", "put", "post", "delete", "options", "head", "patch"];

/// One API's export and the stage variables it was deployed with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExportRecord {
    pub(crate) source: FixtureSource,
    pub(crate) api: ApiName,
    pub(crate) stage: String,
    #[serde(default)]
    pub(crate) stage_variables: BTreeMap<String, String>,
    pub(crate) openapi: Value,
}

/// A directory of `<api>.json` export records.
#[derive(Debug, Clone)]
pub(crate) struct ExportStore {
    dir: PathBuf,
}

impl ExportStore {
    pub(crate) fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn path(&self, api: ApiName) -> PathBuf {
        self.dir.join(format!("{}.json", api.file_stem()))
    }

    /// Reads the export record for `api`.
    ///
    /// # Errors
    /// [`ParityError::MissingExport`] when there is none; other I/O and JSON errors
    /// when it cannot be read or parsed.
    pub(crate) fn load(&self, api: ApiName) -> Result<ExportRecord> {
        let path = self.path(api);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ParityError::MissingExport(api));
            }
            Err(e) => return Err(ParityError::io(path, e)),
        };
        serde_json::from_str(&text).map_err(|source| ParityError::Json { path, source })
    }

    /// Writes `record`.
    ///
    /// # Errors
    /// Fails when the file cannot be written.
    pub(crate) fn save(&self, record: &ExportRecord) -> Result<()> {
        write_json(&self.path(record.api), record)
    }
}

/// The files an operator downloads for one API: `<api>.openapi.json` from
/// `aws apigateway get-export` (or `aws apigatewayv2 export-api`), and optionally
/// `<api>.stage.json` from `get-stage`.
#[derive(Debug, Clone)]
pub(crate) struct ExportInput {
    dir: PathBuf,
}

impl ExportInput {
    pub(crate) fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// Builds the redacted record for `api` deployed to `stage`, or `None` when no export file for it
    /// was downloaded. `fallback_variables` (from the Terraform outputs) are used
    /// when there is no stage file.
    ///
    /// # Errors
    /// Fails when a downloaded file cannot be read or is not JSON.
    pub(crate) fn record(
        &self,
        api: ApiName,
        stage: &str,
        fallback_variables: &BTreeMap<String, String>,
        redactor: &Redactor,
    ) -> Result<Option<ExportRecord>> {
        let openapi_path = self.dir.join(format!("{}.openapi.json", api.file_stem()));
        let Some(mut openapi) = read_optional_json(&openapi_path)? else {
            return Ok(None);
        };
        redactor.redact_json(&mut openapi);
        let stage_path = self.dir.join(format!("{}.stage.json", api.file_stem()));
        let mut stage_variables = match read_optional_json(&stage_path)? {
            Some(stage) => Self::stage_variables(&stage),
            None => fallback_variables.clone(),
        };
        for (name, value) in &mut stage_variables {
            *value = redactor.redact_entry(name, value);
        }
        Ok(Some(ExportRecord {
            source: FixtureSource::Recorded,
            api,
            stage: stage.to_owned(),
            stage_variables,
            openapi,
        }))
    }

    /// Reads `variables` (REST `get-stage`) or `stageVariables` (HTTP `get-stage`).
    fn stage_variables(stage: &Value) -> BTreeMap<String, String> {
        let variables = stage
            .get("variables")
            .or_else(|| stage.get("stageVariables"));
        let mut out = BTreeMap::new();
        if let Some(Value::Object(members)) = variables {
            for (name, value) in members {
                if let Some(text) = value.as_str() {
                    out.insert(name.clone(), text.to_owned());
                }
            }
        }
        out
    }
}

fn read_optional_json(path: &Path) -> Result<Option<Value>> {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(ParityError::io(path, e)),
    };
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|source| ParityError::Json {
            path: path.to_owned(),
            source,
        })
}

/// Integration overrides, keyed by apigw route key, shaped like the JSON file
/// `--integration-overrides` reads.
pub(crate) type OverrideMap = BTreeMap<String, Value>;

impl ExportRecord {
    /// Overrides that re-point every integration whose URI is built from the
    /// stage variable `variable` to plain HTTP, so it can reach the in-process echo
    /// (whose address is passed as that stage variable's value). Everything else in
    /// the export is served unchanged.
    pub(crate) fn echo_overrides(&self, variable: &str) -> OverrideMap {
        let marker = format!("${{stageVariables.{variable}}}");
        let mut overrides = OverrideMap::new();
        let Some(Value::Object(paths)) = self.openapi.get("paths") else {
            return overrides;
        };
        for (path, item) in paths {
            let Value::Object(operations) = item else {
                continue;
            };
            for (key, operation) in operations {
                let Some(method) = Self::method_label(key) else {
                    continue;
                };
                let Some(integration) = operation.get(INTEGRATION_KEY) else {
                    continue;
                };
                let Some(uri) = integration.get("uri").and_then(Value::as_str) else {
                    continue;
                };
                let Some(rest) = uri.strip_prefix("https://") else {
                    continue;
                };
                if !rest.starts_with(&marker) {
                    continue;
                }
                let mut replacement = integration.clone();
                if let Value::Object(ref mut members) = replacement {
                    members.insert("uri".to_owned(), Value::String(format!("http://{rest}")));
                }
                overrides.insert(Self::route_key(&method, path), replacement);
            }
        }
        overrides
    }

    fn method_label(key: &str) -> Option<String> {
        if key == ANY_METHOD_KEY {
            Some("ANY".to_owned())
        } else if HTTP_METHODS.contains(&key) {
            Some(key.to_ascii_uppercase())
        } else {
            None
        }
    }

    fn route_key(method: &str, path: &str) -> String {
        if path == HTTP_API_DEFAULT_PATH {
            "$default".to_owned()
        } else {
            format!("{method} {path}")
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known shape"
)]
mod tests {
    use serde_json::json;

    use super::*;

    fn record() -> ExportRecord {
        ExportRecord {
            source: FixtureSource::HandWritten,
            api: ApiName::Rest,
            stage: "ref".to_owned(),
            stage_variables: BTreeMap::from([("echo_host".to_owned(), "h.example".to_owned())]),
            openapi: json!({
                "paths": {
                    "/http-proxy/{proxy+}": {
                        "x-amazon-apigateway-any-method": {
                            "x-amazon-apigateway-integration": {
                                "type": "http_proxy",
                                "httpMethod": "ANY",
                                "uri": "https://${stageVariables.echo_host}/http-proxy/{proxy}",
                                "timeoutInMillis": 5000
                            }
                        }
                    },
                    "/other": {
                        "get": {"x-amazon-apigateway-integration": {"type": "http_proxy", "uri": "https://example.com/x"}},
                        "parameters": []
                    },
                    "/mock": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}}},
                    "/$default": {
                        "x-amazon-apigateway-any-method": {
                            "x-amazon-apigateway-integration": {"type": "http_proxy", "uri": "https://${stageVariables.echo_host}/d"}
                        }
                    },
                    "/plain": {"post": {"x-amazon-apigateway-integration": {"type": "http_proxy", "uri": "http://${stageVariables.echo_host}/p"}}}
                }
            }),
        }
    }

    #[test]
    fn echo_integrations_are_repointed_to_http() {
        let overrides = record().echo_overrides("echo_host");
        let keys: Vec<_> = overrides.keys().map(String::as_str).collect();
        assert_eq!(keys, ["$default", "ANY /http-proxy/{proxy+}"]);
        let proxy = &overrides["ANY /http-proxy/{proxy+}"];
        assert_eq!(
            proxy["uri"],
            "http://${stageVariables.echo_host}/http-proxy/{proxy}"
        );
        assert_eq!(proxy["timeoutInMillis"], 5000);
        assert_eq!(proxy["type"], "http_proxy");
    }

    #[test]
    fn exports_without_paths_or_a_matching_variable_yield_no_overrides() {
        let mut empty = record();
        empty.openapi = json!({});
        assert!(empty.echo_overrides("echo_host").is_empty());
        assert!(record().echo_overrides("other_variable").is_empty());
    }

    #[test]
    fn input_files_are_redacted_and_stage_variables_prefer_the_stage_file() {
        let dir =
            std::env::temp_dir().join(format!("apigw-parity-export-{}", uuid::Uuid::now_v7()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("rest.openapi.json"),
            r#"{"paths":{"/x":{"get":{"x-amazon-apigateway-integration":{"uri":"arn:aws:lambda:us-east-1:123456789012:function:f"}}}}}"#,
        )
        .unwrap();
        let input = ExportInput::new(&dir);
        let fallback = BTreeMap::from([("echo_host".to_owned(), "fallback.example".to_owned())]);
        let redactor = Redactor::default();

        let record = input
            .record(ApiName::Rest, "ref", &fallback, &redactor)
            .unwrap()
            .unwrap();
        assert_eq!(record.source, FixtureSource::Recorded);
        assert_eq!(record.stage_variables["echo_host"], "fallback.example");
        assert!(record.openapi.to_string().contains("[account-id]"));
        assert!(!record.openapi.to_string().contains("123456789012"));

        std::fs::write(
            dir.join("rest.stage.json"),
            r#"{"variables":{"echo_host":"stage.example","echo_secret":"hunter2hunter2"}}"#,
        )
        .unwrap();
        let record = input
            .record(ApiName::Rest, "ref", &fallback, &redactor)
            .unwrap()
            .unwrap();
        assert_eq!(record.stage_variables["echo_host"], "stage.example");
        assert_eq!(record.stage_variables["echo_secret"], "[redacted]");

        assert!(
            input
                .record(ApiName::Http, "ref", &fallback, &redactor)
                .unwrap()
                .is_none()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn http_stage_files_use_stage_variables_key() {
        let stage = json!({"stageVariables": {"a": "b", "n": 1}});
        let variables = ExportInput::stage_variables(&stage);
        assert_eq!(
            variables,
            BTreeMap::from([("a".to_owned(), "b".to_owned())])
        );
    }

    #[test]
    fn store_round_trips_and_reports_missing_exports() {
        let dir =
            std::env::temp_dir().join(format!("apigw-parity-export-{}", uuid::Uuid::now_v7()));
        let store = ExportStore::new(&dir);
        assert!(matches!(
            store.load(ApiName::Http),
            Err(ParityError::MissingExport(ApiName::Http))
        ));
        store.save(&record()).unwrap();
        assert_eq!(store.load(ApiName::Rest).unwrap(), record());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
