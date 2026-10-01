//! The Terraform `parity_runner` output: where the deployed reference APIs live.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::case::ApiName;
use crate::error::{ParityError, Result};

#[derive(Debug, Clone, Deserialize)]
struct Endpoint {
    base_url: String,
}

/// The JSON written by `terraform output -json parity_runner`. Fields the runner
/// does not use (Cognito identifiers, API IDs) are ignored.
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RunnerOutputs {
    pub(crate) stage: String,
    rest: Endpoint,
    rest_policy: Endpoint,
    http: Endpoint,
    #[serde(default)]
    pub(crate) stage_variables: BTreeMap<String, String>,
}

impl RunnerOutputs {
    /// Reads the outputs file.
    ///
    /// # Errors
    /// Fails when the file cannot be read or is not the expected JSON.
    pub(crate) fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|e| ParityError::io(path, e))?;
        serde_json::from_str(&text).map_err(|source| ParityError::Json {
            path: path.to_owned(),
            source,
        })
    }

    /// The URL of `api`'s stage, without a trailing slash.
    ///
    /// # Errors
    /// [`ParityError::MissingEndpoint`] when the outputs carry an empty URL.
    pub(crate) fn base_url(&self, api: ApiName) -> Result<&str> {
        let endpoint = match api {
            ApiName::Rest => &self.rest,
            ApiName::Http => &self.http,
            ApiName::RestPolicy => &self.rest_policy,
        };
        let url = endpoint.base_url.trim_end_matches('/');
        if url.is_empty() {
            Err(ParityError::MissingEndpoint(api))
        } else {
            Ok(url)
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
    use super::*;

    const OUTPUTS: &str = r#"{
        "region": "us-east-1", "stage": "ref",
        "rest": {"api_id": "r1", "base_url": "https://r1.execute-api.us-east-1.amazonaws.com/ref/"},
        "rest_policy": {"api_id": "p1", "base_url": ""},
        "http": {"api_id": "h1", "base_url": "https://h1.execute-api.us-east-1.amazonaws.com/ref"},
        "stage_variables": {"echo_host": "x.lambda-url.us-east-1.on.aws"},
        "cognito": {"client_id": "c"}
    }"#;

    fn write(text: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "apigw-parity-outputs-{}.json",
            uuid::Uuid::now_v7()
        ));
        std::fs::write(&path, text).unwrap();
        path
    }

    #[test]
    fn terraform_output_is_parsed_and_urls_are_trimmed() {
        let path = write(OUTPUTS);
        let outputs = RunnerOutputs::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(outputs.stage, "ref");
        assert_eq!(
            outputs.base_url(ApiName::Rest).unwrap(),
            "https://r1.execute-api.us-east-1.amazonaws.com/ref"
        );
        assert!(matches!(
            outputs.base_url(ApiName::RestPolicy),
            Err(ParityError::MissingEndpoint(ApiName::RestPolicy))
        ));
        assert_eq!(
            outputs.stage_variables["echo_host"],
            "x.lambda-url.us-east-1.on.aws"
        );
    }

    #[test]
    fn missing_file_and_wrong_shape_are_errors() {
        let missing =
            std::env::temp_dir().join(format!("apigw-parity-nope-{}.json", uuid::Uuid::now_v7()));
        assert!(matches!(
            RunnerOutputs::load(&missing),
            Err(ParityError::Io { .. })
        ));
        let path = write(r#"{"stage": "ref"}"#);
        let result = RunnerOutputs::load(&path);
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(result, Err(ParityError::Json { .. })));
    }
}
