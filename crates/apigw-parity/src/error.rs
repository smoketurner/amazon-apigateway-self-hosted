//! The error type shared by every module of the parity runner.

use std::path::PathBuf;

use crate::case::{ApiName, CaseName};

pub(crate) type Result<T> = std::result::Result<T, ParityError>;

#[derive(Debug, thiserror::Error)]
pub(crate) enum ParityError {
    #[error("cannot access {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not valid YAML for this tool: {message}")]
    Yaml { path: PathBuf, message: String },
    #[error("{path} is not valid JSON for this tool: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("case name {0:?} must be 1-100 characters of a-z, 0-9, '-' or '_'")]
    InvalidCaseName(String),
    #[error("case {0} is defined more than once")]
    DuplicateCase(CaseName),
    #[error("case {case} needs environment variable {variable}, which is not set")]
    MissingEnv { case: CaseName, variable: String },
    #[error("case {case} has an unterminated {{{{env:...}}}} placeholder")]
    UnterminatedPlaceholder { case: CaseName },
    #[error("no fixture for case {0}; run `apigw-parity record` first")]
    MissingFixture(CaseName),
    #[error("no export for the {0} API; run `apigw-parity record` with its export files")]
    MissingExport(ApiName),
    #[error("outputs file has no base URL for the {0} API")]
    MissingEndpoint(ApiName),
    #[error("request for case {case} failed: {source}")]
    Request {
        case: CaseName,
        source: reqwest::Error,
    },
    #[error("case {case} expects an echo response but the body is not an echo event: {reason}")]
    NotAnEcho { case: CaseName, reason: String },
    #[error("cannot start {what}: {reason}")]
    Start { what: &'static str, reason: String },
    #[error("apigw did not become healthy within {seconds} seconds")]
    NotReady { seconds: u64 },
    #[error("{0} case(s) did not match their fixtures")]
    Mismatches(usize),
}

impl ParityError {
    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
}
