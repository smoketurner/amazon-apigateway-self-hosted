use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::gateway::{AuthorizationMode, Enforcement, Unsupported};
use crate::model::ApiKind;
use crate::router::BasePath;
use crate::source::Source;

const STAGE_VARIABLE_ENV_PREFIX: &str = "APIGW_STAGE_VARIABLE_";

/// Serves the routes of an existing Amazon API Gateway REST or HTTP API from a
/// self-hosted container, refreshing them as the API changes.
#[derive(Debug, Parser)]
#[command(version, about)]
#[command(group(ArgGroup::new("api").required(true).args(["rest_api_id", "http_api_id", "openapi_file"])))]
pub(crate) struct Config {
    /// REST API (v1) to mirror. Requires --stage.
    #[arg(long, env = "APIGW_REST_API_ID", requires = "stage")]
    pub(crate) rest_api_id: Option<String>,

    /// HTTP API (v2) to mirror. Requires --stage.
    #[arg(long, env = "APIGW_HTTP_API_ID", requires = "stage")]
    pub(crate) http_api_id: Option<String>,

    /// Serve an `OpenAPI` export from disk instead of downloading one.
    #[arg(long, env = "APIGW_OPENAPI_FILE")]
    pub(crate) openapi_file: Option<PathBuf>,

    /// API Gateway product the --openapi-file was exported from.
    #[arg(long, env = "APIGW_API_TYPE", value_enum, default_value_t = ApiKind::Rest)]
    pub(crate) api_type: ApiKind,

    /// Stage to export, and to read stage variables from.
    #[arg(long, env = "APIGW_STAGE")]
    pub(crate) stage: Option<String>,

    /// Prefix every route with this path, e.g. `/prod` to match an execute-api URL.
    #[arg(long, env = "APIGW_BASE_PATH", default_value = "")]
    pub(crate) base_path: BasePath,

    /// Override a stage variable (repeatable). `APIGW_STAGE_VARIABLE_<name>=<value>`
    /// environment variables do the same.
    #[arg(long = "stage-variable", value_name = "NAME=VALUE", value_parser = parse_key_value)]
    pub(crate) stage_variables: Vec<(String, String)>,

    /// JSON file mapping route keys (`GET /pets/{petId}`) to replacement
    /// `x-amazon-apigateway-integration` objects. Re-read on every refresh.
    #[arg(long, env = "APIGW_INTEGRATION_OVERRIDES")]
    pub(crate) integration_overrides: Option<PathBuf>,

    /// Seconds between configuration refreshes; 0 disables refreshing.
    #[arg(long, env = "APIGW_REFRESH_SECONDS", default_value_t = 60)]
    pub(crate) refresh_seconds: u64,

    /// Last-known-good configuration, written after every successful download
    /// and used at startup when API Gateway cannot be reached.
    #[arg(long = "config-cache", env = "APIGW_CONFIG_CACHE")]
    pub(crate) cache: Option<PathBuf>,

    /// Serve routes that have an authorizer, IAM auth, or API key requirement
    /// without checking credentials. Only for deployments that authenticate in
    /// front of the gateway; by default such routes answer 401.
    #[arg(long, env = "APIGW_INSECURE_SKIP_AUTHORIZATION")]
    pub(crate) insecure_skip_authorization: bool,

    /// What to do with routes under a resource policy, which this gateway does
    /// not evaluate yet: `reject` answers 403, `ignore` serves them unrestricted.
    /// Not affected by --insecure-skip-authorization.
    #[arg(long, env = "APIGW_UNSUPPORTED_RESOURCE_POLICY", value_enum, default_value_t = Unsupported::Reject)]
    pub(crate) unsupported_resource_policy: Unsupported,

    /// What to do with routes that have a request validator, which this gateway
    /// does not run yet: `reject` answers 501, `ignore` forwards unvalidated requests.
    #[arg(long, env = "APIGW_UNSUPPORTED_VALIDATION", value_enum, default_value_t = Unsupported::Reject)]
    pub(crate) unsupported_validation: Unsupported,

    /// Address for API traffic.
    #[arg(long, env = "APIGW_LISTEN", default_value = "0.0.0.0:8443")]
    pub(crate) listen: SocketAddr,

    /// Address for `/healthz` and `/routes`. Disabled when unset.
    #[arg(long, env = "APIGW_ADMIN_LISTEN")]
    pub(crate) admin_listen: Option<SocketAddr>,

    /// PEM certificate chain served on every listener. Reloaded when it changes.
    #[arg(long, env = "APIGW_TLS_CERT")]
    pub(crate) tls_cert: PathBuf,

    /// PEM private key for --tls-cert. Reloaded when it changes.
    #[arg(long, env = "APIGW_TLS_KEY")]
    pub(crate) tls_key: PathBuf,

    /// Maximum concurrent connections per listener.
    #[arg(long, env = "APIGW_MAX_CONNECTIONS", default_value_t = 10_000)]
    pub(crate) max_connections: usize,

    #[arg(long, env = "APIGW_LOG_FORMAT", value_enum, default_value_t = LogFormat::Json)]
    pub(crate) log_format: LogFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum LogFormat {
    Json,
    Text,
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    match s.split_once('=') {
        Some((key, value)) if !key.is_empty() => Ok((key.to_owned(), value.to_owned())),
        Some(_) | None => Err(format!("expected NAME=VALUE, got {s:?}")),
    }
}

impl Config {
    pub(crate) fn source(&self) -> Source {
        match (&self.rest_api_id, &self.http_api_id, &self.openapi_file) {
            (Some(api_id), _, _) => Source::RestApi {
                api_id: api_id.clone(),
                stage: self.stage.clone().unwrap_or_default(),
            },
            (None, Some(api_id), _) => Source::HttpApi {
                api_id: api_id.clone(),
                stage: self.stage.clone().unwrap_or_default(),
            },
            (None, None, path) => Source::File {
                path: path.clone().unwrap_or_default(),
                kind: self.api_type,
            },
        }
    }

    pub(crate) fn enforcement(&self) -> Enforcement {
        Enforcement {
            authorization: if self.insecure_skip_authorization {
                AuthorizationMode::Skip
            } else {
                AuthorizationMode::Enforce
            },
            resource_policy: self.unsupported_resource_policy,
            request_validation: self.unsupported_validation,
        }
    }

    pub(crate) fn refresh_interval(&self) -> Option<Duration> {
        (self.refresh_seconds > 0).then(|| Duration::from_secs(self.refresh_seconds))
    }

    /// Local stage-variable overrides: environment variables first, then flags,
    /// so a flag wins over an environment variable of the same name.
    pub(crate) fn stage_variable_overrides(
        &self,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> BTreeMap<String, String> {
        let mut overrides = BTreeMap::new();
        for (key, value) in env {
            if let Some(name) = key.strip_prefix(STAGE_VARIABLE_ENV_PREFIX)
                && !name.is_empty()
            {
                overrides.insert(name.to_owned(), value);
            }
        }
        for (key, value) in &self.stage_variables {
            overrides.insert(key.clone(), value.clone());
        }
        overrides
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    const TLS: [&str; 4] = ["--tls-cert", "c.pem", "--tls-key", "k.pem"];

    fn parse(args: &[&str]) -> Result<Config, clap::Error> {
        Config::try_parse_from(["apigw"].iter().chain(args).chain(TLS.iter()))
    }

    #[test]
    fn rest_api_requires_stage() {
        assert!(parse(&["--rest-api-id", "abc"]).is_err());
        let config = parse(&["--rest-api-id", "abc", "--stage", "prod"]).unwrap();
        assert!(
            matches!(config.source(), Source::RestApi { ref api_id, ref stage } if api_id == "abc" && stage == "prod")
        );
    }

    #[test]
    fn exactly_one_api_source_is_required() {
        assert!(parse(&[]).is_err());
        assert!(
            parse(&[
                "--http-api-id",
                "a",
                "--stage",
                "s",
                "--openapi-file",
                "x.json"
            ])
            .is_err()
        );
        let config = parse(&["--openapi-file", "x.json", "--api-type", "http"]).unwrap();
        assert!(matches!(
            config.source(),
            Source::File {
                kind: ApiKind::Http,
                ..
            }
        ));
        let config = parse(&["--http-api-id", "a", "--stage", "s"]).unwrap();
        assert!(matches!(config.source(), Source::HttpApi { ref stage, .. } if stage == "s"));
    }

    #[test]
    fn http_api_requires_stage() {
        assert!(parse(&["--http-api-id", "a"]).is_err());
    }

    #[test]
    fn unsupported_protections_are_rejected_unless_ignored() {
        let config = parse(&["--http-api-id", "a", "--stage", "s"]).unwrap();
        assert_eq!(
            config.enforcement(),
            Enforcement {
                authorization: AuthorizationMode::Enforce,
                resource_policy: Unsupported::Reject,
                request_validation: Unsupported::Reject,
            }
        );
        let config = parse(&[
            "--http-api-id",
            "a",
            "--stage",
            "s",
            "--insecure-skip-authorization",
            "--unsupported-resource-policy",
            "ignore",
            "--unsupported-validation",
            "ignore",
        ])
        .unwrap();
        assert_eq!(
            config.enforcement(),
            Enforcement {
                authorization: AuthorizationMode::Skip,
                resource_policy: Unsupported::Ignore,
                request_validation: Unsupported::Ignore,
            }
        );
        assert!(
            parse(&[
                "--http-api-id",
                "a",
                "--stage",
                "s",
                "--unsupported-validation",
                "maybe"
            ])
            .is_err()
        );
    }

    #[test]
    fn tls_is_required() {
        assert!(Config::try_parse_from(["apigw", "--http-api-id", "a", "--stage", "s"]).is_err());
    }

    #[test]
    fn refresh_zero_disables() {
        assert_eq!(
            parse(&[
                "--http-api-id",
                "a",
                "--stage",
                "s",
                "--refresh-seconds",
                "0"
            ])
            .unwrap()
            .refresh_interval(),
            None
        );
        assert_eq!(
            parse(&["--http-api-id", "a", "--stage", "s"])
                .unwrap()
                .refresh_interval(),
            Some(Duration::from_secs(60))
        );
    }

    #[test]
    fn stage_variable_flags_override_environment() {
        let config = parse(&[
            "--http-api-id",
            "a",
            "--stage",
            "s",
            "--stage-variable",
            "host=flag",
            "--stage-variable",
            "empty=",
        ])
        .unwrap();
        let env = [
            ("APIGW_STAGE_VARIABLE_host".to_owned(), "env".to_owned()),
            (
                "APIGW_STAGE_VARIABLE_backendHost".to_owned(),
                "pets.internal".to_owned(),
            ),
            ("APIGW_STAGE_VARIABLE_".to_owned(), "ignored".to_owned()),
            ("UNRELATED".to_owned(), "x".to_owned()),
        ];
        let merged = config.stage_variable_overrides(env);
        assert_eq!(
            merged,
            BTreeMap::from([
                ("backendHost".to_owned(), "pets.internal".to_owned()),
                ("empty".to_owned(), String::new()),
                ("host".to_owned(), "flag".to_owned()),
            ])
        );
        assert!(
            parse(&[
                "--http-api-id",
                "a",
                "--stage",
                "s",
                "--stage-variable",
                "novalue"
            ])
            .is_err()
        );
        assert!(
            parse(&[
                "--http-api-id",
                "a",
                "--stage",
                "s",
                "--stage-variable",
                "=v"
            ])
            .is_err()
        );
    }
}
