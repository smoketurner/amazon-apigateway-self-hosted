use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroU32};
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgGroup, Parser, ValueEnum};

use crate::aws::{CredentialsMode, LambdaEndpoint, LambdaEndpoints};
use crate::gateway::{AuthorizationMode, Enforcement, Unsupported};
use crate::identity::{TrustedProxies, TrustedProxy};
use crate::listener::{Edge, ProxyProtocol};
use crate::model::ApiKind;
use crate::observability::{
    Delivery, LogGroup, MetricsNamespace, MetricsSettings, Settings, StreamName, TraceDelivery,
};
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

    /// A stage that holds the canary deployment of --stage. API Gateway cannot
    /// export a canary deployment, so without this the canary release has the
    /// stage's routes and differs only in stage variables.
    #[arg(long, env = "APIGW_CANARY_EXPORT_STAGE", requires = "rest_api_id")]
    pub(crate) canary_export_stage: Option<String>,

    /// Stage to export, and to read stage variables from. With --openapi-file it
    /// only names the stage for `$context.stage`.
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

    /// Whose credentials integrations with a `credentials` role use: `assume`
    /// assumes that role (its trust policy must allow the gateway's principal),
    /// `gateway` uses the gateway's own credentials.
    #[arg(long, env = "APIGW_INTEGRATION_CREDENTIALS", value_enum, default_value_t = CredentialsMode::Assume)]
    pub(crate) integration_credentials: CredentialsMode,

    /// Serve a Lambda function from a URL speaking Lambda's Invoke protocol, such
    /// as the Lambda Runtime Interface Emulator in a pod (repeatable;
    /// `FUNCTION` is a function name or ARN).
    #[arg(
        long = "lambda-endpoint",
        value_name = "FUNCTION=URL",
        env = "APIGW_LAMBDA_ENDPOINTS",
        value_delimiter = ','
    )]
    pub(crate) lambda_endpoints: Vec<LambdaEndpoint>,

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

    /// Proxies, as CIDR blocks or addresses, whose `X-Forwarded-For` and
    /// `X-Forwarded-Client-Cert` headers are believed. A peer outside this list is
    /// the client, and its forwarding headers are replaced or removed.
    #[arg(
        long,
        env = "APIGW_TRUSTED_PROXIES",
        value_delimiter = ',',
        value_name = "CIDR,..."
    )]
    pub(crate) trusted_proxies: Vec<TrustedProxy>,

    /// Trusted proxies in front of the gateway, counting the one that connects to
    /// it: 1 reads the client from the last `X-Forwarded-For` entry, 2 from the one
    /// before it.
    #[arg(long, env = "APIGW_TRUSTED_PROXY_HOPS", default_value_t = NonZeroU8::MIN, requires = "trusted_proxies")]
    pub(crate) trusted_proxy_hops: NonZeroU8,

    /// Require a PROXY protocol v2 header on the API listener, from
    /// --trusted-proxies only; its source address is the client.
    #[arg(long, env = "APIGW_PROXY_PROTOCOL", requires = "trusted_proxies")]
    pub(crate) proxy_protocol: bool,

    /// How many gateway replicas serve this API. Throttle limits are divided by
    /// this count because each replica keeps its own buckets, so the API-wide rate
    /// is approximately the configured one. A replica's bucket always holds at
    /// least one token, so with more replicas than burst tokens the API-wide burst
    /// is larger than configured.
    #[arg(long, env = "APIGW_REPLICAS", default_value_t = NonZeroU32::MIN)]
    pub(crate) replicas: NonZeroU32,

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

    /// Where access logs go: `aws` writes to the destination in the stage's
    /// access log settings (CloudWatch Logs or Firehose, standard output when
    /// the stage names none), `stdout` writes lines to standard output without
    /// calling AWS, `off` writes none.
    #[arg(long, env = "APIGW_ACCESS_LOGS", value_enum, default_value_t = Delivery::Aws)]
    pub(crate) access_logs: Delivery,

    /// Where execution logs (`loggingLevel`, `dataTraceEnabled`) go: `aws` writes
    /// to the stage's `API-Gateway-Execution-Logs_{apiId}/{stage}` log group.
    #[arg(long, env = "APIGW_EXECUTION_LOGS", value_enum, default_value_t = Delivery::Aws)]
    pub(crate) execution_logs: Delivery,

    /// CloudWatch Logs log group that receives metrics as embedded metric
    /// format events. Metrics are not published when unset. The group must exist.
    #[arg(long, env = "APIGW_METRICS_LOG_GROUP")]
    pub(crate) metrics_log_group: Option<String>,

    /// CloudWatch namespace for published metrics; `AWS/` namespaces are reserved.
    #[arg(long, env = "APIGW_METRICS_NAMESPACE", default_value_t = MetricsNamespace::default(), value_parser = clap::value_parser!(MetricsNamespace))]
    pub(crate) metrics_namespace: MetricsNamespace,

    /// What stage tracing does: `aws` sends X-Ray segments for stages with
    /// tracing enabled and propagates `X-Amzn-Trace-Id` and `traceparent` to
    /// integrations; `off` does neither.
    #[arg(long, env = "APIGW_TRACING", value_enum, default_value_t = TraceDelivery::Aws)]
    pub(crate) tracing: TraceDelivery,

    /// Percentage of requests X-Ray traces after the first request each second,
    /// when the caller made no sampling decision (X-Ray's default rule is 5).
    #[arg(long, env = "APIGW_XRAY_SAMPLING_PERCENT", default_value_t = 5, value_parser = clap::value_parser!(u8).range(..=100))]
    pub(crate) xray_sampling_percent: u8,

    /// Log stream this process writes to in each CloudWatch Logs log group.
    /// Defaults to `{HOSTNAME}/{start time}/{random suffix}`, unique per process.
    #[arg(long, env = "APIGW_LOG_STREAM")]
    pub(crate) log_stream: Option<String>,
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
                canary_stage: self.canary_export_stage.clone(),
            },
            (None, Some(api_id), _) => Source::HttpApi {
                api_id: api_id.clone(),
                stage: self.stage.clone().unwrap_or_default(),
            },
            (None, None, path) => Source::File {
                path: path.clone().unwrap_or_default(),
                kind: self.api_type,
                stage: self.stage.clone(),
            },
        }
    }

    pub(crate) fn lambda_endpoints(&self) -> LambdaEndpoints {
        self.lambda_endpoints
            .iter()
            .map(|LambdaEndpoint(function, url)| (function.clone(), url.clone()))
            .collect()
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

    /// What to deliver to CloudWatch and how. `hostname` names the pod in the
    /// default log stream name.
    pub(crate) fn observability(&self, hostname: Option<&str>) -> Settings {
        Settings {
            access_logs: self.access_logs,
            execution_logs: self.execution_logs,
            metrics: self
                .metrics_log_group
                .as_deref()
                .map(|group| MetricsSettings {
                    group: LogGroup::new(group),
                    namespace: self.metrics_namespace.clone(),
                }),
            tracing: self.tracing,
            sampling_percent: self.xray_sampling_percent,
            stream: StreamName::for_pod(
                self.log_stream.as_deref(),
                hostname,
                jiff::Timestamp::now(),
                uuid::Uuid::now_v7(),
            ),
        }
    }

    pub(crate) fn trusted_proxies(&self) -> TrustedProxies {
        TrustedProxies::new(&self.trusted_proxies, self.trusted_proxy_hops)
    }

    /// What may sit in front of the API listener. The admin listener is never
    /// proxied.
    pub(crate) fn api_edge(&self) -> Edge {
        let trusted = self.trusted_proxies();
        let proxy_protocol = if self.proxy_protocol {
            ProxyProtocol::required_from(trusted.clone())
        } else {
            ProxyProtocol::off()
        };
        Edge {
            trusted,
            proxy_protocol,
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
        Config::try_parse_from(std::iter::once(&"apigw").chain(args).chain(TLS.iter()))
    }

    #[test]
    fn rest_api_requires_stage() {
        assert!(parse(&["--rest-api-id", "abc"]).is_err());
        let config = parse(&["--rest-api-id", "abc", "--stage", "prod"]).unwrap();
        assert!(
            matches!(config.source(), Source::RestApi { ref api_id, ref stage, .. } if api_id == "abc" && stage == "prod")
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
    fn replicas_default_to_one_and_must_be_positive() {
        let config = parse(&["--http-api-id", "a", "--stage", "s"]).unwrap();
        assert_eq!(config.replicas.get(), 1);
        let config = parse(&["--http-api-id", "a", "--stage", "s", "--replicas", "3"]).unwrap();
        assert_eq!(config.replicas.get(), 3);
        assert!(parse(&["--http-api-id", "a", "--stage", "s", "--replicas", "0"]).is_err());
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

    const OPENAPI: [&str; 2] = ["--openapi-file", "api.json"];

    fn parse_proxied(extra: &[&str]) -> Result<Config, clap::Error> {
        let args: Vec<&str> = OPENAPI.iter().chain(extra).copied().collect();
        parse(&args)
    }

    #[test]
    fn trusted_proxies_take_a_comma_separated_list_and_default_to_one_hop() {
        let config =
            parse_proxied(&["--trusted-proxies", "10.0.0.0/8,192.0.2.7,fd00::/8"]).unwrap();
        assert_eq!(config.trusted_proxies.len(), 3);
        assert_eq!(config.trusted_proxy_hops.get(), 1);
        let trusted = config.trusted_proxies();
        assert!(trusted.contains("10.1.2.3".parse().unwrap()));
        assert!(trusted.contains("192.0.2.7".parse().unwrap()));
        assert!(trusted.contains("fd00::1".parse().unwrap()));
        assert!(!trusted.contains("192.0.2.8".parse().unwrap()));
    }

    #[test]
    fn invalid_trusted_proxies_and_hops_are_rejected() {
        assert!(parse_proxied(&["--trusted-proxies", "10.0.0.0/33"]).is_err());
        assert!(parse_proxied(&["--trusted-proxies", "nonsense"]).is_err());
        assert!(
            parse_proxied(&[
                "--trusted-proxies",
                "10.0.0.0/8",
                "--trusted-proxy-hops",
                "0"
            ])
            .is_err()
        );
        let config = parse_proxied(&[
            "--trusted-proxies",
            "10.0.0.0/8",
            "--trusted-proxy-hops",
            "2",
        ])
        .unwrap();
        assert_eq!(config.trusted_proxy_hops.get(), 2);
    }

    #[test]
    fn hops_and_proxy_protocol_need_trusted_proxies() {
        assert!(parse_proxied(&["--trusted-proxy-hops", "2"]).is_err());
        assert!(parse_proxied(&["--proxy-protocol"]).is_err());
        assert!(parse_proxied(&["--proxy-protocol", "--trusted-proxies", "10.0.0.0/8"]).is_ok());
    }

    #[test]
    fn proxy_protocol_applies_to_the_api_listener_only_when_asked() {
        let off = parse_proxied(&["--trusted-proxies", "10.0.0.0/8"]).unwrap();
        assert!(off.api_edge().proxy_protocol.required_from.is_none());
        let on = parse_proxied(&["--trusted-proxies", "10.0.0.0/8", "--proxy-protocol"]).unwrap();
        assert!(on.api_edge().proxy_protocol.required_from.is_some());
    }
}
