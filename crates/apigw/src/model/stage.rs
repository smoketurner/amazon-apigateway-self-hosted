//! Stage-scoped settings, read live with `GetStage` because the export does not
//! carry them.

use std::collections::{BTreeMap, HashMap};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::{Feature, MethodMatch, RoutePath};

/// Identifies one deployed version of a stage. A refresh re-exports only when
/// this changes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DeploymentStamp {
    pub(crate) deployment_id: Option<String>,
    pub(crate) last_updated_epoch_ms: Option<i64>,
}

impl DeploymentStamp {
    /// Whether `other` is the deployment this stamp describes. A stamp with no
    /// deployment ID never matches, so an unknown deployment is always re-read.
    pub(crate) fn is_same_deployment(&self, other: &Self) -> bool {
        self.deployment_id.is_some() && self == other
    }

    fn new(
        deployment_id: Option<String>,
        last_updated: Option<aws_sdk_apigateway::primitives::DateTime>,
    ) -> Self {
        let last_updated_epoch_ms = last_updated.and_then(|t| t.to_millis().ok());
        Self {
            deployment_id,
            last_updated_epoch_ms,
        }
    }
}

impl From<&aws_sdk_apigateway::operation::get_stage::GetStageOutput> for DeploymentStamp {
    fn from(stage: &aws_sdk_apigateway::operation::get_stage::GetStageOutput) -> Self {
        Self::new(stage.deployment_id.clone(), stage.last_updated_date)
    }
}

impl From<&aws_sdk_apigatewayv2::operation::get_stage::GetStageOutput> for DeploymentStamp {
    fn from(stage: &aws_sdk_apigatewayv2::operation::get_stage::GetStageOutput) -> Self {
        Self::new(stage.deployment_id.clone(), stage.last_updated_date)
    }
}

/// Which requests a [`MethodSettings`] entry applies to. REST APIs key settings
/// as `{resource path with / escaped as ~1}/{METHOD}` or `*/*`; HTTP APIs key
/// them by route key, plus a stage-wide default.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub(crate) enum SettingsScope {
    All,
    Method { path: String, method: String },
}

impl SettingsScope {
    /// Parses a REST `methodSettings` key.
    fn from_rest_key(key: &str) -> Option<Self> {
        if key == "*/*" {
            return Some(Self::All);
        }
        let (path, method) = key.rsplit_once('/')?;
        let path = if path == "*" {
            "*".to_owned()
        } else {
            format!("/{}", path.replace("~1", "/").trim_start_matches('/'))
        };
        Some(Self::Method {
            path,
            method: method.to_owned(),
        })
    }

    /// Parses an HTTP API `routeSettings` key (a route key).
    fn from_route_key(key: &str) -> Option<Self> {
        if key == "$default" {
            return Some(Self::Method {
                path: "$default".to_owned(),
                method: "*".to_owned(),
            });
        }
        let (method, path) = key.split_once(' ')?;
        Some(Self::Method {
            path: path.to_owned(),
            method: method.to_owned(),
        })
    }
}

impl fmt::Display for SettingsScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => f.write_str("*"),
            Self::Method { path, method } => write!(f, "{method} {path}"),
        }
    }
}

impl From<SettingsScope> for String {
    fn from(scope: SettingsScope) -> Self {
        scope.to_string()
    }
}

impl TryFrom<String> for SettingsScope {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if value == "*" {
            return Ok(Self::All);
        }
        Self::from_route_key(&value).ok_or_else(|| format!("invalid settings scope {value:?}"))
    }
}

/// Per-method (REST) or per-route (HTTP) stage settings. Fields absent in the
/// source are `None`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct MethodSettings {
    pub(crate) throttling_burst_limit: Option<i32>,
    pub(crate) throttling_rate_limit: Option<f64>,
    pub(crate) metrics_enabled: Option<bool>,
    pub(crate) logging_level: Option<String>,
    pub(crate) data_trace_enabled: Option<bool>,
    pub(crate) caching_enabled: Option<bool>,
    pub(crate) cache_ttl_seconds: Option<i32>,
    pub(crate) cache_data_encrypted: Option<bool>,
    pub(crate) require_authorization_for_cache_control: Option<bool>,
    pub(crate) unauthorized_cache_control_header_strategy: Option<String>,
}

impl MethodSettings {
    /// These settings with every field they leave unset taken from `base`.
    /// API Gateway reports an unset throttle limit as -1, so a negative limit
    /// counts as unset.
    fn overlaid_on(&self, base: &Self) -> Self {
        Self {
            throttling_burst_limit: self
                .throttling_burst_limit
                .filter(|limit| *limit >= 0)
                .or(base.throttling_burst_limit),
            throttling_rate_limit: self
                .throttling_rate_limit
                .filter(|limit| *limit >= 0.0)
                .or(base.throttling_rate_limit),
            metrics_enabled: self.metrics_enabled.or(base.metrics_enabled),
            logging_level: self
                .logging_level
                .clone()
                .or_else(|| base.logging_level.clone()),
            data_trace_enabled: self.data_trace_enabled.or(base.data_trace_enabled),
            caching_enabled: self.caching_enabled.or(base.caching_enabled),
            cache_ttl_seconds: self.cache_ttl_seconds.or(base.cache_ttl_seconds),
            cache_data_encrypted: self.cache_data_encrypted.or(base.cache_data_encrypted),
            require_authorization_for_cache_control: self
                .require_authorization_for_cache_control
                .or(base.require_authorization_for_cache_control),
            unauthorized_cache_control_header_strategy: self
                .unauthorized_cache_control_header_strategy
                .clone()
                .or_else(|| base.unauthorized_cache_control_header_strategy.clone()),
        }
    }

    /// Whether detailed (per method or route) metrics are on.
    pub(crate) fn detailed_metrics(&self) -> bool {
        self.metrics_enabled == Some(true)
    }

    /// The execution logging these settings ask for, if any. Data tracing only
    /// applies while a logging level is set, as in API Gateway.
    pub(crate) fn execution_logging(&self) -> Option<ExecutionLogging> {
        let level = self.logging_level.as_deref()?.parse().ok()?;
        Some(ExecutionLogging {
            level,
            data_trace: self.data_trace_enabled == Some(true),
        })
    }
}

/// A stage's execution logging level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum LoggingLevel {
    /// Only errors.
    Error,
    /// Errors and informational events.
    Info,
}

impl std::str::FromStr for LoggingLevel {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.to_ascii_uppercase().as_str() {
            "ERROR" => Ok(Self::Error),
            "INFO" => Ok(Self::Info),
            _ => Err(format!("{raw:?} is not an execution logging level")),
        }
    }
}

/// Execution logging in effect for a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecutionLogging {
    pub(crate) level: LoggingLevel,
    pub(crate) data_trace: bool,
}

impl From<&aws_sdk_apigateway::types::MethodSetting> for MethodSettings {
    fn from(setting: &aws_sdk_apigateway::types::MethodSetting) -> Self {
        Self {
            throttling_burst_limit: Some(setting.throttling_burst_limit),
            throttling_rate_limit: Some(setting.throttling_rate_limit),
            metrics_enabled: Some(setting.metrics_enabled),
            logging_level: setting.logging_level.clone(),
            data_trace_enabled: Some(setting.data_trace_enabled),
            caching_enabled: Some(setting.caching_enabled),
            cache_ttl_seconds: Some(setting.cache_ttl_in_seconds),
            cache_data_encrypted: Some(setting.cache_data_encrypted),
            require_authorization_for_cache_control: Some(
                setting.require_authorization_for_cache_control,
            ),
            unauthorized_cache_control_header_strategy: setting
                .unauthorized_cache_control_header_strategy
                .as_ref()
                .map(|s| s.as_str().to_owned()),
        }
    }
}

impl From<&aws_sdk_apigatewayv2::types::RouteSettings> for MethodSettings {
    fn from(setting: &aws_sdk_apigatewayv2::types::RouteSettings) -> Self {
        Self {
            throttling_burst_limit: setting.throttling_burst_limit,
            throttling_rate_limit: setting.throttling_rate_limit,
            metrics_enabled: setting.detailed_metrics_enabled,
            logging_level: setting
                .logging_level
                .as_ref()
                .map(|l| l.as_str().to_owned()),
            data_trace_enabled: setting.data_trace_enabled,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccessLogSettings {
    pub(crate) destination_arn: Option<String>,
    pub(crate) format: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct CanarySettings {
    pub(crate) percent_traffic: f64,
    pub(crate) deployment_id: Option<String>,
    pub(crate) stage_variable_overrides: BTreeMap<String, String>,
    pub(crate) use_stage_cache: bool,
}

/// Everything `GetStage` says about the stage being served.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct StageSettings {
    #[serde(default)]
    pub(crate) variables: BTreeMap<String, String>,
    #[serde(default)]
    pub(crate) method_settings: BTreeMap<SettingsScope, MethodSettings>,
    pub(crate) access_log: Option<AccessLogSettings>,
    #[serde(default)]
    pub(crate) tracing_enabled: bool,
    #[serde(default)]
    pub(crate) cache_cluster_enabled: bool,
    pub(crate) canary: Option<CanarySettings>,
}

impl StageSettings {
    /// Stage settings imported but not enforced yet.
    pub(crate) fn unenforced(&self) -> Vec<Feature> {
        let mut features = Vec::new();
        if self.cache_cluster_enabled {
            features.push(Feature::ResponseCaching);
        }
        if self
            .canary
            .as_ref()
            .is_some_and(|c| c.percent_traffic > 0.0)
        {
            features.push(Feature::Canary);
        }
        features
    }
}

impl StageSettings {
    /// The settings in effect for one route: the stage-wide entry, overridden
    /// field by field by the entry for the method on any path, the path with any
    /// method, and the exact path and method, in that order.
    pub(crate) fn settings_for(&self, method: &MethodMatch, path: &RoutePath) -> MethodSettings {
        let path = path.to_string();
        let methods = match method {
            MethodMatch::Any => vec!["ANY".to_owned(), "*".to_owned()],
            MethodMatch::Exact(method) => vec![method.to_string()],
        };
        let lookup = |path: &str, method: &str| {
            self.method_settings.get(&SettingsScope::Method {
                path: path.to_owned(),
                method: method.to_owned(),
            })
        };
        let mut layers = vec![self.method_settings.get(&SettingsScope::All)];
        layers.extend(methods.iter().map(|m| lookup("*", m)));
        layers.push(lookup(&path, "*"));
        layers.extend(methods.iter().map(|m| lookup(&path, m)));
        layers
            .into_iter()
            .flatten()
            .fold(MethodSettings::default(), |base, layer| {
                layer.overlaid_on(&base)
            })
    }

    /// SDK maps are unordered; settings are kept sorted so snapshots compare
    /// and serialize deterministically.
    fn sorted(map: Option<&HashMap<String, String>>) -> BTreeMap<String, String> {
        map.map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default()
    }
}

impl From<&aws_sdk_apigateway::operation::get_stage::GetStageOutput> for StageSettings {
    fn from(stage: &aws_sdk_apigateway::operation::get_stage::GetStageOutput) -> Self {
        let mut method_settings = BTreeMap::new();
        for (key, setting) in stage.method_settings.iter().flatten() {
            if let Some(scope) = SettingsScope::from_rest_key(key) {
                method_settings.insert(scope, MethodSettings::from(setting));
            } else {
                tracing::warn!(key, "ignoring unrecognized method settings key");
            }
        }
        Self {
            variables: Self::sorted(stage.variables.as_ref()),
            method_settings,
            access_log: stage
                .access_log_settings
                .as_ref()
                .map(|l| AccessLogSettings {
                    destination_arn: l.destination_arn.clone(),
                    format: l.format.clone(),
                }),
            tracing_enabled: stage.tracing_enabled,
            cache_cluster_enabled: stage.cache_cluster_enabled,
            canary: stage.canary_settings.as_ref().map(|c| CanarySettings {
                percent_traffic: c.percent_traffic,
                deployment_id: c.deployment_id.clone(),
                stage_variable_overrides: Self::sorted(c.stage_variable_overrides.as_ref()),
                use_stage_cache: c.use_stage_cache,
            }),
        }
    }
}

impl From<&aws_sdk_apigatewayv2::operation::get_stage::GetStageOutput> for StageSettings {
    fn from(stage: &aws_sdk_apigatewayv2::operation::get_stage::GetStageOutput) -> Self {
        let mut method_settings = BTreeMap::new();
        if let Some(ref default) = stage.default_route_settings {
            method_settings.insert(SettingsScope::All, MethodSettings::from(default));
        }
        for (key, setting) in stage.route_settings.iter().flatten() {
            if let Some(scope) = SettingsScope::from_route_key(key) {
                method_settings.insert(scope, MethodSettings::from(setting));
            } else {
                tracing::warn!(key, "ignoring unrecognized route settings key");
            }
        }
        Self {
            variables: Self::sorted(stage.stage_variables.as_ref()),
            method_settings,
            access_log: stage
                .access_log_settings
                .as_ref()
                .map(|l| AccessLogSettings {
                    destination_arn: l.destination_arn.clone(),
                    format: l.format.clone(),
                }),
            tracing_enabled: false,
            cache_cluster_enabled: false,
            canary: None,
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use aws_sdk_apigateway::operation::get_stage::GetStageOutput as RestStage;
    use aws_sdk_apigateway::primitives::DateTime;
    use aws_sdk_apigateway::types::{CanarySettings as RestCanary, MethodSetting};
    use aws_sdk_apigatewayv2::operation::get_stage::GetStageOutput as HttpStage;
    use aws_sdk_apigatewayv2::types::{LoggingLevel, RouteSettings};

    use super::*;

    #[test]
    fn rest_method_settings_keys_are_decoded() {
        assert_eq!(
            SettingsScope::from_rest_key("*/*"),
            Some(SettingsScope::All)
        );
        assert_eq!(
            SettingsScope::from_rest_key("~1pets~1{petId}/GET"),
            Some(SettingsScope::Method {
                path: "/pets/{petId}".to_owned(),
                method: "GET".to_owned()
            })
        );
        assert_eq!(
            SettingsScope::from_rest_key("*/POST"),
            Some(SettingsScope::Method {
                path: "*".to_owned(),
                method: "POST".to_owned()
            })
        );
        assert_eq!(SettingsScope::from_rest_key("nomethod"), None);
    }

    #[test]
    fn route_settings_keys_are_route_keys() {
        assert_eq!(
            SettingsScope::from_route_key("GET /pets"),
            Some(SettingsScope::Method {
                path: "/pets".to_owned(),
                method: "GET".to_owned()
            })
        );
        assert!(SettingsScope::from_route_key("$default").is_some());
        assert_eq!(SettingsScope::from_route_key("garbage"), None);
    }

    #[test]
    fn scopes_round_trip_through_serde_as_map_keys() {
        let mut settings = StageSettings::default();
        settings
            .method_settings
            .insert(SettingsScope::All, MethodSettings::default());
        settings.method_settings.insert(
            SettingsScope::Method {
                path: "/pets".to_owned(),
                method: "GET".to_owned(),
            },
            MethodSettings {
                throttling_rate_limit: Some(5.0),
                ..MethodSettings::default()
            },
        );
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            serde_json::from_str::<StageSettings>(&json).unwrap(),
            settings
        );
    }

    #[test]
    fn rest_stage_is_converted() {
        let stage = RestStage::builder()
            .deployment_id("dep1")
            .last_updated_date(DateTime::from_millis(1_700_000_000_000))
            .variables("host", "a.example")
            .tracing_enabled(true)
            .cache_cluster_enabled(true)
            .method_settings(
                "~1pets/GET",
                MethodSetting::builder()
                    .throttling_burst_limit(10)
                    .throttling_rate_limit(5.0)
                    .logging_level("INFO")
                    .metrics_enabled(true)
                    .build(),
            )
            .method_settings("bad", MethodSetting::builder().build())
            .canary_settings(
                RestCanary::builder()
                    .percent_traffic(10.0)
                    .stage_variable_overrides("host", "b")
                    .build(),
            )
            .access_log_settings(
                aws_sdk_apigateway::types::AccessLogSettings::builder()
                    .destination_arn("arn:aws:logs:us-east-1:1:log-group:x")
                    .format("$context.requestId")
                    .build(),
            )
            .build();
        let settings = StageSettings::from(&stage);
        assert_eq!(
            settings.variables.get("host").map(String::as_str),
            Some("a.example")
        );
        assert_eq!(settings.method_settings.len(), 1);
        assert_eq!(
            settings
                .canary
                .as_ref()
                .unwrap()
                .stage_variable_overrides
                .get("host")
                .map(String::as_str),
            Some("b")
        );
        assert_eq!(
            settings.unenforced(),
            vec![Feature::ResponseCaching, Feature::Canary]
        );
        assert_eq!(
            DeploymentStamp::from(&stage),
            DeploymentStamp {
                deployment_id: Some("dep1".to_owned()),
                last_updated_epoch_ms: Some(1_700_000_000_000)
            }
        );
    }

    #[test]
    fn http_stage_is_converted_with_default_route_settings() {
        let stage = HttpStage::builder()
            .deployment_id("d")
            .stage_variables("k", "v")
            .default_route_settings(
                RouteSettings::builder()
                    .throttling_rate_limit(100.0)
                    .build(),
            )
            .route_settings(
                "GET /pets",
                RouteSettings::builder()
                    .logging_level(LoggingLevel::Error)
                    .build(),
            )
            .build();
        let settings = StageSettings::from(&stage);
        assert_eq!(settings.method_settings.len(), 2);
        assert!(settings.method_settings.contains_key(&SettingsScope::All));
        assert!(settings.unenforced().is_empty());
    }

    fn scope(path: &str, method: &str) -> SettingsScope {
        SettingsScope::Method {
            path: path.to_owned(),
            method: method.to_owned(),
        }
    }

    #[test]
    fn route_settings_layer_from_stage_wide_to_exact() {
        let mut settings = StageSettings::default();
        settings.method_settings.insert(
            SettingsScope::All,
            MethodSettings {
                logging_level: Some("ERROR".to_owned()),
                metrics_enabled: Some(false),
                ..MethodSettings::default()
            },
        );
        settings.method_settings.insert(
            scope("/pets", "*"),
            MethodSettings {
                logging_level: Some("INFO".to_owned()),
                ..MethodSettings::default()
            },
        );
        settings.method_settings.insert(
            scope("/pets", "GET"),
            MethodSettings {
                metrics_enabled: Some(true),
                ..MethodSettings::default()
            },
        );
        let pets = RoutePath::Resource("/pets".to_owned());
        let get = settings.settings_for(&MethodMatch::Exact(axum::http::Method::GET), &pets);
        assert_eq!(get.logging_level.as_deref(), Some("INFO"));
        assert!(get.detailed_metrics());
        let post = settings.settings_for(&MethodMatch::Exact(axum::http::Method::POST), &pets);
        assert_eq!(post.logging_level.as_deref(), Some("INFO"));
        assert!(!post.detailed_metrics());
        let other = settings.settings_for(
            &MethodMatch::Exact(axum::http::Method::GET),
            &RoutePath::Resource("/other".to_owned()),
        );
        assert_eq!(other.logging_level.as_deref(), Some("ERROR"));
        assert!(!other.detailed_metrics());
    }

    #[test]
    fn any_routes_and_the_default_route_find_their_settings() {
        let mut settings = StageSettings::default();
        settings.method_settings.insert(
            scope("/any", "ANY"),
            MethodSettings {
                metrics_enabled: Some(true),
                ..MethodSettings::default()
            },
        );
        settings.method_settings.insert(
            scope("$default", "*"),
            MethodSettings {
                logging_level: Some("INFO".to_owned()),
                ..MethodSettings::default()
            },
        );
        let any = settings.settings_for(&MethodMatch::Any, &RoutePath::Resource("/any".to_owned()));
        assert!(any.detailed_metrics());
        let default = settings.settings_for(&MethodMatch::Any, &RoutePath::Default);
        assert!(default.execution_logging().is_some());
        assert_eq!(
            StageSettings::default().settings_for(&MethodMatch::Any, &RoutePath::Default),
            MethodSettings::default()
        );
    }

    #[test]
    fn execution_logging_needs_a_known_level_and_data_trace_rides_on_it() {
        let logging = |level: Option<&str>, trace: bool| {
            MethodSettings {
                logging_level: level.map(str::to_owned),
                data_trace_enabled: Some(trace),
                ..MethodSettings::default()
            }
            .execution_logging()
        };
        assert_eq!(logging(Some("OFF"), true), None);
        assert_eq!(logging(None, true), None);
        assert_eq!(logging(Some("bogus"), true), None);
        assert_eq!(
            logging(Some("info"), true),
            Some(ExecutionLogging {
                level: crate::model::LoggingLevel::Info,
                data_trace: true
            })
        );
        assert_eq!(
            logging(Some("ERROR"), false),
            Some(ExecutionLogging {
                level: crate::model::LoggingLevel::Error,
                data_trace: false
            })
        );
    }

    #[test]
    fn unset_throttling_and_off_logging_are_not_reported() {
        let mut settings = StageSettings::default();
        settings.method_settings.insert(
            SettingsScope::All,
            MethodSettings {
                throttling_burst_limit: Some(-1),
                throttling_rate_limit: Some(-1.0),
                logging_level: Some("OFF".to_owned()),
                ..MethodSettings::default()
            },
        );
        assert!(settings.unenforced().is_empty());
    }
}
