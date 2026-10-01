//! Stage-level throttling: REST method settings and HTTP API route settings
//! become one token bucket per route, kept in the [`StateBackend`].
//!
//! Each method (REST) or route (HTTP) has its own bucket, sized by its own
//! setting or, failing that, the stage default (`*/*` for REST, the default
//! route settings for HTTP). Account-level and usage-plan throttles are not
//! applied here.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use crate::model::{MethodMatch, MethodSettings, RoutePath, SettingsScope};
use crate::state::{Admission, BucketLimits, StateBackend, StateKey};

impl MethodSettings {
    /// The rate and burst this entry sets. API Gateway reports an unset value
    /// as -1.
    fn throttle_rate(&self) -> Option<f64> {
        self.throttling_rate_limit.filter(|rate| *rate >= 0.0)
    }

    fn throttle_burst(&self) -> Option<f64> {
        self.throttling_burst_limit
            .filter(|burst| *burst >= 0)
            .map(f64::from)
    }
}

/// How the stage's throttle settings apply to its routes.
#[derive(Debug, Clone)]
pub(crate) struct ThrottleSettings {
    settings: BTreeMap<SettingsScope, MethodSettings>,
    replicas: NonZeroU32,
    key_prefix: String,
}

impl ThrottleSettings {
    /// `api_id` and `stage` keep buckets of different APIs apart in a shared
    /// backend; `replicas` is how many gateways serve the API.
    pub(crate) fn new(
        api_id: &str,
        stage: Option<&str>,
        settings: BTreeMap<SettingsScope, MethodSettings>,
        replicas: NonZeroU32,
    ) -> Self {
        Self {
            settings,
            replicas,
            key_prefix: format!("{api_id}:{}", stage.unwrap_or("$default")),
        }
    }

    /// The throttle for a route, or `None` when no setting limits it.
    pub(crate) fn for_route(
        &self,
        method: &MethodMatch,
        path: &RoutePath,
    ) -> Option<RouteThrottle> {
        let own = self.settings.get(&SettingsScope::for_route(method, path));
        let default = self.settings.get(&SettingsScope::All);
        let rate = own
            .and_then(MethodSettings::throttle_rate)
            .or_else(|| default.and_then(MethodSettings::throttle_rate));
        let burst = own
            .and_then(MethodSettings::throttle_burst)
            .or_else(|| default.and_then(MethodSettings::throttle_burst));
        // ASSUMPTION: API Gateway always sets rate and burst together; if only
        // one is given the other is taken to be equal to it.
        let (rate, burst) = match (rate, burst) {
            (Some(rate), Some(burst)) => (rate, burst),
            (Some(only), None) | (None, Some(only)) => (only, only),
            (None, None) => return None,
        };
        let limits = BucketLimits::new(rate, burst)?.per_replica(self.replicas);
        let route = match path {
            RoutePath::Default => "$default".to_owned(),
            RoutePath::Resource(path) => format!("{method} {path}"),
        };
        Some(RouteThrottle {
            key: StateKey::new("throttle", &[&self.key_prefix, &route]),
            limits,
        })
    }
}

/// One route's bucket: where its state lives and how big it is.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct RouteThrottle {
    key: StateKey,
    limits: BucketLimits,
}

impl RouteThrottle {
    /// Takes a token for one request. If the backend cannot answer the request
    /// is admitted: throttling protects the backend's capacity, and refusing
    /// all traffic because shared state is down would take the API down too.
    pub(crate) async fn admit(&self, backend: &StateBackend) -> Admission {
        match backend.take_token(&self.key, self.limits).await {
            Ok(admission) => admission,
            Err(error) => {
                tracing::warn!(%error, key = self.key.as_str(), "throttle state unavailable; admitting the request");
                Admission::Admitted
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::http::Method;

    use super::*;
    use crate::state::{InMemory, InMemoryLimits};

    fn settings(rate: f64, burst: i32) -> MethodSettings {
        MethodSettings {
            throttling_rate_limit: Some(rate),
            throttling_burst_limit: Some(burst),
            ..MethodSettings::default()
        }
    }

    fn unset() -> MethodSettings {
        settings(-1.0, -1)
    }

    fn throttle(
        entries: impl IntoIterator<Item = (SettingsScope, MethodSettings)>,
        replicas: u32,
    ) -> ThrottleSettings {
        ThrottleSettings::new(
            "abc",
            Some("prod"),
            entries.into_iter().collect(),
            NonZeroU32::new(replicas).unwrap(),
        )
    }

    fn get(path: &str) -> (MethodMatch, RoutePath) {
        (
            MethodMatch::Exact(Method::GET),
            RoutePath::Resource(path.to_owned()),
        )
    }

    fn scope(path: &str, method: &str) -> SettingsScope {
        SettingsScope::Method {
            path: path.to_owned(),
            method: method.to_owned(),
        }
    }

    fn limits(rate: f64, burst: f64) -> BucketLimits {
        BucketLimits::new(rate, burst).unwrap()
    }

    #[test]
    fn unset_settings_do_not_throttle() {
        let (method, path) = get("/pets");
        assert!(throttle([], 1).for_route(&method, &path).is_none());
        let settings = throttle([(SettingsScope::All, unset())], 1);
        assert!(settings.for_route(&method, &path).is_none());
    }

    #[test]
    fn method_settings_override_the_stage_default() {
        let settings = throttle(
            [
                (SettingsScope::All, settings(10.0, 20)),
                (scope("/pets", "GET"), settings(1.0, 2)),
            ],
            1,
        );
        let (method, pets) = get("/pets");
        assert_eq!(
            settings.for_route(&method, &pets).unwrap().limits,
            limits(1.0, 2.0)
        );
        let (method, other) = get("/other");
        assert_eq!(
            settings.for_route(&method, &other).unwrap().limits,
            limits(10.0, 20.0)
        );
        let post = MethodMatch::Exact(Method::POST);
        assert_eq!(
            settings.for_route(&post, &pets).unwrap().limits,
            limits(10.0, 20.0)
        );
    }

    #[test]
    fn unset_fields_of_a_method_entry_fall_back_to_the_default() {
        let settings = throttle(
            [
                (SettingsScope::All, settings(10.0, 20)),
                (scope("/pets", "GET"), settings(-1.0, 5)),
            ],
            1,
        );
        let (method, path) = get("/pets");
        assert_eq!(
            settings.for_route(&method, &path).unwrap().limits,
            limits(10.0, 5.0)
        );
    }

    #[test]
    fn a_single_value_sets_both_rate_and_burst() {
        let only_rate = MethodSettings {
            throttling_rate_limit: Some(4.0),
            ..MethodSettings::default()
        };
        let settings = throttle([(SettingsScope::All, only_rate)], 1);
        let (method, path) = get("/pets");
        assert_eq!(
            settings.for_route(&method, &path).unwrap().limits,
            limits(4.0, 4.0)
        );
    }

    #[test]
    fn http_default_route_and_any_routes_resolve() {
        let settings = throttle(
            [
                (SettingsScope::All, settings(5.0, 10)),
                (scope("$default", "*"), settings(1.0, 1)),
                (scope("/{proxy+}", "ANY"), settings(2.0, 3)),
            ],
            1,
        );
        let default = settings
            .for_route(&MethodMatch::Any, &RoutePath::Default)
            .unwrap();
        assert_eq!(default.limits, limits(1.0, 1.0));
        let any = settings
            .for_route(
                &MethodMatch::Any,
                &RoutePath::Resource("/{proxy+}".to_owned()),
            )
            .unwrap();
        assert_eq!(any.limits, limits(2.0, 3.0));
    }

    #[test]
    fn replicas_divide_the_limits() {
        let settings = throttle([(SettingsScope::All, settings(100.0, 40))], 4);
        let (method, path) = get("/pets");
        assert_eq!(
            settings.for_route(&method, &path).unwrap().limits,
            limits(25.0, 10.0)
        );
    }

    #[test]
    fn routes_get_separate_buckets() {
        let settings = throttle([(SettingsScope::All, settings(1.0, 1))], 1);
        let (method, a) = get("/a");
        let (_, b) = get("/b");
        let (a, b) = (
            settings.for_route(&method, &a).unwrap(),
            settings.for_route(&method, &b).unwrap(),
        );
        assert_ne!(a.key, b.key);
        assert_eq!(a.key.as_str(), "throttle:abc:prod:GET /a");
    }

    #[tokio::test]
    async fn admit_throttles_after_the_burst() {
        let backend = StateBackend::InMemory(InMemory::new(InMemoryLimits::default()));
        let settings = throttle([(SettingsScope::All, settings(0.0, 2))], 1);
        let (method, path) = get("/pets");
        let route = settings.for_route(&method, &path).unwrap();
        assert_eq!(route.admit(&backend).await, Admission::Admitted);
        assert_eq!(route.admit(&backend).await, Admission::Admitted);
        assert_eq!(route.admit(&backend).await, Admission::Throttled);
    }

    #[tokio::test]
    async fn zero_limits_block_every_request() {
        let backend = StateBackend::InMemory(InMemory::new(InMemoryLimits::default()));
        let settings = throttle([(SettingsScope::All, settings(0.0, 0))], 1);
        let (method, path) = get("/pets");
        let route = settings.for_route(&method, &path).unwrap();
        assert_eq!(route.admit(&backend).await, Admission::Throttled);
    }
}
