//! API keys and usage plans through a real router: which requests a method that
//! requires a key admits, and how the plan's throttle and quota count them.
//!
//! These live beside the authorizer tests because they share their harness (a
//! router in front of a fake backend and a fake authorizer function).

#![expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#![expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};

use super::tests::{ECHO_FUNCTION, Harness, lambda_uri};
use crate::digest::Sha256Digest;
use crate::gateway::AuthorizationMode;
use crate::model::ApiKind;
use crate::state::BucketLimits;
use crate::state::quota::{QuotaLimit, QuotaPeriod};
use crate::usage::{
    KeyId, KeyRecord, KeyValue, PlanId, PlanLimits, UsageChecker, UsageData, UsagePlan, UsageStore,
};

const KEY: &str = "a-secret-key-value-0123456789";
const OTHER_KEY: &str = "another-secret-key-value-9876";

fn echo() -> Value {
    json!({"type": "aws_proxy", "httpMethod": "POST", "uri": lambda_uri(ECHO_FUNCTION),
        "payloadFormatVersion": "1.0"})
}

/// A REST API with keyed and open routes, and a Lambda authorizer on one of them.
fn doc(key_source: &str) -> Value {
    let keyed = |security: Value| {
        json!({"get": {"security": security, "x-amazon-apigateway-integration": echo()},
            "post": {"security": security, "x-amazon-apigateway-integration": echo()}})
    };
    json!({
        "x-amazon-apigateway-api-key-source": key_source,
        "components": {"securitySchemes": {
            "api_key": {"type": "apiKey", "name": "x-api-key", "in": "header"},
            "auth": {"type": "apiKey", "name": "Authorization", "in": "header",
                "x-amazon-apigateway-authtype": "custom",
                "x-amazon-apigateway-authorizer": {"type": "token",
                    "authorizerUri": lambda_uri("arn:aws:lambda:us-east-1:123456789012:function:auth"),
                    "authorizerResultTtlInSeconds": 300}}}},
        "paths": {
            "/open": {"get": {"x-amazon-apigateway-integration": echo()}},
            "/keyed": keyed(json!([{"api_key": []}])),
            "/slow": keyed(json!([{"api_key": []}])),
            "/keyed-auth": keyed(json!([{"api_key": [], "auth": []}])),
        }
    })
}

fn bucket(rate: f64, burst: f64) -> BucketLimits {
    BucketLimits::new(rate, burst).unwrap()
}

fn plan(id: &str, limits: PlanLimits) -> UsagePlan {
    UsagePlan {
        id: PlanId(id.to_owned()),
        limits,
    }
}

fn key(value: &str, id: &str, enabled: bool) -> (Sha256Digest, KeyRecord) {
    (
        KeyValue::digest(value),
        KeyRecord {
            id: KeyId(id.to_owned()),
            enabled,
        },
    )
}

fn member(plan: &str, key: &str) -> (PlanId, KeyId) {
    (PlanId(plan.to_owned()), KeyId(key.to_owned()))
}

/// `KEY` is enabled and in the plan; the other keys are disabled, in no plan,
/// or unknown.
fn data(limits: PlanLimits) -> UsageData {
    UsageData::new(
        [
            key(KEY, "key-1", true),
            key("disabled-key-value", "key-2", false),
            key("unplanned-key-value", "key-3", true),
            key(OTHER_KEY, "key-4", true),
        ],
        [plan("plan-1", limits)],
        [
            member("plan-1", "key-1"),
            member("plan-1", "key-2"),
            member("plan-1", "key-4"),
        ],
    )
}

fn store(data: UsageData) -> Arc<UsageStore> {
    let store = UsageStore::new(UsageChecker::new("abc", "prod", NonZeroU32::MIN));
    store.replace(data);
    Arc::new(store)
}

async fn harness(source: &str, limits: PlanLimits) -> (Harness, Arc<UsageStore>) {
    let usage = store(data(limits));
    let h = Harness::start_with_usage(&doc(source), AuthorizationMode::Enforce, Arc::clone(&usage))
        .await;
    (h, usage)
}

async fn get(h: &Harness, path: &str, key: Option<&str>) -> (StatusCode, Value) {
    let headers: Vec<(&str, &str)> = key.map(|k| ("x-api-key", k)).into_iter().collect();
    h.call(Method::GET, path, &headers).await
}

fn forbidden(response: &(StatusCode, Value)) -> bool {
    response.0 == StatusCode::FORBIDDEN && response.1 == json!({"message": "Forbidden"})
}

#[tokio::test]
async fn a_valid_key_reaches_the_backend_and_is_identified_in_the_event() {
    let (h, _) = harness("HEADER", PlanLimits::default()).await;
    let (status, _) = get(&h, "/keyed", Some(KEY)).await;
    assert_eq!(status, StatusCode::OK);
    let identity = &h.backend_calls.last()["requestContext"]["identity"];
    assert_eq!(identity["apiKeyId"], "key-1");
    assert_eq!(identity["apiKey"], KEY);
}

#[tokio::test]
async fn routes_that_do_not_need_a_key_ignore_it() {
    let (h, _) = harness("HEADER", PlanLimits::default()).await;
    assert_eq!(get(&h, "/open", None).await.0, StatusCode::OK);
    assert_eq!(get(&h, "/open", Some("garbage")).await.0, StatusCode::OK);
    let identity = &h.backend_calls.last()["requestContext"]["identity"];
    assert!(identity.get("apiKeyId").is_none(), "{identity}");
}

#[tokio::test]
async fn a_missing_empty_unknown_disabled_or_unplanned_key_is_403_forbidden() {
    let (h, _) = harness("HEADER", PlanLimits::default()).await;
    for presented in [
        None,
        Some(""),
        Some("nope"),
        Some("disabled-key-value"),
        Some("unplanned-key-value"),
    ] {
        let response = get(&h, "/keyed", presented).await;
        assert!(forbidden(&response), "{presented:?}: {response:?}");
    }
    for near_miss in [
        KEY.to_uppercase(),
        format!("{KEY} "),
        KEY.strip_suffix('9').unwrap().to_owned(),
        format!("x{KEY}"),
    ] {
        assert!(
            forbidden(&get(&h, "/keyed", Some(&near_miss)).await),
            "{near_miss}"
        );
    }
    assert_eq!(h.backend_calls.count(), 0);
}

#[tokio::test]
async fn the_header_name_is_case_insensitive() {
    let (h, _) = harness("HEADER", PlanLimits::default()).await;
    let (status, _) = h.call(Method::GET, "/keyed", &[("X-API-Key", KEY)]).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn changes_in_api_gateway_take_effect_when_the_data_is_replaced() {
    let (h, usage) = harness("HEADER", PlanLimits::default()).await;
    assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
    usage.replace(UsageData::new(
        [key(KEY, "key-1", false)],
        [plan("plan-1", PlanLimits::default())],
        [member("plan-1", "key-1")],
    ));
    assert!(forbidden(&get(&h, "/keyed", Some(KEY)).await), "disabled");
    usage.replace(UsageData::new(
        [key(KEY, "key-1", true)],
        [plan("plan-1", PlanLimits::default())],
        [member("plan-1", "key-1")],
    ));
    assert_eq!(
        get(&h, "/keyed", Some(KEY)).await.0,
        StatusCode::OK,
        "enabled again"
    );
    usage.replace(UsageData::default());
    assert!(forbidden(&get(&h, "/keyed", Some(KEY)).await), "deleted");
}

#[tokio::test]
async fn data_that_is_too_old_is_not_trusted() {
    let usage = Arc::new(
        UsageStore::new(UsageChecker::new("abc", "prod", NonZeroU32::MIN))
            .with_max_staleness(Duration::from_millis(100)),
    );
    usage.replace(data(PlanLimits::default()));
    let h = Harness::start_with_usage(
        &doc("HEADER"),
        AuthorizationMode::Enforce,
        Arc::clone(&usage),
    )
    .await;
    assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        forbidden(&get(&h, "/keyed", Some(KEY)).await),
        "the last read is too old"
    );
    usage.replace(data(PlanLimits::default()));
    assert_eq!(
        get(&h, "/keyed", Some(KEY)).await.0,
        StatusCode::OK,
        "a fresh read restores service"
    );
}

#[tokio::test]
async fn nothing_is_valid_before_the_first_read() {
    let usage = Arc::new(UsageStore::new(UsageChecker::new(
        "abc",
        "prod",
        NonZeroU32::MIN,
    )));
    let h = Harness::start_with_usage(&doc("HEADER"), AuthorizationMode::Enforce, usage).await;
    assert!(forbidden(&get(&h, "/keyed", Some(KEY)).await));
}

#[tokio::test]
async fn the_plan_throttle_answers_429_too_many_requests() {
    let limits = PlanLimits {
        throttle: Some(bucket(0.0, 2.0)),
        ..PlanLimits::default()
    };
    let (h, _) = harness("HEADER", limits).await;
    assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
    assert_eq!(get(&h, "/slow", Some(KEY)).await.0, StatusCode::OK);
    let (status, body) = get(&h, "/keyed", Some(KEY)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, json!({"message": "Too Many Requests"}));
    assert_eq!(
        get(&h, "/keyed", Some(OTHER_KEY)).await.0,
        StatusCode::OK,
        "another key has its own bucket"
    );
    assert_eq!(h.backend_calls.count(), 3);
}

#[tokio::test]
async fn a_method_throttle_limits_only_that_method() {
    let limits = PlanLimits {
        throttle: None,
        methods: BTreeMap::from([("/slow/GET".to_owned(), bucket(0.0, 1.0))]),
        quota: None,
    };
    let (h, _) = harness("HEADER", limits).await;
    assert_eq!(get(&h, "/slow", Some(KEY)).await.0, StatusCode::OK);
    assert_eq!(
        get(&h, "/slow", Some(KEY)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        h.call(Method::POST, "/slow", &[("x-api-key", KEY)]).await.0,
        StatusCode::OK,
        "POST is not limited"
    );
    for _ in 0..5 {
        assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn the_quota_answers_429_limit_exceeded() {
    let limits = PlanLimits {
        quota: Some(QuotaLimit {
            limit: 3,
            period: QuotaPeriod::Day,
        }),
        ..PlanLimits::default()
    };
    let (h, _) = harness("HEADER", limits).await;
    for path in ["/keyed", "/slow", "/keyed"] {
        assert_eq!(get(&h, path, Some(KEY)).await.0, StatusCode::OK, "{path}");
    }
    let (status, body) = get(&h, "/keyed", Some(KEY)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, json!({"message": "Limit Exceeded"}));
    assert_eq!(
        get(&h, "/open", None).await.0,
        StatusCode::OK,
        "open routes do not count"
    );
    assert_eq!(
        get(&h, "/keyed", Some(OTHER_KEY)).await.0,
        StatusCode::OK,
        "quotas are per key"
    );
}

#[tokio::test]
async fn a_request_refused_for_its_key_does_not_count_against_anyones_quota() {
    let limits = PlanLimits {
        quota: Some(QuotaLimit {
            limit: 1,
            period: QuotaPeriod::Day,
        }),
        ..PlanLimits::default()
    };
    let (h, _) = harness("HEADER", limits).await;
    for _ in 0..5 {
        assert!(forbidden(&get(&h, "/keyed", Some("nope")).await));
    }
    assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
}

#[tokio::test]
async fn the_authorizer_can_be_the_source_of_the_key() {
    let (h, _) = harness("AUTHORIZER", PlanLimits::default()).await;
    let call = |token: &str, header: Option<&str>| {
        let mut headers = vec![("authorization", token.to_owned())];
        if let Some(header) = header {
            headers.push(("x-api-key", header.to_owned()));
        }
        let h = &h;
        async move {
            let headers: Vec<(&str, &str)> =
                headers.iter().map(|(n, v)| (*n, v.as_str())).collect();
            h.call(Method::GET, "/keyed-auth", &headers).await
        }
    };
    assert_eq!(call(&format!("keyed:{KEY}"), None).await.0, StatusCode::OK);
    assert_eq!(
        h.backend_calls.last()["requestContext"]["identity"]["apiKeyId"],
        "key-1"
    );
    assert!(
        h.backend_calls.last()["requestContext"]["identity"]["apiKey"].is_null(),
        "the value was never kept"
    );
    assert!(
        forbidden(&call("allow-all", None).await),
        "the authorizer named no key"
    );
    assert!(
        forbidden(&call("keyed:unknown", None).await),
        "an unknown key"
    );
    assert!(
        forbidden(&call("keyed:disabled-key-value", None).await),
        "a disabled key"
    );
    assert!(
        forbidden(&call("allow-all", Some(KEY)).await),
        "the header is not consulted"
    );
    assert_eq!(
        call("deny", None).await.0,
        StatusCode::FORBIDDEN,
        "the authorizer's own denial still applies"
    );
}

#[tokio::test]
async fn a_cached_authorizer_result_keeps_naming_its_key_without_holding_it() {
    let (h, _) = harness("AUTHORIZER", PlanLimits::default()).await;
    let token = format!("keyed:{KEY}");
    for _ in 0..3 {
        let (status, _) = h
            .call(Method::GET, "/keyed-auth", &[("authorization", &token)])
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    assert_eq!(
        h.auth_calls.count(),
        1,
        "served from the cache after the first call"
    );
}

#[tokio::test]
async fn a_key_the_authorizer_names_is_checked_against_the_plan() {
    let limits = PlanLimits {
        quota: Some(QuotaLimit {
            limit: 2,
            period: QuotaPeriod::Day,
        }),
        ..PlanLimits::default()
    };
    let (h, _) = harness("AUTHORIZER", limits).await;
    let token = format!("keyed:{KEY}");
    let call = || async {
        h.call(Method::GET, "/keyed-auth", &[("authorization", &token)])
            .await
            .0
    };
    assert_eq!(call().await, StatusCode::OK);
    assert_eq!(call().await, StatusCode::OK);
    assert_eq!(call().await, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn skipping_authorization_skips_api_keys() {
    let usage = store(data(PlanLimits {
        throttle: Some(bucket(0.0, 1.0)),
        ..PlanLimits::default()
    }));
    let h = Harness::start_with_usage(&doc("HEADER"), AuthorizationMode::Skip, usage).await;
    for _ in 0..5 {
        assert_eq!(get(&h, "/keyed", None).await.0, StatusCode::OK);
    }
}

#[tokio::test]
async fn without_a_usage_store_key_routes_are_refused_and_reported() {
    let h = Harness::start(&doc("HEADER"), ApiKind::Rest, AuthorizationMode::Enforce).await;
    assert!(forbidden(&get(&h, "/keyed", Some(KEY)).await));
    assert_eq!(get(&h, "/open", None).await.0, StatusCode::OK);
    let keyed = h
        .summaries
        .iter()
        .find(|s| s.route_key == "GET /keyed")
        .unwrap();
    assert!(
        keyed
            .problems
            .iter()
            .any(|p| p.contains("API key this gateway cannot check")),
        "{keyed:?}"
    );
    let skipped = Harness::start(&doc("HEADER"), ApiKind::Rest, AuthorizationMode::Skip).await;
    assert_eq!(get(&skipped, "/keyed", None).await.0, StatusCode::OK);
}

#[tokio::test]
async fn http_apis_cannot_check_keys() {
    let h = Harness::start(&doc("HEADER"), ApiKind::Http, AuthorizationMode::Enforce).await;
    assert!(forbidden(&get(&h, "/keyed", Some(KEY)).await));
}

#[tokio::test]
async fn a_throttled_key_does_not_burn_quota() {
    let limits = PlanLimits {
        throttle: Some(bucket(0.0, 1.0)),
        methods: BTreeMap::new(),
        quota: Some(QuotaLimit {
            limit: 2,
            period: QuotaPeriod::Day,
        }),
    };
    let (h, usage) = harness("HEADER", limits).await;
    assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
    for _ in 0..4 {
        assert_eq!(
            get(&h, "/keyed", Some(KEY)).await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
    }
    // Drop the throttle but keep the counters: one unit of quota is left.
    usage.replace(data(PlanLimits {
        throttle: None,
        methods: BTreeMap::new(),
        quota: Some(QuotaLimit {
            limit: 2,
            period: QuotaPeriod::Day,
        }),
    }));
    assert_eq!(get(&h, "/keyed", Some(KEY)).await.0, StatusCode::OK);
    assert_eq!(
        get(&h, "/keyed", Some(KEY)).await.0,
        StatusCode::TOO_MANY_REQUESTS
    );
}
