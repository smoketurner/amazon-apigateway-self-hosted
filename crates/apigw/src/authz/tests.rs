//! Lambda authorizers end to end: a real router in front of a fake authorizer
//! function and a fake backend, both reached through Lambda endpoint
//! overrides. The authorizer's verdict is chosen by the token the test sends.

#![expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#![expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use axum::routing::post;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::aws::{AwsClients, CredentialsMode, LambdaEndpoints};
use crate::gateway::{ApiContext, AuthorizationMode, Enforcement, Unsupported};
use crate::gateway_response::GatewayResponses;
use crate::integration::StageVariables;
use crate::model::{ApiKind, ApiModel, IntegrationOverrides, StageSettings};
use crate::router::{RouteSummary, build};

const AUTH_FUNCTION: &str = "arn:aws:lambda:us-east-1:123456789012:function:auth";
const ECHO_FUNCTION: &str = "arn:aws:lambda:us-east-1:123456789012:function:echo";

fn lambda_uri(function: &str) -> String {
    format!("arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{function}/invocations")
}

fn echo_integration() -> Value {
    json!({"type": "aws_proxy", "httpMethod": "POST", "uri": lambda_uri(ECHO_FUNCTION),
        "payloadFormatVersion": "1.0"})
}

#[derive(Default)]
struct Calls {
    events: Mutex<Vec<Value>>,
    count: AtomicUsize,
}

impl Calls {
    fn record(&self, event: &Value) {
        self.count.fetch_add(1, Ordering::SeqCst);
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(event.clone());
    }

    fn count(&self) -> usize {
        self.count.load(Ordering::SeqCst)
    }

    fn last(&self) -> Value {
        self.events
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .last()
            .cloned()
            .unwrap()
    }
}

/// What the authorizer function does, chosen by the token in the event.
fn verdict(event: &Value) -> (Option<&'static str>, String) {
    let header = |name: &str| {
        event
            .pointer(&format!("/headers/{name}"))
            .and_then(Value::as_str)
    };
    let token = event
        .get("authorizationToken")
        .and_then(Value::as_str)
        .or_else(|| header("x-token"))
        .unwrap_or_default();
    let arn = event
        .get("methodArn")
        .or_else(|| event.get("routeArn"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let policy = |effect: &str, resource: &str| {
        json!({"principalId": "user-1", "policyDocument": {"Version": "2012-10-17",
            "Statement": [{"Action": "execute-api:Invoke", "Effect": effect, "Resource": resource}]}})
    };
    let ok = |value: Value| (None, value.to_string());
    match token {
        "allow" => ok(policy("Allow", arn)),
        "allow-all" => ok(policy("Allow", "arn:aws:execute-api:*:*:abc/*/*/*")),
        "allow-pet-1" => ok(policy(
            "Allow",
            "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/1",
        )),
        "allow-then-deny" => ok(json!({"principalId": "u", "policyDocument": {"Statement": [
            {"Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "*"},
            {"Action": "execute-api:Invoke", "Effect": "Deny", "Resource": arn}]}})),
        "context" => {
            let mut value = policy("Allow", arn);
            value["context"] = json!({"tenant": "acme", "n": 5, "flag": true});
            ok(value)
        }
        "context-map" => {
            let mut value = policy("Allow", arn);
            value["context"] = json!({"nested": {"a": 1}});
            ok(value)
        }
        "context-array-ok" => {
            let mut value = policy("Allow", arn);
            value["context"] = json!({"list": ["a", "b"], "map": {"k": "v"}});
            ok(value)
        }
        "simple-true" => ok(json!({"isAuthorized": true, "context": {"tenant": "acme"}})),
        "simple-false" => ok(json!({"isAuthorized": false})),
        "simple-missing" => ok(json!({"context": {}})),
        "simple-string" => ok(json!({"isAuthorized": "true"})),
        "no-principal" => ok(json!({"policyDocument": {"Statement": []}})),
        "bad-policy" => ok(json!({"principalId": "u", "policyDocument": {"Statement": [
            {"Effect": "Allow", "Resource": "*"}]}})),
        "unauthorized" => (
            Some("Handled"),
            json!({"errorMessage": "Unauthorized"}).to_string(),
        ),
        "boom" => (
            Some("Unhandled"),
            json!({"errorMessage": "kaput"}).to_string(),
        ),
        "garbage" => (None, "not json".to_owned()),
        "not-an-object" => (None, "[]".to_owned()),
        // "deny", and anything unrecognised.
        _ => ok(policy("Deny", arn)),
    }
}

struct Harness {
    router: Router,
    summaries: Vec<RouteSummary>,
    auth_calls: Arc<Calls>,
    backend_calls: Arc<Calls>,
}

impl Harness {
    async fn start(doc: &Value, kind: ApiKind, mode: AuthorizationMode) -> Self {
        let auth_calls = Arc::new(Calls::default());
        let backend_calls = Arc::new(Calls::default());
        let auth = Arc::clone(&auth_calls);
        let backend = Arc::clone(&backend_calls);
        let app = Router::new()
            .route(
                "/auth",
                post(move |body: axum::body::Bytes| {
                    let auth = Arc::clone(&auth);
                    async move {
                        let event: Value = serde_json::from_slice(&body).unwrap();
                        auth.record(&event);
                        let (function_error, payload) = verdict(&event);
                        let mut headers = HeaderMap::new();
                        if let Some(error) = function_error {
                            headers.insert("X-Amz-Function-Error", error.parse().unwrap());
                        }
                        (headers, payload)
                    }
                }),
            )
            .route(
                "/echo",
                post(move |body: axum::body::Bytes| {
                    let backend = Arc::clone(&backend);
                    async move {
                        let event: Value = serde_json::from_slice(&body).unwrap();
                        backend.record(&event);
                        json!({"statusCode": 200, "body": event.to_string()}).to_string()
                    }
                }),
            )
            .route("/hang", post(std::future::pending::<String>));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let url = |path: &str| reqwest::Url::parse(&format!("http://{addr}{path}")).unwrap();
        let endpoints = LambdaEndpoints::from_iter([
            ("auth".to_owned(), url("/auth")),
            ("echo".to_owned(), url("/echo")),
            ("hanging".to_owned(), url("/hang")),
        ]);
        let sdk = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        let aws = Arc::new(AwsClients::new(
            sdk,
            CredentialsMode::Assume,
            endpoints,
            reqwest::Client::new(),
        ));
        let model = ApiModel::import(
            doc,
            kind,
            StageSettings::default(),
            &IntegrationOverrides::default(),
        )
        .unwrap();
        let api = Arc::new(ApiContext {
            kind,
            api_id: "abc".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: Arc::new(StageVariables::new(
                [("fn".to_owned(), "auth".to_owned())].into(),
            )),
            enforcement: Enforcement {
                authorization: mode,
                resource_policy: Unsupported::Reject,
                request_validation: Unsupported::Reject,
            },
            responses: GatewayResponses::default(),
            state: Arc::new(crate::state::StateBackend::InMemory(
                crate::state::InMemory::new(crate::state::InMemoryLimits::default()),
            )),
            replicas: std::num::NonZeroU32::MIN,
            observer: crate::observability::StageObserver::disabled(),
            http: reqwest::Client::new(),
            aws,
        });
        let (router, summaries) = build(&model, &api, &crate::router::BasePath::default());
        Self {
            router,
            summaries,
            auth_calls,
            backend_calls,
        }
    }

    async fn call(
        &self,
        method: Method,
        uri: &str,
        headers: &[(&str, &str)],
    ) -> (StatusCode, Value) {
        let mut request = Request::builder().method(method).uri(uri);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into_owned()));
        (status, body)
    }

    async fn get(&self, uri: &str, token: &str) -> (StatusCode, Value) {
        self.call(Method::GET, uri, &[("authorization", token)])
            .await
    }

    /// The `requestContext.authorizer` the backend received on its last call.
    fn backend_authorizer(&self) -> Value {
        self.backend_calls.last()["requestContext"]["authorizer"].clone()
    }
}

fn rest_token_doc(authorizer: Value) -> Value {
    let mut config = json!({"type": "token", "authorizerUri": lambda_uri(AUTH_FUNCTION),
        "authorizerResultTtlInSeconds": 300});
    if let (Some(config), Value::Object(extra)) = (config.as_object_mut(), authorizer) {
        config.extend(extra);
    }
    json!({
        "components": {"securitySchemes": {"auth": {
            "type": "apiKey", "name": "Authorization", "in": "header",
            "x-amazon-apigateway-authtype": "custom",
            "x-amazon-apigateway-authorizer": config}}},
        "paths": {
            "/pets/{id}": {"get": {"security": [{"auth": []}],
                "x-amazon-apigateway-integration": echo_integration()}},
            "/open": {"get": {"x-amazon-apigateway-integration": echo_integration()}}
        }
    })
}

async fn rest_token(authorizer: Value) -> Harness {
    Harness::start(
        &rest_token_doc(authorizer),
        ApiKind::Rest,
        AuthorizationMode::Enforce,
    )
    .await
}

fn message(body: &Value) -> &Value {
    &body["message"]
}

#[tokio::test]
async fn an_allowing_token_authorizer_reaches_the_backend_with_its_context() {
    let h = rest_token(json!({})).await;
    let (status, body) = h.get("/pets/7", "context").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(h.auth_calls.count(), 1);
    let event = h.auth_calls.last();
    assert_eq!(event["type"], "TOKEN");
    assert_eq!(event["authorizationToken"], "context");
    assert_eq!(
        event["methodArn"],
        "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/7"
    );
    assert_eq!(
        h.backend_authorizer(),
        json!({"principalId": "user-1", "tenant": "acme", "n": "5", "flag": "true"}),
        "REST context values reach the backend as strings"
    );
}

#[tokio::test]
async fn routes_without_an_authorizer_never_invoke_one() {
    let h = rest_token(json!({})).await;
    assert_eq!(h.call(Method::GET, "/open", &[]).await.0, StatusCode::OK);
    assert_eq!(h.auth_calls.count(), 0);
    assert!(h.backend_calls.last()["requestContext"]["authorizer"].is_null());
}

#[tokio::test]
async fn a_missing_or_empty_token_is_401_without_invoking_the_authorizer() {
    let h = rest_token(json!({})).await;
    let (status, body) = h.call(Method::GET, "/pets/7", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"message": "Unauthorized"}));
    let (status, _) = h
        .call(Method::GET, "/pets/7", &[("authorization", "")])
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.auth_calls.count(), 0);
    assert_eq!(h.backend_calls.count(), 0);
}

#[tokio::test]
async fn a_token_failing_the_validation_expression_is_401_without_invoking() {
    let h = rest_token(json!({"identityValidationExpression": "^Bearer [-0-9a-zA-Z._]+$"})).await;
    for token in [
        "allow",
        "Bearer",
        "Bearer a b",
        "xBearer a",
        "Bearer \u{e9}",
    ] {
        assert_eq!(
            h.get("/pets/7", token).await.0,
            StatusCode::UNAUTHORIZED,
            "{token:?}"
        );
    }
    assert_eq!(h.auth_calls.count(), 0);
}

#[tokio::test]
async fn the_validation_expression_must_match_the_whole_token() {
    let h = rest_token(json!({"identityValidationExpression": "allow"})).await;
    assert_eq!(h.get("/pets/7", "allow").await.0, StatusCode::OK);
    assert_eq!(
        h.get("/pets/7", "allowed").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.get("/pets/7", "xallow").await.0, StatusCode::UNAUTHORIZED);
    let h = rest_token(json!({"identityValidationExpression": "allow|deny"})).await;
    assert_eq!(h.get("/pets/7", "denyx").await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(h.get("/pets/7", "deny").await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn explicit_and_implicit_denials_are_403_with_api_gateways_messages() {
    let h = rest_token(json!({})).await;
    let (status, body) = h.get("/pets/7", "deny").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        message(&body),
        "User is not authorized to access this resource with an explicit deny in an identity-based policy"
    );
    let (status, body) = h.get("/pets/7", "allow-then-deny").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        message(&body),
        "User is not authorized to access this resource with an explicit deny in an identity-based policy"
    );
    let (status, body) = h.get("/pets/2", "allow-pet-1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        message(&body),
        "User is not authorized to access this resource"
    );
    assert_eq!(h.backend_calls.count(), 0);
}

#[tokio::test]
async fn authorizer_failures_map_to_401_and_500() {
    let h = rest_token(json!({"authorizerResultTtlInSeconds": 0})).await;
    let (status, body) = h.get("/pets/7", "unauthorized").await;
    assert_eq!(
        (status, body),
        (StatusCode::UNAUTHORIZED, json!({"message": "Unauthorized"}))
    );
    for token in [
        "boom",
        "garbage",
        "not-an-object",
        "no-principal",
        "bad-policy",
        "context-map",
    ] {
        let (status, body) = h.get("/pets/7", token).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{token}");
        assert_eq!(body, json!({"message": "Internal server error"}), "{token}");
    }
    assert_eq!(h.backend_calls.count(), 0, "no failure reaches the backend");
}

#[tokio::test]
async fn an_unreachable_authorizer_function_is_500() {
    let doc = rest_token_doc(json!({"authorizerUri": lambda_uri(
        "arn:aws:lambda:us-east-1:123456789012:function:nowhere")}));
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    // No endpoint override and no credentials: the SDK call fails.
    let started = std::time::Instant::now();
    let (status, _) = h.get("/pets/7", "allow").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert!(started.elapsed() < Duration::from_secs(9));
}

#[tokio::test(start_paused = true)]
async fn an_authorizer_that_does_not_answer_in_10_seconds_is_500() {
    let doc = rest_token_doc(json!({"authorizerUri": lambda_uri(
        "arn:aws:lambda:us-east-1:123456789012:function:hanging")}));
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    let (status, body) = h.get("/pets/7", "allow").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(body, json!({"message": "Internal server error"}));
    assert_eq!(h.backend_calls.count(), 0);
}

#[tokio::test]
async fn results_are_cached_by_token_and_the_policy_is_checked_per_method() {
    let h = rest_token(json!({})).await;
    assert_eq!(h.get("/pets/1", "allow-pet-1").await.0, StatusCode::OK);
    assert_eq!(h.get("/pets/1", "allow-pet-1").await.0, StatusCode::OK);
    assert_eq!(
        h.auth_calls.count(),
        1,
        "the second request is served from the cache"
    );
    // The cached policy only allows pets/1: another method is denied without
    // asking the function again.
    let (status, body) = h.get("/pets/2", "allow-pet-1").await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        message(&body),
        "User is not authorized to access this resource"
    );
    assert_eq!(h.auth_calls.count(), 1);
    // A different token is a different cache entry.
    assert_eq!(h.get("/pets/1", "allow-all").await.0, StatusCode::OK);
    assert_eq!(h.auth_calls.count(), 2);
}

#[tokio::test]
async fn denials_are_cached_too_and_failures_are_not() {
    let h = rest_token(json!({})).await;
    assert_eq!(h.get("/pets/1", "deny").await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.get("/pets/1", "deny").await.0, StatusCode::FORBIDDEN);
    assert_eq!(h.auth_calls.count(), 1);
    assert_eq!(
        h.get("/pets/1", "boom").await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(
        h.get("/pets/1", "boom").await.0,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert_eq!(h.auth_calls.count(), 3);
    assert_eq!(
        h.get("/pets/1", "unauthorized").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        h.get("/pets/1", "unauthorized").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.auth_calls.count(), 5);
}

#[tokio::test]
async fn a_zero_ttl_disables_caching() {
    let h = rest_token(json!({"authorizerResultTtlInSeconds": 0})).await;
    h.get("/pets/1", "allow").await;
    h.get("/pets/1", "allow").await;
    assert_eq!(h.auth_calls.count(), 2);
}

#[tokio::test]
async fn cached_results_expire_after_the_ttl() {
    let h = rest_token(json!({"authorizerResultTtlInSeconds": 1})).await;
    h.get("/pets/1", "allow").await;
    h.get("/pets/1", "allow").await;
    assert_eq!(h.auth_calls.count(), 1);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    h.get("/pets/1", "allow").await;
    assert_eq!(h.auth_calls.count(), 2);
}

#[tokio::test]
async fn rest_authorizers_cache_for_five_minutes_unless_configured() {
    let mut doc = rest_token_doc(json!({}));
    doc["components"]["securitySchemes"]["auth"]["x-amazon-apigateway-authorizer"]
        .as_object_mut()
        .unwrap()
        .remove("authorizerResultTtlInSeconds");
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    h.get("/pets/1", "allow-all").await;
    h.get("/pets/1", "allow-all").await;
    assert_eq!(h.auth_calls.count(), 1);
}

#[tokio::test]
async fn skipping_authorization_serves_without_invoking_the_authorizer() {
    let h = Harness::start(
        &rest_token_doc(json!({})),
        ApiKind::Rest,
        AuthorizationMode::Skip,
    )
    .await;
    assert_eq!(h.call(Method::GET, "/pets/7", &[]).await.0, StatusCode::OK);
    assert_eq!(h.auth_calls.count(), 0);
    assert!(h.backend_calls.last()["requestContext"]["authorizer"].is_null());
}

#[tokio::test]
async fn an_overlong_method_arn_is_414() {
    let h = rest_token(json!({})).await;
    let (status, _) = h.get(&format!("/pets/{}", "x".repeat(1700)), "allow").await;
    assert_eq!(status, StatusCode::URI_TOO_LONG);
    assert_eq!(h.auth_calls.count(), 0);
}

#[tokio::test]
async fn unevaluable_authorizers_fail_closed_and_are_reported() {
    for authorizer in [
        json!({"identityValidationExpression": r"\G\X"}),
        json!({"authorizerUri": "arn:aws:apigateway:us-east-1:s3:path/x"}),
        json!({"authorizerCredentials": "arn:aws:iam::*:user/*"}),
        json!({"identitySource": "method.request.header.A,method.request.header.B"}),
        json!({"identitySource": "method.request.path.id"}),
        json!({"type": "something-new"}),
    ] {
        let h = rest_token(authorizer.clone()).await;
        let (status, _) = h.get("/pets/7", "allow").await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{authorizer}");
        assert_eq!(h.auth_calls.count(), 0, "{authorizer}");
        let route = h
            .summaries
            .iter()
            .find(|s| s.route_key == "GET /pets/{id}")
            .unwrap();
        assert!(
            route.problems.iter().any(|p| p.contains("authorizer")),
            "{authorizer}: {route:?}"
        );
    }
}

#[tokio::test]
async fn an_authorizer_that_is_not_defined_fails_closed() {
    let doc = json!({"paths": {"/x": {"get": {"security": [{"missing": []}],
        "x-amazon-apigateway-integration": echo_integration()}}}});
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    assert_eq!(
        h.call(Method::GET, "/x", &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn stage_variables_can_name_the_authorizer_function() {
    let doc = rest_token_doc(
        json!({"authorizerUri": lambda_uri("arn:aws:lambda:us-east-1:123456789012:function:${stageVariables.fn}")}),
    );
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    assert_eq!(h.get("/pets/7", "allow").await.0, StatusCode::OK);
}

fn rest_request_doc(identity: &str) -> Value {
    json!({
        "components": {"securitySchemes": {"auth": {
            "type": "apiKey", "name": "Unused", "in": "header",
            "x-amazon-apigateway-authtype": "custom",
            "x-amazon-apigateway-authorizer": {"type": "request",
                "authorizerUri": lambda_uri(AUTH_FUNCTION),
                "identitySource": identity,
                "authorizerResultTtlInSeconds": 300}}}},
        "paths": {"/pets/{id}": {"get": {"security": [{"auth": []}],
            "x-amazon-apigateway-integration": echo_integration()}}}
    })
}

#[tokio::test]
async fn request_authorizers_get_the_request_and_need_every_identity_source() {
    let doc = rest_request_doc("method.request.header.X-Token, method.request.querystring.tenant");
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    let headers = [("x-token", "allow"), ("host", "api.example.com")];
    assert_eq!(
        h.call(Method::GET, "/pets/7?tenant=a", &headers).await.0,
        StatusCode::OK
    );
    let event = h.auth_calls.last();
    assert_eq!(event["type"], "REQUEST");
    assert_eq!(event["httpMethod"], "GET");
    assert_eq!(event["resource"], "/pets/{id}");
    assert_eq!(event["path"], "/pets/7");
    assert_eq!(event["queryStringParameters"], json!({"tenant": "a"}));
    assert_eq!(event["pathParameters"], json!({"id": "7"}));
    assert_eq!(event["headers"]["x-token"], "allow");
    assert_eq!(event["requestContext"]["stage"], "prod");
    assert!(event.get("body").is_none());
    assert!(event["requestContext"].get("authorizer").is_none());
    assert_eq!(
        event["methodArn"],
        "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/7"
    );

    assert_eq!(
        h.call(Method::GET, "/pets/7", &headers).await.0,
        StatusCode::UNAUTHORIZED,
        "missing query string parameter"
    );
    assert_eq!(
        h.call(Method::GET, "/pets/7?tenant=a", &[]).await.0,
        StatusCode::UNAUTHORIZED,
        "missing header"
    );
    assert_eq!(h.auth_calls.count(), 1);
}

#[tokio::test]
async fn request_authorizers_cache_on_the_combination_of_identity_sources() {
    let doc = rest_request_doc("method.request.header.X-Token, method.request.querystring.tenant");
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    let call = |tenant: &'static str| {
        let h = &h;
        async move {
            h.call(
                Method::GET,
                &format!("/pets/7?tenant={tenant}"),
                &[("x-token", "allow-all")],
            )
            .await
            .0
        }
    };
    call("a").await;
    call("a").await;
    assert_eq!(h.auth_calls.count(), 1);
    call("b").await;
    assert_eq!(h.auth_calls.count(), 2);
}

#[tokio::test]
async fn a_request_authorizer_without_identity_sources_is_never_cached() {
    let mut doc = rest_request_doc("");
    doc["components"]["securitySchemes"]["auth"]["x-amazon-apigateway-authorizer"]
        .as_object_mut()
        .unwrap()
        .remove("identitySource");
    let h = Harness::start(&doc, ApiKind::Rest, AuthorizationMode::Enforce).await;
    let headers = [("x-token", "allow-all")];
    h.call(Method::GET, "/pets/7", &headers).await;
    h.call(Method::GET, "/pets/7", &headers).await;
    assert_eq!(h.auth_calls.count(), 2);
}

fn http_doc(authorizer: Value) -> Value {
    let mut config = json!({"type": "request", "authorizerUri": lambda_uri(AUTH_FUNCTION),
        "identitySource": ["$request.header.X-Token"],
        "authorizerPayloadFormatVersion": "2.0", "enableSimpleResponses": true});
    if let (Some(config), Value::Object(extra)) = (config.as_object_mut(), authorizer) {
        config.extend(extra);
    }
    json!({
        "components": {"securitySchemes": {"auth": {"type": "apiKey", "name": "Authorization",
            "in": "header", "x-amazon-apigateway-authorizer": config}}},
        "paths": {"/pets/{id}": {"get": {"security": [{"auth": []}],
            "x-amazon-apigateway-integration": {"type": "aws_proxy", "httpMethod": "POST",
                "uri": ECHO_FUNCTION, "payloadFormatVersion": "2.0"}}}}
    })
}

async fn http(authorizer: Value) -> Harness {
    Harness::start(
        &http_doc(authorizer),
        ApiKind::Http,
        AuthorizationMode::Enforce,
    )
    .await
}

async fn http_get(h: &Harness, token: &str) -> (StatusCode, Value) {
    h.call(
        Method::GET,
        "/pets/7?a=1&a=2",
        &[("x-token", token), ("cookie", "k=v")],
    )
    .await
}

#[tokio::test]
async fn http_payload_2_simple_responses_allow_and_deny() {
    let h = http(json!({})).await;
    let (status, _) = http_get(&h, "simple-true").await;
    assert_eq!(status, StatusCode::OK);
    let event = h.auth_calls.last();
    assert_eq!(event["version"], "2.0");
    assert_eq!(event["type"], "REQUEST");
    assert_eq!(
        event["routeArn"],
        "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/7"
    );
    assert_eq!(event["identitySource"], json!(["simple-true"]));
    assert_eq!(event["rawQueryString"], "a=1&a=2");
    assert_eq!(event["queryStringParameters"], json!({"a": "1,2"}));
    assert_eq!(event["cookies"], json!(["k=v"]));
    assert_eq!(event["pathParameters"], json!({"id": "7"}));
    assert_eq!(event["requestContext"]["http"]["method"], "GET");
    assert!(event.get("body").is_none());
    assert_eq!(
        h.backend_calls.last()["requestContext"]["authorizer"],
        json!({"lambda": {"tenant": "acme"}}),
        "HTTP payload 2.0 nests the context under lambda"
    );

    let (status, body) = http_get(&h, "simple-false").await;
    assert_eq!(
        (status, body),
        (StatusCode::FORBIDDEN, json!({"message": "Forbidden"}))
    );
    for token in [
        "simple-missing",
        "simple-string",
        "allow",
        "boom",
        "garbage",
    ] {
        let (status, body) = http_get(&h, token).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{token}");
        assert_eq!(body, json!({"message": "Internal Server Error"}), "{token}");
    }
    let (status, body) = http_get(&h, "unauthorized").await;
    assert_eq!(
        (status, body),
        (StatusCode::UNAUTHORIZED, json!({"message": "Unauthorized"}))
    );
    let (status, body) = h.call(Method::GET, "/pets/7", &[]).await;
    assert_eq!(
        (status, body),
        (StatusCode::UNAUTHORIZED, json!({"message": "Unauthorized"}))
    );
}

#[tokio::test]
async fn http_payload_2_keeps_structured_context_values() {
    let h = http(json!({"enableSimpleResponses": false})).await;
    let (status, _) = http_get(&h, "context-array-ok").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        h.backend_calls.last()["requestContext"]["authorizer"],
        json!({"lambda": {"list": ["a", "b"], "map": {"k": "v"}}})
    );
}

#[tokio::test]
async fn http_policy_responses_are_evaluated_against_the_route_arn() {
    let h = http(json!({"enableSimpleResponses": false})).await;
    assert_eq!(http_get(&h, "allow").await.0, StatusCode::OK);
    let (status, body) = http_get(&h, "deny").await;
    assert_eq!(
        (status, body),
        (StatusCode::FORBIDDEN, json!({"message": "Forbidden"}))
    );
    let (status, body) = http_get(&h, "allow-pet-1").await;
    assert_eq!(
        (status, body),
        (StatusCode::FORBIDDEN, json!({"message": "Forbidden"}))
    );
    let (status, _) = http_get(&h, "simple-true").await;
    assert_eq!(
        status,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a simple response needs enableSimpleResponses"
    );
}

#[tokio::test]
async fn http_payload_1_matches_the_rest_request_event() {
    let h = http(json!({"authorizerPayloadFormatVersion": "1.0", "enableSimpleResponses": false}))
        .await;
    assert_eq!(http_get(&h, "allow").await.0, StatusCode::OK);
    let event = h.auth_calls.last();
    assert_eq!(event["version"], "1.0");
    assert_eq!(event["type"], "REQUEST");
    assert_eq!(
        event["methodArn"],
        "arn:aws:execute-api:us-east-1:123456789012:abc/prod/GET/pets/7"
    );
    assert_eq!(event["identitySource"], "allow");
    assert_eq!(event["authorizationToken"], "allow");
    assert_eq!(event["httpMethod"], "GET");
    assert_eq!(event["resource"], "/pets/{id}");
    assert!(event.get("routeArn").is_none());
}

#[tokio::test]
async fn http_authorizers_cache_only_with_a_ttl_and_identity_sources() {
    let h = http(json!({})).await;
    http_get(&h, "simple-true").await;
    http_get(&h, "simple-true").await;
    assert_eq!(h.auth_calls.count(), 2, "HTTP APIs do not cache by default");

    let h = http(json!({"authorizerResultTtlInSeconds": 300})).await;
    http_get(&h, "simple-true").await;
    http_get(&h, "simple-true").await;
    assert_eq!(h.auth_calls.count(), 1);
    http_get(&h, "simple-false").await;
    assert_eq!(h.auth_calls.count(), 2);

    let h = http(json!({"authorizerResultTtlInSeconds": 300, "identitySource": []})).await;
    h.call(Method::GET, "/pets/7", &[("x-token", "simple-true")])
        .await;
    h.call(Method::GET, "/pets/7", &[("x-token", "simple-true")])
        .await;
    assert_eq!(h.auth_calls.count(), 2, "no identity sources, no caching");
}

#[tokio::test]
async fn including_the_route_key_in_the_identity_sources_caches_per_route() {
    let mut doc = http_doc(json!({"authorizerResultTtlInSeconds": 300,
        "identitySource": ["$request.header.X-Token", "$context.routeKey"]}));
    doc["paths"]["/other"] = doc["paths"]["/pets/{id}"].clone();
    let h = Harness::start(&doc, ApiKind::Http, AuthorizationMode::Enforce).await;
    let headers = [("x-token", "simple-true")];
    h.call(Method::GET, "/pets/7", &headers).await;
    h.call(Method::GET, "/pets/8", &headers).await;
    assert_eq!(h.auth_calls.count(), 1);
    h.call(Method::GET, "/other", &headers).await;
    assert_eq!(h.auth_calls.count(), 2);
}

#[tokio::test]
async fn http_token_authorizers_do_not_exist() {
    let h = http(json!({"type": "token"})).await;
    assert_eq!(
        http_get(&h, "simple-true").await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.auth_calls.count(), 0);
}
