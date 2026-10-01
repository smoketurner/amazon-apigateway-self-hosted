//! End-to-end tests of non-proxy integrations: a real router built from an
//! `OpenAPI` document, and a local HTTP backend that reports what it received.

#![expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#![expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::aws::AwsClients;
use crate::cors::Cors;
use crate::gateway_response::GatewayResponses;
use crate::integration::StageVariables;
use crate::model::{ApiKind, ApiModel, IntegrationOverrides, StageSettings};
use crate::payload::PayloadSettings;
use crate::router::tests::{STRICT, ctx};
use crate::router::{RouteSummary, build};

pub(super) struct Reply {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: String,
    pub(super) raw: Vec<u8>,
}

impl Reply {
    pub(super) fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }

    pub(super) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// A backend that echoes the request, answers a chosen status, and serves a
/// Base64 payload.
async fn backend() -> SocketAddr {
    let app = Router::new()
        .route(
            "/echo",
            axum::routing::any(|request: Request| async move {
                let (parts, body) = request.into_parts();
                let body = axum::body::to_bytes(body, 1 << 20)
                    .await
                    .unwrap_or_default();
                let headers: BTreeMap<String, String> = parts
                    .headers
                    .iter()
                    .filter_map(|(name, value)| {
                        Some((name.to_string(), value.to_str().ok()?.to_owned()))
                    })
                    .collect();
                (
                    [("x-backend", "b"), ("content-type", "application/json")],
                    json!({
                        "method": parts.method.as_str(),
                        "query": parts.uri.query(),
                        "headers": headers,
                        "body": String::from_utf8_lossy(&body),
                        "bytes": body.len(),
                    })
                    .to_string(),
                )
            }),
        )
        .route(
            "/status/{code}",
            axum::routing::get(
                |axum::extract::Path(code): axum::extract::Path<u16>| async move {
                    (
                        StatusCode::from_u16(code).unwrap_or(StatusCode::OK),
                        [("x-backend", "b"), ("content-type", "application/json")],
                        json!({"code": code, "message": "from backend"}).to_string(),
                    )
                },
            ),
        )
        .route(
            "/base64",
            axum::routing::get(|| async { ([("content-type", "text/plain")], "/wB/".to_owned()) }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    addr
}

pub(super) fn serve(
    doc: &Value,
    variables: &[(&str, &str)],
    binary: &[&str],
) -> (Router, Vec<RouteSummary>) {
    serve_with(doc, variables, binary, None)
}

/// Like [`serve`], with the API's AWS clients replaced when `aws` is given.
pub(super) fn serve_with(
    doc: &Value,
    variables: &[(&str, &str)],
    binary: &[&str],
    aws: Option<AwsClients>,
) -> (Router, Vec<RouteSummary>) {
    serve_kind(ApiKind::Rest, doc, variables, binary, aws)
}

/// Like [`serve_with`], for an API of either type.
pub(super) fn serve_kind(
    kind: ApiKind,
    doc: &Value,
    variables: &[(&str, &str)],
    binary: &[&str],
    aws: Option<AwsClients>,
) -> (Router, Vec<RouteSummary>) {
    let variables: BTreeMap<String, String> = variables
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let stage = StageSettings {
        variables: variables.clone(),
        ..StageSettings::default()
    };
    let model = ApiModel::import(doc, kind, stage, &IntegrationOverrides::default()).unwrap();
    let binary: Vec<String> = binary.iter().map(|t| (*t).to_owned()).collect();
    let mut api = ctx(
        kind,
        STRICT,
        GatewayResponses::compile(kind, &model.gateway_responses),
        None::<Cors>,
    );
    let settings = Arc::get_mut(&mut api).unwrap();
    settings.payload = Arc::new(PayloadSettings::new(&binary, None));
    settings.stage_variables = Arc::new(StageVariables::new(variables));
    if let Some(aws) = aws {
        settings.aws = Arc::new(aws);
    }
    build(&model, &api, &"".parse().unwrap())
}

pub(super) async fn call(
    router: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: &str,
) -> Reply {
    let mut builder = Request::builder().method(method).uri(uri);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder.body(Body::from(body.to_owned())).unwrap();
    let response = router.clone().oneshot(request).await.unwrap();
    let (parts, body) = response.into_parts();
    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&body).into_owned(),
        raw: body.to_vec(),
    }
}

/// A one-route REST API with a method response for each of `statuses`.
pub(super) fn doc(path: &str, method: &str, integration: &Value, statuses: &[&str]) -> Value {
    let responses: BTreeMap<&str, Value> = statuses
        .iter()
        .map(|status| (*status, json!({"description": status})))
        .collect();
    json!({"paths": {path: {method: {
        "responses": responses,
        "x-amazon-apigateway-integration": integration,
    }}}})
}

/// An `HTTP` integration to `path` on `addr`; `settings` override the defaults.
fn http(addr: SocketAddr, path: &str, mut settings: Value) -> Value {
    let defaults = json!({
        "type": "http",
        "httpMethod": "POST",
        "uri": format!("http://{addr}{path}"),
        "passthroughBehavior": "when_no_match",
        "responses": {"default": {"statusCode": "200"}},
    });
    if let (Some(settings), Some(defaults)) = (settings.as_object_mut(), defaults.as_object()) {
        for (name, value) in defaults {
            settings
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }
    settings
}

#[tokio::test]
async fn request_template_and_parameter_mappings_shape_the_backend_request() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({
            "requestParameters": {
                "integration.request.header.x-tenant": "method.request.header.x-tenant",
                "integration.request.header.x-stage": "stageVariables.env",
                "integration.request.querystring.page": "method.request.querystring.page",
                "integration.request.querystring.owner": "method.request.body.owner.name",
            },
            "requestTemplates": {"application/json":
                "{\"id\": \"$input.params('id')\", \"name\": $input.json('$.name'), \"ip\": \"$context.identity.sourceIp\"}"},
        }),
    );
    let (router, summaries) = serve(
        &doc("/orders/{id}", "post", &integration, &["200"]),
        &[("env", "prod")],
        &[],
    );
    assert!(
        summaries.iter().all(|s| s.problems.is_empty()),
        "{summaries:?}"
    );
    let reply = call(
        &router,
        Method::POST,
        "/orders/7?page=2&ignored=1",
        &[("content-type", "application/json"), ("x-tenant", "acme")],
        r#"{"name":"widget","owner":{"name":"ada"}}"#,
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let seen = reply.json();
    assert_eq!(seen["method"], "POST");
    assert_eq!(seen["query"], "owner=ada&page=2");
    assert_eq!(seen["headers"]["x-tenant"], "acme");
    assert_eq!(seen["headers"]["x-stage"], "prod");
    assert_eq!(seen["headers"]["content-type"], "application/json");
    let body: Value = serde_json::from_str(seen["body"].as_str().unwrap()).unwrap();
    assert_eq!(body["id"], "7");
    assert_eq!(body["name"], "widget");
    assert!(body["ip"].is_string());
}

#[tokio::test]
async fn client_headers_and_query_are_not_forwarded_unless_mapped() {
    let addr = backend().await;
    let (router, _) = serve(
        &doc("/e", "post", &http(addr, "/echo", json!({})), &["200"]),
        &[],
        &[],
    );
    let reply = call(
        &router,
        Method::POST,
        "/e?secret=1",
        &[("x-private", "no"), ("content-type", "text/plain")],
        "body",
    )
    .await;
    let seen = reply.json();
    assert_eq!(seen["query"], Value::Null);
    assert!(seen["headers"].get("x-private").is_none());
    assert_eq!(seen["body"], "body");
    assert_eq!(seen["headers"]["content-type"], "text/plain");
    assert!(
        seen["headers"]["user-agent"]
            .as_str()
            .unwrap()
            .starts_with("AmazonAPIGateway_")
    );
}

#[tokio::test]
async fn passthrough_behavior_decides_what_happens_without_a_matching_template() {
    let addr = backend().await;
    let cases = [
        ("when_no_match", true, StatusCode::OK),
        (
            "when_no_templates",
            true,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        ("never", true, StatusCode::UNSUPPORTED_MEDIA_TYPE),
        ("when_no_templates", false, StatusCode::OK),
        ("never", false, StatusCode::UNSUPPORTED_MEDIA_TYPE),
    ];
    for (behavior, has_template, expected) in cases {
        let mut extra = json!({"passthroughBehavior": behavior});
        if has_template {
            extra["requestTemplates"] = json!({"application/xml": "<x/>"});
        }
        let (router, _) = serve(
            &doc("/p", "post", &http(addr, "/echo", extra), &["200"]),
            &[],
            &[],
        );
        let reply = call(
            &router,
            Method::POST,
            "/p",
            &[("content-type", "application/json")],
            r#"{"a":1}"#,
        )
        .await;
        assert_eq!(
            reply.status, expected,
            "{behavior}, template: {has_template}"
        );
        if expected == StatusCode::UNSUPPORTED_MEDIA_TYPE {
            assert_eq!(reply.json(), json!({"message": "Unsupported Media Type"}));
        } else {
            assert_eq!(reply.json()["body"], r#"{"a":1}"#);
        }
    }
}

#[tokio::test]
async fn a_request_without_content_type_uses_the_json_template() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({"requestTemplates": {"application/json": "{\"templated\": true}"}}),
    );
    let (router, _) = serve(&doc("/t", "post", &integration, &["200"]), &[], &[]);
    let reply = call(&router, Method::POST, "/t", &[], "ignored").await;
    assert_eq!(reply.json()["body"], "{\"templated\": true}");
}

#[tokio::test]
async fn a_template_matches_a_content_type_with_parameters() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({"requestTemplates": {"application/json": "templated"}, "passthroughBehavior": "never"}),
    );
    let (router, _) = serve(&doc("/t", "post", &integration, &["200"]), &[], &[]);
    let reply = call(
        &router,
        Method::POST,
        "/t",
        &[("content-type", "application/json; charset=UTF-8")],
        "{}",
    )
    .await;
    assert_eq!(reply.json()["body"], "templated");
}

#[tokio::test]
async fn request_overrides_replace_mapped_parameters() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/{target}",
        json!({
            "requestParameters": {
                "integration.request.path.target": "'nowhere'",
                "integration.request.querystring.q": "'mapped'",
                "integration.request.header.x-a": "'mapped'",
            },
            "requestTemplates": {"application/json":
                "#set($context.requestOverride.path.target = 'echo')\n#set($context.requestOverride.querystring.q = 'overridden')\n#set($context.requestOverride.querystring.n = 25)\n#set($context.requestOverride.header.x-a = 'overridden')\n#set($context.requestOverride.header.x-b = 'new')\n{}"},
        }),
    );
    let (router, _) = serve(&doc("/o", "post", &integration, &["200"]), &[], &[]);
    let reply = call(
        &router,
        Method::POST,
        "/o",
        &[("content-type", "application/json")],
        "{}",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let seen = reply.json();
    assert_eq!(seen["query"], "n=25&q=overridden");
    assert_eq!(seen["headers"]["x-a"], "overridden");
    assert_eq!(seen["headers"]["x-b"], "new");
}

#[tokio::test]
async fn selection_patterns_choose_the_integration_response_by_status() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/status/{code}",
        json!({
            "httpMethod": "GET",
            "requestParameters": {"integration.request.path.code": "method.request.querystring.code"},
            "responses": {
                "default": {"statusCode": "200", "responseTemplates": {"application/json": "{\"ok\": true}"}},
                "4\\d{2}": {"statusCode": "400", "responseTemplates": {"application/json": "{\"client\": \"$input.path('$.message')\"}"}},
                "5\\d{2}": {"statusCode": "502",
                    "responseParameters": {"method.response.header.x-from-backend": "integration.response.header.x-backend"}},
            },
        }),
    );
    let (router, _) = serve(
        &doc("/s", "get", &integration, &["200", "400", "502"]),
        &[],
        &[],
    );
    let get = |code: &'static str| {
        let router = router.clone();
        async move { call(&router, Method::GET, &format!("/s?code={code}"), &[], "").await }
    };
    let ok = get("200").await;
    assert_eq!(
        (ok.status, ok.body.as_str()),
        (StatusCode::OK, "{\"ok\": true}")
    );
    let client = get("404").await;
    assert_eq!(client.status, StatusCode::BAD_REQUEST);
    assert_eq!(client.json(), json!({"client": "from backend"}));
    let server = get("503").await;
    assert_eq!(server.status, StatusCode::BAD_GATEWAY);
    assert_eq!(server.header("x-from-backend"), Some("b"));
    assert_eq!(server.json()["code"], 503);
}

#[tokio::test]
async fn no_matching_integration_response_answers_500() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/status/{code}",
        json!({
            "httpMethod": "GET",
            "requestParameters": {"integration.request.path.code": "method.request.querystring.code"},
            "responses": {"2\\d{2}": {"statusCode": "200"}},
        }),
    );
    let (router, _) = serve(&doc("/s", "get", &integration, &["200"]), &[], &[]);
    let reply = call(&router, Method::GET, "/s?code=404", &[], "").await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.json(), json!({"message": "Internal server error"}));
}

#[tokio::test]
async fn an_undeclared_method_response_answers_500() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({"responses": {"default": {"statusCode": "201"}}}),
    );
    let (router, _) = serve(&doc("/m", "post", &integration, &["200"]), &[], &[]);
    let reply = call(&router, Method::POST, "/m", &[], "").await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn response_parameters_map_headers_and_json_fields() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({
            "responses": {"default": {
                "statusCode": "200",
                "responseParameters": {
                    "method.response.header.x-method": "integration.response.body.method",
                    "method.response.header.x-stage": "stageVariables.env",
                    "method.response.header.x-literal": "'fixed'",
                    "method.response.header.x-backend": "integration.response.header.x-backend",
                    "method.response.header.x-request-id": "context.requestId",
                    "method.response.header.x-missing": "integration.response.header.nope",
                },
            }},
        }),
    );
    let (router, _) = serve(
        &doc("/r", "post", &integration, &["200"]),
        &[("env", "ref")],
        &[],
    );
    let reply = call(&router, Method::POST, "/r", &[], "").await;
    assert_eq!(reply.header("x-method"), Some("POST"));
    assert_eq!(reply.header("x-stage"), Some("ref"));
    assert_eq!(reply.header("x-literal"), Some("fixed"));
    assert_eq!(reply.header("x-backend"), Some("b"));
    assert!(reply.header("x-request-id").is_some());
    assert_eq!(reply.header("x-missing"), None);
    assert_eq!(reply.header("content-type"), Some("application/json"));
}

#[tokio::test]
async fn response_templates_follow_the_accept_header_and_may_override_the_status() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({"responses": {"default": {
            "statusCode": "200",
            "responseTemplates": {
                "application/json": "{\"json\": \"$input.path('$.method')\"}",
                "text/plain": "$input.path('$.method')\n#set($context.responseOverride.status = 202)\n#set($context.responseOverride.header.x-set = 'yes')",
            },
        }}}),
    );
    let (router, _) = serve(&doc("/a", "post", &integration, &["200"]), &[], &[]);
    let json_reply = call(
        &router,
        Method::POST,
        "/a",
        &[("accept", "application/json")],
        "",
    )
    .await;
    assert_eq!(json_reply.body, "{\"json\": \"POST\"}");
    assert_eq!(json_reply.status, StatusCode::OK);
    let default_reply = call(&router, Method::POST, "/a", &[("accept", "image/png")], "").await;
    assert_eq!(default_reply.body, "{\"json\": \"POST\"}");
    let text = call(
        &router,
        Method::POST,
        "/a",
        &[("accept", "text/html, text/plain;q=0.5")],
        "",
    )
    .await;
    assert_eq!(text.body, "POST\n");
    assert_eq!(text.status, StatusCode::ACCEPTED);
    assert_eq!(text.header("x-set"), Some("yes"));
}

#[tokio::test]
async fn invalid_templates_are_reported_and_answer_500() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({"requestTemplates": {"application/json": "#if(true) never closed"}}),
    );
    let (router, summaries) = serve(&doc("/b", "post", &integration, &["200"]), &[], &[]);
    assert!(
        summaries
            .iter()
            .any(|s| s.problems.iter().any(|p| p.contains("request template"))),
        "{summaries:?}"
    );
    let reply = call(
        &router,
        Method::POST,
        "/b",
        &[("content-type", "application/json")],
        "{}",
    )
    .await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(reply.json(), json!({"message": "Internal server error"}));
}

#[tokio::test]
async fn a_failing_render_answers_500() {
    let addr = backend().await;
    let integration = http(
        addr,
        "/echo",
        json!({"requestTemplates": {"application/json": "$input.json('$[?(')"}}),
    );
    let (router, _) = serve(&doc("/b", "post", &integration, &["200"]), &[], &[]);
    let reply = call(
        &router,
        Method::POST,
        "/b",
        &[("content-type", "application/json")],
        "{}",
    )
    .await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn content_handling_converts_binary_requests_and_responses() {
    let addr = backend().await;
    let request = http(
        addr,
        "/echo",
        json!({"contentHandling": "CONVERT_TO_TEXT",
            "requestTemplates": {"application/octet-stream": "$input.body"}}),
    );
    let (router, _) = serve(
        &doc("/in", "post", &request, &["200"]),
        &[],
        &["application/octet-stream"],
    );
    let reply = call(
        &router,
        Method::POST,
        "/in",
        &[("content-type", "application/octet-stream")],
        "abc",
    )
    .await;
    assert_eq!(reply.json()["body"], "YWJj");

    let response = http(
        addr,
        "/base64",
        json!({"httpMethod": "GET", "responses": {"default": {
            "statusCode": "200", "contentHandling": "CONVERT_TO_BINARY",
        }}}),
    );
    let (router, _) = serve(
        &doc("/out", "get", &response, &["200"]),
        &[],
        &["application/octet-stream"],
    );
    let reply = call(&router, Method::GET, "/out", &[], "").await;
    assert_eq!(reply.raw, vec![0xff, 0x00, 0x7f]);
}

fn mock(request_template: &str, responses: &Value) -> Value {
    json!({"type": "mock", "requestTemplates": {"application/json": request_template}, "responses": responses})
}

#[tokio::test]
async fn mock_integrations_render_response_templates_with_vtl() {
    let integration = mock(
        "{\"statusCode\": 200}",
        &json!({"default": {"statusCode": "200", "responseTemplates": {"application/json":
            "#set($name = $input.params('name'))\n{\"hello\":\"$name\",\"stage\":\"$context.stage\",\"method\":\"$context.httpMethod\"}"}}}),
    );
    let (router, summaries) = serve(&doc("/m", "get", &integration, &["200"]), &[], &[]);
    assert!(
        summaries.iter().all(|s| s.problems.is_empty()),
        "{summaries:?}"
    );
    let reply = call(&router, Method::GET, "/m?name=world", &[], "").await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(
        reply.json(),
        json!({"hello": "world", "stage": "$default", "method": "GET"})
    );
}

#[tokio::test]
async fn mock_status_selects_the_integration_response() {
    let integration = mock(
        "#if($input.params('teapot') == 'yes'){\"statusCode\": 418}#else{\"statusCode\": 200}#end",
        &json!({
            "default": {"statusCode": "200", "responseTemplates": {"application/json": "{\"ok\":true}"}},
            "418": {"statusCode": "418", "responseParameters": {"method.response.header.x-mock": "'teapot'"},
                "responseTemplates": {"application/json": "{\"teapot\":true}"}},
        }),
    );
    let (router, _) = serve(&doc("/m", "get", &integration, &["200", "418"]), &[], &[]);
    let teapot = call(&router, Method::GET, "/m?teapot=yes", &[], "").await;
    assert_eq!(teapot.status, StatusCode::IM_A_TEAPOT);
    assert_eq!(teapot.header("x-mock"), Some("teapot"));
    assert_eq!(teapot.json(), json!({"teapot": true}));
    let ok = call(&router, Method::GET, "/m", &[], "").await;
    assert_eq!(ok.status, StatusCode::OK);
}

#[tokio::test]
async fn a_mock_without_integration_responses_answers_500() {
    let integration = mock("{\"statusCode\": 200}", &json!({}));
    let (router, _) = serve(&doc("/m", "get", &integration, &["200"]), &[], &[]);
    let reply = call(&router, Method::GET, "/m", &[], "").await;
    assert_eq!(reply.status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn an_unreachable_backend_answers_504_like_api_gateway() {
    let integration = http(
        "127.0.0.1:1".parse().unwrap(),
        "/echo",
        json!({"timeoutInMillis": 500}),
    );
    let (router, _) = serve(&doc("/u", "post", &integration, &["200"]), &[], &[]);
    let reply = call(&router, Method::POST, "/u", &[], "").await;
    assert_eq!(reply.status, StatusCode::GATEWAY_TIMEOUT);
}
