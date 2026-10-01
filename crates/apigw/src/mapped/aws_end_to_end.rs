//! End-to-end tests of REST `AWS` integrations: a real router built from an
//! `OpenAPI` document, and a local mock standing in for the AWS service that
//! records the signed request it receives. Nothing here reaches AWS.

#![expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#![expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use aws_sdk_lambda::config::{Credentials, SharedCredentialsProvider};
use aws_sigv4::http_request::{
    PayloadChecksumKind, PercentEncodingMode, SignableBody, SignableRequest, SigningSettings,
    UriPathNormalizationMode, sign,
};
use aws_sigv4::sign::v4;
use axum::Router;
use axum::body::Bytes;
use axum::extract::Request;
use axum::http::{HeaderMap, Method, StatusCode};
use serde_json::{Value, json};

use super::end_to_end::{call, doc, serve_kind, serve_with};
use crate::aws::{AwsClients, CredentialsMode, LambdaEndpoints, ServiceEndpoints};
use crate::model::ApiKind;
use crate::router::RouteSummary;

/// What the mock service received.
#[derive(Debug, Clone)]
struct Captured {
    method: String,
    path: String,
    query: Option<String>,
    headers: BTreeMap<String, String>,
    body: Vec<u8>,
}

type Log = Arc<Mutex<Vec<Captured>>>;

/// A service that records every request and answers `200 {"ok":true}`, or a
/// `400` JSON error for paths ending in `/missing`.
async fn mock_service() -> (reqwest::Url, Log) {
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    let app = Router::new().fallback(move |request: Request| {
        let seen = Arc::clone(&seen);
        async move {
            let (parts, body) = request.into_parts();
            let body = axum::body::to_bytes(body, 1 << 20)
                .await
                .unwrap_or_default();
            let headers = parts
                .headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((name.to_string(), value.to_str().ok()?.to_owned()))
                })
                .collect();
            let path = parts.uri.path().to_owned();
            seen.lock().unwrap().push(Captured {
                method: parts.method.to_string(),
                path: path.clone(),
                query: parts.uri.query().map(str::to_owned),
                headers,
                body: body.to_vec(),
            });
            if path.ends_with("/missing") {
                return (
                    StatusCode::BAD_REQUEST,
                    [("content-type", "application/x-amz-json-1.0")],
                    json!({"__type": "ResourceNotFoundException", "message": "nope"}).to_string(),
                );
            }
            (
                StatusCode::OK,
                [("content-type", "application/json")],
                json!({"ok": true}).to_string(),
            )
        }
    });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}").parse().unwrap(), log)
}

const ACCESS_KEY: &str = "AKIDTEST";
const SECRET_KEY: &str = "secret-key";
const SESSION_TOKEN: &str = "session-token";

fn credentials() -> Credentials {
    Credentials::new(
        ACCESS_KEY,
        SECRET_KEY,
        Some(SESSION_TOKEN.to_owned()),
        None,
        "test",
    )
}

/// AWS clients that sign with fixed credentials and send `services` to the mock.
fn clients(services: &[(&str, &reqwest::Url)], lambdas: LambdaEndpoints) -> AwsClients {
    let config = aws_config::SdkConfig::builder()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .credentials_provider(SharedCredentialsProvider::new(credentials()))
        .build();
    AwsClients::new(
        config,
        CredentialsMode::Gateway,
        lambdas,
        reqwest::Client::new(),
    )
    .with_service_endpoints(
        services
            .iter()
            .map(|(name, url)| ((*name).to_owned(), (*url).clone()))
            .collect::<ServiceEndpoints>(),
    )
}

/// Signs the request the mock captured the way the gateway should have, from
/// the headers its `Authorization` says were signed, and returns the
/// `Authorization` value that results.
fn expected_authorization(captured: &Captured, service: &str, region: &str) -> String {
    let authorization = &captured.headers["authorization"];
    let signed_names = authorization
        .split("SignedHeaders=")
        .nth(1)
        .and_then(|rest| rest.split(',').next())
        .unwrap()
        .split(';')
        .collect::<Vec<_>>();
    let amz_date = &captured.headers["x-amz-date"];
    let time = SystemTime::from(
        jiff::civil::DateTime::strptime("%Y%m%dT%H%M%SZ", amz_date)
            .unwrap()
            .to_zoned(jiff::tz::TimeZone::UTC)
            .unwrap()
            .timestamp(),
    );
    let mut settings = SigningSettings::default();
    if service == "s3" {
        settings.percent_encoding_mode = PercentEncodingMode::Single;
        settings.payload_checksum_kind = PayloadChecksumKind::XAmzSha256;
        settings.uri_path_normalization_mode = UriPathNormalizationMode::Disabled;
    }
    let identity = credentials().into();
    let params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name(service)
        .time(time)
        .settings(settings)
        .build()
        .unwrap()
        .into();
    let headers = signed_names
        .iter()
        .filter(|name| !name.starts_with("x-amz-date") && !name.starts_with("x-amz-security"))
        .filter(|name| !name.starts_with("x-amz-content-sha256"))
        .map(|name| (*name, captured.headers[*name].as_str()));
    let query = captured
        .query
        .as_ref()
        .map_or(String::new(), |query| format!("?{query}"));
    let uri = format!("{}{}", captured.host_url(), query);
    let request = SignableRequest::new(
        &captured.method,
        uri,
        headers,
        SignableBody::Bytes(&captured.body),
    )
    .unwrap();
    let (instructions, _) = sign(request, &params).unwrap().into_parts();
    instructions
        .headers()
        .find(|(name, _)| *name == "authorization")
        .map(|(_, value)| value.to_owned())
        .unwrap()
}

impl Captured {
    /// The URL the request was sent to, as the signer saw it.
    fn host_url(&self) -> String {
        format!("http://{}{}", self.headers["host"], self.path)
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).map(String::as_str)
    }
}

fn aws_integration(uri: &str, extra: &Value) -> Value {
    let mut integration = json!({
        "type": "aws",
        "httpMethod": "POST",
        "uri": uri,
        "passthroughBehavior": "never",
        "responses": {"default": {"statusCode": "200"}},
    });
    if let (Some(base), Some(extra)) = (integration.as_object_mut(), extra.as_object()) {
        base.extend(extra.clone());
    }
    integration
}

fn run(integration: &Value, mock: &reqwest::Url, service: &str) -> (Router, Vec<RouteSummary>) {
    serve_with(
        &doc("/x", "post", integration, &["200", "400"]),
        &[],
        &[],
        Some(clients(&[(service, mock)], LambdaEndpoints::default())),
    )
}

async fn post(router: &Router, body: &str) -> super::end_to_end::Reply {
    call(
        router,
        Method::POST,
        "/x",
        &[("content-type", "application/json")],
        body,
    )
    .await
}

#[tokio::test]
async fn sqs_path_requests_are_signed_and_carry_the_template_body() {
    let (mock, log) = mock_service().await;
    let integration = aws_integration(
        "arn:aws:apigateway:us-east-1:sqs:path/{account}/orders",
        &json!({
            "requestParameters": {
                "integration.request.path.account": "'123456789012'",
                "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'",
            },
            "requestTemplates": {"application/json":
                "Action=SendMessage&MessageBody=$util.urlEncode($input.body)"},
            "responses": {"default": {"statusCode": "200", "responseTemplates": {"application/json": "{\"queued\":true}"}}},
        }),
    );
    let (router, summaries) = run(&integration, &mock, "sqs");
    assert!(
        summaries.iter().all(|s| s.problems.is_empty()),
        "{summaries:?}"
    );
    assert_eq!(summaries[0].integration, "AWS");
    let reply = post(&router, r#"{"a":1}"#).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.json(), json!({"queued": true}));

    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/123456789012/orders");
    assert_eq!(seen.query, None);
    assert_eq!(
        String::from_utf8(seen.body.clone()).unwrap(),
        "Action=SendMessage&MessageBody=%7B%22a%22%3A1%7D"
    );
    assert_eq!(
        seen.header("content-type"),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(seen.header("x-amz-security-token"), Some(SESSION_TOKEN));
    let authorization = seen.header("authorization").unwrap();
    assert!(
        authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDTEST/"),
        "{authorization}"
    );
    assert!(
        authorization.contains("/us-east-1/sqs/aws4_request"),
        "{authorization}"
    );
    assert_eq!(
        authorization,
        expected_authorization(&seen, "sqs", "us-east-1")
    );
}

#[tokio::test]
async fn sqs_action_requests_put_the_action_in_the_query_string() {
    let (mock, log) = mock_service().await;
    let integration = aws_integration(
        "arn:aws:apigateway:us-east-1:sqs:action/SendMessage",
        &json!({
            "requestParameters": {
                "integration.request.querystring.QueueUrl": "'https://sqs.us-east-1.amazonaws.com/123456789012/orders'",
                "integration.request.header.Content-Type": "'application/x-www-form-urlencoded'",
            },
            "requestTemplates": {"application/json": "MessageBody=hello%20world"},
        }),
    );
    let (router, _) = run(&integration, &mock, "sqs");
    assert_eq!(post(&router, "{}").await.status, StatusCode::OK);
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.path, "/");
    assert_eq!(
        seen.query.as_deref(),
        Some(
            "QueueUrl=https%3A%2F%2Fsqs.us-east-1.amazonaws.com%2F123456789012%2Forders&Action=SendMessage"
        )
    );
    assert_eq!(
        seen.header("authorization").unwrap(),
        expected_authorization(&seen, "sqs", "us-east-1")
    );
}

#[tokio::test]
async fn mapped_headers_cannot_replace_the_signature_or_the_target() {
    let (mock, log) = mock_service().await;
    let integration = aws_integration(
        "arn:aws:apigateway:us-east-1:dynamodb:action/GetItem",
        &json!({
            "requestParameters": {
                "integration.request.header.Authorization": "'Bearer stolen'",
                "integration.request.header.Host": "'evil.example'",
                "integration.request.header.X-Amz-Security-Token": "'forged'",
                "integration.request.header.X-Amz-Target": "'DynamoDB_20120810.DeleteTable'",
                "integration.request.header.Content-Type": "'text/plain'",
            },
            "requestTemplates": {"application/json": "{}"},
        }),
    );
    let (router, _) = run(&integration, &mock, "dynamodb");
    assert_eq!(post(&router, "{}").await.status, StatusCode::OK);
    let seen = log.lock().unwrap().remove(0);
    assert!(
        seen.header("authorization")
            .unwrap()
            .starts_with("AWS4-HMAC-SHA256")
    );
    assert_eq!(seen.header("x-amz-security-token"), Some(SESSION_TOKEN));
    assert_eq!(
        seen.header("x-amz-target"),
        Some("DynamoDB_20120810.GetItem")
    );
    assert_eq!(
        seen.header("content-type"),
        Some("application/x-amz-json-1.0")
    );
    assert_ne!(seen.header("host"), Some("evil.example"));
    assert_eq!(
        seen.header("authorization").unwrap(),
        expected_authorization(&seen, "dynamodb", "us-east-1")
    );
}

#[tokio::test]
async fn dynamodb_actions_use_the_json_protocol() {
    let (mock, log) = mock_service().await;
    let integration = aws_integration(
        "arn:aws:apigateway:eu-west-1:dynamodb:action/PutItem",
        &json!({
            "requestTemplates": {"application/json":
                "{\"TableName\":\"orders\",\"Item\":{\"id\":{\"S\":\"$input.path('$.id')\"}}}"},
            "responses": {"default": {"statusCode": "200", "responseTemplates": {"application/json": "{\"stored\":true}"}}},
        }),
    );
    let (router, _) = run(&integration, &mock, "dynamodb");
    let reply = post(&router, r#"{"id":"a1"}"#).await;
    assert_eq!(reply.json(), json!({"stored": true}));
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(
        seen.header("x-amz-target"),
        Some("DynamoDB_20120810.PutItem")
    );
    assert_eq!(
        seen.header("content-type"),
        Some("application/x-amz-json-1.0")
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&seen.body).unwrap(),
        json!({"TableName": "orders", "Item": {"id": {"S": "a1"}}})
    );
    assert_eq!(
        seen.header("authorization").unwrap(),
        expected_authorization(&seen, "dynamodb", "eu-west-1")
    );
}

#[tokio::test]
async fn each_json_service_gets_its_own_target_and_content_type() {
    for (service, action, target, content_type) in [
        (
            "states",
            "StartExecution",
            "AWSStepFunctions.StartExecution",
            "application/x-amz-json-1.0",
        ),
        (
            "kinesis",
            "PutRecord",
            "Kinesis_20131202.PutRecord",
            "application/x-amz-json-1.1",
        ),
        (
            "events",
            "PutEvents",
            "AWSEvents.PutEvents",
            "application/x-amz-json-1.1",
        ),
    ] {
        let (mock, log) = mock_service().await;
        let integration = aws_integration(
            &format!("arn:aws:apigateway:us-east-1:{service}:action/{action}"),
            &json!({"requestTemplates": {"application/json": "{}"}}),
        );
        let (router, _) = run(&integration, &mock, service);
        assert_eq!(
            post(&router, "{}").await.status,
            StatusCode::OK,
            "{service}"
        );
        let seen = log.lock().unwrap().remove(0);
        assert_eq!(seen.header("x-amz-target"), Some(target), "{service}");
        assert_eq!(seen.header("content-type"), Some(content_type), "{service}");
        assert_eq!(
            seen.header("authorization").unwrap(),
            expected_authorization(&seen, service, "us-east-1"),
            "{service}"
        );
    }
}

#[tokio::test]
async fn s3_objects_are_read_with_the_s3_signing_rules() {
    let (mock, log) = mock_service().await;
    let integration = aws_integration(
        "arn:aws:apigateway:us-east-1:s3:path/{bucket}/{key}",
        &json!({
            "httpMethod": "GET",
            "passthroughBehavior": "when_no_match",
            "requestParameters": {
                "integration.request.path.bucket": "'reports'",
                "integration.request.path.key": "method.request.querystring.key",
            },
            "responses": {"default": {"statusCode": "200"}},
        }),
    );
    let (router, _) = run(&integration, &mock, "s3");
    let reply = call(
        &router,
        Method::POST,
        "/x?key=a%20b.txt",
        &[("content-type", "application/json")],
        "",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK);
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.method, "GET");
    assert_eq!(seen.path, "/reports/a%20b.txt");
    assert!(seen.header("x-amz-content-sha256").is_some());
    assert_eq!(
        seen.header("authorization").unwrap(),
        expected_authorization(&seen, "s3", "us-east-1")
    );
}

#[tokio::test]
async fn service_errors_are_selected_by_status_like_any_backend() {
    let (mock, _) = mock_service().await;
    let integration = aws_integration(
        "arn:aws:apigateway:us-east-1:sqs:path/{account}/missing",
        &json!({
            "requestParameters": {"integration.request.path.account": "'1'"},
            "requestTemplates": {"application/json": "Action=ReceiveMessage"},
            "responses": {
                "default": {"statusCode": "200"},
                "4\\d{2}": {"statusCode": "400", "responseTemplates": {"application/json":
                    "{\"error\":\"$input.path('$.__type')\"}"}},
            },
        }),
    );
    let (router, _) = run(&integration, &mock, "sqs");
    let reply = post(&router, "{}").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json(), json!({"error": "ResourceNotFoundException"}));
}

#[tokio::test]
async fn a_service_that_cannot_be_reached_answers_504() {
    let dead: reqwest::Url = "http://127.0.0.1:1".parse().unwrap();
    let integration = aws_integration(
        "arn:aws:apigateway:us-east-1:dynamodb:action/GetItem",
        &json!({"requestTemplates": {"application/json": "{}"}, "timeoutInMillis": 500}),
    );
    let (router, _) = run(&integration, &dead, "dynamodb");
    assert_eq!(
        post(&router, "{}").await.status,
        StatusCode::GATEWAY_TIMEOUT
    );
}

#[tokio::test]
async fn unsupported_services_and_missing_methods_are_reported_on_the_route() {
    let (mock, _) = mock_service().await;
    for (integration, reason) in [
        (
            aws_integration(
                "arn:aws:apigateway:us-east-1:ses:action/SendEmail",
                &json!({}),
            ),
            "not supported",
        ),
        (
            aws_integration(
                "arn:aws:apigateway:us-east-1:sqs:action/SendMessage",
                &json!({"httpMethod": null}),
            ),
            "httpMethod",
        ),
        (
            aws_integration(
                "arn:aws:apigateway:us-east-1:sqs:action/SendMessage",
                &json!({"credentials": "arn:aws:iam::*:user/*"}),
            ),
            "caller credential",
        ),
    ] {
        let (router, summaries) = run(&integration, &mock, "sqs");
        assert!(
            summaries[0].problems.iter().any(|p| p.contains(reason)),
            "{reason}: {summaries:?}"
        );
        assert_eq!(
            post(&router, "{}").await.status,
            StatusCode::NOT_IMPLEMENTED,
            "{reason}"
        );
    }
}

/// A Lambda Invoke emulator: `/ok` echoes the event, `/error` raises a function
/// error, and every call is recorded.
async fn lambda_emulator() -> (reqwest::Url, Log) {
    let log: Log = Arc::default();
    let seen = Arc::clone(&log);
    let record = move |headers: HeaderMap, body: Bytes| {
        let mut captured = Captured {
            method: "POST".to_owned(),
            path: String::new(),
            query: None,
            headers: BTreeMap::new(),
            body: body.to_vec(),
        };
        for (name, value) in &headers {
            if let Ok(value) = value.to_str() {
                captured.headers.insert(name.to_string(), value.to_owned());
            }
        }
        seen.lock().unwrap().push(captured);
    };
    let ok_record = record.clone();
    let app = Router::new()
        .route(
            "/ok",
            axum::routing::post(move |headers: HeaderMap, body: Bytes| {
                let asynchronous = headers
                    .get("x-amz-invocation-type")
                    .is_some_and(|value| value == "Event");
                let echoed = String::from_utf8_lossy(&body).into_owned();
                ok_record(headers, body);
                async move {
                    if asynchronous {
                        (StatusCode::ACCEPTED, String::new())
                    } else {
                        (StatusCode::OK, format!("{{\"echo\":{echoed}}}"))
                    }
                }
            }),
        )
        .route(
            "/error",
            axum::routing::post(move |headers: HeaderMap, body: Bytes| {
                record(headers, body);
                async {
                    (
                        [("X-Amz-Function-Error", "Unhandled")],
                        "{\"errorMessage\":\"Error: boom\",\"errorType\":\"Error\"}",
                    )
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}").parse().unwrap(), log)
}

const FUNCTION_URI: &str = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:{name}/invocations";

fn lambda_router(
    function: &str,
    emulator: &reqwest::Url,
    path: &str,
    extra: &Value,
) -> (Router, Vec<RouteSummary>) {
    let uri = FUNCTION_URI.replace("{name}", function);
    let integration = aws_integration(&uri, extra);
    let lambdas = LambdaEndpoints::from_iter([(function.to_owned(), emulator.join(path).unwrap())]);
    serve_with(
        &doc("/x", "post", &integration, &["200", "202", "400"]),
        &[],
        &[],
        Some(clients(&[], lambdas)),
    )
}

#[tokio::test]
async fn non_proxy_lambda_events_are_the_rendered_template() {
    let (emulator, log) = lambda_emulator().await;
    let (router, summaries) = lambda_router(
        "pets",
        &emulator,
        "ok",
        &json!({
            "requestTemplates": {"application/json": "{\"method\":\"$context.httpMethod\",\"body\":$input.json('$')}"},
            "responses": {"default": {"statusCode": "200", "responseTemplates": {"application/json": "$input.json('$.echo.body')"}}},
        }),
    );
    assert_eq!(summaries[0].integration, "AWS");
    assert_eq!(
        summaries[0].target.as_deref(),
        Some("arn:aws:lambda:us-east-1:123456789012:function:pets")
    );
    let reply = post(&router, r#"{"n":1}"#).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.json(), json!({"n": 1}));
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(
        serde_json::from_slice::<Value>(&seen.body).unwrap(),
        json!({"method": "POST", "body": {"n": 1}})
    );
    assert_eq!(
        seen.header("x-amz-invocation-type"),
        Some("RequestResponse")
    );
}

#[tokio::test]
async fn function_errors_are_selected_by_their_message() {
    let (emulator, _) = lambda_emulator().await;
    let (router, _) = lambda_router(
        "pets",
        &emulator,
        "error",
        &json!({
            "requestTemplates": {"application/json": "{}"},
            "responses": {
                "default": {"statusCode": "200", "responseTemplates": {"application/json": "{\"ok\":true}"}},
                ".*boom.*": {"statusCode": "400", "responseTemplates": {"application/json":
                    "{\"error\":\"$util.escapeJavaScript($input.path('$.errorMessage'))\"}"}},
            },
        }),
    );
    let reply = post(&router, "{}").await;
    assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    assert_eq!(reply.json(), json!({"error": "Error: boom"}));
}

#[tokio::test]
async fn a_successful_invocation_never_matches_a_message_pattern() {
    let (emulator, _) = lambda_emulator().await;
    let (router, _) = lambda_router(
        "pets",
        &emulator,
        "ok",
        &json!({
            "requestTemplates": {"application/json": "{}"},
            "responses": {
                "default": {"statusCode": "200"},
                ".*": {"statusCode": "400"},
            },
        }),
    );
    assert_eq!(post(&router, "{}").await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_invocation_type_header_makes_an_invocation_asynchronous() {
    let (emulator, log) = lambda_emulator().await;
    let (router, _) = lambda_router(
        "pets",
        &emulator,
        "ok",
        &json!({
            "requestParameters": {"integration.request.header.X-Amz-Invocation-Type": "'Event'"},
            "requestTemplates": {"application/json": "{\"fire\":\"forget\"}"},
            "responses": {"default": {"statusCode": "202"}},
        }),
    );
    let reply = post(&router, "{}").await;
    assert_eq!(reply.status, StatusCode::ACCEPTED);
    assert!(reply.body.is_empty());
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.header("x-amz-invocation-type"), Some("Event"));
}

#[tokio::test]
async fn an_unknown_invocation_type_answers_500() {
    let (emulator, log) = lambda_emulator().await;
    let (router, _) = lambda_router(
        "pets",
        &emulator,
        "ok",
        &json!({
            "requestParameters": {"integration.request.header.X-Amz-Invocation-Type": "'Later'"},
            "requestTemplates": {"application/json": "{}"},
        }),
    );
    assert_eq!(
        post(&router, "{}").await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(log.lock().unwrap().is_empty());
}

fn subtype(name: &str, parameters: &Value) -> Value {
    json!({
        "type": "aws_proxy",
        "integrationSubtype": name,
        "payloadFormatVersion": "1.0",
        "requestParameters": parameters,
    })
}

fn http_api(
    integration: &Value,
    mock: &reqwest::Url,
    service: &str,
) -> (Router, Vec<RouteSummary>) {
    let document = json!({"paths": {"/x": {"post": {
        "x-amazon-apigateway-integration": integration,
    }}}});
    serve_kind(
        ApiKind::Http,
        &document,
        &[],
        &[],
        Some(clients(&[(service, mock)], LambdaEndpoints::default())),
    )
}

#[tokio::test]
async fn sqs_send_message_maps_the_request_body_and_answers_with_the_service_response() {
    let (mock, log) = mock_service().await;
    let integration = subtype(
        "SQS-SendMessage",
        &json!({
            "QueueUrl": "https://sqs.eu-west-1.amazonaws.com/123456789012/orders",
            "MessageBody": "$request.body.message",
            "DelaySeconds": "5",
        }),
    );
    let (router, summaries) = http_api(&integration, &mock, "sqs");
    assert!(
        summaries.iter().all(|s| s.problems.is_empty()),
        "{summaries:?}"
    );
    assert_eq!(summaries[0].integration, "AWS_PROXY");
    assert_eq!(summaries[0].target.as_deref(), Some("SQS-SendMessage"));
    let reply = post(&router, r#"{"message":"hi there"}"#).await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    assert_eq!(reply.json(), json!({"ok": true}));
    assert_eq!(reply.header("content-type"), Some("application/json"));

    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/123456789012/orders");
    assert_eq!(
        String::from_utf8(seen.body.clone()).unwrap(),
        "Action=SendMessage&MessageBody=hi%20there&DelaySeconds=5"
    );
    let authorization = seen.header("authorization").unwrap();
    assert!(
        authorization.contains("/eu-west-1/sqs/aws4_request"),
        "{authorization}"
    );
    assert_eq!(
        authorization,
        expected_authorization(&seen, "sqs", "eu-west-1")
    );
}

#[tokio::test]
async fn the_region_parameter_wins_and_json_services_get_their_target() {
    let (mock, log) = mock_service().await;
    let integration = subtype(
        "EventBridge-PutEvents",
        &json!({
            "Region": "ap-southeast-2",
            "Source": "shop",
            "DetailType": "order.created",
            "Detail": "$request.body",
        }),
    );
    let (router, _) = http_api(&integration, &mock, "events");
    assert_eq!(post(&router, r#"{"id":7}"#).await.status, StatusCode::OK);
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.header("x-amz-target"), Some("AWSEvents.PutEvents"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen.body).unwrap(),
        json!({"Entries": [{
            "Source": "shop", "DetailType": "order.created", "Detail": "{\"id\":7}"
        }]})
    );
    assert_eq!(
        seen.header("authorization").unwrap(),
        expected_authorization(&seen, "events", "ap-southeast-2")
    );
}

#[tokio::test]
async fn app_config_reads_a_configuration_with_a_get() {
    let (mock, log) = mock_service().await;
    let integration = subtype(
        "AppConfig-GetConfiguration",
        &json!({
            "Region": "us-east-1",
            "Application": "shop",
            "Environment": "prod",
            "Configuration": "flags",
            "ClientId": "$request.header.x-client",
        }),
    );
    let (router, _) = http_api(&integration, &mock, "appconfig");
    let reply = call(
        &router,
        Method::POST,
        "/x",
        &[("x-client", "c-1"), ("content-type", "application/json")],
        "",
    )
    .await;
    assert_eq!(reply.status, StatusCode::OK, "{}", reply.body);
    let seen = log.lock().unwrap().remove(0);
    assert_eq!(seen.method, "GET");
    assert_eq!(
        seen.path,
        "/applications/shop/environments/prod/configurations/flags"
    );
    assert_eq!(seen.query.as_deref(), Some("client_id=c-1"));
    assert_eq!(
        seen.header("authorization").unwrap(),
        expected_authorization(&seen, "appconfig", "us-east-1")
    );
}

#[tokio::test]
async fn a_missing_required_parameter_answers_500_and_reaches_no_service() {
    let (mock, log) = mock_service().await;
    let integration = subtype(
        "SQS-SendMessage",
        &json!({
            "QueueUrl": "https://sqs.us-east-1.amazonaws.com/1/q",
            "MessageBody": "$request.body.absent",
        }),
    );
    let (router, _) = http_api(&integration, &mock, "sqs");
    assert_eq!(
        post(&router, "{}").await.status,
        StatusCode::INTERNAL_SERVER_ERROR
    );
    assert!(log.lock().unwrap().is_empty());
}

#[tokio::test]
async fn unknown_subtypes_and_rest_apis_are_reported_on_the_route() {
    let (mock, _) = mock_service().await;
    let (router, summaries) = http_api(&subtype("SES-SendEmail", &json!({})), &mock, "sqs");
    assert!(
        summaries[0]
            .problems
            .iter()
            .any(|p| p.contains("not supported")),
        "{summaries:?}"
    );
    assert_eq!(
        post(&router, "{}").await.status,
        StatusCode::NOT_IMPLEMENTED
    );

    let rest = doc(
        "/x",
        "post",
        &subtype("SQS-PurgeQueue", &json!({})),
        &["200"],
    );
    let (_, summaries) = serve_with(&rest, &[], &[], None);
    assert!(
        summaries[0]
            .problems
            .iter()
            .any(|p| p.contains("HTTP APIs")),
        "{summaries:?}"
    );
}
