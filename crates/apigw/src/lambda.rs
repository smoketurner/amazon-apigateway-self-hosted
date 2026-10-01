//! `AWS_PROXY` Lambda integrations using API Gateway's proxy event formats
//! (payload format 1.0 for REST APIs, 1.0 or 2.0 for HTTP APIs).

use std::collections::BTreeMap;

use aws_sdk_lambda::primitives::Blob;
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::gateway::{self, ApiContext, Incoming};
use crate::proxy::timeout_error;
use crate::spec::{LambdaProxy, PayloadVersion, Route, RoutePath};

pub(crate) async fn invoke(
    ctx: &ApiContext,
    target: &LambdaProxy,
    route: &Route,
    incoming: &Incoming,
) -> Response {
    let event = match target.payload {
        PayloadVersion::V1 => event_v1(ctx, route, incoming),
        PayloadVersion::V2 => event_v2(ctx, route, incoming),
    };
    let call = ctx
        .lambda
        .invoke()
        .function_name(&target.function)
        .payload(Blob::new(event.to_string()))
        .send();
    let output = match tokio::time::timeout(target.timeout, call).await {
        Err(_) => {
            tracing::warn!(route = %route.route_key(), function = target.function, "Lambda invocation timed out");
            return timeout_error(ctx.kind);
        }
        Ok(Err(err)) => {
            tracing::error!(
                route = %route.route_key(),
                function = target.function,
                err = %aws_sdk_lambda::error::DisplayErrorContext(err),
                "Lambda invocation failed"
            );
            return internal_error();
        }
        Ok(Ok(output)) => output,
    };
    if let Some(function_error) = output.function_error {
        tracing::warn!(route = %route.route_key(), function = target.function, function_error, "Lambda function returned an error");
        return internal_error();
    }
    let payload = output.payload.map(Blob::into_inner).unwrap_or_default();
    match into_response(&payload, target.payload) {
        Ok(response) => response,
        Err(reason) => {
            tracing::error!(route = %route.route_key(), function = target.function, reason, "malformed Lambda proxy response");
            internal_error()
        }
    }
}

fn internal_error() -> Response {
    gateway::error(StatusCode::BAD_GATEWAY, "Internal server error")
}

/// Bodies that are valid UTF-8 are passed as text; anything else is base64.
fn encode_body(body: &[u8]) -> (Value, bool) {
    if body.is_empty() {
        return (Value::Null, false);
    }
    match std::str::from_utf8(body) {
        Ok(text) => (Value::String(text.to_owned()), false),
        Err(_) => (Value::String(BASE64.encode(body)), true),
    }
}

fn object_or_null(map: Map<String, Value>) -> Value {
    if map.is_empty() {
        Value::Null
    } else {
        Value::Object(map)
    }
}

fn string_map<'a>(pairs: impl IntoIterator<Item = (&'a String, &'a String)>) -> Map<String, Value> {
    pairs
        .into_iter()
        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
        .collect()
}

fn resource_path(route: &Route) -> String {
    match route.path {
        RoutePath::Default => "$default".to_owned(),
        RoutePath::Resource(ref path) => path.clone(),
    }
}

fn stage_name(ctx: &ApiContext) -> &str {
    ctx.stage.as_deref().unwrap_or("$default")
}

fn event_v1(ctx: &ApiContext, route: &Route, incoming: &Incoming) -> Value {
    let mut headers = Map::new();
    let mut multi_headers: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (name, value) in &incoming.headers {
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        headers.insert(name.as_str().to_owned(), Value::String(value.clone()));
        multi_headers
            .entry(name.as_str().to_owned())
            .or_default()
            .push(Value::String(value));
    }
    let mut query = Map::new();
    let mut multi_query: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for (key, value) in incoming.query_pairs() {
        query.insert(key.clone(), Value::String(value.clone()));
        multi_query
            .entry(key)
            .or_default()
            .push(Value::String(value));
    }
    let (body, is_base64) = encode_body(&incoming.body);
    let resource = resource_path(route);
    json!({
        "resource": resource,
        "path": incoming.path,
        "httpMethod": incoming.method.as_str(),
        "headers": object_or_null(headers),
        "multiValueHeaders": object_or_null(multi_headers.into_iter().map(|(k, v)| (k, Value::Array(v))).collect()),
        "queryStringParameters": object_or_null(query),
        "multiValueQueryStringParameters": object_or_null(multi_query.into_iter().map(|(k, v)| (k, Value::Array(v))).collect()),
        "pathParameters": object_or_null(string_map(incoming.path_params.iter().map(|(k, v)| (k, v)))),
        "stageVariables": object_or_null(string_map(&ctx.stage_variables)),
        "requestContext": {
            "accountId": "",
            "apiId": ctx.api_id,
            "httpMethod": incoming.method.as_str(),
            "path": incoming.path,
            "protocol": "HTTP/1.1",
            "requestId": incoming.request_id.to_string(),
            "requestTime": request_time(incoming.received),
            "requestTimeEpoch": incoming.received.as_millisecond(),
            "resourcePath": resource,
            "stage": stage_name(ctx),
            "domainName": incoming.header_str("host").unwrap_or_default(),
            "identity": {
                "sourceIp": incoming.source_ip,
                "userAgent": incoming.header_str("user-agent"),
            },
        },
        "body": body,
        "isBase64Encoded": is_base64,
    })
}

fn event_v2(ctx: &ApiContext, route: &Route, incoming: &Incoming) -> Value {
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut cookies = Vec::new();
    for (name, value) in &incoming.headers {
        let value = String::from_utf8_lossy(value.as_bytes()).into_owned();
        if name == header::COOKIE {
            cookies.extend(
                value
                    .split(';')
                    .map(str::trim)
                    .filter(|c| !c.is_empty())
                    .map(str::to_owned),
            );
            continue;
        }
        join_into(&mut headers, name.as_str().to_owned(), value);
    }
    let mut query: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in incoming.query_pairs() {
        join_into(&mut query, key, value);
    }
    let (body, is_base64) = encode_body(&incoming.body);
    let route_key = route.route_key();
    let host = incoming.header_str("host").unwrap_or_default();
    let mut event = json!({
        "version": "2.0",
        "routeKey": route_key,
        "rawPath": incoming.path,
        "rawQueryString": incoming.query.as_deref().unwrap_or_default(),
        "headers": string_map(&headers),
        "requestContext": {
            "accountId": "",
            "apiId": ctx.api_id,
            "domainName": host,
            "domainPrefix": host.split('.').next().unwrap_or_default(),
            "http": {
                "method": incoming.method.as_str(),
                "path": incoming.path,
                "protocol": "HTTP/1.1",
                "sourceIp": incoming.source_ip,
                "userAgent": incoming.header_str("user-agent"),
            },
            "requestId": incoming.request_id.to_string(),
            "routeKey": route_key,
            "stage": stage_name(ctx),
            "time": request_time(incoming.received),
            "timeEpoch": incoming.received.as_millisecond(),
        },
        "isBase64Encoded": is_base64,
    });
    if let Value::Object(ref mut fields) = event {
        if !cookies.is_empty() {
            fields.insert("cookies".to_owned(), json!(cookies));
        }
        if !query.is_empty() {
            fields.insert(
                "queryStringParameters".to_owned(),
                Value::Object(string_map(&query)),
            );
        }
        if !incoming.path_params.is_empty() {
            fields.insert(
                "pathParameters".to_owned(),
                Value::Object(string_map(incoming.path_params.iter().map(|(k, v)| (k, v)))),
            );
        }
        if !ctx.stage_variables.is_empty() {
            fields.insert(
                "stageVariables".to_owned(),
                Value::Object(string_map(&ctx.stage_variables)),
            );
        }
        if !body.is_null() {
            fields.insert("body".to_owned(), body);
        }
    }
    event
}

/// Payload format 2.0 joins repeated headers and query parameters with commas.
fn join_into(map: &mut BTreeMap<String, String>, key: String, value: String) {
    map.entry(key)
        .and_modify(|existing| {
            existing.push(',');
            existing.push_str(&value);
        })
        .or_insert(value);
}

fn request_time(at: jiff::Timestamp) -> String {
    at.strftime("%d/%b/%Y:%H:%M:%S %z").to_string()
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProxyResponse {
    status_code: u16,
    #[serde(default)]
    headers: BTreeMap<String, Value>,
    #[serde(default)]
    multi_value_headers: BTreeMap<String, Vec<Value>>,
    #[serde(default)]
    cookies: Vec<String>,
    body: Option<String>,
    #[serde(default)]
    is_base64_encoded: bool,
}

fn into_response(payload: &[u8], version: PayloadVersion) -> Result<Response, String> {
    let value: Value = serde_json::from_slice(payload).map_err(|e| format!("not JSON: {e}"))?;
    let has_status = value.get("statusCode").is_some();
    if version == PayloadVersion::V2 && !has_status {
        let mut response = Response::new(Body::from(value.to_string()));
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        return Ok(response);
    }
    let parsed = ProxyResponse::deserialize(&value).map_err(|e| e.to_string())?;
    let status = StatusCode::from_u16(parsed.status_code).map_err(|e| e.to_string())?;
    let body = match (parsed.body, parsed.is_base64_encoded) {
        (Some(body), true) => BASE64
            .decode(body)
            .map_err(|e| format!("body is not base64: {e}"))?,
        (Some(body), false) => body.into_bytes(),
        (None, _) => Vec::new(),
    };
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in parsed.headers {
        let (name, value) = header_pair(&name, &value)?;
        headers.insert(name, value);
    }
    for (name, values) in parsed.multi_value_headers {
        for value in values {
            let (name, value) = header_pair(&name, &value)?;
            headers.append(name, value);
        }
    }
    for cookie in parsed.cookies {
        let value = HeaderValue::try_from(cookie).map_err(|e| e.to_string())?;
        headers.append(header::SET_COOKIE, value);
    }
    Ok(response)
}

fn header_pair(name: &str, value: &Value) -> Result<(HeaderName, HeaderValue), String> {
    let text = match value {
        Value::String(s) => s.clone(),
        Value::Number(_) | Value::Bool(_) => value.to_string(),
        Value::Null | Value::Array(_) | Value::Object(_) => {
            return Err(format!("header {name:?} has a non-scalar value"));
        }
    };
    let name = HeaderName::try_from(name).map_err(|e| e.to_string())?;
    let value = HeaderValue::try_from(text).map_err(|e| e.to_string())?;
    Ok((name, value))
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]
mod tests {
    use axum::body::Bytes;
    use axum::http::{HeaderMap, Method};

    use super::*;
    use crate::gateway::{AuthorizationMode, Enforcement, Unsupported};
    use crate::spec::{ApiKind, Integration, MethodMatch, Protections};

    fn ctx(kind: ApiKind) -> ApiContext {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        ApiContext {
            kind,
            api_id: "abc123".to_owned(),
            stage: Some("prod".to_owned()),
            stage_variables: BTreeMap::from([("env".to_owned(), "local".to_owned())]),
            enforcement: Enforcement {
                authorization: AuthorizationMode::Enforce,
                resource_policy: Unsupported::Reject,
                request_validation: Unsupported::Reject,
            },
            http: reqwest::Client::new(),
            lambda: aws_sdk_lambda::Client::new(&config),
        }
    }

    fn route() -> Route {
        Route {
            method: MethodMatch::Exact(Method::POST),
            path: RoutePath::Resource("/pets/{petId}".to_owned()),
            integration: Integration::Unsupported {
                reason: String::new(),
            },
            protections: Protections::default(),
        }
    }

    fn incoming(body: &'static [u8]) -> Incoming {
        let mut headers = HeaderMap::new();
        headers.append("x-multi", HeaderValue::from_static("a"));
        headers.append("x-multi", HeaderValue::from_static("b"));
        headers.insert("cookie", HeaderValue::from_static("s=1; t=2"));
        headers.insert("host", HeaderValue::from_static("api.example.com"));
        Incoming {
            request_id: uuid::Uuid::now_v7(),
            received: jiff::Timestamp::from_second(1_700_000_000).unwrap(),
            method: Method::POST,
            path: "/pets/7".to_owned(),
            query: Some("q=1&q=2".to_owned()),
            headers,
            path_params: vec![("petId".to_owned(), "7".to_owned())],
            source_ip: Some("192.0.2.1".to_owned()),
            body: Bytes::from_static(body),
        }
    }

    #[test]
    fn v1_event_has_single_and_multi_value_fields() {
        let event = event_v1(&ctx(ApiKind::Rest), &route(), &incoming(b"{\"a\":1}"));
        assert_eq!(event["resource"], "/pets/{petId}");
        assert_eq!(event["httpMethod"], "POST");
        assert_eq!(event["headers"]["x-multi"], "b");
        assert_eq!(event["multiValueHeaders"]["x-multi"], json!(["a", "b"]));
        assert_eq!(event["queryStringParameters"]["q"], "2");
        assert_eq!(
            event["multiValueQueryStringParameters"]["q"],
            json!(["1", "2"])
        );
        assert_eq!(event["pathParameters"]["petId"], "7");
        assert_eq!(event["stageVariables"]["env"], "local");
        assert_eq!(event["requestContext"]["stage"], "prod");
        assert_eq!(
            event["requestContext"]["requestTime"],
            "14/Nov/2023:22:13:20 +0000"
        );
        assert_eq!(event["requestContext"]["identity"]["sourceIp"], "192.0.2.1");
        assert_eq!(event["body"], "{\"a\":1}");
        assert_eq!(event["isBase64Encoded"], false);
    }

    #[test]
    fn v2_event_joins_values_and_extracts_cookies() {
        let event = event_v2(&ctx(ApiKind::Http), &route(), &incoming(&[0xff, 0x00]));
        assert_eq!(event["version"], "2.0");
        assert_eq!(event["routeKey"], "POST /pets/{petId}");
        assert_eq!(event["rawQueryString"], "q=1&q=2");
        assert_eq!(event["headers"]["x-multi"], "a,b");
        assert!(event["headers"].get("cookie").is_none());
        assert_eq!(event["cookies"], json!(["s=1", "t=2"]));
        assert_eq!(event["queryStringParameters"]["q"], "1,2");
        assert_eq!(event["requestContext"]["domainPrefix"], "api");
        assert_eq!(event["body"], "/wA=");
        assert_eq!(event["isBase64Encoded"], true);
    }

    #[test]
    fn empty_collections_are_null_in_v1_and_absent_in_v2() {
        let mut req = incoming(b"");
        req.query = None;
        req.path_params.clear();
        let mut context = ctx(ApiKind::Rest);
        context.stage_variables.clear();
        let v1 = event_v1(&context, &route(), &req);
        assert!(v1["queryStringParameters"].is_null());
        assert!(v1["pathParameters"].is_null());
        assert!(v1["stageVariables"].is_null());
        assert!(v1["body"].is_null());
        let v2 = event_v2(&context, &route(), &req);
        for field in [
            "queryStringParameters",
            "pathParameters",
            "stageVariables",
            "body",
        ] {
            assert!(v2.get(field).is_none(), "{field}");
        }
    }

    async fn body_of(response: Response) -> Bytes {
        axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn structured_response_maps_status_headers_and_cookies() {
        let payload = json!({
            "statusCode": 201,
            "headers": {"x-one": "1", "x-num": 2},
            "multiValueHeaders": {"x-many": ["a", "b"]},
            "cookies": ["c=1"],
            "body": "aGk=",
            "isBase64Encoded": true
        });
        let response = into_response(payload.to_string().as_bytes(), PayloadVersion::V2).unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-num"], "2");
        assert_eq!(response.headers().get_all("x-many").iter().count(), 2);
        assert_eq!(response.headers()["set-cookie"], "c=1");
        assert_eq!(&body_of(response).await[..], b"hi");
    }

    #[tokio::test]
    async fn v2_infers_response_without_status_code() {
        let response = into_response(br#"{"hello":"world"}"#, PayloadVersion::V2).unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["content-type"], "application/json");
        assert_eq!(&body_of(response).await[..], br#"{"hello":"world"}"#);
    }

    #[test]
    fn malformed_responses_are_rejected() {
        let cases: [&[u8]; 6] = [
            b"not json",
            br#"{"hello":"world"}"#,
            br#"{"statusCode": 99}"#,
            br#"{"statusCode": 200, "body": "!!", "isBase64Encoded": true}"#,
            br#"{"statusCode": 200, "headers": {"x": {"nested": 1}}}"#,
            br#"{"statusCode": 200, "headers": {"bad header": "v"}}"#,
        ];
        for payload in cases {
            assert!(
                into_response(payload, PayloadVersion::V1).is_err(),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }
}
