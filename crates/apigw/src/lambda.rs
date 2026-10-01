//! `AWS_PROXY` Lambda integrations using API Gateway's proxy event formats
//! (payload format 1.0 for REST APIs, 1.0 or 2.0 for HTTP APIs).

use std::collections::BTreeMap;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde_json::{Map, Value, json};

use crate::aws::AwsClients;
use crate::gateway::GatewayError;
use crate::integration::{LambdaProxy, StageVariables};
use crate::model::PayloadVersion;
use crate::pipeline::RequestContext;
use crate::route::Route;

impl LambdaProxy {
    pub(crate) async fn invoke(
        &self,
        aws: &AwsClients,
        route: &Route,
        ctx: &RequestContext,
        stage_variables: &StageVariables,
    ) -> Response {
        let kind = ctx.api.kind;
        let event = ProxyEvent {
            ctx,
            stage_variables,
        }
        .render(self.payload);
        let call = aws.invoke_lambda(
            &self.function,
            self.credentials.as_ref(),
            event.to_string().into_bytes(),
            ctx.trace_header(),
        );
        let invocation = match tokio::time::timeout(self.timeout, call).await {
            Err(_) => {
                tracing::warn!(route = %route.key, function = %self.function, "Lambda invocation timed out");
                return GatewayError::IntegrationTimeout.response(kind);
            }
            Ok(Err(err)) => {
                tracing::error!(route = %route.key, function = %self.function, %err, "Lambda invocation failed");
                return GatewayError::IntegrationFailure.response(kind);
            }
            Ok(Ok(invocation)) => invocation,
        };
        if let Some(function_error) = invocation.function_error {
            tracing::warn!(route = %route.key, function = %self.function, function_error, "Lambda function returned an error");
            return GatewayError::IntegrationFailure.response(kind);
        }
        match ProxyResponse::into_http(&invocation.payload, self.payload) {
            Ok(response) => response,
            Err(reason) => {
                tracing::error!(route = %route.key, function = %self.function, reason, "malformed Lambda proxy response");
                GatewayError::IntegrationFailure.response(kind)
            }
        }
    }
}

/// A request body as proxy events carry it: valid UTF-8 as text, anything else
/// base64-encoded.
struct EventBody {
    body: Value,
    is_base64: bool,
}

impl EventBody {
    fn new(body: &[u8]) -> Self {
        if body.is_empty() {
            return Self {
                body: Value::Null,
                is_base64: false,
            };
        }
        match std::str::from_utf8(body) {
            Ok(text) => Self {
                body: Value::String(text.to_owned()),
                is_base64: false,
            },
            Err(_) => Self {
                body: Value::String(BASE64.encode(body)),
                is_base64: true,
            },
        }
    }
}

/// A JSON object of string values.
#[derive(Default)]
struct StringFields(Map<String, Value>);

impl StringFields {
    /// Payload format 1.0 sends `null` rather than an empty object.
    fn or_null(self) -> Value {
        if self.0.is_empty() {
            Value::Null
        } else {
            Value::Object(self.0)
        }
    }
}

impl<'a> FromIterator<(&'a String, &'a String)> for StringFields {
    fn from_iter<I: IntoIterator<Item = (&'a String, &'a String)>>(iter: I) -> Self {
        Self(
            iter.into_iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect(),
        )
    }
}

/// Values gathered per key, in arrival order.
#[derive(Default)]
struct MultiValues(BTreeMap<String, Vec<String>>);

impl MultiValues {
    fn push(&mut self, key: String, value: String) {
        self.0.entry(key).or_default().push(value);
    }

    /// Payload format 1.0: the last value per key, and every value per key.
    fn single_and_multi(&self) -> (Value, Value) {
        if self.0.is_empty() {
            return (Value::Null, Value::Null);
        }
        let mut single = Map::new();
        let mut multi = Map::new();
        for (key, values) in &self.0 {
            if let Some(last) = values.last() {
                single.insert(key.clone(), json!(last));
            }
            multi.insert(key.clone(), json!(values));
        }
        (Value::Object(single), Value::Object(multi))
    }

    /// Payload format 2.0 joins repeated values with commas.
    fn joined(&self) -> Map<String, Value> {
        self.0
            .iter()
            .map(|(k, v)| (k.clone(), json!(v.join(","))))
            .collect()
    }
}

/// An API Gateway proxy event built from a request.
struct ProxyEvent<'a> {
    ctx: &'a RequestContext,
    stage_variables: &'a StageVariables,
}

impl ProxyEvent<'_> {
    fn render(&self, version: PayloadVersion) -> Value {
        match version {
            PayloadVersion::V1 => self.v1(),
            PayloadVersion::V2 => self.v2(),
        }
    }

    fn headers(&self) -> MultiValues {
        let mut headers = MultiValues::default();
        for (name, value) in &self.ctx.headers {
            headers.push(
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            );
        }
        headers
    }

    fn query(&self) -> MultiValues {
        let mut query = MultiValues::default();
        for (key, value) in self.ctx.query.pairs() {
            query.push(key, value);
        }
        query
    }

    fn path_parameters(&self) -> StringFields {
        self.ctx.path_params.iter().map(|(k, v)| (k, v)).collect()
    }

    fn v1(&self) -> Value {
        let ctx = self.ctx;
        let (headers, multi_headers) = self.headers().single_and_multi();
        let (query, multi_query) = self.query().single_and_multi();
        let body = EventBody::new(&ctx.body);
        json!({
            "resource": ctx.resource_path,
            "path": ctx.path,
            "httpMethod": ctx.method.as_str(),
            "headers": headers,
            "multiValueHeaders": multi_headers,
            "queryStringParameters": query,
            "multiValueQueryStringParameters": multi_query,
            "pathParameters": self.path_parameters().or_null(),
            "stageVariables": self.stage_variables.into_iter().collect::<StringFields>().or_null(),
            "requestContext": {
                "accountId": "",
                "apiId": ctx.api.api_id,
                "httpMethod": ctx.method.as_str(),
                "path": ctx.path,
                "protocol": "HTTP/1.1",
                "requestId": ctx.request_id.to_string(),
                "extendedRequestId": ctx.request_id.to_string(),
                "requestTime": ctx.request_time(),
                "requestTimeEpoch": ctx.received.as_millisecond(),
                "resourcePath": ctx.resource_path,
                "stage": ctx.api.stage_name(),
                "domainName": ctx.domain_name(),
                "domainPrefix": ctx.domain_prefix(),
                "identity": {
                    "sourceIp": ctx.source_ip(),
                    "userAgent": ctx.header_str("user-agent"),
                },
                "authorizer": (!ctx.authorizer.is_empty()).then(|| Value::Object(ctx.authorizer.clone())),
            },
            "body": body.body,
            "isBase64Encoded": body.is_base64,
        })
    }

    fn v2(&self) -> Value {
        let ctx = self.ctx;
        let mut headers = self.headers();
        let cookies: Vec<String> = headers
            .0
            .remove(header::COOKIE.as_str())
            .unwrap_or_default()
            .iter()
            .flat_map(|value| value.split(';'))
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_owned)
            .collect();
        let body = EventBody::new(&ctx.body);
        let mut event = json!({
            "version": "2.0",
            "routeKey": ctx.route_key.as_str(),
            "rawPath": ctx.path,
            "rawQueryString": ctx.query.raw().unwrap_or_default(),
            "headers": headers.joined(),
            "requestContext": {
                "accountId": "",
                "apiId": ctx.api.api_id,
                "domainName": ctx.domain_name(),
                "domainPrefix": ctx.domain_prefix(),
                "http": {
                    "method": ctx.method.as_str(),
                    "path": ctx.path,
                    "protocol": "HTTP/1.1",
                    "sourceIp": ctx.source_ip(),
                    "userAgent": ctx.header_str("user-agent"),
                },
                "requestId": ctx.request_id.to_string(),
                "routeKey": ctx.route_key.as_str(),
                "stage": ctx.api.stage_name(),
                "time": ctx.request_time(),
                "timeEpoch": ctx.received.as_millisecond(),
            },
            "isBase64Encoded": body.is_base64,
        });
        if let Value::Object(ref mut fields) = event {
            if !cookies.is_empty() {
                fields.insert("cookies".to_owned(), json!(cookies));
            }
            let query = self.query().joined();
            if !query.is_empty() {
                fields.insert("queryStringParameters".to_owned(), Value::Object(query));
            }
            let path_parameters = self.path_parameters();
            if !path_parameters.0.is_empty() {
                fields.insert(
                    "pathParameters".to_owned(),
                    Value::Object(path_parameters.0),
                );
            }
            if !self.stage_variables.is_empty() {
                let variables: StringFields = self.stage_variables.into_iter().collect();
                fields.insert("stageVariables".to_owned(), Value::Object(variables.0));
            }
            if !body.body.is_null() {
                fields.insert("body".to_owned(), body.body);
            }
        }
        event
    }
}

/// A structured Lambda proxy response.
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

impl ProxyResponse {
    /// Turns a function's payload into the HTTP response API Gateway would
    /// send. Payload format 2.0 treats JSON without `statusCode` as a 200 JSON
    /// body.
    fn into_http(payload: &[u8], version: PayloadVersion) -> Result<Response, String> {
        let value: Value = serde_json::from_slice(payload).map_err(|e| format!("not JSON: {e}"))?;
        if version == PayloadVersion::V2 && value.get("statusCode").is_none() {
            let mut response = Response::new(Body::from(value.to_string()));
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            return Ok(response);
        }
        let parsed = Self::deserialize(&value).map_err(|e| e.to_string())?;
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
            let (name, value) = Self::header(&name, &value)?;
            headers.insert(name, value);
        }
        for (name, values) in parsed.multi_value_headers {
            for value in values {
                let (name, value) = Self::header(&name, &value)?;
                headers.append(name, value);
            }
        }
        for cookie in parsed.cookies {
            let value = HeaderValue::try_from(cookie).map_err(|e| e.to_string())?;
            headers.append(header::SET_COOKIE, value);
        }
        Ok(response)
    }

    fn header(name: &str, value: &Value) -> Result<(HeaderName, HeaderValue), String> {
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
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]
mod tests {
    use axum::body::Bytes;

    use super::*;
    use crate::model::ApiKind;
    use crate::pipeline::QueryString;
    use crate::pipeline::context::tests::request;

    fn variables() -> StageVariables {
        StageVariables::new(BTreeMap::from([("env".to_owned(), "local".to_owned())]))
    }

    fn incoming(body: &'static [u8]) -> RequestContext {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers.append("x-multi", HeaderValue::from_static("a"));
        ctx.headers.append("x-multi", HeaderValue::from_static("b"));
        ctx.headers
            .insert("cookie", HeaderValue::from_static("s=1; t=2"));
        ctx.body = Bytes::from_static(body);
        ctx
    }

    fn event(ctx: &RequestContext, version: PayloadVersion) -> Value {
        ProxyEvent {
            ctx,
            stage_variables: &variables(),
        }
        .render(version)
    }

    #[test]
    fn v1_event_has_single_and_multi_value_fields() {
        let event = event(&incoming(b"{\"a\":1}"), PayloadVersion::V1);
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
        assert!(event["requestContext"]["authorizer"].is_null());
        assert_eq!(event["body"], "{\"a\":1}");
        assert_eq!(event["isBase64Encoded"], false);
    }

    #[test]
    fn v2_event_joins_values_and_extracts_cookies() {
        let event = event(&incoming(&[0xff, 0x00]), PayloadVersion::V2);
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
        let mut ctx = incoming(b"");
        ctx.query = QueryString::new(None);
        ctx.path_params.clear();
        let empty = StageVariables::default();
        let v1 = ProxyEvent {
            ctx: &ctx,
            stage_variables: &empty,
        }
        .render(PayloadVersion::V1);
        for field in [
            "queryStringParameters",
            "multiValueQueryStringParameters",
            "pathParameters",
            "stageVariables",
            "body",
        ] {
            assert!(v1[field].is_null(), "{field}");
        }
        let v2 = ProxyEvent {
            ctx: &ctx,
            stage_variables: &empty,
        }
        .render(PayloadVersion::V2);
        for field in [
            "queryStringParameters",
            "pathParameters",
            "stageVariables",
            "body",
        ] {
            assert!(v2.get(field).is_none(), "{field}");
        }
    }

    #[test]
    fn authorizer_context_is_included_when_present() {
        let mut ctx = incoming(b"");
        ctx.authorizer
            .insert("principalId".to_owned(), json!("user-1"));
        assert_eq!(
            event(&ctx, PayloadVersion::V1)["requestContext"]["authorizer"]["principalId"],
            "user-1"
        );
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
        let response =
            ProxyResponse::into_http(payload.to_string().as_bytes(), PayloadVersion::V2).unwrap();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(response.headers()["x-num"], "2");
        assert_eq!(response.headers().get_all("x-many").iter().count(), 2);
        assert_eq!(response.headers()["set-cookie"], "c=1");
        assert_eq!(&body_of(response).await[..], b"hi");
    }

    #[tokio::test]
    async fn v2_infers_response_without_status_code() {
        let response =
            ProxyResponse::into_http(br#"{"hello":"world"}"#, PayloadVersion::V2).unwrap();
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
                ProxyResponse::into_http(payload, PayloadVersion::V1).is_err(),
                "{}",
                String::from_utf8_lossy(payload)
            );
        }
    }
}
