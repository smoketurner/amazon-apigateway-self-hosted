//! `AWS_PROXY` Lambda integrations using API Gateway's proxy event formats
//! (payload format 1.0 for REST APIs, 1.0 or 2.0 for HTTP APIs), buffered
//! (`Invoke`) or streamed (`InvokeWithResponseStream`).

use std::collections::BTreeMap;
use std::time::Instant;

use axum::body::Body;
use axum::http::header;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value, json};
use tokio::time::Instant as TokioInstant;

use crate::aws::AwsClients;
use crate::gateway::GatewayError;
use crate::integration::{LambdaProxy, StageVariables};
use crate::lambda_response::{PreludeError, ProxyResponse, StreamBody, StreamPrelude};
use crate::model::{ApiKind, PayloadVersion, ResponseTransferMode};
use crate::pipeline::RequestContext;
use crate::route::Route;

/// Lambda's payload limit for synchronous invocations, which applies to the
/// event sent and, for buffered integrations, the response returned.
const LAMBDA_PAYLOAD_LIMIT: usize = 6_291_556;

impl LambdaProxy {
    pub(crate) async fn invoke(
        &self,
        aws: &AwsClients,
        route: &Route,
        ctx: &mut RequestContext,
        stage_variables: &StageVariables,
    ) -> Result<Response, GatewayError> {
        let event = ProxyEvent {
            ctx,
            stage_variables,
            account_id: self.function.account().unwrap_or_default(),
        }
        .render(self.payload)
        .to_string()
        .into_bytes();
        if event.len() > LAMBDA_PAYLOAD_LIMIT {
            tracing::warn!(route = %route.key, function = %self.function, bytes = event.len(), "request is larger than Lambda's invocation payload limit");
            return Err(GatewayError::IntegrationFailure);
        }
        ctx.integration.transfer_mode = Some(self.transfer);
        let started = Instant::now();
        let result = match self.transfer {
            ResponseTransferMode::Buffered => self.invoke_buffered(aws, route, ctx, event).await,
            ResponseTransferMode::Stream => {
                self.invoke_streaming(aws, route, ctx, event, started).await
            }
        };
        ctx.integration.latency_ms = u64::try_from(started.elapsed().as_millis()).ok();
        if let Ok(ref response) = result {
            ctx.integration.status = Some(response.status().as_u16());
        }
        result
    }

    async fn invoke_buffered(
        &self,
        aws: &AwsClients,
        route: &Route,
        ctx: &RequestContext,
        event: Vec<u8>,
    ) -> Result<Response, GatewayError> {
        let call = aws.invoke_lambda(
            &self.function,
            self.credentials.as_ref(),
            event,
            ctx.trace_header(),
        );
        let invocation = match tokio::time::timeout(self.timeout, call).await {
            Err(_) => {
                tracing::warn!(route = %route.key, function = %self.function, "Lambda invocation timed out");
                return Err(GatewayError::IntegrationTimeout);
            }
            Ok(Err(err)) => {
                tracing::error!(route = %route.key, function = %self.function, %err, "Lambda invocation failed");
                return Err(GatewayError::IntegrationFailure);
            }
            Ok(Ok(invocation)) => invocation,
        };
        if let Some(function_error) = invocation.function_error {
            tracing::warn!(route = %route.key, function = %self.function, function_error, "Lambda function returned an error");
            return Err(GatewayError::IntegrationFailure);
        }
        if invocation.payload.len() > LAMBDA_PAYLOAD_LIMIT {
            tracing::error!(route = %route.key, function = %self.function, bytes = invocation.payload.len(), "Lambda response is larger than the invocation payload limit");
            return Err(GatewayError::IntegrationFailure);
        }
        ProxyResponse::into_http(&invocation.payload, self.payload).map_err(|reason| {
            tracing::error!(route = %route.key, function = %self.function, reason, "malformed Lambda proxy response");
            GatewayError::IntegrationFailure
        })
    }

    /// Starts the invocation and answers as soon as the function has sent its
    /// response metadata; the payload then flows to the client as it arrives.
    async fn invoke_streaming(
        &self,
        aws: &AwsClients,
        route: &Route,
        ctx: &mut RequestContext,
        event: Vec<u8>,
        started: Instant,
    ) -> Result<Response, GatewayError> {
        let deadline = TokioInstant::now()
            .checked_add(self.timeout)
            .unwrap_or_else(TokioInstant::now);
        let call = aws.invoke_lambda_stream(
            &self.function,
            self.credentials.as_ref(),
            event,
            ctx.trace_header(),
        );
        let mut stream = match tokio::time::timeout_at(deadline, call).await {
            Err(_) => return Err(self.stream_timeout(route)),
            Ok(Err(err)) => {
                tracing::error!(route = %route.key, function = %self.function, %err, "Lambda streaming invocation failed");
                return Err(GatewayError::IntegrationFailure);
            }
            Ok(Ok(stream)) => stream,
        };
        let (prelude, first) = match tokio::time::timeout_at(
            deadline,
            StreamPrelude::read(&mut stream),
        )
        .await
        {
            Err(_) => return Err(self.stream_timeout(route)),
            Ok(Err(PreludeError::Invoke(err))) => {
                tracing::error!(route = %route.key, function = %self.function, %err, "Lambda stream failed before its response metadata");
                return Err(GatewayError::IntegrationFailure);
            }
            Ok(Err(PreludeError::Format(reason))) => {
                tracing::error!(route = %route.key, function = %self.function, reason, "Lambda stream does not follow the response streaming format");
                return Err(GatewayError::MalformedStreamingResponse);
            }
            Ok(Ok(read)) => read,
        };
        ctx.integration.time_to_all_headers_ms = u64::try_from(started.elapsed().as_millis()).ok();
        let mut response = Response::new(Body::empty());
        prelude.into_head(&mut response).map_err(|reason| {
            tracing::error!(route = %route.key, function = %self.function, reason, "invalid response metadata in Lambda stream");
            GatewayError::MalformedStreamingResponse
        })?;
        *response.body_mut() = StreamBody::spawn(stream, first, deadline);
        Ok(response)
    }

    fn stream_timeout(&self, route: &Route) -> GatewayError {
        tracing::warn!(route = %route.key, function = %self.function, "Lambda streaming invocation timed out before its response metadata");
        GatewayError::IntegrationTimeout
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
    /// The account the event reports: API Gateway reports the API owner's,
    /// which a self-hosted gateway only knows from the function's ARN.
    account_id: &'a str,
}

impl ProxyEvent<'_> {
    fn render(&self, version: PayloadVersion) -> Value {
        match version {
            PayloadVersion::V1 => self.v1(),
            PayloadVersion::V2 => self.v2(),
        }
    }

    /// Header names as the event spells them: REST payload 1.0 keeps the
    /// client's case, everything else is lower case.
    fn headers(&self) -> MultiValues {
        let keep_case = self.ctx.api.kind == ApiKind::Rest;
        let mut headers = MultiValues::default();
        for (name, value) in &self.ctx.headers {
            let name = if keep_case {
                self.ctx.header_case.spelling(name.as_str())
            } else {
                name.as_str()
            };
            headers.push(
                name.to_owned(),
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

    /// The `identity` block of payload 1.0: fields API Gateway fills only for
    /// IAM, Cognito, and mutual TLS callers are present as `null`.
    fn identity(&self) -> Value {
        json!({
            "accessKey": null,
            "accountId": null,
            "caller": null,
            "cognitoAuthenticationProvider": null,
            "cognitoAuthenticationType": null,
            "cognitoIdentityId": null,
            "cognitoIdentityPoolId": null,
            "principalOrgId": null,
            "sourceIp": self.ctx.source_ip(),
            "user": null,
            "userAgent": self.ctx.header_str("user-agent"),
            "userArn": null,
        })
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
                "accountId": self.account_id,
                "apiId": ctx.api.api_id,
                "domainName": ctx.domain_name(),
                "domainPrefix": ctx.domain_prefix(),
                "extendedRequestId": ctx.extended_request_id(),
                "httpMethod": ctx.method.as_str(),
                "identity": self.identity(),
                "path": ctx.path,
                "protocol": ctx.protocol(),
                "requestId": ctx.request_id.to_string(),
                "requestTime": ctx.request_time(),
                "requestTimeEpoch": ctx.received.as_millisecond(),
                "resourceId": null,
                "resourcePath": ctx.resource_path,
                "stage": ctx.api.stage_name(),
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
                "accountId": self.account_id,
                "apiId": ctx.api.api_id,
                "domainName": ctx.domain_name(),
                "domainPrefix": ctx.domain_prefix(),
                "http": {
                    "method": ctx.method.as_str(),
                    "path": ctx.path,
                    "protocol": ctx.protocol(),
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

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]
mod tests {
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::http::{HeaderValue, StatusCode, Version};
    use axum::routing::post;

    use super::*;
    use crate::aws::{CredentialsMode, FunctionArn, LambdaEndpoints};
    use crate::header_case::HeaderCase;
    use crate::model::{MethodMatch, Protections, RouteKey, RoutePath};
    use crate::pipeline::context::QueryString;
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
            account_id: "123456789012",
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
    fn v1_request_context_matches_the_documented_shape() {
        let ctx = incoming(b"");
        let event = event(&ctx, PayloadVersion::V1);
        let context = &event["requestContext"];
        assert_eq!(context["accountId"], "123456789012");
        assert_eq!(context["apiId"], "abc123");
        assert_eq!(context["domainName"], "api.example.com");
        assert_eq!(context["domainPrefix"], "api");
        assert_eq!(context["extendedRequestId"], ctx.extended_request_id());
        assert_ne!(context["extendedRequestId"], context["requestId"]);
        assert_eq!(context["protocol"], "HTTP/1.1");
        assert_eq!(context["path"], "/pets/7");
        assert!(context["resourceId"].is_null());
        assert_eq!(context["resourcePath"], "/pets/{petId}");
        let identity = context["identity"].as_object().unwrap();
        for null_field in [
            "accessKey",
            "accountId",
            "caller",
            "cognitoAuthenticationProvider",
            "cognitoAuthenticationType",
            "cognitoIdentityId",
            "cognitoIdentityPoolId",
            "principalOrgId",
            "user",
            "userArn",
        ] {
            assert!(identity[null_field].is_null(), "{null_field}");
        }
        assert_eq!(identity["userAgent"], "curl/8");
        assert_eq!(identity.len(), 12);
    }

    #[test]
    fn rest_headers_keep_the_clients_case_and_http_api_headers_do_not() {
        let mut ctx = incoming(b"");
        ctx.headers
            .insert("content-type", HeaderValue::from_static("text/plain"));
        ctx.header_case = HeaderCase::spelled(&["Content-Type", "X-Multi", "Host"]);
        let rest = event(&ctx, PayloadVersion::V1);
        assert_eq!(rest["headers"]["Content-Type"], "text/plain");
        assert_eq!(rest["multiValueHeaders"]["X-Multi"], json!(["a", "b"]));
        assert_eq!(rest["headers"]["Host"], "api.example.com");
        assert!(rest["headers"].get("content-type").is_none());
        assert_eq!(
            rest["headers"]["user-agent"], "curl/8",
            "unrecorded names stay lower case"
        );

        ctx.api.kind = ApiKind::Http;
        let http = event(&ctx, PayloadVersion::V1);
        assert_eq!(http["headers"]["content-type"], "text/plain");
        let v2 = event(&ctx, PayloadVersion::V2);
        assert_eq!(v2["headers"]["content-type"], "text/plain");
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
        assert_eq!(event["requestContext"]["accountId"], "123456789012");
        assert_eq!(event["body"], "/wA=");
        assert_eq!(event["isBase64Encoded"], true);
    }

    #[test]
    fn v2_protocol_reports_the_clients_http_version() {
        let mut ctx = incoming(b"");
        ctx.api.kind = ApiKind::Http;
        for (version, expected) in [
            (Version::HTTP_11, "HTTP/1.1"),
            (Version::HTTP_2, "HTTP/2.0"),
        ] {
            ctx.version = version;
            assert_eq!(
                event(&ctx, PayloadVersion::V2)["requestContext"]["http"]["protocol"],
                expected
            );
        }
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
            account_id: "",
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
            account_id: "",
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

    fn lambda_route() -> Route {
        let path = RoutePath::Resource("/pets/{petId}".to_owned());
        Route {
            key: RouteKey::new(&MethodMatch::Any, &path),
            method: MethodMatch::Any,
            path,
            integration: crate::integration::Integration::Unsupported {
                reason: String::new(),
            },
            protections: Protections::default(),
            unenforced: Vec::new(),
        }
    }

    fn proxy(function: &str, transfer: ResponseTransferMode) -> LambdaProxy {
        LambdaProxy {
            function: function.parse::<FunctionArn>().unwrap(),
            credentials: None,
            payload: PayloadVersion::V1,
            timeout: Duration::from_secs(5),
            transfer,
        }
    }

    fn clients(endpoint: &reqwest::Url) -> AwsClients {
        let config = aws_config::SdkConfig::builder()
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        AwsClients::new(
            config,
            CredentialsMode::Assume,
            LambdaEndpoints::from_iter([("f".to_owned(), endpoint.clone())]),
            reqwest::Client::new(),
        )
    }

    async fn serve(app: axum::Router) -> reqwest::Url {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        reqwest::Url::parse(&format!("http://{addr}/")).unwrap()
    }

    async fn run(
        transfer: ResponseTransferMode,
        endpoint: &reqwest::Url,
        ctx: &mut RequestContext,
    ) -> Result<Response, GatewayError> {
        proxy("arn:aws:lambda:us-east-1:123456789012:function:f", transfer)
            .invoke(&clients(endpoint), &lambda_route(), ctx, &variables())
            .await
    }

    #[tokio::test]
    async fn buffered_invocations_reject_oversized_requests_and_responses() {
        let big = "x".repeat(LAMBDA_PAYLOAD_LIMIT);
        let app = axum::Router::new()
            .route(
                "/ok",
                post(|| async { r#"{"statusCode":200,"body":"hi"}"# }),
            )
            .route(
                "/big",
                post(move || {
                    let body = big.clone();
                    async move { format!(r#"{{"statusCode":200,"body":"{body}"}}"#) }
                }),
            );
        let base = serve(app).await;

        let mut ctx = incoming(b"");
        let response = run(
            ResponseTransferMode::Buffered,
            &base.join("ok").unwrap(),
            &mut ctx,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(ctx.integration.status, Some(200));
        assert_eq!(
            ctx.integration.transfer_mode,
            Some(ResponseTransferMode::Buffered)
        );

        let result = run(
            ResponseTransferMode::Buffered,
            &base.join("big").unwrap(),
            &mut incoming(b""),
        )
        .await;
        assert_eq!(result.unwrap_err(), GatewayError::IntegrationFailure);

        let oversized = Box::leak(vec![b'a'; LAMBDA_PAYLOAD_LIMIT].into_boxed_slice());
        let result = run(
            ResponseTransferMode::Buffered,
            &base.join("ok").unwrap(),
            &mut incoming(oversized),
        )
        .await;
        assert_eq!(
            result.unwrap_err(),
            GatewayError::IntegrationFailure,
            "the event, larger than the body, exceeds Lambda's request limit"
        );
    }

    #[tokio::test]
    async fn streaming_invocations_answer_before_the_function_finishes() {
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let released = std::sync::Arc::new(tokio::sync::Mutex::new(Some(released)));
        let app = axum::Router::new().route(
            "/stream",
            post(move || {
                let released = std::sync::Arc::clone(&released);
                async move {
                    let (sender, receiver) = tokio::sync::mpsc::channel::<
                        Result<Bytes, std::convert::Infallible>,
                    >(4);
                    let gate = released.lock().await.take();
                    tokio::spawn(async move {
                        let mut prelude = br#"{"statusCode":206,"headers":{"x-s":"1","Content-Type":"text/event-stream"},"cookies":["a=b"]}"#.to_vec();
                        prelude.extend_from_slice(&[0; 4]);
                        sender.send(Ok(Bytes::from(prelude))).await.unwrap();
                        sender
                            .send(Ok(Bytes::from_static(&[0; 4])))
                            .await
                            .unwrap();
                        sender.send(Ok(Bytes::from_static(b"first;"))).await.unwrap();
                        if let Some(gate) = gate {
                            gate.await.unwrap();
                        }
                        sender.send(Ok(Bytes::from_static(b"last"))).await.unwrap();
                    });
                    Body::new(ReceiverBody(receiver))
                }
            }),
        );
        let base = serve(app).await;

        let mut ctx = incoming(b"");
        let response = run(
            ResponseTransferMode::Stream,
            &base.join("stream").unwrap(),
            &mut ctx,
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(response.headers()["x-s"], "1");
        assert_eq!(response.headers()["content-type"], "text/event-stream");
        assert_eq!(response.headers()["set-cookie"], "a=b");
        assert_eq!(
            ctx.integration.transfer_mode,
            Some(ResponseTransferMode::Stream)
        );
        assert!(ctx.integration.time_to_all_headers_ms.is_some());

        let mut body = response.into_body();
        let first = next_data(&mut body).await;
        assert_eq!(&first[..], b"first;");
        release.send(()).unwrap();
        let mut rest = Vec::new();
        while let Some(chunk) = try_next_data(&mut body).await {
            rest.extend_from_slice(&chunk);
        }
        assert_eq!(rest, b"last");
    }

    #[tokio::test]
    async fn streaming_rejects_output_that_does_not_follow_the_format() {
        let app = axum::Router::new()
            .route("/plain", post(|| async { "no delimiter here" }))
            .route(
                "/badjson",
                post(|| async { [b"nope".as_slice(), &[0; 8]].concat() }),
            )
            .route(
                "/late",
                post(|| async { [vec![b' '; 20_000], vec![0; 8]].concat() }),
            );
        let base = serve(app).await;
        for path in ["plain", "badjson", "late"] {
            let result = run(
                ResponseTransferMode::Stream,
                &base.join(path).unwrap(),
                &mut incoming(b""),
            )
            .await;
            assert_eq!(
                result.unwrap_err(),
                GatewayError::MalformedStreamingResponse,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn streaming_endpoint_failures_are_bad_gateways() {
        let app = axum::Router::new().route("/down", post(|| async { StatusCode::BAD_GATEWAY }));
        let base = serve(app).await;
        let result = run(
            ResponseTransferMode::Stream,
            &base.join("down").unwrap(),
            &mut incoming(b""),
        )
        .await;
        assert_eq!(result.unwrap_err(), GatewayError::IntegrationFailure);
    }

    struct ReceiverBody(tokio::sync::mpsc::Receiver<Result<Bytes, std::convert::Infallible>>);

    impl hyper::body::Body for ReceiverBody {
        type Data = Bytes;
        type Error = std::convert::Infallible;

        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
            self.get_mut()
                .0
                .poll_recv(cx)
                .map(|item| item.map(|chunk| chunk.map(hyper::body::Frame::data)))
        }
    }

    async fn try_next_data(body: &mut Body) -> Option<Bytes> {
        use std::future::poll_fn;
        use std::pin::Pin;

        use hyper::body::Body as _;
        let frame = tokio::time::timeout(
            Duration::from_secs(5),
            poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)),
        )
        .await
        .unwrap()?;
        frame.unwrap().into_data().ok()
    }

    async fn next_data(body: &mut Body) -> Bytes {
        try_next_data(body).await.unwrap()
    }
}
