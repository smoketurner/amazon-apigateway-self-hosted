//! `AWS_PROXY` Lambda integrations using API Gateway's proxy event formats
//! (payload format 1.0 for REST APIs, 1.0 or 2.0 for HTTP APIs), buffered
//! (`Invoke`) or streamed (`InvokeWithResponseStream`).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Instant;

use axum::body::Body;
use axum::http::header;
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value, json};
use tokio::time::Instant as TokioInstant;

use crate::authz::MethodArn;
use crate::aws::AwsClients;
use crate::gateway::GatewayError;
use crate::header_policy::{Flavor, IamAuthorization};
use crate::integration::{LambdaProxy, StageVariables};
use crate::lambda_response::{PreludeError, ProxyResponse, StreamBody, StreamPrelude};
use crate::model::{ApiKind, PayloadVersion, Protection, ResponseTransferMode};
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
        let iam = if route.protections.iter().any(|p| p == Protection::Iam) {
            IamAuthorization::Used
        } else {
            IamAuthorization::NotUsed
        };
        let event = ProxyEvent::new(ctx, stage_variables)
            .with_account(self.function.account().unwrap_or_default())
            .with_header_table(iam)
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
        let negotiation =
            (ctx.api.kind == ApiKind::Rest).then(|| ctx.payload.negotiate(&ctx.headers));
        let mut response = ProxyResponse::into_http(
            &invocation.payload,
            self.payload,
            negotiation.as_ref(),
        )
        .map_err(|reason| {
            tracing::error!(route = %route.key, function = %self.function, reason, "malformed Lambda proxy response");
            GatewayError::IntegrationFailure
        })?;
        Self::remap_headers(ctx.api.kind, &mut response);
        Ok(response)
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
        Self::remap_headers(ctx.api.kind, &mut response);
        *response.body_mut() = StreamBody::spawn(stream, first, deadline);
        Ok(response)
    }

    /// REST APIs rename and drop some of the function's response headers.
    fn remap_headers(kind: ApiKind, response: &mut Response) {
        if kind == ApiKind::Rest {
            Flavor::Lambda.remap_response(response.headers_mut());
        }
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
    /// REST APIs send a body as base64 when its `Content-Type` is one of the API's
    /// binary media types and as text otherwise; HTTP APIs base64-encode what
    /// is not valid UTF-8.
    fn for_request(ctx: &RequestContext) -> Self {
        match ctx.api.kind {
            ApiKind::Rest => Self::declared(&ctx.body, ctx.payload.request_is_binary(&ctx.headers)),
            ApiKind::Http => Self::new(&ctx.body),
        }
    }

    fn declared(body: &[u8], binary: bool) -> Self {
        if body.is_empty() {
            return Self::new(body);
        }
        if binary {
            return Self {
                body: Value::String(BASE64.encode(body)),
                is_base64: true,
            };
        }
        Self {
            body: Value::String(String::from_utf8_lossy(body).into_owned()),
            is_base64: false,
        }
    }

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
pub(crate) struct ProxyEvent<'a> {
    ctx: &'a RequestContext,
    stage_variables: &'a StageVariables,
    /// The account the event reports: API Gateway reports the API owner's,
    /// which a self-hosted gateway only knows from the function's ARN.
    account_id: &'a str,
    /// REST proxy events carry the client's headers as API Gateway's header
    /// table lets them through; `None` sends them all, as authorizer events do.
    header_table: Option<IamAuthorization>,
}

impl<'a> ProxyEvent<'a> {
    pub(crate) fn new(ctx: &'a RequestContext, stage_variables: &'a StageVariables) -> Self {
        Self {
            ctx,
            stage_variables,
            account_id: "",
            header_table: None,
        }
    }

    /// Applies API Gateway's REST header table to the event's headers.
    pub(crate) fn with_header_table(mut self, iam: IamAuthorization) -> Self {
        self.header_table = Some(iam);
        self
    }

    /// Reports `account_id` as the account in `requestContext`.
    pub(crate) fn with_account(mut self, account_id: &'a str) -> Self {
        self.account_id = account_id;
        self
    }

    /// The event for a `REQUEST` Lambda authorizer: the proxy event without the
    /// body (and without an authorizer, since none has run), tagged with the
    /// method ARN. HTTP APIs also send the identity source values; payload 1.0
    /// joins them with commas and repeats the first as `authorizationToken`.
    pub(crate) fn authorizer_request(
        &self,
        version: PayloadVersion,
        arn: &MethodArn,
        identity: Option<&[String]>,
    ) -> Value {
        let mut event = self.render(version);
        if let Value::Object(ref mut fields) = event {
            fields.remove("body");
            fields.remove("isBase64Encoded");
            if let Some(Value::Object(request_context)) = fields.get_mut("requestContext") {
                request_context.remove("authorizer");
            }
            fields.insert("type".to_owned(), json!("REQUEST"));
            let arn_key = match version {
                PayloadVersion::V1 => "methodArn",
                PayloadVersion::V2 => "routeArn",
            };
            fields.insert(arn_key.to_owned(), json!(arn.as_str()));
            if let Some(identity) = identity {
                match version {
                    PayloadVersion::V1 => {
                        let joined = identity.join(",");
                        fields.insert("authorizationToken".to_owned(), json!(joined));
                        fields.insert("identitySource".to_owned(), json!(joined));
                        fields.insert("version".to_owned(), json!("1.0"));
                    }
                    PayloadVersion::V2 => {
                        fields.insert("identitySource".to_owned(), json!(identity));
                    }
                }
            }
        }
        event
    }

    pub(crate) fn render(&self, version: PayloadVersion) -> Value {
        match version {
            PayloadVersion::V1 => self.v1(),
            PayloadVersion::V2 => self.v2(),
        }
    }

    /// Header names as the event spells them: REST payload 1.0 keeps the
    /// client's case, everything else is lower case.
    fn headers(&self) -> MultiValues {
        let keep_case = self.ctx.api.kind == ApiKind::Rest;
        let allowed = match self.header_table {
            Some(iam) if keep_case => {
                Cow::Owned(Flavor::Lambda.request_headers(&self.ctx.headers, iam))
            }
            Some(_) | None => Cow::Borrowed(&self.ctx.headers),
        };
        let mut headers = MultiValues::default();
        for (name, value) in allowed.iter() {
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
        let mut identity = json!({
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
        });
        if let (Value::Object(fields), Some(key)) = (&mut identity, self.ctx.api_key.as_ref()) {
            fields.insert("apiKey".to_owned(), json!(key.value()));
            fields.insert("apiKeyId".to_owned(), json!(key.id()));
        }
        if let (Value::Object(fields), Some(cert)) =
            (&mut identity, self.ctx.identity.client_cert())
        {
            fields.insert("clientCert".to_owned(), cert.to_json());
        }
        identity
    }

    fn v1(&self) -> Value {
        let ctx = self.ctx;
        let (headers, multi_headers) = self.headers().single_and_multi();
        let (query, multi_query) = self.query().single_and_multi();
        let body = EventBody::for_request(ctx);
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
                "path": ctx.full_path,
                "protocol": ctx.protocol(),
                "requestId": ctx.request_id.to_string(),
                "requestTime": ctx.request_time(),
                "requestTimeEpoch": ctx.received.as_millisecond(),
                "resourceId": null,
                "resourcePath": ctx.resource_path,
                "stage": ctx.api.stage_name(),
                "authorizer": ctx.authorizer.event_value(PayloadVersion::V1),
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
        let body = EventBody::for_request(ctx);
        let mut event = json!({
            "version": "2.0",
            "routeKey": ctx.route_key.as_str(),
            "rawPath": ctx.full_path,
            "rawQueryString": ctx.query.raw().unwrap_or_default(),
            "headers": headers.joined(),
            "requestContext": {
                "accountId": self.account_id,
                "apiId": ctx.api.api_id,
                "domainName": ctx.domain_name(),
                "domainPrefix": ctx.domain_prefix(),
                "http": {
                    "method": ctx.method.as_str(),
                    "path": ctx.full_path,
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
            if let Some(Value::Object(request_context)) = fields.get_mut("requestContext") {
                if let Some(authorizer) = ctx.authorizer.event_value(PayloadVersion::V2) {
                    request_context.insert("authorizer".to_owned(), authorizer);
                }
                if let Some(cert) = ctx.identity.client_cert() {
                    request_context.insert(
                        "authentication".to_owned(),
                        json!({"clientCert": cert.to_json()}),
                    );
                }
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
    use std::sync::Arc;
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::http::{HeaderValue, StatusCode, Version};
    use axum::routing::post;

    use super::*;
    use crate::authz::{RouteAuthorizer, RoutePolicy};
    use crate::aws::{CredentialsMode, FunctionArn, LambdaEndpoints};
    use crate::client_cert::ClientCertDetails;
    use crate::client_cert::tests::certificate;
    use crate::header_case::HeaderCase;
    use crate::integration::Integration;
    use crate::model::{MethodMatch, Protections, RouteKey, RoutePath};
    use crate::payload::PayloadSettings;
    use crate::pipeline::context::tests::request;
    use crate::pipeline::context::{AuthorizerContext, QueryString};
    use crate::usage::RouteApiKey;
    use crate::validation::RouteValidation;

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
        ProxyEvent::new(ctx, &variables())
            .with_account("123456789012")
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
        assert_eq!(context["path"], "/prod/pets/7");
        assert_eq!(event["path"], "/pets/7");
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
    fn rest_events_apply_the_header_table_but_authorizer_events_do_not() {
        let mut ctx = incoming(b"");
        for (name, value) in [
            ("expect", "100-continue"),
            ("content-md5", "abc"),
            ("via", "1.1 proxy"),
            ("authorization", "Bearer t"),
        ] {
            ctx.headers.insert(name, HeaderValue::from_static(value));
        }
        let vars = variables();
        let table = ProxyEvent::new(&ctx, &vars)
            .with_header_table(IamAuthorization::NotUsed)
            .render(PayloadVersion::V1);
        assert!(table["headers"].get("expect").is_none());
        assert!(table["headers"].get("content-md5").is_none());
        assert_eq!(table["headers"]["via"], "1.1 proxy");
        assert_eq!(table["headers"]["authorization"], "Bearer t");
        let iam = ProxyEvent::new(&ctx, &vars)
            .with_header_table(IamAuthorization::Used)
            .render(PayloadVersion::V1);
        assert!(iam["headers"].get("authorization").is_none());
        let unfiltered = ProxyEvent::new(&ctx, &vars).render(PayloadVersion::V1);
        assert_eq!(unfiltered["headers"]["expect"], "100-continue");
    }

    #[test]
    fn rest_bodies_are_base64_only_for_binary_media_types() {
        let mut ctx = incoming(&[0xff, 0x00, b'a']);
        ctx.headers.insert(
            "content-type",
            HeaderValue::from_static("application/octet-stream"),
        );
        let text = event(&ctx, PayloadVersion::V1);
        assert_eq!(
            text["body"], "\u{fffd}\0a",
            "without binaryMediaTypes the body is text"
        );
        assert_eq!(text["isBase64Encoded"], false);

        ctx.payload = Arc::new(PayloadSettings::new(
            &["application/octet-stream".to_owned()],
            None,
        ));
        let binary = event(&ctx, PayloadVersion::V1);
        assert_eq!(binary["body"], "/wBh");
        assert_eq!(binary["isBase64Encoded"], true);

        ctx.headers
            .insert("content-type", HeaderValue::from_static("application/json"));
        ctx.body = Bytes::from_static(b"{\"a\":1}");
        let json_body = event(&ctx, PayloadVersion::V1);
        assert_eq!(json_body["body"], "{\"a\":1}");
        assert_eq!(json_body["isBase64Encoded"], false);

        ctx.payload = Arc::new(PayloadSettings::new(&["*/*".to_owned()], None));
        assert_eq!(event(&ctx, PayloadVersion::V1)["isBase64Encoded"], true);
        ctx.body = Bytes::new();
        assert!(event(&ctx, PayloadVersion::V1)["body"].is_null());
    }

    #[test]
    fn v2_event_joins_values_and_extracts_cookies() {
        let mut ctx = incoming(&[0xff, 0x00]);
        ctx.api.kind = ApiKind::Http;
        let event = event(&ctx, PayloadVersion::V2);
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
        let v1 = ProxyEvent::new(&ctx, &empty).render(PayloadVersion::V1);
        for field in [
            "queryStringParameters",
            "multiValueQueryStringParameters",
            "pathParameters",
            "stageVariables",
            "body",
        ] {
            assert!(v1[field].is_null(), "{field}");
        }
        let v2 = ProxyEvent::new(&ctx, &empty).render(PayloadVersion::V2);
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
        ctx.authorizer = AuthorizerContext::lambda(Map::from_iter([(
            "principalId".to_owned(),
            json!("user-1"),
        )]));
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
            integration: Integration::Unsupported {
                reason: String::new(),
            },
            protections: Protections::default(),
            authorizer: RouteAuthorizer::None,
            policy: RoutePolicy::None,
            api_key: RouteApiKey::NotRequired,
            validation: RouteValidation::None,
            throttle: None,
            cache: None,
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
    async fn rest_function_responses_are_remapped() {
        let app = axum::Router::new().route(
            "/ok",
            post(|| async {
                r#"{"statusCode":200,"headers":{"Server":"fn","Date":"d","WWW-Authenticate":"Basic","X-Ok":"1"},"body":"hi"}"#
            }),
        );
        let base = serve(app).await;
        let mut rest = incoming(b"");
        let response = run(
            ResponseTransferMode::Buffered,
            &base.join("ok").unwrap(),
            &mut rest,
        )
        .await
        .unwrap();
        assert_eq!(response.headers()["x-amzn-remapped-server"], "fn");
        assert_eq!(response.headers()["x-amzn-remapped-date"], "d");
        assert_eq!(
            response.headers()["x-amzn-remapped-www-authenticate"],
            "Basic"
        );
        assert_eq!(response.headers()["x-ok"], "1");
        assert!(response.headers().get("server").is_none());

        let mut http = incoming(b"");
        http.api.kind = ApiKind::Http;
        let response = run(
            ResponseTransferMode::Buffered,
            &base.join("ok").unwrap(),
            &mut http,
        )
        .await
        .unwrap();
        assert_eq!(response.headers()["server"], "fn");
    }

    #[tokio::test]
    async fn streaming_invocations_answer_before_the_function_finishes() {
        let (release, released) = tokio::sync::oneshot::channel::<()>();
        let released = Arc::new(tokio::sync::Mutex::new(Some(released)));
        let app = axum::Router::new().route(
            "/stream",
            post(move || {
                let released = Arc::clone(&released);
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
        assert_eq!(&*first, b"first;");
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

    fn with_client_cert(mut ctx: RequestContext) -> RequestContext {
        let (der, _) = certificate("mtls client");
        ctx.identity = ctx
            .identity
            .with_verified_certificate(ClientCertDetails::from_der(der.as_ref()).unwrap());
        ctx
    }

    #[test]
    fn client_certificates_appear_where_each_payload_version_puts_them() {
        let ctx = with_client_cert(incoming(b""));
        let v1 = event(&ctx, PayloadVersion::V1);
        let cert = &v1["requestContext"]["identity"]["clientCert"];
        assert_eq!(cert["subjectDN"], "C=US,O=Acme,CN=mtls client");
        assert!(
            cert["clientCertPem"]
                .as_str()
                .unwrap()
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
        assert!(
            cert["validity"]["notBefore"]
                .as_str()
                .unwrap()
                .ends_with("GMT")
        );
        assert_eq!(
            v1["requestContext"]["identity"].as_object().unwrap().len(),
            13
        );
        let v2 = event(&ctx, PayloadVersion::V2);
        assert_eq!(
            v2["requestContext"]["authentication"]["clientCert"]["subjectDN"],
            "C=US,O=Acme,CN=mtls client"
        );
        assert!(v2["requestContext"].get("identity").is_none());
    }

    #[test]
    fn events_have_no_client_certificate_fields_without_one() {
        let ctx = incoming(b"");
        let v1 = event(&ctx, PayloadVersion::V1);
        assert!(v1["requestContext"]["identity"].get("clientCert").is_none());
        let v2 = event(&ctx, PayloadVersion::V2);
        assert!(v2["requestContext"].get("authentication").is_none());
    }
}
