//! `AWS_PROXY` Lambda integrations using API Gateway's proxy event formats
//! (payload format 1.0 for REST APIs, 1.0 or 2.0 for HTTP APIs), buffered
//! (`Invoke`) or streamed (`InvokeWithResponseStream`).

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderMap, header};
use axum::response::Response;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::{Map, Value, json};
use tokio::time::Instant as TokioInstant;

use crate::authz::MethodArn;
use crate::aws::AwsClients;
use crate::gateway::{GatewayError, HeaderNameExt as _};
use crate::header_case::HeaderCase;
use crate::header_policy::{Flavor, IamAuthorization};
use crate::integration::{LambdaProxy, StageVariables};
use crate::lambda_response::{PreludeError, ProxyResponse, StreamBody, StreamPrelude};
use crate::model::{ApiKind, PayloadVersion, Protection, ResponseTransferMode};
use crate::pipeline::RequestContext;
use crate::pipeline::context::QueryString;
use crate::route::Route;

/// Lambda's payload limit for synchronous invocations, which applies to the
/// event sent and, for buffered integrations, the response returned.
pub(crate) const LAMBDA_PAYLOAD_LIMIT: usize = 6_291_556;

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
        let mapped = self.request_mapping.event_request(ctx);
        let event = ProxyEvent::new(ctx, stage_variables)
            .with_account(self.function.account().unwrap_or_default())
            .with_mapped_request(mapped.as_ref())
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
            GatewayError::MalformedIntegrationResponse
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

/// Whether an HTTP API hands a body of this `Content-Type` to a function as
/// text. Everything else, and a body with no type, arrives base64-encoded.
///
/// Measured on a deployed API with some 130 types: text is `text/` followed
/// by letters, digits, `+`, and `-`; `application/` followed by one of a few
/// names, or by letters, digits, and `-` and then `+json` or `+xml`. At most
/// one parameter may follow, as `;name=value` with optional spaces before the
/// name, and a `charset` has to be `utf-8` or `us-ascii`. Case does not
/// matter, and of several comma-separated types the last one counts.
struct TextMediaType;

impl TextMediaType {
    const APPLICATION: [&str; 8] = [
        "json",
        "xml",
        "javascript",
        "x-javascript",
        "ecmascript",
        "x-ecmascript",
        "graphql",
        "x-yaml",
    ];

    fn request_is_text(headers: &HeaderMap) -> bool {
        headers
            .get_all(header::CONTENT_TYPE)
            .iter()
            .next_back()
            .and_then(|value| value.to_str().ok())
            .is_some_and(Self::matches)
    }

    fn matches(content_type: &str) -> bool {
        let last = content_type.rsplit(',').next().unwrap_or_default();
        let last = last.trim_matches([' ', '\t']).to_ascii_lowercase();
        let (essence, parameter) = match last.split_once(';') {
            Some((essence, parameter)) => (essence, Some(parameter)),
            None => (last.as_str(), None),
        };
        if parameter.is_some_and(|parameter| !Self::parameter_allows_text(parameter)) {
            return false;
        }
        let word = |text: &str, extra: &[u8]| {
            text.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || extra.contains(&byte))
        };
        match essence.split_once('/') {
            Some(("text", subtype)) => !subtype.is_empty() && word(subtype, b"+-"),
            Some(("application", subtype)) => {
                Self::APPLICATION.contains(&subtype)
                    || subtype
                        .strip_suffix("+json")
                        .or_else(|| subtype.strip_suffix("+xml"))
                        .is_some_and(|prefix| word(prefix, b"-"))
            }
            Some(_) | None => false,
        }
    }

    /// `parameter` is what follows the `;`, in lower case.
    fn parameter_allows_text(parameter: &str) -> bool {
        let Some((name, value)) = parameter.trim_start_matches(' ').split_once('=') else {
            return false;
        };
        if name.is_empty() || value.is_empty() || value.contains([';', ' ']) {
            return false;
        }
        name != "charset" || matches!(value.trim_matches('"'), "utf-8" | "us-ascii")
    }
}

/// A request body as proxy events carry it.
struct EventBody {
    body: Value,
    is_base64: bool,
}

impl EventBody {
    /// REST APIs send a body as base64 when its `Content-Type` is one of the API's
    /// binary media types and as text otherwise; HTTP APIs send it as text
    /// when its `Content-Type` is one they take for text.
    fn for_request(ctx: &RequestContext) -> Self {
        let binary = match ctx.api.kind {
            ApiKind::Rest => ctx.payload.request_is_binary(&ctx.headers),
            ApiKind::Http => !TextMediaType::request_is_text(&ctx.headers),
        };
        Self::declared(&ctx.body, binary)
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

/// How an event spells header names (measured against deployed APIs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EventSpelling {
    /// REST payload 1.0: the client's spelling, but `Host`, `User-Agent`, and
    /// `Authorization`.
    Rest,
    /// HTTP API payload 1.0: the client's spelling, but `Host`, `User-Agent`,
    /// `Cookie`, `Content-Length`, and `Content-Type`, and a lower-case `accept`.
    HttpV1,
    /// HTTP API payload 2.0: lower case.
    Lower,
}

impl EventSpelling {
    const fn of(kind: ApiKind, version: PayloadVersion) -> Self {
        match (kind, version) {
            (ApiKind::Rest, PayloadVersion::V1 | PayloadVersion::V2) => Self::Rest,
            (ApiKind::Http, PayloadVersion::V1) => Self::HttpV1,
            (ApiKind::Http, PayloadVersion::V2) => Self::Lower,
        }
    }

    /// The fixed spelling this style gives the lower-case header `name`, if any.
    fn fixed(self, name: &str) -> Option<&'static str> {
        let always = match name {
            "host" => Some("Host"),
            "user-agent" => Some("User-Agent"),
            "authorization" => Some("Authorization"),
            "x-forwarded-for" => Some("X-Forwarded-For"),
            "x-forwarded-port" => Some("X-Forwarded-Port"),
            "x-forwarded-proto" => Some("X-Forwarded-Proto"),
            "x-amzn-trace-id" => Some("X-Amzn-Trace-Id"),
            _ => None,
        };
        match self {
            Self::Lower => None,
            Self::Rest => always,
            Self::HttpV1 => always.or(match name {
                "cookie" => Some("Cookie"),
                "content-length" => Some("Content-Length"),
                "content-type" => Some("Content-Type"),
                "accept" => Some("accept"),
                _ => None,
            }),
        }
    }

    /// A header value as the event carries it. A REST API does not decode a
    /// value that is not ASCII: each byte above 127 becomes the character
    /// U+FF00 plus the byte (measured: the two bytes of `é` arrive as
    /// `\u{ffc3}\u{ffa9}`).
    fn value(self, bytes: &[u8]) -> String {
        match self {
            Self::Rest if !bytes.is_ascii() => bytes
                .iter()
                .map(|&byte| {
                    if byte.is_ascii() {
                        char::from(byte)
                    } else {
                        char::from_u32(0xFF00 | u32::from(byte))
                            .unwrap_or(char::REPLACEMENT_CHARACTER)
                    }
                })
                .collect(),
            Self::Rest | Self::HttpV1 | Self::Lower => String::from_utf8_lossy(bytes).into_owned(),
        }
    }

    /// How the lower-case header `name` appears in the event.
    fn name<'n>(self, name: &'n str, sent: &'n HeaderCase) -> Cow<'n, str> {
        match (self, self.fixed(name)) {
            (Self::Lower, _) => Cow::Borrowed(name),
            (Self::Rest | Self::HttpV1, Some(fixed)) => Cow::Borrowed(fixed),
            (Self::Rest | Self::HttpV1, None) => Cow::Borrowed(sent.spelling(name)),
        }
    }
}

/// Headers API Gateway writes into an event itself; what the client sent under
/// these names is folded into the gateway's own values.
const GATEWAY_EVENT_HEADERS: [&str; 4] = [
    "x-forwarded-for",
    "x-forwarded-port",
    "x-forwarded-proto",
    "x-amzn-trace-id",
];

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

    /// Repeated `Cookie` headers as one value, as a deployed HTTP API's payload
    /// 1.0 event carries them (`a=1; b=2`).
    fn join_cookies(&mut self) {
        if let Some(cookies) = self.0.get_mut("Cookie")
            && cookies.len() > 1
        {
            *cookies = vec![cookies.join("; ")];
        }
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
    /// Headers and query string after HTTP API request parameter mapping, in
    /// place of the request's own.
    mapped: Option<&'a (HeaderMap, QueryString)>,
}

impl<'a> ProxyEvent<'a> {
    pub(crate) fn new(ctx: &'a RequestContext, stage_variables: &'a StageVariables) -> Self {
        Self {
            ctx,
            stage_variables,
            account_id: "",
            header_table: None,
            mapped: None,
        }
    }

    /// Uses the headers and query string that request parameter mapping produced.
    pub(crate) fn with_mapped_request(
        mut self,
        mapped: Option<&'a (HeaderMap, QueryString)>,
    ) -> Self {
        self.mapped = mapped;
        self
    }

    fn request_headers(&self) -> &HeaderMap {
        self.mapped
            .map_or(&self.ctx.headers, |(headers, _)| headers)
    }

    fn request_query(&self) -> &QueryString {
        self.mapped.map_or(&self.ctx.query, |(_, query)| query)
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

    /// The request's headers as the event names them.
    fn headers(&self, version: PayloadVersion) -> MultiValues {
        let spelling = EventSpelling::of(self.ctx.api.kind, version);
        let allowed = match self.header_table {
            Some(iam) if spelling == EventSpelling::Rest => {
                Cow::Owned(Flavor::Lambda.request_headers(self.request_headers(), iam))
            }
            Some(_) | None => Cow::Borrowed(self.request_headers()),
        };
        let mut headers = MultiValues::default();
        for (name, value) in allowed.iter() {
            // Measured: no event carries a hop-by-hop header the client sent.
            if GATEWAY_EVENT_HEADERS.contains(&name.as_str()) || name.is_hop_by_hop() {
                continue;
            }
            // An HTTP API reports the length it read, not what the client claimed.
            if spelling != EventSpelling::Rest && name == header::CONTENT_LENGTH {
                continue;
            }
            let name = spelling.name(name.as_str(), &self.ctx.header_case);
            headers.push(name.into_owned(), spelling.value(value.as_bytes()));
        }
        self.push_gateway_headers(&mut headers, spelling);
        if spelling == EventSpelling::HttpV1 {
            headers.join_cookies();
        }
        headers
    }

    /// The headers API Gateway writes into an event itself, whatever the client
    /// sent: the forwarding chain, the port and protocol the client connected
    /// to, the trace header, and for HTTP APIs the body's length.
    fn push_gateway_headers(&self, headers: &mut MultiValues, spelling: EventSpelling) {
        let ctx = self.ctx;
        let mut push = |name: &str, value: String| {
            headers.push(
                spelling.name(name, &HeaderCase::default()).into_owned(),
                value,
            );
        };
        let chain: Vec<&str> = ctx
            .headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        let forwarded_for = if chain.is_empty() {
            ctx.source_ip()
        } else {
            Some(chain.join(", "))
        };
        if let Some(forwarded_for) = forwarded_for {
            push("x-forwarded-for", forwarded_for);
        }
        push("x-forwarded-port", ctx.port().to_string());
        push("x-forwarded-proto", "https".to_owned());
        if let Some(trace) = ctx.started_trace_header() {
            push("x-amzn-trace-id", trace);
        }
        if spelling != EventSpelling::Rest {
            push("content-length", ctx.body.len().to_string());
        }
    }

    fn query(&self) -> MultiValues {
        let mut query = MultiValues::default();
        for (key, value) in self.request_query().pairs() {
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
        let (headers, multi_headers) = self.headers(PayloadVersion::V1).single_and_multi();
        let (query, multi_query) = self.query().single_and_multi();
        let body = EventBody::for_request(ctx);
        let http_api = ctx.api.kind == ApiKind::Http;
        let mut event = json!({
            "resource": ctx.resource_path,
            // An HTTP API reports the path as sent, stage and escapes included.
            "path": if http_api { &ctx.sent_path } else { &ctx.path },
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
                "resourceId": ctx.resource_id,
                "resourcePath": ctx.resource_path,
                "stage": ctx.api.stage_name(),
            },
            "body": body.body,
            "isBase64Encoded": body.is_base64,
        });
        // Present only when there is something to say: an event for a route
        // without an authorizer has no `authorizer` key at all.
        if let Some(Value::Object(request_context)) = event.get_mut("requestContext") {
            if let Some(authorizer) = ctx.authorizer.event_value(PayloadVersion::V1) {
                request_context.insert("authorizer".to_owned(), authorizer);
            }
            if let (false, Some(deployment_id)) = (http_api, &ctx.api.deployment_id) {
                request_context.insert("deploymentId".to_owned(), json!(deployment_id));
            }
            if http_api {
                // An HTTP API has no resources; the route stands in for one.
                request_context.insert("resourceId".to_owned(), json!(ctx.route_key.as_str()));
                if let Some(Value::Object(identity)) = request_context.get_mut("identity") {
                    identity.insert("cognitoAmr".to_owned(), Value::Null);
                }
            }
        }
        if http_api && let Value::Object(ref mut fields) = event {
            fields.insert("version".to_owned(), json!("1.0"));
        }
        event
    }

    fn v2(&self) -> Value {
        let ctx = self.ctx;
        let mut headers = self.headers(PayloadVersion::V2);
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
            "rawQueryString": self.request_query().raw().unwrap_or_default(),
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
    use crate::mapping::{RequestMapping, ResponseMapping};
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

    /// Measured against deployed REST and HTTP APIs: Lambda events leave out the
    /// hop-by-hop headers a client sends.
    #[test]
    fn events_leave_out_hop_by_hop_headers() {
        let mut ctx = incoming(b"");
        for name in [
            "connection",
            "keep-alive",
            "te",
            "upgrade",
            "proxy-connection",
        ] {
            ctx.headers.insert(name, HeaderValue::from_static("x"));
        }
        for kind in [ApiKind::Rest, ApiKind::Http] {
            ctx.api.kind = kind;
            for version in [PayloadVersion::V1, PayloadVersion::V2] {
                let event = event(&ctx, version);
                let headers = event["headers"].as_object().unwrap();
                for name in headers.keys() {
                    let lower = name.to_ascii_lowercase();
                    assert!(
                        ![
                            "connection",
                            "keep-alive",
                            "te",
                            "upgrade",
                            "proxy-connection"
                        ]
                        .contains(&lower.as_str()),
                        "{kind:?} {version:?} kept {name}"
                    );
                }
            }
        }
    }

    /// Measured against a deployed HTTP API: payload 1.0 carries repeated
    /// `Cookie` headers as one value, other repeated headers as their last value
    /// and the list; REST payload 1.0 keeps cookies apart like any header.
    #[test]
    fn repeated_cookies_are_one_value_in_http_api_payload_1() {
        let mut ctx = incoming(b"");
        ctx.headers
            .append("cookie", HeaderValue::from_static("u=3"));
        let rest = event(&ctx, PayloadVersion::V1);
        assert_eq!(
            rest["multiValueHeaders"]["cookie"],
            json!(["s=1; t=2", "u=3"])
        );
        assert_eq!(rest["headers"]["x-multi"], "b");
        ctx.api.kind = ApiKind::Http;
        let http = event(&ctx, PayloadVersion::V1);
        assert_eq!(http["headers"]["Cookie"], "s=1; t=2; u=3");
        assert_eq!(
            http["multiValueHeaders"]["Cookie"],
            json!(["s=1; t=2; u=3"])
        );
        assert_eq!(http["multiValueHeaders"]["x-multi"], json!(["a", "b"]));
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
        assert!(
            event["requestContext"].get("authorizer").is_none(),
            "no authorizer ran, so the key is absent"
        );
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
            rest["headers"]["User-Agent"], "curl/8",
            "API Gateway spells this one itself"
        );
        ctx.headers
            .insert("x-unrecorded", HeaderValue::from_static("1"));
        assert_eq!(
            event(&ctx, PayloadVersion::V1)["headers"]["x-unrecorded"],
            "1",
            "unrecorded names stay lower case"
        );

        ctx.api.kind = ApiKind::Http;
        let http = event(&ctx, PayloadVersion::V1);
        assert_eq!(
            http["headers"]["Content-Type"], "text/plain",
            "payload 1.0 keeps the client's spelling on an HTTP API too"
        );
        assert_eq!(http["headers"]["Content-Length"], "0");
        assert_eq!(http["version"], "1.0");
        assert_eq!(http["requestContext"]["resourceId"], "POST /pets/{petId}");
        assert!(http["requestContext"]["identity"]["cognitoAmr"].is_null());
        let v2 = event(&ctx, PayloadVersion::V2);
        assert_eq!(v2["headers"]["content-type"], "text/plain");
        assert_eq!(v2["headers"]["content-length"], "0");
        assert_eq!(v2["headers"]["x-forwarded-proto"], "https");
        assert!(v2["headers"].get("Host").is_none());
    }

    /// Measured against a deployed REST API: the event names the forwarding
    /// chain, port, protocol, and trace under fixed spellings, and leaves out
    /// `Content-Length`.
    #[test]
    fn rest_events_carry_the_headers_api_gateway_adds() {
        let mut ctx = incoming(b"{}");
        ctx.headers
            .insert("content-length", HeaderValue::from_static("2"));
        ctx.headers
            .insert("x-forwarded-for", HeaderValue::from_static("203.0.113.9"));
        ctx.headers
            .insert("x-forwarded-proto", HeaderValue::from_static("http"));
        ctx.headers
            .insert("x-forwarded-port", HeaderValue::from_static("80"));
        let event = ProxyEvent::new(&ctx, &variables())
            .with_header_table(IamAuthorization::NotUsed)
            .render(PayloadVersion::V1);
        let headers = event["headers"].as_object().unwrap();
        assert_eq!(headers["X-Forwarded-For"], "203.0.113.9");
        assert_eq!(headers["X-Forwarded-Port"], "443");
        assert_eq!(headers["X-Forwarded-Proto"], "https");
        assert_eq!(
            event["multiValueHeaders"]["X-Forwarded-Proto"],
            json!(["https"])
        );
        let trace = headers["X-Amzn-Trace-Id"].as_str().unwrap();
        assert!(trace.starts_with("Root=1-"), "{trace}");
        for absent in [
            "x-forwarded-for",
            "x-forwarded-proto",
            "x-forwarded-port",
            "x-amzn-trace-id",
            "content-length",
            "Content-Length",
        ] {
            assert!(!headers.contains_key(absent), "{absent}");
        }
    }

    #[test]
    fn a_clients_trace_header_follows_the_gateways_own() {
        let mut ctx = incoming(b"");
        ctx.headers.insert(
            "x-amzn-trace-id",
            HeaderValue::from_static("Root=1-67891233-abcdef012345678912345678;Sampled=1"),
        );
        let event = event(&ctx, PayloadVersion::V1);
        let trace = event["headers"]["X-Amzn-Trace-Id"].as_str().unwrap();
        let (own, sent) = trace.split_once(';').unwrap();
        assert!(own.starts_with("Self=1-"), "{trace}");
        assert_eq!(sent, "Root=1-67891233-abcdef012345678912345678;Sampled=1");
    }

    /// Measured against a deployed REST API with `X-Custom: café`.
    #[test]
    fn rest_events_do_not_decode_header_values_that_are_not_ascii() {
        let mut ctx = incoming(b"");
        ctx.headers.insert(
            "x-custom",
            HeaderValue::from_bytes("café".as_bytes()).unwrap(),
        );
        assert_eq!(
            event(&ctx, PayloadVersion::V1)["headers"]["x-custom"],
            "caf\u{ffc3}\u{ffa9}"
        );
        ctx.api.kind = ApiKind::Http;
        assert_eq!(
            event(&ctx, PayloadVersion::V2)["headers"]["x-custom"],
            "café"
        );
    }

    #[test]
    fn the_event_names_the_rest_resource_when_its_id_is_known() {
        let mut ctx = incoming(b"");
        assert!(event(&ctx, PayloadVersion::V1)["requestContext"]["resourceId"].is_null());
        ctx.resource_id = Some("t7o32o".to_owned());
        assert_eq!(
            event(&ctx, PayloadVersion::V1)["requestContext"]["resourceId"],
            "t7o32o"
        );
        assert_eq!(ctx.variables()["resourceId"], "t7o32o");
    }

    #[test]
    fn the_event_names_the_deployment_when_it_is_known() {
        let mut ctx = incoming(b"");
        assert!(
            event(&ctx, PayloadVersion::V1)["requestContext"]
                .get("deploymentId")
                .is_none()
        );
        ctx.api.deployment_id = Some("8ckp7l".to_owned());
        assert_eq!(
            event(&ctx, PayloadVersion::V1)["requestContext"]["deploymentId"],
            "8ckp7l"
        );
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
        assert_eq!(table["headers"]["Authorization"], "Bearer t");
        let iam = ProxyEvent::new(&ctx, &vars)
            .with_header_table(IamAuthorization::Used)
            .render(PayloadVersion::V1);
        assert!(iam["headers"].get("Authorization").is_none());
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
        }
    }

    fn proxy(function: &str, transfer: ResponseTransferMode) -> LambdaProxy {
        LambdaProxy {
            function: function.parse::<FunctionArn>().unwrap(),
            credentials: None,
            payload: PayloadVersion::V1,
            timeout: Duration::from_secs(5),
            transfer,
            request_mapping: RequestMapping::default(),
            response_mapping: ResponseMapping::default(),
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

    /// Every type here was posted to a deployed HTTP API, which answered with
    /// the `isBase64Encoded` shown.
    #[test]
    fn http_api_bodies_are_text_only_for_the_types_api_gateway_takes_for_text() {
        let text = [
            "text/plain",
            "TEXT/HTML",
            "text/csv; charset=utf-8",
            "text/event-stream",
            "text/x1",
            "text/a+b",
            "text/yaml",
            "text/plain; format=flowed",
            "text/html; Charset=UTF-8",
            "application/json",
            "APPLICATION/JSON",
            " application/json",
            "application/xml",
            "application/javascript",
            "application/x-javascript",
            "application/ecmascript",
            "application/x-ecmascript",
            "application/graphql",
            "application/x-yaml",
            "application/soap+xml",
            "application/problem+json",
            "application/a-b+json",
            "application/ab1+json",
            "application/A-B+JSON",
            "application/+json",
            "application/foo+xml",
            "application/graphql-response+json",
            "application/json; charset=utf-8",
            "application/json;charset=utf-8",
            "application/json;  charset=utf-8",
            "application/json; charset=\"utf-8\"",
            "application/json; CHARSET=utf-8",
            "application/json; charset=us-ascii",
            "application/json; foo=bar",
            "application/json; boundary=x",
            "application/soap+xml; action=x",
            "application/json, text/plain",
            "application/pdf, application/json",
        ];
        for content_type in text {
            assert!(TextMediaType::matches(content_type), "{content_type:?}");
        }
        let binary = [
            "",
            "foo",
            "text",
            "text/",
            "text/*",
            "*/*",
            "text/a.b",
            "text/x-foo_bar",
            "text/vnd.foo",
            "text/plain;x",
            "text/plain; charset=iso-8859-1",
            "text/plain; charset=x",
            "application/octet-stream",
            "application/x-www-form-urlencoded",
            "application/x-www-form-urlencoded; charset=utf-8",
            "multipart/form-data; boundary=x",
            "image/png",
            "image/svg+xml",
            "image/foo+json",
            "foo/bar+json",
            "application/vnd.api+json",
            "application/vnd.foo+xml",
            "application/a.b+json",
            "application/a_b+json",
            "application/json+foo",
            "application/foo+json+bar",
            "application/foo+yaml",
            "application/yaml",
            "application/x-json",
            "application/x-xml",
            "application/x-graphql",
            "application/ndjson",
            "application/jsonx",
            "application/xml-dtd",
            "application/typescript",
            "application/html",
            "application/json;",
            "application/json;x",
            "application/json; foo",
            "application/json; foo=",
            "application/json ; charset=utf-8",
            "application/json x",
            "application/json,",
            "application/json,x",
            "application/json; foo=bar, x",
            "application/json; foo=bar; baz=q",
            "application/json; charset=utf-8; x=y",
            "application/json; x=y; charset=utf-8",
            "application/json; charset=utf8",
            "application/json; charset=UTF-16",
            "application/xml;charset=utf-16",
        ];
        for content_type in binary {
            assert!(!TextMediaType::matches(content_type), "{content_type:?}");
        }
    }

    #[test]
    fn an_http_api_body_with_no_type_or_a_binary_one_is_base64() {
        let mut ctx = incoming(b"hello");
        ctx.api.kind = ApiKind::Http;
        ctx.headers.remove(header::CONTENT_TYPE);
        let untyped = EventBody::for_request(&ctx);
        assert_eq!((untyped.body, untyped.is_base64), (json!("aGVsbG8="), true));
        ctx.headers.insert(
            header::CONTENT_TYPE,
            "application/x-www-form-urlencoded".parse().unwrap(),
        );
        assert!(EventBody::for_request(&ctx).is_base64);
        ctx.headers
            .insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        let text = EventBody::for_request(&ctx);
        assert_eq!((text.body, text.is_base64), (json!("hello"), false));
        ctx.body = Bytes::from_static(&[0xff, 0xfe]);
        let lossy = EventBody::for_request(&ctx);
        assert_eq!(
            (lossy.body, lossy.is_base64),
            (json!("\u{fffd}\u{fffd}"), false),
            "text that is not UTF-8 is not encoded either"
        );
    }

    proptest::proptest! {
        #[test]
        fn any_content_type_is_classified(content_type in ".{0,60}") {
            proptest::prop_assert!(content_type.contains('/') || !TextMediaType::matches(&content_type));
        }
    }
}
