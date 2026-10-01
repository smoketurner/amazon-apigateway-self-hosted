//! `HTTP_PROXY` integrations: forward the request to the integration URI and
//! stream the response back unchanged.

use std::time::Instant;

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue};
use axum::response::Response;

use crate::gateway::{GatewayError, HeaderNameExt as _};
use crate::integration::{HttpProxy, ParamSource, PrivateRouting};
use crate::model::RoutePath;
use crate::pipeline::RequestContext;
use crate::route::Route;

impl HttpProxy {
    pub(crate) async fn forward(
        &self,
        client: &reqwest::Client,
        route: &Route,
        ctx: &mut RequestContext,
    ) -> Result<Response, GatewayError> {
        let mut url = match self.target_url(&route.path, ctx) {
            Ok(url) => url,
            Err(err) => {
                tracing::error!(route = %route.key, uri = self.uri, %err, "invalid integration URI");
                return Err(GatewayError::ApiConfiguration);
            }
        };
        let method = self.method.clone().unwrap_or_else(|| ctx.method.clone());
        let mut headers = reqwest::header::HeaderMap::new();
        for (name, value) in &ctx.headers {
            if name != axum::http::header::HOST
                && name != axum::http::header::CONTENT_LENGTH
                && !name.is_hop_by_hop()
            {
                headers.append(name.clone(), value.clone());
            }
        }
        if let Some(PrivateRouting::HostHeader(ref host)) = self.private {
            headers.insert(axum::http::header::HOST, host.clone());
        }
        if let Some(trace) = ctx.trace
            && let Ok(value) = HeaderValue::try_from(trace.traceparent())
        {
            headers.insert(HeaderName::from_static("traceparent"), value);
        }
        for (name, source) in &self.headers {
            let Some(value) = source.resolve(ctx) else {
                continue;
            };
            match (
                HeaderName::try_from(name.as_str()),
                HeaderValue::try_from(value),
            ) {
                (Ok(name), Ok(value)) => {
                    headers.insert(name, value);
                }
                (Err(_), _) | (_, Err(_)) => {
                    tracing::warn!(header = name, "mapped header is not a valid HTTP header");
                }
            }
        }
        self.request_mapping.apply(ctx, &mut headers, &mut url);
        ctx.integration.transfer_mode = Some(self.transfer);
        let started = Instant::now();
        let result = client
            .request(method, url)
            .headers(headers)
            .body(std::mem::take(&mut ctx.body))
            .timeout(self.timeout)
            .send()
            .await;
        let upstream = match result {
            Ok(upstream) => upstream,
            Err(err) if err.is_timeout() => {
                tracing::warn!(route = %route.key, "integration timed out");
                return Err(GatewayError::IntegrationTimeout);
            }
            Err(err) => {
                tracing::warn!(route = %route.key, err = %err, "integration request failed");
                return Err(GatewayError::IntegrationUnreachable);
            }
        };
        let headers_after = u64::try_from(started.elapsed().as_millis()).ok();
        ctx.integration.status = Some(upstream.status().as_u16());
        ctx.integration.time_to_all_headers_ms = headers_after;
        tracing::debug!(
            route = %route.key,
            status = upstream.status().as_u16(),
            latency_ms = headers_after,
            "integration responded"
        );
        let mut response = Response::new(Body::empty());
        *response.status_mut() = upstream.status();
        for (name, value) in upstream.headers() {
            if !name.is_hop_by_hop() {
                response.headers_mut().append(name.clone(), value.clone());
            }
        }
        let Some(mapping) = self.response_mapping.for_status(upstream.status()) else {
            *response.body_mut() = Body::from_stream(upstream.bytes_stream());
            return Ok(response);
        };
        if mapping.reads_body() {
            let body = upstream.bytes().await.map_err(|err| {
                tracing::warn!(route = %route.key, err = %err, "integration response could not be read");
                GatewayError::IntegrationFailure
            })?;
            mapping.apply(ctx, Some(&body), &mut response);
            *response.body_mut() = Body::from(body);
        } else {
            mapping.apply(ctx, None, &mut response);
            *response.body_mut() = Body::from_stream(upstream.bytes_stream());
        }
        Ok(response)
    }

    /// Fills `{name}` placeholders in the integration URI and carries the
    /// client's query string over, as API Gateway does for proxy integrations.
    fn target_url(
        &self,
        route_path: &RoutePath,
        ctx: &RequestContext,
    ) -> Result<reqwest::Url, String> {
        let url = match self.private {
            Some(PrivateRouting::RequestPath) => self.request_path_url(ctx),
            Some(PrivateRouting::HostHeader(_)) | None => {
                self.fill_placeholders(route_path, ctx)?
            }
        };
        let mut url = reqwest::Url::parse(&url).map_err(|e| e.to_string())?;
        let mut query = QueryBuilder(url.query().map(str::to_owned).unwrap_or_default());
        if let Some(raw) = ctx.query.raw() {
            query.append(raw);
        }
        for (name, source) in &self.query_params {
            if let Some(value) = source.resolve(ctx) {
                let mut pair = String::new();
                UrlEncoder(&mut pair).component(name);
                pair.push('=');
                UrlEncoder(&mut pair).component(&value);
                query.append(&pair);
            }
        }
        url.set_query((!query.0.is_empty()).then_some(query.0.as_str()));
        Ok(url)
    }

    /// An HTTP API private integration forwards the request path after the
    /// mapped base URL, preceded by the stage name unless it is `$default`.
    fn request_path_url(&self, ctx: &RequestContext) -> String {
        let stage = ctx
            .api
            .stage
            .as_deref()
            .filter(|stage| *stage != "$default");
        let mut url = self.uri.clone();
        if let Some(stage) = stage {
            url.push('/');
            url.push_str(stage);
        }
        url.push_str(&ctx.path);
        url
    }

    fn fill_placeholders(
        &self,
        route_path: &RoutePath,
        ctx: &RequestContext,
    ) -> Result<String, String> {
        let greedy = route_path.greedy_param();
        let mut url = String::with_capacity(self.uri.len());
        let mut rest = self.uri.as_str();
        while let Some(open) = rest.find('{') {
            let (before, after) = rest.split_at(open);
            url.push_str(before);
            let Some((name, tail)) = after.trim_start_matches('{').split_once('}') else {
                return Err("unterminated placeholder".to_owned());
            };
            let value = match self.path_params.get(name) {
                Some(source) => source.resolve(ctx),
                None => ctx.path_param(name).map(str::to_owned),
            };
            let Some(value) = value else {
                return Err(format!("no value for placeholder {{{name}}}"));
            };
            UrlEncoder(&mut url).path_value(&value, greedy == Some(name));
            rest = tail;
        }
        url.push_str(rest);
        Ok(url)
    }
}

impl ParamSource {
    pub(crate) fn resolve(&self, ctx: &RequestContext) -> Option<String> {
        match *self {
            Self::Path(ref name) => ctx.path_param(name).map(str::to_owned),
            Self::Query(ref name) => ctx
                .query
                .pairs()
                .into_iter()
                .rev()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value),
            Self::Header(ref name) => ctx.header_str(name).map(str::to_owned),
            Self::Context(ref path) => ctx.context_value(path),
            Self::StageVariable(ref name) => ctx.stage_variables.get(name).map(str::to_owned),
            Self::Literal(ref value) => Some(value.clone()),
        }
    }
}

impl RoutePath {
    /// The name of the route's `{name+}` greedy parameter, whose value keeps
    /// its `/`s.
    fn greedy_param(&self) -> Option<&str> {
        let Self::Resource(path) = self else {
            return None;
        };
        path.rsplit('/')
            .next()
            .and_then(|segment| segment.strip_prefix('{'))
            .and_then(|segment| segment.strip_suffix("+}"))
    }
}

/// A query string being assembled from `name=value` pairs.
#[derive(Default)]
pub(crate) struct QueryBuilder(String);

impl QueryBuilder {
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn append(&mut self, pair: &str) {
        if pair.is_empty() {
            return;
        }
        if !self.0.is_empty() {
            self.0.push('&');
        }
        self.0.push_str(pair);
    }
}

/// Percent-encodes into a buffer, leaving only RFC 3986 unreserved bytes bare.
pub(crate) struct UrlEncoder<'a>(pub(crate) &'a mut String);

impl UrlEncoder<'_> {
    fn path_value(&mut self, value: &str, keep_slashes: bool) {
        for byte in value.bytes() {
            if byte == b'/' && keep_slashes {
                self.0.push('/');
            } else {
                self.byte(byte);
            }
        }
    }

    pub(crate) fn component(&mut self, value: &str) {
        for byte in value.bytes() {
            self.byte(byte);
        }
    }

    fn byte(&mut self, byte: u8) {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            self.0.push(char::from(byte));
        } else {
            self.0.push('%');
            for nibble in [byte >> 4, byte & 0x0f] {
                let digit = char::from_digit(u32::from(nibble), 16).unwrap_or('0');
                self.0.push(digit.to_ascii_uppercase());
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use axum::body::Bytes;
    use axum::http::{Method, StatusCode};
    use proptest::prelude::*;

    use super::*;
    use crate::authz::{RouteAuthorizer, RoutePolicy};
    use crate::integration::Integration;
    use crate::mapping::{RequestMapping, ResponseMapping};
    use crate::model::{ApiKind, MethodMatch, Protections, ResponseTransferMode, RouteKey};
    use crate::pipeline::context::QueryString;
    use crate::pipeline::context::tests::request;
    use crate::usage::RouteApiKey;

    fn incoming(params: &[(&str, &str)], query: Option<&str>) -> RequestContext {
        let mut ctx = request(ApiKind::Rest);
        ctx.headers
            .insert("x-tenant", HeaderValue::from_static("acme"));
        ctx.method = Method::GET;
        ctx.query = QueryString::new(query);
        ctx.path_params = params
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        ctx
    }

    fn proxy(uri: &str) -> HttpProxy {
        HttpProxy {
            method: None,
            uri: uri.to_owned(),
            path_params: BTreeMap::new(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::new(),
            request_mapping: RequestMapping::default(),
            response_mapping: ResponseMapping::default(),
            timeout: Duration::from_secs(1),
            transfer: ResponseTransferMode::Buffered,
            private: None,
        }
    }

    fn route(path: &str, target: &HttpProxy) -> Route {
        let path = RoutePath::Resource(path.to_owned());
        Route {
            key: RouteKey::new(&MethodMatch::Any, &path),
            method: MethodMatch::Any,
            path,
            integration: Integration::HttpProxy(target.clone()),
            protections: Protections::default(),
            authorizer: RouteAuthorizer::None,
            policy: RoutePolicy::None,
            api_key: RouteApiKey::NotRequired,
            unenforced: Vec::new(),
            throttle: None,
        }
    }

    #[test]
    fn greedy_values_keep_slashes_and_others_are_encoded() {
        let target = proxy("http://up/{proxy}?fixed=1");
        let url = target
            .target_url(
                &route("/{proxy+}", &target).path,
                &incoming(&[("proxy", "a b/c")], Some("x=1")),
            )
            .unwrap();
        assert_eq!(url.as_str(), "http://up/a%20b/c?fixed=1&x=1");

        let target = proxy("http://up/items/{id}");
        let url = target
            .target_url(
                &route("/items/{id}", &target).path,
                &incoming(&[("id", "a/b")], None),
            )
            .unwrap();
        assert_eq!(url.as_str(), "http://up/items/a%2Fb");
    }

    #[test]
    fn mapped_parameters_are_resolved() {
        let mut target = proxy("http://up/v2/{item}");
        target
            .path_params
            .insert("item".to_owned(), ParamSource::Path("id".to_owned()));
        target.query_params.insert(
            "tenant".to_owned(),
            ParamSource::Header("x-tenant".to_owned()),
        );
        target
            .query_params
            .insert("q".to_owned(), ParamSource::Query("search".to_owned()));
        target.query_params.insert(
            "missing".to_owned(),
            ParamSource::Query("absent".to_owned()),
        );
        let url = target
            .target_url(
                &route("/items/{id}", &target).path,
                &incoming(&[("id", "7")], Some("search=a&search=b%20c")),
            )
            .unwrap();
        assert_eq!(
            url.as_str(),
            "http://up/v2/7?search=a&search=b%20c&q=b%20c&tenant=acme"
        );
    }

    #[test]
    fn missing_or_malformed_placeholders_are_errors() {
        let target = proxy("http://up/{nope}");
        assert!(
            target
                .target_url(&route("/x", &target).path, &incoming(&[], None))
                .is_err()
        );
        let target = proxy("http://up/{open");
        assert!(
            target
                .target_url(&route("/x", &target).path, &incoming(&[], None))
                .is_err()
        );
        let target = proxy("not a url");
        assert!(
            target
                .target_url(&route("/x", &target).path, &incoming(&[], None))
                .is_err()
        );
    }

    #[test]
    fn greedy_param_only_matches_trailing_plus_segment() {
        assert_eq!(
            RoutePath::Resource("/a/{proxy+}".to_owned()).greedy_param(),
            Some("proxy")
        );
        assert_eq!(
            RoutePath::Resource("/a/{id}".to_owned()).greedy_param(),
            None
        );
        assert_eq!(RoutePath::Default.greedy_param(), None);
    }

    async fn upstream() -> std::net::SocketAddr {
        use axum::extract::Request;
        let app = axum::Router::new()
            .route(
                "/echo/{*rest}",
                axum::routing::any(|request: Request| async move {
                    let (parts, body) = request.into_parts();
                    let body = axum::body::to_bytes(body, 1 << 20).await.unwrap();
                    let headers: BTreeMap<String, String> = parts
                        .headers
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_owned()))
                        .collect();
                    (
                        [("x-upstream", "yes"), ("connection", "close")],
                        serde_json::json!({
                            "method": parts.method.as_str(),
                            "uri": parts.uri.to_string(),
                            "headers": headers,
                            "body": String::from_utf8_lossy(&body),
                        })
                        .to_string(),
                    )
                }),
            )
            .route(
                "/slow",
                axum::routing::get(|| async {
                    tokio::time::sleep(Duration::from_secs(5)).await;
                    "late"
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        addr
    }

    async fn send(
        target: HttpProxy,
        route_path: &str,
        mut request: RequestContext,
    ) -> Result<Response, GatewayError> {
        let route = route(route_path, &target);
        target
            .forward(&reqwest::Client::new(), &route, &mut request)
            .await
    }

    #[tokio::test]
    async fn forwards_method_query_headers_and_body() {
        let addr = upstream().await;
        let mut target = proxy(&format!("http://{addr}/echo/{{proxy}}"));
        target
            .headers
            .insert("x-mapped".to_owned(), ParamSource::Literal("v".to_owned()));
        let mut request = incoming(&[("proxy", "a/b")], Some("x=1"));
        request.method = Method::POST;
        request.body = Bytes::from_static(b"payload");
        request
            .headers
            .insert("connection", HeaderValue::from_static("keep-alive"));
        request.headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("198.51.100.1, 192.0.2.9"),
        );
        let response = send(target, "/{proxy+}", request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-upstream"], "yes");
        assert!(response.headers().get("connection").is_none());
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let echoed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(echoed["method"], "POST");
        assert_eq!(echoed["uri"], "/echo/a/b?x=1");
        assert_eq!(echoed["body"], "payload");
        assert_eq!(echoed["headers"]["x-tenant"], "acme");
        assert_eq!(echoed["headers"]["x-mapped"], "v");
        assert_eq!(
            echoed["headers"]["x-forwarded-for"],
            "198.51.100.1, 192.0.2.9"
        );
        assert!(
            echoed["headers"]
                .get("connection")
                .is_none_or(|v| v != "keep-alive")
        );
    }

    #[tokio::test]
    async fn fixed_integration_method_overrides_client_method() {
        let addr = upstream().await;
        let mut target = proxy(&format!("http://{addr}/echo/fixed"));
        target.method = Some(Method::PUT);
        let response = send(target, "/x", incoming(&[], None)).await.unwrap();
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let echoed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(echoed["method"], "PUT");
    }

    #[tokio::test]
    async fn http_api_parameter_mappings_change_the_request_and_response() {
        let addr = upstream().await;
        let mut target = proxy(&format!("http://{addr}/echo/x"));
        target.request_mapping = RequestMapping::compile(&BTreeMap::from([
            (
                "append:header.x-from".to_owned(),
                "$request.header.x-tenant".to_owned(),
            ),
            ("remove:header.x-tenant".to_owned(), String::new()),
            (
                "append:querystring.added".to_owned(),
                "$context.stage".to_owned(),
            ),
        ]));
        target.response_mapping = ResponseMapping::compile(&BTreeMap::from([(
            "200".to_owned(),
            BTreeMap::from([
                ("overwrite:statuscode".to_owned(), "202".to_owned()),
                (
                    "append:header.x-method".to_owned(),
                    "${response.body.method}".to_owned(),
                ),
                ("remove:header.x-upstream".to_owned(), String::new()),
            ]),
        )]));
        let response = send(target, "/x", incoming(&[], Some("q=1")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(response.headers()["x-method"], "GET");
        assert!(response.headers().get("x-upstream").is_none());
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let echoed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(echoed["headers"]["x-from"], "acme");
        assert!(echoed["headers"].get("x-tenant").is_none());
        assert_eq!(echoed["uri"], "/echo/x?q=1&added=prod");
    }

    #[tokio::test]
    async fn responses_without_a_mapping_for_their_status_stream_unchanged() {
        let addr = upstream().await;
        let mut target = proxy(&format!("http://{addr}/echo/x"));
        target.response_mapping = ResponseMapping::compile(&BTreeMap::from([(
            "500".to_owned(),
            BTreeMap::from([("overwrite:statuscode".to_owned(), "403".to_owned())]),
        )]));
        let response = send(target, "/x", incoming(&[], None)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["x-upstream"], "yes");
    }

    fn private_proxy(spec: serde_json::Value, kind: ApiKind, base: &str) -> Option<HttpProxy> {
        use serde::Deserialize as _;

        use crate::integration::StageVariables;
        use crate::model::IntegrationSpec;
        use crate::vpc_link::VpcLinks;
        let spec = IntegrationSpec::deserialize(spec).unwrap();
        let links = VpcLinks::new([format!("vl={base}").parse().unwrap()]);
        let integration =
            Integration::compile(Some(&spec), kind, &StageVariables::default(), &links);
        let Integration::HttpProxy(proxy) = integration else {
            return None;
        };
        Some(proxy)
    }

    async fn echoed(response: Response) -> serde_json::Value {
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn rest_vpc_link_integrations_call_the_mapped_url_with_the_uri_host() {
        let addr = upstream().await;
        let target = private_proxy(
            serde_json::json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl",
                "uri": "http://nlb.internal.example:8080/echo/{proxy}?fixed=1"}),
            ApiKind::Rest,
            &format!("http://{addr}"),
        )
        .unwrap();
        let response = send(
            target,
            "/{proxy+}",
            incoming(&[("proxy", "a/b")], Some("x=1")),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let echo = echoed(response).await;
        assert_eq!(echo["uri"], "/echo/a/b?fixed=1&x=1");
        assert_eq!(echo["headers"]["host"], "nlb.internal.example:8080");
    }

    #[tokio::test]
    async fn http_api_vpc_link_integrations_forward_the_request_path_with_the_stage() {
        let addr = upstream().await;
        let spec = serde_json::json!({"type": "http_proxy", "connectionType": "VPC_LINK", "connectionId": "vl",
            "uri": "arn:aws:elasticloadbalancing:us-east-2:123456789012:listener/app/lb/50dc/0467"});
        let target = private_proxy(spec, ApiKind::Http, &format!("http://{addr}/echo")).unwrap();
        let mut named = incoming(&[], Some("q=1"));
        named.path = "/pets/7".to_owned();
        let echo = echoed(send(target.clone(), "/pets/{id}", named).await.unwrap()).await;
        assert_eq!(echo["uri"], "/echo/prod/pets/7?q=1");

        let mut default_stage = incoming(&[], None);
        default_stage.api.stage = None;
        default_stage.path = "/pets/8".to_owned();
        let echo = echoed(send(target, "/pets/{id}", default_stage).await.unwrap()).await;
        assert_eq!(echo["uri"], "/echo/pets/8");
    }

    #[tokio::test]
    async fn slow_upstreams_time_out_with_504() {
        let addr = upstream().await;
        let mut target = proxy(&format!("http://{addr}/slow"));
        target.timeout = Duration::from_millis(100);
        let error = send(target, "/slow", incoming(&[], None))
            .await
            .unwrap_err();
        assert_eq!(error, GatewayError::IntegrationTimeout);
    }

    #[tokio::test]
    async fn unreachable_upstreams_and_bad_uris_are_gateway_errors() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        let error = send(
            proxy(&format!("http://{closed}/")),
            "/x",
            incoming(&[], None),
        )
        .await
        .unwrap_err();
        assert_eq!(error, GatewayError::IntegrationUnreachable);
        let error = send(proxy("http://up/{missing}"), "/x", incoming(&[], None))
            .await
            .unwrap_err();
        assert_eq!(error, GatewayError::ApiConfiguration);
    }

    proptest! {
        #[test]
        fn encoded_components_round_trip(value in ".*") {
            let mut encoded = String::new();
            UrlEncoder(&mut encoded).component(&value);
            prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)));
            let decoded = reqwest::Url::parse(&format!("http://h/?k={encoded}")).unwrap();
            let pairs: Vec<(String, String)> = decoded.query_pairs().into_owned().collect();
            prop_assert_eq!(pairs, vec![("k".to_owned(), value)]);
        }
    }
}
