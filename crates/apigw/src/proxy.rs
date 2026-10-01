//! `HTTP_PROXY` integrations: forward the request to the integration URI and
//! stream the response back unchanged.

use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, StatusCode};
use axum::response::Response;

use crate::gateway::{self, Incoming, is_hop_by_hop};
use crate::spec::{ApiKind, HttpProxy, ParamSource, Route, RoutePath};

pub(crate) async fn forward(
    client: &reqwest::Client,
    kind: ApiKind,
    target: &HttpProxy,
    route: &Route,
    incoming: Incoming,
) -> Response {
    let url = match target_url(target, route, &incoming) {
        Ok(url) => url,
        Err(err) => {
            tracing::error!(route = %route.route_key(), uri = target.uri, %err, "invalid integration URI");
            return internal_error();
        }
    };
    let method = target
        .method
        .clone()
        .unwrap_or_else(|| incoming.method.clone());
    let mut headers = reqwest::header::HeaderMap::new();
    for (name, value) in &incoming.headers {
        if name != axum::http::header::HOST
            && name != axum::http::header::CONTENT_LENGTH
            && !is_hop_by_hop(name)
        {
            headers.append(name.clone(), value.clone());
        }
    }
    if let Some(ref ip) = incoming.source_ip {
        let forwarded = match incoming.header_str("x-forwarded-for") {
            Some(existing) => format!("{existing}, {ip}"),
            None => ip.clone(),
        };
        if let Ok(value) = HeaderValue::try_from(forwarded) {
            headers.insert(HeaderName::from_static("x-forwarded-for"), value);
        }
    }
    for (name, source) in &target.headers {
        let Some(value) = resolve(source, &incoming) else {
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
    let result = client
        .request(method, url)
        .headers(headers)
        .body(incoming.body)
        .timeout(target.timeout)
        .send()
        .await;
    let upstream = match result {
        Ok(upstream) => upstream,
        Err(err) if err.is_timeout() => {
            tracing::warn!(route = %route.route_key(), "integration timed out");
            return timeout_error(kind);
        }
        Err(err) => {
            tracing::warn!(route = %route.route_key(), err = %err, "integration request failed");
            return internal_error();
        }
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = upstream.status();
    for (name, value) in upstream.headers() {
        if !is_hop_by_hop(name) {
            response.headers_mut().append(name.clone(), value.clone());
        }
    }
    *response.body_mut() = Body::from_stream(upstream.bytes_stream());
    response
}

fn internal_error() -> Response {
    gateway::error(StatusCode::BAD_GATEWAY, "Internal server error")
}

pub(crate) fn timeout_error(kind: ApiKind) -> Response {
    match kind {
        ApiKind::Rest => gateway::error(StatusCode::GATEWAY_TIMEOUT, "Endpoint request timed out"),
        ApiKind::Http => gateway::error(StatusCode::GATEWAY_TIMEOUT, "Service Unavailable"),
    }
}

fn resolve(source: &ParamSource, incoming: &Incoming) -> Option<String> {
    match *source {
        ParamSource::Path(ref name) => incoming.path_param(name).map(str::to_owned),
        ParamSource::Query(ref name) => incoming
            .query_pairs()
            .into_iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value),
        ParamSource::Header(ref name) => incoming.header_str(name).map(str::to_owned),
        ParamSource::Literal(ref value) => Some(value.clone()),
    }
}

/// Fills `{name}` placeholders in the integration URI and carries the client's
/// query string over, as API Gateway does for proxy integrations.
fn target_url(
    target: &HttpProxy,
    route: &Route,
    incoming: &Incoming,
) -> Result<reqwest::Url, String> {
    let greedy = greedy_param(&route.path);
    let mut url = String::with_capacity(target.uri.len());
    let mut rest = target.uri.as_str();
    while let Some(open) = rest.find('{') {
        let (before, after) = rest.split_at(open);
        url.push_str(before);
        let Some((name, tail)) = after.trim_start_matches('{').split_once('}') else {
            return Err("unterminated placeholder".to_owned());
        };
        let value = match target.path_params.get(name) {
            Some(source) => resolve(source, incoming),
            None => incoming.path_param(name).map(str::to_owned),
        };
        let Some(value) = value else {
            return Err(format!("no value for placeholder {{{name}}}"));
        };
        encode_path_value(&value, greedy == Some(name), &mut url);
        rest = tail;
    }
    url.push_str(rest);
    let mut url = reqwest::Url::parse(&url).map_err(|e| e.to_string())?;
    let mut query = url.query().map(str::to_owned).unwrap_or_default();
    if let Some(ref incoming_query) = incoming.query {
        append_query(&mut query, incoming_query);
    }
    for (name, source) in &target.query_params {
        if let Some(value) = resolve(source, incoming) {
            let mut pair = String::new();
            encode_component(name, &mut pair);
            pair.push('=');
            encode_component(&value, &mut pair);
            append_query(&mut query, &pair);
        }
    }
    url.set_query((!query.is_empty()).then_some(query.as_str()));
    Ok(url)
}

fn append_query(query: &mut String, pair: &str) {
    if pair.is_empty() {
        return;
    }
    if !query.is_empty() {
        query.push('&');
    }
    query.push_str(pair);
}

/// The name of a route's `{name+}` greedy parameter, whose value keeps its `/`s.
fn greedy_param(path: &RoutePath) -> Option<&str> {
    let RoutePath::Resource(path) = path else {
        return None;
    };
    path.rsplit('/')
        .next()
        .and_then(|segment| segment.strip_prefix('{'))
        .and_then(|segment| segment.strip_suffix("+}"))
}

fn encode_path_value(value: &str, keep_slashes: bool, out: &mut String) {
    for byte in value.bytes() {
        if byte == b'/' && keep_slashes {
            out.push('/');
        } else {
            encode_byte(byte, out);
        }
    }
}

fn encode_component(value: &str, out: &mut String) {
    for byte in value.bytes() {
        encode_byte(byte, out);
    }
}

fn encode_byte(byte: u8, out: &mut String) {
    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
        out.push(char::from(byte));
    } else {
        out.push('%');
        for nibble in [byte >> 4, byte & 0x0f] {
            let digit = char::from_digit(u32::from(nibble), 16).unwrap_or('0');
            out.push(digit.to_ascii_uppercase());
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
    use axum::http::{HeaderMap, Method};
    use proptest::prelude::*;

    use super::*;
    use crate::spec::{Integration, MethodMatch, Protections};

    fn incoming(params: &[(&str, &str)], query: Option<&str>) -> Incoming {
        let mut headers = HeaderMap::new();
        headers.insert("x-tenant", HeaderValue::from_static("acme"));
        Incoming {
            request_id: uuid::Uuid::now_v7(),
            received: jiff::Timestamp::now(),
            method: Method::GET,
            path: "/".to_owned(),
            query: query.map(str::to_owned),
            headers,
            path_params: params
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            source_ip: None,
            body: Bytes::new(),
        }
    }

    fn proxy(uri: &str) -> HttpProxy {
        HttpProxy {
            method: None,
            uri: uri.to_owned(),
            path_params: BTreeMap::new(),
            query_params: BTreeMap::new(),
            headers: BTreeMap::new(),
            timeout: Duration::from_secs(1),
        }
    }

    fn route(path: &str, target: &HttpProxy) -> Route {
        Route {
            method: MethodMatch::Any,
            path: RoutePath::Resource(path.to_owned()),
            integration: Integration::HttpProxy(target.clone()),
            protections: Protections::default(),
        }
    }

    #[test]
    fn greedy_values_keep_slashes_and_others_are_encoded() {
        let target = proxy("http://up/{proxy}?fixed=1");
        let url = target_url(
            &target,
            &route("/{proxy+}", &target),
            &incoming(&[("proxy", "a b/c")], Some("x=1")),
        )
        .unwrap();
        assert_eq!(url.as_str(), "http://up/a%20b/c?fixed=1&x=1");

        let target = proxy("http://up/items/{id}");
        let url = target_url(
            &target,
            &route("/items/{id}", &target),
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
        let url = target_url(
            &target,
            &route("/items/{id}", &target),
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
        assert!(target_url(&target, &route("/x", &target), &incoming(&[], None)).is_err());
        let target = proxy("http://up/{open");
        assert!(target_url(&target, &route("/x", &target), &incoming(&[], None)).is_err());
        let target = proxy("not a url");
        assert!(target_url(&target, &route("/x", &target), &incoming(&[], None)).is_err());
    }

    #[test]
    fn greedy_param_only_matches_trailing_plus_segment() {
        assert_eq!(
            greedy_param(&RoutePath::Resource("/a/{proxy+}".to_owned())),
            Some("proxy")
        );
        assert_eq!(
            greedy_param(&RoutePath::Resource("/a/{id}".to_owned())),
            None
        );
        assert_eq!(greedy_param(&RoutePath::Default), None);
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

    async fn send(target: HttpProxy, route_path: &str, request: Incoming) -> Response {
        let route = route(route_path, &target);
        forward(
            &reqwest::Client::new(),
            ApiKind::Rest,
            &target,
            &route,
            request,
        )
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
        request.source_ip = Some("192.0.2.9".to_owned());
        request
            .headers
            .insert("connection", HeaderValue::from_static("keep-alive"));
        request
            .headers
            .insert("x-forwarded-for", HeaderValue::from_static("198.51.100.1"));
        let response = send(target, "/{proxy+}", request).await;
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
        let response = send(target, "/x", incoming(&[], None)).await;
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        let echoed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(echoed["method"], "PUT");
    }

    #[tokio::test]
    async fn slow_upstreams_time_out_with_504() {
        let addr = upstream().await;
        let mut target = proxy(&format!("http://{addr}/slow"));
        target.timeout = Duration::from_millis(100);
        let response = send(target, "/slow", incoming(&[], None)).await;
        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn unreachable_upstreams_and_bad_uris_answer_502() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let closed = listener.local_addr().unwrap();
        drop(listener);
        let response = send(
            proxy(&format!("http://{closed}/")),
            "/x",
            incoming(&[], None),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        let response = send(proxy("http://up/{missing}"), "/x", incoming(&[], None)).await;
        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
    }

    proptest! {
        #[test]
        fn encoded_components_round_trip(value in ".*") {
            let mut encoded = String::new();
            encode_component(&value, &mut encoded);
            prop_assert!(encoded.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._~%".contains(&b)));
            let decoded = reqwest::Url::parse(&format!("http://h/?k={encoded}")).unwrap();
            let pairs: Vec<(String, String)> = decoded.query_pairs().into_owned().collect();
            prop_assert_eq!(pairs, vec![("k".to_owned(), value)]);
        }
    }
}
