//! How REST APIs rename, drop, and add headers between clients and integrations.
//!
//! The table is API Gateway's own, from "Amazon API Gateway important notes":
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html>.
//! It only applies to REST APIs; HTTP APIs have no such table and keep proxying
//! every header except the hop-by-hop ones.

use std::fmt;

use axum::http::{HeaderMap, HeaderName, HeaderValue, header};

use crate::gateway::HeaderNameExt as _;

/// The prefix of a remapped response header: `Date` becomes `X-Amzn-Remapped-Date`.
const REMAPPED_PREFIX: &str = "x-amzn-remapped-";

/// The three integration columns of API Gateway's header table, in the table's
/// order (`http`/`http_proxy`/`lambda`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flavor {
    Http,
    HttpProxy,
    Lambda,
}

impl Flavor {
    const fn column(self) -> usize {
        match self {
            Self::Http => 0,
            Self::HttpProxy => 1,
            Self::Lambda => 2,
        }
    }
}

/// What API Gateway does with one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeaderAction {
    Passthrough,
    Dropped,
    /// Sent under `X-Amzn-Remapped-{name}`.
    Remapped,
    /// Sent under `X-Amzn-Remapped-{name}`, and API Gateway supplies its own
    /// value under the original name.
    RemappedOverwritten,
    /// Replaced with the integration endpoint's own value (`Host`).
    Overwritten,
    /// The documentation lists an "Exception" without saying what happens;
    /// the header is passed through.
    Exception,
}

use HeaderAction::{Dropped, Exception, Overwritten, Passthrough, Remapped, RemappedOverwritten};

/// One row of the table: the action per integration column, for requests sent
/// to the integration and responses coming back.
struct HeaderRule {
    name: &'static str,
    request: [HeaderAction; 3],
    response: [HeaderAction; 3],
}

macro_rules! rule {
    ($name:literal, [$($request:expr),+], [$($response:expr),+]) => {
        HeaderRule {
            name: $name,
            request: [$($request),+],
            response: [$($response),+],
        }
    };
    ($name:literal, $request:expr, $response:expr) => {
        HeaderRule {
            name: $name,
            request: [$request; 3],
            response: [$response; 3],
        }
    };
}

/// API Gateway's table of headers that may be dropped, remapped, or modified,
/// verbatim.
const RULES: &[HeaderRule] = &[
    rule!("age", Passthrough, Passthrough),
    rule!(
        "accept",
        [Passthrough, Passthrough, Passthrough],
        [Dropped, Passthrough, Passthrough]
    ),
    rule!("accept-charset", Passthrough, Passthrough),
    rule!("accept-encoding", Passthrough, Passthrough),
    rule!("authorization", Passthrough, Remapped),
    rule!(
        "connection",
        [Passthrough, Passthrough, Dropped],
        [Remapped, Remapped, Remapped]
    ),
    rule!(
        "content-encoding",
        [Passthrough, Dropped, Passthrough],
        [Passthrough, Passthrough, Passthrough]
    ),
    rule!("content-length", Passthrough, Passthrough),
    rule!("content-md5", Dropped, Remapped),
    rule!("content-type", Passthrough, Passthrough),
    rule!("date", Passthrough, RemappedOverwritten),
    rule!("expect", Dropped, Dropped),
    rule!("host", Overwritten, Dropped),
    rule!("max-forwards", Dropped, Remapped),
    rule!("pragma", Passthrough, Passthrough),
    rule!("proxy-authenticate", Dropped, Dropped),
    rule!("range", Passthrough, Passthrough),
    rule!("referer", Passthrough, Passthrough),
    rule!("server", Dropped, RemappedOverwritten),
    rule!("te", Dropped, Dropped),
    rule!(
        "transfer-encoding",
        [Dropped, Dropped, Exception],
        [Dropped, Dropped, Dropped]
    ),
    rule!("trailer", Dropped, Dropped),
    rule!("upgrade", Dropped, Dropped),
    rule!("user-agent", Passthrough, Remapped),
    rule!(
        "via",
        [Dropped, Dropped, Passthrough],
        [Passthrough, Dropped, Dropped]
    ),
    rule!("warn", Passthrough, Passthrough),
    rule!("www-authenticate", Dropped, Remapped),
];

/// Whether the route authorizes with `AWS_IAM`, which makes API Gateway drop the
/// request's `Authorization` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IamAuthorization {
    Used,
    NotUsed,
}

impl Flavor {
    fn rule(name: &HeaderName) -> Option<&'static HeaderRule> {
        RULES.iter().find(|rule| rule.name == name.as_str())
    }

    /// What happens to `name` on its way to this integration.
    pub(crate) fn request_action(self, name: &HeaderName) -> HeaderAction {
        match Self::rule(name) {
            Some(rule) => rule
                .request
                .get(self.column())
                .copied()
                .unwrap_or(Passthrough),
            None if name.is_hop_by_hop() => Dropped,
            None => Passthrough,
        }
    }

    /// What happens to `name` on its way back from this integration.
    pub(crate) fn response_action(self, name: &HeaderName) -> HeaderAction {
        match Self::rule(name) {
            Some(rule) => rule
                .response
                .get(self.column())
                .copied()
                .unwrap_or(Passthrough),
            None if name.is_hop_by_hop() => Dropped,
            None => Passthrough,
        }
    }

    /// The client's headers as this integration receives them. `Authorization`
    /// is also dropped when it carries a Signature Version 4 signature or the
    /// route uses `AWS_IAM`.
    pub(crate) fn request_headers(self, client: &HeaderMap, iam: IamAuthorization) -> HeaderMap {
        let mut sent = HeaderMap::with_capacity(client.len());
        for (name, value) in client {
            let keep = match self.request_action(name) {
                Passthrough | Exception => true,
                Dropped | Remapped | RemappedOverwritten => false,
                Overwritten => self == Self::Lambda,
            };
            let signed = name == header::AUTHORIZATION
                && (iam == IamAuthorization::Used || Self::is_sigv4(value));
            if keep && !signed {
                sent.append(name.clone(), value.clone());
            }
        }
        sent
    }

    /// Applies the table to a response from this integration: dropped headers
    /// are removed and remapped ones renamed. API Gateway supplies its own
    /// `Date` once the original is renamed; hyper does the same.
    pub(crate) fn remap_response(self, headers: &mut HeaderMap) {
        let received = std::mem::take(headers);
        let mut previous: Option<HeaderName> = None;
        for (name, value) in received {
            let name = match name {
                Some(name) => {
                    previous = Some(name.clone());
                    name
                }
                None => match previous.clone() {
                    Some(name) => name,
                    None => continue,
                },
            };
            match self.response_action(&name) {
                Passthrough | Exception | Overwritten => {
                    headers.append(name, value);
                }
                Dropped => {}
                Remapped | RemappedOverwritten => {
                    if let Ok(remapped) = HeaderName::try_from(format!("{REMAPPED_PREFIX}{name}")) {
                        headers.append(remapped, value);
                    }
                }
            }
        }
    }

    fn is_sigv4(value: &HeaderValue) -> bool {
        value
            .as_bytes()
            .get(..16)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"AWS4-HMAC-SHA256"))
    }
}

/// The `Forwarded` header (RFC 7239) HTTP APIs send to `HTTP_PROXY` backends in
/// place of the client's `X-Forwarded-*` headers: "HTTP APIs translate incoming
/// `X-Forwarded-*` headers into a standard `Forwarded` header and will append the
/// egress IP, Host, and protocol." The egress address is not knowable outside
/// AWS, so no `by` parameter is added.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Forwarded {
    prior: Vec<String>,
    clients: Vec<String>,
    host: Option<String>,
}

impl Forwarded {
    /// Removes `Forwarded` and every `X-Forwarded-*` header from `headers`,
    /// keeping what they said.
    pub(crate) fn take_from(headers: &mut HeaderMap) -> Self {
        let values = |headers: &mut HeaderMap, name: &'static str| -> Vec<String> {
            headers
                .remove(name)
                .into_iter()
                .filter_map(|value| value.to_str().ok().map(str::to_owned))
                .collect()
        };
        let prior = values(headers, "forwarded");
        let clients = values(headers, "x-forwarded-for")
            .iter()
            .flat_map(|list| list.split(','))
            .map(|node| node.trim().to_owned())
            .filter(|node| !node.is_empty())
            .collect();
        let host = values(headers, "x-forwarded-host").into_iter().next();
        headers.remove("x-forwarded-proto");
        headers.remove("x-forwarded-port");
        Self {
            prior,
            clients,
            host,
        }
    }

    /// The translated header: earlier `Forwarded` elements, one `for=` element
    /// per client address, and a closing element naming the host and protocol.
    /// The gateway only serves TLS, so the protocol is `https`.
    pub(crate) fn render(&self, own_host: &str) -> Option<HeaderValue> {
        let mut elements = self.prior.clone();
        elements.extend(
            self.clients
                .iter()
                .map(|node| format!("for={}", Self::node(node))),
        );
        let host = self.host.as_deref().unwrap_or(own_host);
        let closing = if host.is_empty() {
            "proto=https".to_owned()
        } else {
            format!("host={};proto=https", Self::quote_if_needed(host))
        };
        if self.clients.is_empty() {
            elements.push(closing);
        } else if let Some(last) = elements.last_mut() {
            last.push(';');
            last.push_str(&closing);
        }
        HeaderValue::try_from(elements.join(", ")).ok()
    }

    /// A node identifier: IPv6 addresses are bracketed and quoted, ports and
    /// obfuscated identifiers quoted as RFC 7239 requires.
    fn node(node: &str) -> String {
        if node.contains(':')
            && !node.starts_with('[')
            && node.parse::<std::net::Ipv6Addr>().is_ok()
        {
            format!("\"[{node}]\"")
        } else {
            Self::quote_if_needed(node)
        }
    }

    fn quote_if_needed(value: &str) -> String {
        let token = value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
        if token {
            value.to_owned()
        } else {
            format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
        }
    }
}

impl fmt::Display for Flavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::HttpProxy => "http_proxy",
            Self::Lambda => "lambda",
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known fixtures")]
#[expect(clippy::panic, reason = "tests fail loudly on unexpected cells")]
mod tests {
    use super::*;

    /// The documentation's table, one line per header: request columns, then
    /// response columns, in `http`/`http_proxy`/`lambda` order. Each cell is
    /// P(assthrough), D(ropped), R(emapped), O(verwritten host), X(exception),
    /// or W (remapped and overwritten).
    const DOCUMENTED: &str = "\
age PPP PPP
accept PPP DPP
accept-charset PPP PPP
accept-encoding PPP PPP
authorization PPP RRR
connection PPD RRR
content-encoding PDP PPP
content-length PPP PPP
content-md5 DDD RRR
content-type PPP PPP
date PPP WWW
expect DDD DDD
host OOO DDD
max-forwards DDD RRR
pragma PPP PPP
proxy-authenticate DDD DDD
range PPP PPP
referer PPP PPP
server DDD WWW
te DDD DDD
transfer-encoding DDX DDD
trailer DDD DDD
upgrade DDD DDD
user-agent PPP RRR
via DDP PDD
warn PPP PPP
www-authenticate DDD RRR";

    fn action(cell: char) -> HeaderAction {
        match cell {
            'P' => Passthrough,
            'D' => Dropped,
            'R' => Remapped,
            'W' => RemappedOverwritten,
            'O' => Overwritten,
            'X' => Exception,
            other => panic!("unknown cell {other}"),
        }
    }

    #[test]
    fn every_documented_header_matches_the_table() {
        let mut seen = 0;
        for line in DOCUMENTED.lines() {
            let mut cells = line.split(' ');
            let name = HeaderName::try_from(cells.next().unwrap()).unwrap();
            let request: Vec<_> = cells.next().unwrap().chars().map(action).collect();
            let response: Vec<_> = cells.next().unwrap().chars().map(action).collect();
            for (index, flavor) in [Flavor::Http, Flavor::HttpProxy, Flavor::Lambda]
                .into_iter()
                .enumerate()
            {
                assert_eq!(
                    flavor.request_action(&name),
                    request[index],
                    "request {name} {flavor}"
                );
                assert_eq!(
                    flavor.response_action(&name),
                    response[index],
                    "response {name} {flavor}"
                );
            }
            seen += 1;
        }
        assert_eq!(
            seen,
            RULES.len(),
            "every rule is covered by the documented table"
        );
    }

    #[test]
    fn undocumented_hop_by_hop_headers_are_dropped_and_others_pass() {
        for flavor in [Flavor::Http, Flavor::HttpProxy, Flavor::Lambda] {
            let keep_alive = HeaderName::from_static("keep-alive");
            let custom = HeaderName::from_static("x-custom");
            assert_eq!(flavor.request_action(&keep_alive), Dropped);
            assert_eq!(flavor.response_action(&keep_alive), Dropped);
            assert_eq!(flavor.request_action(&custom), Passthrough);
            assert_eq!(flavor.response_action(&custom), Passthrough);
        }
    }

    fn map(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            );
        }
        headers
    }

    #[test]
    fn http_proxy_requests_lose_dropped_headers_and_keep_the_rest() {
        let client = map(&[
            ("accept", "*/*"),
            ("content-md5", "x"),
            ("expect", "100-continue"),
            ("host", "api.example.com"),
            ("max-forwards", "3"),
            ("te", "trailers"),
            ("user-agent", "curl"),
            ("via", "1.1 proxy"),
            ("content-encoding", "gzip"),
            ("x-custom", "1"),
            ("x-custom", "2"),
        ]);
        let sent = Flavor::HttpProxy.request_headers(&client, IamAuthorization::NotUsed);
        let mut names: Vec<&str> = sent.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        assert_eq!(names, ["accept", "user-agent", "x-custom"]);
        assert_eq!(sent.get_all("x-custom").iter().count(), 2);

        let lambda = Flavor::Lambda.request_headers(&client, IamAuthorization::NotUsed);
        assert!(
            lambda.contains_key("host"),
            "Lambda events carry the client's Host"
        );
        assert!(lambda.contains_key("via"));
        assert!(lambda.contains_key("content-encoding"));
        assert!(!lambda.contains_key("expect"));
    }

    #[test]
    fn authorization_is_dropped_for_sigv4_and_iam_only() {
        let signed = map(&[(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIA/20250101/us-east-1/execute-api/aws4_request",
        )]);
        let bearer = map(&[("authorization", "Bearer abc")]);
        let flavor = Flavor::HttpProxy;
        assert!(
            flavor
                .request_headers(&signed, IamAuthorization::NotUsed)
                .is_empty()
        );
        assert!(
            flavor
                .request_headers(&bearer, IamAuthorization::Used)
                .is_empty()
        );
        assert!(
            flavor
                .request_headers(&bearer, IamAuthorization::NotUsed)
                .contains_key("authorization")
        );
        let lowercase_scheme = map(&[("authorization", "aws4-hmac-sha256 Credential=x")]);
        assert!(
            flavor
                .request_headers(&lowercase_scheme, IamAuthorization::NotUsed)
                .is_empty()
        );
    }

    #[test]
    fn x_forwarded_headers_become_one_forwarded_header() {
        let mut headers = map(&[
            ("x-forwarded-for", "203.0.113.7, 198.51.100.2"),
            ("x-forwarded-proto", "http"),
            ("x-forwarded-port", "8080"),
            ("x-forwarded-host", "public.example.com"),
            ("x-keep", "1"),
        ]);
        let forwarded = Forwarded::take_from(&mut headers);
        assert_eq!(headers.len(), 1, "every X-Forwarded-* header is removed");
        assert_eq!(
            forwarded.render("api.example.com").unwrap(),
            "for=203.0.113.7, for=198.51.100.2;host=public.example.com;proto=https"
        );

        let mut headers = map(&[("x-forwarded-for", "2001:db8::1")]);
        assert_eq!(
            Forwarded::take_from(&mut headers)
                .render("api.example.com:8443")
                .unwrap(),
            "for=\"[2001:db8::1]\";host=\"api.example.com:8443\";proto=https"
        );

        let mut headers = HeaderMap::new();
        assert_eq!(
            Forwarded::take_from(&mut headers).render("").unwrap(),
            "proto=https"
        );

        let mut headers = map(&[
            ("forwarded", "for=192.0.2.60;proto=http"),
            ("x-forwarded-for", "203.0.113.7"),
        ]);
        assert_eq!(
            Forwarded::take_from(&mut headers).render("h").unwrap(),
            "for=192.0.2.60;proto=http, for=203.0.113.7;host=h;proto=https"
        );
    }

    #[test]
    fn responses_are_remapped_and_dropped_by_flavor() {
        let upstream = map(&[
            ("authorization", "a"),
            ("connection", "close"),
            ("content-md5", "m"),
            ("date", "Tue, 01 Oct 2026 00:00:00 GMT"),
            ("max-forwards", "1"),
            ("server", "nginx"),
            ("user-agent", "u"),
            ("www-authenticate", "Basic"),
            ("via", "1.1 x"),
            ("accept", "text/plain"),
            ("x-custom", "1"),
            ("x-custom", "2"),
            ("content-type", "text/plain"),
        ]);
        let mut proxied = upstream.clone();
        Flavor::HttpProxy.remap_response(&mut proxied);
        let mut names: Vec<&str> = proxied.keys().map(HeaderName::as_str).collect();
        names.sort_unstable();
        assert_eq!(
            names,
            [
                "accept",
                "content-type",
                "x-amzn-remapped-authorization",
                "x-amzn-remapped-connection",
                "x-amzn-remapped-content-md5",
                "x-amzn-remapped-date",
                "x-amzn-remapped-max-forwards",
                "x-amzn-remapped-server",
                "x-amzn-remapped-user-agent",
                "x-amzn-remapped-www-authenticate",
                "x-custom",
            ]
        );
        assert_eq!(proxied.get_all("x-custom").iter().count(), 2);
        assert!(
            !proxied.contains_key("date"),
            "the original Date is replaced"
        );
        assert_eq!(
            proxied["x-amzn-remapped-date"],
            "Tue, 01 Oct 2026 00:00:00 GMT"
        );

        let mut http = upstream;
        Flavor::Http.remap_response(&mut http);
        assert!(
            !http.contains_key("accept"),
            "http integrations drop Accept"
        );
        assert!(http.contains_key("via"));
    }
}
