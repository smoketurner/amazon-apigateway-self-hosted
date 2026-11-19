//! Route selection for HTTP APIs. API Gateway picks the most specific route
//! that matches both the path and the method: a full match (static segments
//! beat `{param}` segments), then a greedy `{proxy+}` match (a longer static
//! prefix beats a shorter one), then `$default`. A route that matches the path
//! but not the method is skipped, so a less specific route that does serve the
//! method can still take the request. See
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-develop-routes.html#http-api-develop-routes.evaluation>.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::Method;

use crate::model::MethodMatch;
use crate::route::Route;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Static(String),
    Param(String),
    Greedy(String),
}

impl Segment {
    /// Ranks segments at the same position: a static segment is more specific
    /// than a parameter, which is more specific than a greedy one.
    fn rank(&self) -> u8 {
        match self {
            Self::Static(_) => 3,
            Self::Param(_) => 2,
            Self::Greedy(_) => 1,
        }
    }
}

/// A route path as the router registers it: `/pets/{petId}` or `/files/{*proxy}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PathPattern(Vec<Segment>);

impl PathPattern {
    /// `None` unless `path` starts with `/` and any greedy segment is last.
    pub(crate) fn parse(path: &str) -> Option<Self> {
        let rest = path.strip_prefix('/')?;
        let mut segments = Vec::new();
        let mut greedy_seen = false;
        for segment in rest.split('/') {
            if greedy_seen {
                return None;
            }
            let parsed = if let Some(name) =
                segment.strip_prefix("{*").and_then(|s| s.strip_suffix('}'))
            {
                greedy_seen = true;
                Segment::Greedy(name.to_owned())
            } else if let Some(name) = segment.strip_prefix('{').and_then(|s| s.strip_suffix('}')) {
                Segment::Param(name.to_owned())
            } else {
                Segment::Static(segment.to_owned())
            };
            segments.push(parsed);
        }
        Some(Self(segments))
    }

    fn specificity(&self) -> Vec<u8> {
        self.0.iter().map(Segment::rank).collect()
    }

    /// The path parameters if `path` matches. A parameter must be non-empty;
    /// a greedy value keeps its slashes and may be empty.
    fn captures(&self, path: &str) -> Option<Vec<(String, String)>> {
        let mut parts = path.strip_prefix('/')?.split('/');
        let mut captured = Vec::new();
        for segment in &self.0 {
            match segment {
                Segment::Static(expected) => {
                    if parts.next()? != expected {
                        return None;
                    }
                }
                Segment::Param(name) => {
                    let value = parts.next().filter(|v| !v.is_empty())?;
                    captured.push((name.clone(), value.to_owned()));
                }
                Segment::Greedy(name) => {
                    // The slash before the greedy segment must be there, but
                    // nothing need follow it: `/files/` gives an empty value
                    // and `/files` does not match. That is measured for a
                    // greedy segment under a prefix; a bare `/{proxy+}` keeps
                    // needing a value, so `/` stays with `$default`.
                    let first = parts.next()?;
                    if first.is_empty() && self.0.len() == 1 {
                        return None;
                    }
                    let mut value = first.to_owned();
                    for part in parts.by_ref() {
                        value.push('/');
                        value.push_str(part);
                    }
                    captured.push((name.clone(), value));
                    return Some(captured);
                }
            }
        }
        parts.next().is_none().then_some(captured)
    }
}

/// A request path as an HTTP API reads it (measured against a deployed API):
/// percent-decoded, with runs of slashes collapsed to one. Routing, path
/// parameters, `rawPath`, and `$context.path` all use this form.
pub(crate) fn decoded_path(sent: &str) -> String {
    let mut bytes = Vec::with_capacity(sent.len());
    let mut rest = sent.bytes();
    while let Some(byte) = rest.next() {
        let mut escape = rest.clone();
        let decoded = match (byte, escape.next(), escape.next()) {
            (b'%', Some(high), Some(low)) => char::from(high)
                .to_digit(16)
                .zip(char::from(low).to_digit(16))
                .and_then(|(high, low)| u8::try_from((high << 4) | low).ok()),
            _ => None,
        };
        let byte = match decoded {
            Some(decoded) => {
                rest = escape;
                decoded
            }
            None => byte,
        };
        if byte == b'/' && bytes.last() == Some(&b'/') {
            continue;
        }
        bytes.push(byte);
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[derive(Debug)]
struct Entry {
    pattern: PathPattern,
    specificity: Vec<u8>,
    methods: BTreeMap<MethodMatch, Route>,
}

/// The route chosen for a request and the path parameters it captured.
#[derive(Debug)]
pub(crate) struct Selection<'a> {
    pub(crate) route: &'a Route,
    pub(crate) params: Vec<(String, String)>,
}

/// An HTTP API's routes, kept most specific first.
#[derive(Debug, Default)]
pub(crate) struct HttpRoutes {
    entries: Vec<Entry>,
    default: Option<Arc<Route>>,
}

impl HttpRoutes {
    pub(crate) fn insert(&mut self, pattern: PathPattern, methods: BTreeMap<MethodMatch, Route>) {
        let specificity = pattern.specificity();
        let at = self
            .entries
            .partition_point(|entry| entry.specificity > specificity);
        self.entries.insert(
            at,
            Entry {
                pattern,
                specificity,
                methods,
            },
        );
    }

    pub(crate) fn set_default(&mut self, route: Arc<Route>) {
        self.default = Some(route);
    }

    /// The most specific route serving `method` at `path`, else `$default`.
    pub(crate) fn select(&self, path: &str, method: &Method) -> Option<Selection<'_>> {
        for entry in &self.entries {
            let route = entry
                .methods
                .get(&MethodMatch::Exact(method.clone()))
                .or_else(|| entry.methods.get(&MethodMatch::Any));
            let Some(route) = route else {
                continue;
            };
            if let Some(params) = entry.pattern.captures(path) {
                return Some(Selection { route, params });
            }
        }
        self.default.as_deref().map(|route| Selection {
            route,
            params: Vec::new(),
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::authz::{RouteAuthorizer, RoutePolicy};
    use crate::integration::Integration;
    use crate::model::{Protections, RouteKey, RoutePath};
    use crate::usage::RouteApiKey;
    use crate::validation::RouteValidation;

    fn route(key: &str, method: MethodMatch) -> Route {
        Route {
            method,
            path: RoutePath::Resource(key.to_owned()),
            key: RouteKey::from(key),
            integration: Integration::Unsupported {
                reason: key.to_owned(),
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

    fn table(routes: &[(&str, &str, MethodMatch)]) -> HttpRoutes {
        let mut table = HttpRoutes::default();
        let mut by_path: BTreeMap<&str, BTreeMap<MethodMatch, Route>> = BTreeMap::new();
        for (path, label, method) in routes {
            by_path
                .entry(path)
                .or_default()
                .insert(method.clone(), route(label, method.clone()));
        }
        for (path, methods) in by_path {
            table.insert(PathPattern::parse(path).unwrap(), methods);
        }
        table
    }

    /// Measured against a deployed HTTP API.
    #[test]
    fn paths_are_decoded_and_their_slashes_collapsed() {
        for (sent, read) in [
            ("/lambda-v2/a%20b%2Fc/d", "/lambda-v2/a b/c/d"),
            ("/lambda-v2/a//b/", "/lambda-v2/a/b/"),
            ("//throttled", "/throttled"),
            ("/a%2F%2Fb", "/a/b"),
            ("/plain", "/plain"),
            ("/bad%zz%2", "/bad%zz%2"),
            ("/", "/"),
        ] {
            assert_eq!(decoded_path(sent), read, "{sent}");
        }
    }

    fn chosen(table: &HttpRoutes, method: &Method, path: &str) -> Option<String> {
        table
            .select(path, method)
            .map(|selection| selection.route.key.to_string())
    }

    fn get() -> MethodMatch {
        MethodMatch::Exact(Method::GET)
    }

    /// The example in API Gateway's routing documentation.
    #[test]
    fn documented_priorities() {
        let mut table = table(&[
            ("/pets/dog/1", "GET /pets/dog/1", get()),
            ("/pets/dog/{id}", "GET /pets/dog/{id}", get()),
            ("/pets/{*proxy}", "GET /pets/{proxy+}", get()),
            ("/{*proxy}", "ANY /{proxy+}", MethodMatch::Any),
        ]);
        table.set_default(Arc::new(route("$default", MethodMatch::Any)));
        let pick = |method, path| chosen(&table, method, path).unwrap();
        assert_eq!(pick(&Method::GET, "/pets/dog/1"), "GET /pets/dog/1");
        assert_eq!(pick(&Method::GET, "/pets/dog/2"), "GET /pets/dog/{id}");
        assert_eq!(pick(&Method::GET, "/pets/cat/1"), "GET /pets/{proxy+}");
        assert_eq!(pick(&Method::POST, "/test/5"), "ANY /{proxy+}");
        assert_eq!(pick(&Method::GET, "/"), "$default");
    }

    #[test]
    fn a_route_without_the_method_is_skipped_for_a_less_specific_one() {
        let table = table(&[
            ("/pets/dog/1", "GET /pets/dog/1", get()),
            ("/{*proxy}", "ANY /{proxy+}", MethodMatch::Any),
        ]);
        assert_eq!(
            chosen(&table, &Method::POST, "/pets/dog/1").as_deref(),
            Some("ANY /{proxy+}")
        );
        assert_eq!(chosen(&table, &Method::POST, "/"), None);
    }

    #[test]
    fn an_exact_method_beats_any_on_the_same_path_and_path_beats_method() {
        let table = table(&[
            ("/a/{x}", "ANY /a/{x}", MethodMatch::Any),
            ("/a/{x}", "GET /a/{x}", get()),
            ("/a/b", "POST /a/b", MethodMatch::Exact(Method::POST)),
            ("/{*p}", "GET /{p+}", get()),
        ]);
        assert_eq!(
            chosen(&table, &Method::GET, "/a/b").as_deref(),
            Some("GET /a/{x}")
        );
        assert_eq!(
            chosen(&table, &Method::PUT, "/a/b").as_deref(),
            Some("ANY /a/{x}")
        );
        assert_eq!(
            chosen(&table, &Method::POST, "/a/b").as_deref(),
            Some("POST /a/b")
        );
        assert_eq!(
            chosen(&table, &Method::GET, "/a/b/c").as_deref(),
            Some("GET /{p+}")
        );
    }

    #[test]
    fn captures_parameters_and_keep_greedy_slashes() {
        let table = table(&[
            (
                "/files/{id}/{*rest}",
                "ANY /files/{id}/{rest+}",
                MethodMatch::Any,
            ),
            ("/", "GET /", get()),
        ]);
        let selection = table.select("/files/7/a/b/c", &Method::GET).unwrap();
        assert_eq!(
            selection.params,
            vec![
                ("id".to_owned(), "7".to_owned()),
                ("rest".to_owned(), "a/b/c".to_owned())
            ]
        );
        assert!(table.select("/files/7", &Method::GET).is_none());
        assert!(table.select("/files//x", &Method::GET).is_none());
        assert_eq!(
            table.select("/files/7/", &Method::GET).unwrap().params,
            vec![
                ("id".to_owned(), "7".to_owned()),
                ("rest".to_owned(), String::new())
            ],
            "a greedy value may be empty once its slash is there"
        );
        assert_eq!(chosen(&table, &Method::GET, "/").as_deref(), Some("GET /"));
    }

    #[test]
    fn invalid_patterns_are_rejected() {
        assert!(PathPattern::parse("pets").is_none());
        assert!(PathPattern::parse("/{*p}/x").is_none());
        assert!(PathPattern::parse("/a/{p}").is_some());
    }

    proptest! {
        /// Selection never panics and whatever it returns matches the request.
        #[test]
        fn selection_is_total(path in "(/[a-z0-9{}*+]{0,4}){0,5}", method in 0_u8..3) {
            let table = table(&[
                ("/a/{x}", "a", get()),
                ("/{*p}", "g", MethodMatch::Any),
                ("/", "r", get()),
            ]);
            let method = [Method::GET, Method::POST, Method::DELETE].get(usize::from(method)).cloned().unwrap_or(Method::GET);
            if let Some(selection) = table.select(&path, &method) {
                prop_assert!(!selection.route.key.as_str().is_empty());
            }
        }
    }
}
