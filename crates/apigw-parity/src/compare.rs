//! Compares two observations, honoring the parts of them a case selects.

use std::fmt;

use serde_json::Value;

use crate::case::{BodyCompare, Compare, EchoCompare, EchoField};
use crate::echo::EchoReceived;
use crate::fixture::{Observation, Observed};

/// Keys whose values differ per request, masked before JSON bodies are compared.
const VOLATILE_JSON_KEYS: [&str; 8] = [
    "requestId",
    "extendedRequestId",
    "timeEpoch",
    "requestTimeEpoch",
    "time",
    "requestTime",
    "traceId",
    "x-amzn-trace-id",
];
const ABSENT: &str = "<absent>";

/// One difference between an expected and an actual observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Mismatch {
    field: String,
    expected: String,
    actual: String,
}

impl Mismatch {
    fn new(
        field: impl Into<String>,
        expected: impl fmt::Display,
        actual: impl fmt::Display,
    ) -> Self {
        Self {
            field: field.into(),
            expected: expected.to_string(),
            actual: actual.to_string(),
        }
    }
}

impl fmt::Display for Mismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: expected {}, got {}",
            self.field, self.expected, self.actual
        )
    }
}

/// A header value, or a marker for its absence, for display.
struct HeaderValue<'a>(Option<&'a String>);

impl fmt::Display for HeaderValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(value) => write!(f, "{value:?}"),
            None => f.write_str(ABSENT),
        }
    }
}

impl Compare {
    /// The differences between `expected` and `actual` in the parts this
    /// comparison selects. Empty means they match.
    pub(crate) fn diff(&self, expected: &Observation, actual: &Observation) -> Vec<Mismatch> {
        let mut mismatches = Vec::new();
        if self.status && expected.response.status != actual.response.status {
            mismatches.push(Mismatch::new(
                "response.status",
                expected.response.status,
                actual.response.status,
            ));
        }
        for name in &self.headers {
            let name = name.to_ascii_lowercase();
            let want = expected.response.headers.get(&name);
            let got = actual.response.headers.get(&name);
            if want != got {
                mismatches.push(Mismatch::new(
                    format!("response.headers.{name}"),
                    HeaderValue(want),
                    HeaderValue(got),
                ));
            }
        }
        self.diff_body(&expected.response, &actual.response, &mut mismatches);
        if let Some(ref echo) = self.echo {
            echo.diff(
                expected.echo.as_ref(),
                actual.echo.as_ref(),
                &mut mismatches,
            );
        }
        mismatches
    }

    fn diff_body(&self, expected: &Observed, actual: &Observed, mismatches: &mut Vec<Mismatch>) {
        let (want, got) = (expected.body_text(), actual.body_text());
        let equal = match self.body {
            BodyCompare::Ignore => return,
            BodyCompare::Exact => want == got,
            BodyCompare::Json => match (parse_masked(want), parse_masked(got)) {
                (Some(want), Some(got)) => want == got,
                (Some(_) | None, None) | (None, Some(_)) => want == got,
            },
        };
        if !equal {
            mismatches.push(Mismatch::new(
                "response.body",
                format!("{want:?}"),
                format!("{got:?}"),
            ));
        }
    }
}

impl EchoCompare {
    fn diff(
        &self,
        expected: Option<&EchoReceived>,
        actual: Option<&EchoReceived>,
        mismatches: &mut Vec<Mismatch>,
    ) {
        let (want, got) = match (expected, actual) {
            (Some(want), Some(got)) => (want, got),
            (None, Some(_)) => {
                mismatches.push(Mismatch::new("echo", "no recorded echo", "an echo"));
                return;
            }
            (Some(_), None) => {
                mismatches.push(Mismatch::new("echo", "an echo", "no echo"));
                return;
            }
            (None, None) => return,
        };
        if self.compares(EchoField::Method) && want.method != got.method {
            mismatches.push(Mismatch::new("echo.method", &want.method, &got.method));
        }
        if self.compares(EchoField::Path) && want.path != got.path {
            mismatches.push(Mismatch::new("echo.path", &want.path, &got.path));
        }
        if self.compares(EchoField::Query) && want.query != got.query {
            mismatches.push(Mismatch::new("echo.query", &want.query, &got.query));
        }
        if self.compares(EchoField::Resource) && want.resource != got.resource {
            mismatches.push(Mismatch::new(
                "echo.resource",
                format!("{:?}", want.resource),
                format!("{:?}", got.resource),
            ));
        }
        if self.compares(EchoField::PathParameters) && want.path_parameters != got.path_parameters {
            mismatches.push(Mismatch::new(
                "echo.path_parameters",
                format!("{:?}", want.path_parameters),
                format!("{:?}", got.path_parameters),
            ));
        }
        if self.compares(EchoField::Body) && want.body != got.body {
            mismatches.push(Mismatch::new(
                "echo.body",
                format!("{:?}", want.body),
                format!("{:?}", got.body),
            ));
        }
        for name in &self.headers {
            let name = name.to_ascii_lowercase();
            let (want, got) = (want.headers.get(&name), got.headers.get(&name));
            if want != got {
                mismatches.push(Mismatch::new(
                    format!("echo.headers.{name}"),
                    HeaderValue(want),
                    HeaderValue(got),
                ));
            }
        }
    }
}

fn parse_masked(text: &str) -> Option<Value> {
    let mut value: Value = serde_json::from_str(text).ok()?;
    mask_volatile(&mut value);
    Some(value)
}

fn mask_volatile(value: &mut Value) {
    match value {
        Value::Object(members) => {
            for (key, member) in members.iter_mut() {
                if VOLATILE_JSON_KEYS.contains(&key.as_str()) {
                    *member = Value::Null;
                } else {
                    mask_volatile(member);
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                mask_volatile(item);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    fn observation(status: u16, headers: &[(&str, &str)], body: &str) -> Observation {
        Observation {
            response: Observed {
                status,
                headers: headers
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                    .collect(),
                ..Observed::default()
            }
            .with_body(body.as_bytes()),
            echo: None,
        }
    }

    fn echo(path: &str, headers: &[(&str, &str)]) -> EchoReceived {
        EchoReceived {
            method: "GET".to_owned(),
            path: path.to_owned(),
            query: "a=1".to_owned(),
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect::<BTreeMap<_, _>>(),
            ..EchoReceived::default()
        }
    }

    #[test]
    fn identical_observations_match() {
        let a = observation(200, &[("content-type", "text/plain")], "x");
        assert!(Compare::default().diff(&a, &a.clone()).is_empty());
    }

    #[test]
    fn status_is_compared_unless_disabled() {
        let (a, b) = (observation(200, &[], "x"), observation(403, &[], "x"));
        let mismatches = Compare::default().diff(&a, &b);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(
            mismatches.first().unwrap().to_string(),
            "response.status: expected 200, got 403"
        );
        let lenient = Compare {
            status: false,
            ..Compare::default()
        };
        assert!(lenient.diff(&a, &b).is_empty());
    }

    #[test]
    fn only_selected_headers_are_compared_case_insensitively() {
        let a = observation(200, &[("x-a", "1"), ("x-b", "1")], "");
        let b = observation(200, &[("x-a", "2"), ("x-b", "2")], "");
        let compare = Compare {
            headers: vec!["X-A".to_owned(), "x-missing".to_owned()],
            ..Compare::default()
        };
        let mismatches = compare.diff(&a, &b);
        assert_eq!(mismatches.len(), 1);
        assert_eq!(
            mismatches.first().unwrap().to_string(),
            "response.headers.x-a: expected \"1\", got \"2\""
        );
        let absent = compare.diff(&a, &observation(200, &[], ""));
        assert!(
            absent
                .iter()
                .any(|m| m.to_string().ends_with("got <absent>"))
        );
    }

    #[test]
    fn json_bodies_ignore_key_order_whitespace_and_volatile_keys() {
        let compare = Compare {
            body: BodyCompare::Json,
            ..Compare::default()
        };
        let a = observation(
            200,
            &[],
            r#"{"a":1,"requestId":"r1","n":{"time":"t1","b":2}}"#,
        );
        let b = observation(
            200,
            &[],
            r#"{ "n": {"b":2, "time":"t2"}, "requestId":"r2", "a":1 }"#,
        );
        assert!(compare.diff(&a, &b).is_empty());
        let c = observation(200, &[], r#"{"a":2}"#);
        assert_eq!(compare.diff(&a, &c).len(), 1);
        let not_json = observation(200, &[], "plain");
        assert_eq!(
            compare
                .diff(&not_json, &observation(200, &[], "plain"))
                .len(),
            0
        );
        assert_eq!(compare.diff(&not_json, &a).len(), 1);
    }

    #[test]
    fn exact_bodies_and_ignored_bodies() {
        let (a, b) = (
            observation(200, &[], "{\"a\":1}"),
            observation(200, &[], "{ \"a\": 1 }"),
        );
        assert_eq!(Compare::default().diff(&a, &b).len(), 1);
        let ignore = Compare {
            body: BodyCompare::Ignore,
            ..Compare::default()
        };
        assert!(ignore.diff(&a, &b).is_empty());
    }

    #[test]
    fn resource_and_path_parameters_are_compared_when_selected() {
        let compare = Compare {
            echo: Some(EchoCompare {
                fields: vec![EchoField::Resource, EchoField::PathParameters],
                headers: Vec::new(),
            }),
            ..Compare::default()
        };
        let mut want = observation(200, &[], "");
        want.echo = Some(EchoReceived {
            resource: Some("/a/{p}".to_owned()),
            path_parameters: BTreeMap::from([("p".to_owned(), "1".to_owned())]),
            ..echo("/a/1", &[])
        });
        let mut got = want.clone();
        assert!(compare.diff(&want, &got).is_empty());
        if let Some(ref mut echoed) = got.echo {
            echoed.resource = None;
            echoed.path_parameters.clear();
        }
        let fields: Vec<String> = compare
            .diff(&want, &got)
            .iter()
            .map(|m| {
                m.to_string()
                    .split(':')
                    .next()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        assert_eq!(fields, ["echo.resource", "echo.path_parameters"]);
    }

    #[test]
    fn echo_fields_are_compared_selectively() {
        let compare = Compare {
            echo: Some(EchoCompare {
                headers: vec!["x-mapped".to_owned()],
                ..EchoCompare::default()
            }),
            ..Compare::default()
        };
        let mut want = observation(200, &[], "");
        want.echo = Some(echo("/a", &[("x-mapped", "1"), ("x-other", "1")]));
        let mut got = observation(200, &[], "");
        got.echo = Some(echo("/b", &[("x-mapped", "2"), ("x-other", "2")]));
        let fields: Vec<String> = compare
            .diff(&want, &got)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(
            fields,
            [
                "echo.path: expected /a, got /b",
                "echo.headers.x-mapped: expected \"1\", got \"2\"",
            ]
        );
        got.echo = None;
        assert_eq!(compare.diff(&want, &got).len(), 1);
        want.echo = None;
        assert!(compare.diff(&want, &got).is_empty());
    }
}
