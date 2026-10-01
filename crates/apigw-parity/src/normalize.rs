//! Turns raw responses into fixtures: masks volatile values, aliases client IPs
//! consistently, drops headers the Lambda function URL adds, and redacts secrets
//! so nothing sensitive is ever written to a fixture.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::str::FromStr;

use serde_json::Value;

use crate::case::{BodyCompare, Case};
use crate::client::RawResponse;
use crate::echo::{EchoEvent, EchoReceived};
use crate::error::{ParityError, Result};
use crate::fixture::{Observation, Observed};

const MASKED: &str = "[masked]";
const REDACTED: &str = "[redacted]";
const ACCOUNT_ID: &str = "[account-id]";
const TOKEN: &str = "[token]";
const ACCOUNT_ID_DIGITS: usize = 12;
const MIN_SECRET_LEN: usize = 4;
const SENSITIVE_KEY_HINTS: [&str; 5] = ["secret", "password", "token", "apikey", "api_key"];

/// What to do with one header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeaderAction {
    Keep,
    /// Keep the header's presence but hide its value, because it differs per request.
    Mask,
    /// Remove it: it is added by infrastructure the comparison does not cover.
    Drop,
}

/// Which headers are volatile or infrastructure noise.
#[derive(Debug, Clone, Copy)]
struct HeaderPolicy;

impl HeaderPolicy {
    const RESPONSE_MASKED: [&'static str; 9] = [
        "x-amzn-requestid",
        "x-amz-apigw-id",
        "apigw-requestid",
        "x-amzn-trace-id",
        "date",
        "x-amz-cf-id",
        "x-amz-cf-pop",
        "x-cache",
        "via",
    ];
    const RESPONSE_DROPPED: [&'static str; 5] = [
        "connection",
        "content-length",
        "transfer-encoding",
        "keep-alive",
        "server",
    ];
    /// Headers a Lambda function URL (or the HTTP stack in front of it) adds to
    /// what the echo function sees; they say nothing about the gateway.
    const FUNCTION_URL_ADDED: [&'static str; 9] = [
        "host",
        "content-length",
        "connection",
        "transfer-encoding",
        "x-forwarded-for",
        "x-forwarded-port",
        "x-forwarded-proto",
        "via",
        "traceparent",
    ];

    fn response(name: &str) -> HeaderAction {
        if Self::RESPONSE_DROPPED.contains(&name) {
            HeaderAction::Drop
        } else if Self::RESPONSE_MASKED.contains(&name) {
            HeaderAction::Mask
        } else {
            HeaderAction::Keep
        }
    }

    fn echo(name: &str) -> HeaderAction {
        if Self::FUNCTION_URL_ADDED.contains(&name)
            || name.starts_with("x-amzn-")
            || name.starts_with("x-amz-")
        {
            HeaderAction::Drop
        } else {
            HeaderAction::Keep
        }
    }
}

/// Removes secrets, tokens, and account IDs from text and JSON.
#[derive(Debug, Clone, Default)]
pub(crate) struct Redactor {
    secrets: Vec<String>,
}

impl Redactor {
    /// A redactor that also removes every one of `secrets` (ignoring any shorter
    /// than [`MIN_SECRET_LEN`], which would mangle ordinary text).
    pub(crate) fn new(secrets: impl IntoIterator<Item = String>) -> Self {
        let mut secrets: Vec<String> = secrets
            .into_iter()
            .filter(|secret| secret.len() >= MIN_SECRET_LEN)
            .collect();
        secrets.sort_by_key(|secret| std::cmp::Reverse(secret.len()));
        secrets.dedup();
        Self { secrets }
    }

    pub(crate) fn redact(&self, text: &str) -> String {
        let mut text = text.to_owned();
        for secret in &self.secrets {
            text = text.replace(secret.as_str(), REDACTED);
        }
        Self::mask_account_ids(&Self::mask_tokens(&text))
    }

    /// Redacts every string in `value`, and the whole value of any object member
    /// whose key suggests a credential.
    pub(crate) fn redact_json(&self, value: &mut Value) {
        match value {
            Value::String(text) => *text = self.redact(text),
            Value::Array(items) => {
                for item in items {
                    self.redact_json(item);
                }
            }
            Value::Object(members) => {
                for (key, member) in members.iter_mut() {
                    if member.is_string() && Self::is_sensitive_key(key) {
                        *member = Value::String(REDACTED.to_owned());
                    } else {
                        self.redact_json(member);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    /// Redacts `value`, wholesale when `key` names a credential.
    pub(crate) fn redact_entry(&self, key: &str, value: &str) -> String {
        if Self::is_sensitive_key(key) {
            REDACTED.to_owned()
        } else {
            self.redact(value)
        }
    }

    fn is_sensitive_key(key: &str) -> bool {
        let lower = key.to_ascii_lowercase();
        SENSITIVE_KEY_HINTS.iter().any(|hint| lower.contains(hint))
    }

    /// Replaces JWT-shaped words (`eyJ...` with two dots) with a placeholder.
    fn mask_tokens(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut word = String::new();
        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.') {
                word.push(ch);
            } else {
                Self::flush_token_word(&mut word, &mut out);
                out.push(ch);
            }
        }
        Self::flush_token_word(&mut word, &mut out);
        out
    }

    fn flush_token_word(word: &mut String, out: &mut String) {
        let is_jwt = word.starts_with("eyJ") && word.matches('.').count() == 2;
        out.push_str(if is_jwt { TOKEN } else { word.as_str() });
        word.clear();
    }

    /// Replaces words that are exactly twelve digits (AWS account IDs).
    fn mask_account_ids(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        let mut run = String::new();
        for ch in text.chars() {
            if ch.is_ascii_alphanumeric() {
                run.push(ch);
            } else {
                Self::flush_account_run(&mut run, &mut out);
                out.push(ch);
            }
        }
        Self::flush_account_run(&mut run, &mut out);
        out
    }

    fn flush_account_run(run: &mut String, out: &mut String) {
        let is_account = run.len() == ACCOUNT_ID_DIGITS && run.bytes().all(|b| b.is_ascii_digit());
        out.push_str(if is_account { ACCOUNT_ID } else { run.as_str() });
        run.clear();
    }
}

/// Maps each distinct IP address in one case to a stable alias, so a fixture
/// recorded from one client address compares equal to a replay from another.
#[derive(Debug, Default)]
struct IpAliases {
    seen: Vec<IpAddr>,
}

impl IpAliases {
    fn alias_for(&mut self, ip: IpAddr) -> String {
        let index = if let Some(index) = self.seen.iter().position(|seen| *seen == ip) {
            index
        } else {
            self.seen.push(ip);
            self.seen.len().saturating_sub(1)
        };
        format!("<ip-{}>", index.saturating_add(1))
    }

    /// Replaces every IP-address word in `value`, leaving separators intact.
    fn alias_in(&mut self, value: &str) -> String {
        let mut out = String::with_capacity(value.len());
        let mut word = String::new();
        for ch in value.chars() {
            if ch.is_ascii_hexdigit() || ch == '.' || ch == ':' {
                word.push(ch);
            } else {
                self.flush(&mut word, &mut out);
                out.push(ch);
            }
        }
        self.flush(&mut word, &mut out);
        out
    }

    /// Writes `word` to `out`, aliasing it when it is an IP address, an
    /// `ip:port` pair, or either followed by sentence punctuation.
    fn flush(&mut self, word: &mut String, out: &mut String) {
        let core = word.trim_end_matches(['.', ':']);
        let punctuation = word.get(core.len()..).unwrap_or_default();
        let (address, port) = match core.split_once(':') {
            Some((host, port))
                if !port.contains(':') && port.bytes().all(|b| b.is_ascii_digit()) =>
            {
                (host, Some(port))
            }
            Some(_) | None => (core, None),
        };
        match IpAddr::from_str(address) {
            Ok(ip)
                if address.contains(['.', ':'])
                    && address.bytes().any(|b| b.is_ascii_hexdigit()) =>
            {
                out.push_str(&self.alias_for(ip));
                if let Some(port) = port {
                    out.push(':');
                    out.push_str(port);
                }
                out.push_str(punctuation);
            }
            Ok(_) | Err(_) => out.push_str(word),
        }
        word.clear();
    }
}

/// Normalizes raw responses into comparable observations.
#[derive(Debug, Clone, Default)]
pub(crate) struct Normalizer {
    redactor: Redactor,
}

impl Normalizer {
    pub(crate) fn new(redactor: Redactor) -> Self {
        Self { redactor }
    }

    /// Normalizes `raw`, the response to `case`.
    ///
    /// # Errors
    /// [`ParityError::NotAnEcho`] when the case compares what the echo received but
    /// the response body is not an echo event.
    pub(crate) fn observe(&self, case: &Case, raw: &RawResponse) -> Result<Observation> {
        let mut ips = IpAliases::default();
        let mut headers = BTreeMap::new();
        for (name, value) in &raw.headers {
            let value = match HeaderPolicy::response(name) {
                HeaderAction::Drop => continue,
                HeaderAction::Mask => MASKED.to_owned(),
                HeaderAction::Keep => ips.alias_in(&self.redactor.redact(value)),
            };
            headers
                .entry(name.clone())
                .and_modify(|joined: &mut String| {
                    joined.push_str(", ");
                    joined.push_str(&value);
                })
                .or_insert(value);
        }
        let mut response = Observed {
            status: raw.status,
            headers,
            ..Observed::default()
        };
        if case.compare.body != BodyCompare::Ignore {
            response = response.with_body(&self.redact_body(&raw.body));
        }
        let echo = if case.compare.echo.is_some() {
            Some(self.echo(case, raw, &mut ips)?)
        } else {
            None
        };
        Ok(Observation { response, echo })
    }

    fn redact_body(&self, body: &[u8]) -> Vec<u8> {
        match std::str::from_utf8(body) {
            Ok(text) => self.redactor.redact(text).into_bytes(),
            Err(_) => body.to_vec(),
        }
    }

    fn echo(&self, case: &Case, raw: &RawResponse, ips: &mut IpAliases) -> Result<EchoReceived> {
        let event = EchoEvent::parse(&raw.body).map_err(|e| ParityError::NotAnEcho {
            case: case.name.clone(),
            reason: e.to_string(),
        })?;
        let mut received = event.received();
        let mut headers = BTreeMap::new();
        for (name, value) in received.headers {
            if HeaderPolicy::echo(&name) == HeaderAction::Drop {
                continue;
            }
            headers.insert(name, ips.alias_in(&self.redactor.redact(&value)));
        }
        received.headers = headers;
        received.body = received.body.map(|body| self.redactor.redact(&body));
        received.query = self.redactor.redact(&received.query);
        Ok(received)
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(
    clippy::indexing_slicing,
    reason = "tests index fixtures of known shape"
)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::case::{Compare, EchoCompare};

    fn case(compare: Compare) -> Case {
        let mut case: Case = serde_saphyr::from_str("name: c\napi: rest\npath: /x\n").unwrap();
        case.compare = compare;
        case
    }

    fn raw(status: u16, headers: &[(&str, &str)], body: &str) -> RawResponse {
        RawResponse {
            status,
            headers: headers
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[test]
    fn volatile_headers_are_masked_and_noise_is_dropped() {
        let response = raw(
            200,
            &[
                ("x-amzn-requestid", "11111111-2222-3333-4444-555555555555"),
                ("date", "Tue, 01 Jan 2030 00:00:00 GMT"),
                ("content-length", "5"),
                ("connection", "keep-alive"),
                ("content-type", "application/json"),
                ("x-custom", "a"),
                ("x-custom", "b"),
            ],
            "hello",
        );
        let observed = Normalizer::default()
            .observe(&case(Compare::default()), &response)
            .unwrap();
        let headers = &observed.response.headers;
        assert_eq!(headers["x-amzn-requestid"], "[masked]");
        assert_eq!(headers["date"], "[masked]");
        assert_eq!(headers["content-type"], "application/json");
        assert_eq!(headers["x-custom"], "a, b");
        assert!(!headers.contains_key("content-length"));
        assert!(!headers.contains_key("connection"));
        assert_eq!(observed.response.body.as_deref(), Some("hello"));
    }

    #[test]
    fn ignored_bodies_are_not_stored() {
        let compare = Compare {
            body: BodyCompare::Ignore,
            ..Compare::default()
        };
        let observed = Normalizer::default()
            .observe(&case(compare), &raw(200, &[], "volatile"))
            .unwrap();
        assert_eq!(observed.response.body, None);
    }

    const ECHO_BODY: &str = r#"{"version":"2.0","rawPath":"/p","rawQueryString":"b=2&a=1",
        "headers":{"host":"x.lambda-url.us-east-1.on.aws","x-forwarded-for":"203.0.113.9","x-amzn-trace-id":"Root=1",
        "x-mapped":"from 203.0.113.9 via 203.0.113.10 and 203.0.113.9","x-secret-thing":"tok-3n"},
        "requestContext":{"http":{"method":"GET","path":"/p"}},"body":"payload tok-3n"}"#;

    fn echo_compare() -> Compare {
        Compare {
            echo: Some(EchoCompare::default()),
            ..Compare::default()
        }
    }

    #[test]
    fn echo_drops_function_url_headers_and_aliases_ips_consistently() {
        let normalizer = Normalizer::new(Redactor::new(["tok-3n".to_owned()]));
        let observed = normalizer
            .observe(&case(echo_compare()), &raw(200, &[], ECHO_BODY))
            .unwrap();
        let echo = observed.echo.unwrap();
        assert_eq!(echo.query, "a=1&b=2");
        assert_eq!(
            echo.headers.keys().map(String::as_str).collect::<Vec<_>>(),
            ["x-mapped", "x-secret-thing"]
        );
        assert_eq!(
            echo.headers["x-mapped"],
            "from <ip-1> via <ip-2> and <ip-1>"
        );
        assert_eq!(echo.headers["x-secret-thing"], "[redacted]");
        assert_eq!(echo.body.as_deref(), Some("payload [redacted]"));
    }

    #[test]
    fn echo_expectation_on_a_non_echo_body_is_an_error() {
        let result = Normalizer::default().observe(
            &case(echo_compare()),
            &raw(403, &[], r#"{"message":"Forbidden"}"#),
        );
        assert!(matches!(result, Err(ParityError::NotAnEcho { .. })));
    }

    #[test]
    fn redactor_removes_secrets_tokens_and_account_ids() {
        let redactor = Redactor::new(["abcd1234".to_owned(), "ab".to_owned()]);
        let jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln";
        let text = format!(
            "key=abcd1234 ab arn:aws:lambda:us-east-1:123456789012:function:f token {jwt} id=1234567890123 n=12345678901"
        );
        let redacted = redactor.redact(&text);
        assert_eq!(
            redacted,
            "key=[redacted] ab arn:aws:lambda:us-east-1:[account-id]:function:f token [token] id=1234567890123 n=12345678901"
        );
    }

    #[test]
    fn redact_json_covers_nested_strings_and_sensitive_keys() {
        let mut value = serde_json::json!({
            "arn": "arn:aws:iam::123456789012:role/r",
            "stage": {"echo_secret": "hunter2hunter2", "echo_host": "h.example"},
            "list": ["123456789012", 5, null],
        });
        Redactor::default().redact_json(&mut value);
        assert_eq!(value["arn"], "arn:aws:iam::[account-id]:role/r");
        assert_eq!(value["stage"]["echo_secret"], "[redacted]");
        assert_eq!(value["stage"]["echo_host"], "h.example");
        assert_eq!(value["list"][0], "[account-id]");
    }

    #[test]
    fn ip_aliases_handle_ipv6_ports_and_non_ips() {
        let mut ips = IpAliases::default();
        assert_eq!(
            ips.alias_in("2001:db8::1, 192.0.2.1:8080 v1.2.3 abcdef 10.0.0.1 2001:db8::1"),
            "<ip-1>, <ip-2>:8080 v1.2.3 abcdef <ip-3> <ip-1>"
        );
    }

    proptest! {
        #[test]
        fn a_secret_never_survives_redaction(
            secret in "[A-Za-z0-9]{4,24}",
            prefix in "[ -~]{0,20}",
            suffix in "[ -~]{0,20}",
        ) {
            let redactor = Redactor::new([secret.clone()]);
            let redacted = redactor.redact(&format!("{prefix}{secret}{suffix}"));
            prop_assert!(!redacted.contains(&secret) || "[redacted][account-id][token]".contains(&secret));
        }

        #[test]
        fn redaction_is_idempotent(text in "[ -~]{0,80}") {
            let redactor = Redactor::new(["secretvalue".to_owned()]);
            let once = redactor.redact(&text);
            prop_assert_eq!(redactor.redact(&once), once);
        }
    }
}
