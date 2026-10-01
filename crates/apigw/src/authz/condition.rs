//! The `Condition` element of a policy statement.
//!
//! Only conditions this gateway can decide are evaluated: `aws:SourceIp`
//! against `IpAddress` and `NotIpAddress`, the string operators on
//! `aws:UserAgent` and `aws:Referer`, `aws:SecureTransport`, and the date
//! operators on `aws:CurrentTime` and `aws:EpochTime`. Anything else (other
//! keys such as `aws:SourceVpce`, other operators, set qualifiers, policy
//! variables, an unreadable value, or a client address that could not be
//! established) is [`Truth::Unknown`], which a statement turns into "applies"
//! for a `Deny` and "does not apply" for an `Allow`.

use std::net::IpAddr;

use ipnet::IpNet;
use jiff::Timestamp;
use serde_json::Value;

use super::glob::{CaseSensitivity, Glob};
use crate::identity::SourceIp;
use crate::pipeline::RequestContext;

/// What a condition says about a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Truth {
    True,
    False,
    /// This gateway cannot tell.
    Unknown,
}

impl Truth {
    /// Every condition of a statement must hold: a false one decides, an
    /// unknown one taints the rest.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::False, _) | (_, Self::False) => Self::False,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::True, Self::True) => Self::True,
        }
    }

    fn from_bool(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }

    fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Whether any of `candidates` holds, over values that may be unknown.
    fn any(candidates: impl IntoIterator<Item = Self>) -> Self {
        let mut result = Self::False;
        for candidate in candidates {
            match candidate {
                Self::True => return Self::True,
                Self::Unknown => result = Self::Unknown,
                Self::False => {}
            }
        }
        result
    }
}

/// What the conditions of a request are decided from.
#[derive(Debug, Clone)]
pub(crate) struct RequestAttributes {
    source_ip: SourceIp,
    user_agent: Option<String>,
    referer: Option<String>,
    now: Timestamp,
}

impl RequestAttributes {
    pub(crate) fn of(ctx: &RequestContext) -> Self {
        Self {
            source_ip: ctx.identity.source_ip(),
            user_agent: ctx.header_str("user-agent").map(str::to_owned),
            referer: ctx.header_str("referer").map(str::to_owned),
            now: ctx.received,
        }
    }
}

/// A condition key's value for one request.
enum KeyValue {
    /// The key has no value in this request.
    Absent,
    /// This gateway cannot establish the value.
    Unknowable,
    Text(String),
    Address(IpAddr),
    Time(Timestamp),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Key {
    SourceIp,
    UserAgent,
    Referer,
    SecureTransport,
    CurrentTime,
    EpochTime,
    Other,
}

impl Key {
    fn parse(name: &str) -> Self {
        match name.to_ascii_lowercase().as_str() {
            "aws:sourceip" => Self::SourceIp,
            "aws:useragent" => Self::UserAgent,
            "aws:referer" => Self::Referer,
            "aws:securetransport" => Self::SecureTransport,
            "aws:currenttime" => Self::CurrentTime,
            "aws:epochtime" => Self::EpochTime,
            _ => Self::Other,
        }
    }

    fn value(self, attributes: &RequestAttributes) -> KeyValue {
        match self {
            Self::SourceIp => match attributes.source_ip {
                SourceIp::Known(ip) => KeyValue::Address(ip),
                SourceIp::Unknown => KeyValue::Unknowable,
            },
            Self::UserAgent => attributes
                .user_agent
                .clone()
                .map_or(KeyValue::Absent, KeyValue::Text),
            Self::Referer => attributes
                .referer
                .clone()
                .map_or(KeyValue::Absent, KeyValue::Text),
            // Every listener terminates TLS.
            Self::SecureTransport => KeyValue::Text("true".to_owned()),
            Self::CurrentTime | Self::EpochTime => KeyValue::Time(attributes.now),
            Self::Other => KeyValue::Unknowable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Comparison {
    StringEquals,
    StringEqualsIgnoreCase,
    StringLike,
    IpAddress,
    Bool,
    DateEquals,
    DateLessThan,
    DateLessThanEquals,
    DateGreaterThan,
    DateGreaterThanEquals,
}

/// A condition operator: a comparison, whether its result is negated, and
/// whether a missing key satisfies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Operator {
    comparison: Comparison,
    negated: bool,
    if_exists: bool,
}

impl Operator {
    /// `None` for operators this gateway does not evaluate, including any with
    /// a `ForAnyValue:` or `ForAllValues:` qualifier.
    fn parse(name: &str) -> Option<Self> {
        let lower = name.to_ascii_lowercase();
        let (lower, if_exists) = match lower.strip_suffix("ifexists") {
            Some(base) => (base.to_owned(), true),
            None => (lower, false),
        };
        let (comparison, negated) = match lower.as_str() {
            "stringequals" => (Comparison::StringEquals, false),
            "stringnotequals" => (Comparison::StringEquals, true),
            "stringequalsignorecase" => (Comparison::StringEqualsIgnoreCase, false),
            "stringnotequalsignorecase" => (Comparison::StringEqualsIgnoreCase, true),
            "stringlike" => (Comparison::StringLike, false),
            "stringnotlike" => (Comparison::StringLike, true),
            "ipaddress" => (Comparison::IpAddress, false),
            "notipaddress" => (Comparison::IpAddress, true),
            "bool" => (Comparison::Bool, false),
            "dateequals" => (Comparison::DateEquals, false),
            "datenotequals" => (Comparison::DateEquals, true),
            "datelessthan" => (Comparison::DateLessThan, false),
            "datelessthanequals" => (Comparison::DateLessThanEquals, false),
            "dategreaterthan" => (Comparison::DateGreaterThan, false),
            "dategreaterthanequals" => (Comparison::DateGreaterThanEquals, false),
            _ => return None,
        };
        Some(Self {
            comparison,
            negated,
            if_exists,
        })
    }
}

/// One `Operator: { key: values }` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Clause {
    /// `None` when the operator is not one this gateway evaluates.
    operator: Option<Operator>,
    key: Key,
    values: Vec<String>,
}

impl Clause {
    fn matches_value(comparison: Comparison, policy_value: &str, actual: &KeyValue) -> Truth {
        if policy_value.contains("${") {
            return Truth::Unknown;
        }
        match (comparison, actual) {
            (Comparison::StringEquals, KeyValue::Text(text)) => {
                Truth::from_bool(policy_value == text)
            }
            // Booleans compare as the text `true` or `false`, in any case.
            (Comparison::StringEqualsIgnoreCase | Comparison::Bool, KeyValue::Text(text)) => {
                Truth::from_bool(policy_value.eq_ignore_ascii_case(text))
            }
            (Comparison::StringLike, KeyValue::Text(text)) => {
                Truth::from_bool(Glob::new(policy_value, CaseSensitivity::Sensitive).matches(text))
            }
            (Comparison::IpAddress, KeyValue::Address(ip)) => Self::ip_in(policy_value, *ip),
            (
                Comparison::DateEquals
                | Comparison::DateLessThan
                | Comparison::DateLessThanEquals
                | Comparison::DateGreaterThan
                | Comparison::DateGreaterThanEquals,
                KeyValue::Time(now),
            ) => Self::date_compare(comparison, policy_value, *now),
            _ => Truth::Unknown,
        }
    }

    fn ip_in(policy_value: &str, ip: IpAddr) -> Truth {
        let network = policy_value
            .parse::<IpNet>()
            .or_else(|_| policy_value.parse::<IpAddr>().map(IpNet::from));
        match network {
            Ok(network) => Truth::from_bool(network.contains(&ip)),
            Err(_) => Truth::Unknown,
        }
    }

    /// A policy date is an RFC 3339 timestamp or seconds since the epoch.
    fn date_compare(comparison: Comparison, policy_value: &str, now: Timestamp) -> Truth {
        let parsed = policy_value.parse::<Timestamp>().ok().or_else(|| {
            policy_value
                .parse::<i64>()
                .ok()
                .and_then(|s| Timestamp::from_second(s).ok())
        });
        let Some(policy) = parsed else {
            return Truth::Unknown;
        };
        Truth::from_bool(match comparison {
            Comparison::DateEquals => now == policy,
            Comparison::DateLessThan => now < policy,
            Comparison::DateLessThanEquals => now <= policy,
            Comparison::DateGreaterThan => now > policy,
            Comparison::DateGreaterThanEquals => now >= policy,
            Comparison::StringEquals
            | Comparison::StringEqualsIgnoreCase
            | Comparison::StringLike
            | Comparison::IpAddress
            | Comparison::Bool => return Truth::Unknown,
        })
    }

    fn evaluate(&self, attributes: &RequestAttributes) -> Truth {
        let Some(operator) = self.operator else {
            return Truth::Unknown;
        };
        let actual = self.key.value(attributes);
        match actual {
            KeyValue::Unknowable => return Truth::Unknown,
            KeyValue::Absent => {
                // A missing key fails an operator, unless the operator is
                // negated or tolerates missing keys.
                return Truth::from_bool(operator.negated || operator.if_exists);
            }
            KeyValue::Text(_) | KeyValue::Address(_) | KeyValue::Time(_) => {}
        }
        let matched = Truth::any(
            self.values
                .iter()
                .map(|value| Self::matches_value(operator.comparison, value, &actual)),
        );
        if operator.negated {
            matched.negate()
        } else {
            matched
        }
    }
}

/// A statement's `Condition` block: every clause must hold.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Conditions(Vec<Clause>);

impl Conditions {
    /// Reads a `Condition` block. A block that is not an object, or a clause
    /// that is not understood, is kept as a clause that cannot be decided
    /// rather than dropped, so it is never silently true.
    pub(crate) fn parse(block: &Value) -> Self {
        let Value::Object(operators) = block else {
            return Self(vec![Self::undecidable()]);
        };
        let mut clauses = Vec::new();
        for (name, keys) in operators {
            let operator = Operator::parse(name);
            let Value::Object(keys) = keys else {
                clauses.push(Self::undecidable());
                continue;
            };
            for (key, values) in keys {
                clauses.push(Clause {
                    operator,
                    key: Key::parse(key),
                    values: Self::values(values),
                });
            }
        }
        Self(clauses)
    }

    fn undecidable() -> Clause {
        Clause {
            operator: None,
            key: Key::Other,
            values: Vec::new(),
        }
    }

    fn values(value: &Value) -> Vec<String> {
        match value {
            Value::Array(items) => items.iter().filter_map(Self::scalar).collect(),
            other => Self::scalar(other).into_iter().collect(),
        }
    }

    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(_) | Value::Bool(_) => Some(value.to_string()),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Whether the conditions hold for a request.
    pub(crate) fn evaluate(&self, attributes: &RequestAttributes) -> Truth {
        self.0.iter().fold(Truth::True, |truth, clause| {
            truth.and(clause.evaluate(attributes))
        })
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use serde_json::json;

    use super::*;

    fn attributes(ip: SourceIp) -> RequestAttributes {
        RequestAttributes {
            source_ip: ip,
            user_agent: Some("curl/8.0".to_owned()),
            referer: None,
            now: "2024-06-01T12:00:00Z".parse().unwrap(),
        }
    }

    fn known(ip: &str) -> RequestAttributes {
        attributes(SourceIp::Known(ip.parse().unwrap()))
    }

    fn eval(condition: &Value, attributes: &RequestAttributes) -> Truth {
        Conditions::parse(condition).evaluate(attributes)
    }

    #[test]
    fn ip_address_matches_cidrs_and_single_addresses() {
        let condition = json!({"IpAddress": {"aws:SourceIp": ["192.0.2.0/24", "198.51.100.7", "2001:db8::/32"]}});
        for (ip, expected) in [
            ("192.0.2.1", Truth::True),
            ("192.0.2.255", Truth::True),
            ("192.0.3.1", Truth::False),
            ("198.51.100.7", Truth::True),
            ("198.51.100.8", Truth::False),
            ("2001:db8::1", Truth::True),
            ("2001:db9::1", Truth::False),
        ] {
            assert_eq!(eval(&condition, &known(ip)), expected, "{ip}");
        }
    }

    #[test]
    fn not_ip_address_is_true_when_no_value_matches() {
        let condition =
            json!({"NotIpAddress": {"aws:SourceIp": ["192.0.2.0/24", "198.51.100.0/24"]}});
        assert_eq!(eval(&condition, &known("203.0.113.9")), Truth::True);
        assert_eq!(eval(&condition, &known("192.0.2.9")), Truth::False);
        assert_eq!(eval(&condition, &known("198.51.100.9")), Truth::False);
    }

    #[test]
    fn an_address_that_could_not_be_established_is_unknown_even_when_negated() {
        let unknown = attributes(SourceIp::Unknown);
        for operator in ["IpAddress", "NotIpAddress"] {
            let condition = json!({operator: {"aws:SourceIp": "192.0.2.0/24"}});
            assert_eq!(eval(&condition, &unknown), Truth::Unknown, "{operator}");
        }
    }

    #[test]
    fn unreadable_policy_addresses_are_unknown_unless_another_value_decides() {
        let junk = json!({"IpAddress": {"aws:SourceIp": ["not-an-ip"]}});
        assert_eq!(eval(&junk, &known("192.0.2.1")), Truth::Unknown);
        let negated_junk = json!({"NotIpAddress": {"aws:SourceIp": ["not-an-ip"]}});
        assert_eq!(eval(&negated_junk, &known("192.0.2.1")), Truth::Unknown);
        let mixed = json!({"IpAddress": {"aws:SourceIp": ["not-an-ip", "192.0.2.0/24"]}});
        assert_eq!(eval(&mixed, &known("192.0.2.1")), Truth::True);
        assert_eq!(eval(&mixed, &known("10.0.0.1")), Truth::Unknown);
    }

    #[test]
    fn ipv4_never_matches_an_ipv6_network() {
        let condition = json!({"IpAddress": {"aws:SourceIp": "2001:db8::/32"}});
        assert_eq!(eval(&condition, &known("192.0.2.1")), Truth::False);
    }

    #[test]
    fn every_clause_must_hold() {
        let condition = json!({
            "IpAddress": {"aws:SourceIp": "192.0.2.0/24"},
            "StringEquals": {"aws:UserAgent": "curl/8.0"},
        });
        assert_eq!(eval(&condition, &known("192.0.2.1")), Truth::True);
        assert_eq!(eval(&condition, &known("10.0.0.1")), Truth::False);
        let one_unknown = json!({
            "IpAddress": {"aws:SourceIp": "192.0.2.0/24"},
            "StringEquals": {"aws:SourceVpce": "vpce-1"},
        });
        assert_eq!(eval(&one_unknown, &known("192.0.2.1")), Truth::Unknown);
        assert_eq!(
            eval(&one_unknown, &known("10.0.0.1")),
            Truth::False,
            "a false clause decides"
        );
    }

    #[test]
    fn string_operators_follow_iam() {
        let case = |operator: &str, value: &str| {
            eval(
                &json!({operator: {"aws:UserAgent": value}}),
                &known("192.0.2.1"),
            )
        };
        assert_eq!(case("StringEquals", "curl/8.0"), Truth::True);
        assert_eq!(case("StringEquals", "CURL/8.0"), Truth::False);
        assert_eq!(case("StringEqualsIgnoreCase", "CURL/8.0"), Truth::True);
        assert_eq!(case("StringNotEquals", "other"), Truth::True);
        assert_eq!(case("StringNotEquals", "curl/8.0"), Truth::False);
        assert_eq!(case("StringLike", "curl/*"), Truth::True);
        assert_eq!(case("StringLike", "CURL/*"), Truth::False);
        assert_eq!(case("StringNotLike", "wget/*"), Truth::True);
        assert_eq!(case("StringNotLike", "curl/*"), Truth::False);
        assert_eq!(case("StringLike", "curl/8.?"), Truth::True);
    }

    #[test]
    fn a_missing_key_fails_positive_operators_and_satisfies_negated_ones() {
        let no_referer = |operator: &str| {
            eval(
                &json!({operator: {"aws:Referer": "https://a.example/*"}}),
                &known("192.0.2.1"),
            )
        };
        assert_eq!(no_referer("StringLike"), Truth::False);
        assert_eq!(no_referer("StringNotLike"), Truth::True);
        assert_eq!(no_referer("StringEquals"), Truth::False);
        assert_eq!(no_referer("StringLikeIfExists"), Truth::True);
        assert_eq!(no_referer("StringEqualsIfExists"), Truth::True);
    }

    #[test]
    fn tls_is_always_in_use() {
        let secure = |value: &str| {
            eval(
                &json!({"Bool": {"aws:SecureTransport": value}}),
                &known("192.0.2.1"),
            )
        };
        assert_eq!(secure("true"), Truth::True);
        assert_eq!(secure("false"), Truth::False);
    }

    #[test]
    fn dates_compare_against_the_time_of_the_request() {
        let at = |operator: &str, value: &str| {
            eval(
                &json!({operator: {"aws:CurrentTime": value}}),
                &known("192.0.2.1"),
            )
        };
        assert_eq!(at("DateLessThan", "2024-06-01T12:00:01Z"), Truth::True);
        assert_eq!(at("DateLessThan", "2024-06-01T12:00:00Z"), Truth::False);
        assert_eq!(
            at("DateLessThanEquals", "2024-06-01T12:00:00Z"),
            Truth::True
        );
        assert_eq!(at("DateGreaterThan", "2024-06-01T11:59:59Z"), Truth::True);
        assert_eq!(at("DateGreaterThan", "2024-06-01T12:00:00Z"), Truth::False);
        assert_eq!(
            at("DateGreaterThanEquals", "2024-06-01T12:00:00Z"),
            Truth::True
        );
        assert_eq!(at("DateEquals", "2024-06-01T12:00:00Z"), Truth::True);
        assert_eq!(at("DateNotEquals", "2024-06-01T12:00:00Z"), Truth::False);
        assert_eq!(
            at("DateGreaterThan", "1717243199"),
            Truth::True,
            "epoch seconds"
        );
        assert_eq!(at("DateGreaterThan", "yesterday"), Truth::Unknown);
        let epoch = eval(
            &json!({"DateLessThan": {"aws:EpochTime": "2024-06-02T00:00:00Z"}}),
            &known("192.0.2.1"),
        );
        assert_eq!(epoch, Truth::True);
    }

    #[test]
    fn anything_else_is_unknown() {
        let attributes = known("192.0.2.1");
        for condition in [
            json!({"StringEquals": {"aws:SourceVpce": "vpce-1"}}),
            json!({"StringNotEquals": {"aws:SourceVpc": "vpc-1"}}),
            json!({"Null": {"aws:SourceVpce": "true"}}),
            json!({"ForAnyValue:StringEquals": {"aws:UserAgent": "curl/8.0"}}),
            json!({"NumericLessThan": {"aws:EpochTime": "5"}}),
            json!({"StringEquals": {"aws:UserAgent": "${aws:username}"}}),
            json!({"StringEquals": "not an object"}),
            json!("not an object"),
        ] {
            assert_eq!(eval(&condition, &attributes), Truth::Unknown, "{condition}");
        }
    }

    #[test]
    fn keys_and_operators_are_case_insensitive() {
        let condition = json!({"ipaddress": {"AWS:SOURCEIP": "192.0.2.0/24"}});
        assert_eq!(eval(&condition, &known("192.0.2.1")), Truth::True);
    }

    #[test]
    fn numbers_and_booleans_in_values_are_read_as_text() {
        let condition = json!({"Bool": {"aws:SecureTransport": true}});
        assert_eq!(eval(&condition, &known("192.0.2.1")), Truth::True);
    }

    #[test]
    fn an_empty_block_holds() {
        let conditions = Conditions::parse(&json!({}));
        assert!(conditions.is_empty());
        assert_eq!(conditions.evaluate(&known("192.0.2.1")), Truth::True);
    }

    #[test]
    fn truth_tables() {
        use Truth::{False, True, Unknown};
        for (a, b, expected) in [
            (True, True, True),
            (True, False, False),
            (False, Unknown, False),
            (Unknown, False, False),
            (Unknown, True, Unknown),
            (True, Unknown, Unknown),
            (Unknown, Unknown, Unknown),
        ] {
            assert_eq!(a.and(b), expected, "{a:?} and {b:?}");
        }
        assert_eq!(Truth::any([False, Unknown, False]), Unknown);
        assert_eq!(Truth::any([False, Unknown, True]), True);
        assert_eq!(Truth::any([]), False);
    }
}
