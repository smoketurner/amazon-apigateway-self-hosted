//! How verified claims reach `$context.authorizer` and Lambda events: API
//! Gateway delivers every claim as a string, and REST and HTTP APIs spell some
//! of them differently.

use serde_json::{Map, Value};

use super::token::Claims;

/// Which API product's spelling to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ClaimStyle {
    /// REST APIs (Cognito user pool authorizers): lists are comma-joined and
    /// `exp` and `iat` are dates in Java's `Date.toString()` form.
    Rest,
    /// HTTP APIs (JWT authorizers): lists are written `[a b]` and times stay
    /// numbers.
    Http,
}

impl ClaimStyle {
    /// A time claim in the form REST APIs show it: `Tue Oct 25 10:11:58 UTC 2022`.
    fn date(seconds: i64) -> Option<String> {
        jiff::Timestamp::from_second(seconds)
            .ok()
            .map(|at| at.strftime("%a %b %d %H:%M:%S UTC %Y").to_string())
    }

    fn scalar(value: &Value) -> Option<String> {
        match value {
            Value::String(text) => Some(text.clone()),
            Value::Number(_) | Value::Bool(_) => Some(value.to_string()),
            Value::Null | Value::Array(_) | Value::Object(_) => None,
        }
    }

    fn text(self, name: &str, value: &Value) -> Option<String> {
        if self == Self::Rest
            && matches!(name, "exp" | "iat")
            && let Some(date) = value.as_i64().and_then(Self::date)
        {
            return Some(date);
        }
        match value {
            Value::Null => None,
            Value::Array(items) => {
                let items: Vec<String> = items
                    .iter()
                    .map(|item| Self::scalar(item).unwrap_or_else(|| item.to_string()))
                    .collect();
                Some(match self {
                    Self::Rest => items.join(","),
                    Self::Http => format!("[{}]", items.join(" ")),
                })
            }
            Value::Object(_) => Some(value.to_string()),
            Value::String(_) | Value::Number(_) | Value::Bool(_) => Self::scalar(value),
        }
    }

    /// The claims as the string-valued map API Gateway exposes.
    pub(super) fn claims(self, claims: &Claims) -> Map<String, Value> {
        claims
            .iter()
            .filter_map(|(name, value)| {
                self.text(name, value)
                    .map(|text| (name.clone(), Value::String(text)))
            })
            .collect()
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use serde_json::json;

    use super::*;

    fn claims(value: &Value) -> Claims {
        Claims::from_map(value.as_object().cloned().unwrap())
    }

    #[test]
    fn rest_claims_follow_cognito_authorizer_output() {
        let input = claims(&json!({
            "sub": "u1",
            "cognito:groups": ["group-a", "group-b"],
            "email_verified": true,
            "auth_time": 1_666_606_318,
            "exp": 1_666_692_718,
            "iat": 1_666_606_318,
            "missing": null,
        }));
        assert_eq!(
            Value::Object(ClaimStyle::Rest.claims(&input)),
            json!({
                "sub": "u1",
                "cognito:groups": "group-a,group-b",
                "email_verified": "true",
                "auth_time": "1666606318",
                "exp": "Tue Oct 25 10:11:58 UTC 2022",
                "iat": "Mon Oct 24 10:11:58 UTC 2022",
            })
        );
    }

    #[test]
    fn http_claims_keep_times_numeric_and_bracket_lists() {
        let input = claims(&json!({
            "cognito:groups": ["Group2", "Group1"],
            "exp": 1_586_634_792,
            "scope": "openid email",
            "nested": {"a": 1},
        }));
        assert_eq!(
            Value::Object(ClaimStyle::Http.claims(&input)),
            json!({
                "cognito:groups": "[Group2 Group1]",
                "exp": "1586634792",
                "scope": "openid email",
                "nested": "{\"a\":1}",
            })
        );
    }

    #[test]
    fn an_unrepresentable_date_stays_a_number() {
        let input = claims(&json!({"exp": i64::MAX}));
        assert_eq!(
            Value::Object(ClaimStyle::Rest.claims(&input)),
            json!({"exp": i64::MAX.to_string()})
        );
    }
}
