//! The Java regular expressions that authorizers validate credentials with.

use std::str::FromStr;

use apigw_regex::{JavaRegex, RegexError};

/// An `identityValidationExpression`: a Java regular expression the whole
/// value must match. Authorizers use it on a `TOKEN` authorizer's token and on a
/// Cognito authorizer's `aud` claim.
#[derive(Debug)]
pub(super) struct TokenPattern(Box<JavaRegex>);

impl FromStr for TokenPattern {
    type Err = RegexError;

    fn from_str(expression: &str) -> Result<Self, Self::Err> {
        JavaRegex::new(expression).map(|regex| Self(Box::new(regex)))
    }
}

impl TokenPattern {
    /// Whether `value` matches. A match that cannot be completed (the backtrack
    /// limit) is an error, which answers 500 rather than guessing.
    pub(super) fn is_match(&self, value: &str) -> Result<bool, RegexError> {
        self.0.matches(value)
    }
}
