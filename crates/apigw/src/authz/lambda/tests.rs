use super::*;

fn pattern(expression: &str) -> TokenPattern {
    expression.parse().unwrap()
}

fn matches(expression: &str, token: &str) -> bool {
    pattern(expression).is_match(token).unwrap()
}

#[test]
fn token_patterns_match_the_whole_token() {
    let bearer = "^Bearer [-0-9a-zA-Z._]+$";
    assert!(matches(bearer, "Bearer abc.DEF-1_2"));
    assert!(!matches(bearer, "Bearer "));
    assert!(!matches(bearer, "Bearer a b"));
    assert!(!matches(bearer, "xBearer a"));
    assert!(matches("a|b", "a"));
    assert!(!matches("a|b", "ab"));
    assert!(!matches("a", "a\n"));
    assert!(matches("", ""));
    assert!(!matches("", "a"));
}

#[test]
fn token_pattern_classes_are_ascii_as_in_java() {
    assert!(matches(r"\w+", "abc_123"));
    assert!(!matches(r"\w+", "caf\u{e9}"));
    assert!(matches(r"\d+", "123"));
    assert!(!matches(r"\d+", "\u{663}"));
    assert!(matches("caf\u{e9}", "caf\u{e9}"));
}

#[test]
fn java_constructs_beyond_plain_regular_expressions_work() {
    assert!(matches("(?i)bearer .+", "BEARER x"));
    assert!(matches("Bearer (?!none$).+", "Bearer x"));
    assert!(!matches("Bearer (?!none$).+", "Bearer none"));
    assert!(matches(r"(\w)\1", "aa"));
}

#[test]
fn token_patterns_that_cannot_be_evaluated_are_rejected() {
    for expression in [r"\G", r"\X", "(", "[", r"\p{javaLowerCase}"] {
        assert!(expression.parse::<TokenPattern>().is_err(), "{expression}");
    }
}

#[test]
fn a_runaway_match_is_an_error_not_a_pass() {
    let hostile = pattern(r"(a|aa)+\1c");
    assert!(hostile.is_match(&format!("{}b", "a".repeat(200))).is_err());
}

#[test]
#[expect(clippy::panic, reason = "fails loudly on an unexpected response shape")]
fn rest_context_values_reach_the_backend_as_strings() {
    let policy = br#"{"principalId":"u","policyDocument":{"Statement":[]},"context":{"a":1,"b":true,"c":"x"}}"#;
    let parsed = AuthorizerResponse::parse(policy, &Flavor::RestRequest).unwrap();
    let AuthorizerResponse::Policy { context, .. } = parsed else {
        panic!("a policy document was returned");
    };
    assert_eq!(
        Value::Object(context),
        json!({"a": "1", "b": "true", "c": "x"})
    );
}

#[test]
fn malformed_responses_are_configuration_errors() {
    for bad in [
        &br#"{"principalId":"u"}"#[..],
        br#"{"principalId":7,"policyDocument":{"Statement":[]}}"#,
        br#"{"principalId":"u","policyDocument":"{}"}"#,
        br#"{"principalId":"u","policyDocument":{"Statement":[]},"context":[]}"#,
        br#"{"principalId":"u","policyDocument":{"Statement":[]},"context":{"k":null}}"#,
        b"[]",
        b"",
    ] {
        assert_eq!(
            AuthorizerResponse::parse(bad, &Flavor::RestRequest).unwrap_err(),
            Denial::AuthorizerConfiguration,
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}
