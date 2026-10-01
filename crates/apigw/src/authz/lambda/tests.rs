use super::*;

fn pattern(expression: &str) -> TokenPattern {
    expression.parse().unwrap()
}

#[test]
fn token_patterns_match_the_whole_token() {
    let bearer = pattern("^Bearer [-0-9a-zA-Z._]+$");
    assert!(bearer.is_match("Bearer abc.DEF-1_2"));
    assert!(!bearer.is_match("Bearer "));
    assert!(!bearer.is_match("Bearer a b"));
    assert!(!bearer.is_match("xBearer a"));
    assert!(pattern("a|b").is_match("a"));
    assert!(!pattern("a|b").is_match("ab"));
    assert!(!pattern("a").is_match("a\n"));
    assert!(pattern("").is_match(""));
    assert!(!pattern("").is_match("a"));
}

#[test]
fn token_pattern_classes_are_ascii_as_in_java() {
    assert!(pattern(r"\w+").is_match("abc_123"));
    assert!(!pattern(r"\w+").is_match("caf\u{e9}"));
    assert!(pattern(r"\d+").is_match("123"));
    assert!(!pattern(r"\d+").is_match("\u{663}"));
    assert!(pattern("caf\u{e9}").is_match("caf\u{e9}"));
}

#[test]
fn token_patterns_that_rust_cannot_evaluate_are_rejected() {
    for expression in ["(?=a)b", r"(a)\1", "(", "[", r"\p{L}+", "a{99999999}"] {
        assert!(expression.parse::<TokenPattern>().is_err(), "{expression}");
    }
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
        br"[]",
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
