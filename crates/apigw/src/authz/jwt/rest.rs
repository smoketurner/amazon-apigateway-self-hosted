//! REST API JWT authorizers (`type: jwt` on a REST API): several trusted
//! issuers, each with its own audiences and additional claim rules, and the
//! signing algorithms the authorizer allows.
//!
//! See <https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-jwt-authorizer.html>.

use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;

use super::keys::{Issuer, KeyLocation, REST_JWT_KEY_TTL};
use super::token::{Claims, IssuerConfig, SigningAlgorithm};
use crate::authz::Denial;
use crate::model::AuthorizerSpec;

/// The clock skew API Gateway allows on `exp`, `nbf`, and `iat`.
pub(super) const CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_ISSUERS: usize = 10;
const MAX_AUDIENCES: usize = 100;
const MAX_CLAIM_RULES: usize = 10;
/// Claims API Gateway validates itself, which a claim rule may not name.
const RESERVED_CLAIMS: [&str; 7] = ["iss", "aud", "exp", "nbf", "iat", "scope", "scp"];
/// The only claim rule format.
const SINGLE_STRING: &str = "SINGLE_STRING";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    jwt_configuration: JwtConfiguration,
}

/// `jwksUri`, which `get-authorizer` returns, is ignored as API Gateway
/// ignores it on import: keys are always found through discovery.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct JwtConfiguration {
    #[serde(default)]
    issuers: Vec<IssuerSpec>,
    #[serde(default)]
    default_algorithms: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssuerSpec {
    issuer: String,
    #[serde(default)]
    audiences: Vec<String>,
    #[serde(default)]
    additional_claims: Vec<ClaimRuleSpec>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClaimRuleSpec {
    claim_name: String,
    format: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    expected_values: Vec<String>,
}

/// An additional claim the issuer's tokens are checked for.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimRule {
    name: String,
    required: bool,
    expected: Option<String>,
}

impl ClaimRule {
    fn compile(spec: ClaimRuleSpec) -> Result<Self, String> {
        let name = spec.claim_name;
        if name.is_empty() {
            return Err("a claim rule names no claim".to_owned());
        }
        if RESERVED_CLAIMS.contains(&name.as_str()) {
            return Err(format!(
                "the claim {name:?} is validated by the authorizer and cannot have a rule"
            ));
        }
        match spec.format.as_deref() {
            Some(SINGLE_STRING) => {}
            Some(other) => {
                return Err(format!(
                    "the claim rule for {name:?} has format {other:?}, not {SINGLE_STRING}"
                ));
            }
            None => return Err(format!("the claim rule for {name:?} has no format")),
        }
        let mut expected = spec.expected_values.into_iter();
        let first = expected.next();
        if expected.next().is_some() {
            return Err(format!(
                "the claim rule for {name:?} lists more than one expected value"
            ));
        }
        Ok(Self {
            name,
            required: spec.required,
            expected: first,
        })
    }

    /// Whether the token satisfies the rule. A rule that checks the claim at
    /// all (it is required or has an expected value) only accepts a claim
    /// whose value is a single string.
    fn admits(&self, claims: &Claims) -> bool {
        match (claims.get(&self.name), self.expected.as_deref()) {
            (None, _) => !self.required,
            (Some(_), None) if !self.required => true,
            (Some(Value::String(value)), expected) => expected.is_none_or(|e| e == value),
            (
                Some(
                    Value::Null
                    | Value::Bool(_)
                    | Value::Number(_)
                    | Value::Array(_)
                    | Value::Object(_),
                ),
                _,
            ) => false,
        }
    }
}

/// An issuer the authorizer trusts, with what it accepts from that issuer.
#[derive(Debug)]
struct TrustedIssuer {
    issuer: Issuer,
    audiences: Vec<String>,
    rules: Vec<ClaimRule>,
}

impl TrustedIssuer {
    fn compile(spec: IssuerSpec) -> Result<Self, String> {
        let IssuerSpec {
            issuer,
            audiences,
            additional_claims,
        } = spec;
        let url = Url::parse(&issuer).map_err(|_| format!("the issuer {issuer:?} is not a URL"))?;
        if url.scheme() != "https" || url.host_str().is_none_or(str::is_empty) {
            return Err(format!(
                "the issuer {issuer:?} is not an absolute https URL"
            ));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(format!(
                "the issuer {issuer:?} may not have a query string or fragment"
            ));
        }
        if audiences.is_empty() {
            return Err(format!("the issuer {issuer:?} lists no audience"));
        }
        if audiences.len() > MAX_AUDIENCES {
            return Err(format!(
                "the issuer {issuer:?} lists more than {MAX_AUDIENCES} audiences"
            ));
        }
        if additional_claims.len() > MAX_CLAIM_RULES {
            return Err(format!(
                "the issuer {issuer:?} has more than {MAX_CLAIM_RULES} claim rules"
            ));
        }
        let rules = additional_claims
            .into_iter()
            .map(ClaimRule::compile)
            .collect::<Result<Vec<_>, _>>()?;
        for (i, rule) in rules.iter().enumerate() {
            if rules
                .iter()
                .skip(i.saturating_add(1))
                .any(|r| r.name == rule.name)
            {
                return Err(format!(
                    "the issuer {issuer:?} has more than one rule for {:?}",
                    rule.name
                ));
            }
        }
        Ok(Self {
            // The issuer is matched exactly as written, trailing slash and all.
            issuer: Issuer::new(issuer),
            audiences,
            rules,
        })
    }
}

/// A compiled REST API JWT authorizer, apart from the key lookup the token
/// verifier does.
#[derive(Debug)]
pub(super) struct RestJwt {
    issuers: Vec<TrustedIssuer>,
}

/// What compiling a definition yields.
pub(super) struct Compiled {
    pub(super) rest: RestJwt,
    pub(super) issuers: Vec<IssuerConfig>,
    pub(super) algorithms: Vec<SigningAlgorithm>,
    /// The identity source, from the security scheme's `name`.
    pub(super) identity_source: String,
}

impl RestJwt {
    /// Compiles a REST API `jwt` authorizer.
    ///
    /// # Errors
    ///
    /// With the reason, when the definition is one API Gateway would refuse.
    pub(super) fn compile(spec: &AuthorizerSpec) -> Result<Compiled, String> {
        let header = match (spec.header_name.as_deref(), spec.location.as_deref()) {
            (Some(name), Some(location))
                if !name.is_empty() && location.eq_ignore_ascii_case("header") =>
            {
                name
            }
            (Some(_), Some(location)) if !location.eq_ignore_ascii_case("header") => {
                return Err(format!(
                    "a JWT authorizer reads its token from a header, not {location:?}"
                ));
            }
            _ => {
                return Err(
                    "the security scheme does not name the header that carries the token"
                        .to_owned(),
                );
            }
        };
        let Config { jwt_configuration } =
            Config::deserialize(&spec.config).map_err(|e| e.to_string())?;
        let JwtConfiguration {
            issuers,
            default_algorithms,
        } = jwt_configuration;
        if default_algorithms.is_empty() {
            return Err("the authorizer allows no signing algorithm".to_owned());
        }
        let mut algorithms = Vec::new();
        for name in &default_algorithms {
            let algorithm = SigningAlgorithm::from_name(name)
                .ok_or_else(|| format!("{name:?} is not a supported signing algorithm"))?;
            if !algorithms.contains(&algorithm) {
                algorithms.push(algorithm);
            }
        }
        if issuers.is_empty() {
            return Err("the authorizer trusts no issuer".to_owned());
        }
        if issuers.len() > MAX_ISSUERS {
            return Err(format!(
                "the authorizer trusts more than {MAX_ISSUERS} issuers"
            ));
        }
        let issuers = issuers
            .into_iter()
            .map(TrustedIssuer::compile)
            .collect::<Result<Vec<_>, _>>()?;
        for (i, trusted) in issuers.iter().enumerate() {
            if issuers
                .iter()
                .skip(i.saturating_add(1))
                .any(|other| other.issuer == trusted.issuer)
            {
                return Err(format!(
                    "the issuer {:?} is listed more than once",
                    trusted.issuer.as_str()
                ));
            }
        }
        Ok(Compiled {
            issuers: issuers
                .iter()
                .map(|trusted| IssuerConfig {
                    issuer: trusted.issuer.clone(),
                    location: KeyLocation::Discovery,
                    max_age: REST_JWT_KEY_TTL,
                })
                .collect(),
            rest: Self { issuers },
            algorithms,
            identity_source: format!("method.request.header.{header}"),
        })
    }

    /// Checks a verified token's audience, claim rules, and scopes, in API
    /// Gateway's order: a token for another audience is 401, and one that
    /// fails a claim rule or carries none of the route's scopes is 403.
    pub(super) fn check(&self, claims: &Claims, required: &[String]) -> Result<(), Denial> {
        let trusted = claims
            .text("iss")
            .and_then(|iss| self.issuers.iter().find(|t| t.issuer.as_str() == iss))
            .ok_or(Denial::Unauthorized)?;
        claims.check_audience(&trusted.audiences).map_err(|error| {
            tracing::debug!(%error, "token rejected");
            Denial::Unauthorized
        })?;
        if let Some(rule) = trusted.rules.iter().find(|rule| !rule.admits(claims)) {
            tracing::debug!(claim = rule.name, "token fails a claim rule");
            return Err(Denial::InsufficientScope);
        }
        if !claims.grants_any(required) {
            return Err(Denial::InsufficientScope);
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index known fixtures")]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(config: &Value) -> AuthorizerSpec {
        AuthorizerSpec {
            auth_type: Some("jwt".to_owned()),
            header_name: Some("Authorization".to_owned()),
            location: Some("header".to_owned()),
            config: config.clone(),
        }
    }

    fn config(issuers: &Value) -> Value {
        json!({"type": "jwt", "jwtConfiguration": {"issuers": issuers,
            "defaultAlgorithms": ["RS256"]}})
    }

    fn issuer(extra: &Value) -> Value {
        let mut issuer = json!({"issuer": "https://idp.example.com", "audiences": ["api"]});
        if let (Some(issuer), Some(extra)) = (issuer.as_object_mut(), extra.as_object()) {
            issuer.extend(extra.clone());
        }
        issuer
    }

    fn compile_err(config: &Value) -> String {
        RestJwt::compile(&spec(config)).err().unwrap()
    }

    fn claims(value: &Value) -> Claims {
        Claims::from_map(value.as_object().cloned().unwrap())
    }

    fn rule(required: bool, expected: Option<&str>) -> ClaimRule {
        ClaimRule {
            name: "department".to_owned(),
            required,
            expected: expected.map(str::to_owned),
        }
    }

    #[test]
    fn the_documented_example_compiles() {
        let compiled = RestJwt::compile(&spec(&json!({
            "type": "jwt",
            "jwtConfiguration": {
                "issuers": [{
                    "issuer": "https://identity.example.com",
                    "audiences": ["api://orders"],
                    "additionalClaims": [{"claimName": "department", "format": "SINGLE_STRING",
                        "required": true, "expectedValues": ["eng"]}],
                    "jwksUri": "https://identity.example.com/keys",
                }],
                "defaultAlgorithms": ["RS256", "ES256", "RS256"],
            },
        })))
        .unwrap();
        assert_eq!(
            compiled.algorithms,
            [SigningAlgorithm::Rs256, SigningAlgorithm::Es256]
        );
        assert_eq!(
            compiled.identity_source,
            "method.request.header.Authorization"
        );
        assert_eq!(compiled.issuers.len(), 1);
        assert_eq!(compiled.issuers[0].location, KeyLocation::Discovery);
        assert_eq!(compiled.issuers[0].max_age, REST_JWT_KEY_TTL);
        assert_eq!(compiled.rest.issuers[0].rules, [rule(true, Some("eng"))]);
    }

    #[test]
    #[expect(clippy::too_many_lines, reason = "one table of refused definitions")]
    fn definitions_api_gateway_refuses_are_not_evaluated() {
        let many = |n: usize, make: &dyn Fn(usize) -> Value| -> Value {
            Value::Array((0..n).map(make).collect())
        };
        let cases = [
            (config(&json!([])), "trusts no issuer"),
            (
                config(&many(11, &|i| {
                    issuer(&json!({"issuer": format!("https://idp{i}.example")}))
                })),
                "more than 10 issuers",
            ),
            (
                config(&json!([issuer(&json!({})), issuer(&json!({}))])),
                "listed more than once",
            ),
            (
                config(&json!([issuer(
                    &json!({"issuer": "http://idp.example.com"})
                )])),
                "https",
            ),
            (
                config(&json!([issuer(&json!({"issuer": "idp.example.com"}))])),
                "not a URL",
            ),
            (
                config(&json!([issuer(
                    &json!({"issuer": "https://idp.example.com/?a=1"})
                )])),
                "query",
            ),
            (
                config(&json!([issuer(
                    &json!({"issuer": "https://idp.example.com/#x"})
                )])),
                "fragment",
            ),
            (
                config(&json!([issuer(&json!({"audiences": []}))])),
                "no audience",
            ),
            (
                config(&json!([issuer(
                    &json!({"audiences": many(101, &|i| json!(format!("a{i}")))})
                )])),
                "more than 100 audiences",
            ),
            (
                config(&json!([issuer(
                    &json!({"additionalClaims": many(11, &|i| json!(
                    {"claimName": format!("c{i}"), "format": "SINGLE_STRING"}))})
                )])),
                "more than 10 claim rules",
            ),
            (
                config(&json!([issuer(&json!({"additionalClaims": [
                    {"claimName": "aud", "format": "SINGLE_STRING"}]}))])),
                "validated by the authorizer",
            ),
            (
                config(&json!([issuer(&json!({"additionalClaims": [
                    {"claimName": "d", "format": "SINGLE_STRING"},
                    {"claimName": "d", "format": "SINGLE_STRING"}]}))])),
                "more than one rule",
            ),
            (
                config(&json!([issuer(&json!({"additionalClaims": [
                    {"claimName": "d", "format": "STRING_ARRAY"}]}))])),
                "STRING_ARRAY",
            ),
            (
                config(&json!([issuer(
                    &json!({"additionalClaims": [{"claimName": "d"}]})
                )])),
                "no format",
            ),
            (
                config(&json!([issuer(&json!({"additionalClaims": [
                    {"claimName": "d", "format": "SINGLE_STRING", "expectedValues": ["a", "b"]}]}))])),
                "more than one expected value",
            ),
            (
                json!({"type": "jwt", "jwtConfiguration": {"issuers": [issuer(&json!({}))]}}),
                "no signing algorithm",
            ),
            (
                json!({"type": "jwt", "jwtConfiguration": {"issuers": [issuer(&json!({}))],
                    "defaultAlgorithms": ["HS256"]}}),
                "HS256",
            ),
            (
                json!({"type": "jwt", "jwtConfiguration": {"issuers": [issuer(&json!({}))],
                    "defaultAlgorithms": ["none"]}}),
                "\"none\"",
            ),
            (json!({"type": "jwt"}), "jwtConfiguration"),
        ];
        for (config, expected) in cases {
            let error = compile_err(&config);
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }

    #[test]
    fn the_token_comes_from_the_header_the_scheme_names() {
        let config = config(&json!([issuer(&json!({}))]));
        let mut query = spec(&config);
        query.location = Some("query".to_owned());
        assert!(RestJwt::compile(&query).err().unwrap().contains("query"));
        let mut unnamed = spec(&config);
        unnamed.header_name = None;
        assert!(RestJwt::compile(&unnamed).is_err());
        let mut nowhere = spec(&config);
        nowhere.location = None;
        assert!(RestJwt::compile(&nowhere).is_err());
        let mut custom = spec(&config);
        custom.header_name = Some("X-Token".to_owned());
        assert_eq!(
            RestJwt::compile(&custom).unwrap().identity_source,
            "method.request.header.X-Token"
        );
    }

    #[test]
    fn claim_rules_follow_the_documented_table() {
        let token = |value: Value| claims(&json!({"department": value}));
        let absent = claims(&json!({}));
        let eng = token(json!("eng"));
        let ops = token(json!("ops"));
        let list = token(json!(["eng"]));
        let number = token(json!(7));

        let required_any = rule(true, None);
        assert!(required_any.admits(&eng));
        assert!(!required_any.admits(&absent));
        assert!(
            !required_any.admits(&list),
            "an array is not a single string"
        );

        let required_eng = rule(true, Some("eng"));
        assert!(required_eng.admits(&eng));
        assert!(!required_eng.admits(&ops));
        assert!(!required_eng.admits(&token(json!("ENG"))), "case-sensitive");
        assert!(!required_eng.admits(&absent));
        assert!(!required_eng.admits(&list));

        let optional_eng = rule(false, Some("eng"));
        assert!(optional_eng.admits(&absent));
        assert!(optional_eng.admits(&eng));
        assert!(!optional_eng.admits(&ops));
        assert!(!optional_eng.admits(&number));

        let unchecked = rule(false, None);
        for token in [&absent, &eng, &list, &number] {
            assert!(unchecked.admits(token));
        }
    }

    #[test]
    fn audience_is_401_and_rules_and_scopes_are_403() {
        let compiled = RestJwt::compile(&spec(&config(&json!([
            issuer(&json!({"additionalClaims": [{"claimName": "department",
                "format": "SINGLE_STRING", "required": true, "expectedValues": ["eng"]}]})),
            {"issuer": "https://other.example.com/", "audiences": ["other"]},
        ]))))
        .unwrap();
        let check = |value: Value, scopes: &[&str]| {
            let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
            compiled.rest.check(&claims(&value), &scopes)
        };
        let good = json!({"iss": "https://idp.example.com", "aud": "api",
            "department": "eng", "scope": "orders:read"});
        assert_eq!(check(good.clone(), &[]), Ok(()));
        assert_eq!(
            check(good.clone(), &["orders:write", "orders:read"]),
            Ok(())
        );
        assert_eq!(
            check(good.clone(), &["orders:write"]),
            Err(Denial::InsufficientScope)
        );
        let mut wrong_aud = good.clone();
        wrong_aud["aud"] = json!("other");
        assert_eq!(check(wrong_aud, &[]), Err(Denial::Unauthorized));
        let mut wrong_department = good;
        wrong_department["department"] = json!("ops");
        assert_eq!(check(wrong_department, &[]), Err(Denial::InsufficientScope));
        assert_eq!(
            check(
                json!({"iss": "https://other.example.com/", "aud": "other"}),
                &[]
            ),
            Ok(()),
            "each issuer has its own audiences and rules"
        );
        assert_eq!(
            check(
                json!({"iss": "https://other.example.com", "aud": "other"}),
                &[]
            ),
            Err(Denial::Unauthorized),
            "the issuer matches exactly, trailing slash included"
        );
        assert_eq!(
            check(
                json!({"iss": "https://idp.example.com", "client_id": "api",
                "department": "eng"}),
                &[]
            ),
            Ok(()),
            "a Cognito access token's client_id stands in for aud"
        );
    }
}
