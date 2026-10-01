//! Verifying a bearer token's signature and reading its claims.

use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde_json::{Map, Value};

use super::keys::{Issuer, KeyError, KeyLocation, KeyStore};

/// The algorithms API Gateway accepts: RSA with PKCS#1 v1.5.
const ALGORITHMS: [Algorithm; 3] = [Algorithm::RS256, Algorithm::RS384, Algorithm::RS512];

#[derive(Debug, thiserror::Error)]
pub(super) enum TokenError {
    #[error("the token is not a signed JWT: {0}")]
    Malformed(String),
    #[error("the token is signed with {0:?}, which is not accepted")]
    Algorithm(Algorithm),
    #[error("the token names no key id")]
    NoKeyId,
    #[error("the token was not issued by a configured issuer")]
    Issuer,
    #[error("no key could be found for the token: {0}")]
    Key(#[from] KeyError),
    #[error("the key does not allow {0:?}")]
    KeyAlgorithm(Algorithm),
    #[error("the signature is not valid: {0}")]
    Signature(String),
    #[error("the token has expired or has no expiry")]
    Expired,
    #[error("the token is not valid yet")]
    NotYetValid,
    #[error("the token claims to be issued in the future")]
    IssuedInFuture,
    #[error("the token is for another audience")]
    Audience,
}

/// An issuer's key location, as configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IssuerConfig {
    pub(super) issuer: Issuer,
    pub(super) location: KeyLocation,
}

/// The claims of a token whose signature has been verified.
#[derive(Debug, Clone, PartialEq)]
pub(super) struct Claims(Map<String, Value>);

impl Claims {
    #[cfg(test)]
    pub(super) fn from_map(claims: Map<String, Value>) -> Self {
        Self(claims)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&String, &Value)> {
        self.0.iter()
    }

    pub(super) fn text(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(Value::as_str)
    }

    /// A time claim, in seconds since the epoch. A claim that is present but
    /// not a whole number makes the token unacceptable.
    fn time(&self, name: &str) -> Result<Option<i64>, TokenError> {
        match self.0.get(name) {
            None => Ok(None),
            Some(value) => value
                .as_i64()
                .map(Some)
                .ok_or_else(|| TokenError::Malformed(format!("{name} is not a whole number"))),
        }
    }

    /// Checks `exp` (required, after `now`), `nbf` (not after `now`), and `iat`
    /// (not after `now`), all in seconds since the epoch.
    pub(super) fn check_times(&self, now: i64) -> Result<(), TokenError> {
        match self.time("exp")? {
            Some(exp) if exp > now => {}
            Some(_) | None => return Err(TokenError::Expired),
        }
        if self.time("nbf")?.is_some_and(|nbf| nbf > now) {
            return Err(TokenError::NotYetValid);
        }
        if self.time("iat")?.is_some_and(|iat| iat > now) {
            return Err(TokenError::IssuedInFuture);
        }
        Ok(())
    }

    /// Checks that the token is for one of `accepted`: its `aud`, or its
    /// `client_id` only when it has no `aud`.
    pub(super) fn check_audience(&self, accepted: &[String]) -> Result<(), TokenError> {
        let listed = |value: &str| accepted.iter().any(|a| a == value);
        let matches = match self.0.get("aud") {
            Some(Value::String(audience)) => listed(audience),
            Some(Value::Array(audiences)) => audiences.iter().filter_map(Value::as_str).any(listed),
            Some(Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_)) => false,
            None => self.text("client_id").is_some_and(listed),
        };
        if matches {
            Ok(())
        } else {
            Err(TokenError::Audience)
        }
    }

    /// The scopes the token grants: `scope` (space separated) and `scp` (space
    /// separated, or a list), in order of appearance.
    pub(super) fn scopes(&self) -> Vec<String> {
        let mut scopes = Vec::new();
        for name in ["scope", "scp"] {
            match self.0.get(name) {
                Some(Value::String(list)) => {
                    scopes.extend(list.split_whitespace().map(str::to_owned));
                }
                Some(Value::Array(items)) => {
                    scopes.extend(items.iter().filter_map(Value::as_str).map(str::to_owned));
                }
                Some(Value::Null | Value::Bool(_) | Value::Number(_) | Value::Object(_)) | None => {
                }
            }
        }
        scopes
    }

    /// Whether the token grants at least one of `required` (or none is required).
    pub(super) fn grants_any(&self, required: &[String]) -> bool {
        if required.is_empty() {
            return true;
        }
        let granted = self.scopes();
        required.iter().any(|scope| granted.contains(scope))
    }
}

/// Verifies tokens against a set of issuers.
pub(super) struct Verifier<'a> {
    pub(super) keys: &'a KeyStore,
    pub(super) issuers: &'a [IssuerConfig],
}

impl Verifier<'_> {
    /// Checks the token's algorithm, key, and signature. The claims it returns
    /// are authentic but not yet checked for time, audience, or scope.
    ///
    /// The issuer is read from the unverified payload only to choose which
    /// configured issuer's keys to use; the key must still verify the token.
    pub(super) async fn verify(&self, token: &str) -> Result<Claims, TokenError> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|e| TokenError::Malformed(e.to_string()))?;
        if !ALGORITHMS.contains(&header.alg) {
            return Err(TokenError::Algorithm(header.alg));
        }
        let kid = header.kid.as_deref().ok_or(TokenError::NoKeyId)?;
        let claimed = jsonwebtoken::dangerous::insecure_decode_claims::<Map<String, Value>>(token)
            .map_err(|e| TokenError::Malformed(e.to_string()))?;
        let issuer = claimed
            .get("iss")
            .and_then(Value::as_str)
            .and_then(|iss| self.issuers.iter().find(|c| c.issuer.as_str() == iss))
            .ok_or(TokenError::Issuer)?;
        let jwk = self.keys.key(&issuer.issuer, issuer.location, kid).await?;
        Self::check_key_allows(&jwk, header.alg)?;
        let key = DecodingKey::from_jwk(&jwk).map_err(|e| TokenError::Signature(e.to_string()))?;
        let mut validation = Validation::new(header.alg);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        let verified = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| TokenError::Signature(e.to_string()))?;
        Ok(Claims(verified.claims))
    }

    /// A key that names the algorithm it is for may not be used with another,
    /// and only RSA keys verify the accepted algorithms.
    fn check_key_allows(jwk: &Jwk, algorithm: Algorithm) -> Result<(), TokenError> {
        if !matches!(jwk.algorithm, AlgorithmParameters::RSA(_)) {
            return Err(TokenError::KeyAlgorithm(algorithm));
        }
        let allowed = match jwk.common.key_algorithm {
            None => true,
            Some(KeyAlgorithm::RS256) => algorithm == Algorithm::RS256,
            Some(KeyAlgorithm::RS384) => algorithm == Algorithm::RS384,
            Some(KeyAlgorithm::RS512) => algorithm == Algorithm::RS512,
            Some(_) => false,
        };
        if allowed {
            Ok(())
        } else {
            Err(TokenError::KeyAlgorithm(algorithm))
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    const NOW: i64 = 1_700_000_000;

    fn claims(value: &Value) -> Claims {
        Claims::from_map(value.as_object().cloned().unwrap())
    }

    fn times(exp: Option<i64>, nbf: Option<i64>, iat: Option<i64>) -> Result<(), TokenError> {
        let mut map = Map::new();
        for (name, value) in [("exp", exp), ("nbf", nbf), ("iat", iat)] {
            if let Some(value) = value {
                map.insert(name.to_owned(), json!(value));
            }
        }
        Claims::from_map(map).check_times(NOW)
    }

    #[test]
    fn exp_is_required_and_must_be_after_now() {
        assert!(times(Some(NOW + 1), None, None).is_ok());
        assert!(matches!(
            times(Some(NOW), None, None),
            Err(TokenError::Expired)
        ));
        assert!(matches!(
            times(Some(NOW - 1), None, None),
            Err(TokenError::Expired)
        ));
        assert!(matches!(times(None, None, None), Err(TokenError::Expired)));
    }

    #[test]
    fn nbf_and_iat_may_equal_now_but_not_exceed_it() {
        assert!(times(Some(NOW + 1), Some(NOW), Some(NOW)).is_ok());
        assert!(matches!(
            times(Some(NOW + 1), Some(NOW + 1), None),
            Err(TokenError::NotYetValid)
        ));
        assert!(matches!(
            times(Some(NOW + 1), None, Some(NOW + 1)),
            Err(TokenError::IssuedInFuture)
        ));
    }

    #[test]
    fn time_claims_that_are_not_whole_numbers_are_rejected() {
        for bad in [
            json!("soon"),
            json!(1.5),
            json!(null),
            json!([1]),
            json!(true),
        ] {
            for name in ["exp", "nbf", "iat"] {
                let mut map = Map::new();
                map.insert("exp".to_owned(), json!(NOW + 100));
                map.insert(name.to_owned(), bad.clone());
                assert!(
                    Claims::from_map(map).check_times(NOW).is_err(),
                    "{name}={bad}"
                );
            }
        }
    }

    #[test]
    fn audiences_follow_api_gateways_rules() {
        let accepted = vec!["api".to_owned(), "api-2".to_owned()];
        let check = |value: Value| claims(&value).check_audience(&accepted).is_ok();
        assert!(check(json!({"aud": "api"})));
        assert!(check(json!({"aud": ["x", "api-2"]})));
        assert!(check(json!({"client_id": "api"})));
        assert!(check(json!({"aud": "api", "client_id": "nope"})));
        assert!(!check(json!({"aud": "nope", "client_id": "api"})));
        assert!(!check(json!({"aud": []})));
        assert!(!check(json!({"aud": null, "client_id": "api"})));
        assert!(check(json!({"aud": ["api", 7]})));
        assert!(!check(json!({"aud": ["x", 7], "client_id": "api"})));
        assert!(!check(json!({"aud": "API"})));
        assert!(!check(json!({})));
        assert!(!check(json!({"client_id": 7})));
    }

    #[test]
    fn scopes_come_from_scope_and_scp() {
        let scopes = |value: Value| claims(&value).scopes();
        assert_eq!(scopes(json!({"scope": "a b  c"})), ["a", "b", "c"]);
        assert_eq!(scopes(json!({"scp": ["a", "b"]})), ["a", "b"]);
        assert_eq!(scopes(json!({"scp": "a b"})), ["a", "b"]);
        assert_eq!(scopes(json!({"scope": "a", "scp": ["b"]})), ["a", "b"]);
        assert!(scopes(json!({"scope": 7, "scp": null})).is_empty());
        assert!(scopes(json!({})).is_empty());
    }

    #[test]
    fn a_route_needs_one_of_its_scopes_or_none() {
        let token = claims(&json!({"scope": "read write"}));
        let want = |scopes: &[&str]| {
            let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
            token.grants_any(&scopes)
        };
        assert!(want(&[]));
        assert!(want(&["read"]));
        assert!(want(&["admin", "write"]));
        assert!(!want(&["admin"]));
        assert!(!want(&["rea"]));
        assert!(!claims(&json!({})).grants_any(&["read".to_owned()]));
        assert!(claims(&json!({})).grants_any(&[]));
    }

    proptest! {
        #[test]
        fn expiry_is_exactly_the_strictly_future_check(exp in any::<i64>(), now in any::<i64>()) {
            let result = Claims::from_map(
                std::iter::once(("exp".to_owned(), json!(exp))).collect(),
            )
            .check_times(now);
            prop_assert_eq!(result.is_ok(), exp > now);
        }

        #[test]
        fn scope_extraction_never_panics(scope in ".{0,40}", scp in ".{0,40}") {
            let token = claims(&json!({"scope": scope, "scp": scp}));
            let _ = token.scopes();
        }
    }
}
