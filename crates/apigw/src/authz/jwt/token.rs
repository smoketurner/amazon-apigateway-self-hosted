//! Verifying a bearer token's signature and reading its claims.

use std::time::Duration;

use aws_lc_rs::signature::{ECDSA_P521_SHA512_FIXED, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve, Jwk, KeyAlgorithm};
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::keys::{Issuer, KeyError, KeyLocation, KeyStore};

/// A signing algorithm a token authorizer can accept. HTTP API JWT and Cognito
/// authorizers accept the RSA ones; a REST API JWT authorizer accepts the ones
/// its `defaultAlgorithms` lists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SigningAlgorithm {
    Rs256,
    Rs384,
    Rs512,
    Es256,
    Es384,
    Es512,
}

impl SigningAlgorithm {
    /// RSA with PKCS#1 v1.5: what HTTP API JWT and Cognito authorizers accept.
    pub(super) const RSA: [Self; 3] = [Self::Rs256, Self::Rs384, Self::Rs512];

    /// The algorithm a JOSE `alg` names, spelled exactly.
    pub(super) fn from_name(name: &str) -> Option<Self> {
        match name {
            "RS256" => Some(Self::Rs256),
            "RS384" => Some(Self::Rs384),
            "RS512" => Some(Self::Rs512),
            "ES256" => Some(Self::Es256),
            "ES384" => Some(Self::Es384),
            "ES512" => Some(Self::Es512),
            _ => None,
        }
    }

    /// The `jsonwebtoken` algorithm, for every algorithm but ES512, which that
    /// crate does not implement.
    fn library(self) -> Option<Algorithm> {
        match self {
            Self::Rs256 => Some(Algorithm::RS256),
            Self::Rs384 => Some(Algorithm::RS384),
            Self::Rs512 => Some(Algorithm::RS512),
            Self::Es256 => Some(Algorithm::ES256),
            Self::Es384 => Some(Algorithm::ES384),
            Self::Es512 => None,
        }
    }

    /// Whether `jwk` may verify this algorithm: the key type and curve must
    /// fit, and a key that names its algorithm may not be used with another.
    fn allowed_by(self, jwk: &Jwk) -> bool {
        use AlgorithmParameters::{EllipticCurve as Ec, RSA};
        let (fits, name) = match (self, &jwk.algorithm) {
            (Self::Rs256, RSA(_)) => (true, KeyAlgorithm::RS256),
            (Self::Rs384, RSA(_)) => (true, KeyAlgorithm::RS384),
            (Self::Rs512, RSA(_)) => (true, KeyAlgorithm::RS512),
            (Self::Es256, Ec(ec)) => (ec.curve == EllipticCurve::P256, KeyAlgorithm::ES256),
            (Self::Es384, Ec(ec)) => (ec.curve == EllipticCurve::P384, KeyAlgorithm::ES384),
            // `jsonwebtoken` has no name for ES512, so a P-521 key that says
            // `"alg": "ES512"` reads as an unknown algorithm.
            (Self::Es512, Ec(ec)) => (
                ec.curve == EllipticCurve::P521,
                KeyAlgorithm::UNKNOWN_ALGORITHM,
            ),
            _ => return false,
        };
        fits && jwk.common.key_algorithm.is_none_or(|named| named == name)
    }
}

#[derive(Debug, thiserror::Error)]
pub(super) enum TokenError {
    #[error("the token is not a signed JWT: {0}")]
    Malformed(String),
    #[error("the token is signed with {0:?}, which is not accepted")]
    Algorithm(String),
    #[error("the token names no key id")]
    NoKeyId,
    #[error("the token was not issued by a configured issuer")]
    Issuer,
    #[error("no key could be found for the token: {0}")]
    Key(#[from] KeyError),
    #[error("the key does not allow {0:?}")]
    KeyAlgorithm(SigningAlgorithm),
    #[error("the signature is not valid: {0}")]
    Signature(String),
    #[error("the token's {0} is not a whole number")]
    Time(&'static str),
    #[error("the token has expired or has no expiry")]
    Expired,
    #[error("the token is not valid yet")]
    NotYetValid,
    #[error("the token claims to be issued in the future")]
    IssuedInFuture,
    #[error("the token is for another audience")]
    Audience,
}

/// An issuer's key location, as configured, and how long its keys are cached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct IssuerConfig {
    pub(super) issuer: Issuer,
    pub(super) location: KeyLocation,
    pub(super) max_age: Duration,
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

    pub(super) fn to_map(&self) -> Map<String, Value> {
        self.0.clone()
    }

    pub(super) fn get(&self, name: &str) -> Option<&Value> {
        self.0.get(name)
    }

    pub(super) fn text(&self, name: &str) -> Option<&str> {
        self.0.get(name).and_then(Value::as_str)
    }

    /// A time claim, in seconds since the epoch. A claim that is present but
    /// not a whole number makes the token unacceptable.
    fn time(&self, name: &'static str) -> Result<Option<i64>, TokenError> {
        match self.0.get(name) {
            None => Ok(None),
            Some(value) => value.as_i64().map(Some).ok_or(TokenError::Time(name)),
        }
    }

    /// Checks `exp` (required, after `now`), `nbf` (not after `now`), and `iat`
    /// (not after `now`), all in seconds since the epoch, allowing `skew`
    /// seconds of difference between the issuer's clock and this one.
    pub(super) fn check_times(&self, now: i64, skew: i64) -> Result<(), TokenError> {
        let earliest = now.saturating_sub(skew);
        let latest = now.saturating_add(skew);
        match self.time("exp")? {
            Some(exp) if exp > earliest => {}
            Some(_) | None => return Err(TokenError::Expired),
        }
        if self.time("nbf")?.is_some_and(|nbf| nbf > latest) {
            return Err(TokenError::NotYetValid);
        }
        if self.time("iat")?.is_some_and(|iat| iat > latest) {
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

/// The parts of a JOSE header that decide how a token is verified.
#[derive(Deserialize)]
struct Header {
    alg: String,
    kid: Option<String>,
}

/// A compact JWS split into its parts, with the header and payload decoded but
/// nothing verified yet.
struct Compact<'a> {
    signing_input: &'a str,
    signature: &'a str,
    header: Header,
    payload: Map<String, Value>,
}

impl<'a> Compact<'a> {
    fn parse(token: &'a str) -> Result<Self, TokenError> {
        let malformed = |what: &str| TokenError::Malformed(what.to_owned());
        let (signing_input, signature) = token
            .rsplit_once('.')
            .ok_or_else(|| malformed("expected three parts"))?;
        let (header, payload) = signing_input
            .split_once('.')
            .ok_or_else(|| malformed("expected three parts"))?;
        if payload.contains('.') {
            return Err(malformed("expected three parts"));
        }
        let json = |part: &str, what: &str| -> Result<Vec<u8>, TokenError> {
            URL_SAFE_NO_PAD
                .decode(part)
                .map_err(|e| TokenError::Malformed(format!("{what}: {e}")))
        };
        let header: Header = serde_json::from_slice(&json(header, "header")?)
            .map_err(|e| TokenError::Malformed(format!("header: {e}")))?;
        // As API Gateway reads them: the first JSON value counts, and `null`
        // is a token with no claims. Either way the signature decides.
        let payload = json(payload, "payload")?;
        let payload = match serde_json::Deserializer::from_slice(&payload)
            .into_iter::<Option<Map<String, Value>>>()
            .next()
        {
            Some(Ok(claims)) => claims.unwrap_or_default(),
            Some(Err(e)) => return Err(TokenError::Malformed(format!("payload: {e}"))),
            None => return Err(TokenError::Malformed("payload: empty".to_owned())),
        };
        Ok(Self {
            signing_input,
            signature,
            header,
            payload,
        })
    }
}

/// Verifies tokens against a set of issuers.
pub(super) struct Verifier<'a> {
    pub(super) keys: &'a KeyStore,
    pub(super) issuers: &'a [IssuerConfig],
    pub(super) algorithms: &'a [SigningAlgorithm],
}

impl Verifier<'_> {
    /// Checks the token's algorithm, key, and signature. The claims it returns
    /// are authentic but not yet checked for time, audience, or scope.
    ///
    /// The issuer in the unverified payload is used only to choose which
    /// configured issuer's keys to use; the key must still verify the token,
    /// and the verified claims must name that issuer.
    pub(super) async fn verify(&self, token: &str) -> Result<Claims, TokenError> {
        let compact = Compact::parse(token)?;
        let algorithm = SigningAlgorithm::from_name(&compact.header.alg)
            .filter(|alg| self.algorithms.contains(alg))
            .ok_or_else(|| TokenError::Algorithm(compact.header.alg.clone()))?;
        let kid = compact.header.kid.as_deref().ok_or(TokenError::NoKeyId)?;
        let named = compact.payload.get("iss").and_then(Value::as_str);
        // With one issuer its keys are tried whatever the token says, as API
        // Gateway does, and the issuer is compared once the signature holds;
        // with several the token's `iss` has to pick whose keys to use.
        let issuer = match self.issuers {
            [only] => only,
            several => several
                .iter()
                .find(|c| named == Some(c.issuer.as_str()))
                .ok_or(TokenError::Issuer)?,
        };
        let jwk = self
            .keys
            .key(&issuer.issuer, issuer.location, issuer.max_age, kid)
            .await?;
        if !algorithm.allowed_by(&jwk) {
            return Err(TokenError::KeyAlgorithm(algorithm));
        }
        let claims = match algorithm.library() {
            Some(library) => Self::verify_with_library(token, &jwk, library),
            None => Self::verify_p521(&compact, &jwk),
        }?;
        if claims.text("iss") == Some(issuer.issuer.as_str()) {
            Ok(claims)
        } else {
            Err(TokenError::Issuer)
        }
    }

    fn verify_with_library(
        token: &str,
        jwk: &Jwk,
        algorithm: Algorithm,
    ) -> Result<Claims, TokenError> {
        let key = DecodingKey::from_jwk(jwk).map_err(|e| TokenError::Signature(e.to_string()))?;
        let mut validation = Validation::new(algorithm);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.validate_nbf = false;
        validation.validate_aud = false;
        validation.leeway = 0;
        let verified = jsonwebtoken::decode::<Map<String, Value>>(token, &key, &validation)
            .map_err(|e| TokenError::Signature(e.to_string()))?;
        Ok(Claims(verified.claims))
    }

    /// ES512 (ECDSA on P-521 with SHA-512), which `jsonwebtoken` does not
    /// implement: the signature is the 132-byte `r || s`, and the key is the
    /// uncompressed point built from the JWK's `x` and `y`.
    fn verify_p521(compact: &Compact<'_>, jwk: &Jwk) -> Result<Claims, TokenError> {
        const COORDINATE: usize = 66;
        let invalid = |what: &str| TokenError::Signature(what.to_owned());
        let AlgorithmParameters::EllipticCurve(ref ec) = jwk.algorithm else {
            return Err(invalid("the key is not an elliptic curve key"));
        };
        let coordinate = |encoded: &str| {
            URL_SAFE_NO_PAD
                .decode(encoded)
                .ok()
                .filter(|bytes| bytes.len() == COORDINATE)
                .ok_or_else(|| invalid("the key is not a P-521 point"))
        };
        let mut point = Vec::with_capacity(1 + 2 * COORDINATE);
        point.push(0x04);
        point.extend(coordinate(&ec.x)?);
        point.extend(coordinate(&ec.y)?);
        let signature = URL_SAFE_NO_PAD
            .decode(compact.signature)
            .map_err(|_| invalid("the signature is not base64url"))?;
        UnparsedPublicKey::new(&ECDSA_P521_SHA512_FIXED, &point)
            .verify(compact.signing_input.as_bytes(), &signature)
            .map_err(|_| invalid("the signature does not match"))?;
        Ok(Claims(compact.payload.clone()))
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
        Claims::from_map(map).check_times(NOW, 0)
    }

    #[test]
    fn claims_are_the_first_json_value_and_null_is_none() {
        let token = |payload: &str| {
            format!(
                "{}.{}.c2ln",
                URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","kid":"k"}"#),
                URL_SAFE_NO_PAD.encode(payload)
            )
        };
        let claims = |payload: &str| Compact::parse(&token(payload)).map(|c| c.payload);
        assert_eq!(claims("null").unwrap(), Map::new());
        assert_eq!(claims(r#"{"a":1} x"#).unwrap().get("a"), Some(&json!(1)));
        for payload in ["", "[1]", r#""s""#, "{"] {
            assert!(
                matches!(claims(payload), Err(TokenError::Malformed(_))),
                "{payload:?}"
            );
        }
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
    fn skew_widens_every_time_check_by_the_same_amount() {
        let check = |exp: i64, nbf: Option<i64>, iat: Option<i64>| {
            let mut map = Map::new();
            map.insert("exp".to_owned(), json!(exp));
            if let Some(nbf) = nbf {
                map.insert("nbf".to_owned(), json!(nbf));
            }
            if let Some(iat) = iat {
                map.insert("iat".to_owned(), json!(iat));
            }
            Claims::from_map(map).check_times(NOW, 60)
        };
        assert!(check(NOW - 59, None, None).is_ok());
        assert!(matches!(
            check(NOW - 60, None, None),
            Err(TokenError::Expired)
        ));
        assert!(check(NOW + 1, Some(NOW + 60), Some(NOW + 60)).is_ok());
        assert!(matches!(
            check(NOW + 1, Some(NOW + 61), None),
            Err(TokenError::NotYetValid)
        ));
        assert!(matches!(
            check(NOW + 1, None, Some(NOW + 61)),
            Err(TokenError::IssuedInFuture)
        ));
        assert!(
            Claims::from_map(std::iter::once(("exp".to_owned(), json!(i64::MIN))).collect())
                .check_times(i64::MIN, i64::MAX)
                .is_err(),
            "skew saturates rather than overflowing"
        );
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
                    Claims::from_map(map).check_times(NOW, 0).is_err(),
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
        assert_eq!(
            scopes(json!({"scope": 7, "scp": null})),
            Vec::<String>::new()
        );
        assert_eq!(scopes(json!({})), Vec::<String>::new());
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
            .check_times(now, 0);
            prop_assert_eq!(result.is_ok(), exp > now);
        }

        #[test]
        fn scope_extraction_never_panics(scope in ".{0,40}", scp in ".{0,40}") {
            let token = claims(&json!({"scope": scope, "scp": scp}));
            prop_assert!(token.scopes().iter().all(|scope| !scope.is_empty()));
        }
    }
}
