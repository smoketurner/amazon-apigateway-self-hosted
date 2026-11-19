//! The `WWW-Authenticate` header on an HTTP API JWT authorizer's `401`.
//!
//! API Gateway says why it refused a token in `error_description`, in the
//! words of the Go libraries it parses tokens with. The wordings here were
//! measured against a deployed API (see `docs/parity.md`); a refusal whose
//! wording is not known gets a challenge without a description.

use axum::http::HeaderValue;
use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use serde_json::{Map, Value};

use super::keys::KeyError;
use super::token::TokenError;

const SEGMENTS: &str = "token contains an invalid number of segments";
const BEARER_PREFIX: &str = "tokenstring should not contain 'bearer '";
const ALG_UNSPECIFIED: &str = "signing method (alg) is unspecified.";
const ALG_UNAVAILABLE: &str = "signing method (alg) is unavailable.";
const NO_KID: &str = r#"no "kid" provided in the JWT"#;
const NO_KEY: &str = r#"unable to find an appropriate key in the JWKS. Ensure a "kid" is provided in the JWT, and that your JWKS has a supported cert available for this ID"#;
const BAD_SIGNATURE: &str = "crypto/rsa: verification error";
const EXPIRED: &str = "the token has expired";
const WRONG_AUDIENCE: &str = "the token does not have a valid audience";

/// Go's URL-safe decoder: padding optional once the text is padded out, and
/// leftover bits in the last character ignored.
const GO_URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

/// A `WWW-Authenticate` header value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Challenge(HeaderValue);

impl Challenge {
    /// What a request without a token is answered with.
    pub(super) const fn bare() -> Self {
        Self(HeaderValue::from_static("Bearer"))
    }

    /// What a refused `token` is answered with on a route asking for `scopes`.
    pub(super) fn refused(scopes: &[String], token: &str, error: &TokenError) -> Self {
        let mut value = format!(
            r#"Bearer scope="{}" error="invalid_token""#,
            scopes.join(" ")
        );
        if let Some(description) = Self::describe(token, error) {
            value.push_str(r#" error_description=""#);
            value.push_str(&description);
            value.push('"');
        }
        HeaderValue::from_str(&value).map_or_else(|_| Self::bare(), Self)
    }

    pub(crate) fn into_header(self) -> HeaderValue {
        self.0
    }

    #[cfg(test)]
    pub(crate) fn as_str(&self) -> &str {
        self.0.to_str().unwrap_or_default()
    }

    /// API Gateway's description of why `token` was refused, where it is known.
    /// What it finds wrong before looking for a key comes first, in its order;
    /// `error` decides the rest.
    fn describe(token: &str, error: &TokenError) -> Option<String> {
        let header = match Self::read(token) {
            Ok(header) => header,
            Err(description) => return description,
        };
        let known = match *error {
            // A key that was looked for too recently to look again is as
            // unknown as one that was not found.
            TokenError::Key(KeyError::UnknownKey(_) | KeyError::Throttled) => NO_KEY,
            // What is left of a token API Gateway reads further than this
            // gateway does: a key ID that is not text names no key.
            TokenError::Malformed(_) if !header.get("kid").is_some_and(Value::is_string) => NO_KEY,
            // API Gateway tries the key whatever algorithm it is published for.
            TokenError::KeyAlgorithm(_) => BAD_SIGNATURE,
            TokenError::Signature(_) => {
                let signature = token
                    .rsplit_once('.')
                    .map_or("", |(_, signature)| signature);
                return Some(match Base64Segment(signature).decode() {
                    Ok(_) => BAD_SIGNATURE.to_owned(),
                    Err(offset) => Self::corrupt(offset),
                });
            }
            TokenError::Expired => EXPIRED,
            TokenError::Audience => WRONG_AUDIENCE,
            TokenError::Malformed(_)
            | TokenError::Algorithm(_)
            | TokenError::NoKeyId
            | TokenError::Issuer
            | TokenError::Key(
                KeyError::Fetch { .. }
                | KeyError::Status { .. }
                | KeyError::TooLarge { .. }
                | KeyError::Malformed { .. }
                | KeyError::Location(_),
            )
            | TokenError::Time(_)
            | TokenError::NotYetValid
            | TokenError::IssuedInFuture => return None,
        };
        Some(known.to_owned())
    }

    /// Reads `token` the way API Gateway does up to the point where it looks
    /// for a key, which is when it has the header this returns. `Err(None)`
    /// is a refusal whose wording is not known.
    fn read(token: &str) -> Result<Map<String, Value>, Option<String>> {
        let mut parts = token.split('.');
        let (Some(header), Some(payload), Some(_signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(Some(SEGMENTS.to_owned()));
        };
        let header = Base64Segment(header).decode().map_err(|offset| {
            Some(if token.to_ascii_lowercase().starts_with("bearer ") {
                BEARER_PREFIX.to_owned()
            } else {
                Self::corrupt(offset)
            })
        })?;
        let header = GoJson::Unmarshal.object(&header)?;
        let payload = Base64Segment(payload)
            .decode()
            .map_err(|offset| Some(Self::corrupt(offset)))?;
        GoJson::Decoder.object(&payload)?;
        let Some(Value::String(algorithm)) = header.get("alg") else {
            return Err(Some(ALG_UNSPECIFIED.to_owned()));
        };
        match algorithm.as_str() {
            "RS256" | "RS384" | "RS512" => {}
            "PS256" | "PS384" | "PS512" | "ES256" | "ES384" | "ES512" | "HS256" | "HS384"
            | "HS512" | "none" => {
                return Err(Some(format!("signing method {algorithm} is invalid")));
            }
            _ => return Err(Some(ALG_UNAVAILABLE.to_owned())),
        }
        if header.contains_key("kid") {
            Ok(header)
        } else {
            Err(Some(NO_KID.to_owned()))
        }
    }

    fn corrupt(offset: usize) -> String {
        format!("illegal base64 data at input byte {offset}")
    }
}

/// One dot-separated part of a token.
struct Base64Segment<'a>(&'a str);

impl Base64Segment<'_> {
    /// The decoded bytes, or the offset Go's decoder reports the text as
    /// corrupt at once it is padded to a multiple of four characters.
    fn decode(&self) -> Result<Vec<u8>, usize> {
        let mut padded = self.0.as_bytes().to_vec();
        while !padded.len().is_multiple_of(4) {
            padded.push(b'=');
        }
        match Self::corrupt_at(&padded) {
            Some(offset) => Err(offset),
            None => GO_URL.decode(&padded).map_err(|_| 0),
        }
    }

    /// Where Go's `base64.URLEncoding` stops on `padded`: at a character
    /// outside the alphabet, at padding in the first half of a group of four,
    /// or at whatever follows complete padding.
    fn corrupt_at(padded: &[u8]) -> Option<usize> {
        for (index, &byte) in padded.iter().enumerate() {
            if byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' {
                continue;
            }
            if byte != b'=' {
                return Some(index);
            }
            let (_, from_padding) = padded.split_at(index);
            return match (index % 4, from_padding) {
                (2, [_, b'=']) | (3, [_]) => None,
                (2, [_, b'=', _, ..]) => Some(index.saturating_add(2)),
                (3, [_, _, ..]) => Some(index.saturating_add(1)),
                (2, [_]) => Some(padded.len()),
                _ => Some(index),
            };
        }
        None
    }
}

/// Which of Go's two JSON readers API Gateway reads a part with. They word
/// missing input differently, and only one minds what follows the value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GoJson {
    /// `json.Unmarshal`, for the header.
    Unmarshal,
    /// `json.Decoder`, for the claims.
    Decoder,
}

impl GoJson {
    fn object(self, bytes: &[u8]) -> Result<Map<String, Value>, Option<String>> {
        let mut values = serde_json::Deserializer::from_slice(bytes).into_iter::<Value>();
        let value = match values.next() {
            None => return Err(Some(self.empty().to_owned())),
            Some(Err(error)) => {
                return Err(self.bad_literal(bytes).or_else(|| {
                    if error.is_eof() {
                        Some(self.truncated().to_owned())
                    } else {
                        Self::bad_start(bytes)
                    }
                }));
            }
            Some(Ok(value)) => value,
        };
        if self == Self::Unmarshal {
            let (_, after) = bytes.split_at(values.byte_offset().min(bytes.len()));
            if let Some(&extra) = after.iter().find(|byte| !byte.is_ascii_whitespace()) {
                return Err(Some(format!(
                    "invalid character {} after top-level value",
                    Self::quoted(extra)
                )));
            }
        }
        let kind = match value {
            Value::Object(object) => return Ok(object),
            Value::Null => return Ok(Map::new()),
            Value::Array(_) => "array",
            Value::String(_) => "string",
            Value::Number(_) => "number",
            Value::Bool(_) => "bool",
        };
        Err(Some(format!(
            "json: cannot unmarshal {kind} into Go value of type {}",
            self.target()
        )))
    }

    const fn empty(self) -> &'static str {
        match self {
            Self::Unmarshal => "unexpected end of JSON input",
            Self::Decoder => "EOF",
        }
    }

    const fn truncated(self) -> &'static str {
        match self {
            Self::Unmarshal => "unexpected end of JSON input",
            Self::Decoder => "unexpected EOF",
        }
    }

    const fn target(self) -> &'static str {
        match self {
            Self::Unmarshal => "map[string]interface {}",
            Self::Decoder => "jwt.MapClaims",
        }
    }

    /// Go's complaint about a `true`, `false`, or `null` that goes wrong
    /// partway. `json.Unmarshal` reads the end of the input as a space.
    fn bad_literal(self, bytes: &[u8]) -> Option<String> {
        let start = bytes.iter().position(|byte| !byte.is_ascii_whitespace())?;
        let (_, text) = bytes.split_at(start);
        let literal = match text.first()? {
            b't' => "true",
            b'f' => "false",
            b'n' => "null",
            _ => return None,
        };
        let mut sent = text.iter();
        for expected in literal.bytes() {
            let found = match (sent.next(), self) {
                (Some(&found), _) => found,
                (None, Self::Unmarshal) => b' ',
                (None, Self::Decoder) => return None,
            };
            if found != expected {
                return Some(format!(
                    "invalid character {} in literal {literal} (expecting '{}')",
                    Self::quoted(found),
                    char::from(expected)
                ));
            }
        }
        // A complete literal with something stuck to it.
        match (sent.next(), self) {
            (Some(&extra), Self::Unmarshal) if !extra.is_ascii_whitespace() => Some(format!(
                "invalid character {} after top-level value",
                Self::quoted(extra)
            )),
            (Some(_) | None, Self::Unmarshal | Self::Decoder) => None,
        }
    }

    /// Go's complaint about text that cannot start a JSON value. Any other
    /// syntax error is worded in ways not reproduced here.
    fn bad_start(bytes: &[u8]) -> Option<String> {
        let &first = bytes.iter().find(|byte| !byte.is_ascii_whitespace())?;
        if matches!(
            first,
            b'{' | b'[' | b'"' | b'-' | b'0'..=b'9' | b't' | b'f' | b'n'
        ) {
            return None;
        }
        Some(format!(
            "invalid character {} looking for beginning of value",
            Self::quoted(first)
        ))
    }

    /// A byte the way Go's JSON errors quote it: as the character with that
    /// number, escaped when it does not print.
    fn quoted(byte: u8) -> String {
        match byte {
            b'\'' => r"'\''".to_owned(),
            b'\\' => r"'\\'".to_owned(),
            0x07 => r"'\a'".to_owned(),
            0x08 => r"'\b'".to_owned(),
            0x0b => r"'\v'".to_owned(),
            0x0c => r"'\f'".to_owned(),
            0x00..=0x1f | 0x7f => format!(r"'\x{byte:02x}'"),
            0x80..=0xa0 | 0xad => format!(r"'\u{byte:04x}'"),
            b' '..=b'~' | 0xa1..=0xff => format!("'{}'", char::from(byte)),
        }
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use proptest::prelude::*;

    use super::*;

    const REAL_HEADER: &str = r#"{"alg":"RS256","kid":"k"}"#;

    fn encode(text: &str) -> String {
        URL_SAFE_NO_PAD.encode(text)
    }

    fn token(header: &str, payload: &str) -> String {
        format!("{}.{}.{}", encode(header), encode(payload), encode("sig"))
    }

    fn read(token: &str) -> Option<String> {
        Challenge::read(token).err().flatten()
    }

    /// Every row is a token sent to a deployed HTTP API and the description it
    /// answered with.
    #[test]
    fn refusals_before_the_key_lookup_are_worded_as_measured() {
        let cases = [
            (String::new(), SEGMENTS.to_owned()),
            ("x".to_owned(), SEGMENTS.to_owned()),
            ("a.b".to_owned(), SEGMENTS.to_owned()),
            ("a.b.c.d".to_owned(), SEGMENTS.to_owned()),
            ("Basic abc".to_owned(), SEGMENTS.to_owned()),
            ("bearer a.b.c".to_owned(), BEARER_PREFIX.to_owned()),
            ("BEARER a.b.c".to_owned(), BEARER_PREFIX.to_owned()),
            ("a.b.c".to_owned(), Challenge::corrupt(1)),
            (" a.b.c".to_owned(), Challenge::corrupt(0)),
            ("abcd!fgh.e30.x".to_owned(), Challenge::corrupt(4)),
            ("abcde.e30.x".to_owned(), Challenge::corrupt(5)),
            (
                "Bearera.b.c".to_owned(),
                r"invalid character '\x05' looking for beginning of value".to_owned(),
            ),
            (
                "abcdef.e30.x".to_owned(),
                "invalid character 'i' looking for beginning of value".to_owned(),
            ),
            ("e30=.e30.x".to_owned(), ALG_UNSPECIFIED.to_owned()),
            (
                ".e30.x".to_owned(),
                "unexpected end of JSON input".to_owned(),
            ),
            (
                format!("{}.!.x", encode(REAL_HEADER)),
                Challenge::corrupt(0),
            ),
            (format!("{}..x", encode(REAL_HEADER)), "EOF".to_owned()),
            (
                token("[1]", "{}"),
                "json: cannot unmarshal array into Go value of type map[string]interface {}"
                    .to_owned(),
            ),
            (
                token(r#""s""#, "{}"),
                "json: cannot unmarshal string into Go value of type map[string]interface {}"
                    .to_owned(),
            ),
            (
                token("5", "{}"),
                "json: cannot unmarshal number into Go value of type map[string]interface {}"
                    .to_owned(),
            ),
            (
                token("true", "{}"),
                "json: cannot unmarshal bool into Go value of type map[string]interface {}"
                    .to_owned(),
            ),
            (token("null", "{}"), ALG_UNSPECIFIED.to_owned()),
            (
                token("{} x", "{}"),
                "invalid character 'x' after top-level value".to_owned(),
            ),
            (
                token("'x", "{}"),
                r"invalid character '\'' looking for beginning of value".to_owned(),
            ),
            (token(" ", "{}"), "unexpected end of JSON input".to_owned()),
            (
                token(r#"{"alg":"#, "{}"),
                "unexpected end of JSON input".to_owned(),
            ),
            (
                token(REAL_HEADER, "[1]"),
                "json: cannot unmarshal array into Go value of type jwt.MapClaims".to_owned(),
            ),
            (
                token(REAL_HEADER, r#""s""#),
                "json: cannot unmarshal string into Go value of type jwt.MapClaims".to_owned(),
            ),
        ];
        for (token, expected) in cases {
            let expected = Some(expected).filter(|text| !text.is_empty());
            assert_eq!(read(&token), expected, "{token:?}");
        }
    }

    /// Measured like the rows above.
    #[test]
    fn a_broken_json_literal_is_worded_as_go_words_it() {
        let cases = [
            (
                token("nojson", "{}"),
                "invalid character 'o' in literal null (expecting 'u')".to_owned(),
            ),
            (
                token("nul", "{}"),
                "invalid character ' ' in literal null (expecting 'l')".to_owned(),
            ),
            (
                token("fals}", "{}"),
                "invalid character '}' in literal false (expecting 'e')".to_owned(),
            ),
            (
                token("trux", "{}"),
                "invalid character 'x' in literal true (expecting 'e')".to_owned(),
            ),
            (
                token(r"nu\", "{}"),
                r"invalid character '\\' in literal null (expecting 'l')".to_owned(),
            ),
            (
                token("nullx", "{}"),
                "invalid character 'x' after top-level value".to_owned(),
            ),
            // Go has more to say about JSON that goes wrong inside an object.
            (token(r#"{"alg" 1}"#, "{}"), String::new()),
        ];
        for (token, expected) in cases {
            let expected = Some(expected).filter(|text| !text.is_empty());
            assert_eq!(read(&token), expected, "{token:?}");
        }
    }

    /// Measured like the rows above.
    #[test]
    fn an_unusable_algorithm_or_a_missing_key_id_is_named() {
        let cases = [
            (token(r#"{"kid":"k"}"#, "{}"), ALG_UNSPECIFIED.to_owned()),
            (
                token(r#"{"alg":5,"kid":"k"}"#, "{}"),
                ALG_UNSPECIFIED.to_owned(),
            ),
            (
                token(r#"{"alg":"FOO","kid":"k"}"#, "{}"),
                ALG_UNAVAILABLE.to_owned(),
            ),
            (
                token(r#"{"alg":"rs256","kid":"k"}"#, "{}"),
                ALG_UNAVAILABLE.to_owned(),
            ),
            (
                token(r#"{"alg":"","kid":"k"}"#, "{}"),
                ALG_UNAVAILABLE.to_owned(),
            ),
            (
                token(r#"{"alg":"none"}"#, "{}"),
                "signing method none is invalid".to_owned(),
            ),
            (
                token(r#"{"alg":"HS256","kid":"k"}"#, "{}"),
                "signing method HS256 is invalid".to_owned(),
            ),
            (
                token(r#"{"alg":"ES256","kid":"k"}"#, "{}"),
                "signing method ES256 is invalid".to_owned(),
            ),
            (
                token(r#"{"alg":"PS256","kid":"k"}"#, "{}"),
                "signing method PS256 is invalid".to_owned(),
            ),
            (token(r#"{"alg":"RS256"}"#, "{}"), NO_KID.to_owned()),
        ];
        for (token, expected) in cases {
            let expected = Some(expected).filter(|text| !text.is_empty());
            assert_eq!(read(&token), expected, "{token:?}");
        }
    }

    #[test]
    fn tokens_api_gateway_goes_on_to_find_a_key_for_are_read_without_complaint() {
        for header in [
            REAL_HEADER,
            r#"{"alg":"RS384","kid":5}"#,
            r#"{"alg":"RS512","kid":null}"#,
            r#"{"alg":"RS256","kid":""}"#,
        ] {
            for payload in ["{}", "null", "{} x"] {
                assert!(Challenge::read(&token(header, payload)).is_ok());
            }
        }
    }

    #[test]
    fn later_refusals_are_worded_by_what_failed() {
        let good = token(REAL_HEADER, "{}");
        let describe = |token: &str, error: TokenError| Challenge::describe(token, &error);
        assert_eq!(
            describe(&good, TokenError::Key(KeyError::UnknownKey("k".to_owned()))).as_deref(),
            Some(NO_KEY)
        );
        assert_eq!(describe(&good, TokenError::Issuer), None);
        assert_eq!(
            describe(&good, TokenError::Key(KeyError::Throttled)).as_deref(),
            Some(NO_KEY)
        );
        assert_eq!(
            describe(
                &token(r#"{"alg":"RS256","kid":5}"#, "{}"),
                TokenError::Malformed(String::new())
            )
            .as_deref(),
            Some(NO_KEY)
        );
        assert_eq!(describe(&good, TokenError::Malformed(String::new())), None);
        assert_eq!(
            describe(&good, TokenError::Signature(String::new())).as_deref(),
            Some(BAD_SIGNATURE)
        );
        let unsigned = format!("{}.{}.", encode(REAL_HEADER), encode("{}"));
        assert_eq!(
            describe(&unsigned, TokenError::Signature(String::new())).as_deref(),
            Some(BAD_SIGNATURE)
        );
        let garbled = format!("{}.{}.!!", encode(REAL_HEADER), encode("{}"));
        assert_eq!(
            describe(&garbled, TokenError::Signature(String::new())),
            Some(Challenge::corrupt(0))
        );
        assert_eq!(
            describe(&good, TokenError::Expired).as_deref(),
            Some(EXPIRED)
        );
        assert_eq!(
            describe(&good, TokenError::Audience).as_deref(),
            Some(WRONG_AUDIENCE)
        );
        assert_eq!(describe(&good, TokenError::NotYetValid), None);
        assert_eq!(describe(&good, TokenError::IssuedInFuture), None);
        assert_eq!(describe(&good, TokenError::Time("exp")), None);
    }

    #[test]
    fn the_challenge_names_the_routes_scopes() {
        let none = Challenge::refused(&[], "x", &TokenError::Issuer);
        assert_eq!(
            none.as_str(),
            r#"Bearer scope="" error="invalid_token" error_description="token contains an invalid number of segments""#
        );
        let scoped = Challenge::refused(
            &["read".to_owned(), "write".to_owned()],
            &token(REAL_HEADER, "{}"),
            &TokenError::NotYetValid,
        );
        assert_eq!(
            scoped.as_str(),
            r#"Bearer scope="read write" error="invalid_token""#
        );
        assert_eq!(Challenge::bare().as_str(), "Bearer");
    }

    #[test]
    fn a_scope_no_header_can_carry_leaves_a_bare_challenge() {
        let challenge = Challenge::refused(&["a\nb".to_owned()], "x", &TokenError::Issuer);
        assert_eq!(challenge, Challenge::bare());
    }

    proptest! {
        #[test]
        fn any_token_gets_a_challenge(token in ".{0,80}", scope in ".{0,12}") {
            let challenge = Challenge::refused(&[scope], &token, &TokenError::Issuer);
            prop_assert!(challenge.into_header().as_bytes().starts_with(b"Bearer"));
        }

        #[test]
        fn what_the_strict_decoder_takes_decodes_the_same(bytes in proptest::collection::vec(any::<u8>(), 0..40)) {
            let encoded = URL_SAFE_NO_PAD.encode(&bytes);
            prop_assert_eq!(Base64Segment(&encoded).decode(), Ok(bytes));
        }
    }
}
