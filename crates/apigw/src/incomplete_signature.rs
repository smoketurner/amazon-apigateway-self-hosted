//! What a REST API says to a request no route claims that carries an
//! `Authorization` header or Signature Version 4 query-string parameters.
//!
//! Such a request is taken for an attempt at Signature Version 4, and is read
//! as one before the missing route is reported. The wording
//! below was measured against a deployed REST API; every message carries the
//! header's SHA-256 digest in Base64 instead of the header.

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::digest::Sha256Digest;
use crate::gateway_response::Failure;
use crate::model::ResponseType;
use crate::pipeline::context::QueryString;

const INCOMPLETE: &str = "IncompleteSignatureException";
const UNRECOGNIZED: &str = "UnrecognizedClientException";
const INVALID: &str = "InvalidSignatureException";
/// The parameters a Signature Version 4 header must have, in the order API
/// Gateway reports the missing ones.
const REQUIRED: [&str; 3] = ["Credential", "Signature", "SignedHeaders"];

/// What a request no route claimed says about who signed it: an
/// `Authorization` header, or Signature Version 4 query-string parameters.
pub(crate) enum UnclaimedSignature<'a> {
    Header(&'a str),
    Query(Vec<(String, String)>),
}

impl<'a> UnclaimedSignature<'a> {
    /// `None` when the request carries neither, or an empty header: it is
    /// then simply a request for a route that does not exist.
    pub(crate) fn of(headers: &'a HeaderMap, query: &QueryString) -> Option<Self> {
        if let Some(value) = headers.get("authorization").and_then(|v| v.to_str().ok())
            && !value.is_empty()
        {
            return Some(Self::Header(value));
        }
        let pairs = query.pairs();
        pairs
            .iter()
            .any(|(name, _)| name == "X-Amz-Algorithm")
            .then_some(Self::Query(pairs))
    }

    /// The `403` API Gateway answers with.
    pub(crate) fn failure(&self, headers: &HeaderMap, now: jiff::Timestamp) -> Failure {
        let date = match *self {
            Self::Header(value) => match Self::header_parameters(value, headers) {
                Ok(()) => ["x-amz-date", "date"]
                    .iter()
                    .find_map(|name| headers.get(*name))
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                Err(failure) => return failure,
            },
            Self::Query(ref pairs) => match Self::query_parameters(pairs) {
                Ok(date) => Some(date),
                Err(failure) => return failure,
            },
        };
        SignatureDate(date.unwrap_or_default()).failure(now)
    }

    fn refuse(message: String, error_type: &'static str) -> Failure {
        Failure::new(ResponseType::MissingAuthenticationToken)
            .with_message(message)
            .with_error_type(error_type)
    }

    fn digest(value: &str) -> String {
        BASE64.encode(Sha256Digest::of(value.as_bytes()).as_bytes())
    }

    /// Checks that the header has the shape of a Signature Version 4 header
    /// and that the request is dated.
    fn header_parameters(value: &str, headers: &HeaderMap) -> Result<(), Failure> {
        let (algorithm, parameters) = value.split_once(' ').unwrap_or((value, ""));
        if algorithm.contains('=') {
            return Err(Self::refuse(
                format!(
                    "Authorization header must begin with the algorithm name, which cannot include an equal-sign (hashed with SHA-256 and encoded with Base64): '{}'.",
                    Self::digest(value)
                ),
                INCOMPLETE,
            ));
        }
        let mut names = Vec::new();
        for parameter in parameters.split(',').map(str::trim) {
            if parameter.is_empty() {
                continue;
            }
            let Some((name, _)) = parameter.split_once('=') else {
                return Err(Self::refuse(
                    format!(
                        "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with SHA-256 and encoded with Base64): '{}'.",
                        Self::digest(value)
                    ),
                    INCOMPLETE,
                ));
            };
            names.push(name);
        }
        let mut missing: Vec<String> = REQUIRED
            .iter()
            .filter(|required| !names.contains(required))
            .map(|required| format!("Authorization header requires '{required}' parameter."))
            .collect();
        if !headers.contains_key("x-amz-date") && !headers.contains_key("date") {
            missing.push(
                "Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header."
                    .to_owned(),
            );
        }
        if missing.is_empty() {
            return Ok(());
        }
        Err(Self::refuse(
            format!(
                "{} (Hashed with SHA-256 and encoded with Base64) Authorization={}",
                missing.join(" "),
                Self::digest(value)
            ),
            INCOMPLETE,
        ))
    }

    /// Checks that a pre-signed URL names everything a signature needs, and
    /// returns its date.
    fn query_parameters(pairs: &[(String, String)]) -> Result<String, Failure> {
        let value = |wanted: &str| {
            pairs
                .iter()
                .find(|(name, _)| name == wanted)
                .map(|(_, value)| value.clone())
        };
        let missing: Vec<String> = REQUIRED
            .iter()
            .chain(&["Date"])
            .filter(|required| value(&format!("X-Amz-{required}")).is_none())
            .map(|required| format!("AWS query-string parameters must include 'X-Amz-{required}'."))
            .collect();
        match value("X-Amz-Date") {
            Some(date) if missing.is_empty() => Ok(date),
            Some(_) | None => Err(Self::refuse(
                format!(
                    "{} Re-examine the query-string parameters.",
                    missing.join(" ")
                ),
                INCOMPLETE,
            )),
        }
    }
}

/// The date a complete signature was made at, as the request states it.
struct SignatureDate(String);

impl SignatureDate {
    const FORMAT: &'static str = "%Y%m%dT%H%M%SZ";
    /// How far a signature's date may be from the present.
    const WINDOW: jiff::SignedDuration = jiff::SignedDuration::from_mins(5);

    fn basic(at: jiff::Timestamp) -> String {
        at.strftime(Self::FORMAT).to_string()
    }

    /// A complete signature is refused for its date when that is unreadable
    /// or more than five minutes off, and otherwise for its credentials, which
    /// a gateway outside AWS has no way to recognize.
    fn failure(&self, now: jiff::Timestamp) -> Failure {
        // The basic format always ends in `Z`; read it as the offset it means.
        let stated = self.0.strip_suffix('Z').and_then(|civil| {
            jiff::Timestamp::strptime("%Y%m%dT%H%M%S%z", format!("{civil}+0000")).ok()
        });
        let Some(stated) = stated else {
            return UnclaimedSignature::refuse(
                format!(
                    "Date must be in ISO-8601 'basic format'. Got '{}'. See http://en.wikipedia.org/wiki/ISO_8601",
                    self.0
                ),
                INCOMPLETE,
            );
        };
        let (earliest, latest) = (
            now.saturating_sub(Self::WINDOW).unwrap_or(now),
            now.saturating_add(Self::WINDOW).unwrap_or(now),
        );
        if stated < earliest {
            return UnclaimedSignature::refuse(
                format!(
                    "Signature expired: {} is now earlier than {} ({} - 5 min.)",
                    self.0,
                    Self::basic(earliest),
                    Self::basic(now)
                ),
                INVALID,
            );
        }
        if stated > latest {
            return UnclaimedSignature::refuse(
                format!(
                    "Signature not yet current: {} is still later than {} ({} + 5 min.)",
                    self.0,
                    Self::basic(latest),
                    Self::basic(now)
                ),
                INVALID,
            );
        }
        UnclaimedSignature::refuse(
            "The security token included in the request is invalid.".to_owned(),
            UNRECOGNIZED,
        )
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    /// The moment the dated examples below were measured at.
    fn now() -> jiff::Timestamp {
        "2026-11-19T15:51:58Z".parse().unwrap()
    }

    fn header_message(
        authorization: &'static str,
        date: Option<(&'static str, &'static str)>,
    ) -> String {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static(authorization));
        if let Some((name, value)) = date {
            headers.insert(name, HeaderValue::from_static(value));
        }
        UnclaimedSignature::of(&headers, &QueryString::new(None))
            .unwrap()
            .failure(&headers, now())
            .message()
            .to_owned()
    }

    fn query_message(query: &str) -> String {
        let headers = HeaderMap::new();
        UnclaimedSignature::of(&headers, &QueryString::new(Some(query)))
            .unwrap()
            .failure(&headers, now())
            .message()
            .to_owned()
    }

    const COMPLETE: &str = "AWS4-HMAC-SHA256 Credential=AKID/20261119/us-east-1/execute-api/aws4_request, SignedHeaders=host, Signature=abc";
    const AMZ_DATE: Option<(&str, &str)> = Some(("x-amz-date", "20261119T154500Z"));

    /// Every expected string here is what a deployed REST API answered.
    #[test]
    fn header_messages_match_a_deployed_api() {
        assert_eq!(
            header_message("allow", None),
            "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. (Hashed with SHA-256 and encoded with Base64) Authorization=QQCDc1c1oQ5lihnt0XBOYGyd0RLiJYJbY/r+3tdmyLk="
        );
        assert_eq!(
            header_message("allow", AMZ_DATE),
            "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. (Hashed with SHA-256 and encoded with Base64) Authorization=QQCDc1c1oQ5lihnt0XBOYGyd0RLiJYJbY/r+3tdmyLk="
        );
        assert_eq!(
            header_message("Bearer abc", None),
            "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with SHA-256 and encoded with Base64): 'w1Xc6WwWEogNEZQP/dkBTThsJT4MNlKmzQanIm970rY='."
        );
        assert_eq!(
            header_message("X Credential=a", None),
            "Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. (Hashed with SHA-256 and encoded with Base64) Authorization=SYAkdgL47E1r9n/fae+kwe9DITo3gFOXojeT+lp4DyI="
        );
        assert_eq!(
            header_message("a=b", None),
            "Authorization header must begin with the algorithm name, which cannot include an equal-sign (hashed with SHA-256 and encoded with Base64): 'QhRPOTnD/7vwv4sfEq/7XCOkxb1B4P9nLVSldU8GIFg='."
        );
        assert_eq!(
            header_message("x a=b, c", None),
            "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with SHA-256 and encoded with Base64): 'daWcjc2/uVr+gp7dvUGFQlbsw1Q3ZuhylRubarsvzu0='."
        );
        // Parameter names are case-sensitive.
        assert!(
            header_message("X credential=a, signature=b, signedheaders=c", None)
                .starts_with("Authorization header requires 'Credential' parameter.")
        );
    }

    /// A complete signature is judged by its date next; these too were measured.
    #[test]
    fn a_complete_signature_is_refused_for_its_date_or_its_credentials() {
        assert_eq!(
            header_message(COMPLETE, AMZ_DATE),
            "Signature expired: 20261119T154500Z is now earlier than 20261119T154658Z (20261119T155158Z - 5 min.)"
        );
        assert_eq!(
            header_message(COMPLETE, Some(("date", "20261119T154500Z"))),
            "Signature expired: 20261119T154500Z is now earlier than 20261119T154658Z (20261119T155158Z - 5 min.)"
        );
        assert_eq!(
            header_message(COMPLETE, Some(("x-amz-date", "yesterday"))),
            "Date must be in ISO-8601 'basic format'. Got 'yesterday'. See http://en.wikipedia.org/wiki/ISO_8601"
        );
        assert_eq!(
            header_message(COMPLETE, Some(("date", "Thu, 19 Nov 2026 15:45:00 GMT"))),
            "Date must be in ISO-8601 'basic format'. Got 'Thu, 19 Nov 2026 15:45:00 GMT'. See http://en.wikipedia.org/wiki/ISO_8601"
        );
        assert_eq!(
            header_message(COMPLETE, Some(("x-amz-date", "20261119T155000Z"))),
            "The security token included in the request is invalid."
        );
        assert!(
            header_message(COMPLETE, Some(("x-amz-date", "20261119T160000Z"))).starts_with(
                "Signature not yet current: 20261119T160000Z is still later than 20261119T155658Z"
            )
        );
    }

    #[test]
    fn query_string_messages_match_a_deployed_api() {
        assert_eq!(
            query_message("X-Amz-Algorithm=AWS4-HMAC-SHA256"),
            "AWS query-string parameters must include 'X-Amz-Credential'. AWS query-string parameters must include 'X-Amz-Signature'. AWS query-string parameters must include 'X-Amz-SignedHeaders'. AWS query-string parameters must include 'X-Amz-Date'. Re-examine the query-string parameters."
        );
        assert_eq!(
            query_message("X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=a"),
            "AWS query-string parameters must include 'X-Amz-Signature'. AWS query-string parameters must include 'X-Amz-SignedHeaders'. AWS query-string parameters must include 'X-Amz-Date'. Re-examine the query-string parameters."
        );
        assert_eq!(
            query_message(
                "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKID&X-Amz-Signature=abc&X-Amz-SignedHeaders=host&X-Amz-Date=20261119T154500Z"
            ),
            "Signature expired: 20261119T154500Z is now earlier than 20261119T154658Z (20261119T155158Z - 5 min.)"
        );
    }

    #[test]
    fn a_request_that_claims_no_signature_is_just_unrouted() {
        let mut headers = HeaderMap::new();
        let none = QueryString::new(Some("a=1"));
        assert!(UnclaimedSignature::of(&headers, &none).is_none());
        headers.insert("authorization", HeaderValue::from_static(""));
        assert!(UnclaimedSignature::of(&headers, &none).is_none());
    }
}
