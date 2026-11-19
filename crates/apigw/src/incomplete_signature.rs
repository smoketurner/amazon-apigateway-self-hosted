//! What a REST API says to a request with an `Authorization` header that no
//! route claims.
//!
//! Such a request is taken for an attempt at Signature Version 4, and the
//! header is read as one before the missing route is reported. The wording
//! below was measured against a deployed REST API; every message carries the
//! header's SHA-256 digest in Base64 instead of the header.

use axum::http::HeaderMap;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;

use crate::digest::Sha256Digest;
use crate::gateway_response::Failure;
use crate::model::ResponseType;

const INCOMPLETE: &str = "IncompleteSignatureException";
const UNRECOGNIZED: &str = "UnrecognizedClientException";
/// The parameters a Signature Version 4 header must have, in the order API
/// Gateway reports the missing ones.
const REQUIRED: [&str; 3] = ["Credential", "Signature", "SignedHeaders"];

/// The `Authorization` header of a request no route claimed.
pub(crate) struct UnclaimedAuthorization<'a>(&'a str);

impl<'a> UnclaimedAuthorization<'a> {
    /// `None` when the request has no `Authorization` header, or an empty one:
    /// it is then simply a request for a route that does not exist.
    pub(crate) fn of(headers: &'a HeaderMap) -> Option<Self> {
        let value = headers.get("authorization")?.to_str().ok()?;
        (!value.is_empty()).then_some(Self(value))
    }

    fn digest(&self) -> String {
        BASE64.encode(Sha256Digest::of(self.0.as_bytes()).as_bytes())
    }

    /// The `403` API Gateway answers with.
    pub(crate) fn failure(&self, headers: &HeaderMap) -> Failure {
        let refuse = |message: String, error_type| {
            Failure::new(ResponseType::MissingAuthenticationToken)
                .with_message(message)
                .with_error_type(error_type)
        };
        let (algorithm, parameters) = self.0.split_once(' ').unwrap_or((self.0, ""));
        if algorithm.contains('=') {
            return refuse(
                format!(
                    "Authorization header must begin with the algorithm name, which cannot include an equal-sign (hashed with SHA-256 and encoded with Base64): '{}'.",
                    self.digest()
                ),
                INCOMPLETE,
            );
        }
        let mut names = Vec::new();
        for parameter in parameters.split(',').map(str::trim) {
            if parameter.is_empty() {
                continue;
            }
            let Some((name, _)) = parameter.split_once('=') else {
                return refuse(
                    format!(
                        "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with SHA-256 and encoded with Base64): '{}'.",
                        self.digest()
                    ),
                    INCOMPLETE,
                );
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
            // A complete header names credentials, which a gateway outside
            // AWS has no way to recognize.
            return refuse(
                "The security token included in the request is invalid.".to_owned(),
                UNRECOGNIZED,
            );
        }
        refuse(
            format!(
                "{} (Hashed with SHA-256 and encoded with Base64) Authorization={}",
                missing.join(" "),
                self.digest()
            ),
            INCOMPLETE,
        )
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use axum::http::HeaderValue;

    use super::*;

    fn message(authorization: &'static str, date: bool) -> String {
        let mut headers = HeaderMap::new();
        headers.insert("authorization", HeaderValue::from_static(authorization));
        if date {
            headers.insert("x-amz-date", HeaderValue::from_static("20261119T154500Z"));
        }
        UnclaimedAuthorization::of(&headers)
            .unwrap()
            .failure(&headers)
            .message()
            .to_owned()
    }

    /// Every expected string here is what a deployed REST API answered.
    #[test]
    fn messages_match_a_deployed_api() {
        assert_eq!(
            message("allow", false),
            "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. (Hashed with SHA-256 and encoded with Base64) Authorization=QQCDc1c1oQ5lihnt0XBOYGyd0RLiJYJbY/r+3tdmyLk="
        );
        assert_eq!(
            message("allow", true),
            "Authorization header requires 'Credential' parameter. Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. (Hashed with SHA-256 and encoded with Base64) Authorization=QQCDc1c1oQ5lihnt0XBOYGyd0RLiJYJbY/r+3tdmyLk="
        );
        assert_eq!(
            message("Bearer abc", false),
            "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with SHA-256 and encoded with Base64): 'w1Xc6WwWEogNEZQP/dkBTThsJT4MNlKmzQanIm970rY='."
        );
        assert_eq!(
            message("X Credential=a", false),
            "Authorization header requires 'Signature' parameter. Authorization header requires 'SignedHeaders' parameter. Authorization header requires existence of either a 'X-Amz-Date' or a 'Date' header. (Hashed with SHA-256 and encoded with Base64) Authorization=SYAkdgL47E1r9n/fae+kwe9DITo3gFOXojeT+lp4DyI="
        );
        assert_eq!(
            message("a=b", false),
            "Authorization header must begin with the algorithm name, which cannot include an equal-sign (hashed with SHA-256 and encoded with Base64): 'QhRPOTnD/7vwv4sfEq/7XCOkxb1B4P9nLVSldU8GIFg='."
        );
        assert_eq!(
            message("x a=b, c", false),
            "Invalid key=value pair (missing equal-sign) in Authorization header (hashed with SHA-256 and encoded with Base64): 'daWcjc2/uVr+gp7dvUGFQlbsw1Q3ZuhylRubarsvzu0='."
        );
        assert_eq!(
            message(
                "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261119/us-east-1/execute-api/aws4_request, SignedHeaders=host, Signature=abc",
                true
            ),
            "The security token included in the request is invalid."
        );
        // Parameter names are case-sensitive.
        assert!(
            message("X credential=a, signature=b, signedheaders=c", false)
                .starts_with("Authorization header requires 'Credential' parameter.")
        );
    }

    #[test]
    fn a_request_without_the_header_is_just_unrouted() {
        let mut headers = HeaderMap::new();
        assert!(UnclaimedAuthorization::of(&headers).is_none());
        headers.insert("authorization", HeaderValue::from_static(""));
        assert!(UnclaimedAuthorization::of(&headers).is_none());
    }
}
