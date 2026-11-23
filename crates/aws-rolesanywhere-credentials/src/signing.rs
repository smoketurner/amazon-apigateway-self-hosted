//! The SigV4-X509 signature of a `CreateSession` request.
//!
//! The process is `SigV4`'s, except that the certificate's private key signs the string to sign
//! directly (no derived HMAC key), the algorithm names the key type, and the certificate's
//! serial number stands in for the access key ID. See
//! <https://docs.aws.amazon.com/rolesanywhere/latest/userguide/authentication-sign-process.html>.

use aws_lc_rs::digest::{SHA256, digest};

use crate::identity::Identity;
use crate::key::Algorithm;

pub(crate) const SERVICE: &str = "rolesanywhere";
pub(crate) const PATH: &str = "/sessions";
pub(crate) const CONTENT_TYPE: &str = "application/json";

/// The headers of a signed `CreateSession` request, beside `Host`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SignedHeaders {
    pub(crate) date: String,
    pub(crate) certificate: String,
    pub(crate) chain: Option<String>,
    pub(crate) authorization: String,
}

/// Signs a `CreateSession` request to `host` in `region` at `time`, with the canonical `query`
/// (see [`canonical_query`]) and `body`, or `None` if the key fails to sign.
pub(crate) fn sign(
    identity: &Identity,
    region: &str,
    host: &str,
    query: &str,
    time: jiff::Timestamp,
    body: &[u8],
) -> Option<SignedHeaders> {
    let date = time.strftime("%Y%m%dT%H%M%SZ").to_string();
    let mut headers = vec![
        ("content-type", CONTENT_TYPE),
        ("host", host),
        ("x-amz-date", date.as_str()),
        ("x-amz-x509", identity.certificate.as_str()),
    ];
    if let Some(chain) = &identity.chain {
        headers.push(("x-amz-x509-chain", chain.as_str()));
    }
    let canonical = canonical_request(query, &headers, &sha256_hex(body));
    let algorithm = identity.key.algorithm();
    let scope = scope(time, region);
    let signature = identity
        .key
        .sign(string_to_sign(algorithm, &date, &scope, &canonical).as_bytes())?;
    let authorization = authorization(
        algorithm,
        &identity.serial,
        &scope,
        &signed_header_names(&headers),
        &hex(&signature),
    );
    Some(SignedHeaders {
        date,
        certificate: identity.certificate.clone(),
        chain: identity.chain.clone(),
        authorization,
    })
}

/// The query string of `parameters` in canonical form: sorted by name, then value, with both
/// percent-encoded. It is sent exactly as signed.
pub(crate) fn canonical_query(parameters: &[(&str, &str)]) -> String {
    let mut sorted = parameters.to_vec();
    sorted.sort_unstable();
    let mut query = String::new();
    for (name, value) in sorted {
        if !query.is_empty() {
            query.push('&');
        }
        percent_encode(&mut query, name);
        query.push('=');
        percent_encode(&mut query, value);
    }
    query
}

/// Appends `text` with every byte but RFC 3986's unreserved characters written as `%XX`.
fn percent_encode(out: &mut String, text: &str) {
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            for nibble in [byte >> 4, byte & 0x0f] {
                out.extend(char::from_digit(u32::from(nibble), 16).map(|c| c.to_ascii_uppercase()));
            }
        }
    }
}

/// The canonical form of a `POST /sessions` request with the canonical `query` and `headers`,
/// which must be lowercase names in sorted order with values that need no trimming.
pub(crate) fn canonical_request(
    query: &str,
    headers: &[(&str, &str)],
    payload_hash: &str,
) -> String {
    let mut canonical = format!("POST\n{PATH}\n{query}\n");
    for (name, value) in headers {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(value);
        canonical.push('\n');
    }
    canonical.push('\n');
    canonical.push_str(&signed_header_names(headers));
    canonical.push('\n');
    canonical.push_str(payload_hash);
    canonical
}

pub(crate) fn signed_header_names(headers: &[(&str, &str)]) -> String {
    let mut names = String::new();
    for (index, (name, _)) in headers.iter().enumerate() {
        if index > 0 {
            names.push(';');
        }
        names.push_str(name);
    }
    names
}

/// `{yyyymmdd}/{region}/rolesanywhere/aws4_request`.
pub(crate) fn scope(time: jiff::Timestamp, region: &str) -> String {
    format!(
        "{}/{region}/{SERVICE}/aws4_request",
        time.strftime("%Y%m%d")
    )
}

pub(crate) fn string_to_sign(
    algorithm: Algorithm,
    date: &str,
    scope: &str,
    canonical_request: &str,
) -> String {
    format!(
        "{}\n{date}\n{scope}\n{}",
        algorithm.name(),
        sha256_hex(canonical_request.as_bytes())
    )
}

pub(crate) fn authorization(
    algorithm: Algorithm,
    serial: &str,
    scope: &str,
    signed_headers: &str,
    signature: &str,
) -> String {
    format!(
        "{} Credential={serial}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        algorithm.name()
    )
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex(digest(&SHA256, bytes).as_ref())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        for nibble in [byte >> 4, byte & 0x0f] {
            out.extend(char::from_digit(u32::from(nibble), 16));
        }
    }
    out
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
mod tests {
    use super::*;

    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    /// The example canonical request from the AWS signing-process guide.
    #[test]
    fn canonical_request_matches_the_documented_example() {
        let headers = [
            ("content-type", "application/json"),
            ("host", "rolesanywhere.us-east-1.amazonaws.com"),
            ("x-amz-date", "20211103T120000Z"),
            ("x-amz-x509", "{base64-encoded DER data}"),
        ];
        assert_eq!(
            canonical_request("", &headers, EMPTY_SHA256),
            "POST\n/sessions\n\n\
             content-type:application/json\n\
             host:rolesanywhere.us-east-1.amazonaws.com\n\
             x-amz-date:20211103T120000Z\n\
             x-amz-x509:{base64-encoded DER data}\n\
             \n\
             content-type;host;x-amz-date;x-amz-x509\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_chain_is_a_signed_header() {
        let headers = [
            ("host", "h"),
            ("x-amz-x509", "a"),
            ("x-amz-x509-chain", "b,c"),
        ];
        let canonical = canonical_request("a=b", &headers, EMPTY_SHA256);
        assert!(
            canonical.starts_with("POST\n/sessions\na=b\n"),
            "{canonical}"
        );
        assert!(canonical.contains("x-amz-x509-chain:b,c\n"), "{canonical}");
        assert!(
            canonical.ends_with(&format!(
                "\nhost;x-amz-x509;x-amz-x509-chain\n{EMPTY_SHA256}"
            )),
            "{canonical}"
        );
    }

    #[test]
    fn string_to_sign_and_authorization_follow_the_documented_layout() {
        let time: jiff::Timestamp = "2020-11-05T12:00:00Z".parse().unwrap();
        let scope = scope(time, "us-east-1");
        assert_eq!(scope, "20201105/us-east-1/rolesanywhere/aws4_request");
        assert_eq!(
            string_to_sign(Algorithm::Ecdsa, "20201105T120000Z", &scope, ""),
            format!(
                "AWS4-X509-ECDSA-SHA256\n20201105T120000Z\n\
                 20201105/us-east-1/rolesanywhere/aws4_request\n{EMPTY_SHA256}"
            )
        );
        assert_eq!(
            authorization(
                Algorithm::Rsa,
                "11111222223333344444",
                &scope,
                "content-type;host;x-amz-date;x-amz-x509",
                "abcd"
            ),
            "AWS4-X509-RSA-SHA256 Credential=11111222223333344444/20201105/us-east-1/\
             rolesanywhere/aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509, \
             Signature=abcd"
        );
    }

    #[test]
    fn the_query_is_sorted_and_percent_encoded_as_the_credential_helper_sends_it() {
        assert_eq!(
            canonical_query(&[
                (
                    "trustAnchorArn",
                    "arn:aws:rolesanywhere:us-east-1:1:trust-anchor/t"
                ),
                ("roleArn", "arn:aws:iam::1:role/path/r"),
                ("profileArn", "arn:aws:rolesanywhere:us-east-1:1:profile/p"),
            ]),
            "profileArn=arn%3Aaws%3Arolesanywhere%3Aus-east-1%3A1%3Aprofile%2Fp\
             &roleArn=arn%3Aaws%3Aiam%3A%3A1%3Arole%2Fpath%2Fr\
             &trustAnchorArn=arn%3Aaws%3Arolesanywhere%3Aus-east-1%3A1%3Atrust-anchor%2Ft"
        );
        assert_eq!(
            canonical_query(&[("b", "2"), ("a", "1"), ("a", "0")]),
            "a=0&a=1&b=2"
        );
        assert_eq!(
            canonical_query(&[("k", "a b+c=d&é~")]),
            "k=a%20b%2Bc%3Dd%26%C3%A9~"
        );
        assert_eq!(canonical_query(&[]), "");
    }

    proptest::proptest! {
        #[test]
        fn percent_encoding_round_trips_through_unreserved_characters_and_escapes(text in ".*") {
            let mut encoded = String::new();
            percent_encode(&mut encoded, &text);
            let mut decoded = Vec::new();
            let mut bytes = encoded.bytes();
            while let Some(byte) = bytes.next() {
                if byte == b'%' {
                    let pair = [bytes.next().unwrap(), bytes.next().unwrap()];
                    proptest::prop_assert!(pair.iter().all(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b)));
                    decoded.push(u8::from_str_radix(std::str::from_utf8(&pair).unwrap(), 16).unwrap());
                } else {
                    proptest::prop_assert!(byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte));
                    decoded.push(byte);
                }
            }
            proptest::prop_assert_eq!(decoded, text.into_bytes());
        }
    }

    #[test]
    fn hex_is_lowercase_and_zero_padded() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa0, 0xff]), "000fa0ff");
        assert_eq!(hex(&[]), "");
        assert_eq!(sha256_hex(b""), EMPTY_SHA256);
    }
}
