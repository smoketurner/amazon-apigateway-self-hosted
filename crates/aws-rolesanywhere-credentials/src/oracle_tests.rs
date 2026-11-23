//! Checks against requests the AWS credential helper (`aws_signing_helper`) signed, recorded by
//! `tools/rolesanywhere-oracle`.

use std::collections::BTreeMap;

use aws_lc_rs::signature::UnparsedPublicKey;
use rustls_pki_types::pem::PemObject as _;
use serde::Deserialize;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::identity::Identity;
use crate::session::CreateSessionBody;
use crate::signing;
use crate::testing::TempDir;

const FIXTURES: &str = include_str!("../tests/fixtures/signing-helper.json");
const TRUST_ANCHOR: &str = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/anchor-id";
const PROFILE: &str = "arn:aws:rolesanywhere:us-east-1:111122223333:profile/profile-id";
const ROLE: &str = "arn:aws:iam::111122223333:role/gateway";

#[derive(Deserialize)]
struct Fixture {
    name: String,
    certificate: String,
    #[serde(default)]
    intermediates: String,
    private_key: String,
    request: Recorded,
}

#[derive(Deserialize)]
struct Recorded {
    method: String,
    path: String,
    query: String,
    headers: BTreeMap<String, String>,
    body: String,
}

fn unhex(text: &str) -> Vec<u8> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    assert_eq!(rest.len(), 0, "odd-length hex");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn every_key_type_and_chain_shape_is_recorded() {
    let fixtures: Vec<Fixture> = serde_json::from_str(FIXTURES).unwrap();
    let names: Vec<_> = fixtures
        .iter()
        .map(|fixture| fixture.name.as_str())
        .collect();
    assert_eq!(
        names,
        [
            "rsa-2048",
            "rsa-2048-chain",
            "p256",
            "p256-chain",
            "p384-chain",
            "p521"
        ]
    );
}

#[test]
fn the_credential_helpers_requests_match_this_crates_signing() {
    let fixtures: Vec<Fixture> = serde_json::from_str(FIXTURES).unwrap();
    for fixture in fixtures {
        let name = fixture.name.as_str();
        let request = &fixture.request;
        let header = |header: &str| {
            request
                .headers
                .get(header)
                .map_or_else(|| panic!("{name}: no {header} header"), String::as_str)
        };
        assert_eq!(request.method, "POST", "{name}");
        assert_eq!(request.path, signing::PATH, "{name}");

        let dir = TempDir::new();
        let certificate = dir.write(
            "tls.crt",
            format!("{}{}", fixture.certificate, fixture.intermediates),
        );
        let key = dir.write("tls.key", &fixture.private_key);
        let identity = Identity::load(&certificate, &key).unwrap();
        assert_eq!(header("x-amz-x509"), identity.certificate, "{name}");
        assert_eq!(
            request.headers.get("x-amz-x509-chain"),
            identity.chain.as_ref(),
            "{name}"
        );
        assert_eq!(header("content-type"), signing::CONTENT_TYPE, "{name}");

        let query = signing::canonical_query(&[
            ("profileArn", PROFILE),
            ("roleArn", ROLE),
            ("trustAnchorArn", TRUST_ANCHOR),
        ]);
        assert_eq!(request.query, query, "{name}");
        let body = serde_json::to_string(&CreateSessionBody {
            duration_seconds: 3600,
        })
        .unwrap();
        assert_eq!(request.body, body, "{name}");

        let date = header("x-amz-date");
        let time = jiff::Timestamp::strptime("%Y%m%dT%H%M%SZ%z", format!("{date}+0000")).unwrap();
        let scope = signing::scope(time, "us-east-1");
        let authorization = header("authorization");
        let algorithm = identity.key.algorithm();
        let prefix = format!(
            "{} Credential={}/{scope}, SignedHeaders=",
            algorithm.name(),
            identity.serial
        );
        let rest = authorization
            .strip_prefix(&prefix)
            .unwrap_or_else(|| panic!("{name}: {authorization} does not start with {prefix}"));
        let (signed_headers, signature) = rest.split_once(", Signature=").unwrap();

        let headers: Vec<(&str, &str)> = signed_headers
            .split(';')
            .map(|signed| (signed, header(signed)))
            .collect();
        let canonical = signing::canonical_request(
            &request.query,
            &headers,
            &signing::sha256_hex(request.body.as_bytes()),
        );
        let string_to_sign = signing::string_to_sign(algorithm, date, &scope, &canonical);
        let pem = rustls_pki_types::CertificateDer::from_pem_slice(fixture.certificate.as_bytes())
            .unwrap();
        let (_, leaf) = X509Certificate::from_der(&pem).unwrap();
        UnparsedPublicKey::new(
            identity.key.verification_algorithm(),
            &leaf.public_key().subject_public_key.data,
        )
        .verify(string_to_sign.as_bytes(), &unhex(signature))
        .unwrap_or_else(|_| panic!("{name}: the helper's signature does not verify"));
    }
}
