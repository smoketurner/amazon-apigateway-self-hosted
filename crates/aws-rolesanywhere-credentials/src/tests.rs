use std::time::{Duration, SystemTime};

use aws_credential_types::provider::ProvideCredentials as _;
use aws_credential_types::provider::error::CredentialsError;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, UnparsedPublicKey};
use aws_smithy_async::test_util::{InstantSleep, ManualTimeSource, instant_time_and_sleep};
use aws_smithy_runtime_api::client::orchestrator::HttpRequest;
use aws_smithy_types::error::display::DisplayErrorContext;
use aws_smithy_types::retry::RetryConfig;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rcgen::PKCS_ECDSA_P256_SHA256;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use super::*;
use crate::key::Algorithm;
use crate::testing::{FakeHttp, Pki, SERIAL, TempDir};

const ANCHOR: &str = "arn:aws:rolesanywhere:us-east-1:111122223333:trust-anchor/anchor-id";
const PROFILE: &str = "arn:aws:rolesanywhere:us-east-1:111122223333:profile/profile-id";
const ROLE: &str = "arn:aws:iam::111122223333:role/gateway";
const NOW: &str = "2026-11-23T12:00:00Z";
const QUERY: &str = "profileArn=arn%3Aaws%3Arolesanywhere%3Aus-east-1%3A111122223333%3Aprofile%2Fprofile-id\
    &roleArn=arn%3Aaws%3Aiam%3A%3A111122223333%3Arole%2Fgateway\
    &trustAnchorArn=arn%3Aaws%3Arolesanywhere%3Aus-east-1%3A111122223333%3Atrust-anchor%2Fanchor-id";
const CREDENTIALS: &str = r#"{"credentialSet":[{"credentials":{
    "accessKeyId":"ASIAEXAMPLE","secretAccessKey":"secret","sessionToken":"token",
    "expiration":"2026-11-23T14:00:00Z"}}],"subjectArn":"arn:aws:rolesanywhere:us-east-1:1:subject/s"}"#;

struct Fixture {
    dir: TempDir,
    pki: Pki,
    certificate: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new();
        let pki = Pki::issue(&PKCS_ECDSA_P256_SHA256);
        let (certificate, key) = pki.write(&dir);
        Self {
            dir,
            pki,
            certificate,
            key,
        }
    }

    /// A complete builder, configured with an HTTP client that answers nothing.
    fn builder(&self) -> Builder {
        RolesAnywhereCredentialsProvider::builder()
            .configure(&sdk(&FakeHttp::default()).config)
            .certificate_path(&self.certificate)
            .private_key_path(&self.key)
            .trust_anchor_arn(ANCHOR.parse().unwrap())
            .profile_arn(PROFILE.parse().unwrap())
            .role_arn(ROLE)
    }
}

struct Sdk {
    config: SdkConfig,
    sleep: InstantSleep,
    time: ManualTimeSource,
}

fn sdk(client: &FakeHttp) -> Sdk {
    let now: jiff::Timestamp = NOW.parse().unwrap();
    let (time, sleep) = instant_time_and_sleep(SystemTime::try_from(now).unwrap());
    let config = SdkConfig::builder()
        .http_client(client.clone())
        .time_source(time.clone())
        .sleep_impl(sleep.clone())
        .retry_config(RetryConfig::standard())
        .behavior_version(BehaviorVersion::latest())
        .build();
    Sdk {
        config,
        sleep,
        time,
    }
}

fn header<'a>(request: &'a HttpRequest, name: &str) -> &'a str {
    request
        .headers()
        .get(name)
        .unwrap_or_else(|| panic!("no {name} header"))
}

fn unhex(text: &str) -> Vec<u8> {
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    assert_eq!(rest.len(), 0, "odd-length hex");
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

/// Rebuilds the canonical request from what was sent and checks the signature in its
/// `Authorization` header with the certificate's public key, as Roles Anywhere does.
fn assert_signed_by(request: &HttpRequest, leaf_der: &[u8]) {
    let authorization = header(request, "authorization");
    let (_, signature) = authorization.split_once(", Signature=").unwrap();
    let mut headers = vec![
        ("content-type", header(request, "content-type")),
        ("host", header(request, "host")),
        ("x-amz-date", header(request, "x-amz-date")),
        ("x-amz-x509", header(request, "x-amz-x509")),
    ];
    if let Some(chain) = request.headers().get("x-amz-x509-chain") {
        headers.push(("x-amz-x509-chain", chain));
    }
    let body = request.body().bytes().unwrap();
    let (_, query) = request.uri().split_once('?').unwrap();
    let canonical = signing::canonical_request(query, &headers, &signing::sha256_hex(body));
    let date = header(request, "x-amz-date");
    let time = jiff::Timestamp::strptime("%Y%m%dT%H%M%SZ%z", format!("{date}+0000")).unwrap();
    let string_to_sign = signing::string_to_sign(
        Algorithm::Ecdsa,
        date,
        &signing::scope(time, "us-east-1"),
        &canonical,
    );
    let (_, leaf) = X509Certificate::from_der(leaf_der).unwrap();
    UnparsedPublicKey::new(
        &ECDSA_P256_SHA256_ASN1,
        &leaf.public_key().subject_public_key.data,
    )
    .verify(string_to_sign.as_bytes(), &unhex(signature))
    .unwrap();
}

#[tokio::test]
async fn create_session_is_signed_with_the_certificate_and_returns_its_credentials() {
    let fixture = Fixture::new();
    let client = FakeHttp::new([(201, CREDENTIALS)]);
    let sdk = sdk(&client);
    let provider = fixture
        .builder()
        .session_duration(Duration::from_hours(2))
        .configure(&sdk.config)
        .build()
        .unwrap();

    let credentials = provider.provide_credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAEXAMPLE");
    assert_eq!(credentials.secret_access_key(), "secret");
    assert_eq!(credentials.session_token(), Some("token"));
    let expiry: jiff::Timestamp = "2026-11-23T14:00:00Z".parse().unwrap();
    assert_eq!(
        credentials.expiry(),
        Some(SystemTime::try_from(expiry).unwrap())
    );

    let requests = client.requests();
    let [request] = requests.as_slice() else {
        panic!("expected one request, got {}", requests.len());
    };
    assert_eq!(request.method(), "POST");
    assert_eq!(
        request.uri(),
        format!("https://rolesanywhere.us-east-1.amazonaws.com/sessions?{QUERY}")
    );
    assert_eq!(
        header(request, "host"),
        "rolesanywhere.us-east-1.amazonaws.com"
    );
    assert_eq!(header(request, "content-type"), "application/json");
    assert_eq!(header(request, "x-amz-date"), "20261123T120000Z");
    let leaf = STANDARD.encode(&fixture.pki.leaf_der);
    assert_eq!(header(request, "x-amz-x509"), leaf);
    assert_eq!(
        header(request, "x-amz-x509-chain"),
        STANDARD.encode(&fixture.pki.intermediate_der)
    );
    assert_eq!(
        request.body().bytes().unwrap(),
        br#"{"durationSeconds":7200}"#
    );
    let serial = u128::from_be_bytes(SERIAL);
    assert!(
        header(request, "authorization").starts_with(&format!(
            "AWS4-X509-ECDSA-SHA256 Credential={serial}/20261123/us-east-1/rolesanywhere/\
             aws4_request, SignedHeaders=content-type;host;x-amz-date;x-amz-x509;\
             x-amz-x509-chain, Signature="
        )),
        "{}",
        header(request, "authorization")
    );
    assert_signed_by(request, &fixture.pki.leaf_der);
}

#[tokio::test]
async fn a_renewed_certificate_is_used_from_the_next_refresh() {
    let fixture = Fixture::new();
    let client = FakeHttp::new([(201, CREDENTIALS), (201, CREDENTIALS)]);
    let sdk = sdk(&client);
    let provider = fixture.builder().configure(&sdk.config).build().unwrap();
    provider.provide_credentials().await.unwrap();

    let renewed = Pki::issue(&PKCS_ECDSA_P256_SHA256);
    renewed.write(&fixture.dir);
    sdk.time.advance(Duration::from_hours(1));
    provider.provide_credentials().await.unwrap();

    let requests = client.requests();
    let [first, second] = requests.as_slice() else {
        panic!("expected two requests, got {}", requests.len());
    };
    assert_eq!(
        header(first, "x-amz-x509"),
        STANDARD.encode(&fixture.pki.leaf_der)
    );
    assert_eq!(
        header(second, "x-amz-x509"),
        STANDARD.encode(&renewed.leaf_der)
    );
    assert_eq!(header(second, "x-amz-date"), "20261123T130000Z");
    assert_signed_by(second, &renewed.leaf_der);
}

#[tokio::test]
async fn service_errors_are_provider_errors_with_the_service_message() {
    let fixture = Fixture::new();
    let client = FakeHttp::new([(403, r#"{"message":"Untrusted signing certificate."}"#)]);
    let sdk = sdk(&client);
    let provider = fixture.builder().configure(&sdk.config).build().unwrap();
    let error = provider.provide_credentials().await.unwrap_err();
    assert!(
        matches!(error, CredentialsError::ProviderError(_)),
        "{error:?}"
    );
    let message = DisplayErrorContext(&error).to_string();
    assert!(
        message.contains("CreateSession answered 403: Untrusted signing certificate."),
        "{message}"
    );
    assert_eq!(client.requests().len(), 1, "403 is not retried");
}

#[tokio::test]
async fn server_errors_are_retried() {
    let fixture = Fixture::new();
    let client = FakeHttp::new([(503, "{}"), (201, CREDENTIALS)]);
    let sdk = sdk(&client);
    let provider = fixture.builder().configure(&sdk.config).build().unwrap();
    let credentials = provider.provide_credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAEXAMPLE");
    assert_eq!(client.requests().len(), 2);
    assert_eq!(sdk.sleep.logs().len(), 1);
}

#[tokio::test]
async fn files_that_become_unusable_are_configuration_errors() {
    let fixture = Fixture::new();
    let client = FakeHttp::default();
    let sdk = sdk(&client);
    let provider = fixture.builder().configure(&sdk.config).build().unwrap();
    std::fs::remove_file(&fixture.key).unwrap();
    let error = provider.provide_credentials().await.unwrap_err();
    assert!(
        matches!(error, CredentialsError::InvalidConfiguration(_)),
        "{error:?}"
    );
    assert_eq!(client.requests().len(), 0);
}

#[tokio::test]
async fn an_endpoint_url_replaces_the_region_endpoint_and_its_port_is_signed() {
    let fixture = Fixture::new();
    let client = FakeHttp::new([(201, CREDENTIALS)]);
    let sdk = sdk(&client);
    let provider = fixture
        .builder()
        .endpoint_url("http://localhost:4566/ignored/")
        .configure(&sdk.config)
        .build()
        .unwrap();
    provider.provide_credentials().await.unwrap();
    let requests = client.requests();
    let request = requests.first().unwrap();
    assert_eq!(
        request.uri(),
        format!("http://localhost:4566/sessions?{QUERY}")
    );
    assert_eq!(header(request, "host"), "localhost:4566");
    assert_signed_by(request, &fixture.pki.leaf_der);
}

#[test]
fn every_required_setting_is_checked() {
    let fixture = Fixture::new();
    let anchor: TrustAnchorArn = ANCHOR.parse().unwrap();
    let profile: ProfileArn = PROFILE.parse().unwrap();
    let offline = sdk(&FakeHttp::default()).config;
    let complete = || fixture.builder();
    let error = |builder: Builder| builder.build().unwrap_err().to_string();
    assert!(complete().build().is_ok());
    assert_eq!(
        error(
            Builder::default()
                .configure(&offline)
                .private_key_path(&fixture.key)
                .trust_anchor_arn(anchor.clone())
                .profile_arn(profile.clone())
                .role_arn(ROLE)
        ),
        "a certificate path is required"
    );
    assert_eq!(
        error(
            Builder::default()
                .configure(&offline)
                .certificate_path(&fixture.certificate)
                .trust_anchor_arn(anchor.clone())
                .profile_arn(profile.clone())
                .role_arn(ROLE)
        ),
        "a private key path is required"
    );
    assert_eq!(
        error(
            Builder::default()
                .configure(&offline)
                .certificate_path(&fixture.certificate)
                .private_key_path(&fixture.key)
                .profile_arn(profile.clone())
                .role_arn(ROLE)
        ),
        "a trust anchor ARN is required"
    );
    assert_eq!(
        error(
            Builder::default()
                .configure(&offline)
                .certificate_path(&fixture.certificate)
                .private_key_path(&fixture.key)
                .trust_anchor_arn(anchor.clone())
                .role_arn(ROLE)
        ),
        "a profile ARN is required"
    );
    assert_eq!(
        error(
            Builder::default()
                .configure(&offline)
                .certificate_path(&fixture.certificate)
                .private_key_path(&fixture.key)
                .trust_anchor_arn(anchor)
                .profile_arn(profile)
        ),
        "a role ARN is required"
    );
}

#[test]
fn the_trust_anchor_and_profile_must_share_a_region() {
    let fixture = Fixture::new();
    let error = fixture
        .builder()
        .profile_arn(
            "arn:aws:rolesanywhere:eu-west-1:111122223333:profile/p"
                .parse()
                .unwrap(),
        )
        .build()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "the trust anchor is in us-east-1 but the profile is in eu-west-1"
    );
}

#[test]
fn session_durations_are_limited_to_what_roles_anywhere_allows() {
    let fixture = Fixture::new();
    for seconds in [900, 3600, 43_200] {
        assert!(
            fixture
                .builder()
                .session_duration(Duration::from_secs(seconds))
                .build()
                .is_ok(),
            "{seconds}"
        );
    }
    for seconds in [0, 899, 43_201, u64::MAX] {
        let error = fixture
            .builder()
            .session_duration(Duration::from_secs(seconds))
            .build()
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("the session duration must be 900 to 43200 seconds, not {seconds}")
        );
    }
}

#[test]
fn an_unknown_partition_needs_an_endpoint_url() {
    let fixture = Fixture::new();
    let iso = || {
        fixture
            .builder()
            .trust_anchor_arn(
                "arn:aws-iso:rolesanywhere:us-iso-east-1:1:trust-anchor/t"
                    .parse()
                    .unwrap(),
            )
            .profile_arn(
                "arn:aws-iso:rolesanywhere:us-iso-east-1:1:profile/p"
                    .parse()
                    .unwrap(),
            )
    };
    assert_eq!(
        iso().build().unwrap_err().to_string(),
        "no Roles Anywhere endpoint is known for partition \"aws-iso\"; set an endpoint URL"
    );
    assert!(
        iso()
            .endpoint_url("https://rolesanywhere.us-iso-east-1.c2s.ic.gov")
            .build()
            .is_ok()
    );
}

#[test]
fn endpoints_need_an_http_scheme_and_a_host() {
    let fixture = Fixture::new();
    for bad in [
        "",
        "rolesanywhere.us-east-1.amazonaws.com",
        "/sessions",
        "ftp://rolesanywhere.example.test",
        "https://user@rolesanywhere.example.test",
        "not a url",
    ] {
        let error = fixture.builder().endpoint_url(bad).build().unwrap_err();
        assert!(matches!(error, BuildError::Endpoint(_)), "{bad:?}: {error}");
    }
    assert_eq!(
        endpoint_origin("https://[::1]:8443/ignored/path"),
        Some(("https://[::1]:8443".to_owned(), "[::1]:8443".to_owned()))
    );
}

#[test]
fn unusable_certificates_fail_the_build() {
    let fixture = Fixture::new();
    let error = fixture
        .builder()
        .private_key_path(fixture.dir.path("missing.key"))
        .build()
        .unwrap_err();
    assert!(
        matches!(error, BuildError::Identity(IdentityError::ReadKey { .. })),
        "{error}"
    );
}

#[test]
#[cfg(not(feature = "default-https-client"))]
fn without_the_default_client_an_http_client_must_be_configured() {
    let fixture = Fixture::new();
    let error = fixture
        .builder()
        .configure(&SdkConfig::builder().build())
        .build()
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        "no HTTP client: configure one through an SdkConfig or enable the default-https-client feature"
    );
}

#[test]
#[cfg(feature = "default-https-client")]
fn with_the_default_client_no_configuration_is_needed() {
    let fixture = Fixture::new();
    assert!(
        fixture
            .builder()
            .configure(&SdkConfig::builder().build())
            .build()
            .is_ok()
    );
}
