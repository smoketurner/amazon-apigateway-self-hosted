//! Token authorizers end to end: a real router and key store in front of a
//! local identity provider that serves discovery documents and key sets, with
//! tokens signed by locally generated RSA keys. Nothing here reaches AWS.

#![expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#![expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]
#![expect(
    clippy::arithmetic_side_effects,
    reason = "test timestamps are small offsets from now"
)]

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Duration;

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{KeyPair, KeySize, PublicKeyComponents};
use aws_lc_rs::signature::{
    KeyPair as _, RSA_PKCS1_SHA256, RSA_PKCS1_SHA384, RSA_PKCS1_SHA512, RSA_PSS_SHA256,
};
use axum::Router;
use axum::http::{Method, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde_json::{Value, json};

use super::keys::{Issuer, KeyError, KeyLocation};
use super::{IssuerEndpoint, KeyStore};
use crate::authz::tests::{Harness, echo_integration};
use crate::gateway::AuthorizationMode;
use crate::model::ApiKind;

const HTTP_ISSUER: &str = "https://idp.example.com/tenant";
const POOL: &str = "us-east-1_PoolA";
const COGNITO_ISSUER: &str = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_PoolA";
const OTHER_COGNITO_ISSUER: &str = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_PoolB";

fn now() -> i64 {
    jiff::Timestamp::now().as_second()
}

/// An RSA signing key and the JWK that publishes its public half.
struct TestKey {
    pair: KeyPair,
    kid: &'static str,
}

#[derive(Clone, Copy)]
enum Alg {
    Rs256,
    Rs384,
    Rs512,
    /// RSA-PSS, which is not among the algorithms accepted.
    Ps256,
}

impl Alg {
    fn name(self) -> &'static str {
        match self {
            Self::Rs256 => "RS256",
            Self::Rs384 => "RS384",
            Self::Rs512 => "RS512",
            Self::Ps256 => "PS256",
        }
    }
}

impl TestKey {
    fn generate(kid: &'static str) -> Self {
        Self {
            pair: KeyPair::generate(KeySize::Rsa2048).unwrap(),
            kid,
        }
    }

    fn jwk(&self) -> Value {
        let components = PublicKeyComponents::<Vec<u8>>::from(self.pair.public_key());
        json!({"kty": "RSA", "kid": self.kid, "use": "sig", "alg": "RS256",
            "n": B64.encode(&components.n), "e": B64.encode(&components.e)})
    }

    fn sign_with(&self, alg: Alg, header: &Value, claims: &Value) -> String {
        let signing_input = format!(
            "{}.{}",
            B64.encode(header.to_string()),
            B64.encode(claims.to_string())
        );
        let mut signature = vec![0_u8; self.pair.public_modulus_len()];
        let padding = match alg {
            Alg::Rs256 => &RSA_PKCS1_SHA256,
            Alg::Rs384 => &RSA_PKCS1_SHA384,
            Alg::Rs512 => &RSA_PKCS1_SHA512,
            Alg::Ps256 => &RSA_PSS_SHA256,
        };
        self.pair
            .sign(
                padding,
                &SystemRandom::new(),
                signing_input.as_bytes(),
                &mut signature,
            )
            .unwrap();
        format!("{signing_input}.{}", B64.encode(signature))
    }

    /// A valid RS256 token for `claims`.
    fn token(&self, claims: &Value) -> String {
        self.sign_with(
            Alg::Rs256,
            &json!({"alg": "RS256", "typ": "JWT", "kid": self.kid}),
            claims,
        )
    }
}

/// Generating RSA keys is slow enough to share them between tests.
fn key_a() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| TestKey::generate("key-a"))
}

fn key_b() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| TestKey::generate("key-b"))
}

/// A different key that claims `key-a`'s id.
fn forger() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| TestKey::generate("key-a"))
}

#[derive(Debug, Clone)]
enum IdpMode {
    Normal,
    Status(StatusCode),
    Slow(Duration),
    /// A key set larger than the 150 KB cap.
    Huge,
    /// A discovery document naming another issuer.
    WrongIssuer,
    /// A discovery document whose `jwks_uri` is not http(s).
    UnusableJwksUri,
    /// Not JSON.
    Garbage,
}

struct IdpState {
    issuer: String,
    keys: Mutex<Vec<Value>>,
    mode: Mutex<IdpMode>,
    discovery_hits: AtomicUsize,
    jwks_hits: AtomicUsize,
}

/// A local identity provider.
struct Idp {
    addr: SocketAddr,
    state: Arc<IdpState>,
}

impl Idp {
    async fn start(issuer: &str, keys: &[&TestKey]) -> Self {
        let state = Arc::new(IdpState {
            issuer: issuer.to_owned(),
            keys: Mutex::new(keys.iter().map(|k| k.jwk()).collect()),
            mode: Mutex::new(IdpMode::Normal),
            discovery_hits: AtomicUsize::new(0),
            jwks_hits: AtomicUsize::new(0),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let discovery = Arc::clone(&state);
        let jwks = Arc::clone(&state);
        let well_known = Arc::clone(&state);
        let app = Router::new()
            .route(
                "/.well-known/openid-configuration",
                get(move || {
                    let state = Arc::clone(&discovery);
                    async move { Self::discovery(&state, addr).await }
                }),
            )
            .route(
                "/jwks",
                get(move || {
                    let state = Arc::clone(&jwks);
                    async move { Self::key_set(&state).await }
                }),
            )
            .route(
                "/.well-known/jwks.json",
                get(move || {
                    let state = Arc::clone(&well_known);
                    async move { Self::key_set(&state).await }
                }),
            );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        Self { addr, state }
    }

    fn mode(state: &IdpState) -> IdpMode {
        state
            .mode
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    async fn discovery(state: &IdpState, addr: SocketAddr) -> (StatusCode, String) {
        state.discovery_hits.fetch_add(1, Ordering::SeqCst);
        match Self::mode(state) {
            IdpMode::Status(status) => (status, String::new()),
            IdpMode::Slow(delay) => {
                tokio::time::sleep(delay).await;
                (StatusCode::OK, "{}".to_owned())
            }
            IdpMode::WrongIssuer => (
                StatusCode::OK,
                json!({"issuer": "https://evil.example", "jwks_uri": format!("http://{addr}/jwks")})
                    .to_string(),
            ),
            IdpMode::UnusableJwksUri => (
                StatusCode::OK,
                json!({"issuer": state.issuer, "jwks_uri": "ftp://idp.example/jwks"}).to_string(),
            ),
            IdpMode::Garbage => (StatusCode::OK, "not json".to_owned()),
            IdpMode::Normal | IdpMode::Huge => (
                StatusCode::OK,
                json!({"issuer": state.issuer, "jwks_uri": format!("http://{addr}/jwks")})
                    .to_string(),
            ),
        }
    }

    async fn key_set(state: &IdpState) -> (StatusCode, String) {
        state.jwks_hits.fetch_add(1, Ordering::SeqCst);
        match Self::mode(state) {
            IdpMode::Status(status) => (status, String::new()),
            IdpMode::Slow(delay) => {
                tokio::time::sleep(delay).await;
                (StatusCode::OK, "{}".to_owned())
            }
            IdpMode::Huge => {
                let filler = "x".repeat(160 * 1024);
                let keys = state
                    .keys
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                (
                    StatusCode::OK,
                    json!({"keys": keys, "padding": filler}).to_string(),
                )
            }
            IdpMode::Garbage => (StatusCode::OK, "not json".to_owned()),
            IdpMode::Normal | IdpMode::WrongIssuer | IdpMode::UnusableJwksUri => {
                let keys = state
                    .keys
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                (StatusCode::OK, json!({"keys": keys}).to_string())
            }
        }
    }

    fn set_mode(&self, mode: IdpMode) {
        *self
            .state
            .mode
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = mode;
    }

    fn set_keys(&self, keys: &[Value]) {
        *self
            .state
            .keys
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = keys.to_vec();
    }

    fn discovery_hits(&self) -> usize {
        self.state.discovery_hits.load(Ordering::SeqCst)
    }

    fn jwks_hits(&self) -> usize {
        self.state.jwks_hits.load(Ordering::SeqCst)
    }

    /// A key store that fetches `issuer`'s keys from this provider.
    fn key_store(&self, issuer: &str) -> KeyStore {
        let endpoint = format!("{issuer}=http://{}", self.addr).parse().unwrap();
        KeyStore::new(reqwest::Client::new(), [endpoint])
    }
}

fn http_doc(authorizer: &Value) -> Value {
    let mut config = json!({"type": "jwt", "identitySource": "$request.header.Authorization",
        "jwtConfiguration": {"issuer": HTTP_ISSUER, "audience": ["api", "api-2"]}});
    if let (Some(config), Some(extra)) = (config.as_object_mut(), authorizer.as_object()) {
        config.extend(extra.clone());
    }
    let route = |scopes: &[&str]| {
        json!({"get": {"security": [{"jwt": scopes}],
            "x-amazon-apigateway-integration": {"type": "aws_proxy", "httpMethod": "POST",
                "uri": crate::authz::tests::ECHO_FUNCTION, "payloadFormatVersion": "2.0"}}})
    };
    json!({
        "components": {"securitySchemes": {"jwt": {"type": "oauth2", "flows": {},
            "x-amazon-apigateway-authorizer": config}}},
        "paths": {"/pets": route(&[]), "/scoped": route(&["read", "admin"]),
            "/open": {"get": {"x-amazon-apigateway-integration": echo_integration()}}}
    })
}

async fn http_harness(idp: &Idp) -> Harness {
    http_harness_with(idp.key_store(HTTP_ISSUER)).await
}

async fn http_harness_with(keys: KeyStore) -> Harness {
    Harness::start_with(
        &http_doc(&json!({})),
        ApiKind::Http,
        AuthorizationMode::Enforce,
        keys,
    )
    .await
}

fn http_claims(overrides: &Value) -> Value {
    let mut claims = json!({"iss": HTTP_ISSUER, "aud": "api", "sub": "user-1",
        "scope": "read write", "iat": now() - 10, "exp": now() + 3600});
    if let (Some(claims), Some(extra)) = (claims.as_object_mut(), overrides.as_object()) {
        for (name, value) in extra {
            if value.is_null() {
                claims.remove(name);
            } else {
                claims.insert(name.clone(), value.clone());
            }
        }
    }
    claims
}

async fn get_with(h: &Harness, path: &str, token: &str) -> StatusCode {
    h.call(
        Method::GET,
        path,
        &[("authorization", &format!("Bearer {token}"))],
    )
    .await
    .0
}

async fn status_of(h: &Harness, token: &str) -> StatusCode {
    get_with(h, "/pets", token).await
}

#[tokio::test]
async fn a_valid_token_reaches_the_backend_with_its_claims() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let token = key_a().token(&http_claims(&json!({"cognito:groups": ["g1", "g2"]})));
    let (status, _) = h
        .call(Method::GET, "/pets", &[("authorization", &token)])
        .await;
    assert_eq!(status, StatusCode::OK, "a bare token is accepted");
    assert_eq!(
        status_of(&h, &token).await,
        StatusCode::OK,
        "so is a Bearer token"
    );
    let authorizer = h.backend_authorizer();
    let jwt = &authorizer["jwt"];
    assert_eq!(jwt["claims"]["sub"], "user-1");
    assert_eq!(jwt["claims"]["aud"], "api");
    assert_eq!(jwt["claims"]["iss"], HTTP_ISSUER);
    assert_eq!(jwt["claims"]["cognito:groups"], "[g1 g2]");
    assert!(
        jwt["claims"]["exp"]
            .as_str()
            .unwrap()
            .parse::<i64>()
            .is_ok()
    );
    assert_eq!(jwt["scopes"], json!(["read", "write"]));
    assert_eq!(h.backend_calls.count(), 2);
}

#[tokio::test]
async fn routes_without_the_authorizer_do_not_need_a_token() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    assert_eq!(h.call(Method::GET, "/open", &[]).await.0, StatusCode::OK);
    assert_eq!(idp.jwks_hits(), 0);
}

#[tokio::test]
async fn a_missing_or_empty_token_is_401_without_contacting_the_provider() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let (status, body) = h.call(Method::GET, "/pets", &[]).await;
    assert_eq!(
        (status, body),
        (StatusCode::UNAUTHORIZED, json!({"message": "Unauthorized"}))
    );
    assert_eq!(
        h.call(Method::GET, "/pets", &[("authorization", "")])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(idp.discovery_hits(), 0);
}

#[tokio::test]
#[expect(clippy::too_many_lines, reason = "one table of rejected tokens")]
async fn tokens_that_fail_verification_are_401() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a(), key_b()]).await;
    let h = http_harness(&idp).await;
    let a = key_a();
    let n = now();
    let cases: Vec<(&str, String)> = vec![
        ("expired", a.token(&http_claims(&json!({"exp": n - 1})))),
        ("expires now", a.token(&http_claims(&json!({"exp": n})))),
        ("no exp", a.token(&http_claims(&json!({"exp": null})))),
        (
            "exp not a number",
            a.token(&http_claims(&json!({"exp": "tomorrow"}))),
        ),
        (
            "not before",
            a.token(&http_claims(&json!({"nbf": n + 600}))),
        ),
        (
            "issued in the future",
            a.token(&http_claims(&json!({"iat": n + 600}))),
        ),
        (
            "wrong issuer",
            a.token(&http_claims(&json!({"iss": "https://evil.example"}))),
        ),
        ("no issuer", a.token(&http_claims(&json!({"iss": null})))),
        (
            "wrong audience",
            a.token(&http_claims(&json!({"aud": "other"}))),
        ),
        (
            "audience list without a match",
            a.token(&http_claims(&json!({"aud": ["x", "y"]}))),
        ),
        (
            "no audience at all",
            a.token(&http_claims(&json!({"aud": null}))),
        ),
        (
            "wrong aud beats a matching client_id",
            a.token(&http_claims(&json!({"aud": "other", "client_id": "api"}))),
        ),
        (
            "a number as the audience",
            a.token(&http_claims(&json!({"aud": 7}))),
        ),
        (
            "unknown key id",
            TestKey::generate("key-unknown").token(&http_claims(&json!({}))),
        ),
        (
            "forged with a published key id",
            forger().token(&http_claims(&json!({}))),
        ),
        (
            "key b's signature under key a's id",
            a.sign_with(
                Alg::Rs256,
                &json!({"alg": "RS256", "kid": "key-b"}),
                &http_claims(&json!({})),
            ),
        ),
        (
            "no key id",
            a.sign_with(
                Alg::Rs256,
                &json!({"alg": "RS256"}),
                &http_claims(&json!({})),
            ),
        ),
        (
            "hmac algorithm",
            a.sign_with(
                Alg::Rs256,
                &json!({"alg": "HS256", "kid": "key-a"}),
                &http_claims(&json!({})),
            ),
        ),
        (
            "no algorithm",
            a.sign_with(
                Alg::Rs256,
                &json!({"alg": "none", "kid": "key-a"}),
                &http_claims(&json!({})),
            ),
        ),
        (
            "elliptic curve algorithm",
            a.sign_with(
                Alg::Rs256,
                &json!({"alg": "ES256", "kid": "key-a"}),
                &http_claims(&json!({})),
            ),
        ),
        (
            "a different RSA algorithm than the key allows",
            a.sign_with(
                Alg::Rs384,
                &json!({"alg": "RS384", "kid": "key-a"}),
                &http_claims(&json!({})),
            ),
        ),
        (
            "RSA-PSS algorithm",
            a.sign_with(
                Alg::Ps256,
                &json!({"alg": "PS256", "kid": "key-a"}),
                &http_claims(&json!({})),
            ),
        ),
        ("not a token", "abc".to_owned()),
        ("two parts", "a.b".to_owned()),
        ("empty parts", "..".to_owned()),
        ("garbage parts", "!!!.@@@.###".to_owned()),
    ];
    for (name, token) in &cases {
        assert_eq!(
            status_of(&h, token).await,
            StatusCode::UNAUTHORIZED,
            "{name}"
        );
    }
    let tampered = {
        let token = a.token(&http_claims(&json!({})));
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = B64.encode(http_claims(&json!({"sub": "admin"})).to_string());
        parts[1] = &forged;
        parts.join(".")
    };
    assert_eq!(
        status_of(&h, &tampered).await,
        StatusCode::UNAUTHORIZED,
        "tampered payload"
    );
    assert_eq!(h.backend_calls.count(), 0, "nothing reached the backend");
}

#[tokio::test]
async fn all_three_rsa_algorithms_verify() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let mut jwk = key_a().jwk();
    jwk.as_object_mut().unwrap().remove("alg");
    idp.set_keys(&[jwk]);
    let h = http_harness(&idp).await;
    for alg in [Alg::Rs256, Alg::Rs384, Alg::Rs512] {
        let token = key_a().sign_with(
            alg,
            &json!({"alg": alg.name(), "kid": "key-a"}),
            &http_claims(&json!({})),
        );
        assert_eq!(
            status_of(&h, &token).await,
            StatusCode::OK,
            "{}",
            alg.name()
        );
    }
}

#[tokio::test]
async fn the_client_id_stands_in_for_a_missing_audience_and_a_list_may_match_any() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let a = key_a();
    let ok = [
        http_claims(&json!({"aud": null, "client_id": "api-2"})),
        http_claims(&json!({"aud": ["other", "api"]})),
        http_claims(&json!({"aud": "api-2"})),
    ];
    for claims in ok {
        assert_eq!(
            status_of(&h, &a.token(&claims)).await,
            StatusCode::OK,
            "{claims}"
        );
    }
}

#[tokio::test]
async fn a_token_just_inside_its_validity_window_is_accepted() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let n = now();
    let claims = http_claims(&json!({"exp": n + 30, "nbf": n - 1, "iat": n - 1}));
    assert_eq!(status_of(&h, &key_a().token(&claims)).await, StatusCode::OK);
}

#[tokio::test]
async fn route_scopes_need_one_matching_scope_and_a_miss_is_403() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let a = key_a();
    for (claims, expected) in [
        (json!({"scope": "read"}), StatusCode::OK),
        (json!({"scope": "openid admin"}), StatusCode::OK),
        (json!({"scope": null, "scp": ["admin"]}), StatusCode::OK),
        (json!({"scope": null, "scp": "read other"}), StatusCode::OK),
        (json!({"scope": "write"}), StatusCode::FORBIDDEN),
        (json!({"scope": "reader"}), StatusCode::FORBIDDEN),
        (json!({"scope": ""}), StatusCode::FORBIDDEN),
        (json!({"scope": null}), StatusCode::FORBIDDEN),
        (json!({"scope": ["read"]}), StatusCode::OK),
    ] {
        let token = a.token(&http_claims(&claims));
        assert_eq!(get_with(&h, "/scoped", &token).await, expected, "{claims}");
    }
    let (status, body) = h
        .call(
            Method::GET,
            "/scoped",
            &[(
                "authorization",
                &a.token(&http_claims(&json!({"scope": "write"}))),
            )],
        )
        .await;
    assert_eq!(
        (status, body),
        (StatusCode::FORBIDDEN, json!({"message": "Forbidden"}))
    );
    let token = a.token(&http_claims(&json!({"scope": null})));
    assert_eq!(
        status_of(&h, &token).await,
        StatusCode::OK,
        "routes without scopes ignore them"
    );
    assert_eq!(h.backend_authorizer()["jwt"]["scopes"], Value::Null);
}

#[tokio::test]
async fn a_bad_token_on_a_scoped_route_is_401_not_403() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let token = key_a().token(&http_claims(&json!({"exp": now() - 5, "scope": "read"})));
    assert_eq!(
        get_with(&h, "/scoped", &token).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn the_token_can_come_from_a_query_string_parameter() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let doc = http_doc(&json!({"identitySource": ["$request.querystring.access_token"]}));
    let h = Harness::start_with(
        &doc,
        ApiKind::Http,
        AuthorizationMode::Enforce,
        idp.key_store(HTTP_ISSUER),
    )
    .await;
    let token = key_a().token(&http_claims(&json!({})));
    assert_eq!(
        h.call(Method::GET, &format!("/pets?access_token={token}"), &[])
            .await
            .0,
        StatusCode::OK
    );
    assert_eq!(
        h.call(Method::GET, "/pets", &[("authorization", &token)])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn keys_are_fetched_once_and_cached() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = http_harness(&idp).await;
    let token = key_a().token(&http_claims(&json!({})));
    for _ in 0..3 {
        assert_eq!(status_of(&h, &token).await, StatusCode::OK);
    }
    assert_eq!((idp.discovery_hits(), idp.jwks_hits()), (1, 1));
}

#[tokio::test]
async fn concurrent_first_requests_share_one_fetch() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = Arc::new(http_harness(&idp).await);
    let token = key_a().token(&http_claims(&json!({})));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let h = Arc::clone(&h);
        let token = token.clone();
        tasks.spawn(async move { status_of(&h, &token).await });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), StatusCode::OK);
    }
    assert_eq!((idp.discovery_hits(), idp.jwks_hits()), (1, 1));
}

#[tokio::test]
async fn a_rotated_key_is_picked_up_when_a_token_names_it() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let keys = idp
        .key_store(HTTP_ISSUER)
        .with_timing(Duration::from_secs(3600), Duration::ZERO);
    let h = http_harness_with(keys).await;
    assert_eq!(
        status_of(&h, &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::OK
    );
    let b_token = key_b().token(&http_claims(&json!({})));
    assert_eq!(
        status_of(&h, &b_token).await,
        StatusCode::UNAUTHORIZED,
        "not published yet"
    );
    idp.set_keys(&[key_a().jwk(), key_b().jwk()]);
    assert_eq!(status_of(&h, &b_token).await, StatusCode::OK);
    assert_eq!(
        status_of(&h, &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::OK,
        "the old key keeps working"
    );
}

#[tokio::test]
async fn unknown_key_ids_cannot_make_the_gateway_refetch_on_every_request() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let keys = idp
        .key_store(HTTP_ISSUER)
        .with_timing(Duration::from_secs(3600), Duration::from_secs(3600));
    let h = http_harness_with(keys).await;
    let stranger = TestKey::generate("stranger").token(&http_claims(&json!({})));
    for _ in 0..5 {
        assert_eq!(status_of(&h, &stranger).await, StatusCode::UNAUTHORIZED);
    }
    assert_eq!(idp.jwks_hits(), 1);
    // A known key keeps being served from the cache meanwhile.
    assert_eq!(
        status_of(&h, &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn keys_expire_from_the_cache() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let keys = idp
        .key_store(HTTP_ISSUER)
        .with_timing(Duration::from_millis(150), Duration::ZERO);
    let h = http_harness_with(keys).await;
    let token = key_a().token(&http_claims(&json!({})));
    assert_eq!(status_of(&h, &token).await, StatusCode::OK);
    assert_eq!(status_of(&h, &token).await, StatusCode::OK);
    assert_eq!(idp.jwks_hits(), 1);
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(status_of(&h, &token).await, StatusCode::OK);
    assert_eq!(idp.jwks_hits(), 2);
}

#[tokio::test]
async fn expired_keys_are_not_used_when_the_provider_is_down() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let keys = idp
        .key_store(HTTP_ISSUER)
        .with_timing(Duration::from_millis(150), Duration::ZERO);
    let h = http_harness_with(keys).await;
    let token = key_a().token(&http_claims(&json!({})));
    assert_eq!(status_of(&h, &token).await, StatusCode::OK);
    idp.set_mode(IdpMode::Status(StatusCode::INTERNAL_SERVER_ERROR));
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert_eq!(status_of(&h, &token).await, StatusCode::UNAUTHORIZED);
    idp.set_mode(IdpMode::Normal);
    assert_eq!(
        status_of(&h, &token).await,
        StatusCode::OK,
        "recovers once the provider does"
    );
}

#[tokio::test]
async fn provider_failures_fail_closed() {
    for (name, mode) in [
        (
            "an error status",
            IdpMode::Status(StatusCode::SERVICE_UNAVAILABLE),
        ),
        ("a missing document", IdpMode::Status(StatusCode::NOT_FOUND)),
        ("garbage", IdpMode::Garbage),
        ("another issuer's document", IdpMode::WrongIssuer),
        ("an unusable jwks_uri", IdpMode::UnusableJwksUri),
        ("an oversized key set", IdpMode::Huge),
    ] {
        let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
        idp.set_mode(mode);
        let keys = idp
            .key_store(HTTP_ISSUER)
            .with_timing(Duration::from_secs(3600), Duration::ZERO);
        let h = http_harness_with(keys).await;
        let token = key_a().token(&http_claims(&json!({})));
        assert_eq!(
            status_of(&h, &token).await,
            StatusCode::UNAUTHORIZED,
            "{name}"
        );
        assert_eq!(h.backend_calls.count(), 0, "{name}");
    }
}

#[tokio::test]
async fn a_slow_provider_is_given_up_on_after_a_second_and_a_half() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    idp.set_mode(IdpMode::Slow(Duration::from_secs(10)));
    let h = http_harness(&idp).await;
    let started = std::time::Instant::now();
    assert_eq!(
        status_of(&h, &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::UNAUTHORIZED
    );
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_millis(1400), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(4), "{elapsed:?}");
}

#[tokio::test]
async fn only_usable_rsa_signing_keys_are_kept() {
    let idp = Idp::start(HTTP_ISSUER, &[]).await;
    let good = key_a().jwk();
    let mut encryption = key_b().jwk();
    encryption["use"] = json!("enc");
    let mut no_kid = key_b().jwk();
    no_kid.as_object_mut().unwrap().remove("kid");
    let ec = json!({"kty": "EC", "kid": "key-b", "crv": "P-256", "x": "AAAA", "y": "AAAA"});
    let unknown = json!({"kty": "FUTURE", "kid": "key-b"});
    idp.set_keys(&[encryption, no_kid, ec, unknown, good]);
    let keys = idp
        .key_store(HTTP_ISSUER)
        .with_timing(Duration::from_secs(3600), Duration::ZERO);
    let h = http_harness_with(keys).await;
    assert_eq!(
        status_of(&h, &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::OK
    );
    assert_eq!(
        status_of(&h, &key_b().token(&http_claims(&json!({})))).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn skipping_authorization_serves_without_verifying() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = Harness::start_with(
        &http_doc(&json!({})),
        ApiKind::Http,
        AuthorizationMode::Skip,
        idp.key_store(HTTP_ISSUER),
    )
    .await;
    assert_eq!(h.call(Method::GET, "/pets", &[]).await.0, StatusCode::OK);
    assert_eq!(idp.discovery_hits(), 0);
}

#[tokio::test]
async fn unevaluable_jwt_authorizers_fail_closed_and_are_reported() {
    for authorizer in [
        json!({"jwtConfiguration": {"issuer": "http://idp.example.com", "audience": ["api"]}}),
        json!({"jwtConfiguration": {"issuer": HTTP_ISSUER, "audience": []}}),
        json!({"jwtConfiguration": {"issuer": HTTP_ISSUER}}),
        json!({"identitySource": ["$request.header.A", "$request.header.B"]}),
        json!({"identitySource": ["$request.body.x"]}),
        json!({"jwtConfiguration": {"audience": ["api"]}}),
    ] {
        let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
        let h = Harness::start_with(
            &http_doc(&authorizer),
            ApiKind::Http,
            AuthorizationMode::Enforce,
            idp.key_store(HTTP_ISSUER),
        )
        .await;
        let token = key_a().token(&http_claims(&json!({})));
        assert_eq!(
            status_of(&h, &token).await,
            StatusCode::UNAUTHORIZED,
            "{authorizer}"
        );
        assert_eq!(idp.discovery_hits(), 0, "{authorizer}");
        let route = h
            .summaries
            .iter()
            .find(|s| s.route_key == "GET /pets")
            .unwrap();
        assert!(
            route.problems.iter().any(|p| p.contains("authorizer")),
            "{authorizer}: {route:?}"
        );
    }
}

#[tokio::test]
async fn an_issuer_without_an_override_must_be_https() {
    // The key store has no endpoint for this issuer, so keys are fetched from
    // the issuer itself, which would be a real network call over TLS: the
    // authorizer is not compiled for an http issuer, so nothing is fetched.
    let doc = http_doc(
        &json!({"jwtConfiguration": {"issuer": "http://127.0.0.1:1", "audience": ["api"]}}),
    );
    let h = Harness::start(&doc, ApiKind::Http, AuthorizationMode::Enforce).await;
    assert_eq!(status_of(&h, "a.b.c").await, StatusCode::UNAUTHORIZED);
}

fn cognito_doc(authorizer: &Value) -> Value {
    let mut config = json!({"type": "cognito_user_pools", "providerARNs": [
        format!("arn:aws:cognito-idp:us-east-1:123456789012:userpool/{POOL}")]});
    if let (Some(config), Some(extra)) = (config.as_object_mut(), authorizer.as_object()) {
        config.extend(extra.clone());
    }
    let route = |scopes: &[&str]| {
        json!({"get": {"security": [{"pool": scopes}],
            "x-amazon-apigateway-integration": echo_integration()}})
    };
    json!({
        "components": {"securitySchemes": {"pool": {"type": "apiKey", "name": "Authorization",
            "in": "header", "x-amazon-apigateway-authtype": "cognito_user_pools",
            "x-amazon-apigateway-authorizer": config}}},
        "paths": {"/pets": route(&[]), "/scoped": route(&["https://api.example.com/read", "other/scope"]),
            "/open": {"get": {"x-amazon-apigateway-integration": echo_integration()}}}
    })
}

async fn cognito_harness(idp: &Idp, authorizer: &Value) -> Harness {
    Harness::start_with(
        &cognito_doc(authorizer),
        ApiKind::Rest,
        AuthorizationMode::Enforce,
        idp.key_store(COGNITO_ISSUER),
    )
    .await
}

fn id_claims(overrides: &Value) -> Value {
    let mut claims = json!({"iss": COGNITO_ISSUER, "aud": "client-1", "token_use": "id",
        "sub": "user-1", "cognito:username": "ann", "email_verified": true,
        "cognito:groups": ["admins", "devs"], "auth_time": now() - 30,
        "iat": now() - 10, "exp": now() + 3600});
    merge(&mut claims, overrides);
    claims
}

fn access_claims(overrides: &Value) -> Value {
    let mut claims = json!({"iss": COGNITO_ISSUER, "client_id": "client-1", "token_use": "access",
        "sub": "user-1", "username": "ann", "scope": "https://api.example.com/read openid",
        "iat": now() - 10, "exp": now() + 3600});
    merge(&mut claims, overrides);
    claims
}

fn merge(claims: &mut Value, overrides: &Value) {
    if let (Some(claims), Some(extra)) = (claims.as_object_mut(), overrides.as_object()) {
        for (name, value) in extra {
            if value.is_null() {
                claims.remove(name);
            } else {
                claims.insert(name.clone(), value.clone());
            }
        }
    }
}

#[tokio::test]
async fn cognito_id_tokens_authorize_routes_without_scopes() {
    let idp = Idp::start(COGNITO_ISSUER, &[key_a()]).await;
    let h = cognito_harness(&idp, &json!({})).await;
    let token = key_a().token(&id_claims(&json!({})));
    let (status, _) = h
        .call(Method::GET, "/pets", &[("authorization", &token)])
        .await;
    assert_eq!(status, StatusCode::OK);
    let claims = &h.backend_authorizer()["claims"];
    assert_eq!(claims["sub"], "user-1");
    assert_eq!(claims["cognito:username"], "ann");
    assert_eq!(claims["email_verified"], "true");
    assert_eq!(claims["cognito:groups"], "admins,devs");
    assert!(
        claims["exp"].as_str().unwrap().contains("UTC 20"),
        "{claims}"
    );
    assert!(claims["auth_time"].as_str().unwrap().parse::<i64>().is_ok());
    assert!(h.backend_authorizer().get("jwt").is_none());
    assert_eq!(
        idp.discovery_hits(),
        0,
        "Cognito keys come from the well-known key set"
    );
    assert_eq!(idp.jwks_hits(), 1);
}

#[tokio::test]
async fn cognito_scopes_decide_between_id_and_access_tokens() {
    let idp = Idp::start(COGNITO_ISSUER, &[key_a()]).await;
    let h = cognito_harness(&idp, &json!({})).await;
    let a = key_a();
    let cases = [
        (
            "id token, no scopes required",
            "/pets",
            id_claims(&json!({})),
            StatusCode::OK,
        ),
        (
            "access token, no scopes required",
            "/pets",
            access_claims(&json!({})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "access token with a required scope",
            "/scoped",
            access_claims(&json!({})),
            StatusCode::OK,
        ),
        (
            "access token with another required scope",
            "/scoped",
            access_claims(&json!({"scope": "other/scope"})),
            StatusCode::OK,
        ),
        (
            "access token without a required scope",
            "/scoped",
            access_claims(&json!({"scope": "openid profile"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "access token without scopes",
            "/scoped",
            access_claims(&json!({"scope": null})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "id token, scopes required",
            "/scoped",
            id_claims(&json!({})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "id token carrying a scope claim",
            "/scoped",
            id_claims(&json!({"scope": "https://api.example.com/read"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "no token_use",
            "/pets",
            id_claims(&json!({"token_use": null})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "unknown token_use",
            "/pets",
            id_claims(&json!({"token_use": "refresh"})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "expired",
            "/pets",
            id_claims(&json!({"exp": now() - 1})),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "another pool",
            "/pets",
            id_claims(&json!({"iss": OTHER_COGNITO_ISSUER})),
            StatusCode::UNAUTHORIZED,
        ),
    ];
    for (name, path, claims, expected) in cases {
        let token = a.token(&claims);
        assert_eq!(get_with(&h, path, &token).await, expected, "{name}");
    }
    let forged = forger().token(&id_claims(&json!({})));
    assert_eq!(
        get_with(&h, "/pets", &forged).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn cognito_validation_expressions_apply_to_the_aud_claim() {
    let idp = Idp::start(COGNITO_ISSUER, &[key_a()]).await;
    let h = cognito_harness(
        &idp,
        &json!({"identityValidationExpression": "client-[0-9]+"}),
    )
    .await;
    let a = key_a();
    assert_eq!(
        get_with(&h, "/pets", &a.token(&id_claims(&json!({})))).await,
        StatusCode::OK
    );
    assert_eq!(
        get_with(
            &h,
            "/pets",
            &a.token(&id_claims(&json!({"aud": "client-x"})))
        )
        .await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_with(
            &h,
            "/pets",
            &a.token(&id_claims(&json!({"aud": "client-1-extra"})))
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "the expression must match the whole claim"
    );
    assert_eq!(
        get_with(&h, "/pets", &a.token(&id_claims(&json!({"aud": null})))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        get_with(&h, "/scoped", &a.token(&access_claims(&json!({})))).await,
        StatusCode::UNAUTHORIZED,
        "an access token has no aud, so the expression rejects it"
    );
}

#[tokio::test]
async fn a_cognito_authorizer_may_list_several_pools() {
    let idp = Idp::start(COGNITO_ISSUER, &[key_a()]).await;
    let arns = json!([
        format!("arn:aws:cognito-idp:us-east-1:123456789012:userpool/{POOL}"),
        "arn:aws:cognito-idp:us-east-1:123456789012:userpool/${stageVariables.fn}"
    ]);
    let doc = cognito_doc(&json!({"providerARNs": arns}));
    let keys = {
        let first = format!("{COGNITO_ISSUER}=http://{}", idp.addr)
            .parse()
            .unwrap();
        let second = format!(
            "https://cognito-idp.us-east-1.amazonaws.com/auth=http://{}",
            idp.addr
        )
        .parse()
        .unwrap();
        KeyStore::new(reqwest::Client::new(), [first, second])
    };
    let h = Harness::start_with(&doc, ApiKind::Rest, AuthorizationMode::Enforce, keys).await;
    let a = key_a();
    let from_second = a.token(&id_claims(
        &json!({"iss": "https://cognito-idp.us-east-1.amazonaws.com/auth"}),
    ));
    assert_eq!(
        get_with(&h, "/pets", &a.token(&id_claims(&json!({})))).await,
        StatusCode::OK
    );
    assert_eq!(
        get_with(&h, "/pets", &from_second).await,
        StatusCode::OK,
        "stage variable in the ARN"
    );
    let third = a.token(&id_claims(&json!({"iss": OTHER_COGNITO_ISSUER})));
    assert_eq!(
        get_with(&h, "/pets", &third).await,
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn unevaluable_cognito_authorizers_fail_closed() {
    for authorizer in [
        json!({"providerARNs": []}),
        json!({"providerARNs": ["arn:aws:cognito-idp:us-east-1:123456789012:identitypool/x"]}),
        json!({"providerARNs": ["arn:aws:s3:::bucket"]}),
        json!({"providerARNs": ["arn:aws-us-gov:cognito-idp:us-gov-west-1:1:userpool/p"]}),
        json!({"identityValidationExpression": r"\G"}),
        json!({"identitySource": "method.request.header.A,method.request.header.B"}),
    ] {
        let idp = Idp::start(COGNITO_ISSUER, &[key_a()]).await;
        let h = cognito_harness(&idp, &authorizer).await;
        let token = key_a().token(&id_claims(&json!({})));
        assert_eq!(
            get_with(&h, "/pets", &token).await,
            StatusCode::UNAUTHORIZED,
            "{authorizer}"
        );
        assert_eq!(idp.jwks_hits(), 0, "{authorizer}");
    }
}

#[tokio::test]
async fn token_authorizers_of_the_other_api_kind_are_not_evaluated() {
    let idp = Idp::start(HTTP_ISSUER, &[key_a()]).await;
    let h = Harness::start_with(
        &cognito_doc(&json!({})),
        ApiKind::Http,
        AuthorizationMode::Enforce,
        idp.key_store(COGNITO_ISSUER),
    )
    .await;
    assert_eq!(
        get_with(&h, "/pets", &key_a().token(&id_claims(&json!({})))).await,
        StatusCode::UNAUTHORIZED
    );
    let h = Harness::start_with(
        &http_doc(&json!({})),
        ApiKind::Rest,
        AuthorizationMode::Enforce,
        idp.key_store(HTTP_ISSUER),
    )
    .await;
    assert_eq!(
        get_with(&h, "/pets", &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(idp.discovery_hits() + idp.jwks_hits(), 0);
}

/// A server that answers every request with a chunked response (no
/// `Content-Length`) holding a key set padded to `padding` bytes.
async fn chunked_key_set_server(jwk: Value, padding: usize) -> SocketAddr {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let body = json!({"keys": [jwk], "padding": "x".repeat(padding)}).to_string();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let body = body.clone();
            tokio::spawn(async move {
                let mut request = [0_u8; 2048];
                if socket.read(&mut request).await.is_err() {
                    return;
                }
                let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n";
                if socket.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                for chunk in body.as_bytes().chunks(16 * 1024) {
                    let framed =
                        [format!("{:x}\r\n", chunk.len()).as_bytes(), chunk, b"\r\n"].concat();
                    if socket.write_all(&framed).await.is_err() {
                        return;
                    }
                }
                if socket.write_all(b"0\r\n\r\n").await.is_err() {
                    return;
                }
                if socket.shutdown().await.is_err() {
                    tracing::debug!("client hung up before the response ended");
                }
            });
        }
    });
    addr
}

#[tokio::test]
async fn key_sets_are_capped_at_150_kb_even_without_a_content_length() {
    for (padding, expected) in [
        (100 * 1024, StatusCode::OK),
        (140 * 1024, StatusCode::OK),
        (160 * 1024, StatusCode::UNAUTHORIZED),
        (400 * 1024, StatusCode::UNAUTHORIZED),
    ] {
        let addr = chunked_key_set_server(key_a().jwk(), padding).await;
        let endpoint = format!("{COGNITO_ISSUER}=http://{addr}").parse().unwrap();
        let h = Harness::start_with(
            &cognito_doc(&json!({})),
            ApiKind::Rest,
            AuthorizationMode::Enforce,
            KeyStore::new(reqwest::Client::new(), [endpoint]),
        )
        .await;
        let token = key_a().token(&id_claims(&json!({})));
        assert_eq!(
            get_with(&h, "/pets", &token).await,
            expected,
            "{padding} bytes of padding"
        );
    }
}

#[test]
fn key_sets_may_only_be_named_over_tls_or_the_operators_own_plaintext_mirror() {
    let url = |s: &str| reqwest::Url::parse(s).unwrap();
    let allowed = KeyStore::jwks_uri_allowed;
    let https = url("https://idp.example.com");
    let http = url("http://mirror.internal");
    assert!(allowed(&url("https://keys.example.com/jwks"), &https));
    assert!(allowed(&url("https://keys.example.com/jwks"), &http));
    assert!(allowed(&url("http://mirror.internal/jwks"), &http));
    assert!(
        !allowed(&url("http://keys.example.com/jwks"), &https),
        "no downgrade from TLS"
    );
    assert!(!allowed(&url("ftp://keys.example.com/jwks"), &https));
    assert!(!allowed(&url("ftp://keys.example.com/jwks"), &http));
    assert!(!allowed(&url("file:///etc/passwd"), &http));
}

#[tokio::test]
async fn an_issuer_without_an_override_must_be_an_https_url() {
    let store = KeyStore::new(reqwest::Client::new(), []);
    for issuer in [
        "http://idp.example.com",
        "ftp://idp.example.com",
        "idp.example.com",
        "",
    ] {
        let error = store
            .key(&Issuer::new(issuer), KeyLocation::Discovery, "kid")
            .await
            .unwrap_err();
        assert!(matches!(error, KeyError::Location(_)), "{issuer}: {error}");
    }
    assert!(store.base(&Issuer::new("https://idp.example.com")).is_ok());
}

#[tokio::test]
async fn rsa_pss_is_not_accepted_even_from_a_key_that_names_no_algorithm() {
    let mut jwk = key_a().jwk();
    jwk.as_object_mut().unwrap().remove("alg");
    let idp = Idp::start(HTTP_ISSUER, &[]).await;
    idp.set_keys(&[jwk]);
    let h = http_harness(&idp).await;
    let pss = key_a().sign_with(
        Alg::Ps256,
        &json!({"alg": "PS256", "kid": "key-a"}),
        &http_claims(&json!({})),
    );
    assert_eq!(status_of(&h, &pss).await, StatusCode::UNAUTHORIZED);
    assert_eq!(
        status_of(&h, &key_a().token(&http_claims(&json!({})))).await,
        StatusCode::OK
    );
}

/// A server that promises a 10 MB key set and then says nothing more.
async fn stalled_oversize_server() -> SocketAddr {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut request = [0_u8; 2048];
                if socket.read(&mut request).await.is_err() {
                    return;
                }
                let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 10485760\r\n\r\n{";
                if socket.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn an_oversize_content_length_is_refused_without_reading_the_body() {
    let addr = stalled_oversize_server().await;
    let endpoint = format!("{COGNITO_ISSUER}=http://{addr}").parse().unwrap();
    let h = Harness::start_with(
        &cognito_doc(&json!({})),
        ApiKind::Rest,
        AuthorizationMode::Enforce,
        KeyStore::new(reqwest::Client::new(), [endpoint]),
    )
    .await;
    let started = std::time::Instant::now();
    let token = key_a().token(&id_claims(&json!({})));
    assert_eq!(
        get_with(&h, "/pets", &token).await,
        StatusCode::UNAUTHORIZED
    );
    assert!(
        started.elapsed() < Duration::from_millis(1000),
        "{:?}",
        started.elapsed()
    );
}

#[test]
fn issuer_endpoint_flags_parse() {
    let endpoint: IssuerEndpoint = "https://idp.example.com/t=https://mirror.internal:8443/t"
        .parse()
        .unwrap();
    assert!(!endpoint.is_plaintext());
    let endpoint: IssuerEndpoint = "https://idp.example.com=http://mirror:8080"
        .parse()
        .unwrap();
    assert!(endpoint.is_plaintext());
    for bad in [
        "",
        "no-equals",
        "=http://x",
        "issuer=not a url",
        "issuer=ftp://x",
    ] {
        assert!(bad.parse::<IssuerEndpoint>().is_err(), "{bad:?}");
    }
}
