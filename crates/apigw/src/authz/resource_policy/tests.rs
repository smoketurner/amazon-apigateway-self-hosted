//! Resource policies: the outcome tables of API Gateway's authorization flow,
//! policy evaluation for anonymous callers, and the whole request path through
//! a router for every kind of authentication.
//!
//! <https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-authorization-flow.html>

#![expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#![expect(clippy::indexing_slicing, reason = "tests index known JSON fields")]

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use super::*;
use crate::authz::tests::{ECHO_FUNCTION, Harness, lambda_uri};
use crate::gateway::AuthorizationMode;
use crate::identity::{ClientIdentity, TrustedProxies};
use crate::model::ApiKind;
use crate::pipeline::context::tests::request;

use Decision::{Allow as A, ExplicitDeny as D, ImplicitDeny as N};

const RP: DeniedBy = DeniedBy::ResourcePolicy;
const ID: DeniedBy = DeniedBy::Identity;

const fn deny(explicit: bool, by: DeniedBy) -> Verdict {
    Verdict::Deny { explicit, by }
}

#[test]
fn table_a_lambda_authorizer_or_iam_in_the_same_account() {
    // (identity policy or authorizer, resource policy) -> outcome
    let rows = [
        (A, A, Verdict::Allow),
        (A, N, Verdict::Allow),
        (A, D, deny(true, RP)),
        (N, A, Verdict::Allow),
        (N, N, deny(false, RP)),
        (N, D, deny(true, RP)),
        (D, A, deny(true, ID)),
        (D, N, deny(true, ID)),
        (D, D, deny(true, RP)),
    ];
    for (identity, resource, expected) in rows {
        assert_eq!(
            Verdict::combine(Identity::Authorizer, identity, resource),
            expected,
            "authorizer {identity:?}, resource policy {resource:?}"
        );
    }
}

#[test]
fn table_b_cognito_or_cross_account_iam_needs_both_to_allow() {
    let rows = [
        (A, A, Verdict::Allow),
        (A, N, deny(false, RP)),
        (A, D, deny(true, RP)),
        (N, A, deny(false, RP)),
        (N, N, deny(false, RP)),
        (N, D, deny(true, RP)),
        (D, A, deny(true, ID)),
        (D, N, deny(true, ID)),
        (D, D, deny(true, RP)),
    ];
    for (identity, resource, expected) in rows {
        assert_eq!(
            Verdict::combine(Identity::UserPool, identity, resource),
            expected,
            "user pool {identity:?}, resource policy {resource:?}"
        );
    }
}

#[test]
fn without_authentication_the_resource_policy_decides_alone() {
    for identity in [A, N, D] {
        assert_eq!(
            Verdict::combine(Identity::Anonymous, identity, A),
            Verdict::Allow
        );
        assert_eq!(
            Verdict::combine(Identity::Anonymous, identity, N),
            deny(false, RP)
        );
        assert_eq!(
            Verdict::combine(Identity::Anonymous, identity, D),
            deny(true, RP)
        );
    }
}

fn fallback() -> ArnScope {
    ArnScope {
        partition: "aws".to_owned(),
        region: "us-east-1".to_owned(),
        account: "000000000000".to_owned(),
    }
}

fn compile(statements: &Value) -> ResourcePolicy {
    let document = json!({"Version": "2012-10-17", "Statement": statements});
    ResourcePolicy::compile(&document, "abc123", fallback()).unwrap()
}

fn statement(effect: &str, extra: &Value) -> Value {
    let mut statement = json!({"Effect": effect, "Principal": "*",
        "Action": "execute-api:Invoke", "Resource": "execute-api:/*"});
    statement
        .as_object_mut()
        .unwrap()
        .extend(extra.as_object().cloned().unwrap_or_default());
    statement
}

fn from_ip(ip: &str) -> RequestContext {
    let mut ctx = request(ApiKind::Rest);
    ctx.identity = {
        let mut headers = axum::http::HeaderMap::new();
        TrustedProxies::none().identify(format!("{ip}:5000").parse().unwrap(), &mut headers)
    };
    ctx
}

fn ip_condition(operator: &str, cidr: &str) -> Value {
    json!({"Condition": {operator: {"aws:SourceIp": cidr}}})
}

#[test]
fn an_allow_with_an_address_condition() {
    let policy = compile(&json!([statement(
        "Allow",
        &ip_condition("IpAddress", "192.0.2.0/24")
    )]));
    assert_eq!(policy.decide(&from_ip("192.0.2.9")), A);
    assert_eq!(policy.decide(&from_ip("192.0.3.9")), N);
}

#[test]
fn a_deny_with_a_negated_address_condition_blocks_everyone_else() {
    let policy = compile(&json!([
        statement("Allow", &json!({})),
        statement("Deny", &ip_condition("NotIpAddress", "192.0.2.0/24")),
    ]));
    assert_eq!(policy.decide(&from_ip("192.0.2.9")), A);
    assert_eq!(policy.decide(&from_ip("203.0.113.9")), D);
}

#[test]
fn an_unknown_client_address_never_allows_and_always_denies() {
    let mut ctx = request(ApiKind::Rest);
    ctx.identity = ClientIdentity::unknown();
    let allow = compile(&json!([statement(
        "Allow",
        &ip_condition("IpAddress", "0.0.0.0/0")
    )]));
    assert_eq!(
        allow.decide(&ctx),
        N,
        "an Allow with an unevaluable condition does not apply"
    );
    for operator in ["IpAddress", "NotIpAddress"] {
        let deny = compile(&json!([
            statement("Allow", &json!({})),
            statement("Deny", &ip_condition(operator, "192.0.2.0/24")),
        ]));
        assert_eq!(
            deny.decide(&ctx),
            D,
            "a Deny with an unevaluable {operator} applies"
        );
    }
}

#[test]
fn unevaluable_conditions_on_other_keys_deny_and_never_allow() {
    let vpce = json!({"Condition": {"StringEquals": {"aws:SourceVpce": "vpce-1"}}});
    let ctx = from_ip("192.0.2.9");
    assert_eq!(compile(&json!([statement("Allow", &vpce)])).decide(&ctx), N);
    assert_eq!(
        compile(&json!([
            statement("Allow", &json!({})),
            statement("Deny", &vpce)
        ]))
        .decide(&ctx),
        D
    );
}

#[test]
fn resources_can_be_shorthand_patterns_or_full_arns() {
    let ctx = request(ApiKind::Rest);
    for (resource, expected) in [
        ("execute-api:/*", A),
        ("execute-api:/prod/POST/pets/*", A),
        ("execute-api:/prod/GET/pets/*", N),
        ("execute-api:/dev/*", N),
        (
            "arn:aws:execute-api:us-east-1:123456789012:abc123/prod/POST/pets/7",
            A,
        ),
        ("arn:aws:execute-api:us-east-1:123456789012:abc123/*", A),
        ("arn:aws:execute-api:us-east-1:123456789012:other/*", A),
        ("arn:aws:execute-api:us-east-1:123456789012:other/dev/*", N),
        ("arn:aws:execute-api:eu-west-1:123456789012:abc123/*", A),
        ("*", A),
    ] {
        let policy = compile(&json!([statement("Allow", &json!({"Resource": resource}))]));
        assert_eq!(policy.decide(&ctx), expected, "{resource}");
    }
}

#[test]
fn shorthand_means_the_api_the_policy_is_compiled_for() {
    let shorthand =
        json!({"Statement": [statement("Allow", &json!({"Resource": "execute-api:/*"}))]});
    let own = ResourcePolicy::compile(&shorthand, "abc123", fallback()).unwrap();
    assert_eq!(own.decide(&request(ApiKind::Rest)), A);
    let other = ResourcePolicy::compile(&shorthand, "someone-else", fallback()).unwrap();
    assert_eq!(
        other.decide(&request(ApiKind::Rest)),
        N,
        "a request for abc123"
    );
}

#[test]
fn every_api_id_a_policy_names_concretely_is_the_api_itself() {
    // A file source gives the API no AWS id, and an export carries the id of the
    // API it came from, so a concrete id in the policy cannot be compared.
    let ctx = request(ApiKind::Rest);
    let policy = |effect: &str, resource: &str| {
        compile(&json!([
            statement("Allow", &json!({})),
            statement(effect, &json!({"Resource": resource})),
        ]))
    };
    assert_eq!(
        policy(
            "Deny",
            "arn:aws:execute-api:us-east-1:123456789012:xyz999/prod/POST/pets/*"
        )
        .decide(&ctx),
        D,
        "a Deny written with the exporting API's id still applies"
    );
    assert_eq!(
        policy(
            "Deny",
            "arn:aws:execute-api:us-east-1:123456789012:xyz999/prod/GET/*"
        )
        .decide(&ctx),
        A,
        "its method and path are still compared"
    );
    assert_eq!(
        policy(
            "Deny",
            "arn:aws:execute-api:us-east-1:123456789012:xyz*/prod/POST/*"
        )
        .decide(&ctx),
        A,
        "an id with a wildcard is a pattern and is left alone: it does not match abc123"
    );
    assert_eq!(
        policy(
            "Deny",
            "arn:aws:execute-api:us-east-1:123456789012:*/prod/POST/*"
        )
        .decide(&ctx),
        D
    );
    assert_eq!(
        policy("Deny", "arn:aws:execute-api:us-east-1:123456789012:abc123").decide(&ctx),
        A,
        "an ARN with no path names the API but no method"
    );
}

#[test]
fn only_principals_naming_everyone_apply_to_an_anonymous_caller() {
    let ctx = request(ApiKind::Rest);
    for (principal, expected) in [
        (json!("*"), A),
        (json!({"AWS": "*"}), A),
        (json!({"AWS": ["arn:aws:iam::1:root", "*"]}), A),
        (json!({"AWS": "arn:aws:iam::123456789012:root"}), N),
        (json!({"Service": "apigateway.amazonaws.com"}), N),
        (json!("arn:aws:iam::123456789012:root"), N),
    ] {
        let policy = compile(&json!([statement(
            "Allow",
            &json!({"Principal": principal})
        )]));
        assert_eq!(policy.decide(&ctx), expected, "{principal}");
    }
}

#[test]
fn a_deny_for_a_named_principal_does_not_block_anonymous_callers() {
    let policy = compile(&json!([
        statement("Allow", &json!({})),
        statement(
            "Deny",
            &json!({"Principal": {"AWS": "arn:aws:iam::222222222222:root"}})
        ),
    ]));
    assert_eq!(policy.decide(&request(ApiKind::Rest)), A);
}

/// A `Deny` with `NotPrincipal` in place of `Principal`.
fn deny_all_but(principal: Value) -> Value {
    let mut deny = statement("Deny", &json!({}));
    let fields = deny.as_object_mut().unwrap();
    fields.remove("Principal");
    fields.insert("NotPrincipal".to_owned(), principal);
    deny
}

#[test]
fn not_principal_applies_to_anonymous_callers_unless_it_excludes_everyone() {
    let ctx = request(ApiKind::Rest);
    let denied = compile(&json!([
        statement("Allow", &json!({})),
        deny_all_but(json!({"AWS": "arn:aws:iam::1:root"})),
    ]));
    assert_eq!(denied.decide(&ctx), D);
    let exempt = compile(&json!([
        statement("Allow", &json!({})),
        deny_all_but(json!("*")),
    ]));
    assert_eq!(exempt.decide(&ctx), A);
}

#[test]
fn a_statement_without_a_principal_is_unevaluable() {
    let ctx = request(ApiKind::Rest);
    let mut allow = statement("Allow", &json!({}));
    allow.as_object_mut().unwrap().remove("Principal");
    assert_eq!(compile(&json!([allow])).decide(&ctx), N);
    let mut deny = statement("Deny", &json!({}));
    deny.as_object_mut().unwrap().remove("Principal");
    assert_eq!(
        compile(&json!([statement("Allow", &json!({})), deny])).decide(&ctx),
        D
    );
}

#[test]
fn methods_and_stages_are_matched() {
    let ctx = request(ApiKind::Rest);
    let get_only = compile(&json!([statement(
        "Allow",
        &json!({"Resource": "execute-api:/*/GET/*"})
    )]));
    assert_eq!(get_only.decide(&ctx), N, "the request is a POST");
    let deny_post = compile(&json!([
        statement("Allow", &json!({})),
        statement("Deny", &json!({"Resource": "execute-api:/*/POST/pets/*"})),
    ]));
    assert_eq!(deny_post.decide(&ctx), D);
}

#[test]
fn the_deny_message_names_the_method_with_the_account_masked() {
    let policy = ResourcePolicy::compile(
        &json!({"Statement": [statement(
            "Allow",
            &json!({"Resource": "arn:aws:execute-api:eu-west-1:123456789012:abc123/*"})
        )]}),
        "abc123",
        fallback(),
    )
    .unwrap();
    let ctx = request(ApiKind::Rest);
    assert_eq!(
        policy.denial(&ctx, true),
        Denial::ResourcePolicy {
            resource: "arn:aws:execute-api:eu-west-1:********9012:abc123/prod/POST/pets/7"
                .to_owned(),
            explicit: true,
        }
    );
}

#[test]
fn account_masking_keeps_the_last_four_digits() {
    let scope = ArnScope {
        partition: "aws-cn".to_owned(),
        region: "cn-north-1".to_owned(),
        account: "123456789012".to_owned(),
    };
    let arn = MethodArn::new(&scope, "api", "stage", &Method::GET, "/a/b");
    assert_eq!(
        arn.masked(),
        "arn:aws-cn:execute-api:cn-north-1:********9012:api/stage/GET/a/b"
    );
}

#[test]
fn malformed_policies_are_rejected() {
    for bad in [
        json!("not a policy"),
        json!({"Statement": [{"Effect": "Allow", "Principal": "*", "Resource": "*"}]}),
        json!({"Statement": [{"Effect": "Maybe", "Principal": "*", "Action": "*", "Resource": "*"}]}),
    ] {
        assert!(
            ResourcePolicy::compile(&bad, "abc123", fallback()).is_err(),
            "{bad}"
        );
    }
}

// The whole request path.

const ALLOW_IP: &str = "192.0.2.5";
const NEITHER_IP: &str = "203.0.113.1";
const DENY_IP: &str = "198.51.100.9";

/// Allows 192.0.2.0/24, denies 198.51.100.0/24, and says nothing about the rest.
fn address_policy() -> Value {
    json!({"Version": "2012-10-17", "Statement": [
        statement("Allow", &ip_condition("IpAddress", "192.0.2.0/24")),
        statement("Deny", &ip_condition("IpAddress", "198.51.100.0/24")),
    ]})
}

fn policy_doc(policy: &Value) -> Value {
    json!({
        "x-amazon-apigateway-policy": policy,
        "components": {"securitySchemes": {"auth": {
            "type": "apiKey", "name": "Authorization", "in": "header",
            "x-amazon-apigateway-authtype": "custom",
            "x-amazon-apigateway-authorizer": {"type": "token",
                "authorizerUri": lambda_uri("arn:aws:lambda:us-east-1:123456789012:function:auth"),
                "authorizerResultTtlInSeconds": 0}}}},
        "paths": {
            "/open": {"get": {"x-amazon-apigateway-integration": echo()}},
            "/pets/{id}": {"get": {"security": [{"auth": []}],
                "x-amazon-apigateway-integration": echo()}},
        }
    })
}

fn echo() -> Value {
    json!({"type": "aws_proxy", "httpMethod": "POST", "uri": lambda_uri(ECHO_FUNCTION),
        "payloadFormatVersion": "1.0"})
}

async fn harness(policy: Value, mode: AuthorizationMode) -> Harness {
    Harness::start(&policy_doc(&policy), ApiKind::Rest, mode).await
}

const EXPLICIT_RESOURCE_POLICY: &str = "with an explicit deny in a resource-based policy";
const IMPLICIT_RESOURCE_POLICY: &str =
    "because no resource-based policy allows the execute-api:Invoke action";
const EXPLICIT_IDENTITY: &str = "with an explicit deny in an identity-based policy";

fn message(body: &Value) -> &str {
    body["message"].as_str().unwrap_or_default()
}

#[tokio::test]
async fn with_no_authentication_the_policy_must_explicitly_allow() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    let (status, _) = h.call_from(ALLOW_IP, Method::GET, "/open", &[]).await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = h.call_from(NEITHER_IP, Method::GET, "/open", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(message(&body).starts_with("User: anonymous is not authorized to perform: execute-api:Invoke on resource: arn:aws:execute-api:us-east-1:********0000:abc/prod/GET/open "), "{body}");
    assert!(message(&body).ends_with(IMPLICIT_RESOURCE_POLICY), "{body}");
    let (status, body) = h.call_from(DENY_IP, Method::GET, "/open", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(message(&body).ends_with(EXPLICIT_RESOURCE_POLICY), "{body}");
    assert_eq!(h.backend_calls.count(), 1);
}

/// One row of Table A, with a Lambda authorizer on `/pets/{id}`: the token
/// picks what the authorizer says, the client address what the policy says.
async fn lambda_row(h: &Harness, token: &str, ip: &str) -> (StatusCode, String) {
    let (status, body) = h
        .call_from(ip, Method::GET, "/pets/2", &[("authorization", token)])
        .await;
    (status, message(&body).to_owned())
}

#[tokio::test]
async fn table_a_for_a_lambda_authorizer_through_the_router() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    // "allow-all" allows every method; "allow-pet-1" allows only pets/1, so it
    // says nothing about pets/2; "deny" denies explicitly.
    let rows = [
        ("allow-all", ALLOW_IP, true, None),
        ("allow-all", NEITHER_IP, true, None),
        ("allow-all", DENY_IP, false, Some(EXPLICIT_RESOURCE_POLICY)),
        ("allow-pet-1", ALLOW_IP, true, None),
        (
            "allow-pet-1",
            NEITHER_IP,
            false,
            Some(IMPLICIT_RESOURCE_POLICY),
        ),
        (
            "allow-pet-1",
            DENY_IP,
            false,
            Some(EXPLICIT_RESOURCE_POLICY),
        ),
        ("deny", ALLOW_IP, false, Some(EXPLICIT_IDENTITY)),
        ("deny", NEITHER_IP, false, Some(EXPLICIT_IDENTITY)),
        ("deny", DENY_IP, false, Some(EXPLICIT_RESOURCE_POLICY)),
    ];
    for (token, ip, allowed, text) in rows {
        let (status, message) = lambda_row(&h, token, ip).await;
        if allowed {
            assert_eq!(status, StatusCode::OK, "{token} from {ip}: {message}");
        } else {
            assert_eq!(status, StatusCode::FORBIDDEN, "{token} from {ip}");
            assert!(
                message.ends_with(text.unwrap()),
                "{token} from {ip}: {message}"
            );
        }
    }
}

#[tokio::test]
async fn an_explicit_resource_policy_deny_ends_the_request_before_the_authorizer_runs() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    let (status, _) = h
        .call_from(
            DENY_IP,
            Method::GET,
            "/pets/2",
            &[("authorization", "allow-all")],
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        h.auth_calls.count(),
        0,
        "phase one denies before the authorizer is invoked"
    );
    let (status, _) = h.call_from(DENY_IP, Method::GET, "/pets/2", &[]).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "even without a token");
    assert_eq!(h.auth_calls.count(), 0);
}

#[tokio::test]
async fn an_allow_in_the_resource_policy_does_not_replace_authentication() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    let (status, _) = h.call_from(ALLOW_IP, Method::GET, "/pets/2", &[]).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "no token");
    let (status, _) = h.call_from(NEITHER_IP, Method::GET, "/pets/2", &[]).await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "no token, and no opinion from the policy"
    );
    let (status, _) = h
        .call_from(
            ALLOW_IP,
            Method::GET,
            "/pets/2",
            &[("authorization", "unauthorized")],
        )
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "an authorizer that refuses"
    );
    assert_eq!(h.backend_calls.count(), 0);
}

#[tokio::test]
async fn an_authorizer_failure_is_not_rescued_by_an_allowing_policy() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    let (status, _) = h
        .call_from(
            ALLOW_IP,
            Method::GET,
            "/pets/2",
            &[("authorization", "boom")],
        )
        .await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn the_authorizer_context_survives_an_allow_from_the_resource_policy() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    let (status, _) = h
        .call_from(
            ALLOW_IP,
            Method::GET,
            "/pets/2",
            &[("authorization", "allow-pet-1")],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(h.backend_authorizer()["principalId"], "user-1");
}

#[tokio::test]
async fn skipping_authorization_never_skips_the_resource_policy() {
    let h = harness(address_policy(), AuthorizationMode::Skip).await;
    for (ip, route, expected) in [
        (ALLOW_IP, "/open", StatusCode::OK),
        (NEITHER_IP, "/open", StatusCode::FORBIDDEN),
        (DENY_IP, "/open", StatusCode::FORBIDDEN),
        // The authorizer is taken to have allowed the caller, so the policy
        // only counts when it denies.
        (ALLOW_IP, "/pets/2", StatusCode::OK),
        (NEITHER_IP, "/pets/2", StatusCode::OK),
        (DENY_IP, "/pets/2", StatusCode::FORBIDDEN),
    ] {
        let (status, _) = h.call_from(ip, Method::GET, route, &[]).await;
        assert_eq!(status, expected, "{route} from {ip}");
    }
    assert_eq!(h.auth_calls.count(), 0, "no authorizer ran");
}

#[tokio::test]
async fn a_client_address_that_cannot_be_established_fails_closed() {
    let allow_only = json!({"Version": "2012-10-17", "Statement": [
        statement("Allow", &ip_condition("IpAddress", "192.0.2.0/24")),
    ]});
    let h = harness(allow_only, AuthorizationMode::Enforce).await;
    let (status, body) = h.call(Method::GET, "/open", &[]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an Allow on the address cannot be shown to apply"
    );
    assert!(message(&body).ends_with(IMPLICIT_RESOURCE_POLICY), "{body}");
    let (status, body) = harness(address_policy(), AuthorizationMode::Enforce)
        .await
        .call(Method::GET, "/open", &[])
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        message(&body).ends_with(EXPLICIT_RESOURCE_POLICY),
        "a Deny on the address applies when it cannot be read: {body}"
    );
    let deny_outsiders = json!({"Version": "2012-10-17", "Statement": [
        statement("Allow", &json!({})),
        statement("Deny", &ip_condition("NotIpAddress", "192.0.2.0/24")),
    ]});
    let h = harness(deny_outsiders, AuthorizationMode::Enforce).await;
    let (status, body) = h.call(Method::GET, "/open", &[]).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a Deny on the address applies when it cannot be read"
    );
    assert!(message(&body).ends_with(EXPLICIT_RESOURCE_POLICY), "{body}");
    assert_eq!(
        h.call_from(ALLOW_IP, Method::GET, "/open", &[]).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn a_policy_that_cannot_be_read_refuses_every_route_and_is_reported() {
    for mode in [AuthorizationMode::Enforce, AuthorizationMode::Skip] {
        let broken = json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Principal": "*", "Resource": "*"}]});
        let h = harness(broken, mode).await;
        for route in ["/open", "/pets/2"] {
            let (status, _) = h
                .call_from(
                    ALLOW_IP,
                    Method::GET,
                    route,
                    &[("authorization", "allow-all")],
                )
                .await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{route} in {mode:?}");
        }
        assert!(
            h.summaries.iter().all(|s| s
                .problems
                .iter()
                .any(|p| p.contains("resource policy this gateway cannot evaluate"))),
            "{:?}",
            h.summaries
        );
        assert_eq!(h.backend_calls.count(), 0);
    }
}

#[tokio::test]
async fn a_policy_given_as_a_string_is_evaluated() {
    let h = harness(
        json!(address_policy().to_string()),
        AuthorizationMode::Enforce,
    )
    .await;
    assert_eq!(
        h.call_from(ALLOW_IP, Method::GET, "/open", &[]).await.0,
        StatusCode::OK
    );
    assert_eq!(
        h.call_from(NEITHER_IP, Method::GET, "/open", &[]).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn an_unparseable_policy_string_fails_closed() {
    let h = harness(json!("{not json"), AuthorizationMode::Enforce).await;
    assert_eq!(
        h.call_from(ALLOW_IP, Method::GET, "/open", &[]).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn an_empty_policy_protects_nothing() {
    let h = harness(
        json!({"Version": "2012-10-17", "Statement": []}),
        AuthorizationMode::Enforce,
    )
    .await;
    assert_eq!(
        h.call_from(NEITHER_IP, Method::GET, "/open", &[]).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_deny_message_uses_the_account_in_the_policy() {
    let policy = json!({"Version": "2012-10-17", "Statement": [
        statement("Deny", &json!({"Resource": "arn:aws:execute-api:eu-west-1:123456789012:abc/*"})),
    ]});
    let h = harness(policy, AuthorizationMode::Enforce).await;
    let (_, body) = h.call_from(NEITHER_IP, Method::GET, "/open", &[]).await;
    assert!(
        message(&body)
            .contains("resource: arn:aws:execute-api:eu-west-1:********9012:abc/prod/GET/open "),
        "{body}"
    );
}

#[tokio::test]
async fn the_error_is_a_403_access_denied_gateway_response() {
    let h = harness(address_policy(), AuthorizationMode::Enforce).await;
    let request = axum::http::Request::builder()
        .uri("/open")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = h.router.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response.headers()["x-amzn-errortype"],
        "AccessDeniedException"
    );
}
