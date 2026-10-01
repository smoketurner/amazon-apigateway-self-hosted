use axum::http::HeaderValue;
use serde_json::{Value, json};

use super::*;
use crate::model::{ApiKind, IntegrationOverrides, StageSettings};
use crate::pipeline::context::QueryString;
use crate::pipeline::context::tests::request;

fn pet_models() -> Value {
    json!({
        "Pet": {
            "type": "object",
            "required": ["name", "owner"],
            "properties": {
                "name": {"type": "string", "minLength": 2},
                "age": {"type": "integer", "minimum": 0},
                "owner": {"$ref": "#/components/schemas/Owner"},
                "email": {"type": "string", "format": "email"}
            }
        },
        "Owner": {
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "integer"}}
        }
    })
}

fn operation(extra: &Value) -> Value {
    let mut operation = json!({
        "x-amazon-apigateway-integration": {"type": "mock", "requestTemplates": {"application/json": "{\"statusCode\": 200}"}},
        "x-amazon-apigateway-request-validator": "all"
    });
    if let (Some(operation), Some(extra)) = (operation.as_object_mut(), extra.as_object()) {
        operation.extend(extra.clone());
    }
    operation
}

fn body_of(content: &Value) -> Value {
    json!({"required": true, "content": content})
}

fn compile(paths: &Value, models: &Value) -> BTreeMap<String, RouteValidation> {
    let doc = json!({
        "components": {"schemas": models},
        "x-amazon-apigateway-request-validators": {
            "all": {"validateRequestBody": true, "validateRequestParameters": true},
            "params": {"validateRequestBody": false, "validateRequestParameters": true},
            "body": {"validateRequestBody": true, "validateRequestParameters": false}
        },
        "paths": paths
    });
    let model = ApiModel::import(
        &doc,
        ApiKind::Rest,
        StageSettings::default(),
        &IntegrationOverrides::default(),
    )
    .unwrap();
    let validators = RequestValidators::compile(&model);
    model
        .operations
        .iter()
        .map(|operation| {
            (
                operation.route_key.to_string(),
                validators.for_route(operation),
            )
        })
        .collect()
}

fn checks(route: RouteValidation) -> Option<Arc<RequestChecks>> {
    match route {
        RouteValidation::Checks(checks) => Some(checks),
        RouteValidation::None | RouteValidation::Unevaluable(_) => None,
    }
}

fn pet_route() -> RouteValidation {
    let paths = json!({"/pets": {"post": operation(&json!({
        "requestBody": body_of(&json!({"application/json": {"schema": {"$ref": "#/components/schemas/Pet"}}}))
    }))}});
    compile(&paths, &pet_models()).remove("POST /pets").unwrap()
}

fn with_body(content_type: Option<&str>, body: &str) -> RequestContext {
    let mut ctx = request(ApiKind::Rest);
    ctx.query = QueryString::new(None);
    if let Some(content_type) = content_type {
        ctx.headers
            .insert("content-type", HeaderValue::from_str(content_type).unwrap());
    }
    ctx.body = Bytes::from(body.to_owned());
    ctx
}

async fn failure(route: &RouteValidation, ctx: &RequestContext) -> Failure {
    route.check(ctx).await.unwrap_err()
}

fn violations(failure: &Failure) -> &str {
    failure.validation().unwrap()
}

#[tokio::test]
async fn a_body_that_matches_its_model_passes() {
    let route = pet_route();
    let ok = r#"{"name": "Rex", "age": 3, "owner": {"id": 7}}"#;
    assert!(
        route
            .check(&with_body(Some("application/json"), ok))
            .await
            .is_ok()
    );
    assert!(
        route.check(&with_body(None, ok)).await.is_ok(),
        "no content type means JSON"
    );
    assert!(
        route
            .check(&with_body(Some("Application/JSON; charset=utf-8"), ok))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn content_types_match_without_regard_to_case() {
    let route = pet_route();
    for content_type in [
        "Application/JSON",
        "APPLICATION/JSON; charset=utf-8",
        " application/json ",
    ] {
        let failed = failure(&route, &with_body(Some(content_type), "[]")).await;
        assert_eq!(
            failed.response_type(),
            Some(ResponseType::BadRequestBody),
            "{content_type}"
        );
    }
    let paths = json!({"/a": {"post": operation(&json!({"requestBody": body_of(&json!({
        "Application/JSON": {"schema": {"type": "object"}}
    }))}))}});
    let mixed_case_model = compile(&paths, &json!({})).remove("POST /a").unwrap();
    assert!(
        mixed_case_model
            .check(&with_body(Some("application/json"), "[]"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn a_body_that_breaks_its_model_is_a_bad_request_body() {
    let route = pet_route();
    for (body, expected) in [
        (r#"{"name": "Rex"}"#, r#""owner" is a required property"#),
        (
            r#"{"name": "R", "owner": {"id": 1}}"#,
            "is shorter than 2 characters",
        ),
        (
            r#"{"name": "Rex", "owner": {"id": "x"}}"#,
            r#"is not of type "integer""#,
        ),
        (
            r#"{"name": "Rex", "age": -1, "owner": {"id": 1}}"#,
            "is less than the minimum of 0",
        ),
        (
            r#"{"name": "Rex", "owner": {}}"#,
            r#""id" is a required property"#,
        ),
        ("[]", r#"is not of type "object""#),
    ] {
        let failed = failure(&route, &with_body(Some("application/json"), body)).await;
        assert_eq!(
            failed.response_type(),
            Some(ResponseType::BadRequestBody),
            "{body}"
        );
        assert_eq!(failed.message(), "Invalid request body");
        let text = violations(&failed);
        assert!(text.starts_with('[') && text.ends_with(']'), "{text}");
        assert!(text.contains(expected), "{body}: {text}");
    }
}

#[tokio::test]
async fn malformed_and_empty_bodies_are_invalid() {
    let route = pet_route();
    for body in ["", "{", "not json", r#"{"name": "Rex"} trailing"#, "\u{0}"] {
        let failed = failure(&route, &with_body(Some("application/json"), body)).await;
        assert_eq!(
            failed.response_type(),
            Some(ResponseType::BadRequestBody),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn formats_are_not_enforced() {
    let route = pet_route();
    let body = r#"{"name": "Rex", "email": "nope", "owner": {"id": 1}}"#;
    assert!(route.check(&with_body(None, body)).await.is_ok());
}

#[tokio::test]
async fn content_types_without_a_model_are_not_validated_unless_there_is_a_default() {
    let paths = json!({
        "/a": {"post": operation(&json!({"requestBody": body_of(&json!({
            "application/json": {"schema": {"type": "object"}}
        }))}))},
        "/b": {"post": operation(&json!({"requestBody": body_of(&json!({
            "application/json": {"schema": {"type": "object"}},
            "$default": {"schema": {"type": "array"}}
        }))}))}
    });
    let mut routes = compile(&paths, &json!({}));
    let only_json = routes.remove("POST /a").unwrap();
    assert!(
        only_json
            .check(&with_body(Some("text/plain"), "anything"))
            .await
            .is_ok()
    );
    assert!(
        only_json
            .check(&with_body(Some("application/json"), "[]"))
            .await
            .is_err()
    );

    let with_default = routes.remove("POST /b").unwrap();
    assert!(
        with_default
            .check(&with_body(Some("text/plain"), "[1]"))
            .await
            .is_ok()
    );
    assert!(
        with_default
            .check(&with_body(Some("text/plain"), "{}"))
            .await
            .is_err()
    );
    assert!(
        with_default
            .check(&with_body(Some("application/json"), "{}"))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn each_content_type_uses_its_own_model() {
    let paths = json!({"/a": {"post": operation(&json!({"requestBody": body_of(&json!({
        "application/json": {"schema": {"type": "object"}},
        "application/vnd.list+json": {"schema": {"type": "array"}}
    }))}))}});
    let route = compile(&paths, &json!({})).remove("POST /a").unwrap();
    assert!(
        route
            .check(&with_body(Some("application/json"), "{}"))
            .await
            .is_ok()
    );
    assert!(
        route
            .check(&with_body(Some("application/json"), "[]"))
            .await
            .is_err()
    );
    assert!(
        route
            .check(&with_body(Some("application/vnd.list+json"), "[]"))
            .await
            .is_ok()
    );
    assert!(
        route
            .check(&with_body(Some("application/vnd.list+json"), "{}"))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn references_resolve_through_several_models() {
    let models = json!({
        "A": {"type": "object", "properties": {"b": {"$ref": "#/components/schemas/B"}}},
        "B": {"type": "object", "properties": {"c": {"$ref": "#/components/schemas/C"}}},
        "C": {"type": "string"},
        "Tree": {"type": "object", "properties": {"children": {"type": "array", "items": {"$ref": "#/components/schemas/Tree"}}}}
    });
    let paths = json!({
        "/a": {"post": operation(&json!({"requestBody": body_of(&json!({"application/json": {"schema": {"$ref": "#/components/schemas/A"}}}))}))},
        "/t": {"post": operation(&json!({"requestBody": body_of(&json!({"application/json": {"schema": {"$ref": "#/components/schemas/Tree"}}}))}))}
    });
    let mut routes = compile(&paths, &models);
    let a = routes.remove("POST /a").unwrap();
    assert!(
        a.check(&with_body(None, r#"{"b": {"c": "x"}}"#))
            .await
            .is_ok()
    );
    assert!(
        a.check(&with_body(None, r#"{"b": {"c": 1}}"#))
            .await
            .is_err()
    );
    let tree = routes.remove("POST /t").unwrap();
    assert!(
        tree.check(&with_body(None, r#"{"children": [{"children": []}]}"#))
            .await
            .is_ok()
    );
    assert!(
        tree.check(&with_body(None, r#"{"children": [{"children": 1}]}"#))
            .await
            .is_err()
    );
}

#[test]
fn models_that_cannot_be_compiled_make_the_route_unevaluable() {
    for (name, schema) in [
        (
            "a reference to a model the API does not have",
            json!({"$ref": "#/components/schemas/Missing"}),
        ),
        (
            "a reference to a remote document",
            json!({"$ref": "https://example.invalid/schema.json"}),
        ),
        (
            "a reference to a local file",
            json!({"$ref": "file:///etc/passwd"}),
        ),
        ("a type that does not exist", json!({"type": "nonsense"})),
        ("a schema that is not an object", json!(true)),
    ] {
        let paths = json!({"/a": {"post": operation(&json!({"requestBody": body_of(&json!({"application/json": {"schema": schema}}))}))}});
        let route = compile(&paths, &json!({})).remove("POST /a").unwrap();
        assert!(route.is_unevaluable(), "{name}");
        assert!(
            route
                .unevaluable_reason()
                .unwrap()
                .contains("application/json"),
            "{name}"
        );
    }
}

#[test]
fn only_the_validators_checks_that_are_enabled_apply() {
    let body = body_of(&json!({"application/json": {"schema": {"type": "object"}}}));
    let parameters = json!([{"name": "x-token", "in": "header", "required": true}]);
    let paths = json!({
        "/none": {"get": {"x-amazon-apigateway-integration": {"type": "mock"}, "parameters": parameters}},
        "/params": {"post": operation(&json!({"x-amazon-apigateway-request-validator": "params", "parameters": parameters, "requestBody": body}))},
        "/body": {"post": operation(&json!({"x-amazon-apigateway-request-validator": "body", "parameters": parameters, "requestBody": body}))},
        "/nothing-to-check": {"get": operation(&json!({"parameters": [{"name": "optional", "in": "query"}]}))}
    });
    let mut routes = compile(&paths, &json!({}));
    assert!(matches!(
        routes.remove("GET /none").unwrap(),
        RouteValidation::None
    ));
    assert!(matches!(
        routes.remove("GET /nothing-to-check").unwrap(),
        RouteValidation::None
    ));
    let params = checks(routes.remove("POST /params").unwrap()).unwrap();
    assert_eq!((params.required.len(), params.models.len()), (1, 0));
    let body = checks(routes.remove("POST /body").unwrap()).unwrap();
    assert_eq!((body.required.len(), body.models.len()), (0, 1));
}

fn parameter_route() -> RouteValidation {
    let paths = json!({"/items/{id}": {"get": operation(&json!({"parameters": [
        {"name": "id", "in": "path", "required": true},
        {"name": "X-Token", "in": "header", "required": true},
        {"name": "limit", "in": "query", "required": true},
        {"name": "page", "in": "query", "required": false},
        {"name": "session", "in": "cookie", "required": true}
    ]}))}});
    compile(&paths, &json!({}))
        .remove("GET /items/{id}")
        .unwrap()
}

fn with_parameters(query: Option<&str>, headers: &[(&str, &str)]) -> RequestContext {
    let mut ctx = request(ApiKind::Rest);
    ctx.query = QueryString::new(query);
    for (name, value) in headers {
        ctx.headers.insert(
            axum::http::HeaderName::try_from(*name).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    ctx
}

#[tokio::test]
async fn required_parameters_must_be_present() {
    let route = parameter_route();
    assert!(
        route
            .check(&with_parameters(Some("limit=5"), &[("x-token", "t")]))
            .await
            .is_ok()
    );
    let failed = failure(&route, &with_parameters(Some("limit=5"), &[])).await;
    assert_eq!(
        failed.response_type(),
        Some(ResponseType::BadRequestParameters)
    );
    assert_eq!(
        failed.message(),
        "Missing required request parameters: [X-Token]"
    );
    assert_eq!(failed.validation(), None);
}

#[tokio::test]
async fn every_missing_parameter_is_listed() {
    let route = parameter_route();
    let failed = failure(&route, &with_parameters(None, &[])).await;
    assert_eq!(
        failed.message(),
        "Missing required request parameters: [X-Token, limit]"
    );
}

#[tokio::test]
async fn blank_parameters_count_as_missing() {
    let route = parameter_route();
    for (query, header) in [
        ("limit=", "t"),
        ("limit=%20", "t"),
        ("limit", "t"),
        ("limit=1", " "),
    ] {
        let failed = failure(
            &route,
            &with_parameters(Some(query), &[("x-token", header)]),
        )
        .await;
        assert_eq!(
            failed.response_type(),
            Some(ResponseType::BadRequestParameters),
            "{query:?} {header:?}"
        );
    }
}

#[tokio::test]
async fn a_repeated_parameter_with_any_value_is_present() {
    let route = parameter_route();
    assert!(
        route
            .check(&with_parameters(
                Some("limit=&limit=3"),
                &[("x-token", "t")]
            ))
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn parameters_are_checked_before_the_body() {
    let paths = json!({"/a": {"post": operation(&json!({
        "parameters": [{"name": "q", "in": "query", "required": true}],
        "requestBody": body_of(&json!({"application/json": {"schema": {"type": "object"}}}))
    }))}});
    let route = compile(&paths, &json!({})).remove("POST /a").unwrap();
    let mut ctx = with_body(Some("application/json"), "[]");
    let failed = failure(&route, &ctx).await;
    assert_eq!(
        failed.response_type(),
        Some(ResponseType::BadRequestParameters)
    );
    ctx.query = QueryString::new(Some("q=1"));
    let failed = failure(&route, &ctx).await;
    assert_eq!(failed.response_type(), Some(ResponseType::BadRequestBody));
}

#[tokio::test]
async fn large_bodies_are_checked_off_the_async_threads() {
    let route = pet_route();
    let items: Vec<Value> = (0..INLINE_BODY_BYTES).map(|n| json!(n)).collect();
    let big = json!({"name": "Rex", "owner": {"id": 1}, "tags": items}).to_string();
    assert!(big.len() > INLINE_BODY_BYTES);
    assert!(route.check(&with_body(None, &big)).await.is_ok());
    let broken = json!({"name": "Rex", "tags": items}).to_string();
    let failed = failure(&route, &with_body(None, &broken)).await;
    assert_eq!(failed.response_type(), Some(ResponseType::BadRequestBody));
}

#[tokio::test]
async fn the_reported_violations_are_bounded() {
    let paths = json!({"/a": {"post": operation(&json!({"requestBody": body_of(&json!({
        "application/json": {"schema": {"type": "array", "items": {"type": "string", "maxLength": 1}}}
    }))}))}});
    let route = compile(&paths, &json!({})).remove("POST /a").unwrap();
    let many = json!(vec!["too long"; 100]).to_string();
    let failed = failure(&route, &with_body(None, &many)).await;
    assert_eq!(
        violations(&failed).matches("too long").count(),
        MAX_REPORTED_ERRORS
    );

    let paths = json!({"/a": {"post": operation(&json!({"requestBody": body_of(&json!({
        "application/json": {"schema": {"type": "object", "properties": {"v": {"type": "integer"}}}}
    }))}))}});
    let route = compile(&paths, &json!({})).remove("POST /a").unwrap();
    let huge = json!({"v": "x".repeat(10_000)}).to_string();
    let failed = failure(&route, &with_body(None, &huge)).await;
    assert!(violations(&failed).chars().count() <= MAX_ERROR_CHARS.saturating_add(4));
    assert!(violations(&failed).ends_with("...]"));
}

#[tokio::test]
async fn routes_without_validation_admit_everything() {
    assert!(
        RouteValidation::None
            .check(&with_body(Some("application/json"), "{"))
            .await
            .is_ok()
    );
}
