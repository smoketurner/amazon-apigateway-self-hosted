use axum::http::HeaderValue;
use serde::Deserialize;
use serde_json::{Value, json};

use super::*;
use crate::gateway_response::GatewayResponses;
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
        (
            r#"{"name": "Rex"}"#,
            r#"[object has missing required properties (["owner"])]"#,
        ),
        (
            r#"{"name": "R", "owner": {"id": 1}}"#,
            r#"[string "R" is too short (length: 1, required minimum: 2)]"#,
        ),
        (
            r#"{"name": "Rex", "owner": {"id": "x"}}"#,
            r#"[instance type (string) does not match any allowed primitive type (allowed: ["integer"]), format attribute "int32" not supported]"#,
        ),
        (
            r#"{"name": "Rex", "age": -1, "owner": {"id": 1}}"#,
            r#"[numeric instance is lower than the required minimum (minimum: 0, found: -1), format attribute "int32" not supported]"#,
        ),
        (
            r#"{"name": "Rex", "owner": {}}"#,
            r#"[object has missing required properties (["id"])]"#,
        ),
        (
            "[]",
            r#"[instance type (array) does not match any allowed primitive type (allowed: ["object"])]"#,
        ),
    ] {
        let failed = failure(&route, &with_body(Some("application/json"), body)).await;
        assert_eq!(
            failed.response_type(),
            Some(ResponseType::BadRequestBody),
            "{body}"
        );
        assert_eq!(failed.message(), Some("Invalid request body"));
        assert_eq!(violations(&failed), expected, "{body}");
    }
}

#[tokio::test]
async fn malformed_and_empty_bodies_are_invalid() {
    let route = pet_route();
    for body in ["", "{", "not json", "\u{0}"] {
        let failed = failure(&route, &with_body(Some("application/json"), body)).await;
        assert_eq!(
            failed.response_type(),
            Some(ResponseType::BadRequestBody),
            "{body:?}"
        );
        assert_eq!(
            violations(&failed),
            "[Unknown error parsing request body]",
            "{body:?}"
        );
    }
}

/// The reference REST API's `Item` model, behind `POST /validated/{id}`.
fn item_route() -> RouteValidation {
    schema_route(
        &json!({"$ref": "#/components/schemas/Item"}),
        &json!({
            "Item": {
                "type": "object",
                "required": ["name"],
                "additionalProperties": false,
                "properties": {
                    "name": {"type": "string", "minLength": 1},
                    "count": {"type": "integer", "minimum": 0}
                }
            }
        }),
    )
}

fn schema_route(schema: &Value, models: &Value) -> RouteValidation {
    let paths = json!({"/a": {"post": operation(&json!({
        "requestBody": body_of(&json!({"application/json": {"schema": schema}}))
    }))}});
    compile(&paths, models).remove("POST /a").unwrap()
}

fn with_bytes(body: &[u8]) -> RequestContext {
    let mut ctx = with_body(Some("application/json"), "");
    ctx.body = Bytes::copy_from_slice(body);
    ctx
}

/// The `validationErrorString` of a body that breaks `schema`.
async fn violation(schema: &Value, body: &str) -> String {
    let route = schema_route(schema, &json!({}));
    violations(&failure(&route, &with_body(None, body)).await).to_owned()
}

async fn passes(schema: &Value, body: &str) -> bool {
    schema_route(schema, &json!({}))
        .check(&with_body(None, body))
        .await
        .is_ok()
}

const REFERENCE_BODY_TEMPLATE: &str =
    r#"{"message":$context.error.validationErrorString,"type":"$context.error.responseType"}"#;

/// One request body sent to the reference REST API's `POST /validated/{id}`
/// and what API Gateway answered.
#[derive(Deserialize)]
struct Recorded {
    body: String,
    status: u16,
    /// The response body, when the request was refused.
    response: Option<String>,
}

/// What the `Item` route answers `body` with through the reference API's
/// `BAD_REQUEST_BODY` gateway response, or `None` when the body passes.
async fn item_response(body: &[u8]) -> Option<String> {
    let specs = serde_json::from_value(json!({
        "BAD_REQUEST_BODY": {"responseTemplates": {"application/json": REFERENCE_BODY_TEMPLATE}}
    }))
    .unwrap();
    let ctx = with_bytes(body);
    let failed = item_route().check(&ctx).await.err()?;
    assert_eq!(failed.response_type(), Some(ResponseType::BadRequestBody));
    let response = GatewayResponses::compile(ApiKind::Rest, &specs).render(&failed, &ctx);
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    Some(String::from_utf8(bytes.to_vec()).unwrap())
}

/// Replays `tests/fixtures/rest-validation-errors.jsonl`: bodies recorded
/// against the reference REST API on 2026-11-19, with the exact response body
/// API Gateway rendered from `$context.error.validationErrorString`.
#[tokio::test]
async fn violations_read_as_api_gateway_reports_them() {
    let recorded = include_str!("../../tests/fixtures/rest-validation-errors.jsonl");
    let mut refused = 0_usize;
    for line in recorded.lines() {
        let Recorded {
            body,
            status,
            response,
        } = serde_json::from_str(line).unwrap();
        assert_eq!(status == 200, response.is_none(), "{body:?}");
        assert_eq!(item_response(body.as_bytes()).await, response, "{body:?}");
        refused = refused.saturating_add(usize::from(response.is_some()));
    }
    assert_eq!(refused, 101);
}

/// The four requests the wording was first compared on.
#[tokio::test]
async fn the_reference_requests_answer_as_api_gateway_does() {
    for (body, expected) in [
        (
            "{}",
            r#"{"message":[object has missing required properties ([\"name\"])],"type":"BAD_REQUEST_BODY"}"#,
        ),
        (
            r#"{"name":5}"#,
            r#"{"message":[instance type (integer) does not match any allowed primitive type (allowed: [\"string\"])],"type":"BAD_REQUEST_BODY"}"#,
        ),
        (
            "not json",
            r#"{"message":[Unknown error parsing request body],"type":"BAD_REQUEST_BODY"}"#,
        ),
        (
            "",
            r#"{"message":[Unknown error parsing request body],"type":"BAD_REQUEST_BODY"}"#,
        ),
    ] {
        assert_eq!(
            item_response(body.as_bytes()).await.as_deref(),
            Some(expected),
            "{body:?}"
        );
    }
}

/// Measured on the reference REST API: bytes that are not UTF-8 are read as
/// U+FFFD and a byte order mark is skipped.
#[tokio::test]
async fn bodies_that_are_not_utf8_are_read_as_api_gateway_reads_them() {
    assert_eq!(item_response(b"{\"name\":\"\xff\"}").await, None);
    for (body, expected) in [
        (
            b"\xff".as_slice(),
            r#"{"message":[Unknown error parsing request body],"type":"BAD_REQUEST_BODY"}"#,
        ),
        (
            b"\xef\xbb\xbf{}".as_slice(),
            r#"{"message":[object has missing required properties ([\"name\"])],"type":"BAD_REQUEST_BODY"}"#,
        ),
        (
            b"{\"name\":\"a\",\"\xff\":1}".as_slice(),
            "{\"message\":[object instance has properties which are not allowed by the schema: [\\\"\\uFFFD\\\"]],\"type\":\"BAD_REQUEST_BODY\"}",
        ),
    ] {
        assert_eq!(
            item_response(body).await.as_deref(),
            Some(expected),
            "{body:?}"
        );
    }
}

#[tokio::test]
async fn enum_violations_use_the_validators_wording() {
    let schema = json!({"enum": ["a", 1, 1.5, null, {"k": [true]}]});
    assert_eq!(
        violation(&schema, r#""b""#).await,
        r#"[instance value ("b") not found in enum (possible values: ["a",1,1.5,null,{"k":[true]}])]"#
    );
    assert_eq!(
        violation(&schema, r#"{"k":[false],"n":2.50}"#).await,
        r#"[instance value ({"k":[false],"n":2.5}) not found in enum (possible values: ["a",1,1.5,null,{"k":[true]}])]"#
    );
    for member in ["\"a\"", "1", "1.0", "15e-1", "null", r#"{"k":[true]}"#] {
        assert!(passes(&schema, member).await, "{member}");
    }
}

#[tokio::test]
async fn numeric_violations_use_the_validators_wording() {
    for (schema, body, expected) in [
        (
            json!({"maximum": 10}),
            "11",
            "[numeric instance is greater than the required maximum (maximum: 10, found: 11)]",
        ),
        (
            json!({"maximum": 10}),
            "10.5",
            "[numeric instance is greater than the required maximum (maximum: 10, found: 10.5)]",
        ),
        (
            json!({"maximum": 10, "exclusiveMaximum": true}),
            "10",
            "[numeric instance is not strictly lower than the required maximum 10]",
        ),
        (
            json!({"minimum": 2.5}),
            "2",
            "[numeric instance is lower than the required minimum (minimum: 2.5, found: 2)]",
        ),
        (
            json!({"minimum": 0, "exclusiveMinimum": true}),
            "0.0",
            "[numeric instance is not strictly greater than the required minimum 0]",
        ),
        (
            json!({"multipleOf": 2}),
            "7",
            "[remainder of division is not zero (7 / 2)]",
        ),
        (
            json!({"multipleOf": 0.1}),
            "0.35",
            "[remainder of division is not zero (0.35 / 0.1)]",
        ),
        (
            json!({"multipleOf": 100}),
            "1e-3",
            "[remainder of division is not zero (0.001 / 100)]",
        ),
    ] {
        assert_eq!(violation(&schema, body).await, expected, "{schema} {body}");
    }
    for (schema, body) in [
        (json!({"maximum": 10}), "10"),
        (json!({"maximum": 10}), "10.0"),
        (json!({"maximum": 10, "exclusiveMaximum": true}), "9.999"),
        (json!({"minimum": 0, "exclusiveMinimum": true}), "1e-300"),
        (json!({"minimum": 18_446_744_073_709_551_615_u64}), "1.9e19"),
        (json!({"multipleOf": 2}), "8"),
        (json!({"multipleOf": 0.1}), "0.3"),
        (json!({"multipleOf": 0.01}), "1e30"),
        (json!({"multipleOf": 2.5}), "-7.5"),
        (json!({"multipleOf": 3}), "0"),
        (json!({"maximum": 1}), "\"not a number\""),
    ] {
        assert!(passes(&schema, body).await, "{schema} {body}");
    }
}

#[tokio::test]
async fn string_violations_use_the_validators_wording() {
    for (schema, body, expected) in [
        (
            json!({"maxLength": 2}),
            "\"h\u{e9}llo\"",
            "[string \"h\u{e9}llo\" is too long (length: 5, maximum allowed: 2)]",
        ),
        (
            json!({"minLength": 2}),
            "\"\u{1f600}\"",
            "[string \"\u{1f600}\" is too short (length: 1, required minimum: 2)]",
        ),
        (
            json!({"pattern": "^[a-z]+$"}),
            r#""A1""#,
            r#"[ECMA 262 regex "^[a-z]+$" does not match input string "A1"]"#,
        ),
        (
            json!({"pattern": "^\\d+$"}),
            "\"\u{663}\"",
            "[ECMA 262 regex \"^\\d+$\" does not match input string \"\u{663}\"]",
        ),
        (
            json!({"type": "string", "format": "password", "maxLength": 1}),
            r#""ab""#,
            r#"[format attribute "password" not supported, string "ab" is too long (length: 2, maximum allowed: 1)]"#,
        ),
        (
            json!({"type": "integer", "format": "int64", "maximum": 1}),
            "2",
            r#"[numeric instance is greater than the required maximum (maximum: 1, found: 2), format attribute "int64" not supported]"#,
        ),
        (
            json!({"type": "string", "format": "email", "maxLength": 1}),
            r#""ab""#,
            r#"[string "ab" is too long (length: 2, maximum allowed: 1)]"#,
        ),
    ] {
        assert_eq!(violation(&schema, body).await, expected, "{schema} {body}");
    }
    for (schema, body) in [
        (json!({"maxLength": 1}), "\"\u{1f600}\""),
        (json!({"pattern": "b"}), "\"abc\""),
        (json!({"pattern": "^a"}), "5"),
        (json!({"format": "password"}), "\"secret\""),
        (
            json!({"type": "string", "format": "uuid"}),
            "\"not a uuid\"",
        ),
        (json!({"type": "integer"}), "5"),
    ] {
        assert!(passes(&schema, body).await, "{schema} {body}");
    }
}

#[tokio::test]
async fn array_violations_use_the_validators_wording() {
    for (schema, body, expected) in [
        (
            json!({"minItems": 2}),
            "[1]",
            "[array is too short: must have at least 2 elements but instance has 1 elements]",
        ),
        (
            json!({"maxItems": 1}),
            "[1,2]",
            "[array is too long: must have at most 1 elements but instance has 2 elements]",
        ),
        (
            json!({"uniqueItems": true}),
            "[1,2,1.0]",
            "[array must not contain duplicate elements]",
        ),
        (
            json!({"uniqueItems": true}),
            r#"[{"a":1,"b":2},{"b":2,"a":1}]"#,
            "[array must not contain duplicate elements]",
        ),
        (
            json!({"items": [{}, {}], "additionalItems": false}),
            "[1,2,3]",
            "[schema only allows 2 elements in array but instance has 3 elements]",
        ),
        (
            json!({"items": [{"type": "string"}], "additionalItems": {"type": "boolean"}}),
            r#"["a",1]"#,
            r#"[instance type (integer) does not match any allowed primitive type (allowed: ["boolean"])]"#,
        ),
        (
            json!({"items": {"type": "string"}}),
            r#"[1,"a",null]"#,
            r#"[instance type (integer) does not match any allowed primitive type (allowed: ["string"]), instance type (null) does not match any allowed primitive type (allowed: ["string"])]"#,
        ),
        (
            json!({"maxItems": 1, "items": {"type": "string"}}),
            "[1,2]",
            "[array is too long: must have at most 1 elements but instance has 2 elements]",
        ),
    ] {
        assert_eq!(violation(&schema, body).await, expected, "{schema} {body}");
    }
    for (schema, body) in [
        (
            json!({"uniqueItems": true}),
            r#"[1,"1",[1],{"a":1},true,null]"#,
        ),
        (json!({"items": [{"type": "string"}]}), r#"["a",1]"#),
        (json!({"minItems": 2}), "\"x\""),
    ] {
        assert!(passes(&schema, body).await, "{schema} {body}");
    }
}

#[tokio::test]
async fn object_violations_use_the_validators_wording() {
    for (schema, body, expected) in [
        (
            json!({"minProperties": 2}),
            r#"{"a":1}"#,
            "[object has too few properties (found 1 but schema requires at least 2)]",
        ),
        (
            json!({"maxProperties": 1}),
            r#"{"a":1,"b":2}"#,
            "[object has too many properties (found 2 but schema requires at most 1)]",
        ),
        (
            json!({"required": ["b", "c", "a"]}),
            r#"{"c":1}"#,
            r#"[object has missing required properties (["a","b"])]"#,
        ),
        (
            json!({"dependencies": {"card": ["cvv", "address"]}}),
            r#"{"card":1,"cvv":2}"#,
            r#"[property "card" of object has missing property dependencies (schema requires ["address","cvv"]; missing: ["address"])]"#,
        ),
        (
            json!({"dependencies": {"card": {"required": ["cvv"]}}}),
            r#"{"card":1}"#,
            r#"[object has missing required properties (["cvv"])]"#,
        ),
        (
            json!({"patternProperties": {"^x-": {"type": "string"}}, "additionalProperties": false}),
            r#"{"x-a":1,"y":2}"#,
            r#"[object instance has properties which are not allowed by the schema: ["y"]]"#,
        ),
        (
            json!({"patternProperties": {"^x-": {"type": "string"}}, "additionalProperties": false}),
            r#"{"x-a":1}"#,
            r#"[instance type (integer) does not match any allowed primitive type (allowed: ["string"])]"#,
        ),
        (
            json!({"properties": {"a": {}}, "additionalProperties": {"type": "boolean"}}),
            r#"{"a":1,"b":2}"#,
            r#"[instance type (integer) does not match any allowed primitive type (allowed: ["boolean"])]"#,
        ),
        (
            json!({"type": ["string", "null", "integer", "null"]}),
            "true",
            r#"[instance type (boolean) does not match any allowed primitive type (allowed: ["integer","null","string"])]"#,
        ),
        (
            json!({"type": ["object", "number", "array", "boolean"]}),
            "null",
            r#"[instance type (null) does not match any allowed primitive type (allowed: ["array","boolean","integer","number","object"])]"#,
        ),
        (
            json!({"type": ["number", "null"]}),
            "\"x\"",
            r#"[instance type (string) does not match any allowed primitive type (allowed: ["integer","null","number"])]"#,
        ),
    ] {
        assert_eq!(violation(&schema, body).await, expected, "{schema} {body}");
    }
    for (schema, body) in [
        (json!({"dependencies": {"card": ["cvv"]}}), r#"{"cvv":1}"#),
        (json!({"type": "number"}), "3"),
        (json!({"required": ["a"]}), "[]"),
    ] {
        assert!(passes(&schema, body).await, "{schema} {body}");
    }
}

/// The validator checks every member's own keywords, but looks inside a
/// member only while nothing has failed yet; members are visited in sorted
/// order.
#[tokio::test]
async fn nothing_is_descended_into_after_the_first_violation() {
    let text = json!({"type": "string"});
    let nested = json!({"properties": {"inner": text}});
    let wrong = r#"instance type (integer) does not match any allowed primitive type (allowed: ["string"])"#;
    let too_few = "object has too few properties (found 1 but schema requires at least 2)";
    for (schema, body, expected) in [
        (
            json!({"properties": {"a": text, "b": nested}}),
            r#"{"b":{"inner":2},"a":1}"#,
            format!("[{wrong}]"),
        ),
        (
            json!({"properties": {"z": {"minProperties": 2}, "b": nested}}),
            r#"{"z":{"k":1},"b":{"inner":2}}"#,
            format!("[{too_few}, {wrong}]"),
        ),
        (
            json!({"properties": {"a": text, "b": {"minProperties": 2, "properties": {"inner": text}}}}),
            r#"{"a":1,"b":{"inner":2}}"#,
            format!("[{too_few}, {wrong}]"),
        ),
        (
            json!({"minProperties": 2, "properties": {"a": text}}),
            r#"{"a":1}"#,
            format!("[{too_few}]"),
        ),
    ] {
        assert_eq!(violation(&schema, body).await, expected, "{schema} {body}");
    }
}

#[tokio::test]
async fn combined_schemas_report_one_message_of_their_own() {
    let both = json!([{"type": "string"}, {"minLength": 3}]);
    for (schema, body, expected) in [
        (
            json!({"allOf": [{"type": "string"}, {"minLength": 3}, {"maxLength": 5}]}),
            r#""ab""#,
            "[instance failed to match all required schemas (matched only 2 out of 3)]",
        ),
        (
            json!({"anyOf": [{"type": "string"}, {"type": "boolean"}]}),
            "5",
            "[instance failed to match at least one required schema among 2]",
        ),
        (
            json!({"oneOf": both}),
            "\"abcd\"",
            "[instance failed to match exactly one schema (matched 2 out of 2)]",
        ),
        (
            json!({"oneOf": [{"type": "string"}, {"type": "boolean"}]}),
            "5",
            "[instance failed to match exactly one schema (matched 0 out of 2)]",
        ),
        (
            json!({"not": {"type": "string"}}),
            "\"a\"",
            "[instance matched a schema which it should not have]",
        ),
        (
            json!({"anyOf": [{"properties": {"a": {"type": "integer"}}}]}),
            r#"{"a":"x"}"#,
            "[instance failed to match at least one required schema among 1]",
        ),
    ] {
        assert_eq!(violation(&schema, body).await, expected, "{schema} {body}");
    }
    for (schema, body) in [
        (json!({"anyOf": both}), "\"a\""),
        (json!({"oneOf": both}), "\"ab\""),
        (json!({"not": {"type": "string"}}), "1"),
    ] {
        assert!(passes(&schema, body).await, "{schema} {body}");
    }
}

#[tokio::test]
async fn equal_violations_are_reported_once() {
    let schema = json!({"type": "array", "items": {"type": "string", "maxLength": 1}});
    let many = json!(vec!["too long"; 100]).to_string();
    assert_eq!(
        violation(&schema, &many).await,
        r#"[string "too long" is too long (length: 8, maximum allowed: 1)]"#
    );
}

#[tokio::test]
async fn a_very_large_report_is_cut_off() {
    let schema = json!({"type": "array", "items": {"type": "string", "maxLength": 1}});
    let texts: Vec<String> = (0..4000).map(|n| format!("{n:0>1000}")).collect();
    let text = violation(&schema, &json!(texts).to_string()).await;
    assert!(text.len() > 1024 * 1024, "{}", text.len());
    assert!(text.len() < 1024 * 1024 + 4096, "{}", text.len());
    assert!(text.starts_with("[string \"") && text.ends_with(']'));
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
        (
            "a subschema that is not an object",
            json!({"properties": {"a": true}}),
        ),
        (
            "a reference that refers to itself",
            json!({"properties": {"a": {"$ref": "#/properties/a"}}}),
        ),
        (
            "a schema that applies to a value through itself",
            json!({"allOf": [{"anyOf": [{"$ref": "#"}]}]}),
        ),
        (
            "a pattern that is not a regular expression",
            json!({"pattern": "("}),
        ),
        ("a negative length", json!({"minLength": -1})),
        ("a divisor of zero", json!({"multipleOf": 0})),
        ("a required that is not a list", json!({"required": true})),
        ("an empty allOf", json!({"allOf": []})),
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
        Some("Missing required request parameters: [X-Token]")
    );
    assert_eq!(failed.validation(), None);
}

#[tokio::test]
async fn every_missing_parameter_is_listed() {
    let route = parameter_route();
    let failed = failure(&route, &with_parameters(None, &[])).await;
    assert_eq!(
        failed.message(),
        Some("Missing required request parameters: [X-Token, limit]")
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
async fn routes_without_validation_admit_everything() {
    assert!(
        RouteValidation::None
            .check(&with_body(Some("application/json"), "{"))
            .await
            .is_ok()
    );
}
