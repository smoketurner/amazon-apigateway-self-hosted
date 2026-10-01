//! Templates whose output was produced by Apache Velocity 1.7 and Jayway `JsonPath` 2.9.
//!
//! The table in `cases.rs` is generated from the real engines by `tools/vtl-oracle`; each case
//! renders against the same request: a JSON body, parameters, `$context`, and stage variables.

mod cases;

use apigw_vtl::{InputParams, Map, Renderer, SimpleInput, Template, Value};

/// What Velocity did with a template.
#[derive(Debug)]
enum Outcome {
    Output(&'static str),
    Failure,
}

#[derive(Debug)]
struct Case {
    name: &'static str,
    template: &'static str,
    /// JSON overriding parts of the standard request: `bodyJson`, `params`, `context`, and
    /// `stageVariables`.
    request: Option<&'static str>,
    outcome: Outcome,
}

/// The request every case renders against unless it overrides part of it.
const STANDARD_REQUEST: &str = r#"{
    "bodyJson": {"items":[{"id":1,"name":"a"},{"id":2,"name":"b"}],"total":2,"price":9.99,"big":3000000000,"name":"n","flag":true},
    "params": {"path":{"id":"7"},"querystring":{"q":"x y"},"header":{"X-H":"hv"}},
    "context": {"requestId":"r1","identity":{"sourceIp":"1.2.3.4"},"requestOverride":{"header":{},"querystring":{},"path":{}}},
    "stageVariables": {"env":"dev"}
}"#;

/// One request: a JSON body, method parameters, `$context`, and stage variables.
struct Request {
    body: String,
    params: InputParams,
    context: Map,
    stage_variables: Map,
}

fn object(value: &Value, key: &str) -> Map {
    match value {
        Value::Map(map) => match map.get(key) {
            Some(Value::Map(inner)) => inner,
            _ => Map::new(),
        },
        _ => Map::new(),
    }
}

impl Request {
    /// The standard request with the parts named in `overrides` replaced.
    fn new(overrides: Option<&str>) -> Self {
        let fixture = parse(STANDARD_REQUEST);
        if let (Value::Map(base), Value::Map(changes)) =
            (&fixture, parse(overrides.unwrap_or("{}")))
        {
            for (key, value) in changes.entries() {
                base.insert(key, value);
            }
        }
        let body = match &fixture {
            Value::Map(map) => map.get("bodyJson").and_then(|json| json.to_json().ok()),
            _ => None,
        };
        let params = object(&fixture, "params");
        Self {
            body: body.unwrap_or_default(),
            params: InputParams {
                path: object(&Value::Map(params.clone()), "path"),
                querystring: object(&Value::Map(params.clone()), "querystring"),
                header: object(&Value::Map(params), "header"),
            },
            context: object(&fixture, "context"),
            stage_variables: object(&fixture, "stageVariables"),
        }
    }
}

fn parse(json: &str) -> Value {
    Value::from_json(json).unwrap_or(Value::Null)
}

fn render(template: &str, overrides: Option<&str>) -> Result<String, String> {
    let template = Template::parse(template).map_err(|err| err.to_string())?;
    let request = Request::new(overrides);
    let input = SimpleInput::new(request.body, request.params);
    Renderer::new(&input)
        .with_context(request.context)
        .with_stage_variables(request.stage_variables)
        .render(&template)
        .map_err(|err| err.to_string())
}

#[test]
fn renders_like_apache_velocity() {
    let mut failures = Vec::new();
    for case in cases::CASES {
        let got = render(case.template, case.request);
        let matches = match (&case.outcome, &got) {
            (Outcome::Output(expected), Ok(output)) => expected == output,
            (Outcome::Failure, Err(_)) => true,
            (Outcome::Output(_) | Outcome::Failure, Ok(_) | Err(_)) => false,
        };
        if !matches {
            failures.push(format!(
                "{}: velocity {:?}, got {:?}\n  template: {:?}",
                case.name, case.outcome, got, case.template
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases differ:\n{}",
        failures.len(),
        cases::CASES.len(),
        failures.join("\n")
    );
}
