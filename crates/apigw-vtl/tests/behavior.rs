//! The public API: what the gateway sees of rendering, limits, and errors.

#![expect(clippy::unwrap_used, reason = "test code")]

use apigw_vtl::{
    InputParams, Limits, Map, ParseError, RenderError, Renderer, SimpleInput, Template, Value,
};

fn map(json: &str) -> Map {
    match Value::from_json(json) {
        Ok(Value::Map(map)) => map,
        _ => Map::new(),
    }
}

fn input(body: &str) -> SimpleInput {
    SimpleInput::new(body, InputParams::default())
}

fn render(template: &str) -> Result<String, RenderError> {
    render_with(template, "{}", Limits::default())
}

fn render_with(template: &str, body: &str, limits: Limits) -> Result<String, RenderError> {
    let template = Template::parse(template).map_err(|err| RenderError::Method {
        method: "parse".to_owned(),
        message: err.to_string(),
    })?;
    Renderer::new(&input(body))
        .with_limits(limits)
        .render(&template)
}

#[test]
fn context_overrides_are_readable_after_rendering() {
    let context = map(
        r#"{"requestOverride":{"header":{},"path":{},"querystring":{}},"responseOverride":{"header":{}}}"#,
    );
    let template = Template::parse(
        "#set($context.requestOverride.header.X-Tenant = 'acme')\n\
         #set($context.requestOverride.querystring.page = 2)\n\
         #set($context.responseOverride.status = 201)\n\
         #set($context.responseOverride.header.Location = '/items/1')",
    )
    .unwrap();
    let request = input("{}");
    let output = Renderer::new(&request)
        .with_context(context.clone())
        .render(&template)
        .unwrap();
    assert_eq!(output, "");
    let overrides = Value::Map(context).to_json().unwrap();
    assert_eq!(
        overrides,
        r#"{"requestOverride":{"header":{"X-Tenant":"acme"},"path":{},"querystring":{"page":2}},"responseOverride":{"header":{"Location":"/items/1"},"status":201}}"#
    );
}

#[test]
fn context_and_stage_variables_are_nested_maps() {
    let template =
        Template::parse("$context.identity.sourceIp $stageVariables.region $context.missing")
            .unwrap();
    let request = input("{}");
    let output = Renderer::new(&request)
        .with_context(map(r#"{"identity":{"sourceIp":"10.0.0.1"}}"#))
        .with_stage_variables(map(r#"{"region":"eu"}"#))
        .render(&template)
        .unwrap();
    assert_eq!(output, "10.0.0.1 eu $context.missing");
}

#[test]
fn input_params_search_path_then_query_then_headers() {
    let params = InputParams {
        path: map(r#"{"id":"p"}"#),
        querystring: map(r#"{"id":"q","page":"2"}"#),
        header: map(r#"{"X-Trace":"t"}"#),
    };
    let request = SimpleInput::new("{}", params);
    let template = Template::parse("$input.params('id') $input.params('page') $input.params('x-trace') [$input.params('none')]").unwrap();
    let output = Renderer::new(&request).render(&template).unwrap();
    assert_eq!(output, "p 2 t []");
}

#[test]
fn rendering_does_not_carry_state_between_renders() {
    let template = Template::parse("#set($n = $n + 1)[$n]#set($m = 1)$m").unwrap();
    let request = input("{}");
    let renderer = Renderer::new(&request);
    assert_eq!(renderer.render(&template).unwrap(), "[$n]1");
    assert_eq!(renderer.render(&template).unwrap(), "[$n]1");
}

#[test]
fn collections_have_reference_semantics() {
    assert_eq!(
        render("#set($a = [])#set($b = $a)#set($x = $b.add(1))$a.size()#set($m = {})#set($n = $m)#set($n.k = 1)$m").unwrap(),
        "1{k=1}"
    );
}

#[test]
fn loops_stop_after_a_thousand_iterations() {
    assert_eq!(
        render("#set($n = 0)#foreach($i in [1..5000])#set($n = $n + 1)#end$n").unwrap(),
        "1000"
    );
}

#[test]
fn output_beyond_the_limit_is_an_error() {
    let limits = Limits::default().with_output_bytes(100);
    assert_eq!(
        render_with("#foreach($i in [1..50])0123456789#end", "{}", limits),
        Err(RenderError::OutputLimit { limit: 100 })
    );
    assert!(render_with("short", "{}", limits).is_ok());
}

#[test]
fn nested_loops_that_print_nothing_hit_the_step_budget() {
    let limits = Limits::default().with_steps(10_000);
    assert_eq!(
        render_with(
            "#foreach($a in [1..1000])#foreach($b in [1..1000])#end#end",
            "{}",
            limits
        ),
        Err(RenderError::StepLimit { limit: 10_000 })
    );
}

#[test]
fn huge_ranges_are_charged_to_the_step_budget() {
    assert!(matches!(
        render("#foreach($i in [1..2000000000])#end"),
        Err(RenderError::StepLimit { .. })
    ));
}

#[test]
fn evaluation_depth_is_limited() {
    let limits = Limits::default().with_depth(8);
    let mut template = String::new();
    for _ in 0..20 {
        template.push_str("#if(true)");
    }
    template.push('x');
    for _ in 0..20 {
        template.push_str("#end");
    }
    assert_eq!(
        render_with(&template, "{}", limits),
        Err(RenderError::DepthLimit { limit: 8 })
    );
}

#[test]
fn deeply_nested_templates_are_rejected_when_parsed() {
    let depth = 200;
    let source = format!("{}x{}", "#if(true)".repeat(depth), "#end".repeat(depth));
    assert!(matches!(
        Template::parse(&source),
        Err(ParseError::TooDeep { .. })
    ));
    let expression = format!("#set($x = {}1{})", "(".repeat(depth), ")".repeat(depth));
    assert!(matches!(
        Template::parse(&expression),
        Err(ParseError::TooDeep { .. })
    ));
    let list = format!("#set($x = {}1{})", "[".repeat(depth), "]".repeat(depth));
    assert!(matches!(
        Template::parse(&list),
        Err(ParseError::TooDeep { .. })
    ));
}

#[test]
fn self_referencing_collections_do_not_overflow_the_stack() {
    assert_eq!(
        render("#set($l = [])#set($x = $l.add($l))$l"),
        Err(RenderError::CircularReference)
    );
    assert_eq!(
        render("#set($m = {})#set($m.self = $m)"),
        Err(RenderError::CircularReference)
    );
    assert_eq!(
        render("#set($a = [])#set($b = [$a])#set($r = $a.add($b))"),
        Err(RenderError::CircularReference)
    );
}

#[test]
fn unsupported_directives_are_typed_errors() {
    for directive in [
        "#macro(m)x#end",
        "#parse('a')",
        "#include('a')",
        "#evaluate('a')",
        "#define($b)x#end",
    ] {
        assert!(
            matches!(
                Template::parse(directive),
                Err(ParseError::UnsupportedDirective { .. })
            ),
            "{directive}"
        );
    }
}

#[test]
fn syntax_errors_report_where_they_are() {
    let error = Template::parse("a\nb #if(true)\n").unwrap_err();
    assert!(
        matches!(
            error,
            ParseError::Syntax {
                line: 3,
                column: 1,
                ..
            }
        ),
        "{error:?}"
    );
    assert!(matches!(
        Template::parse("#set($a = 99999999999999999999)"),
        Err(ParseError::IntegerLiteralTooLarge { .. })
    ));
}

#[test]
fn method_failures_are_render_errors() {
    assert!(matches!(
        render("#set($s = 'abc')$s.substring(9)"),
        Err(RenderError::Method { .. })
    ));
    assert!(matches!(
        render("#set($l = [1])$l.get(5)"),
        Err(RenderError::Method { .. })
    ));
    assert!(matches!(
        render("$util.base64Decode('***')"),
        Err(RenderError::Method { .. })
    ));
    assert!(matches!(
        render("$util.parseJson('{')"),
        Err(RenderError::Method { .. })
    ));
    assert!(matches!(
        render("#set($s = 'a')$s.matches('(')"),
        Err(RenderError::Method { .. })
    ));
}

#[test]
fn indexing_outside_a_list_is_an_error() {
    assert_eq!(
        render("#set($l = [1])$l[3]"),
        Err(RenderError::IndexOutOfBounds { index: 3, len: 1 })
    );
}

#[test]
fn changing_a_list_while_iterating_it_is_an_error() {
    assert_eq!(
        render("#set($l = [1, 2, 3])#foreach($i in $l)#set($r = $l.add(9))#end"),
        Err(RenderError::ConcurrentModification)
    );
}

#[test]
fn integer_overflow_is_an_error_not_a_wrapped_value() {
    assert_eq!(
        render("#set($a = 9223372036854775807)#set($b = $a + 1)$b"),
        Err(RenderError::IntegerOverflow)
    );
}

#[test]
fn json_paths_need_a_json_body() {
    assert!(matches!(
        render_with("$input.path('$.a')", "not json", Limits::default()),
        Err(RenderError::InvalidBodyJson(_))
    ));
    assert!(matches!(
        render_with("$input.path('$.a[')", "{}", Limits::default()),
        Err(RenderError::InvalidJsonPath { .. })
    ));
    assert_eq!(
        render_with("[$input.body]", "not json", Limits::default()).unwrap(),
        "[not json]"
    );
}

#[test]
fn input_json_is_compact_json_and_path_is_a_java_object() {
    let body = r#"{ "a" : [ 1, 2 ], "b": { "c": "é\"" } }"#;
    assert_eq!(
        render_with("$input.json('$') $input.path('$')", body, Limits::default()).unwrap(),
        r#"{"a":[1,2],"b":{"c":"é\""}} {a=[1, 2], b={c=é"}}"#
    );
}

#[test]
fn input_path_results_alias_the_parsed_body() {
    assert_eq!(
        render_with(
            "#set($a = $input.path('$.items'))#set($x = $a.add(3))$input.path('$.items')",
            r#"{"items":[1,2]}"#,
            Limits::default()
        )
        .unwrap(),
        "[1, 2, 3]"
    );
}

#[test]
fn util_functions_follow_api_gateway() {
    assert_eq!(
        render("$util.base64Encode('héllo') $util.base64Decode('aMOpbGxv') $util.urlEncode('a b&c/é') $util.urlDecode('a+b%26c')").unwrap(),
        "aMOpbGxv héllo a+b%26c%2F%C3%A9 a b&c"
    );
}

#[test]
fn escape_java_script_escapes_quotes_slashes_and_non_ascii() {
    assert_eq!(
        render("#set($s = \"a'b\")$util.escapeJavaScript($s)").unwrap(),
        "a\\'b"
    );
    assert_eq!(
        render("$util.escapeJavaScript('é/')").unwrap(),
        "\\u00E9\\/"
    );
}

#[test]
fn values_and_templates_can_cross_threads() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Template>();
    assert_send_sync::<Value>();
    assert_send_sync::<Map>();
    assert_send_sync::<SimpleInput>();
}

#[test]
fn paren_before_a_closing_directive_is_text_not_a_method_call() {
    assert_eq!(
        render("#foreach($i in [1])$foreach.hasNext(#end").unwrap(),
        "false("
    );
    assert!(render("#foreach($i in [1])$foreach.hasNext( #end").is_err());
}
