//! The public API: what the gateway sees of rendering, limits, and errors.

#![expect(clippy::unwrap_used, reason = "test code")]

use apigw_vtl::{
    InputParams, Limits, Map, NullReferences, ParseError, RenderError, Renderer, SimpleInput,
    Template, Value,
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
    for directive in ["#parse('a')", "#include('a')"] {
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
        Template::parse(&format!("#set($a = {})", "9".repeat(20_000))),
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
fn integer_overflow_promotes_to_big_integer() {
    assert_eq!(
        render("#set($a = 9223372036854775807)#set($b = $a + 1)$b").unwrap(),
        "9223372036854775808"
    );
    assert_eq!(
        render("#set($a = 99999999999999999999)#set($b = $a * $a * $a * $a)$b").unwrap(),
        "99999999999999999996000000000000000000059999999999999999999600000000000000000001"
    );
}

#[test]
fn numbers_beyond_the_size_limit_are_errors() {
    let template = format!(
        "#set($a = 9{})#foreach($i in [1..12])#set($a = $a * $a)#end",
        "9".repeat(30)
    );
    assert_eq!(render(&template), Err(RenderError::NumberTooLarge));
    assert!(matches!(
        render("#set($a = 99999999999999999999)#set($b = $a % -7)"),
        Err(RenderError::Arithmetic { .. })
    ));
}

#[test]
fn json_paths_need_a_json_body() {
    assert!(matches!(
        render_with("$input.path('$.a')", "{\"a\":", Limits::default()),
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

/// How a deployed REST API reads the body for `$input.json` and `$input.path`.
#[test]
fn bodies_are_read_the_way_api_gateway_reads_them() {
    let json = |body: &str| render_with("$input.json('$')", body, Limits::default());
    assert_eq!(
        json(""),
        Ok("{}".to_owned()),
        "an empty body is an empty object"
    );
    assert_eq!(json("  "), Ok("{}".to_owned()));
    assert_eq!(json("null"), Ok("{}".to_owned()));
    assert_eq!(
        json("{\"a\":null,\"b\":[null,1]}"),
        Ok("{\"a\":null,\"b\":[null,1]}".to_owned()),
        "nulls inside a body are kept"
    );
    for (body, rendered) in [
        ("not json", "\"not json\""),
        ("tru", "\"tru\""),
        ("12abc", "\"12abc\""),
        ("<xml/>", "\"<xml/>\""),
        ("not json {", "\"not json {\""),
        ("true", "true"),
        ("5", "5"),
        ("\"str\"", "\"str\""),
        ("{\"a\":1} trailing", "{\"a\":1}"),
    ] {
        assert_eq!(json(body), Ok(rendered.to_owned()), "{body}");
    }
    for broken in ["{\"a\":", "[1,", "{bad}", "\"unterminated"] {
        assert!(
            matches!(json(broken), Err(RenderError::InvalidBodyJson(_))),
            "{broken}"
        );
    }
}

fn render_nulls(template: &str, null_references: NullReferences) -> String {
    let template = Template::parse(template).unwrap();
    Renderer::new(&input(r#"{"a":1}"#))
        .with_null_references(null_references)
        .render(&template)
        .unwrap()
}

/// Velocity prints a null reference as written; API Gateway prints nothing (the lead confirms
/// each form against a deployed API in the `/vtl/undefined` recording).
#[test]
fn null_references_render_as_written_or_as_nothing() {
    let forms = "[$undefined][$undefined.prop][$undefined.method()][$!undefined][${undefined}]\
                 [$!{undefined}]#set($m = {})[$m.missing]#set($x = $undefined)[$x]\
                 [$input.path('$.missing')][\\$undefined][\\\\$undefined]";
    assert_eq!(
        render_nulls(forms, NullReferences::Literal),
        "[$undefined][$undefined.prop][$undefined.method()][][${undefined}][][$m.missing][$x]\
         [][\\$undefined][\\\\$undefined]"
    );
    assert_eq!(
        render_nulls(forms, NullReferences::Empty),
        "[][][][][][][][][][\\$undefined][\\]"
    );
    assert_eq!(
        render_nulls("#set($s = $undefined + 'x')$s", NullReferences::Empty),
        "$undefinedx",
        "concatenation appends a null reference as written in both modes"
    );
}

#[test]
fn macros_are_ignored_and_their_calls_render_as_written() {
    assert_eq!(
        render("#set($x = 'outer')#macro(m $x)in=$x #set($y = 'set')#end#m('arg')x=$x y=$!y")
            .unwrap(),
        "#m('arg')x=outer y="
    );
    assert_eq!(
        render("#macro(m)x#end#m(foo bar) #m #@m(1)body $x#end").unwrap(),
        "#m(foo bar) #m #@m(1)body $x#end"
    );
    for broken in [
        "#macro()#end",
        "#macro('m')#end",
        "#macro(m)x",
        "#macro(m foo)#end",
    ] {
        assert!(Template::parse(broken).is_err(), "{broken}");
    }
}

#[test]
fn evaluate_renders_as_written() {
    assert_eq!(
        render("#set($t = '#set($y = 3)$y')#evaluate($t) #evaluate('a' 'b') #evaluate x").unwrap(),
        "#evaluate($t) #evaluate('a' 'b') #evaluate x"
    );
}

#[test]
fn define_renders_its_block_each_time_it_is_used() {
    assert_eq!(
        render("#define($block)x=$x#end#set($x = 1)$block #set($x = 2)$block").unwrap(),
        "x=1x=2"
    );
    assert_eq!(render("#define($d)x$d#end$d").unwrap(), "xx$d");
    assert_eq!(
        render("#define($d)a#break b#end#foreach($i in [1,2])$d#end").unwrap(),
        "aa"
    );
    assert_eq!(render("#define($d)a#stop b#end$d after").unwrap(), "a");
}

#[test]
fn define_blocks_in_context_are_read_back_as_text() {
    let context = Map::new();
    let template: Template = "#define($d)v=$v#end#set($v = 1)#set($context.blk = $d)#set($v = 2)"
        .parse()
        .unwrap();
    Renderer::new(&input("{}"))
        .with_context(context.clone())
        .render(&template)
        .unwrap();
    assert_eq!(context.get("blk").unwrap().to_string(), "v=2");
}

#[test]
#[expect(clippy::format_collect, reason = "builds a test template")]
fn recursive_defines_stop_at_the_depth_limit() {
    let mut template: String = (0..200)
        .map(|i| format!("#define($d{i})<$d{}>#end", i + 1))
        .collect();
    template.push_str("$d0");
    assert!(matches!(
        render(&template),
        Err(RenderError::DepthLimit { .. })
    ));
}

#[test]
fn integers_widen_like_java() {
    assert_eq!(
        render("#set($i = 2147483647)#set($j = $i + 1)$j #set($k = $i * 2)$k").unwrap(),
        "21474836484294967294"
    );
    assert_eq!(
        render("#set($a = -9223372036854775808)#set($b = $a / -1)$b #set($c = $a * -1)$c").unwrap(),
        "-9223372036854775808-9223372036854775808"
    );
    assert_eq!(
        render("#set($a = 99999999999999999999)#set($b = $a + 0.5)$b #set($c = $b / 4)$c").unwrap(),
        "99999999999999999999.524999999999999999999.9"
    );
    assert!(matches!(
        render("#set($a = 99999999999999999999)#set($b = $a + 0.5)#set($c = $b % 2)"),
        Err(RenderError::Arithmetic { .. })
    ));
}

#[test]
fn map_keys_keep_their_java_types() {
    assert_eq!(
        render(
            "#set($m = {1: 'int', '1': 'string', true: 'bool'})$m $m.get(1) $m.get('1') $m.size()"
        )
        .unwrap(),
        "{1=int, 1=string, true=bool} int string 3"
    );
    assert_eq!(
        render(
            "#set($k = 3000000000 - 2999999999)#set($m = {1: 'i'})[$!m.get($k)] $m.containsKey($k)"
        )
        .unwrap(),
        "[] false"
    );
}

#[test]
fn json_numbers_keep_their_digits() {
    assert_eq!(
        render_with(
            "$input.path('$.n') $input.path('$.d') $input.json('$')",
            r#"{"n":123456789012345678901234567890,"d":1.23456789012345678901}"#,
            Limits::default()
        )
        .unwrap(),
        r#"123456789012345678901234567890 1.23456789012345678901 {"n":123456789012345678901234567890,"d":1.23456789012345678901}"#
    );
    let long_number = format!(r#"{{"n":{}}}"#, "9".repeat(5000));
    assert!(matches!(
        render_with("$input.path('$.n')", &long_number, Limits::default()),
        Err(RenderError::InvalidBodyJson(_))
    ));
}

#[test]
fn functions_after_a_deep_scan_follow_jayway() {
    let body = r#"{"store":{"books":[{"price":1},{"price":2.5}],"bike":{"price":3}}}"#;
    let json = |path: &str| {
        render_with(&format!("$input.json('{path}')"), body, Limits::default()).unwrap()
    };
    assert_eq!(json("$..price.max()"), "3.0");
    assert_eq!(json("$..price.sum()"), "6.5");
    assert_eq!(json("$.store..price.length()"), "[null,null,null]");
    assert_eq!(json("$.store..price.sum()"), "\"\"");
}

#[test]
fn a_paren_left_open_after_a_property_restricts_what_follows() {
    assert_eq!(
        render("#set($s = 'a')#if(true)$s.x(#end.y").unwrap(),
        "$s.x(.y"
    );
    assert!(render("#set($s = 'a')#if(true)$s.x(#end y").is_err());
    assert!(render("#set($m = {'b': 1})$m.b#set($v = 1)(x y").is_err());
    assert_eq!(render("#set($m = {'b': 1})$m.b x(y z").unwrap(), "1 x(y z");
}
