//! Parsing and rendering report problems as errors and never panic, whatever the template,
//! JSON path, or request.

use apigw_vtl::{InputParams, JsonPath, Limits, Renderer, SimpleInput, Template, Value};
use proptest::prelude::*;

const TEMPLATE_FRAGMENTS: &[&str] = &[
    "#set($a = ",
    "#set($a.b = ",
    "#set($a[0] = ",
    "#if(",
    "#elseif(",
    "#else",
    "#end",
    "#foreach($i in ",
    "#break",
    "#stop",
    "#macro(",
    "#macro(m $a)",
    "#m(",
    "#m($a)",
    "#@m(",
    "#define($a)",
    "#define($d)$d",
    "$d",
    "#evaluate(",
    "#parse(",
    "#{if}(",
    "#{end}",
    "$a",
    "$!a",
    "${a}",
    "$!{a}",
    "$a.b",
    "$a.b(",
    "$a.b()",
    "$a[0]",
    "$a['k']",
    "$a.size()",
    "$a.add(1)",
    "$a.put('k', 1)",
    "$a.substring(1)",
    "$a.replaceAll('.', 'x')",
    "$a.split(',')",
    "$i",
    "$foreach.index",
    "$velocityCount",
    "$input.body",
    "$input.path('$.a')",
    "$input.json('$..b')",
    "$input.params('x')",
    "$util.urlEncode($a)",
    "$util.escapeJavaScript('\"')",
    "$util.parseJson('[1]')",
    "$context.a.b",
    "$stageVariables.s",
    "(",
    ")",
    "[",
    "]",
    "{",
    "}",
    "'",
    "\"",
    "..",
    ",",
    ":",
    ".",
    "$",
    "#",
    "\\",
    "\\\\",
    "\\$",
    "\\#",
    "##",
    "#*",
    "*#",
    "#[[",
    "]]#",
    "\n",
    " ",
    "\t",
    "\r\n",
    "1",
    "2.5",
    "-1",
    "3000000000",
    "9223372036854775807",
    "99999999999999999999",
    "-9223372036854775808",
    "0.5",
    "1e-300",
    "$a.b(#end",
    ".x",
    "'q'",
    "true",
    "false",
    "null",
    " + ",
    " - ",
    " * ",
    " / ",
    " % ",
    " == ",
    " != ",
    " < ",
    " >= ",
    " && ",
    " || ",
    "!",
    "text",
    "é",
    "😀",
];

const BODY: &str = r#"{"a":[1,{"b":2}],"c":"x","d":{"e":[3,4]}}"#;

fn limits() -> Limits {
    Limits::default()
        .with_output_bytes(20_000)
        .with_steps(50_000)
        .with_depth(32)
}

fn exercise(source: &str) {
    if let Ok(template) = Template::parse(source) {
        let input = SimpleInput::new(BODY, InputParams::default());
        drop(
            Renderer::new(&input)
                .with_limits(limits())
                .render(&template),
        );
    }
}

fn fragments() -> impl Strategy<Value = String> {
    prop::collection::vec(prop::sample::select(TEMPLATE_FRAGMENTS), 0..40)
        .prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    #[test]
    fn fragment_templates_never_panic(source in fragments()) {
        exercise(&source);
    }

    #[test]
    fn arbitrary_templates_never_panic(source in any::<String>()) {
        exercise(&source);
    }

    #[test]
    fn prelude_templates_never_panic(source in fragments()) {
        exercise(&format!("#set($a = [1, 2, {{'k': 'v'}}])#set($s = 'str')\n{source}"));
    }

    #[test]
    fn arbitrary_json_paths_never_panic(path in any::<String>()) {
        if let (Ok(path), Ok(document)) = (path.parse::<JsonPath>(), Value::from_json(BODY)) {
            drop(path.evaluate(&document));
        }
    }

    #[test]
    fn json_path_fragments_never_panic(
        parts in prop::collection::vec(
            prop::sample::select(&[
                "$", "@", ".", "..", "a", "d", "e", "*", "[", "]", "0", "-1", ":", ",", "'a'", "?(", ")", "@.b", "==", "!=", "<", "&&",
                "||", "!", "'x'", "1", "=~", "/x/i", " in ", "[1,2]", "length()", "max()", "keys()", "first()", "index(1)",
                "concat()", "append(1)", "last()", "sum()",
            ][..]),
            0..14,
        ),
    ) {
        let path = parts.concat();
        if let (Ok(path), Ok(document)) = (path.parse::<JsonPath>(), Value::from_json(BODY)) {
            drop(path.evaluate(&document));
        }
    }

    #[test]
    fn arbitrary_json_bodies_never_panic(body in any::<String>()) {
        if let Ok(template) = Template::parse("$input.path('$.a') $input.json('$..*') $input.body") {
            let input = SimpleInput::new(body, InputParams::default());
            drop(Renderer::new(&input).with_limits(limits()).render(&template));
        }
    }
}

fn nested(open: &str, close: &str, depth: usize) -> String {
    format!("{}{}", open.repeat(depth), close.repeat(depth))
}

/// Directives nested far beyond the limits are errors, not stack overflows.
#[test]
fn deeply_nested_directives_are_bounded() {
    for depth in [10, 63, 64, 65, 1_000, 20_000] {
        exercise(&nested("#macro(m $a)", "#end", depth));
        exercise(&nested("#define($d)$d", "#end", depth));
        exercise(&nested("#@m(", ")x#end", depth));
        exercise(&nested("#evaluate('", "')", depth));
        exercise(&nested("$a.b(", ")", depth));
        exercise(&nested("#m(", ")", depth));
        exercise(&nested("#if(true)$a.b(", "#end", depth));
        exercise(&format!(
            "#set($d = 1){}",
            "#define($d)x$d#end".repeat(depth)
        ));
    }
}

/// Defines that render one another without end stop at the depth limit.
#[test]
#[expect(clippy::format_collect, reason = "builds a test template")]
fn mutually_recursive_defines_are_bounded() {
    let mut template: String = (0..300_usize)
        .map(|i| format!("#define($d{i})$d{}$d{}#end", i + 1, i.div_euclid(2)))
        .collect();
    template.push_str("$d0 #set($context.x = $d0)");
    exercise(&template);
}

/// Repeated squaring and printing of big numbers stays within the limits.
#[test]
fn big_number_arithmetic_is_bounded() {
    for template in [
        "#set($a = 99999999999999999999)#foreach($i in [1..40])#set($a = $a * $a)$a#end",
        "#set($a = 99999999999999999999)#set($b = $a + 1e-300)#foreach($i in [1..40])#set($b = $b * $b)#end$b",
        "#set($a = 99999999999999999999)#foreach($i in [1..1000])#set($b = $a / 7 % 3)$a#end",
        "#set($l = [])#set($a = 99999999999999999999)#foreach($i in [1..30])#set($a = $a * $a)#set($x = $l.add($a))#end#foreach($i in [1..1000])$l#end",
    ] {
        exercise(template);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    #[test]
    fn json_numbers_never_panic(
        digits in "-?[0-9]{1,60}(\\.[0-9]{0,40})?([eE][+-]?[0-9]{1,6})?",
        template in prop::sample::select(&[
            "$input.path('$.n')",
            "#set($x = $input.path('$.n') + 1)$x",
            "#set($x = $input.path('$.n') * 0.1)$x",
            "#set($x = $input.path('$.n') / 3)$x #set($y = $input.path('$.n') % 7)$y",
            "#if($input.path('$.n') > 1.5)gt#end",
            "$input.json('$')",
        ][..]),
    ) {
        if let Ok(template) = Template::parse(template) {
            let input = SimpleInput::new(format!("{{\"n\":{digits}}}"), InputParams::default());
            drop(Renderer::new(&input).with_limits(limits()).render(&template));
        }
    }
}
