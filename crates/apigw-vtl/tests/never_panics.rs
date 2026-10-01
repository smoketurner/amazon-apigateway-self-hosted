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
