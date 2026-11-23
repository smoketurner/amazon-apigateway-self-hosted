# apigw-vtl

Apache Velocity 1.7 mapping templates, as Amazon API Gateway evaluates them, with `$input`,
`$util`, `$context`, and `$stageVariables` and Jayway-compatible JSON paths. It is a pure library
with no I/O: the caller supplies the request through `TemplateInput` and reads `$context`
changes (such as `requestOverride` and `responseOverride`) back from the map it passed in.

The behavior is that of the real engine, quirks included: undefined references render as their
source text, directive-only lines vanish, `#foreach` stops after 1,000 iterations, values print
like Java, and arithmetic follows Velocity's `MathUtils`. Where a deployed API Gateway was recorded
to differ from Velocity (for example, `#macro` and `#evaluate` render as written), the crate does
what API Gateway does. Output size, evaluation steps, and nesting are bounded by `Limits`.

```rust
use apigw_vtl::{InputParams, Renderer, SimpleInput, Template};

let template: Template = r##"{"names": [#foreach($u in $input.path('$.users'))"$u.name"#if($foreach.hasNext),#end#end]}"##.parse()?;
let input = SimpleInput::new(r#"{"users":[{"name":"ann"},{"name":"bob"}]}"#, InputParams::default());
let output = Renderer::new(&input).render(&template)?;
assert_eq!(output, r#"{"names": ["ann","bob"]}"#);
```

The crate docs (`cargo doc -p apigw-vtl --open`) list every known difference from Velocity, Java,
and API Gateway.

## Tests

```bash
cargo test -p apigw-vtl
```

`tests/oracle.rs` compares output with Apache Velocity 1.7 and Jayway `JsonPath` 2.9, recorded by
[`tools/vtl-oracle`](../../tools/vtl-oracle). `tests/semantics` covers API Gateway's own behavior,
`tests/never_panics.rs` is a proptest, and `fuzz/fuzz_targets/render.rs` and `json_path.rs` fuzz
the parser, renderer, and JSON paths.
