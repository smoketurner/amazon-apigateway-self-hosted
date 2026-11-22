#![no_main]

use apigw_vtl::{InputParams, Limits, NullReferences, Renderer, SimpleInput, Template};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Request {
    template: String,
    body: String,
    empty_nulls: bool,
}

fuzz_target!(|request: Request| {
    let Ok(template) = Template::parse(&request.template) else {
        return;
    };
    let input = SimpleInput::new(request.body, InputParams::default());
    let limits = Limits::default()
        .with_output_bytes(1 << 20)
        .with_steps(200_000)
        .with_depth(64);
    let null_references = if request.empty_nulls {
        NullReferences::Empty
    } else {
        NullReferences::Literal
    };
    drop(
        Renderer::new(&input)
            .with_limits(limits)
            .with_null_references(null_references)
            .render(&template),
    );
});
