#![no_main]

use apigw_vtl::{InputParams, Limits, Renderer, SimpleInput, Template};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Request {
    template: String,
    body: String,
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
    drop(Renderer::new(&input).with_limits(limits).render(&template));
});
