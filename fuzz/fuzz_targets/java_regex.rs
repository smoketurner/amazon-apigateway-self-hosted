#![no_main]

use apigw_regex::{JavaRegex, RegexOptions, Replacement};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Operation {
    pattern: String,
    input: String,
    replacement: String,
    limit: i32,
}

fuzz_target!(|operation: Operation| {
    let options = RegexOptions::default()
        .with_backtrack_limit(10_000)
        .with_size_limit(100_000);
    let Ok(regex) = JavaRegex::with_options(&operation.pattern, &options) else {
        return;
    };
    drop(regex.matches(&operation.input));
    drop(regex.find(&operation.input));
    drop(regex.replace_all(&operation.input, &Replacement::from(operation.replacement.as_str())));
    drop(regex.split(&operation.input, operation.limit));
});
