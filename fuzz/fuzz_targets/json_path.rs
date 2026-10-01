#![no_main]

use apigw_vtl::{JsonPath, Value};
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Debug, Arbitrary)]
struct Query {
    path: String,
    document: String,
}

fuzz_target!(|query: Query| {
    let (Ok(path), Ok(document)) = (query.path.parse::<JsonPath>(), Value::from_json(&query.document)) else {
        return;
    };
    drop(path.evaluate(&document));
});
