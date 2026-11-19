//! What a body model's validation found, as `$context.error.validationErrorString`.
//!
//! API Gateway validates with the Java `json-schema-validator` library and
//! reports the distinct messages of its report in the iteration order of a
//! `java.util.HashSet<String>`, joined with `, ` inside brackets. Both the
//! wording and the order are reproduced here.

use std::cmp::Ordering;
use std::collections::HashSet;

use serde_json::Value;

use super::number::java_text;
use crate::gateway_response::unicode_escape;

/// What API Gateway reports for a body it cannot read as JSON.
const UNPARSEABLE: &str = "Unknown error parsing request body";
/// The initial bucket count of a `java.util.HashSet`.
const JAVA_INITIAL_CAPACITY: u32 = 16;
/// The largest bucket count of a `java.util.HashSet`.
const JAVA_MAXIMUM_CAPACITY: u32 = 1 << 30;
/// Messages past this many bytes are dropped, so a body that breaks its model
/// in very many places cannot make the response arbitrarily large. API Gateway
/// has no such limit up to at least the 6 KB that were measured.
const MAX_REPORT_BYTES: usize = 1024 * 1024;

/// The text of `$context.error.validationErrorString`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidationErrorString(String);

impl ValidationErrorString {
    pub(super) fn unparseable() -> Self {
        Self(format!("[{UNPARSEABLE}]"))
    }

    fn of(messages: Vec<String>) -> Self {
        Self(format!("[{}]", java_hash_set_order(messages).join(", ")))
    }
}

impl From<ValidationErrorString> for String {
    fn from(text: ValidationErrorString) -> Self {
        text.0
    }
}

/// The messages of one validation: errors, and warnings that are reported
/// along with them but do not fail a request on their own.
#[derive(Debug, Default)]
pub(super) struct Report {
    messages: Vec<String>,
    bytes: usize,
    failed: bool,
    /// Notes errors without keeping their text.
    quiet: bool,
}

impl Report {
    /// A report for a subschema whose messages are never shown (`anyOf`, `not`, ...).
    pub(super) fn quiet() -> Self {
        Self {
            quiet: true,
            ..Self::default()
        }
    }

    pub(super) fn error(&mut self, message: impl FnOnce() -> String) {
        self.failed = true;
        self.record(message);
    }

    pub(super) fn warn(&mut self, message: impl FnOnce() -> String) {
        self.record(message);
    }

    /// An error for a body that cannot be checked at all.
    pub(super) fn unknown_error(&mut self) {
        self.error(|| UNPARSEABLE.to_owned());
    }

    fn record(&mut self, message: impl FnOnce() -> String) {
        if self.quiet || self.bytes > MAX_REPORT_BYTES {
            return;
        }
        let message = message();
        self.bytes = self.bytes.saturating_add(message.len());
        self.messages.push(message);
    }

    pub(super) const fn is_success(&self) -> bool {
        !self.failed
    }

    pub(super) fn into_result(self) -> Result<(), ValidationErrorString> {
        if self.is_success() {
            Ok(())
        } else {
            Err(ValidationErrorString::of(self.messages))
        }
    }
}

/// `String.hashCode`.
fn java_hash(text: &str) -> u32 {
    text.encode_utf16().fold(0_u32, |hash, unit| {
        hash.wrapping_mul(31).wrapping_add(u32::from(unit))
    })
}

/// The distinct `messages` in the order a `java.util.HashSet<String>` they were
/// added to iterates: by bucket, then by insertion.
fn java_hash_set_order(messages: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut distinct: Vec<String> = Vec::new();
    for message in messages {
        if seen.insert(message.clone()) {
            distinct.push(message);
        }
    }
    let count = u64::try_from(distinct.len()).unwrap_or(u64::MAX);
    let mut capacity = JAVA_INITIAL_CAPACITY;
    // The table doubles when it holds more than 0.75 of its capacity.
    while capacity < JAVA_MAXIMUM_CAPACITY
        && count.saturating_mul(4) > u64::from(capacity).saturating_mul(3)
    {
        capacity = capacity.saturating_mul(2);
    }
    let mask = capacity.saturating_sub(1);
    distinct.sort_by_cached_key(|message| {
        let hash = java_hash(message);
        (hash ^ (hash >> 16)) & mask
    });
    distinct
}

/// The order of `String.compareTo`: by UTF-16 code unit.
pub(super) fn java_string_order(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// `value` as Jackson's `JsonNode.toString` prints it: compact, with numbers
/// as Java prints them.
pub(super) fn json_text(value: &Value) -> String {
    let mut out = String::new();
    write_json(value, &mut out);
    out
}

/// A JSON array of strings, as Jackson prints it.
pub(super) fn json_strings<'a>(items: impl IntoIterator<Item = &'a str>) -> String {
    let mut out = String::from("[");
    for (index, item) in items.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_json_string(item, &mut out);
    }
    out.push(']');
    out
}

fn write_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&java_text(number)),
        Value::String(text) => write_json_string(text, out),
        Value::Array(elements) => {
            out.push('[');
            for (index, element) in elements.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json(element, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            out.push('{');
            for (index, (name, member)) in members.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_json_string(name, out);
                out.push(':');
                write_json(member, out);
            }
            out.push('}');
        }
    }
}

fn write_json_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            control if control < ' ' => out.push_str(&unicode_escape(control)),
            other => out.push(other),
        }
    }
    out.push('"');
}
