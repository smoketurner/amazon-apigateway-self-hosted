//! A stage's access log format: free text with `$context.*` substitutions.
//! CLF, JSON, XML, and CSV are all just templates of this kind.

use serde_json::Value;

/// What a variable that has no value renders as, as in API Gateway.
const MISSING: &str = "-";

const PREFIX: &str = "$context.";

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    /// A `$context` variable, as its dot-separated path below `$context`.
    Variable(Vec<String>),
}

/// A parsed access log format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccessLogFormat(Vec<Segment>);

impl From<&str> for AccessLogFormat {
    /// Splits `format` into literal text and `$context.name.path` variables. A
    /// `$` that does not start a `$context.` variable is literal text.
    fn from(format: &str) -> Self {
        let mut segments = Vec::new();
        let mut literal = String::new();
        let mut rest = format;
        while let Some(at) = rest.find(PREFIX) {
            let (before, after) = rest.split_at(at);
            literal.push_str(before);
            let after = after.get(PREFIX.len()..).unwrap_or_default();
            let name_len = Self::variable_len(after);
            if name_len == 0 {
                literal.push_str(PREFIX);
                rest = after;
                continue;
            }
            let (name, tail) = after.split_at(name_len);
            if !literal.is_empty() {
                segments.push(Segment::Literal(std::mem::take(&mut literal)));
            }
            segments.push(Segment::Variable(
                name.split('.').map(str::to_owned).collect(),
            ));
            rest = tail;
        }
        literal.push_str(rest);
        if !literal.is_empty() {
            segments.push(Segment::Literal(literal));
        }
        Self(segments)
    }
}

impl AccessLogFormat {
    /// Byte length of the variable name at the start of `text`: names are
    /// `[A-Za-z0-9_]` runs joined by single dots, so a sentence-ending `.` is
    /// not part of the name.
    fn variable_len(text: &str) -> usize {
        let is_word = |c: char| c.is_ascii_alphanumeric() || c == '_';
        let mut len = 0;
        let mut chars = text.char_indices().peekable();
        while let Some((index, c)) = chars.next() {
            let continues = is_word(c)
                || (c == '.' && index > 0 && chars.peek().is_some_and(|&(_, next)| is_word(next)));
            if !continues {
                break;
            }
            len = index.saturating_add(c.len_utf8());
        }
        len
    }

    /// Renders the format against `context`, the request's `$context` object.
    /// Values are escaped for use inside a JSON string, so a user agent with a
    /// quote in it cannot break a JSON log line.
    pub(crate) fn render(&self, context: &Value) -> String {
        let mut out = String::new();
        for segment in &self.0 {
            match segment {
                Segment::Literal(text) => out.push_str(text),
                Segment::Variable(path) => {
                    let value = path
                        .iter()
                        .try_fold(context, |value, key| value.get(key.as_str()));
                    match value {
                        None | Some(Value::Null) => out.push_str(MISSING),
                        Some(Value::String(text)) => Self::escape_into(&mut out, text),
                        Some(other) => Self::escape_into(&mut out, &other.to_string()),
                    }
                }
            }
        }
        out
    }

    fn escape_into(out: &mut String, text: &str) {
        for c in text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if c.is_control() => {
                    let escaped = format!("\\u{:04x}", u32::from(c));
                    out.push_str(&escaped);
                }
                c => out.push(c),
            }
        }
    }
}

#[cfg(test)]
#[expect(clippy::unwrap_used, reason = "tests assert on known-good fixtures")]
#[expect(clippy::indexing_slicing, reason = "tests index JSON they parsed")]
mod tests {
    use proptest::prelude::*;
    use serde_json::json;

    use super::*;

    fn context() -> Value {
        json!({
            "requestId": "r-1",
            "status": 200,
            "identity": {"sourceIp": "192.0.2.1", "userAgent": "curl \"8\"\n"},
            "integration": {"latency": 12},
            "authorizer": {"principalId": null},
        })
    }

    #[test]
    fn json_format_renders_variables_and_keeps_the_structure() {
        let format = AccessLogFormat::from(
            r#"{ "requestId":"$context.requestId", "ip": "$context.identity.sourceIp", "status":"$context.status", "latency":"$context.integration.latency" }"#,
        );
        let rendered = format.render(&context());
        assert_eq!(
            rendered,
            r#"{ "requestId":"r-1", "ip": "192.0.2.1", "status":"200", "latency":"12" }"#
        );
        assert!(serde_json::from_str::<Value>(&rendered).is_ok());
    }

    #[test]
    fn clf_xml_and_csv_templates_render() {
        let clf = AccessLogFormat::from(
            r#"$context.identity.sourceIp [$context.requestId] "$context.status""#,
        );
        assert_eq!(clf.render(&context()), r#"192.0.2.1 [r-1] "200""#);
        let xml = AccessLogFormat::from(
            "<request id=\"$context.requestId\"><s>$context.status</s></request>",
        );
        assert_eq!(
            xml.render(&context()),
            "<request id=\"r-1\"><s>200</s></request>"
        );
        let csv = AccessLogFormat::from("$context.requestId,$context.status,$context.stage");
        assert_eq!(csv.render(&context()), "r-1,200,-");
    }

    #[test]
    fn missing_null_and_unknown_variables_render_as_dash() {
        let format = AccessLogFormat::from(
            "$context.authorizer.principalId $context.nope $context.identity.nope.deeper",
        );
        assert_eq!(format.render(&context()), "- - -");
    }

    #[test]
    fn values_are_json_escaped() {
        let format = AccessLogFormat::from(r#"{"ua":"$context.identity.userAgent"}"#);
        let rendered = format.render(&context());
        assert_eq!(rendered, r#"{"ua":"curl \"8\"\n"}"#);
        assert_eq!(
            serde_json::from_str::<Value>(&rendered).unwrap()["ua"],
            "curl \"8\"\n"
        );
    }

    #[test]
    fn variable_names_stop_before_trailing_punctuation() {
        let format = AccessLogFormat::from("status=$context.status. next: $context.requestId,$");
        assert_eq!(format.render(&context()), "status=200. next: r-1,$");
    }

    #[test]
    fn dollar_signs_that_are_not_variables_stay_literal() {
        let format = AccessLogFormat::from("$$context. $context.. $stageVariables.x cost $5");
        assert_eq!(
            format.render(&context()),
            "$$context. $context.. $stageVariables.x cost $5"
        );
    }

    #[test]
    fn empty_format_renders_nothing() {
        assert_eq!(AccessLogFormat::from("").render(&context()), "");
    }

    proptest! {
        #[test]
        fn rendering_never_panics_and_literal_text_is_preserved(text in "[ -~]{0,60}") {
            let format = AccessLogFormat::from(text.as_str());
            let rendered = format.render(&context());
            if !text.contains('$') {
                prop_assert_eq!(rendered, text);
            }
        }

        #[test]
        fn json_templates_always_render_valid_json(agent in "\\PC{0,30}") {
            let context = json!({"ua": agent});
            let rendered = AccessLogFormat::from(r#"{"ua":"$context.ua"}"#).render(&context);
            prop_assert_eq!(&serde_json::from_str::<Value>(&rendered).unwrap()["ua"], &Value::String(agent));
        }
    }
}
