//! The `$util` object: escaping, encoding, and JSON parsing helpers.

use base64::Engine as _;
use base64::alphabet::STANDARD as STANDARD_ALPHABET;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};

use crate::error::RenderError;
use crate::value::{Value, push_formatted};

/// Java's `Base64.getDecoder()` accepts input with or without trailing `=` padding.
const STANDARD: GeneralPurpose = GeneralPurpose::new(
    &STANDARD_ALPHABET,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

fn fail(method: &str, message: impl Into<String>) -> RenderError {
    RenderError::Method {
        method: format!("$util.{method}"),
        message: message.into(),
    }
}

/// Calls a `$util` method. Like Velocity, a call whose arguments do not match any method is
/// unresolved (`None`), while a `null` argument reaches the method and throws.
pub(crate) fn call(name: &str, args: &[Value]) -> Result<Option<Value>, RenderError> {
    let known = matches!(
        name,
        "escapeJavaScript"
            | "parseJson"
            | "urlEncode"
            | "urlDecode"
            | "base64Encode"
            | "base64Decode"
    );
    let [argument] = args else {
        return Ok(None);
    };
    if !known {
        return Ok(None);
    }
    let text = match argument {
        Value::Str(text) => text,
        Value::Null => return Err(fail(name, "argument is null")),
        _ => return Ok(None),
    };
    let result = match name {
        "escapeJavaScript" => Value::from(escape_java_script(text)),
        "parseJson" => Value::from_json(text).map_err(|err| fail(name, err.to_string()))?,
        "urlEncode" => Value::from(url_encode(text)),
        "urlDecode" => Value::from(url_decode(text).map_err(|message| fail(name, message))?),
        "base64Encode" => Value::from(STANDARD.encode(text.as_bytes())),
        _ => {
            let bytes = STANDARD
                .decode(text.as_bytes())
                .map_err(|err| fail(name, err.to_string()))?;
            Value::from(String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    Ok(Some(result))
}

/// Apache Commons Lang 2's `StringEscapeUtils.escapeJavaScript`, which API Gateway uses:
/// quotes, backslashes, and slashes are escaped, and everything outside printable ASCII becomes
/// a `\uXXXX` escape per UTF-16 unit.
pub(crate) fn escape_java_script(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for unit in text.encode_utf16() {
        match unit {
            0x08 => out.push_str("\\b"),
            0x0A => out.push_str("\\n"),
            0x09 => out.push_str("\\t"),
            0x0C => out.push_str("\\f"),
            0x0D => out.push_str("\\r"),
            0x22 => out.push_str("\\\""),
            0x27 => out.push_str("\\'"),
            0x2F => out.push_str("\\/"),
            0x5C => out.push_str("\\\\"),
            unit if !(0x20..=0x7F).contains(&unit) => {
                push_formatted(&mut out, format_args!("\\u{unit:04X}"));
            }
            unit => {
                if let Some(c) = char::from_u32(u32::from(unit)) {
                    out.push(c);
                }
            }
        }
    }
    out
}

/// `URLEncoder.encode(text, "UTF-8")`: unreserved characters stay, a space becomes `+`, and
/// the rest are percent-encoded bytes.
pub(crate) fn url_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'.' | b'-' | b'*' | b'_' => {
                out.push(char::from(byte));
            }
            b' ' => out.push('+'),
            other => push_formatted(&mut out, format_args!("%{other:02X}")),
        }
    }
    out
}

/// `URLDecoder.decode(text, "UTF-8")`.
pub(crate) fn url_decode(text: &str) -> Result<String, String> {
    let mut bytes = Vec::with_capacity(text.len());
    let mut iter = text.bytes();
    while let Some(byte) = iter.next() {
        match byte {
            b'+' => bytes.push(b' '),
            b'%' => {
                let high = iter.next().and_then(hex_value);
                let low = iter.next().and_then(hex_value);
                match (high, low) {
                    (Some(high), Some(low)) => bytes.push(high << 4 | low),
                    _ => return Err("incomplete or invalid percent escape".to_owned()),
                }
            }
            other => bytes.push(other),
        }
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(byte.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(byte.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_like_commons_lang() {
        assert_eq!(escape_java_script("a'b\"c/d\\e"), "a\\'b\\\"c\\/d\\\\e");
        assert_eq!(escape_java_script("é中\u{1}\n"), "\\u00E9\\u4E2D\\u0001\\n");
        assert_eq!(escape_java_script("😀"), "\\uD83D\\uDE00");
    }

    #[test]
    fn url_codec_round_trips() {
        assert_eq!(url_encode("a b&c=d/é"), "a+b%26c%3Dd%2F%C3%A9");
        assert_eq!(
            url_decode("a+b%26c%3Dd%2F%C3%A9").as_deref(),
            Ok("a b&c=d/é")
        );
        assert!(url_decode("%zz").is_err());
        assert!(url_decode("%4").is_err());
    }
}
