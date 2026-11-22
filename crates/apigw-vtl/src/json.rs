//! A strict JSON reader that types numbers the way Jayway's json-smart provider does.
//!
//! json-smart reads an integer as `Integer`, `Long`, or `BigInteger` by size, and any other
//! number as `Double`, unless its text is longer than 18 characters, which makes it a
//! `BigDecimal` that keeps every digit. A general-purpose JSON parser turns those into doubles,
//! so this one keeps the number text.

use crate::number::{BigDecimal, BigInt};
use crate::value::{List, Map, Value};

/// Deepest nesting of arrays and objects, as in `serde_json`.
const MAX_DEPTH: usize = 128;

/// The longest number text json-smart still reads as a `Double`.
const MAX_DOUBLE_TEXT: usize = 18;

/// The longest number text read at all. Converting decimal digits to binary takes time that
/// grows with the square of their count, so a body of enormous numbers is refused instead.
const MAX_NUMBER_TEXT: usize = 4096;

/// Parses a whole document: one value with only whitespace around it.
pub(crate) fn parse_document(text: &str) -> Result<Value, String> {
    let mut reader = Reader::new(text);
    let value = reader.value(0)?;
    reader.skip_whitespace();
    if reader.pos < reader.bytes.len() {
        return Err(reader.error("trailing characters"));
    }
    Ok(value)
}

/// Parses the first value in `text`, ignoring whatever follows it.
pub(crate) fn parse_first(text: &str) -> Result<Value, String> {
    Reader::new(text).value(0)
}

struct Reader<'a> {
    text: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    const fn new(text: &'a str) -> Self {
        Self {
            text,
            bytes: text.as_bytes(),
            pos: 0,
        }
    }

    fn error(&self, message: &str) -> String {
        format!("{message} at byte {}", self.pos)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn advance(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn eat(&mut self, byte: u8) -> bool {
        if self.peek() == Some(byte) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.advance();
        }
    }

    fn literal(&mut self, word: &str, value: Value) -> Result<Value, String> {
        if self
            .bytes
            .get(self.pos..self.pos.saturating_add(word.len()))
            == Some(word.as_bytes())
        {
            self.pos = self.pos.saturating_add(word.len());
            Ok(value)
        } else {
            Err(self.error("expected a value"))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, String> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth),
            Some(b'[') => self.array(depth),
            Some(b'"') => self.string().map(Value::from),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("expected a value")),
            None => Err(self.error("unexpected end of input")),
        }
    }

    fn nested(&self, depth: usize) -> Result<usize, String> {
        let next = depth.saturating_add(1);
        if next > MAX_DEPTH {
            Err(self.error("recursion limit exceeded"))
        } else {
            Ok(next)
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, String> {
        let depth = self.nested(depth)?;
        self.advance();
        let map = Map::new();
        self.skip_whitespace();
        if self.eat(b'}') {
            return Ok(Value::Map(map));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.error("expected a string key"));
            }
            let key = self.string()?;
            self.skip_whitespace();
            if !self.eat(b':') {
                return Err(self.error("expected ':'"));
            }
            let value = self.value(depth)?;
            map.insert(key, value);
            self.skip_whitespace();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b'}') {
                return Ok(Value::Map(map));
            }
            return Err(self.error("expected ',' or '}'"));
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, String> {
        let depth = self.nested(depth)?;
        self.advance();
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.eat(b']') {
            return Ok(Value::List(List::from_values(items)));
        }
        loop {
            items.push(self.value(depth)?);
            self.skip_whitespace();
            if self.eat(b',') {
                continue;
            }
            if self.eat(b']') {
                return Ok(Value::List(List::from_values(items)));
            }
            return Err(self.error("expected ',' or ']'"));
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let digits = self
            .text
            .get(self.pos..self.pos.saturating_add(4))
            .ok_or_else(|| self.error("incomplete \\u escape"))?;
        let unit = u32::from_str_radix(digits, 16).map_err(|_| self.error("invalid \\u escape"))?;
        self.pos = self.pos.saturating_add(4);
        Ok(unit)
    }

    fn string(&mut self) -> Result<String, String> {
        self.advance();
        let mut out = String::new();
        loop {
            let start = self.pos;
            while self
                .peek()
                .is_some_and(|b| b != b'"' && b != b'\\' && b >= 0x20)
            {
                self.advance();
            }
            out.push_str(self.text.get(start..self.pos).unwrap_or_default());
            match self.peek() {
                Some(b'"') => {
                    self.advance();
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.advance();
                    let escape = self
                        .peek()
                        .ok_or_else(|| self.error("unterminated string"))?;
                    self.advance();
                    match escape {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => out.push(self.unicode_escape()?),
                        _ => return Err(self.error("invalid escape")),
                    }
                }
                Some(_) => return Err(self.error("control character in string")),
                None => return Err(self.error("unterminated string")),
            }
        }
    }

    fn unicode_escape(&mut self) -> Result<char, String> {
        let first = self.hex4()?;
        if (0xD800..0xDC00).contains(&first) {
            if self.bytes.get(self.pos..self.pos.saturating_add(2)) != Some(b"\\u") {
                return Err(self.error("lone leading surrogate"));
            }
            self.pos = self.pos.saturating_add(2);
            let second = self.hex4()?;
            if !(0xDC00..0xE000).contains(&second) {
                return Err(self.error("invalid surrogate pair"));
            }
            let scalar = 0x1_0000_u32
                .wrapping_add((first.wrapping_sub(0xD800)).wrapping_shl(10))
                .wrapping_add(second.wrapping_sub(0xDC00));
            return char::from_u32(scalar).ok_or_else(|| self.error("invalid surrogate pair"));
        }
        char::from_u32(first).ok_or_else(|| self.error("lone trailing surrogate"))
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.advance();
        }
        self.pos.saturating_sub(start)
    }

    fn number(&mut self) -> Result<Value, String> {
        let start = self.pos;
        self.eat(b'-');
        if self.eat(b'0') {
            if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.error("leading zero in number"));
            }
        } else if self.digits() == 0 {
            return Err(self.error("expected digits"));
        }
        let mut integral = true;
        if self.eat(b'.') {
            integral = false;
            if self.digits() == 0 {
                return Err(self.error("expected digits after '.'"));
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            integral = false;
            self.advance();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.advance();
            }
            if self.digits() == 0 {
                return Err(self.error("expected digits in exponent"));
            }
        }
        let text = self.text.get(start..self.pos).unwrap_or_default();
        if text.len() > MAX_NUMBER_TEXT {
            return Err(self.error("number longer than 4096 characters"));
        }
        let too_large = |_| format!("number {text} is too large");
        if integral {
            return BigInt::parse(text)
                .map_err(too_large)?
                .map(Value::big_integer)
                .ok_or_else(|| self.error("invalid number"));
        }
        if text.len() > MAX_DOUBLE_TEXT {
            return BigDecimal::parse(text)
                .map_err(too_large)?
                .map(|value| Value::BigDecimal(value.into()))
                .ok_or_else(|| self.error("invalid number"));
        }
        text.parse::<f64>()
            .map(Value::Double)
            .map_err(|_| self.error("invalid number"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn typed(text: &str) -> String {
        parse_document(text).map_or_else(|err| format!("ERR {err}"), |v| format!("{v:?} {v}"))
    }

    #[test]
    fn numbers_are_typed_like_json_smart() {
        assert_eq!(typed("1"), "Int(1) 1");
        assert_eq!(typed("-2147483648"), "Int(-2147483648) -2147483648");
        assert_eq!(typed("3000000000"), "Long(3000000000) 3000000000");
        assert_eq!(
            typed("123456789012345678901234567890"),
            "BigInt(123456789012345678901234567890) 123456789012345678901234567890"
        );
        assert_eq!(typed("0.1"), "Double(0.1) 0.1");
        assert_eq!(typed("1E2"), "Double(100) 100.0");
        assert_eq!(typed("1e400"), "Double(inf) Infinity");
        assert_eq!(
            typed("1.23456789012345678901"),
            "BigDecimal(1.23456789012345678901) 1.23456789012345678901"
        );
        assert_eq!(typed("-0.0"), "Double(-0) -0.0");
    }

    #[test]
    fn malformed_json_is_an_error() {
        for text in [
            "",
            "{",
            "[1,]",
            "01",
            "1.",
            "\"a",
            "{\"a\" 1}",
            "tru",
            "1 2",
            "\"\\x\"",
            "\"\\ud800\"",
        ] {
            assert!(parse_document(text).is_err(), "{text}");
        }
        assert!(parse_document(&"[".repeat(200)).is_err());
    }

    #[test]
    fn strings_and_structure_survive() {
        assert_eq!(
            parse_document(r#" {"a": [true, null, "\u00e9\ud83d\ude00\n"], "a": 2} "#)
                .map(|v| v.to_string()),
            Ok("{a=2}".to_owned())
        );
        assert_eq!(
            parse_first("[1] trailing").map(|v| v.to_string()),
            Ok("[1]".to_owned())
        );
    }
}
