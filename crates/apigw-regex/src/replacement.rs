//! Java replacement strings, as used by `String.replaceAll` and `Matcher.appendReplacement`.

use crate::error::{RegexError, ReplacementError};
use crate::regex::{Captures, JavaRegex};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Part {
    Literal(String),
    /// `$` followed by digits; how many of them name the group depends on the pattern.
    Number(String),
    /// `${name}`
    Named(String),
}

/// A Java replacement string: `$n` and `${name}` insert groups and `\` escapes the next
/// character.
///
/// Like Java, a malformed replacement is only an error once a match is expanded with it, so
/// replacing in text that has no match never fails.
///
/// # Examples
///
/// ```
/// use apigw_regex::{JavaRegex, Replacement};
///
/// # fn main() -> Result<(), apigw_regex::RegexError> {
/// let regex = JavaRegex::new(r"(\w+)@(\w+)")?;
/// let swapped = regex.replace_all("ann@example", &Replacement::from("$2 at $1"))?;
/// assert_eq!(swapped, "example at ann");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replacement {
    parts: Result<Vec<Part>, ReplacementError>,
}

impl Replacement {
    /// Escapes `text` so that it is inserted verbatim, like `Matcher.quoteReplacement`.
    #[must_use]
    pub fn quote(text: &str) -> String {
        let mut quoted = String::with_capacity(text.len());
        for c in text.chars() {
            if matches!(c, '\\' | '$') {
                quoted.push('\\');
            }
            quoted.push(c);
        }
        quoted
    }

    fn parse(raw: &str) -> Result<Vec<Part>, ReplacementError> {
        let mut parts = Vec::new();
        let mut literal = String::new();
        let mut chars = raw.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => literal.push(
                    chars
                        .next()
                        .ok_or(ReplacementError::MissingEscapedCharacter)?,
                ),
                '$' => {
                    if !literal.is_empty() {
                        parts.push(Part::Literal(std::mem::take(&mut literal)));
                    }
                    parts.push(Self::parse_reference(&mut chars)?);
                }
                other => literal.push(other),
            }
        }
        if !literal.is_empty() {
            parts.push(Part::Literal(literal));
        }
        Ok(parts)
    }

    /// Parses what follows a `$`.
    fn parse_reference(
        chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    ) -> Result<Part, ReplacementError> {
        match chars.peek().copied() {
            None => Err(ReplacementError::MissingGroupIndex),
            Some('{') => {
                chars.next();
                let mut name = String::new();
                while let Some(c) = chars.peek().copied().filter(char::is_ascii_alphanumeric) {
                    name.push(c);
                    chars.next();
                }
                if name.is_empty() {
                    return Err(ReplacementError::EmptyGroupName);
                }
                if chars.next() != Some('}') {
                    return Err(ReplacementError::UnclosedGroupName);
                }
                if name.starts_with(|c: char| c.is_ascii_digit()) {
                    return Err(ReplacementError::GroupNameStartsWithDigit(name));
                }
                Ok(Part::Named(name))
            }
            Some(first) if first.is_ascii_digit() => {
                let mut digits = String::new();
                while let Some(c) = chars.peek().copied().filter(char::is_ascii_digit) {
                    digits.push(c);
                    chars.next();
                }
                Ok(Part::Number(digits))
            }
            Some(_) => Err(ReplacementError::IllegalGroupReference),
        }
    }

    /// Appends the expansion of this replacement for one match.
    ///
    /// # Errors
    ///
    /// Returns [`RegexError::Replacement`] when the replacement is malformed or names a group
    /// the pattern does not have.
    pub(crate) fn expand_into(
        &self,
        regex: &JavaRegex,
        captures: &Captures<'_>,
        out: &mut String,
    ) -> Result<(), RegexError> {
        let parts = self.parts.as_ref().map_err(Clone::clone)?;
        for part in parts {
            match part {
                Part::Literal(text) => out.push_str(text),
                Part::Number(digits) => Self::expand_number(digits, regex, captures, out)?,
                Part::Named(name) => {
                    let index = regex
                        .group_index(name)
                        .ok_or_else(|| ReplacementError::UnknownGroupName(name.clone()))?;
                    Self::append_group(captures, index, out);
                }
            }
        }
        Ok(())
    }

    /// Takes digits greedily while the number is still a valid group, as Java does; digits
    /// beyond that are literal text.
    fn expand_number(
        digits: &str,
        regex: &JavaRegex,
        captures: &Captures<'_>,
        out: &mut String,
    ) -> Result<(), RegexError> {
        let mut digits = digits.chars();
        let mut number = digits
            .next()
            .and_then(|c| c.to_digit(10))
            .map_or(0, |d| d as usize);
        let mut rest = digits.as_str();
        for c in digits.clone() {
            let candidate = number
                .saturating_mul(10)
                .saturating_add(c.to_digit(10).map_or(0, |d| d as usize));
            if regex.group_count() < candidate {
                break;
            }
            number = candidate;
            rest = rest.strip_prefix(c).unwrap_or(rest);
        }
        if number > regex.group_count() {
            return Err(ReplacementError::UnknownGroupNumber(number).into());
        }
        Self::append_group(captures, number, out);
        out.push_str(rest);
        Ok(())
    }

    fn append_group(captures: &Captures<'_>, index: usize, out: &mut String) {
        if let Some(group) = captures.get(index) {
            out.push_str(group.as_str());
        }
    }
}

impl From<&str> for Replacement {
    fn from(raw: &str) -> Self {
        Self {
            parts: Self::parse(raw),
        }
    }
}
