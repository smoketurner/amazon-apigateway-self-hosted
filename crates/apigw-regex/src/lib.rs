//! `java.util.regex` semantics on top of `fancy-regex`.
//!
//! API Gateway evaluates mapping templates, integration response selection patterns, and
//! Lambda authorizer identity validation expressions with Java's regex engine. Rust engines
//! differ from it in ways that change results: Java's `\w`, `\d`, `\s`, and `\b` are ASCII by
//! default, `.` and `$` know about line terminators beyond `\n`, `matches()` covers the whole
//! input, and replacement strings use `$n` with greedy group numbers. This crate parses Java
//! pattern syntax, translates it to an equivalent `fancy-regex` pattern, and provides Java's
//! `matches`, `find`, `replaceAll`, `replaceFirst`, and `split` on top.
//!
//! Patterns that Java rejects fail with [`RegexError::Syntax`]. Patterns Java accepts but that
//! cannot be translated faithfully fail with [`RegexError::Unsupported`] so that callers can
//! report them when the API definition is loaded instead of matching differently at run time.
//! Evaluation is bounded by a configurable backtrack limit and reports
//! [`RegexError::BacktrackLimitExceeded`].
//!
//! # Differences from Java
//!
//! The translation is checked against the output of real `java.util.regex` (JDK 21) by a
//! committed fixture corpus; see `tools/java-regex-oracle`. The remaining known differences:
//!
//! - Strings are UTF-8, so Java's behavior of splitting a surrogate pair when it steps over an
//!   empty match (`"😀".split("")` yields lone surrogates) cannot be reproduced; matching
//!   advances by whole characters.
//! - When a quantified group can match the empty string (`(a*)*`), Java records the final empty
//!   iteration as the group's capture; the engine keeps the last non-empty one.
//! - `\b` and `\B` use ASCII word characters. Java also treats a combining mark that follows a
//!   letter as a word character.
//! - With `(?iu)`, case folding is Unicode simple case folding. Java compares through
//!   `toUpperCase` and `toLowerCase`, which also equates dotted and dotless `i` with `i` and `I`.
//! - Unicode property and script tables follow the Rust engine's Unicode version, which can be
//!   newer than the JDK's.
//! - A back reference under `(?i)` is rejected as [`Unsupported::CaseInsensitiveBackReference`],
//!   along with the other [`Unsupported`] constructs.
//! - Assertions such as `$`, multiline `^`, and `\b` are translated to look-around, so patterns
//!   using them run on the backtracking engine and count against the backtrack limit.
//!
//! # Examples
//!
//! ```
//! use apigw_regex::{JavaRegex, Replacement};
//!
//! # fn main() -> Result<(), apigw_regex::RegexError> {
//! let regex = JavaRegex::new(r"(?<user>\w+)@example\.com")?;
//! assert!(regex.matches("ann@example.com")?);
//! let redacted = regex.replace_all("mail ann@example.com", &Replacement::from("${user}@***"))?;
//! assert_eq!(redacted, "mail ann@***");
//! # Ok(())
//! # }
//! ```

mod ast;
mod classes;
mod emit;
mod error;
mod parser;
mod regex;
mod replacement;

pub use error::{RegexError, ReplacementError, Unsupported};
pub use regex::{
    Captures, DEFAULT_BACKTRACK_LIMIT, DEFAULT_SIZE_LIMIT, JavaRegex, Match, Matches, RegexOptions,
};
pub use replacement::Replacement;
