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
//! report them when the API definition is loaded instead of matching differently at run time;
//! the only such construct is `\N{name}`. Evaluation is bounded by a configurable backtrack
//! limit and reports [`RegexError::BacktrackLimitExceeded`], never a silent "no match".
//!
//! # Differences from Java
//!
//! The translation is checked against the output of real `java.util.regex` (JDK 21) by a
//! committed fixture corpus; see `tools/java-regex-oracle`. The remaining known differences:
//!
//! - Strings are UTF-8, so Java's behavior of splitting a surrogate pair when it steps over an
//!   empty match (`"😀".split("")` yields lone surrogates) cannot be reproduced; matching
//!   advances by whole characters. A lone surrogate in a pattern never matches, as in Java for
//!   any input without lone surrogates.
//! - A case-insensitive back reference compares by Unicode simple case folding over the same
//!   number of UTF-8 bytes (the engine's back reference). Java compares character by character
//!   through `toUpperCase` and `toLowerCase`, and folds only ASCII letters without `(?u)`. So
//!   `(?i)(é)\1` matches `éÉ` here but not in Java, and `(?iu)(.)\1` matches `k` followed by
//!   the Kelvin sign (U+212A), `sſ`, `ßẞ`, `iı`, and `iİ` in Java but not here.
//! - Java bounds a look-behind as if `\X` had no width, so a look-behind around `\X` never
//!   matches in Java; here it matches the cluster.
//! - `\b{g}` follows Java's algorithm: a boundary is any position at or after the end of the
//!   first cluster that starts where the previous match ended. Java reads that position from
//!   matcher state that its own look-ahead and repetition nodes also overwrite, which the
//!   translation does not reproduce.
//! - Unicode properties, scripts, case mappings, and grapheme cluster types follow the Unicode
//!   version of the Rust standard library and the engine, which can be newer than the JDK's.
//!   Block and script names, and block ranges, are Java's own (`src/tables.rs`).
//! - Assertions such as `$`, multiline `^`, and `\b` are translated to look-around, and loops
//!   whose body can match the empty string run on the backtracking engine, so those patterns
//!   count against the backtrack limit.
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
mod case;
mod classes;
mod emit;
mod error;
mod parser;
mod regex;
mod replacement;
mod tables;

pub use error::{RegexError, ReplacementError, Unsupported};
pub use regex::{
    Captures, DEFAULT_BACKTRACK_LIMIT, DEFAULT_SIZE_LIMIT, JavaRegex, Match, Matches, RegexOptions,
};
pub use replacement::Replacement;
