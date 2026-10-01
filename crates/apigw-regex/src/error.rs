//! Error types for pattern translation, replacement parsing, and matching.

use std::fmt;

use thiserror::Error;

/// A Java regex construct that parses in Java but has no faithful translation.
///
/// Patterns using these are rejected when the pattern is compiled so that a misbehaving
/// pattern is reported at load time instead of silently matching differently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Unsupported {
    /// `\G`, the end of the previous match.
    EndOfPreviousMatch,
    /// `\X` or `\b{g}`, grapheme cluster handling.
    GraphemeCluster,
    /// `\N{name}`, a character by Unicode name.
    NamedCharacter,
    /// `\p{InBlock}` or `\p{block=...}`; the Unicode block tables are not available.
    UnicodeBlock(String),
    /// `\p{javaXxx}`, the `java.lang.Character` predicates.
    JavaCharacterPredicate(String),
    /// `\p{Graph}` or `\p{Print}` combined with Unicode character classes.
    UnicodePosixClass(String),
    /// A back reference evaluated case-insensitively.
    CaseInsensitiveBackReference,
    /// A lone UTF-16 surrogate, which cannot appear in a Rust string.
    LoneSurrogate,
}

impl fmt::Display for Unsupported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EndOfPreviousMatch => f.write_str("\\G (end of previous match)"),
            Self::GraphemeCluster => f.write_str("grapheme cluster matching (\\X, \\b{g})"),
            Self::NamedCharacter => f.write_str("\\N{name} character names"),
            Self::UnicodeBlock(name) => write!(f, "Unicode block property {name}"),
            Self::JavaCharacterPredicate(name) => {
                write!(f, "java.lang.Character predicate {name}")
            }
            Self::UnicodePosixClass(name) => {
                write!(f, "POSIX class {name} with Unicode character classes")
            }
            Self::CaseInsensitiveBackReference => f.write_str("case-insensitive back reference"),
            Self::LoneSurrogate => f.write_str("lone UTF-16 surrogate"),
        }
    }
}

/// A malformed Java replacement string, raised when a match is expanded.
///
/// Mirrors the `IllegalArgumentException` and `IndexOutOfBoundsException` cases of
/// `Matcher.appendReplacement`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ReplacementError {
    /// The replacement ends in a lone `\`.
    #[error("character to be escaped is missing")]
    MissingEscapedCharacter,
    /// The replacement ends in a lone `$`.
    #[error("illegal group reference: group index is missing")]
    MissingGroupIndex,
    /// `$` is followed by something other than a digit or `{`.
    #[error("illegal group reference")]
    IllegalGroupReference,
    /// `${}` has an empty name.
    #[error("named capturing group has 0 length name")]
    EmptyGroupName,
    /// `${name` is missing its closing brace.
    #[error("named capturing group is missing trailing '}}'")]
    UnclosedGroupName,
    /// `${1abc}` starts with a digit.
    #[error("capturing group name {{{0}}} starts with digit character")]
    GroupNameStartsWithDigit(String),
    /// `${name}` names a group the pattern does not define.
    #[error("no group with name {{{0}}}")]
    UnknownGroupName(String),
    /// `$n` names a group number above the pattern's group count.
    #[error("no group {0}")]
    UnknownGroupNumber(usize),
}

/// Why a pattern could not be compiled or a match could not be evaluated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RegexError {
    /// Java would reject the pattern with a `PatternSyntaxException`.
    #[error("invalid pattern: {message} near index {index}")]
    Syntax {
        /// What is wrong with the pattern.
        message: String,
        /// Zero-based index, in characters, where the problem was found.
        index: usize,
    },
    /// Java accepts the pattern but it cannot be translated faithfully.
    #[error("unsupported regex construct: {construct} near index {index}")]
    Unsupported {
        /// The construct that cannot be translated.
        construct: Unsupported,
        /// Zero-based index, in characters, where the construct starts.
        index: usize,
    },
    /// The pattern nests deeper than the translator allows.
    #[error("pattern nests more than {limit} levels deep")]
    TooDeep {
        /// The nesting limit that was exceeded.
        limit: usize,
    },
    /// The translated pattern was rejected by the matching engine, for example because a
    /// character property is unknown or the compiled program would be too large.
    #[error("pattern cannot be compiled: {0}")]
    Engine(String),
    /// Matching exceeded the configured backtrack limit.
    #[error("regex backtrack limit exceeded")]
    BacktrackLimitExceeded,
    /// The matching engine failed for another reason, such as running out of stack.
    #[error("regex evaluation failed: {0}")]
    Runtime(String),
    /// A replacement string was malformed for the match being expanded.
    #[error("invalid replacement: {0}")]
    Replacement(#[from] ReplacementError),
}

impl RegexError {
    pub(crate) fn syntax(message: impl Into<String>, index: usize) -> Self {
        Self::Syntax {
            message: message.into(),
            index,
        }
    }

    pub(crate) fn unsupported(construct: Unsupported, index: usize) -> Self {
        Self::Unsupported { construct, index }
    }

    /// Returns `true` when Java accepts the pattern but this crate cannot translate it.
    ///
    /// Callers that load patterns from an API definition should report these distinctly
    /// from [`RegexError::Syntax`], which means the definition is invalid in AWS too.
    #[must_use]
    pub fn is_untranslatable(&self) -> bool {
        matches!(
            self,
            Self::Unsupported { .. } | Self::TooDeep { .. } | Self::Engine(_)
        )
    }
}

impl From<fancy_regex::Error> for RegexError {
    fn from(err: fancy_regex::Error) -> Self {
        match err {
            fancy_regex::Error::RuntimeError(fancy_regex::RuntimeError::BacktrackLimitExceeded) => {
                Self::BacktrackLimitExceeded
            }
            fancy_regex::Error::RuntimeError(other) => Self::Runtime(other.to_string()),
            other => Self::Engine(other.to_string()),
        }
    }
}
