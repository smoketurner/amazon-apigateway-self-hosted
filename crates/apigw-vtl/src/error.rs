//! Errors from parsing and rendering templates.

use thiserror::Error;

use crate::value::DepthExceeded;

/// A template that cannot be parsed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseError {
    /// Velocity would reject the template with a `ParseErrorException`.
    #[error("syntax error at line {line}, column {column}: {message}")]
    Syntax {
        /// One-based line of the problem.
        line: usize,
        /// One-based column of the problem.
        column: usize,
        /// What is wrong.
        message: String,
    },
    /// The template nests directives, expressions, or strings deeper than the limit.
    #[error("template nests more than {limit} levels deep")]
    TooDeep {
        /// The nesting limit that was exceeded.
        limit: usize,
    },
    /// `#parse` or `#include`, which load other templates: API Gateway answers templates that
    /// use them with a 500.
    #[error("unsupported directive #{name} at line {line}")]
    UnsupportedDirective {
        /// The directive name, without the `#`.
        name: String,
        /// One-based line of the directive.
        line: usize,
    },
    /// An integer literal with more digits than this crate computes with (32,768 bits).
    #[error("integer literal {literal} at line {line} is too large")]
    IntegerLiteralTooLarge {
        /// The literal as written.
        literal: String,
        /// One-based line of the literal.
        line: usize,
    },
}

/// A failure while rendering a template.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RenderError {
    /// The output grew beyond the configured limit.
    #[error("rendered output exceeds {limit} bytes")]
    OutputLimit {
        /// The configured limit in bytes.
        limit: usize,
    },
    /// The template performed more operations than the configured budget.
    #[error("template exceeded the limit of {limit} evaluation steps")]
    StepLimit {
        /// The configured step budget.
        limit: u64,
    },
    /// Evaluation nested deeper than the configured limit.
    #[error("evaluation nests more than {limit} levels deep")]
    DepthLimit {
        /// The configured nesting limit.
        limit: usize,
    },
    /// A method threw, as `MethodInvocationException` in Velocity.
    #[error("method {method} failed: {message}")]
    Method {
        /// The method that failed.
        method: String,
        /// Why it failed.
        message: String,
    },
    /// `$list[n]` used an index outside the list.
    #[error("index {index} is out of bounds for a list of {len} elements")]
    IndexOutOfBounds {
        /// The index that was used.
        index: i64,
        /// The length of the list.
        len: usize,
    },
    /// A list was modified while a `#foreach` was iterating over it.
    #[error("list modified during #foreach")]
    ConcurrentModification,
    /// A `BigInteger` or `BigDecimal` grew beyond the size this crate computes with (32,768
    /// bits, or a scale of 10,000), where Java would keep allocating.
    #[error("number too large")]
    NumberTooLarge,
    /// An arithmetic operation Java rejects with `ArithmeticException` or
    /// `NumberFormatException`, such as `BigInteger.mod` of a negative modulus or `%` of a
    /// `BigDecimal`.
    #[error("arithmetic failed: {message}")]
    Arithmetic {
        /// Why it failed.
        message: String,
    },
    /// A collection was stored inside itself, which Java allows but which cannot be freed or
    /// printed.
    #[error("a collection cannot contain itself")]
    CircularReference,
    /// A value contains itself or nests too deeply to be formatted.
    #[error("value nests too deeply to format")]
    ValueTooDeep,
    /// The request body is not valid JSON but the template asked to read it with a JSON path.
    #[error("request body is not valid JSON: {0}")]
    InvalidBodyJson(String),
    /// A JSON path expression is malformed.
    #[error("invalid JSON path {path:?}: {message}")]
    InvalidJsonPath {
        /// The path as written.
        path: String,
        /// What is wrong with it.
        message: String,
    },
}

impl From<DepthExceeded> for RenderError {
    fn from(_: DepthExceeded) -> Self {
        Self::ValueTooDeep
    }
}
