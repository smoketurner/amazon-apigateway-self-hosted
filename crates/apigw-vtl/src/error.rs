//! Errors from parsing and rendering templates.

use thiserror::Error;

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
    /// A Velocity directive that API Gateway mapping templates are not evaluated with here.
    #[error("unsupported directive #{name} at line {line}")]
    UnsupportedDirective {
        /// The directive name, without the `#`.
        name: String,
        /// One-based line of the directive.
        line: usize,
    },
    /// An integer literal outside the range of a 64-bit integer.
    #[error("integer literal {literal} at line {line} does not fit in 64 bits")]
    IntegerLiteralTooLarge {
        /// The literal as written.
        literal: String,
        /// One-based line of the literal.
        line: usize,
    },
}

/// A failure while rendering a template.
#[derive(Debug, Clone, PartialEq, Error)]
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
    /// Integer arithmetic left the range of a 64-bit integer, where Java promotes to
    /// `BigInteger`.
    #[error("integer overflow")]
    IntegerOverflow,
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

impl From<crate::value::DepthExceeded> for RenderError {
    fn from(_: crate::value::DepthExceeded) -> Self {
        Self::ValueTooDeep
    }
}
