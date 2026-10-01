//! Apache Velocity 1.7 mapping templates, as Amazon API Gateway evaluates them.
//!
//! API Gateway transforms requests and responses with Velocity Template Language (VTL)
//! templates that see `$input`, `$util`, `$context`, and `$stageVariables`. This crate parses
//! and renders those templates without any I/O, so a gateway can call it from its request
//! pipeline.
//!
//! The behavior is that of the real engine, including its quirks: an undefined reference renders
//! as its own source text (`$!x` renders nothing), directive-only lines vanish, `#foreach` stops
//! after 1,000 iterations, `#if` treats literals as false, and values print like Java
//! (`{k=v}`, `[a, b]`, `1.0E10`). Templates are checked against output produced by Apache
//! Velocity 1.7 itself; see `tools/vtl-oracle` in the repository.
//!
//! # Differences from Velocity and Java
//!
//! Output is compared with Apache Velocity 1.7 and Jayway `JsonPath` 2.9 (see `tools/vtl-oracle`).
//! What is known to differ:
//!
//! - `#macro`, `#parse`, `#include`, `#evaluate`, and `#define` are rejected as
//!   [`ParseError::UnsupportedDirective`].
//! - Integer arithmetic that leaves 64 bits is a [`RenderError::IntegerOverflow`]; Java promotes to
//!   `BigInteger`. JSON integers beyond 64 bits become doubles.
//! - `Map` keys are strings, so `{1: 'a'}` and `$m.get('1')` agree where Java distinguishes them.
//! - There is no reflection (`$x.class`, `getClass()`), and arrays are lists: `split` prints as a
//!   list instead of `[Ljava.lang.String;@...`. `Map.keySet()`, `values()`, and `entrySet()` are
//!   snapshots without `get(int)` or `[i]`, as the Java collections have none.
//! - Only the methods templates use are implemented, for the JDK 8 API. A call that matches no
//!   method renders as written, as in Velocity; Velocity instead throws for a single-overload
//!   method called with the wrong arguments.
//! - Lexer states that make Velocity's output depend on earlier tokens are reproduced for the
//!   common cases (whitespace before `#set`, `##` after a property, `[` after a reference and a
//!   directive). Odd sequences such as `$#set(...)` or `# #set(...)` are not.
//! - JSON paths: functions after `..`, such as `$..price.max()`, are rejected, and Jayway's lenient
//!   handling of some malformed paths is an error here. `$util.parseJson` accepts strict JSON, not
//!   json-smart's permissive syntax.
//! - `$input.json` returns compact JSON and `$input.params(name)` matches headers
//!   case-insensitively; both follow API Gateway's documentation but have not been compared with a
//!   live API.
//!
//! # Examples
//!
//! ```
//! use apigw_vtl::{InputParams, Renderer, SimpleInput, Template};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let template: Template = r##"{"names": [#foreach($u in $input.path('$.users'))"$u.name"#if($foreach.hasNext),#end#end]}"##.parse()?;
//! let input = SimpleInput::new(r#"{"users":[{"name":"ann"},{"name":"bob"}]}"#, InputParams::default());
//! let output = Renderer::new(&input).render(&template)?;
//! assert_eq!(output, r#"{"names": ["ann","bob"]}"#);
//! # Ok(())
//! # }
//! ```

mod ast;
mod error;
mod eval;
mod jsonpath;
mod methods;
mod ops;
mod parser;
mod util;
mod value;

use std::str::FromStr;

pub use error::{ParseError, RenderError};
pub use jsonpath::{JsonPath, JsonPathError};
pub use value::{DepthExceeded, List, Map, MapEntry, Value};

/// A parsed template, ready to be rendered any number of times.
#[derive(Debug, Clone)]
pub struct Template {
    block: ast::Block,
}

impl Template {
    /// Parses a template.
    ///
    /// # Errors
    ///
    /// Returns [`ParseError`] when Velocity 1.7 would reject the template, when it uses a
    /// directive this crate does not evaluate (`#macro`, `#parse`, `#include`, `#evaluate`,
    /// `#define`), or when it nests too deeply.
    pub fn parse(source: &str) -> Result<Self, ParseError> {
        Ok(Self {
            block: parser::Parser::parse(source)?,
        })
    }
}

impl FromStr for Template {
    type Err = ParseError;

    fn from_str(source: &str) -> Result<Self, Self::Err> {
        Self::parse(source)
    }
}

/// The method request parameters that `$input.params()` exposes.
#[derive(Debug, Clone, Default)]
pub struct InputParams {
    /// Path parameters.
    pub path: Map,
    /// Query string parameters.
    pub querystring: Map,
    /// Header parameters; names are matched case-insensitively by `$input.params(name)`.
    pub header: Map,
}

/// The request data behind `$input`, implemented by the gateway.
///
/// `$input.body` and `$input.path(...)` read [`TemplateInput::body`], and `$input.params()`
/// reads [`TemplateInput::params`].
pub trait TemplateInput {
    /// The raw request (or integration response) body.
    fn body(&self) -> &str;

    /// The method request parameters.
    fn params(&self) -> &InputParams;
}

/// A [`TemplateInput`] that owns its body and parameters.
#[derive(Debug, Clone)]
pub struct SimpleInput {
    body: String,
    params: InputParams,
}

impl SimpleInput {
    /// Creates an input from a body and parameters.
    #[must_use]
    pub fn new(body: impl Into<String>, params: InputParams) -> Self {
        Self {
            body: body.into(),
            params,
        }
    }
}

impl TemplateInput for SimpleInput {
    fn body(&self) -> &str {
        &self.body
    }

    fn params(&self) -> &InputParams {
        &self.params
    }
}

/// Bounds on what one render may consume.
///
/// Exceeding a bound is a [`RenderError`], never a panic. `#foreach` itself always stops after
/// 1,000 iterations, as in API Gateway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Limits {
    /// The most bytes a render may produce; API Gateway's payload limit is 10 MiB.
    pub output_bytes: usize,
    /// How many evaluation steps (nodes rendered, expressions and range elements evaluated)
    /// one render may take; this bounds nested loops that print nothing.
    pub steps: u64,
    /// How deeply directives, strings, and expressions may nest during evaluation.
    pub depth: usize,
}

impl Limits {
    /// Sets the most bytes a render may produce.
    #[must_use]
    pub const fn with_output_bytes(mut self, output_bytes: usize) -> Self {
        self.output_bytes = output_bytes;
        self
    }

    /// Sets the evaluation step budget.
    #[must_use]
    pub const fn with_steps(mut self, steps: u64) -> Self {
        self.steps = steps;
        self
    }

    /// Sets the evaluation nesting limit.
    #[must_use]
    pub const fn with_depth(mut self, depth: usize) -> Self {
        self.depth = depth;
        self
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            output_bytes: 10 * 1024 * 1024,
            steps: 5_000_000,
            depth: 128,
        }
    }
}

/// Renders templates for one request.
///
/// `$context` and `$stageVariables` are maps the gateway owns: the renderer shares them, so
/// after rendering the gateway reads back what the template stored, such as
/// `$context.requestOverride.header` and `$context.responseOverride.status`.
pub struct Renderer<'a> {
    input: &'a dyn TemplateInput,
    context: Map,
    stage_variables: Map,
    limits: Limits,
}

impl std::fmt::Debug for Renderer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Renderer")
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<'a> Renderer<'a> {
    /// Creates a renderer over `input` with empty `$context` and `$stageVariables`.
    #[must_use]
    pub fn new(input: &'a dyn TemplateInput) -> Self {
        Self {
            input,
            context: Map::new(),
            stage_variables: Map::new(),
            limits: Limits::default(),
        }
    }

    /// Sets the `$context` map. Keep a clone of the handle to read changes back.
    #[must_use]
    pub fn with_context(mut self, context: Map) -> Self {
        self.context = context;
        self
    }

    /// Sets the `$stageVariables` map.
    #[must_use]
    pub fn with_stage_variables(mut self, stage_variables: Map) -> Self {
        self.stage_variables = stage_variables;
        self
    }

    /// Sets the resource limits.
    #[must_use]
    pub const fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Renders `template`.
    ///
    /// # Errors
    ///
    /// Returns [`RenderError`] when a limit is exceeded, a method throws, or an index is out of
    /// bounds; API Gateway answers such requests with a 500.
    pub fn render(&self, template: &Template) -> Result<String, RenderError> {
        eval::Interpreter::new(
            self.input,
            self.context.clone(),
            self.stage_variables.clone(),
            self.limits,
        )
        .render(&template.block)
    }
}
