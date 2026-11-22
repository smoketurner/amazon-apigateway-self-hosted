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
//! (`{k=v}`, `[a, b]`, `1.0E10`). Arithmetic follows Velocity's `MathUtils`: `Integer` widens to
//! `Long`, a `long` that overflows becomes a `BigInteger`, and a `BigInteger` meeting a `double`
//! computes as `BigDecimal`. Map keys keep their Java types, so `{1: 'a'}` and `{'1': 'a'}` are
//! different maps. Templates are checked against output produced by Apache Velocity 1.7 itself;
//! see `tools/vtl-oracle` in the repository.
//!
//! # API Gateway's own behavior
//!
//! Where a deployed API Gateway was recorded to differ from Velocity's defaults, this crate does
//! what API Gateway does (the recordings are `parity/fixtures/rest-vtl-*.json`):
//!
//! - `#macro` definitions are parsed and ignored, so a macro call renders as written; `#evaluate`
//!   renders as written; `#define` binds a block that renders each time its reference is used.
//! - `#parse` and `#include` are [`ParseError::UnsupportedDirective`]; API Gateway answers such
//!   templates with a 500.
//! - `$input.path` of a definite path that addresses nothing is an empty string, and
//!   `$input.json` of such a path, or of a path whose function fails (`$.a..price.sum()`), is
//!   `""`.
//! - API Gateway renders a `null` reference as nothing; [`NullReferences::Empty`] selects that,
//!   and the default, [`NullReferences::Literal`], is Velocity's.
//!
//! # Differences from Velocity and Java
//!
//! Output is compared with Apache Velocity 1.7 and Jayway `JsonPath` 2.9 (see `tools/vtl-oracle`).
//! What is known to differ:
//!
//! - Numbers are bounded: a `BigInteger` or `BigDecimal` beyond 32,768 bits or a scale of 10,000
//!   is a [`RenderError::NumberTooLarge`], and a JSON number written with more than 4,096
//!   characters makes the body invalid.
//! - There is no reflection (`$x.class`, `getClass()`), and arrays are lists: `split` prints as a
//!   list instead of `[Ljava.lang.String;@...`. `Map.keySet()`, `values()`, and `entrySet()` are
//!   snapshots without `get(int)` or `[i]`, as the Java collections have none. A `#define` block
//!   has no `equals` or `hashCode`.
//! - Only the methods templates use are implemented, for the JDK 8 API. A call that matches no
//!   method renders as written, as in Velocity; Velocity instead throws for a single-overload
//!   method called with the wrong arguments.
//! - Velocity's lexer states that outlive a reference are reproduced: whitespace before `#set`,
//!   `##` after a property, and the reference and method-argument states that `#set`, comments,
//!   and a `(` left open after `$a.b` carry into the following text. Odd sequences such as
//!   `$#set(...)` or `# #set(...)` are not.
//! - JSON paths: Jayway's lenient handling of some malformed paths is an error here.
//!   `$util.parseJson` accepts strict JSON, not json-smart's permissive syntax.
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
mod json;
mod jsonpath;
mod methods;
mod number;
mod ops;
mod parser;
mod util;
mod value;

use std::str::FromStr;

pub use error::{ParseError, RenderError};
pub use jsonpath::{JsonPath, JsonPathError};
pub use number::{BigDecimal, BigInt, NumberTooLarge};
pub use value::{BlockRef, DepthExceeded, List, Map, MapEntry, Value};

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
    /// Returns [`ParseError`] when Velocity 1.7 would reject the template, when it uses
    /// `#parse` or `#include`, or when it nests too deeply.
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

/// How a reference renders when it is `null`: undefined, or a method or path that found
/// nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum NullReferences {
    /// As written, as Apache Velocity 1.7 renders it: `$missing` renders `$missing`, and the
    /// quiet form `$!missing` renders nothing.
    #[default]
    Literal,
    /// As nothing, as API Gateway renders it.
    Empty,
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
    null_references: NullReferences,
}

impl std::fmt::Debug for Renderer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Renderer")
            .field("limits", &self.limits)
            .field("null_references", &self.null_references)
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
            null_references: NullReferences::default(),
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

    /// Sets how a `null` reference renders: as written, as Velocity does (the default), or as
    /// nothing, as API Gateway does.
    #[must_use]
    pub const fn with_null_references(mut self, null_references: NullReferences) -> Self {
        self.null_references = null_references;
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
            self.null_references,
        )
        .render(&template.block)
    }
}
