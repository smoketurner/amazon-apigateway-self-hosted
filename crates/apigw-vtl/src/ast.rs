//! The parsed form of a template.

use std::sync::Arc;

use crate::value::Value;

/// A sequence of template nodes.
#[derive(Debug, Clone, Default)]
pub(crate) struct Block(pub(crate) Vec<Node>);

/// One element of a template.
#[derive(Debug, Clone)]
pub(crate) enum Node {
    /// Literal text.
    Text(String),
    /// `$reference`.
    Reference(Reference),
    /// `#set`.
    Set(Set),
    /// `#if`, `#elseif`, `#else`.
    If(If),
    /// `#foreach`.
    Foreach(Foreach),
    /// `#break`.
    Break,
    /// `#stop`.
    Stop,
}

/// A step in a reference chain.
#[derive(Debug, Clone)]
pub(crate) enum Step {
    /// `.name`
    Property(Arc<str>),
    /// `.name(args)`
    Method(Arc<str>, Vec<Expr>),
    /// `[index]`
    Index(Box<Expr>),
}

/// `$name.chain`, with how it was written.
#[derive(Debug, Clone)]
pub(crate) struct Reference {
    /// The variable the chain starts at.
    pub(crate) head: Arc<str>,
    /// Property, method, and index steps applied to the variable.
    pub(crate) steps: Vec<Step>,
    /// `$!name`: render nothing instead of the reference text when null.
    pub(crate) quiet: bool,
    /// The reference exactly as written, which is what an unresolved reference renders.
    pub(crate) source: String,
    /// Backslashes written before the `$`.
    pub(crate) backslashes: usize,
}

/// `#set($target = value)`.
#[derive(Debug, Clone)]
pub(crate) struct Set {
    pub(crate) head: Arc<str>,
    pub(crate) steps: Vec<Step>,
    pub(crate) value: Expr,
}

/// A conditional with its branches.
#[derive(Debug, Clone)]
pub(crate) struct If {
    pub(crate) branches: Vec<(Expr, Block)>,
    pub(crate) otherwise: Option<Block>,
}

/// `#foreach($var in source)`.
#[derive(Debug, Clone)]
pub(crate) struct Foreach {
    pub(crate) var: Arc<str>,
    pub(crate) source: Expr,
    pub(crate) body: Block,
}

/// Binary operators.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BinaryOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

/// An expression.
#[derive(Debug, Clone)]
pub(crate) enum Expr {
    /// A number, boolean, or single-quoted string.
    Literal(Value),
    /// A double-quoted string, which is itself a template.
    Interpolated(Block),
    /// A reference.
    Reference(Reference),
    /// `[a, b]`
    List(Vec<Self>),
    /// `{k: v}`
    Map(Vec<(Self, Self)>),
    /// `[from..to]`
    Range(Box<Self>, Box<Self>),
    /// `!x`
    Not(Box<Self>),
    /// `a op b`
    Binary(BinaryOp, Box<Self>, Box<Self>),
}
