//! JSON path expressions with Jayway `JsonPath` 2.x semantics.
//!
//! API Gateway evaluates `$input.path('$.a.b')` and `$input.json(...)` with Jayway `JsonPath`.
//! This module implements its dot and bracket notation, wildcards, deep scan (`..`), index
//! lists, slices, filters (`[?(@.price < 10 && @.in_stock)]`), and the common functions
//! (`length()`, `min()`, `max()`, `avg()`, `sum()`, `stddev()`, `keys()`, `first()`, `last()`,
//! `index(n)`, `concat(..)`, `append(..)`).
//!
//! Evaluation follows Jayway with `SUPPRESS_EXCEPTIONS`: a definite path that finds nothing
//! evaluates to `null` and an indefinite one to an empty list. Behaviors that look like Jayway
//! quirks are reproduced because they were observed against the real library: a slice with a
//! negative start and a positive end concatenates two slices, multiple property names yield one
//! map, and functions after a wildcard run once per match.

use std::fmt;
use std::str::FromStr;

use apigw_regex::JavaRegex;

use crate::value::{List, Map, Value, doubles_equal};

/// A malformed or unsupported path expression, or a function that cannot be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonPathError {
    message: String,
}

impl JsonPathError {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for JsonPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for JsonPathError {}

/// Deepest nesting of filter expressions and of documents scanned with `..`.
const MAX_DEPTH: usize = 64;

#[derive(Debug, Clone)]
enum Selector {
    /// `.name` or `['a','b']`
    Child(Vec<String>),
    /// `[0]` or `[0,1]`
    Index(Vec<i64>),
    /// `[from:to]`
    Slice(Option<i64>, Option<i64>),
    /// `.*` or `[*]`
    Wildcard,
    /// `[?(...)]`
    Filter(Filter),
    /// `.length()` and friends
    Function(Function),
}

impl Selector {
    /// Whether the selector can match more than one value.
    const fn is_multiple(&self) -> bool {
        match self {
            Self::Child(_) | Self::Function(_) => false,
            Self::Index(indexes) => indexes.len() != 1,
            Self::Slice(..) | Self::Wildcard | Self::Filter(_) => true,
        }
    }
}

#[derive(Debug, Clone)]
struct Segment {
    /// Preceded by `..`: the selector applies to every descendant.
    scan: bool,
    selector: Selector,
}

/// What a path found.
#[derive(Debug)]
enum Found {
    /// A definite path that addressed nothing, or an indefinite one with no matches.
    Nothing,
    /// The one value a definite path addresses.
    One(Value),
    /// Every match of an indefinite path.
    Many(Vec<Value>),
}

/// The segments of a path, shared by top-level paths and filter operands.
#[derive(Debug, Clone)]
struct Segments(Vec<Segment>);

impl Segments {
    fn is_definite(&self) -> bool {
        self.0
            .iter()
            .all(|segment| !segment.scan && !segment.selector.is_multiple())
    }

    fn run(&self, start: &Value, root: &Value) -> Result<Found, JsonPathError> {
        let mut current = vec![start.clone()];
        let mut multiple = false;
        let mut scanned = false;
        for segment in &self.0 {
            if let Selector::Function(function) = &segment.selector {
                if scanned {
                    return Err(JsonPathError::new("functions after '..' are not supported"));
                }
                current = if multiple {
                    current
                        .iter()
                        .map(|value| function.apply(value).map(|v| v.unwrap_or(Value::Null)))
                        .collect::<Result<_, _>>()?
                } else {
                    let input = current.first().cloned();
                    match input {
                        Some(input) => vec![function.apply(&input)?.unwrap_or(Value::Null)],
                        None => Vec::new(),
                    }
                };
                continue;
            }
            multiple |= segment.selector.is_multiple() || segment.scan;
            scanned |= segment.scan;
            let mut next = Vec::new();
            for node in &current {
                if segment.scan {
                    scan(node, &segment.selector, root, &mut next, 0);
                } else {
                    segment.selector.apply(node, root, false, &mut next);
                }
            }
            current = next;
        }
        Ok(if multiple {
            Found::Many(current)
        } else {
            current
                .into_iter()
                .next()
                .map_or(Found::Nothing, Found::One)
        })
    }
}

/// A compiled JSON path.
///
/// # Examples
///
/// ```
/// use apigw_vtl::{JsonPath, Value};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let doc = Value::from_json(r#"{"items":[{"id":1},{"id":2}]}"#)?;
/// let ids = "$.items[*].id".parse::<JsonPath>()?.evaluate(&doc)?;
/// assert_eq!(ids.to_string(), "[1, 2]");
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct JsonPath {
    segments: Segments,
}

impl JsonPath {
    /// Evaluates the path against `document`.
    ///
    /// A definite path (plain names and single indexes) yields the one value it addresses, or
    /// `null` when it is missing. Any other path yields a list of every match.
    ///
    /// # Errors
    ///
    /// Returns [`JsonPathError`] when a function cannot be applied, for example `max()` of an
    /// empty array, as Jayway throws.
    pub fn evaluate(&self, document: &Value) -> Result<Value, JsonPathError> {
        Ok(match self.segments.run(document, document)? {
            Found::One(value) => value,
            Found::Many(values) => Value::List(List::from_values(values)),
            Found::Nothing => {
                if self.segments.is_definite() {
                    Value::Null
                } else {
                    Value::List(List::new())
                }
            }
        })
    }
}

impl FromStr for JsonPath {
    type Err = JsonPathError;

    fn from_str(path: &str) -> Result<Self, Self::Err> {
        let trimmed = path.trim();
        let source = if trimmed.starts_with('$') || trimmed.starts_with('@') {
            trimmed.to_owned()
        } else {
            format!("$.{trimmed}")
        };
        let mut parser = PathParser::new(&source);
        let segments = parser.parse_path()?;
        Ok(Self {
            segments: Segments(segments),
        })
    }
}

/// Applies `selector` to `node` and every container below it, in document order.
fn scan(node: &Value, selector: &Selector, root: &Value, out: &mut Vec<Value>, depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    selector.apply(node, root, true, out);
    let children: Vec<Value> = match node {
        Value::Map(map) => map.entries().into_iter().map(|(_, child)| child).collect(),
        Value::List(list) => list.snapshot(),
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Double(_)
        | Value::Str(_)
        | Value::Entry(_)
        | Value::Input
        | Value::Util
        | Value::Loop(_) => return,
    };
    for child in children {
        if matches!(child, Value::Map(_) | Value::List(_)) {
            scan(&child, selector, root, out, depth.saturating_add(1));
        }
    }
}

impl Selector {
    /// Adds the matches of the selector at `node`. `scanning` is set when the selector is
    /// being applied at every descendant of a `..`.
    fn apply(&self, node: &Value, root: &Value, scanning: bool, out: &mut Vec<Value>) {
        match self {
            Self::Child(names) => Self::apply_child(names, node, scanning, out),
            Self::Index(indexes) => {
                if let Value::List(list) = node {
                    for index in indexes {
                        if let Some(value) =
                            normalize_index(*index, list.len()).and_then(|i| list.get(i))
                        {
                            out.push(value);
                        }
                    }
                }
            }
            Self::Slice(from, to) => {
                if let Value::List(list) = node {
                    out.extend(slice(&list.snapshot(), *from, *to));
                }
            }
            Self::Wildcard => match node {
                Value::Map(map) => out.extend(map.entries().into_iter().map(|(_, value)| value)),
                Value::List(list) => out.extend(list.snapshot()),
                Value::Null
                | Value::Bool(_)
                | Value::Int(_)
                | Value::Double(_)
                | Value::Str(_)
                | Value::Entry(_)
                | Value::Input
                | Value::Util
                | Value::Loop(_) => {}
            },
            Self::Filter(filter) => match node {
                Value::List(list) => {
                    for item in list.snapshot() {
                        if filter.matches(&item, root, 0) {
                            out.push(item);
                        }
                    }
                }
                Value::Map(_) if !scanning => {
                    if filter.matches(node, root, 0) {
                        out.push(node.clone());
                    }
                }
                Value::Map(_)
                | Value::Null
                | Value::Bool(_)
                | Value::Int(_)
                | Value::Double(_)
                | Value::Str(_)
                | Value::Entry(_)
                | Value::Input
                | Value::Util
                | Value::Loop(_) => {}
            },
            Self::Function(_) => {}
        }
    }

    /// One name yields its value; several yield a map of the names present, and during a scan
    /// only maps that have every name match.
    fn apply_child(names: &[String], node: &Value, scanning: bool, out: &mut Vec<Value>) {
        let Value::Map(map) = node else {
            return;
        };
        if let [name] = names {
            if let Some(value) = map.get(name) {
                out.push(value);
            }
            return;
        }
        if scanning && !names.iter().all(|name| map.contains_key(name)) {
            return;
        }
        let picked = Map::new();
        for name in names {
            if let Some(value) = map.get(name) {
                picked.insert(name.as_str(), value);
            }
        }
        out.push(Value::Map(picked));
    }
}

fn normalize_index(index: i64, len: usize) -> Option<usize> {
    let len = i64::try_from(len).ok()?;
    let resolved = if index < 0 {
        index.checked_add(len)?
    } else {
        index
    };
    if (0..len).contains(&resolved) {
        usize::try_from(resolved).ok()
    } else {
        None
    }
}

/// Jayway's slice rules. Two oddities are reproduced: `[a:b]` with a positive `a` and a negative
/// `b` is empty, and with a negative `a` and a positive `b` it is `[a:]` followed by `[:b]`.
fn slice(items: &[Value], from: Option<i64>, to: Option<i64>) -> Vec<Value> {
    let len = i64::try_from(items.len()).unwrap_or(i64::MAX);
    let take = |start: i64, end: i64| -> Vec<Value> {
        let (start, end) = (start.clamp(0, len), end.clamp(0, len));
        let (start, end) = (
            usize::try_from(start).unwrap_or(0),
            usize::try_from(end).unwrap_or(0),
        );
        items
            .iter()
            .skip(start)
            .take(end.saturating_sub(start))
            .cloned()
            .collect()
    };
    let from_start = |from: i64| {
        if from < 0 {
            from.saturating_add(len).max(0)
        } else {
            from
        }
    };
    let to_end = |to: i64| if to < 0 { to.saturating_add(len) } else { to };
    match (from, to) {
        (None, None) => take(0, len),
        (Some(from), None) => take(from_start(from), len),
        (None, Some(to)) => take(0, to_end(to)),
        (Some(from), Some(to)) if from >= 0 && to >= 0 => take(from, to),
        (Some(from), Some(to)) if from < 0 && to < 0 => take(from_start(from), to_end(to)),
        (Some(from), Some(to)) if from < 0 => {
            let mut head = take(from_start(from), len);
            head.extend(take(0, to));
            head
        }
        (Some(_), Some(_)) => Vec::new(),
    }
}

// ----- functions -----

#[derive(Debug, Clone)]
enum Function {
    Length,
    Min,
    Max,
    Avg,
    Sum,
    StdDev,
    Keys,
    First,
    Last,
    Index(i64),
    Concat(Vec<Value>),
    Append(Vec<Value>),
}

impl Function {
    /// Applies the function to one value. `None` is a `null` result; an error is a function
    /// Jayway throws for.
    fn apply(&self, input: &Value) -> Result<Option<Value>, JsonPathError> {
        match self {
            Self::Length => Ok(match input {
                Value::List(list) => i64::try_from(list.len()).ok().map(Value::Int),
                Value::Map(map) => i64::try_from(map.len()).ok().map(Value::Int),
                _ => None,
            }),
            Self::Min | Self::Max | Self::Avg | Self::Sum | Self::StdDev => {
                let numbers = numbers(input);
                if numbers.is_empty() {
                    return Err(JsonPathError::new(
                        "aggregation function attempted to calculate a value using an empty array",
                    ));
                }
                Ok(Some(Value::Double(self.aggregate(&numbers))))
            }
            Self::Keys => Ok(match input {
                Value::Map(map) => Some(Value::List(List::from_values(
                    map.entries()
                        .into_iter()
                        .map(|(key, _)| Value::Str(key))
                        .collect(),
                ))),
                _ => None,
            }),
            Self::First => match input {
                Value::List(list) => list
                    .get(0)
                    .map(Some)
                    .ok_or_else(|| JsonPathError::new("first() of an empty array")),
                _ => Ok(None),
            },
            Self::Last => match input {
                Value::List(list) => list
                    .len()
                    .checked_sub(1)
                    .and_then(|last| list.get(last))
                    .map(Some)
                    .ok_or_else(|| JsonPathError::new("last() of an empty array")),
                _ => Ok(None),
            },
            Self::Index(index) => match input {
                Value::List(list) => normalize_index(*index, list.len())
                    .and_then(|i| list.get(i))
                    .map(Some)
                    .ok_or_else(|| JsonPathError::new(format!("index({index}) is out of bounds"))),
                _ => Ok(None),
            },
            Self::Concat(extra) => {
                let mut joined = String::new();
                if let Value::List(list) = input {
                    for item in list.snapshot() {
                        if let Value::Str(text) = item {
                            joined.push_str(&text);
                        }
                    }
                }
                for value in extra {
                    if matches!(value, Value::Int(_) | Value::Double(_)) {
                        joined.push_str(
                            &value
                                .to_java_string()
                                .map_err(|e| JsonPathError::new(e.to_string()))?,
                        );
                    }
                }
                Ok(Some(Value::from(joined)))
            }
            Self::Append(extra) => Ok(Some(match input {
                Value::List(list) => {
                    let mut items = list.snapshot();
                    items.extend(
                        extra
                            .iter()
                            .filter(|v| matches!(v, Value::Int(_) | Value::Double(_)))
                            .cloned(),
                    );
                    Value::List(List::from_values(items))
                }
                other => other.clone(),
            })),
        }
    }

    fn aggregate(&self, numbers: &[f64]) -> f64 {
        let count = f64::from(u32::try_from(numbers.len()).unwrap_or(u32::MAX));
        let sum: f64 = numbers.iter().sum();
        match self {
            Self::Min => numbers.iter().copied().fold(f64::INFINITY, f64::min),
            Self::Max => numbers.iter().copied().fold(f64::NEG_INFINITY, f64::max),
            Self::Sum => sum,
            Self::Avg => sum / count,
            _ => {
                let average = sum / count;
                let variance = numbers.iter().map(|x| (x - average).powi(2)).sum::<f64>() / count;
                variance.sqrt()
            }
        }
    }
}

/// The numbers in an array; other elements are skipped.
fn numbers(input: &Value) -> Vec<f64> {
    let Value::List(list) = input else {
        return Vec::new();
    };
    list.snapshot()
        .into_iter()
        .filter_map(|item| match item {
            Value::Int(value) => Some(f64_from_i64(value)),
            Value::Double(value) => Some(value),
            _ => None,
        })
        .collect()
}

/// Converts an integer to a double, losing precision beyond 2^53 like Java's widening.
#[expect(
    clippy::cast_precision_loss,
    reason = "Java's long to double conversion rounds the same way"
)]
const fn f64_from_i64(value: i64) -> f64 {
    value as f64
}

// ----- filters -----

#[derive(Debug, Clone)]
enum Filter {
    Or(Box<Self>, Box<Self>),
    And(Box<Self>, Box<Self>),
    Not(Box<Self>),
    Exists(Operand),
    Compare(Operand, CompareOp, Operand),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CompareOp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Regex,
    In,
    NotIn,
    SubsetOf,
    AnyOf,
    NoneOf,
    Size,
    Empty,
    Contains,
}

#[derive(Debug, Clone)]
enum Operand {
    Literal(Value),
    Regex(String),
    /// `@...` or `$...`
    Path {
        from_root: bool,
        segments: Segments,
    },
}

/// The value of an operand: a JSON value, or nothing when a path matched nothing.
type Resolved = Option<Value>;

impl Filter {
    fn matches(&self, current: &Value, root: &Value, depth: usize) -> bool {
        if depth > MAX_DEPTH {
            return false;
        }
        let next = depth.saturating_add(1);
        match self {
            Self::Or(a, b) => a.matches(current, root, next) || b.matches(current, root, next),
            Self::And(a, b) => a.matches(current, root, next) && b.matches(current, root, next),
            Self::Not(inner) => !inner.matches(current, root, next),
            Self::Exists(operand) => operand.resolve(current, root).is_some(),
            Self::Compare(left, op, right) => {
                let left = left.resolve(current, root);
                let right = right.resolve(current, root);
                op.holds(left.as_ref(), right.as_ref())
            }
        }
    }
}

impl Operand {
    fn resolve(&self, current: &Value, root: &Value) -> Resolved {
        match self {
            Self::Literal(value) => Some(value.clone()),
            Self::Regex(pattern) => Some(Value::from(pattern.as_str())),
            Self::Path {
                from_root,
                segments,
            } => {
                let start = if *from_root { root } else { current };
                match segments.run(start, root) {
                    Ok(Found::One(value)) => Some(value),
                    Ok(Found::Many(values)) if !values.is_empty() => {
                        Some(Value::List(List::from_values(values)))
                    }
                    Ok(Found::Many(_) | Found::Nothing) | Err(_) => None,
                }
            }
        }
    }
}

impl CompareOp {
    fn holds(self, left: Option<&Value>, right: Option<&Value>) -> bool {
        match self {
            Self::Eq => values_equal(left, right),
            Self::Ne => !values_equal(left, right),
            Self::Lt | Self::Le | Self::Gt | Self::Ge => {
                let (Some(left), Some(right)) = (left, right) else {
                    return false;
                };
                match compare_values(left, right) {
                    Some(ordering) => match self {
                        Self::Lt => ordering.is_lt(),
                        Self::Le => ordering.is_le(),
                        Self::Gt => ordering.is_gt(),
                        _ => ordering.is_ge(),
                    },
                    None => false,
                }
            }
            Self::Regex => regex_matches(left, right),
            Self::In => membership(left, right).unwrap_or(false),
            Self::NotIn => !membership(left, right).unwrap_or(false),
            Self::SubsetOf => subset(left, right).unwrap_or(false),
            Self::AnyOf => overlap(left, right).unwrap_or(false),
            Self::NoneOf => overlap(left, right).is_some_and(|found| !found),
            Self::Size => size_of(left).is_some_and(|size| match right {
                Some(Value::Int(expected)) => size == *expected,
                _ => false,
            }),
            Self::Empty => {
                let empty = match left {
                    Some(Value::List(list)) => list.is_empty(),
                    Some(Value::Str(text)) => text.is_empty(),
                    Some(Value::Map(map)) => map.is_empty(),
                    _ => return false,
                };
                matches!(right, Some(Value::Bool(expected)) if *expected == empty)
            }
            Self::Contains => match (left, right) {
                (Some(Value::Str(text)), Some(Value::Str(part))) => text.contains(&**part),
                (Some(Value::List(list)), Some(item)) => {
                    list.snapshot().iter().any(|v| json_equal(v, item))
                }
                _ => false,
            },
        }
    }
}

fn values_equal(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(a), Some(b)) => json_equal(a, b),
        _ => false,
    }
}

/// Equality as Jayway compares JSON nodes: numbers by value across integer and double.
fn json_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Int(x), Value::Double(y)) | (Value::Double(y), Value::Int(x)) => {
            doubles_equal(f64_from_i64(*x), *y)
        }
        (Value::List(x), Value::List(y)) => {
            let (x, y) = (x.snapshot(), y.snapshot());
            x.len() == y.len() && x.iter().zip(&y).all(|(p, q)| json_equal(p, q))
        }
        (Value::Map(x), Value::Map(y)) => {
            let (x, y) = (x.entries(), y.entries());
            x.len() == y.len()
                && x.iter().all(|(key, value)| {
                    y.iter()
                        .find(|(other, _)| other == key)
                        .is_some_and(|(_, other)| json_equal(value, other))
                })
        }
        _ => a.java_equals(b),
    }
}

fn compare_values(left: &Value, right: &Value) -> Option<std::cmp::Ordering> {
    match (left, right) {
        (Value::Int(a), Value::Int(b)) => Some(a.cmp(b)),
        (Value::Int(a), Value::Double(b)) => f64_from_i64(*a).partial_cmp(b),
        (Value::Double(a), Value::Int(b)) => a.partial_cmp(&f64_from_i64(*b)),
        (Value::Double(a), Value::Double(b)) => a.partial_cmp(b),
        (Value::Str(a), Value::Str(b)) => Some(a.encode_utf16().cmp(b.encode_utf16())),
        _ => None,
    }
}

fn regex_matches(left: Option<&Value>, right: Option<&Value>) -> bool {
    let (Some(Value::Str(text)), Some(Value::Str(pattern))) = (left, right) else {
        return false;
    };
    JavaRegex::new(pattern)
        .and_then(|regex| regex.matches(text))
        .unwrap_or(false)
}

fn membership(left: Option<&Value>, right: Option<&Value>) -> Option<bool> {
    let (Some(left), Some(Value::List(items))) = (left, right) else {
        return None;
    };
    Some(items.snapshot().iter().any(|item| json_equal(item, left)))
}

fn subset(left: Option<&Value>, right: Option<&Value>) -> Option<bool> {
    let (Some(Value::List(left)), Some(Value::List(right))) = (left, right) else {
        return None;
    };
    let right = right.snapshot();
    Some(
        left.snapshot()
            .iter()
            .all(|a| right.iter().any(|b| json_equal(a, b))),
    )
}

fn overlap(left: Option<&Value>, right: Option<&Value>) -> Option<bool> {
    let (Some(Value::List(left)), Some(Value::List(right))) = (left, right) else {
        return None;
    };
    let right = right.snapshot();
    Some(
        left.snapshot()
            .iter()
            .any(|a| right.iter().any(|b| json_equal(a, b))),
    )
}

fn size_of(value: Option<&Value>) -> Option<i64> {
    let size = match value? {
        Value::List(list) => list.len(),
        Value::Str(text) => text.encode_utf16().count(),
        Value::Map(map) => map.len(),
        _ => return None,
    };
    i64::try_from(size).ok()
}

// ----- parsing -----

struct PathParser {
    chars: Vec<char>,
    pos: usize,
    depth: usize,
}

impl PathParser {
    fn new(source: &str) -> Self {
        Self {
            chars: source.chars().collect(),
            pos: 0,
            depth: 0,
        }
    }

    fn peek(&self) -> Option<char> {
        self.chars.get(self.pos).copied()
    }

    fn peek_at(&self, offset: usize) -> Option<char> {
        self.chars.get(self.pos.saturating_add(offset)).copied()
    }

    fn advance(&mut self) {
        self.pos = self.pos.saturating_add(1);
    }

    fn eat(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn eat_str(&mut self, text: &str) -> bool {
        if text
            .chars()
            .enumerate()
            .all(|(i, c)| self.peek_at(i) == Some(c))
        {
            self.pos = self.pos.saturating_add(text.chars().count());
            true
        } else {
            false
        }
    }

    fn skip_spaces(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.advance();
        }
    }

    fn fail<T>(&self, message: &str) -> Result<T, JsonPathError> {
        Err(JsonPathError::new(format!(
            "{message} at position {}",
            self.pos
        )))
    }

    fn expect(&mut self, c: char) -> Result<(), JsonPathError> {
        if self.eat(c) {
            Ok(())
        } else {
            self.fail(&format!("expected '{c}'"))
        }
    }

    /// Parses `$` or `@` followed by segments.
    fn parse_path(&mut self) -> Result<Vec<Segment>, JsonPathError> {
        if !(self.eat('$') || self.eat('@')) {
            return self.fail("a path must start with '$' or '@'");
        }
        self.parse_segments()
    }

    fn parse_segments(&mut self) -> Result<Vec<Segment>, JsonPathError> {
        let mut segments = Vec::new();
        loop {
            let scan = match (self.peek(), self.peek_at(1)) {
                (Some('.'), Some('.')) => {
                    self.pos = self.pos.saturating_add(2);
                    true
                }
                (Some('.'), _) => {
                    self.advance();
                    false
                }
                (Some('['), _) => false,
                _ => return Ok(segments),
            };
            let selector = self.parse_selector()?;
            segments.push(Segment { scan, selector });
        }
    }

    fn parse_selector(&mut self) -> Result<Selector, JsonPathError> {
        match self.peek() {
            Some('*') => {
                self.advance();
                Ok(Selector::Wildcard)
            }
            Some('[') => self.parse_bracket(),
            Some(_) => self.parse_name(),
            None => self.fail("a path cannot end with '.'"),
        }
    }

    fn parse_name(&mut self) -> Result<Selector, JsonPathError> {
        let mut name = String::new();
        while let Some(c) = self.peek() {
            if matches!(
                c,
                '.' | '[' | ' ' | '(' | ')' | ']' | '=' | '<' | '>' | '!' | '&' | '|' | ','
            ) {
                break;
            }
            name.push(c);
            self.advance();
        }
        if name.is_empty() {
            return self.fail("expected a property name");
        }
        if self.peek() == Some('(') {
            return self.parse_function(&name);
        }
        Ok(Selector::Child(vec![name]))
    }

    fn parse_function(&mut self, name: &str) -> Result<Selector, JsonPathError> {
        self.expect('(')?;
        let mut args = Vec::new();
        self.skip_spaces();
        if !self.eat(')') {
            loop {
                self.skip_spaces();
                args.push(self.parse_literal()?);
                self.skip_spaces();
                if self.eat(',') {
                    continue;
                }
                self.expect(')')?;
                break;
            }
        }
        let function = match name {
            "length" => Function::Length,
            "min" => Function::Min,
            "max" => Function::Max,
            "avg" => Function::Avg,
            "sum" => Function::Sum,
            "stddev" => Function::StdDev,
            "keys" => Function::Keys,
            "first" => Function::First,
            "last" => Function::Last,
            "index" => match args.first() {
                Some(Value::Int(index)) => Function::Index(*index),
                _ => return self.fail("index() takes an integer"),
            },
            "concat" => Function::Concat(args),
            "append" => Function::Append(args),
            other => return Err(JsonPathError::new(format!("unknown function {other}()"))),
        };
        Ok(Selector::Function(function))
    }

    fn parse_bracket(&mut self) -> Result<Selector, JsonPathError> {
        self.expect('[')?;
        self.skip_spaces();
        let selector = match self.peek() {
            Some('*') => {
                self.advance();
                Selector::Wildcard
            }
            Some('?') => {
                self.advance();
                self.skip_spaces();
                self.expect('(')?;
                let filter = self.parse_filter()?;
                self.skip_spaces();
                self.expect(')')?;
                Selector::Filter(filter)
            }
            Some('\'' | '"') => {
                let mut names = vec![self.parse_quoted()?];
                loop {
                    self.skip_spaces();
                    if self.eat(',') {
                        self.skip_spaces();
                        names.push(self.parse_quoted()?);
                    } else {
                        break;
                    }
                }
                Selector::Child(names)
            }
            _ => self.parse_index_or_slice()?,
        };
        self.skip_spaces();
        self.expect(']')?;
        Ok(selector)
    }

    fn parse_index_or_slice(&mut self) -> Result<Selector, JsonPathError> {
        let first = self.parse_optional_integer()?;
        self.skip_spaces();
        if self.eat(':') {
            self.skip_spaces();
            let second = self.parse_optional_integer()?;
            self.skip_spaces();
            if self.eat(':') {
                self.skip_spaces();
                self.parse_optional_integer()?;
            }
            return Ok(Selector::Slice(first, second));
        }
        let Some(first) = first else {
            return self.fail("expected an index");
        };
        let mut indexes = vec![first];
        loop {
            self.skip_spaces();
            if self.eat(',') {
                self.skip_spaces();
                let Some(next) = self.parse_optional_integer()? else {
                    return self.fail("expected an index");
                };
                indexes.push(next);
            } else {
                return Ok(Selector::Index(indexes));
            }
        }
    }

    fn parse_optional_integer(&mut self) -> Result<Option<i64>, JsonPathError> {
        let start = self.pos;
        self.eat('-');
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.advance();
        }
        let text: String = self
            .chars
            .get(start..self.pos)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        if text.is_empty() {
            return Ok(None);
        }
        text.parse::<i64>()
            .map(Some)
            .map_err(|_| JsonPathError::new(format!("invalid index {text}")))
    }

    fn parse_quoted(&mut self) -> Result<String, JsonPathError> {
        let Some(quote) = self.peek().filter(|c| *c == '\'' || *c == '"') else {
            return self.fail("expected a quoted string");
        };
        self.advance();
        let mut text = String::new();
        loop {
            match self.peek() {
                Some('\\') => {
                    self.advance();
                    match self.peek() {
                        Some('n') => text.push('\n'),
                        Some('t') => text.push('\t'),
                        Some('r') => text.push('\r'),
                        Some(c) => text.push(c),
                        None => return self.fail("unterminated string"),
                    }
                    self.advance();
                }
                Some(c) if c == quote => {
                    self.advance();
                    return Ok(text);
                }
                Some(c) => {
                    text.push(c);
                    self.advance();
                }
                None => return self.fail("unterminated string"),
            }
        }
    }

    // ----- filter expressions -----

    fn parse_filter(&mut self) -> Result<Filter, JsonPathError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            return self.fail("filter nests too deeply");
        }
        let result = self.parse_or();
        self.depth = self.depth.saturating_sub(1);
        result
    }

    fn parse_or(&mut self) -> Result<Filter, JsonPathError> {
        let mut left = self.parse_and()?;
        loop {
            self.skip_spaces();
            if self.eat_str("||") {
                let right = self.parse_and()?;
                left = Filter::Or(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_and(&mut self) -> Result<Filter, JsonPathError> {
        let mut left = self.parse_term()?;
        loop {
            self.skip_spaces();
            if self.eat_str("&&") {
                let right = self.parse_term()?;
                left = Filter::And(Box::new(left), Box::new(right));
            } else {
                return Ok(left);
            }
        }
    }

    fn parse_term(&mut self) -> Result<Filter, JsonPathError> {
        self.skip_spaces();
        if self.peek() == Some('!') && self.peek_at(1) != Some('=') {
            self.advance();
            self.depth = self.depth.saturating_add(1);
            if self.depth > MAX_DEPTH {
                return self.fail("filter nests too deeply");
            }
            let inner = self.parse_term();
            self.depth = self.depth.saturating_sub(1);
            return Ok(Filter::Not(Box::new(inner?)));
        }
        if self.peek() == Some('(') {
            self.advance();
            let inner = self.parse_filter()?;
            self.skip_spaces();
            self.expect(')')?;
            return Ok(inner);
        }
        let left = self.parse_operand()?;
        self.skip_spaces();
        let Some(op) = self.parse_operator() else {
            return Ok(Filter::Exists(left));
        };
        self.skip_spaces();
        let right = self.parse_operand()?;
        Ok(Filter::Compare(left, op, right))
    }

    fn parse_operator(&mut self) -> Option<CompareOp> {
        const SYMBOLS: [(&str, CompareOp); 8] = [
            ("==", CompareOp::Eq),
            ("!=", CompareOp::Ne),
            ("<>", CompareOp::Ne),
            ("<=", CompareOp::Le),
            (">=", CompareOp::Ge),
            ("=~", CompareOp::Regex),
            ("<", CompareOp::Lt),
            (">", CompareOp::Gt),
        ];
        const WORDS: [(&str, CompareOp); 8] = [
            ("nin", CompareOp::NotIn),
            ("in", CompareOp::In),
            ("subsetof", CompareOp::SubsetOf),
            ("anyof", CompareOp::AnyOf),
            ("noneof", CompareOp::NoneOf),
            ("size", CompareOp::Size),
            ("empty", CompareOp::Empty),
            ("contains", CompareOp::Contains),
        ];
        for (text, op) in SYMBOLS {
            if self.eat_str(text) {
                return Some(op);
            }
        }
        for (text, op) in WORDS {
            if self.word_ahead(text) {
                self.pos = self.pos.saturating_add(text.chars().count());
                return Some(op);
            }
        }
        None
    }

    fn word_ahead(&self, word: &str) -> bool {
        let matches_word = word
            .chars()
            .enumerate()
            .all(|(i, c)| self.peek_at(i) == Some(c));
        matches_word
            && self
                .peek_at(word.chars().count())
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
    }

    fn parse_operand(&mut self) -> Result<Operand, JsonPathError> {
        self.skip_spaces();
        match self.peek() {
            Some('@') => {
                self.advance();
                Ok(Operand::Path {
                    from_root: false,
                    segments: Segments(self.parse_segments()?),
                })
            }
            Some('$') => {
                self.advance();
                Ok(Operand::Path {
                    from_root: true,
                    segments: Segments(self.parse_segments()?),
                })
            }
            Some('/') => Ok(Operand::Regex(self.parse_regex_literal()?)),
            _ => Ok(Operand::Literal(self.parse_literal()?)),
        }
    }

    fn parse_regex_literal(&mut self) -> Result<String, JsonPathError> {
        self.expect('/')?;
        let mut pattern = String::new();
        loop {
            match self.peek() {
                Some('\\') if self.peek_at(1) == Some('/') => {
                    pattern.push('/');
                    self.pos = self.pos.saturating_add(2);
                }
                Some('/') => {
                    self.advance();
                    break;
                }
                Some(c) => {
                    pattern.push(c);
                    self.advance();
                }
                None => return self.fail("unterminated regular expression"),
            }
        }
        let mut flags = String::new();
        while let Some(c) = self
            .peek()
            .filter(|c| matches!(c, 'i' | 's' | 'm' | 'x' | 'u'))
        {
            flags.push(c);
            self.advance();
        }
        Ok(if flags.is_empty() {
            pattern
        } else {
            format!("(?{flags}){pattern}")
        })
    }

    fn parse_literal(&mut self) -> Result<Value, JsonPathError> {
        self.skip_spaces();
        match self.peek() {
            Some('\'' | '"') => Ok(Value::from(self.parse_quoted()?)),
            Some('[') => {
                self.advance();
                let mut items = Vec::new();
                self.skip_spaces();
                if !self.eat(']') {
                    loop {
                        items.push(self.parse_literal()?);
                        self.skip_spaces();
                        if self.eat(',') {
                            continue;
                        }
                        self.expect(']')?;
                        break;
                    }
                }
                Ok(Value::List(List::from_values(items)))
            }
            Some(c) if c == '-' || c.is_ascii_digit() => self.parse_number(),
            _ => {
                for (word, value) in [
                    ("true", Value::Bool(true)),
                    ("false", Value::Bool(false)),
                    ("null", Value::Null),
                ] {
                    if self.word_ahead(word) {
                        self.pos = self.pos.saturating_add(word.chars().count());
                        return Ok(value);
                    }
                }
                self.fail("expected a value")
            }
        }
    }

    fn parse_number(&mut self) -> Result<Value, JsonPathError> {
        let start = self.pos;
        self.eat('-');
        while self.peek().is_some_and(|c| c.is_ascii_digit()) {
            self.advance();
        }
        let mut is_float = false;
        if self.peek() == Some('.') && self.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
            is_float = true;
            self.advance();
            while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                self.advance();
            }
        }
        if self.peek().is_some_and(|c| c == 'e' || c == 'E') {
            let save = self.pos;
            self.advance();
            if self.peek().is_some_and(|c| c == '+' || c == '-') {
                self.advance();
            }
            if self.peek().is_some_and(|c| c.is_ascii_digit()) {
                is_float = true;
                while self.peek().is_some_and(|c| c.is_ascii_digit()) {
                    self.advance();
                }
            } else {
                self.pos = save;
            }
        }
        let text: String = self
            .chars
            .get(start..self.pos)
            .map(|s| s.iter().collect())
            .unwrap_or_default();
        if is_float {
            text.parse::<f64>()
                .map(Value::Double)
                .map_err(|_| JsonPathError::new(format!("invalid number {text}")))
        } else {
            text.parse::<i64>()
                .map(Value::Int)
                .map_err(|_| JsonPathError::new(format!("invalid number {text}")))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eval(path: &str, json: &str) -> String {
        let doc = Value::from_json(json).unwrap_or(Value::Null);
        match path.parse::<JsonPath>() {
            Ok(path) => match path.evaluate(&doc) {
                Ok(value) => value.to_json().unwrap_or_default(),
                Err(err) => format!("ERR {err}"),
            },
            Err(err) => format!("ERR {err}"),
        }
    }

    const STORE: &str = r#"{"store":{"book":[{"category":"reference","author":"Nigel Rees","price":8.95},{"category":"fiction","author":"Evelyn Waugh","price":12.99,"isbn":"0-553"},{"category":"fiction","author":"Herman Melville","price":8.99}],"bicycle":{"color":"red","price":19.95}},"expensive":10}"#;

    #[test]
    fn dot_and_bracket_notation() {
        assert_eq!(eval("$.store.bicycle.color", STORE), r#""red""#);
        assert_eq!(eval("$['store']['bicycle']['color']", STORE), r#""red""#);
        assert_eq!(eval("$.store.book[0].author", STORE), r#""Nigel Rees""#);
        assert_eq!(eval("$.store.book[-1].price", STORE), "8.99");
    }

    #[test]
    fn missing_paths_are_null_or_empty() {
        assert_eq!(eval("$.nothing", STORE), "null");
        assert_eq!(eval("$.store.nothing.deeper", STORE), "null");
        assert_eq!(eval("$.store.book[9]", STORE), "null");
        assert_eq!(eval("$.store.book[*].nothing", STORE), "[]");
        assert_eq!(eval("$..nothing", STORE), "[]");
    }

    #[test]
    fn wildcards_scans_and_slices() {
        assert_eq!(
            eval("$.store.book[*].author", STORE),
            r#"["Nigel Rees","Evelyn Waugh","Herman Melville"]"#
        );
        assert_eq!(eval("$..price", STORE), "[8.95,12.99,8.99,19.95]");
        assert_eq!(eval("$.store.book[0:2].price", STORE), "[8.95,12.99]");
        assert_eq!(eval("$.store.book[-2:].price", STORE), "[12.99,8.99]");
        assert_eq!(eval("$.store.book[:1].price", STORE), "[8.95]");
        assert_eq!(eval("$.store.book[0,2].price", STORE), "[8.95,8.99]");
    }

    #[test]
    fn filters() {
        assert_eq!(
            eval("$.store.book[?(@.price < 10)].price", STORE),
            "[8.95,8.99]"
        );
        assert_eq!(
            eval("$.store.book[?(@.isbn)].author", STORE),
            r#"["Evelyn Waugh"]"#
        );
        assert_eq!(
            eval(
                "$.store.book[?(@.category == 'fiction' && @.price > 10)].author",
                STORE
            ),
            r#"["Evelyn Waugh"]"#
        );
        assert_eq!(
            eval("$.store.book[?(@.author =~ /.*REES/i)].price", STORE),
            "[8.95]"
        );
        assert_eq!(
            eval("$.store.book[?(@.price < $.expensive)].price", STORE),
            "[8.95,8.99]"
        );
        assert_eq!(eval("$.store.book[?(!@.isbn)].price", STORE), "[8.95,8.99]");
    }

    #[test]
    fn functions() {
        assert_eq!(eval("$.store.book.length()", STORE), "3");
        assert_eq!(eval("$.n.max()", r#"{"n":[3,1,2]}"#), "3.0");
        assert_eq!(eval("$.n.sum()", r#"{"n":[3,1,2]}"#), "6.0");
        assert_eq!(eval("$.n.avg()", r#"{"n":[3,1,2]}"#), "2.0");
        assert_eq!(eval("$.n.first()", r#"{"n":[3,1,2]}"#), "3");
        assert_eq!(eval("$.n.last()", r#"{"n":[3,1,2]}"#), "2");
        assert_eq!(eval("$.n.index(-2)", r#"{"n":[3,1,2]}"#), "1");
        assert_eq!(eval("$.o.keys()", r#"{"o":{"b":1,"a":2}}"#), r#"["b","a"]"#);
    }

    #[test]
    fn functions_after_a_wildcard_run_once_per_match() {
        assert_eq!(
            eval("$.a[*].length()", r#"{"a":[[1,2],{"k":1},3]}"#),
            "[2,1,null]"
        );
        assert!(eval("$.a[*].max()", r#"{"a":[1,2]}"#).starts_with("ERR"));
    }

    #[test]
    fn aggregates_of_nothing_are_errors() {
        assert!(eval("$.n.max()", r#"{"n":[]}"#).starts_with("ERR"));
        assert!(eval("$.n.first()", r#"{"n":[]}"#).starts_with("ERR"));
    }

    #[test]
    fn functions_after_a_scan_are_not_supported() {
        assert!(eval("$..price.max()", STORE).starts_with("ERR"));
    }

    #[test]
    fn jayway_slice_oddities_are_reproduced() {
        let doc = r#"{"h":[1,2,3,4,5]}"#;
        assert_eq!(eval("$.h[1:-1]", doc), "[]");
        assert_eq!(eval("$.h[-2:5]", doc), "[4,5,1,2,3,4,5]");
        assert_eq!(eval("$.h[-3:-1]", doc), "[3,4]");
    }

    #[test]
    fn several_names_yield_one_map() {
        assert_eq!(
            eval("$['a','b']", r#"{"a":1,"b":2,"c":3}"#),
            r#"{"a":1,"b":2}"#
        );
        assert_eq!(eval("$['x','y']", r#"{"a":1}"#), "{}");
    }

    #[test]
    fn malformed_paths_are_errors() {
        assert!(eval("$.a[", "{}").starts_with("ERR"));
        assert!(eval("$.a[?(@.b ==)]", "{}").starts_with("ERR"));
    }
}
