//! The Java-like value model that templates compute with.
//!
//! API Gateway renders templates over Java objects: `String`, `Integer`/`Long`, `Double`,
//! `Boolean`, `LinkedHashMap`, `ArrayList`, and `null`. [`Value`] models those with the Java
//! behaviors templates can observe: `toString` formatting, reference semantics for collections
//! (a list or map assigned to two variables is one object), and insertion-ordered maps.

use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use indexmap::IndexMap;

/// How deeply nested values may be when formatting or comparing them. A template can build a
/// collection that contains itself, which Java rejects with a stack overflow.
pub(crate) const MAX_VALUE_DEPTH: usize = 64;

/// A value nested deeper than [`MAX_VALUE_DEPTH`], usually a collection that contains itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepthExceeded;

impl fmt::Display for DepthExceeded {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "value nests more than {MAX_VALUE_DEPTH} levels deep")
    }
}

impl std::error::Error for DepthExceeded {}

/// A shared, mutable handle: clones refer to the same underlying data, like a Java reference.
struct Shared<T>(Arc<Mutex<T>>);

impl<T> Shared<T> {
    fn new(value: T) -> Self {
        Self(Arc::new(Mutex::new(value)))
    }

    /// Locks the data. A panic while the lock was held cannot corrupt a plain `Vec` or map, so
    /// a poisoned lock is recovered rather than propagated.
    fn lock(&self) -> MutexGuard<'_, T> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl<T> Clone for Shared<T> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

/// A Java `List` with reference semantics.
#[derive(Clone)]
pub struct List {
    items: Shared<Vec<Value>>,
    /// Whether elements can be reached by position. A `Set` or other `Collection`, such as
    /// `Map.keySet()`, holds its elements the same way but has no `get(int)` or `[i]`.
    indexed: bool,
}

impl List {
    /// Creates an empty list.
    #[must_use]
    pub fn new() -> Self {
        Self::from_values(Vec::new())
    }

    /// Creates a list holding `values`.
    #[must_use]
    pub fn from_values(values: Vec<Value>) -> Self {
        Self {
            items: Shared::new(values),
            indexed: true,
        }
    }

    /// Creates a collection that is not a list: it can be iterated and queried, but its
    /// elements cannot be reached by position.
    #[must_use]
    pub fn collection(values: Vec<Value>) -> Self {
        Self {
            items: Shared::new(values),
            indexed: false,
        }
    }

    /// Whether elements can be reached by position.
    #[must_use]
    pub const fn is_indexed(&self) -> bool {
        self.indexed
    }

    /// Number of elements.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.lock().len()
    }

    /// Whether the list has no elements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.lock().is_empty()
    }

    /// The element at `index`.
    #[must_use]
    pub fn get(&self, index: usize) -> Option<Value> {
        self.items.lock().get(index).cloned()
    }

    /// Appends an element.
    pub fn push(&self, value: Value) {
        self.items.lock().push(value);
    }

    /// A copy of the elements, safe to iterate while the list is modified.
    #[must_use]
    pub fn snapshot(&self) -> Vec<Value> {
        self.items.lock().clone()
    }

    /// Runs `f` with exclusive access to the elements.
    pub fn with<R>(&self, f: impl FnOnce(&mut Vec<Value>) -> R) -> R {
        f(&mut self.items.lock())
    }

    /// Whether both handles refer to the same list.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.items.ptr_eq(&other.items)
    }
}

impl Default for List {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for List {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("List(..)")
    }
}

impl From<Vec<Value>> for List {
    fn from(values: Vec<Value>) -> Self {
        Self::from_values(values)
    }
}

/// A Java `Map` with string keys, reference semantics, and insertion order.
///
/// Java templates can use any object as a key; keys here are strings, so a non-string key is
/// converted with Java's `toString`.
#[derive(Clone)]
pub struct Map(Shared<IndexMap<Arc<str>, Value>>);

impl Map {
    /// Creates an empty map.
    #[must_use]
    pub fn new() -> Self {
        Self(Shared::new(IndexMap::new()))
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    /// Whether the map has no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.lock().is_empty()
    }

    /// The value stored under `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Value> {
        self.0.lock().get(key).cloned()
    }

    /// Whether `key` is present, even with a null value.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.lock().contains_key(key)
    }

    /// Stores `value` under `key`, returning the previous value. An existing key keeps its
    /// position, like `LinkedHashMap`.
    pub fn insert(&self, key: impl Into<Arc<str>>, value: Value) -> Option<Value> {
        self.0.lock().insert(key.into(), value)
    }

    /// Removes `key`, returning its value.
    pub fn remove(&self, key: &str) -> Option<Value> {
        self.0.lock().shift_remove(key)
    }

    /// A copy of the entries in insertion order.
    #[must_use]
    pub fn entries(&self) -> Vec<(Arc<str>, Value)> {
        self.0
            .lock()
            .iter()
            .map(|(key, value)| (Arc::clone(key), value.clone()))
            .collect()
    }

    /// Runs `f` with exclusive access to the entries.
    pub fn with<R>(&self, f: impl FnOnce(&mut IndexMap<Arc<str>, Value>) -> R) -> R {
        f(&mut self.0.lock())
    }

    /// Whether both handles refer to the same map.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl Default for Map {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Map {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Map(..)")
    }
}

impl<K: Into<Arc<str>>> FromIterator<(K, Value)> for Map {
    fn from_iter<I: IntoIterator<Item = (K, Value)>>(iter: I) -> Self {
        let map = Self::new();
        for (key, value) in iter {
            map.insert(key, value);
        }
        map
    }
}

/// A `Map.Entry`, produced by iterating `entrySet()`.
#[derive(Debug, Clone, PartialEq)]
pub struct MapEntry {
    /// The entry's key.
    pub key: Arc<str>,
    /// The entry's value.
    pub value: Value,
}

/// The `$foreach` variable of one loop iteration.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub(crate) index: i64,
    pub(crate) count: i64,
    pub(crate) has_next: bool,
    pub(crate) parent: Option<Arc<LoopInfo>>,
}

impl LoopInfo {
    pub(crate) fn topmost(self: &Arc<Self>) -> Arc<Self> {
        let mut current = Arc::clone(self);
        while let Some(parent) = current.parent.clone() {
            current = parent;
        }
        current
    }
}

/// A value a template can compute with.
#[derive(Clone)]
pub enum Value {
    /// `null`.
    Null,
    /// A `Boolean`.
    Bool(bool),
    /// An `Integer` or `Long`.
    Int(i64),
    /// A `Double`.
    Double(f64),
    /// A `String`.
    Str(Arc<str>),
    /// A `List`.
    List(List),
    /// A `Map`.
    Map(Map),
    /// A `Map.Entry`.
    Entry(Arc<MapEntry>),
    /// The `$input` object.
    Input,
    /// The `$util` object.
    Util,
    /// The `$foreach` object.
    Loop(Arc<LoopInfo>),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(value) => write!(f, "Bool({value})"),
            Self::Int(value) => write!(f, "Int({value})"),
            Self::Double(value) => write!(f, "Double({value})"),
            Self::Str(value) => write!(f, "Str({value:?})"),
            Self::List(list) => list.fmt(f),
            Self::Map(map) => map.fmt(f),
            Self::Entry(entry) => write!(f, "Entry({:?})", entry.key),
            Self::Input => f.write_str("Input"),
            Self::Util => f.write_str("Util"),
            Self::Loop(_) => f.write_str("Loop"),
        }
    }
}

impl Value {
    /// A string value.
    #[must_use]
    pub fn string(text: impl Into<Arc<str>>) -> Self {
        Self::Str(text.into())
    }

    /// Whether the value is `null`.
    #[must_use]
    pub const fn is_null(&self) -> bool {
        matches!(self, Self::Null)
    }

    /// The string content of a string value.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(text) => Some(text),
            Self::Null
            | Self::Bool(_)
            | Self::Int(_)
            | Self::Double(_)
            | Self::List(_)
            | Self::Map(_)
            | Self::Entry(_)
            | Self::Input
            | Self::Util
            | Self::Loop(_) => None,
        }
    }

    /// The Java class name, as `getClass().getName()` would report it.
    #[must_use]
    pub const fn java_class(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "java.lang.Boolean",
            Self::Int(_) => "java.lang.Long",
            Self::Double(_) => "java.lang.Double",
            Self::Str(_) => "java.lang.String",
            Self::List(_) => "java.util.ArrayList",
            Self::Map(_) => "java.util.LinkedHashMap",
            Self::Entry(_) => "java.util.Map$Entry",
            Self::Input => "com.amazonaws.apigateway.Input",
            Self::Util => "com.amazonaws.apigateway.Util",
            Self::Loop(_) => "org.apache.velocity.runtime.directive.ForeachScope",
        }
    }

    /// Formats the value like Java's `toString`: `{k=v}` for maps, `[a, b]` for lists, and
    /// `1.0E10` for large doubles.
    ///
    /// # Errors
    ///
    /// Fails when the value contains itself or nests deeper than [`MAX_VALUE_DEPTH`].
    pub fn to_java_string(&self) -> Result<String, DepthExceeded> {
        let mut out = String::new();
        self.write_java(&mut out, 0)?;
        Ok(out)
    }

    pub(crate) fn write_java(&self, out: &mut String, depth: usize) -> Result<(), DepthExceeded> {
        if depth > MAX_VALUE_DEPTH {
            return Err(DepthExceeded);
        }
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Int(value) => out.push_str(&value.to_string()),
            Self::Double(value) => out.push_str(&JavaDouble(*value).to_string()),
            Self::Str(text) => out.push_str(text),
            Self::List(list) => {
                out.push('[');
                for (index, item) in list.snapshot().iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    item.write_java(out, depth.saturating_add(1))?;
                }
                out.push(']');
            }
            Self::Map(map) => {
                out.push('{');
                for (index, (key, value)) in map.entries().iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    out.push_str(key);
                    out.push('=');
                    value.write_java(out, depth.saturating_add(1))?;
                }
                out.push('}');
            }
            Self::Entry(entry) => {
                out.push_str(&entry.key);
                out.push('=');
                entry.value.write_java(out, depth.saturating_add(1))?;
            }
            Self::Input | Self::Util | Self::Loop(_) => out.push_str(self.java_class()),
        }
        Ok(())
    }

    /// Java's `Object.equals`: collections compare by content and an `Integer` never equals a
    /// `Double`.
    #[must_use]
    pub fn java_equals(&self, other: &Self) -> bool {
        self.equals_at(other, 0)
    }

    fn equals_at(&self, other: &Self, depth: usize) -> bool {
        if depth > MAX_VALUE_DEPTH {
            return false;
        }
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Double(a), Self::Double(b)) => a.to_bits() == b.to_bits() || a == b,
            (Self::Str(a), Self::Str(b)) => a == b,
            (Self::List(a), Self::List(b)) => {
                a.same_as(b) || {
                    let (left, right) = (a.snapshot(), b.snapshot());
                    left.len() == right.len()
                        && left
                            .iter()
                            .zip(&right)
                            .all(|(x, y)| x.equals_at(y, depth.saturating_add(1)))
                }
            }
            (Self::Map(a), Self::Map(b)) => {
                a.same_as(b) || {
                    let (left, right) = (a.entries(), b.entries());
                    left.len() == right.len()
                        && left.iter().all(|(key, value)| {
                            right
                                .iter()
                                .find(|(other_key, _)| other_key == key)
                                .is_some_and(|(_, other)| {
                                    value.equals_at(other, depth.saturating_add(1))
                                })
                        })
                }
            }
            (Self::Entry(a), Self::Entry(b)) => {
                a.key == b.key && a.value.equals_at(&b.value, depth.saturating_add(1))
            }
            (Self::Input, Self::Input) | (Self::Util, Self::Util) => true,
            (Self::Loop(a), Self::Loop(b)) => Arc::ptr_eq(a, b),
            (
                Self::Null
                | Self::Bool(_)
                | Self::Int(_)
                | Self::Double(_)
                | Self::Str(_)
                | Self::List(_)
                | Self::Map(_)
                | Self::Entry(_)
                | Self::Input
                | Self::Util
                | Self::Loop(_),
                _,
            ) => false,
        }
    }
}

impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        self.java_equals(other)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = self.to_java_string().map_err(|_| fmt::Error)?;
        f.write_str(&text)
    }
}

impl From<bool> for Value {
    fn from(value: bool) -> Self {
        Self::Bool(value)
    }
}

impl From<i64> for Value {
    fn from(value: i64) -> Self {
        Self::Int(value)
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Double(value)
    }
}

impl From<&str> for Value {
    fn from(value: &str) -> Self {
        Self::Str(value.into())
    }
}

impl From<String> for Value {
    fn from(value: String) -> Self {
        Self::Str(value.into())
    }
}

impl From<Vec<Value>> for Value {
    fn from(values: Vec<Value>) -> Self {
        Self::List(List::from_values(values))
    }
}

impl From<List> for Value {
    fn from(list: List) -> Self {
        Self::List(list)
    }
}

impl From<Map> for Value {
    fn from(map: Map) -> Self {
        Self::Map(map)
    }
}

impl From<Option<Value>> for Value {
    fn from(value: Option<Value>) -> Self {
        value.unwrap_or(Self::Null)
    }
}

impl From<&serde_json::Value> for Value {
    /// Converts parsed JSON the way Jayway's JSON provider does: object order is preserved,
    /// integers become `Int`, and other numbers become `Double`.
    fn from(json: &serde_json::Value) -> Self {
        match json {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(value) => Self::Bool(*value),
            serde_json::Value::Number(number) => number
                .as_i64()
                .map(Self::Int)
                .or_else(|| number.as_f64().map(Self::Double))
                .unwrap_or(Self::Null),
            serde_json::Value::String(text) => Self::Str(text.as_str().into()),
            serde_json::Value::Array(items) => {
                Self::List(List::from_values(items.iter().map(Self::from).collect()))
            }
            serde_json::Value::Object(object) => Self::Map(
                object
                    .iter()
                    .map(|(key, value)| (key.as_str(), Self::from(value)))
                    .collect(),
            ),
        }
    }
}

impl Value {
    /// Parses a JSON document into a value.
    ///
    /// # Errors
    ///
    /// Returns the parser's error for malformed JSON.
    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        let json: serde_json::Value = serde_json::from_str(text)?;
        Ok(Self::from(&json))
    }

    /// Serializes the value as compact JSON, with string escaping limited to what JSON
    /// requires.
    ///
    /// # Errors
    ///
    /// Fails when the value nests deeper than [`MAX_VALUE_DEPTH`].
    pub fn to_json(&self) -> Result<String, DepthExceeded> {
        let mut out = String::new();
        self.write_json(&mut out, 0)?;
        Ok(out)
    }

    fn write_json(&self, out: &mut String, depth: usize) -> Result<(), DepthExceeded> {
        if depth > MAX_VALUE_DEPTH {
            return Err(DepthExceeded);
        }
        match self {
            Self::Null => out.push_str("null"),
            Self::Str(text) => write_json_string(out, text),
            Self::List(list) => {
                out.push('[');
                for (index, item) in list.snapshot().iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write_json(out, depth.saturating_add(1))?;
                }
                out.push(']');
            }
            Self::Map(map) => {
                out.push('{');
                for (index, (key, value)) in map.entries().iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_json_string(out, key);
                    out.push(':');
                    value.write_json(out, depth.saturating_add(1))?;
                }
                out.push('}');
            }
            Self::Bool(_) | Self::Int(_) | Self::Double(_) => self.write_java(out, depth)?,
            Self::Entry(_) | Self::Input | Self::Util | Self::Loop(_) => {
                write_json_string(out, &self.to_java_string()?);
            }
        }
        Ok(())
    }
}

fn write_json_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{C}' => out.push_str("\\f"),
            c if c < '\u{20}' => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// A `double` formatted like `Double.toString`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct JavaDouble(pub(crate) f64);

impl fmt::Display for JavaDouble {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0;
        if value.is_nan() {
            return f.write_str("NaN");
        }
        if value.is_infinite() {
            return f.write_str(if value > 0.0 { "Infinity" } else { "-Infinity" });
        }
        if value == 0.0 {
            return f.write_str(if value.is_sign_negative() { "-0.0" } else { "0.0" });
        }
        let scientific = format!("{:e}", value.abs());
        let Some((mantissa, exponent)) = scientific.split_once('e') else {
            return f.write_str(&scientific);
        };
        let exponent: i32 = exponent.parse().unwrap_or(0);
        let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
        if value.is_sign_negative() {
            f.write_str("-")?;
        }
        if (-3..7).contains(&exponent) {
            write_decimal(f, &digits, exponent)
        } else {
            write_scientific(f, &digits, exponent)
        }
    }
}

/// Writes `digits` with the decimal point placed after `exponent + 1` digits.
fn write_decimal(f: &mut fmt::Formatter<'_>, digits: &str, exponent: i32) -> fmt::Result {
    if exponent < 0 {
        let zeros = usize::try_from(exponent.unsigned_abs().saturating_sub(1)).unwrap_or(0);
        return write!(f, "0.{}{digits}", "0".repeat(zeros));
    }
    let integer_len = usize::try_from(exponent).unwrap_or(0).saturating_add(1);
    if digits.len() <= integer_len {
        let zeros = integer_len.saturating_sub(digits.len());
        write!(f, "{digits}{}.0", "0".repeat(zeros))
    } else {
        let (integer, fraction) = digits.split_at(integer_len);
        write!(f, "{integer}.{fraction}")
    }
}

fn write_scientific(f: &mut fmt::Formatter<'_>, digits: &str, exponent: i32) -> fmt::Result {
    let (head, tail) = digits.split_at(1);
    let tail = if tail.is_empty() { "0" } else { tail };
    write!(f, "{head}.{tail}E{exponent}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn double(value: f64) -> String {
        JavaDouble(value).to_string()
    }

    #[test]
    fn doubles_format_like_java() {
        assert_eq!(double(1.0), "1.0");
        assert_eq!(double(100.0), "100.0");
        assert_eq!(double(1.0e7), "1.0E7");
        assert_eq!(double(12_345_678.9), "1.23456789E7");
        assert_eq!(double(9_999_999.0), "9999999.0");
        assert_eq!(double(0.001), "0.001");
        assert_eq!(double(0.0001), "1.0E-4");
        assert_eq!(double(-0.0), "-0.0");
        assert_eq!(double(1.5e-7), "1.5E-7");
        assert_eq!(double(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(double(-2.5), "-2.5");
        assert_eq!(double(f64::NAN), "NaN");
        assert_eq!(double(f64::NEG_INFINITY), "-Infinity");
        assert_eq!(double(123_456_789_012.0), "1.23456789012E11");
    }

    #[test]
    fn collections_format_like_java() {
        let map = Map::new();
        map.insert("a", Value::Int(1));
        map.insert("b", Value::from(vec![Value::from("x"), Value::Null]));
        assert_eq!(Value::Map(map).to_string(), "{a=1, b=[x, null]}");
    }

    #[test]
    fn self_containing_list_is_rejected() {
        let list = List::new();
        list.push(Value::List(list.clone()));
        assert_eq!(Value::List(list).to_java_string(), Err(DepthExceeded));
    }

    #[test]
    fn equality_follows_java_equals() {
        assert!(Value::Int(1).java_equals(&Value::Int(1)));
        assert!(!Value::Int(1).java_equals(&Value::Double(1.0)));
        assert!(Value::from(vec![Value::Int(1)]).java_equals(&Value::from(vec![Value::Int(1)])));
    }

    #[test]
    fn json_round_trip_preserves_order_and_types() {
        let value = Value::from_json(r#"{"z":1,"a":[1.5,"x",null,true]}"#).unwrap_or(Value::Null);
        assert_eq!(value.to_json().unwrap_or_default(), r#"{"z":1,"a":[1.5,"x",null,true]}"#);
    }
}
