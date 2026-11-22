//! The Java-like value model that templates compute with.
//!
//! API Gateway renders templates over Java objects: `String`, `Integer`, `Long`, `BigInteger`,
//! `Double`, `BigDecimal`, `Boolean`, `LinkedHashMap`, `ArrayList`, and `null`. [`Value`] models
//! those with the Java behaviors templates can observe: `toString` formatting, `equals`, reference
//! semantics for collections (a list or map assigned to two variables is one object), and
//! insertion-ordered maps whose keys can be any value.

use std::collections::HashSet;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use indexmap::{Equivalent, IndexMap};

use crate::ast;
use crate::json;
use crate::number::{BigDecimal, BigInt};

/// How deeply nested values may be when formatting or comparing them. A template can build a
/// collection that contains itself, which Java rejects with a stack overflow.
pub(crate) const MAX_VALUE_DEPTH: usize = 64;

/// A value nested deeper than 64 levels, usually a collection that contains itself.
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

    /// The address of the shared data, which identifies it.
    fn address(&self) -> usize {
        Arc::as_ptr(&self.0).addr()
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

    fn address(&self) -> usize {
        self.items.address()
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

/// A map key: any value, compared with Java's `equals` and hashed consistently with it.
#[derive(Clone)]
pub(crate) struct Key(pub(crate) Value);

/// Tags that keep keys of different Java classes apart when hashing.
mod tag {
    pub(super) const NULL: u8 = 0;
    pub(super) const BOOL: u8 = 1;
    pub(super) const INT: u8 = 2;
    pub(super) const LONG: u8 = 3;
    pub(super) const BIG_INT: u8 = 4;
    pub(super) const BIG_DECIMAL: u8 = 5;
    pub(super) const DOUBLE: u8 = 6;
    pub(super) const STR: u8 = 7;
    pub(super) const LIST: u8 = 8;
    pub(super) const MAP: u8 = 9;
    pub(super) const ENTRY: u8 = 10;
    pub(super) const OBJECT: u8 = 11;
}

impl Hash for Key {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match &self.0 {
            Value::Null => state.write_u8(tag::NULL),
            Value::Bool(value) => {
                state.write_u8(tag::BOOL);
                value.hash(state);
            }
            Value::Int(value) => {
                state.write_u8(tag::INT);
                value.hash(state);
            }
            Value::Long(value) => {
                state.write_u8(tag::LONG);
                value.hash(state);
            }
            Value::BigInt(value) => {
                state.write_u8(tag::BIG_INT);
                value.hash(state);
            }
            Value::BigDecimal(value) => {
                state.write_u8(tag::BIG_DECIMAL);
                value.hash(state);
            }
            Value::Double(value) => {
                state.write_u8(tag::DOUBLE);
                java_double_bits(*value).hash(state);
            }
            Value::Str(text) => StrKey(text).hash(state),
            // Collections compare by content, which can change after insertion, so they all
            // share one hash per kind and are told apart by `equals`.
            Value::List(_) => state.write_u8(tag::LIST),
            Value::Map(_) => state.write_u8(tag::MAP),
            Value::Entry(_) => state.write_u8(tag::ENTRY),
            Value::Input | Value::Util | Value::Loop(_) | Value::Block(_) => {
                state.write_u8(tag::OBJECT);
            }
        }
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        self.0.java_equals(&other.0)
    }
}

impl Eq for Key {}

/// A string key to look up without allocating a [`Key`].
struct StrKey<'a>(&'a str);

impl Hash for StrKey<'_> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        state.write_u8(tag::STR);
        self.0.hash(state);
    }
}

impl Equivalent<Key> for StrKey<'_> {
    fn equivalent(&self, key: &Key) -> bool {
        matches!(&key.0, Value::Str(text) if **text == *self.0)
    }
}

/// `Double.doubleToLongBits`, which `Double.equals` and `hashCode` use: every NaN is one value
/// and `-0.0` differs from `0.0`.
fn java_double_bits(value: f64) -> u64 {
    if value.is_nan() {
        0x7ff8_0000_0000_0000
    } else {
        value.to_bits()
    }
}

/// A Java `Map` with reference semantics and insertion order (a `LinkedHashMap`). Keys can be
/// any value and are compared with `equals`, so the key `1` differs from the key `'1'`.
#[derive(Clone)]
pub struct Map(Shared<IndexMap<Key, Value>>);

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

    /// The value stored under the string key `key`.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<Value> {
        self.0.lock().get(&StrKey(key)).cloned()
    }

    /// The value stored under `key`.
    #[must_use]
    pub fn get_value(&self, key: &Value) -> Option<Value> {
        match key {
            Value::Str(text) => self.get(text),
            other => self.0.lock().get(&Key(other.clone())).cloned(),
        }
    }

    /// Whether the string key `key` is present, even with a null value.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.lock().contains_key(&StrKey(key))
    }

    /// Whether `key` is present, even with a null value.
    #[must_use]
    pub fn contains_value_key(&self, key: &Value) -> bool {
        match key {
            Value::Str(text) => self.contains_key(text),
            other => self.0.lock().contains_key(&Key(other.clone())),
        }
    }

    /// Stores `value` under the string key `key`, returning the previous value. An existing key
    /// keeps its position, like `LinkedHashMap`.
    pub fn insert(&self, key: impl Into<Arc<str>>, value: Value) -> Option<Value> {
        self.insert_value(Value::Str(key.into()), value)
    }

    /// Stores `value` under `key`, returning the previous value.
    #[expect(
        clippy::must_use_candidate,
        reason = "storing is the point; the previous value is optional"
    )]
    pub fn insert_value(&self, key: Value, value: Value) -> Option<Value> {
        self.0.lock().insert(Key(key), value)
    }

    /// Removes the string key `key`, returning its value.
    #[must_use]
    pub fn remove(&self, key: &str) -> Option<Value> {
        self.0.lock().shift_remove(&StrKey(key))
    }

    /// Removes `key`, returning its value.
    #[must_use]
    pub fn remove_value(&self, key: &Value) -> Option<Value> {
        match key {
            Value::Str(text) => self.remove(text),
            other => self.0.lock().shift_remove(&Key(other.clone())),
        }
    }

    /// A copy of the entries in insertion order.
    #[must_use]
    pub fn entries(&self) -> Vec<(Value, Value)> {
        self.0
            .lock()
            .iter()
            .map(|(key, value)| (key.0.clone(), value.clone()))
            .collect()
    }

    /// Removes every entry.
    pub fn clear(&self) {
        self.0.lock().clear();
    }

    /// Whether both handles refer to the same map.
    #[must_use]
    pub fn same_as(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }

    fn address(&self) -> usize {
        self.0.address()
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
    pub key: Value,
    /// The entry's value.
    pub value: Value,
}

/// The `$foreach` variable of one loop iteration.
#[derive(Debug, Clone)]
pub struct LoopInfo {
    pub(crate) index: i32,
    pub(crate) count: i32,
    pub(crate) has_next: bool,
    pub(crate) parent: Option<Arc<Self>>,
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

/// The value a `#define` gives its reference: a block rendered each time it is used.
#[derive(Clone)]
pub struct BlockRef(pub(crate) Arc<ast::Block>);

impl BlockRef {
    /// The address of the block, which identifies one `#define` evaluation.
    pub(crate) fn address(&self) -> usize {
        Arc::as_ptr(&self.0).addr()
    }
}

impl fmt::Debug for BlockRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Block(..)")
    }
}

/// A value a template can compute with.
#[derive(Clone)]
pub enum Value {
    /// `null`.
    Null,
    /// A `Boolean`.
    Bool(bool),
    /// An `Integer`.
    Int(i32),
    /// A `Long`.
    Long(i64),
    /// A `BigInteger`.
    BigInt(Arc<BigInt>),
    /// A `Double`.
    Double(f64),
    /// A `BigDecimal`.
    BigDecimal(Arc<BigDecimal>),
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
    /// A `#define` block, which renders when used.
    Block(BlockRef),
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Null => f.write_str("Null"),
            Self::Bool(value) => write!(f, "Bool({value})"),
            Self::Int(value) => write!(f, "Int({value})"),
            Self::Long(value) => write!(f, "Long({value})"),
            Self::BigInt(value) => value.fmt(f),
            Self::Double(value) => write!(f, "Double({value})"),
            Self::BigDecimal(value) => value.fmt(f),
            Self::Str(value) => write!(f, "Str({value:?})"),
            Self::List(list) => list.fmt(f),
            Self::Map(map) => map.fmt(f),
            Self::Entry(entry) => write!(f, "Entry({:?})", entry.key),
            Self::Input => f.write_str("Input"),
            Self::Util => f.write_str("Util"),
            Self::Loop(_) => f.write_str("Loop"),
            Self::Block(block) => block.fmt(f),
        }
    }
}

/// How a `#define` block turns into text while formatting a value that holds one.
pub(crate) type BlockText<'a, E> = dyn FnMut(&BlockRef) -> Result<Option<String>, E> + 'a;

impl Value {
    /// A string value.
    #[must_use]
    pub fn string(text: impl Into<Arc<str>>) -> Self {
        Self::Str(text.into())
    }

    /// An integer with the narrowest Java type that holds it: `Integer`, else `Long`, as
    /// Velocity's literals and JSON numbers are typed.
    #[must_use]
    pub fn integer(value: i64) -> Self {
        i32::try_from(value).map_or(Self::Long(value), Self::Int)
    }

    /// An integer of any size: `Integer`, `Long`, or `BigInteger`.
    #[must_use]
    pub fn big_integer(value: BigInt) -> Self {
        value
            .to_i64()
            .map_or_else(|| Self::BigInt(Arc::new(value)), Self::integer)
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
            | Self::Long(_)
            | Self::BigInt(_)
            | Self::Double(_)
            | Self::BigDecimal(_)
            | Self::List(_)
            | Self::Map(_)
            | Self::Entry(_)
            | Self::Input
            | Self::Util
            | Self::Loop(_)
            | Self::Block(_) => None,
        }
    }

    /// The Java class name, as `getClass().getName()` would report it.
    #[must_use]
    pub const fn java_class(&self) -> &'static str {
        match self {
            Self::Null => "null",
            Self::Bool(_) => "java.lang.Boolean",
            Self::Int(_) => "java.lang.Integer",
            Self::Long(_) => "java.lang.Long",
            Self::BigInt(_) => "java.math.BigInteger",
            Self::Double(_) => "java.lang.Double",
            Self::BigDecimal(_) => "java.math.BigDecimal",
            Self::Str(_) => "java.lang.String",
            Self::List(_) => "java.util.ArrayList",
            Self::Map(_) => "java.util.LinkedHashMap",
            Self::Entry(_) => "java.util.Map$Entry",
            Self::Input => "com.amazonaws.apigateway.Input",
            Self::Util => "com.amazonaws.apigateway.Util",
            Self::Loop(_) => "org.apache.velocity.runtime.directive.ForeachScope",
            Self::Block(_) => "org.apache.velocity.runtime.directive.Block$Reference",
        }
    }

    /// Formats the value like Java's `toString`: `{k=v}` for maps, `[a, b]` for lists, and
    /// `1.0E10` for large doubles. A `#define` block, which needs a render to produce its
    /// text, formats as nothing here.
    ///
    /// # Errors
    ///
    /// Fails when the value contains itself or nests deeper than 64 levels.
    pub fn to_java_string(&self) -> Result<String, DepthExceeded> {
        let mut out = String::new();
        self.write_java(&mut out, 0, &mut |_| Ok(Some(String::new())))?;
        Ok(out)
    }

    pub(crate) fn write_java<E: From<DepthExceeded>>(
        &self,
        out: &mut String,
        depth: usize,
        block: &mut BlockText<'_, E>,
    ) -> Result<(), E> {
        if depth > MAX_VALUE_DEPTH {
            return Err(DepthExceeded.into());
        }
        let next = depth.saturating_add(1);
        match self {
            Self::Null => out.push_str("null"),
            Self::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Self::Int(value) => out.push_str(&value.to_string()),
            Self::Long(value) => out.push_str(&value.to_string()),
            Self::BigInt(value) => out.push_str(&value.to_string()),
            Self::Double(value) => out.push_str(&JavaDouble(*value).to_string()),
            Self::BigDecimal(value) => out.push_str(&value.to_string()),
            Self::Str(text) => out.push_str(text),
            Self::List(list) => {
                out.push('[');
                for (index, item) in list.snapshot().iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    item.write_java(out, next, block)?;
                }
                out.push(']');
            }
            Self::Map(map) => {
                out.push('{');
                for (index, (key, value)) in map.entries().iter().enumerate() {
                    if index > 0 {
                        out.push_str(", ");
                    }
                    key.write_java(out, next, block)?;
                    out.push('=');
                    value.write_java(out, next, block)?;
                }
                out.push('}');
            }
            Self::Entry(entry) => {
                entry.key.write_java(out, next, block)?;
                out.push('=');
                entry.value.write_java(out, next, block)?;
            }
            Self::Block(reference) => match block(reference)? {
                Some(text) => out.push_str(&text),
                None => out.push_str("null"),
            },
            Self::Input | Self::Util | Self::Loop(_) => out.push_str(self.java_class()),
        }
        Ok(())
    }

    /// Java's `Object.equals`: collections compare by content, numbers only equal numbers of the
    /// same class (an `Integer` never equals a `Long` or a `Double`), and doubles compare like
    /// `Double.equals`.
    #[must_use]
    pub fn java_equals(&self, other: &Self) -> bool {
        self.equals_at(other, 0)
    }

    fn equals_at(&self, other: &Self, depth: usize) -> bool {
        if depth > MAX_VALUE_DEPTH {
            return false;
        }
        let next = depth.saturating_add(1);
        match (self, other) {
            (Self::Null, Self::Null) | (Self::Input, Self::Input) | (Self::Util, Self::Util) => {
                true
            }
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Int(a), Self::Int(b)) => a == b,
            (Self::Long(a), Self::Long(b)) => a == b,
            (Self::BigInt(a), Self::BigInt(b)) => a == b,
            (Self::BigDecimal(a), Self::BigDecimal(b)) => a == b,
            (Self::Double(a), Self::Double(b)) => java_double_bits(*a) == java_double_bits(*b),
            (Self::Str(a), Self::Str(b)) => **a == **b,
            (Self::List(a), Self::List(b)) => {
                a.same_as(b) || {
                    let (left, right) = (a.snapshot(), b.snapshot());
                    left.len() == right.len()
                        && left.iter().zip(&right).all(|(x, y)| x.equals_at(y, next))
                }
            }
            (Self::Map(a), Self::Map(b)) => {
                a.same_as(b) || {
                    let (left, right) = (a.entries(), b.entries());
                    left.len() == right.len()
                        && left.iter().all(|(key, value)| {
                            right
                                .iter()
                                .find(|(other_key, _)| key.equals_at(other_key, next))
                                .is_some_and(|(_, other)| value.equals_at(other, next))
                        })
                }
            }
            (Self::Entry(a), Self::Entry(b)) => {
                a.key.equals_at(&b.key, next) && a.value.equals_at(&b.value, next)
            }
            (Self::Loop(a), Self::Loop(b)) => Arc::ptr_eq(a, b),
            (Self::Block(a), Self::Block(b)) => Arc::ptr_eq(&a.0, &b.0),
            (
                Self::Null
                | Self::Bool(_)
                | Self::Int(_)
                | Self::Long(_)
                | Self::BigInt(_)
                | Self::Double(_)
                | Self::BigDecimal(_)
                | Self::Str(_)
                | Self::List(_)
                | Self::Map(_)
                | Self::Entry(_)
                | Self::Input
                | Self::Util
                | Self::Loop(_)
                | Self::Block(_),
                _,
            ) => false,
        }
    }

    /// Whether `target` is this value or is reachable from it through lists and maps.
    ///
    /// Templates check this before storing a collection inside another, because a collection
    /// that contains itself can never be freed and has no Java `toString`. The second result
    /// is the number of collections visited, for charging against the step budget.
    pub(crate) fn reaches(&self, target: &Self) -> (bool, usize) {
        let mut seen = HashSet::new();
        let mut stack = vec![self.clone()];
        while let Some(value) = stack.pop() {
            let address = match &value {
                Self::List(list) => list.address(),
                Self::Map(map) => map.address(),
                _ => continue,
            };
            if !seen.insert(address) {
                continue;
            }
            let found = match (&value, target) {
                (Self::List(a), Self::List(b)) => a.same_as(b),
                (Self::Map(a), Self::Map(b)) => a.same_as(b),
                _ => false,
            };
            if found {
                return (true, seen.len());
            }
            match &value {
                Self::List(list) => stack.extend(list.snapshot()),
                Self::Map(map) => {
                    for (key, value) in map.entries() {
                        stack.push(key);
                        stack.push(value);
                    }
                }
                _ => {}
            }
        }
        (false, seen.len())
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

impl From<i32> for Value {
    fn from(value: i32) -> Self {
        Self::Int(value)
    }
}

impl From<i64> for Value {
    /// An `Integer` when the value fits, else a `Long`.
    fn from(value: i64) -> Self {
        Self::integer(value)
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

impl From<Vec<Self>> for Value {
    fn from(values: Vec<Self>) -> Self {
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

impl From<Option<Self>> for Value {
    fn from(value: Option<Self>) -> Self {
        value.unwrap_or(Self::Null)
    }
}

impl From<&serde_json::Value> for Value {
    /// Converts parsed JSON: object order is preserved, integers become `Integer`, `Long`, or
    /// `BigInteger` by size, and other numbers become `Double`.
    fn from(json: &serde_json::Value) -> Self {
        match json {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(value) => Self::Bool(*value),
            serde_json::Value::Number(number) => number
                .as_i64()
                .map(Self::integer)
                .or_else(|| {
                    number
                        .as_u64()
                        .map(|value| Self::big_integer(BigInt::from_u64(value)))
                })
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
    /// Parses a JSON document into a value, typing numbers as Jayway's json-smart provider
    /// does: integers as `Integer`, `Long`, or `BigInteger` by size, and other numbers as
    /// `Double`, or as `BigDecimal` when written with more than 18 characters.
    ///
    /// # Errors
    ///
    /// Returns a description of the problem for malformed JSON.
    pub fn from_json(text: &str) -> Result<Self, String> {
        json::parse_document(text)
    }

    /// Serializes the value as compact JSON, with string escaping limited to what JSON
    /// requires.
    ///
    /// # Errors
    ///
    /// Fails when the value nests deeper than 64 levels.
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
                    write_json_string(out, &key.to_java_string()?);
                    out.push(':');
                    value.write_json(out, depth.saturating_add(1))?;
                }
                out.push('}');
            }
            Self::Bool(_)
            | Self::Int(_)
            | Self::Long(_)
            | Self::BigInt(_)
            | Self::Double(_)
            | Self::BigDecimal(_) => out.push_str(&self.to_java_string()?),
            Self::Entry(_) | Self::Input | Self::Util | Self::Loop(_) | Self::Block(_) => {
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
            c if c < '\u{20}' => push_formatted(out, format_args!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Appends formatted text; `String` formatting cannot fail.
pub(crate) fn push_formatted(out: &mut String, args: fmt::Arguments<'_>) {
    out.push_str(&fmt::format(args));
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
            return f.write_str(if value.is_sign_negative() {
                "-0.0"
            } else {
                "0.0"
            });
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
        map.insert_value(Value::Int(2), Value::Bool(true));
        assert_eq!(Value::Map(map).to_string(), "{a=1, b=[x, null], 2=true}");
    }

    #[test]
    fn map_keys_compare_like_java() {
        let map = Map::new();
        map.insert_value(Value::Int(1), Value::from("int"));
        map.insert("1", Value::from("string"));
        map.insert_value(Value::Long(1), Value::from("long"));
        map.insert_value(Value::Double(f64::NAN), Value::from("nan"));
        map.insert_value(Value::Null, Value::from("null"));
        assert_eq!(map.len(), 5);
        assert_eq!(
            map.get("1").map(|v| v.to_string()),
            Some("string".to_owned())
        );
        assert_eq!(
            map.get_value(&Value::Int(1)).map(|v| v.to_string()),
            Some("int".to_owned())
        );
        assert_eq!(
            map.get_value(&Value::Double(f64::NAN))
                .map(|v| v.to_string()),
            Some("nan".to_owned())
        );
        assert!(map.contains_value_key(&Value::Null));
        assert!(!map.contains_value_key(&Value::Double(1.0)));
        let list_key = Value::from(vec![Value::Int(1)]);
        map.insert_value(list_key, Value::from("list"));
        assert!(map.contains_value_key(&Value::from(vec![Value::Int(1)])));
        assert_eq!(
            map.remove_value(&Value::Long(1)).map(|v| v.to_string()),
            Some("long".to_owned())
        );
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
        assert!(!Value::Int(1).java_equals(&Value::Long(1)));
        assert!(!Value::Int(1).java_equals(&Value::Double(1.0)));
        assert!(Value::Double(f64::NAN).java_equals(&Value::Double(f64::NAN)));
        assert!(!Value::Double(0.0).java_equals(&Value::Double(-0.0)));
        assert!(Value::from(vec![Value::Int(1)]).java_equals(&Value::from(vec![Value::Int(1)])));
    }

    #[test]
    fn json_round_trip_preserves_order_and_types() {
        let value = Value::from_json(r#"{"z":1,"a":[1.5,"x",null,true]}"#).unwrap_or(Value::Null);
        assert_eq!(
            value.to_json().unwrap_or_default(),
            r#"{"z":1,"a":[1.5,"x",null,true]}"#
        );
    }
}
