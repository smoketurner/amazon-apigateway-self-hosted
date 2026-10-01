//! Method calls on templates' values: the `String`, `List`, `Map`, and number methods that
//! templates use, plus `$input` and `$util`.
//!
//! A call that matches no method returns `None`, which renders the reference as written, as
//! Velocity does for an unresolved method. A method that throws returns an error.

use std::sync::Arc;

use apigw_regex::{JavaRegex, Replacement};

use crate::error::RenderError;
use crate::eval::Interpreter;
use crate::jsonpath::{JsonPath, JsonPathError};
use crate::ops::int_to_f64;
use crate::util;
use crate::value::{List, Map, MapEntry, Value};

/// Regexes kept per render so that a pattern used in a loop compiles once.
const REGEX_CACHE_SIZE: usize = 64;

type MethodResult = Result<Option<Value>, RenderError>;

fn fail(method: &str, message: impl Into<String>) -> RenderError {
    RenderError::Method {
        method: method.to_owned(),
        message: message.into(),
    }
}

#[expect(
    clippy::unnecessary_wraps,
    reason = "the dispatch tables return MethodResult from every arm"
)]
fn ok(value: impl Into<Value>) -> MethodResult {
    Ok(Some(value.into()))
}

/// What a `void` Java method evaluates to in Velocity.
#[expect(
    clippy::unnecessary_wraps,
    reason = "the dispatch tables return MethodResult from every arm"
)]
fn void() -> MethodResult {
    Ok(Some(Value::from("")))
}

fn int(value: usize) -> Value {
    Value::Int(i64::try_from(value).unwrap_or(i64::MAX))
}

impl Interpreter<'_> {
    /// Calls `name` on `target`, or returns `None` when no such method exists.
    pub(crate) fn call_method(
        &mut self,
        target: &Value,
        name: &str,
        args: &[Value],
    ) -> MethodResult {
        if matches!(target, Value::List(_) | Value::Map(_))
            && matches!(
                name,
                "add" | "addAll" | "set" | "put" | "putIfAbsent" | "putAll"
            )
        {
            for arg in args {
                self.check_acyclic(target, arg)?;
            }
        }
        match target {
            Value::Str(text) => self.string_method(text, name, args),
            Value::List(list) => {
                self.charge_for_size(list.len().saturating_mul(16))?;
                Self::list_method(list, name, args)
            }
            Value::Map(map) => {
                self.charge_for_size(map.len().saturating_mul(16))?;
                Self::map_method(map, name, args)
            }
            Value::Entry(entry) => Self::entry_method(entry, name, args),
            Value::Int(_) | Value::Double(_) | Value::Bool(_) => {
                Self::scalar_method(target, name, args)
            }
            Value::Input => self.input_method(name, args),
            Value::Util => util::call(name, args),
            Value::Null | Value::Loop(_) => Ok(None),
        }
    }

    /// Charges one step per kilobyte a method has to process, so that a template cannot run
    /// string or collection methods over a large input an unbounded number of times.
    fn charge_for_size(&mut self, size: usize) -> Result<(), RenderError> {
        self.charge(u64::try_from(size >> 10).unwrap_or(u64::MAX))
    }

    /// Fails when storing `item` in `container` would make a collection contain itself.
    pub(crate) fn check_acyclic(
        &mut self,
        container: &Value,
        item: &Value,
    ) -> Result<(), RenderError> {
        if !matches!(item, Value::List(_) | Value::Map(_)) {
            return Ok(());
        }
        let (cyclic, visited) = item.reaches(container);
        self.charge(u64::try_from(visited).unwrap_or(u64::MAX))?;
        if cyclic {
            Err(RenderError::CircularReference)
        } else {
            Ok(())
        }
    }

    fn compiled(&mut self, method: &str, pattern: &str) -> Result<Arc<JavaRegex>, RenderError> {
        if let Some((_, regex)) = self
            .regex_cache
            .iter()
            .find(|(source, _)| source == pattern)
        {
            return Ok(Arc::clone(regex));
        }
        let regex = Arc::new(JavaRegex::new(pattern).map_err(|err| fail(method, err.to_string()))?);
        if self.regex_cache.len() >= REGEX_CACHE_SIZE {
            self.regex_cache.remove(0);
        }
        self.regex_cache
            .push((pattern.to_owned(), Arc::clone(&regex)));
        Ok(regex)
    }

    // ----- String -----

    fn string_method(&mut self, text: &Arc<str>, name: &str, args: &[Value]) -> MethodResult {
        self.charge_for_size(text.len())?;
        let units: Vec<u16> = text.encode_utf16().collect();
        if args.iter().any(Value::is_null)
            && !matches!(name, "equals" | "equalsIgnoreCase" | "contentEquals")
        {
            return if string_method_arity(name).is_some_and(|counts| counts.contains(&args.len())) {
                Err(fail(name, "null argument"))
            } else {
                Ok(None)
            };
        }
        if let Some(value) = Self::string_inspect(text, &units, name, args)? {
            return Ok(Some(value));
        }
        if let Some(value) = Self::string_compare(text, &units, name, args)? {
            return Ok(Some(value));
        }
        self.string_regex(text, name, args)
    }

    /// Length, characters, substrings, searching, and case conversion.
    fn string_inspect(text: &Arc<str>, units: &[u16], name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("length", []) => ok(int(units.len())),
            ("isEmpty", []) => ok(text.is_empty()),
            ("toString" | "intern" | "toLowerCase" | "toUpperCase" | "trim", []) => {
                ok(match name {
                    "toLowerCase" => text.to_lowercase(),
                    "toUpperCase" => text.to_uppercase(),
                    "trim" => text.trim_matches(|c: char| c <= ' ').to_owned(),
                    _ => text.to_string(),
                })
            }
            ("hashCode", []) => ok(Value::Int(java_hash(units))),
            ("codePointAt", [Value::Int(index)]) if fits_i32(*index) => {
                let at = usize::try_from(*index).ok().filter(|i| *i < units.len());
                let Some(at) = at else {
                    return Err(fail(
                        name,
                        format!("index {index} out of range for length {}", units.len()),
                    ));
                };
                let scalar = char::decode_utf16(units.iter().skip(at).copied()).next();
                ok(Value::Int(match scalar {
                    Some(Ok(c)) => i64::from(u32::from(c)),
                    _ => units.get(at).map_or(0, |unit| i64::from(*unit)),
                }))
            }
            ("charAt", [Value::Int(index)]) if fits_i32(*index) => {
                let unit = usize::try_from(*index)
                    .ok()
                    .and_then(|i| units.get(i))
                    .copied();
                match unit {
                    Some(unit) => ok(String::from_utf16_lossy(&[unit])),
                    None => Err(fail(
                        name,
                        format!("index {index} out of range for length {}", units.len()),
                    )),
                }
            }
            ("substring", [Value::Int(begin)]) if fits_i32(*begin) => {
                Self::substring(units, *begin, None)
            }
            ("substring", [Value::Int(begin), Value::Int(end)])
                if fits_i32(*begin) && fits_i32(*end) =>
            {
                Self::substring(units, *begin, Some(*end))
            }
            ("indexOf", [Value::Str(needle)]) => ok(index_of(units, needle, 0)),
            ("indexOf", [Value::Str(needle), Value::Int(from)]) if fits_i32(*from) => {
                ok(index_of(units, needle, *from))
            }
            ("lastIndexOf", [Value::Str(needle)]) => ok(last_index_of(units, needle, i64::MAX)),
            ("lastIndexOf", [Value::Str(needle), Value::Int(from)]) if fits_i32(*from) => {
                ok(last_index_of(units, needle, *from))
            }
            ("contains", [Value::Str(part)]) => ok(text.contains(&**part)),
            ("startsWith", [Value::Str(prefix)]) => ok(text.starts_with(&**prefix)),
            ("startsWith", [Value::Str(prefix), Value::Int(offset)]) if fits_i32(*offset) => {
                ok(starts_with_at(units, prefix, *offset))
            }
            ("endsWith", [Value::Str(suffix)]) => ok(text.ends_with(&**suffix)),
            _ => Ok(None),
        }
    }

    /// Comparison, concatenation, and literal replacement.
    fn string_compare(text: &Arc<str>, units: &[u16], name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("equals" | "contentEquals", [other]) => {
                ok(matches!(other, Value::Str(o) if o == text))
            }
            ("equalsIgnoreCase", [other]) => {
                ok(matches!(other, Value::Str(o) if equals_ignore_case(text, o)))
            }
            ("concat", [Value::Str(other)]) => ok(format!("{text}{other}")),
            ("compareTo", [Value::Str(other)]) => {
                ok(compare_to(units, &other.encode_utf16().collect::<Vec<_>>()))
            }
            ("compareToIgnoreCase", [Value::Str(other)]) => ok(compare_to(
                &text.to_lowercase().encode_utf16().collect::<Vec<_>>(),
                &other.to_lowercase().encode_utf16().collect::<Vec<_>>(),
            )),
            ("replace", [Value::Str(from), Value::Str(to)]) => ok(if from.is_empty() {
                replace_empty(text, to)
            } else {
                text.replace(&**from, to)
            }),
            _ => Ok(None),
        }
    }

    /// The methods that take a regular expression.
    fn string_regex(&mut self, text: &Arc<str>, name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("replaceAll", [Value::Str(pattern), Value::Str(replacement)]) => {
                let regex = self.compiled(name, pattern)?;
                let replaced = regex
                    .replace_all(text, &Replacement::from(&**replacement))
                    .map_err(|err| fail(name, err.to_string()))?;
                ok(replaced)
            }
            ("replaceFirst", [Value::Str(pattern), Value::Str(replacement)]) => {
                let regex = self.compiled(name, pattern)?;
                let replaced = regex
                    .replace_first(text, &Replacement::from(&**replacement))
                    .map_err(|err| fail(name, err.to_string()))?;
                ok(replaced)
            }
            ("matches", [Value::Str(pattern)]) => {
                let regex = self.compiled(name, pattern)?;
                ok(regex
                    .matches(text)
                    .map_err(|err| fail(name, err.to_string()))?)
            }
            ("split", [Value::Str(pattern)]) => self.split(text, pattern, 0),
            ("split", [Value::Str(pattern), Value::Int(limit)]) if fits_i32(*limit) => {
                self.split(text, pattern, i32::try_from(*limit).unwrap_or(0))
            }

            _ => Ok(None),
        }
    }

    fn substring(units: &[u16], begin: i64, end: Option<i64>) -> MethodResult {
        let len = i64::try_from(units.len()).unwrap_or(i64::MAX);
        let end = end.unwrap_or(len);
        if begin < 0 || end > len || begin > end {
            return Err(fail(
                "substring",
                format!("begin {begin}, end {end}, length {len}"),
            ));
        }
        let (start, stop) = (
            usize::try_from(begin).unwrap_or(0),
            usize::try_from(end).unwrap_or(0),
        );
        ok(String::from_utf16_lossy(
            units.get(start..stop).unwrap_or_default(),
        ))
    }

    fn split(&mut self, text: &str, pattern: &str, limit: i32) -> MethodResult {
        let regex = self.compiled("split", pattern)?;
        let parts = regex
            .split(text, limit)
            .map_err(|err| fail("split", err.to_string()))?;
        ok(Value::from(
            parts.into_iter().map(Value::from).collect::<Vec<_>>(),
        ))
    }

    // ----- List -----

    fn list_method(list: &List, name: &str, args: &[Value]) -> MethodResult {
        let list_only = matches!(name, "get" | "set" | "subList" | "indexOf" | "lastIndexOf")
            || (name == "add" && args.len() == 2)
            || (name == "remove" && matches!(args, [Value::Int(_)]))
            || (name == "addAll" && args.len() == 2);
        if list_only && !list.is_indexed() {
            return Ok(None);
        }
        match (name, args) {
            ("size", []) => ok(int(list.len())),
            ("isEmpty", []) => ok(list.is_empty()),
            ("toString", []) => ok(Value::List(list.clone()).to_java_string()?),
            ("get", [Value::Int(index)]) if fits_i32(*index) => {
                let len = list.len();
                let resolved = usize::try_from(*index).ok().filter(|i| *i < len);
                match resolved.and_then(|i| list.get(i)) {
                    Some(value) => ok(value),
                    None => Err(fail(name, format!("index {index}, size {len}"))),
                }
            }
            ("contains", [item]) => ok(list.snapshot().iter().any(|v| v.java_equals(item))),
            ("indexOf", [item]) => ok(Value::Int(
                list.snapshot()
                    .iter()
                    .position(|v| v.java_equals(item))
                    .map_or(-1, |i| i64::try_from(i).unwrap_or(-1)),
            )),
            ("lastIndexOf", [item]) => ok(Value::Int(
                list.snapshot()
                    .iter()
                    .rposition(|v| v.java_equals(item))
                    .map_or(-1, |i| i64::try_from(i).unwrap_or(-1)),
            )),
            ("subList", [Value::Int(from), Value::Int(to)]) if fits_i32(*from) && fits_i32(*to) => {
                let len = list.len();
                let (Ok(from), Ok(to)) = (usize::try_from(*from), usize::try_from(*to)) else {
                    return Err(fail(name, "negative index"));
                };
                if from > to || to > len {
                    return Err(fail(
                        name,
                        format!("fromIndex {from}, toIndex {to}, size {len}"),
                    ));
                }
                ok(Value::from(
                    list.snapshot()
                        .into_iter()
                        .skip(from)
                        .take(to.saturating_sub(from))
                        .collect::<Vec<_>>(),
                ))
            }
            ("containsAll", [Value::List(other)]) => {
                let items = list.snapshot();
                ok(other
                    .snapshot()
                    .iter()
                    .all(|o| items.iter().any(|v| v.java_equals(o))))
            }
            ("equals", [other]) => ok(Value::List(list.clone()).java_equals(other)),
            ("toArray", []) => ok(Value::from(list.snapshot())),

            _ => Self::list_mutate(list, name, args),
        }
    }

    /// The methods that change a list.
    fn list_mutate(list: &List, name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("add", [item]) => {
                list.push(item.clone());
                ok(true)
            }
            ("add", [Value::Int(index), item]) if fits_i32(*index) => {
                let len = list.len();
                let at = usize::try_from(*index).ok().filter(|i| *i <= len);
                let Some(at) = at else {
                    return Err(fail(name, format!("index {index}, size {len}")));
                };
                list.with(|items| items.insert(at, item.clone()));
                void()
            }
            ("addAll", [Value::List(other)]) => {
                let extra = other.snapshot();
                let changed = !extra.is_empty();
                list.with(|items| items.extend(extra));
                ok(changed)
            }
            ("remove", [Value::Int(index)]) if fits_i32(*index) => {
                let len = list.len();
                let at = usize::try_from(*index).ok().filter(|i| *i < len);
                match at {
                    Some(at) => ok(list.with(|items| items.remove(at))),
                    None => Err(fail(name, format!("index {index}, size {len}"))),
                }
            }
            ("remove", [item]) => {
                let removed = list.with(|items| {
                    items
                        .iter()
                        .position(|v| v.java_equals(item))
                        .map(|i| items.remove(i))
                        .is_some()
                });
                ok(removed)
            }
            ("clear", []) => {
                list.with(Vec::clear);
                void()
            }
            ("set", [Value::Int(index), item]) if fits_i32(*index) => {
                let len = list.len();
                let at = usize::try_from(*index).ok().filter(|i| *i < len);
                match at {
                    Some(at) => ok(list.with(|items| {
                        items
                            .get_mut(at)
                            .map(|slot| std::mem::replace(slot, item.clone()))
                    })),
                    None => Err(fail(name, format!("index {index}, size {len}"))),
                }
            }
            _ => Ok(None),
        }
    }

    // ----- Map -----

    fn map_method(map: &Map, name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("size", []) => ok(int(map.len())),
            ("isEmpty", []) => ok(map.is_empty()),
            ("toString", []) => ok(Value::Map(map.clone()).to_java_string()?),
            ("get", [key]) => ok(Self::map_key(key)?.and_then(|k| map.get(&k))),
            ("getOrDefault", [key, default]) => ok(Self::map_key(key)?
                .and_then(|k| map.get(&k))
                .unwrap_or_else(|| default.clone())),
            ("containsKey", [key]) => ok(Self::map_key(key)?.is_some_and(|k| map.contains_key(&k))),
            ("containsValue", [value]) => {
                ok(map.entries().iter().any(|(_, v)| v.java_equals(value)))
            }
            ("put", [key, value]) => {
                let Some(key) = Self::map_key(key)? else {
                    return ok(Value::Null);
                };
                ok(map.insert(key, value.clone()))
            }
            ("putIfAbsent", [key, value]) => {
                let Some(key) = Self::map_key(key)? else {
                    return ok(Value::Null);
                };
                match map.get(&key) {
                    Some(existing) if !existing.is_null() => ok(existing),
                    _ => ok(map.insert(key, value.clone())),
                }
            }
            ("remove", [key]) => ok(Self::map_key(key)?.and_then(|k| map.remove(&k))),
            ("putAll", [Value::Map(other)]) => {
                for (key, value) in other.entries() {
                    map.insert(key, value);
                }
                void()
            }
            ("clear", []) => {
                map.with(indexmap::IndexMap::clear);
                void()
            }
            ("keySet", []) => ok(Value::List(List::collection(
                map.entries()
                    .into_iter()
                    .map(|(key, _)| Value::Str(key))
                    .collect(),
            ))),
            ("values", []) => ok(Value::List(List::collection(
                map.entries().into_iter().map(|(_, v)| v).collect(),
            ))),
            ("entrySet", []) => ok(Value::List(List::collection(
                map.entries()
                    .into_iter()
                    .map(|(key, value)| Value::Entry(Arc::new(MapEntry { key, value })))
                    .collect(),
            ))),
            ("equals", [other]) => ok(Value::Map(map.clone()).java_equals(other)),
            _ => Ok(None),
        }
    }

    fn entry_method(entry: &Arc<MapEntry>, name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("getKey", []) => ok(Value::Str(Arc::clone(&entry.key))),
            ("getValue", []) => ok(entry.value.clone()),
            ("toString", []) => ok(Value::Entry(Arc::clone(entry)).to_java_string()?),
            _ => Ok(None),
        }
    }

    // ----- numbers and booleans -----

    fn scalar_method(target: &Value, name: &str, args: &[Value]) -> MethodResult {
        match (target, name, args) {
            (_, "toString", []) => ok(target.to_java_string()?),
            (_, "equals", [other]) => ok(target.java_equals(other)),
            (Value::Int(n), "intValue", []) => ok(Value::Int(i64::from(int_value(*n)))),
            (Value::Int(n), "longValue", []) => ok(Value::Int(*n)),
            (Value::Int(n), "doubleValue", []) => ok(Value::Double(int_to_f64(*n))),
            (Value::Int(n), "compareTo", [Value::Int(other)]) => {
                ok(Value::Int(i64::from(n.cmp(other) as i8)))
            }
            (Value::Double(d), "intValue", []) => ok(Value::Int(double_to_int(*d))),
            (Value::Double(d), "longValue", []) => ok(Value::Int(double_to_long(*d))),
            (Value::Double(d), "doubleValue", []) => ok(Value::Double(*d)),
            (Value::Double(d), "isNaN", []) => ok(d.is_nan()),
            (Value::Double(d), "isInfinite", []) => ok(d.is_infinite()),
            (Value::Double(d), "compareTo", [Value::Double(other)]) => {
                ok(Value::Int(i64::from(d.total_cmp(other) as i8)))
            }
            (Value::Bool(b), "booleanValue", []) => ok(*b),
            _ => Ok(None),
        }
    }

    // ----- $input -----

    fn input_method(&mut self, name: &str, args: &[Value]) -> MethodResult {
        match (name, args) {
            ("params", []) => {
                let params = self.input.params();
                ok(Value::Map(
                    [
                        ("path", Value::Map(params.path.clone())),
                        ("querystring", Value::Map(params.querystring.clone())),
                        ("header", Value::Map(params.header.clone())),
                    ]
                    .into_iter()
                    .collect(),
                ))
            }
            ("params", [Value::Str(key)]) => {
                let params = self.input.params();
                let found = params
                    .path
                    .get(key)
                    .or_else(|| params.querystring.get(key))
                    .or_else(|| {
                        params
                            .header
                            .entries()
                            .into_iter()
                            .find(|(name, _)| name.eq_ignore_ascii_case(key))
                            .map(|(_, value)| value)
                    });
                match found {
                    Some(Value::Null) | None => ok(""),
                    Some(value) => ok(value.to_java_string()?),
                }
            }
            ("path", [Value::Str(path)]) => {
                self.charge_for_size(self.input.body().len())?;
                let document = self.body_document()?;
                ok(evaluate_path(path, &document)?)
            }
            ("json", [Value::Str(path)]) => {
                self.charge_for_size(self.input.body().len())?;
                let document = self.body_document()?;
                ok(evaluate_path(path, &document)?.to_json()?)
            }
            _ => Ok(None),
        }
    }

    /// The request body parsed as JSON once and shared, so `$input.path` results alias it.
    fn body_document(&mut self) -> Result<Value, RenderError> {
        if self.body_json.is_none() {
            let parsed = Value::from_json(self.input.body())
                .map_err(|err| RenderError::InvalidBodyJson(err.to_string()));
            self.body_json = Some(parsed);
        }
        match &self.body_json {
            Some(result) => result.clone(),
            None => Ok(Value::Null),
        }
    }
}

fn evaluate_path(path: &str, document: &Value) -> Result<Value, RenderError> {
    let invalid = |err: JsonPathError| RenderError::InvalidJsonPath {
        path: path.to_owned(),
        message: err.to_string(),
    };
    path.parse::<JsonPath>()
        .map_err(invalid)?
        .evaluate(document)
        .map_err(invalid)
}

/// The argument counts a `String` method accepts, for deciding whether a null argument would
/// throw (a method with the right shape) or whether no method matches at all.
const fn string_method_arity(name: &str) -> Option<&'static [usize]> {
    match name.as_bytes() {
        b"concat"
        | b"contains"
        | b"startsWith"
        | b"endsWith"
        | b"compareTo"
        | b"compareToIgnoreCase"
        | b"matches"
        | b"split"
        | b"indexOf"
        | b"lastIndexOf" => Some(&[1, 2]),
        b"replace" | b"replaceAll" | b"replaceFirst" => Some(&[2]),
        _ => None,
    }
}

/// Whether a Java `Integer` can hold the value; Velocity does not narrow a `Long` argument.
const fn fits_i32(value: i64) -> bool {
    value >= -2_147_483_648 && value <= 2_147_483_647
}

/// `String.hashCode`.
fn java_hash(units: &[u16]) -> i64 {
    let hash = units.iter().fold(0_i32, |acc, unit| {
        acc.wrapping_mul(31).wrapping_add(i32::from(*unit))
    });
    i64::from(hash)
}

/// `Long.intValue`: keeps the low 32 bits.
fn int_value(value: i64) -> i32 {
    let [a, b, c, d, ..] = value.to_le_bytes();
    i32::from_le_bytes([a, b, c, d])
}

/// `(int) double`: truncates, saturates, and maps NaN to zero.
#[expect(
    clippy::cast_possible_truncation,
    reason = "Java's narrowing from double saturates the same way"
)]
fn double_to_int(value: f64) -> i64 {
    i64::from(value as i32)
}

/// `(long) double`: truncates, saturates, and maps NaN to zero.
#[expect(
    clippy::cast_possible_truncation,
    reason = "Java's narrowing from double saturates the same way"
)]
const fn double_to_long(value: f64) -> i64 {
    value as i64
}

fn index_of(units: &[u16], needle: &str, from: i64) -> Value {
    let needle: Vec<u16> = needle.encode_utf16().collect();
    let start = usize::try_from(from.max(0)).unwrap_or(usize::MAX);
    if start > units.len() {
        return Value::Int(if needle.is_empty() {
            i64::try_from(units.len()).unwrap_or(-1)
        } else {
            -1
        });
    }
    let found = (start..=units.len().saturating_sub(needle.len()))
        .find(|i| units.get(*i..i.saturating_add(needle.len())) == Some(needle.as_slice()));
    Value::Int(found.map_or(-1, |i| i64::try_from(i).unwrap_or(-1)))
}

fn last_index_of(units: &[u16], needle: &str, from: i64) -> Value {
    let needle: Vec<u16> = needle.encode_utf16().collect();
    if from < 0 || needle.len() > units.len() {
        return Value::Int(-1);
    }
    let latest = units.len().saturating_sub(needle.len());
    let start = usize::try_from(from).unwrap_or(usize::MAX).min(latest);
    let found = (0..=start)
        .rev()
        .find(|i| units.get(*i..i.saturating_add(needle.len())) == Some(needle.as_slice()));
    Value::Int(found.map_or(-1, |i| i64::try_from(i).unwrap_or(-1)))
}

fn starts_with_at(units: &[u16], prefix: &str, offset: i64) -> bool {
    let prefix: Vec<u16> = prefix.encode_utf16().collect();
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    units.get(offset..offset.saturating_add(prefix.len())) == Some(prefix.as_slice())
}

fn equals_ignore_case(a: &str, b: &str) -> bool {
    a.chars().count() == b.chars().count()
        && a.chars().zip(b.chars()).all(|(x, y)| {
            x == y || x.to_uppercase().eq(y.to_uppercase()) || x.to_lowercase().eq(y.to_lowercase())
        })
}

/// `String.compareTo`: the difference of the first differing UTF-16 units, else of the lengths.
fn compare_to(a: &[u16], b: &[u16]) -> Value {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return Value::Int(i64::from(*x).saturating_sub(i64::from(*y)));
        }
    }
    Value::Int(
        i64::try_from(a.len())
            .unwrap_or(0)
            .saturating_sub(i64::try_from(b.len()).unwrap_or(0)),
    )
}

/// `"abc".replace("", "-")` puts the replacement between every character.
fn replace_empty(text: &str, replacement: &str) -> String {
    let mut out = String::from(replacement);
    for c in text.chars() {
        out.push(c);
        out.push_str(replacement);
    }
    out
}
