//! JSON Schema draft 4 body models, checked the way API Gateway checks them.
//!
//! API Gateway runs the Java `json-schema-validator` library, and a request
//! that fails is answered with that library's messages. To report the same
//! messages this follows the library's evaluation rather than a generic
//! validator's: every keyword of a schema is checked against a value, the
//! value's members and elements are visited (members in sorted order) only
//! while nothing has failed yet, `allOf`/`anyOf`/`oneOf`/`not` report one
//! message of their own instead of their subschemas', and a `format` the
//! library does not know adds a warning. The message texts are the library's
//! `validation.properties` catalog.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use fancy_regex::Regex;
use serde_json::{Map, Number, Value};

use super::number::{Decimal, java_text};
use super::report::{Report, java_string_order, json_strings, json_text};

/// How deeply a model's schemas may nest, so that compiling one cannot
/// exhaust the stack.
const MAX_SCHEMA_DEPTH: usize = 100;
/// How deeply one validation may recurse through schemas and the body.
const MAX_VALIDATION_DEPTH: usize = 512;
/// The `format`s the library checks; any other is reported as not supported.
const SUPPORTED_FORMATS: [&str; 15] = [
    "base64",
    "date-time",
    "email",
    "hostname",
    "ipv4",
    "ipv6",
    "json-pointer",
    "mac",
    "md5",
    "regex",
    "sha1",
    "sha256",
    "sha512",
    "uri",
    "uuid",
];
/// The format API Gateway gives an `OpenAPI` `integer` that names none. Its
/// export leaves the format out again, but its validator still reports it.
const DEFAULT_INTEGER_FORMAT: &str = "int32";

/// The index of a compiled schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NodeId(usize);

/// The primitive types, in the order the library lists allowed types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum JsonType {
    Array,
    Boolean,
    Integer,
    Null,
    Number,
    Object,
    String,
}

impl JsonType {
    fn named(name: &str) -> Option<Self> {
        Some(match name {
            "array" => Self::Array,
            "boolean" => Self::Boolean,
            "integer" => Self::Integer,
            "number" => Self::Number,
            "null" => Self::Null,
            "object" => Self::Object,
            "string" => Self::String,
            _ => return None,
        })
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Array => "array",
            Self::Boolean => "boolean",
            Self::Integer => "integer",
            Self::Number => "number",
            Self::Null => "null",
            Self::Object => "object",
            Self::String => "string",
        }
    }

    /// A number written without a fraction or exponent is an `integer`;
    /// `1.0` is a `number`.
    fn of(value: &Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(_) => Self::Boolean,
            Value::Number(number) if number.is_u64() || number.is_i64() => Self::Integer,
            Value::Number(_) => Self::Number,
            Value::String(_) => Self::String,
            Value::Array(_) => Self::Array,
            Value::Object(_) => Self::Object,
        }
    }
}

/// A `pattern` or `patternProperties` expression, matched anywhere in a text.
#[derive(Debug)]
struct Pattern {
    source: String,
    regex: Regex,
}

impl Pattern {
    fn compile(source: &str) -> Result<Self, String> {
        let translated = jsonschema_regex::to_rust_regex(source)
            .map_err(|()| format!("the regular expression {source:?} is not supported"))?;
        let regex = Regex::new(&translated)
            .map_err(|error| format!("the regular expression {source:?} is invalid: {error}"))?;
        Ok(Self {
            source: source.to_owned(),
            regex,
        })
    }

    /// A match that could not be decided counts as none.
    fn matches(&self, text: &str) -> bool {
        self.regex.is_match(text).unwrap_or(false)
    }
}

/// A `minimum` or `maximum`.
#[derive(Debug)]
struct Bound {
    limit: Number,
    decimal: Decimal,
    exclusive: bool,
}

/// A `multipleOf`.
#[derive(Debug)]
struct Divisor {
    number: Number,
    decimal: Decimal,
}

/// An `enum`.
#[derive(Debug)]
struct Enumeration {
    /// The [`equivalence_key`] of each value.
    keys: HashSet<String>,
    /// The values as the message lists them.
    text: String,
}

/// What `additionalProperties` or `additionalItems` allows.
#[derive(Debug, Default)]
enum Additional {
    #[default]
    Any,
    Schema(NodeId),
    Forbidden,
}

/// `items`.
#[derive(Debug, Default)]
enum Items {
    #[default]
    Any,
    Every(NodeId),
    Positional {
        schemas: Vec<NodeId>,
        rest: Additional,
    },
}

impl Items {
    fn schema_for(&self, index: usize) -> Option<NodeId> {
        match self {
            Self::Any => None,
            Self::Every(schema) => Some(*schema),
            Self::Positional { schemas, rest } => match (schemas.get(index), rest) {
                (Some(schema), _) | (None, Additional::Schema(schema)) => Some(*schema),
                (None, Additional::Any | Additional::Forbidden) => None,
            },
        }
    }
}

/// One entry of `dependencies`.
#[derive(Debug)]
enum Dependency {
    Properties(Vec<String>),
    Schema(NodeId),
}

/// The keywords of one schema.
#[derive(Debug, Default)]
struct Level {
    unsupported_format: Option<String>,
    types: Option<Vec<JsonType>>,
    enumeration: Option<Enumeration>,
    minimum: Option<Bound>,
    maximum: Option<Bound>,
    multiple_of: Option<Divisor>,
    min_length: Option<u64>,
    max_length: Option<u64>,
    pattern: Option<Pattern>,
    min_items: Option<u64>,
    max_items: Option<u64>,
    unique_items: bool,
    items: Items,
    min_properties: Option<u64>,
    max_properties: Option<u64>,
    /// Sorted, as the library reports missing properties.
    required: Vec<String>,
    properties: BTreeMap<String, NodeId>,
    pattern_properties: Vec<(Pattern, NodeId)>,
    additional_properties: Additional,
    dependencies: BTreeMap<String, Dependency>,
    all_of: Vec<NodeId>,
    any_of: Vec<NodeId>,
    one_of: Vec<NodeId>,
    not: Option<NodeId>,
}

impl Level {
    /// The schemas that apply to the same value as this one.
    fn same_value_schemas(&self) -> impl Iterator<Item = NodeId> + '_ {
        let dependencies = self
            .dependencies
            .values()
            .filter_map(|dependency| match dependency {
                Dependency::Schema(schema) => Some(*schema),
                Dependency::Properties(_) => None,
            });
        self.all_of
            .iter()
            .chain(&self.any_of)
            .chain(&self.one_of)
            .chain(&self.not)
            .copied()
            .chain(dependencies)
    }

    /// The schemas a member is checked against: its `properties` entry and
    /// every matching `patternProperties` entry, else `additionalProperties`.
    fn member_schemas(&self, name: &str) -> Vec<NodeId> {
        let mut schemas: Vec<NodeId> = self.properties.get(name).copied().into_iter().collect();
        for (pattern, schema) in &self.pattern_properties {
            if pattern.matches(name) {
                schemas.push(*schema);
            }
        }
        if schemas.is_empty()
            && let Additional::Schema(schema) = self.additional_properties
        {
            schemas.push(schema);
        }
        schemas
    }

    fn is_declared(&self, name: &str) -> bool {
        self.properties.contains_key(name)
            || self
                .pattern_properties
                .iter()
                .any(|(pattern, _)| pattern.matches(name))
    }

    fn check_additional(&self, instance: &Value, report: &mut Report) {
        match instance {
            Value::Array(elements) => {
                if let Items::Positional {
                    ref schemas,
                    rest: Additional::Forbidden,
                } = self.items
                    && elements.len() > schemas.len()
                {
                    report.error(|| {
                        format!(
                            "schema only allows {} elements in array but instance has {} elements",
                            schemas.len(),
                            elements.len()
                        )
                    });
                }
            }
            Value::Object(members) => {
                if !matches!(self.additional_properties, Additional::Forbidden) {
                    return;
                }
                let mut unwanted: Vec<&str> = members
                    .keys()
                    .map(String::as_str)
                    .filter(|name| !self.is_declared(name))
                    .collect();
                if unwanted.is_empty() {
                    return;
                }
                unwanted.sort_by(|left, right| java_string_order(left, right));
                report.error(|| {
                    format!(
                        "object instance has properties which are not allowed by the schema: {}",
                        json_strings(unwanted)
                    )
                });
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    fn check_enum(&self, instance: &Value, report: &mut Report) {
        if let Some(ref enumeration) = self.enumeration
            && !enumeration.keys.contains(&equivalence_key(instance))
        {
            report.error(|| {
                format!(
                    "instance value ({}) not found in enum (possible values: {})",
                    json_text(instance),
                    enumeration.text
                )
            });
        }
    }

    fn check_maximum_sizes(&self, instance: &Value, report: &mut Report) {
        match instance {
            Value::Array(elements) => {
                let found = size(elements.len());
                if let Some(most) = self.max_items.filter(|most| found > *most) {
                    report.error(|| {
                        format!(
                            "array is too long: must have at most {most} elements but instance has {found} elements"
                        )
                    });
                }
            }
            Value::String(text) => {
                let found = size(text.chars().count());
                if let Some(most) = self.max_length.filter(|most| found > *most) {
                    report.error(|| {
                        format!(
                            "string \"{text}\" is too long (length: {found}, maximum allowed: {most})"
                        )
                    });
                }
            }
            Value::Object(members) => {
                let found = size(members.len());
                if let Some(most) = self.max_properties.filter(|most| found > *most) {
                    report.error(|| {
                        format!(
                            "object has too many properties (found {found} but schema requires at most {most})"
                        )
                    });
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn check_minimum_sizes(&self, instance: &Value, report: &mut Report) {
        match instance {
            Value::Array(elements) => {
                let found = size(elements.len());
                if let Some(least) = self.min_items.filter(|least| found < *least) {
                    report.error(|| {
                        format!(
                            "array is too short: must have at least {least} elements but instance has {found} elements"
                        )
                    });
                }
            }
            Value::String(text) => {
                let found = size(text.chars().count());
                if let Some(least) = self.min_length.filter(|least| found < *least) {
                    report.error(|| {
                        format!(
                            "string \"{text}\" is too short (length: {found}, required minimum: {least})"
                        )
                    });
                }
            }
            Value::Object(members) => {
                let found = size(members.len());
                if let Some(least) = self.min_properties.filter(|least| found < *least) {
                    report.error(|| {
                        format!(
                            "object has too few properties (found {found} but schema requires at least {least})"
                        )
                    });
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }

    fn check_maximum(&self, found: &Number, report: &mut Report) {
        let Some(ref bound) = self.maximum else {
            return;
        };
        // A number that cannot be compared does not pass.
        let order = Decimal::of(found).map(|found| found.cmp(&bound.decimal));
        if order.is_none_or(Ordering::is_gt) {
            report.error(|| {
                format!(
                    "numeric instance is greater than the required maximum (maximum: {}, found: {})",
                    java_text(&bound.limit),
                    java_text(found)
                )
            });
        } else if bound.exclusive && order == Some(Ordering::Equal) {
            report.error(|| {
                format!(
                    "numeric instance is not strictly lower than the required maximum {}",
                    java_text(&bound.limit)
                )
            });
        }
    }

    fn check_minimum(&self, found: &Number, report: &mut Report) {
        let Some(ref bound) = self.minimum else {
            return;
        };
        let order = Decimal::of(found).map(|found| found.cmp(&bound.decimal));
        if order.is_none_or(Ordering::is_lt) {
            report.error(|| {
                format!(
                    "numeric instance is lower than the required minimum (minimum: {}, found: {})",
                    java_text(&bound.limit),
                    java_text(found)
                )
            });
        } else if bound.exclusive && order == Some(Ordering::Equal) {
            report.error(|| {
                format!(
                    "numeric instance is not strictly greater than the required minimum {}",
                    java_text(&bound.limit)
                )
            });
        }
    }

    fn check_multiple_of(&self, found: &Number, report: &mut Report) {
        let Some(ref divisor) = self.multiple_of else {
            return;
        };
        if !Decimal::of(found).is_some_and(|found| found.is_multiple_of(&divisor.decimal)) {
            report.error(|| {
                format!(
                    "remainder of division is not zero ({} / {})",
                    java_text(found),
                    java_text(&divisor.number)
                )
            });
        }
    }

    fn check_pattern(&self, instance: &Value, report: &mut Report) {
        if let (Some(pattern), Value::String(text)) = (&self.pattern, instance)
            && !pattern.matches(text)
        {
            report.error(|| {
                format!(
                    "ECMA 262 regex \"{}\" does not match input string \"{text}\"",
                    pattern.source
                )
            });
        }
    }

    fn check_required(&self, instance: &Value, report: &mut Report) {
        let Value::Object(members) = instance else {
            return;
        };
        let missing: Vec<&str> = self
            .required
            .iter()
            .map(String::as_str)
            .filter(|name| !members.contains_key(*name))
            .collect();
        if !missing.is_empty() {
            report.error(|| {
                format!(
                    "object has missing required properties ({})",
                    json_strings(missing)
                )
            });
        }
    }

    fn check_type(&self, instance: &Value, report: &mut Report) {
        let Some(ref allowed) = self.types else {
            return;
        };
        let found = JsonType::of(instance);
        if !allowed.contains(&found) {
            report.error(|| {
                format!(
                    "instance type ({}) does not match any allowed primitive type (allowed: {})",
                    found.name(),
                    json_strings(allowed.iter().map(|allowed| allowed.name()))
                )
            });
        }
    }

    fn check_unique_items(&self, instance: &Value, report: &mut Report) {
        let Value::Array(elements) = instance else {
            return;
        };
        if !self.unique_items {
            return;
        }
        let mut seen = HashSet::new();
        if !elements
            .iter()
            .all(|element| seen.insert(equivalence_key(element)))
        {
            report.error(|| "array must not contain duplicate elements".to_owned());
        }
    }
}

fn size(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// A text two values share exactly when the library treats them as equal:
/// numbers by value (`1` equals `1.0`), objects without regard to member order.
fn equivalence_key(value: &Value) -> String {
    let mut key = String::new();
    write_equivalence_key(value, &mut key);
    key
}

fn write_equivalence_key(value: &Value, key: &mut String) {
    match value {
        Value::Null | Value::Bool(_) | Value::String(_) => key.push_str(&json_text(value)),
        Value::Number(number) => {
            key.push('#');
            match Decimal::of(number) {
                Some(decimal) => key.push_str(&decimal.key()),
                None => key.push_str(&number.to_string()),
            }
        }
        Value::Array(elements) => {
            key.push('[');
            for element in elements {
                write_equivalence_key(element, key);
                key.push(',');
            }
            key.push(']');
        }
        Value::Object(members) => {
            let mut members: Vec<(&String, &Value)> = members.iter().collect();
            members.sort_by(|left, right| left.0.cmp(right.0));
            key.push('{');
            for (name, member) in members {
                key.push_str(&json_text(&Value::String(name.clone())));
                key.push(':');
                write_equivalence_key(member, key);
                key.push(',');
            }
            key.push('}');
        }
    }
}

/// A body model compiled from an API's schemas.
#[derive(Debug)]
pub(super) struct BodySchema {
    nodes: Vec<Level>,
    root: NodeId,
}

impl BodySchema {
    /// Compiles the schema at the root of `document`, resolving `$ref`s as
    /// JSON pointers into `document`. `Err` says why the model cannot be
    /// checked.
    pub(super) fn compile(document: &Value) -> Result<Self, String> {
        let mut compiler = Compiler {
            document,
            nodes: Vec::new(),
            by_pointer: HashMap::new(),
        };
        let root = compiler.node("", 0)?;
        let schema = Self {
            nodes: compiler.nodes,
            root,
        };
        if schema.refers_to_itself() {
            return Err("a schema applies to a value through itself (allOf, anyOf, oneOf, not, or dependencies)".to_owned());
        }
        Ok(schema)
    }

    /// What `instance` violates.
    pub(super) fn report(&self, instance: &Value) -> Report {
        let mut report = Report::default();
        self.check(self.root, instance, &mut report, 0);
        report
    }

    /// Whether some schema reaches itself through schemas that apply to the
    /// same value, which would never finish validating.
    fn refers_to_itself(&self) -> bool {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum Visit {
            Unseen,
            Open,
            Done,
        }
        let mut visits = vec![Visit::Unseen; self.nodes.len()];
        for start in 0..self.nodes.len() {
            // (node, whether its schemas have been pushed)
            let mut stack = vec![(start, false)];
            while let Some((node, expanded)) = stack.pop() {
                let (Some(visit), Some(level)) = (visits.get_mut(node), self.nodes.get(node))
                else {
                    continue;
                };
                if expanded {
                    *visit = Visit::Done;
                    continue;
                }
                match *visit {
                    Visit::Done => continue,
                    Visit::Open => return true,
                    Visit::Unseen => {}
                }
                *visit = Visit::Open;
                stack.push((node, true));
                for next in level.same_value_schemas() {
                    if visits.get(next.0) != Some(&Visit::Done) {
                        stack.push((next.0, false));
                    }
                }
            }
        }
        false
    }

    fn passes(&self, schema: NodeId, instance: &Value, depth: usize) -> bool {
        let mut report = Report::quiet();
        self.check(schema, instance, &mut report, depth);
        report.is_success()
    }

    fn check(&self, schema: NodeId, instance: &Value, report: &mut Report, depth: usize) {
        let Some(level) = self
            .nodes
            .get(schema.0)
            .filter(|_| depth < MAX_VALIDATION_DEPTH)
        else {
            report.unknown_error();
            return;
        };
        let depth = depth.saturating_add(1);
        self.check_keywords(level, instance, report, depth);
        // The library stops descending once the report holds any error, from
        // this value or from one it visited earlier.
        if !report.is_success() {
            return;
        }
        match instance {
            Value::Array(elements) => {
                for (index, element) in elements.iter().enumerate() {
                    if let Some(child) = level.items.schema_for(index) {
                        self.check(child, element, report, depth);
                    }
                }
            }
            Value::Object(members) => {
                let mut members: Vec<(&String, &Value)> = members.iter().collect();
                members.sort_by(|left, right| java_string_order(left.0, right.0));
                for (name, member) in members {
                    for child in level.member_schemas(name) {
                        self.check(child, member, report, depth);
                    }
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
        }
    }

    /// Every keyword of `level`, in the library's order: the format warning,
    /// then the keywords by name.
    fn check_keywords(&self, level: &Level, instance: &Value, report: &mut Report, depth: usize) {
        if let Some(ref format) = level.unsupported_format {
            report.warn(|| format!("format attribute \"{format}\" not supported"));
        }
        level.check_additional(instance, report);
        self.check_all_of(level, instance, report, depth);
        self.check_any_of(level, instance, report, depth);
        self.check_dependencies(level, instance, report, depth);
        level.check_enum(instance, report);
        level.check_maximum_sizes(instance, report);
        if let Value::Number(found) = instance {
            level.check_maximum(found, report);
        }
        level.check_minimum_sizes(instance, report);
        if let Value::Number(found) = instance {
            level.check_minimum(found, report);
            level.check_multiple_of(found, report);
        }
        if let Some(not) = level.not
            && self.passes(not, instance, depth)
        {
            report.error(|| "instance matched a schema which it should not have".to_owned());
        }
        self.check_one_of(level, instance, report, depth);
        level.check_pattern(instance, report);
        level.check_required(instance, report);
        level.check_type(instance, report);
        level.check_unique_items(instance, report);
    }

    fn matched(&self, schemas: &[NodeId], instance: &Value, depth: usize) -> usize {
        schemas
            .iter()
            .filter(|schema| self.passes(**schema, instance, depth))
            .count()
    }

    fn check_all_of(&self, level: &Level, instance: &Value, report: &mut Report, depth: usize) {
        let total = level.all_of.len();
        let matched = self.matched(&level.all_of, instance, depth);
        if matched < total {
            report.error(|| {
                format!(
                    "instance failed to match all required schemas (matched only {matched} out of {total})"
                )
            });
        }
    }

    fn check_any_of(&self, level: &Level, instance: &Value, report: &mut Report, depth: usize) {
        let total = level.any_of.len();
        if total > 0
            && !level
                .any_of
                .iter()
                .any(|schema| self.passes(*schema, instance, depth))
        {
            report.error(|| {
                format!("instance failed to match at least one required schema among {total}")
            });
        }
    }

    fn check_one_of(&self, level: &Level, instance: &Value, report: &mut Report, depth: usize) {
        let total = level.one_of.len();
        if total == 0 {
            return;
        }
        let matched = self.matched(&level.one_of, instance, depth);
        if matched != 1 {
            report.error(|| {
                format!(
                    "instance failed to match exactly one schema (matched {matched} out of {total})"
                )
            });
        }
    }

    fn check_dependencies(
        &self,
        level: &Level,
        instance: &Value,
        report: &mut Report,
        depth: usize,
    ) {
        let Value::Object(members) = instance else {
            return;
        };
        let present = level
            .dependencies
            .iter()
            .filter(|(name, _)| members.contains_key(*name));
        // Property dependencies first, then schema dependencies.
        for (name, dependency) in present.clone() {
            let Dependency::Properties(required) = dependency else {
                continue;
            };
            let missing: Vec<&str> = required
                .iter()
                .map(String::as_str)
                .filter(|dependency| !members.contains_key(*dependency))
                .collect();
            if !missing.is_empty() {
                report.error(|| {
                    format!(
                        "property \"{name}\" of object has missing property dependencies (schema requires {}; missing: {})",
                        json_strings(required.iter().map(String::as_str)),
                        json_strings(missing)
                    )
                });
            }
        }
        for (_, dependency) in present {
            if let Dependency::Schema(schema) = dependency {
                self.check(*schema, instance, report, depth);
            }
        }
    }
}

/// Builds the [`Level`]s of a document's schemas, each once.
struct Compiler<'a> {
    document: &'a Value,
    nodes: Vec<Level>,
    /// The schema compiled for each JSON pointer, `$ref`s followed.
    by_pointer: HashMap<String, NodeId>,
}

impl<'a> Compiler<'a> {
    fn node(&mut self, pointer: &str, depth: usize) -> Result<NodeId, String> {
        if depth > MAX_SCHEMA_DEPTH {
            return Err(format!(
                "schemas nest more than {MAX_SCHEMA_DEPTH} levels deep"
            ));
        }
        let (pointer, fields) = self.resolve(pointer)?;
        if let Some(node) = self.by_pointer.get(&pointer) {
            return Ok(*node);
        }
        let node = NodeId(self.nodes.len());
        self.nodes.push(Level::default());
        self.by_pointer.insert(pointer.clone(), node);
        let level = self.level(fields, &pointer, depth.saturating_add(1))?;
        if let Some(slot) = self.nodes.get_mut(node.0) {
            *slot = level;
        }
        Ok(node)
    }

    /// The schema at `pointer` after following `$ref`s, and where it is.
    fn resolve(&self, pointer: &str) -> Result<(String, &'a Map<String, Value>), String> {
        let mut pointer = pointer.to_owned();
        let mut followed = BTreeSet::new();
        loop {
            let Some(schema) = self.document.pointer(&pointer) else {
                return Err(format!("\"#{pointer}\" does not exist"));
            };
            let Value::Object(fields) = schema else {
                return Err(format!("the schema at \"#{pointer}\" is not a JSON object"));
            };
            let Some(reference) = fields.get("$ref") else {
                return Ok((pointer, fields));
            };
            let Some(target) = reference
                .as_str()
                .and_then(|reference| reference.strip_prefix('#'))
            else {
                return Err(format!(
                    "the $ref {reference} at \"#{pointer}\" is not a reference into the API's models"
                ));
            };
            if !followed.insert(pointer.clone()) {
                return Err(format!("the $ref \"#{target}\" refers to itself"));
            }
            target.clone_into(&mut pointer);
        }
    }

    fn child(&mut self, pointer: &str, path: &[&str], depth: usize) -> Result<NodeId, String> {
        let mut pointer = pointer.to_owned();
        for segment in path {
            pointer.push('/');
            pointer.push_str(&segment.replace('~', "~0").replace('/', "~1"));
        }
        self.node(&pointer, depth)
    }

    fn children(
        &mut self,
        fields: &Map<String, Value>,
        keyword: &str,
        pointer: &str,
        depth: usize,
    ) -> Result<Vec<NodeId>, String> {
        match fields.get(keyword) {
            None => Ok(Vec::new()),
            Some(Value::Array(schemas)) if !schemas.is_empty() => (0..schemas.len())
                .map(|index| self.child(pointer, &[keyword, &index.to_string()], depth))
                .collect(),
            Some(_) => Err(invalid(pointer, keyword, "a non-empty array of schemas")),
        }
    }

    fn additional(
        &mut self,
        fields: &Map<String, Value>,
        keyword: &str,
        pointer: &str,
        depth: usize,
    ) -> Result<Additional, String> {
        match fields.get(keyword) {
            None | Some(Value::Bool(true)) => Ok(Additional::Any),
            Some(Value::Bool(false)) => Ok(Additional::Forbidden),
            Some(Value::Object(_)) => self
                .child(pointer, &[keyword], depth)
                .map(Additional::Schema),
            Some(_) => Err(invalid(pointer, keyword, "a boolean or a schema")),
        }
    }

    fn level(
        &mut self,
        fields: &'a Map<String, Value>,
        pointer: &str,
        depth: usize,
    ) -> Result<Level, String> {
        let types = types(fields, pointer)?;
        let mut level = Level {
            unsupported_format: unsupported_format(fields, types.as_deref(), pointer)?,
            types,
            enumeration: enumeration(fields, pointer)?,
            minimum: bound(fields, "minimum", "exclusiveMinimum", pointer)?,
            maximum: bound(fields, "maximum", "exclusiveMaximum", pointer)?,
            multiple_of: divisor(fields, pointer)?,
            min_length: count(fields, "minLength", pointer)?,
            max_length: count(fields, "maxLength", pointer)?,
            pattern: match fields.get("pattern") {
                None => None,
                Some(Value::String(source)) => Some(Pattern::compile(source)?),
                Some(_) => return Err(invalid(pointer, "pattern", "a string")),
            },
            min_items: count(fields, "minItems", pointer)?,
            max_items: count(fields, "maxItems", pointer)?,
            unique_items: flag(fields, "uniqueItems", pointer)?,
            min_properties: count(fields, "minProperties", pointer)?,
            max_properties: count(fields, "maxProperties", pointer)?,
            required: match fields.get("required") {
                None => Vec::new(),
                Some(names) => sorted_names(names, "required", pointer)?,
            },
            additional_properties: self.additional(
                fields,
                "additionalProperties",
                pointer,
                depth,
            )?,
            all_of: self.children(fields, "allOf", pointer, depth)?,
            any_of: self.children(fields, "anyOf", pointer, depth)?,
            one_of: self.children(fields, "oneOf", pointer, depth)?,
            not: match fields.get("not") {
                None => None,
                Some(_) => Some(self.child(pointer, &["not"], depth)?),
            },
            ..Level::default()
        };
        level.items = match fields.get("items") {
            None => Items::Any,
            Some(Value::Object(_)) => Items::Every(self.child(pointer, &["items"], depth)?),
            Some(Value::Array(_)) => Items::Positional {
                schemas: self.children(fields, "items", pointer, depth)?,
                rest: self.additional(fields, "additionalItems", pointer, depth)?,
            },
            Some(_) => return Err(invalid(pointer, "items", "a schema or an array of schemas")),
        };
        for name in member_names(fields, "properties", pointer)? {
            let schema = self.child(pointer, &["properties", name], depth)?;
            level.properties.insert(name.to_owned(), schema);
        }
        for source in member_names(fields, "patternProperties", pointer)? {
            let schema = self.child(pointer, &["patternProperties", source], depth)?;
            level
                .pattern_properties
                .push((Pattern::compile(source)?, schema));
        }
        for name in member_names(fields, "dependencies", pointer)? {
            let dependency = match fields.get("dependencies").and_then(|all| all.get(name)) {
                Some(names @ Value::Array(_)) => {
                    Dependency::Properties(sorted_names(names, "dependencies", pointer)?)
                }
                _ => Dependency::Schema(self.child(pointer, &["dependencies", name], depth)?),
            };
            level.dependencies.insert(name.to_owned(), dependency);
        }
        Ok(level)
    }
}

fn invalid(pointer: &str, keyword: &str, expected: &str) -> String {
    format!("{keyword} at \"#{pointer}\" must be {expected}")
}

fn types(fields: &Map<String, Value>, pointer: &str) -> Result<Option<Vec<JsonType>>, String> {
    let names = match fields.get("type") {
        None => return Ok(None),
        Some(Value::String(name)) => vec![name.as_str()],
        Some(Value::Array(names)) => names
            .iter()
            .map(Value::as_str)
            .collect::<Option<Vec<&str>>>()
            .ok_or_else(|| invalid(pointer, "type", "a type name or an array of them"))?,
        Some(_) => return Err(invalid(pointer, "type", "a type name or an array of them")),
    };
    let mut types = names
        .into_iter()
        .map(|name| {
            JsonType::named(name).ok_or_else(|| {
                format!("type at \"#{pointer}\" names {name:?}, which is not a JSON type")
            })
        })
        .collect::<Result<Vec<JsonType>, String>>()?;
    // The library counts an integer as a number, and says so in its message.
    if types.contains(&JsonType::Number) {
        types.push(JsonType::Integer);
    }
    types.sort_unstable();
    types.dedup();
    Ok(Some(types))
}

/// The `format` the library would warn about: one it does not know, or the
/// `int32` API Gateway adds to an `integer` without a format.
fn unsupported_format(
    fields: &Map<String, Value>,
    types: Option<&[JsonType]>,
    pointer: &str,
) -> Result<Option<String>, String> {
    match fields.get("format") {
        None if matches!(types, Some([JsonType::Integer])) => {
            Ok(Some(DEFAULT_INTEGER_FORMAT.to_owned()))
        }
        None => Ok(None),
        Some(Value::String(format)) if SUPPORTED_FORMATS.contains(&format.as_str()) => Ok(None),
        Some(Value::String(format)) => Ok(Some(format.clone())),
        Some(_) => Err(invalid(pointer, "format", "a string")),
    }
}

fn enumeration(fields: &Map<String, Value>, pointer: &str) -> Result<Option<Enumeration>, String> {
    match fields.get("enum") {
        None => Ok(None),
        Some(values @ Value::Array(elements)) => Ok(Some(Enumeration {
            keys: elements.iter().map(equivalence_key).collect(),
            text: json_text(values),
        })),
        Some(_) => Err(invalid(pointer, "enum", "an array")),
    }
}

fn number<'a>(
    fields: &'a Map<String, Value>,
    keyword: &str,
    pointer: &str,
) -> Result<Option<(&'a Number, Decimal)>, String> {
    match fields.get(keyword) {
        None => Ok(None),
        Some(Value::Number(number)) => Decimal::of(number)
            .map(|decimal| Some((number, decimal)))
            .ok_or_else(|| invalid(pointer, keyword, "a finite number")),
        Some(_) => Err(invalid(pointer, keyword, "a number")),
    }
}

fn bound(
    fields: &Map<String, Value>,
    keyword: &str,
    exclusive: &str,
    pointer: &str,
) -> Result<Option<Bound>, String> {
    let exclusive = flag(fields, exclusive, pointer)?;
    Ok(
        number(fields, keyword, pointer)?.map(|(limit, decimal)| Bound {
            limit: limit.clone(),
            decimal,
            exclusive,
        }),
    )
}

fn divisor(fields: &Map<String, Value>, pointer: &str) -> Result<Option<Divisor>, String> {
    match number(fields, "multipleOf", pointer)? {
        None => Ok(None),
        Some((number, decimal)) if decimal.is_positive() => Ok(Some(Divisor {
            number: number.clone(),
            decimal,
        })),
        Some(_) => Err(invalid(pointer, "multipleOf", "greater than 0")),
    }
}

fn count(fields: &Map<String, Value>, keyword: &str, pointer: &str) -> Result<Option<u64>, String> {
    match fields.get(keyword) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid(pointer, keyword, "a non-negative integer")),
    }
}

fn flag(fields: &Map<String, Value>, keyword: &str, pointer: &str) -> Result<bool, String> {
    match fields.get(keyword) {
        None => Ok(false),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(invalid(pointer, keyword, "a boolean")),
    }
}

/// The distinct strings of an array, in the order of `String.compareTo`.
fn sorted_names(names: &Value, keyword: &str, pointer: &str) -> Result<Vec<String>, String> {
    let mut names: Vec<String> = names
        .as_array()
        .and_then(|names| {
            names
                .iter()
                .map(|name| name.as_str().map(str::to_owned))
                .collect()
        })
        .ok_or_else(|| invalid(pointer, keyword, "an array of property names"))?;
    names.sort_by(|left, right| java_string_order(left, right));
    names.dedup();
    Ok(names)
}

/// The member names of an object-valued keyword.
fn member_names<'a>(
    fields: &'a Map<String, Value>,
    keyword: &str,
    pointer: &str,
) -> Result<Vec<&'a str>, String> {
    match fields.get(keyword) {
        None => Ok(Vec::new()),
        Some(Value::Object(members)) => Ok(members.keys().map(String::as_str).collect()),
        Some(_) => Err(invalid(pointer, keyword, "an object")),
    }
}
