//! Rendering: evaluating a parsed template against variables.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::{BinaryOp, Block, Expr, Foreach, If, Node, Reference, Set, Step};
use crate::error::RenderError;
use crate::value::{List, LoopInfo, Map, Value};
use crate::{Limits, TemplateInput};

/// How many iterations a `#foreach` runs, as in API Gateway.
pub(crate) const MAX_LOOP_ITERATIONS: usize = 1_000;

/// What a block asks its caller to do next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Flow {
    Continue,
    Break,
    Stop,
}

pub(crate) struct Interpreter<'a> {
    pub(crate) input: &'a dyn TemplateInput,
    pub(crate) vars: HashMap<Arc<str>, Value>,
    out: String,
    steps: u64,
    limits: Limits,
    depth: usize,
    current_loop: Option<Arc<LoopInfo>>,
    pub(crate) body_json: Option<Result<Value, RenderError>>,
    pub(crate) regex_cache: Vec<(String, Arc<apigw_regex::JavaRegex>)>,
}

impl<'a> Interpreter<'a> {
    pub(crate) fn new(
        input: &'a dyn TemplateInput,
        context: Map,
        stage_variables: Map,
        limits: Limits,
    ) -> Self {
        let mut vars: HashMap<Arc<str>, Value> = HashMap::new();
        vars.insert("input".into(), Value::Input);
        vars.insert("util".into(), Value::Util);
        vars.insert("context".into(), Value::Map(context));
        vars.insert("stageVariables".into(), Value::Map(stage_variables));
        Self {
            input,
            vars,
            out: String::new(),
            steps: 0,
            limits,
            depth: 0,
            current_loop: None,
            body_json: None,
            regex_cache: Vec::new(),
        }
    }

    pub(crate) fn render(mut self, template: &Block) -> Result<String, RenderError> {
        self.render_block(template)?;
        Ok(self.out)
    }

    pub(crate) fn charge(&mut self, steps: u64) -> Result<(), RenderError> {
        self.steps = self.steps.saturating_add(steps);
        if self.steps > self.limits.steps {
            return Err(RenderError::StepLimit {
                limit: self.limits.steps,
            });
        }
        Ok(())
    }

    fn enter(&mut self) -> Result<(), RenderError> {
        self.depth = self.depth.saturating_add(1);
        if self.depth > self.limits.depth {
            return Err(RenderError::DepthLimit {
                limit: self.limits.depth,
            });
        }
        Ok(())
    }

    fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    fn push_str(&mut self, text: &str) -> Result<(), RenderError> {
        if self.out.len().saturating_add(text.len()) > self.limits.output_bytes {
            return Err(RenderError::OutputLimit {
                limit: self.limits.output_bytes,
            });
        }
        self.out.push_str(text);
        Ok(())
    }

    fn push_backslashes(&mut self, count: usize) -> Result<(), RenderError> {
        if self.out.len().saturating_add(count) > self.limits.output_bytes {
            return Err(RenderError::OutputLimit {
                limit: self.limits.output_bytes,
            });
        }
        self.out.push_str(&"\\".repeat(count));
        Ok(())
    }

    // ----- blocks and directives -----

    fn render_block(&mut self, block: &Block) -> Result<Flow, RenderError> {
        self.enter()?;
        let result = self.render_nodes(block);
        self.leave();
        result
    }

    fn render_nodes(&mut self, block: &Block) -> Result<Flow, RenderError> {
        for node in &block.0 {
            self.charge(1)?;
            let flow = match node {
                Node::Text(text) => {
                    self.push_str(text)?;
                    Flow::Continue
                }
                Node::Reference(reference) => {
                    self.render_reference(reference)?;
                    Flow::Continue
                }
                Node::Set(set) => {
                    self.execute_set(set)?;
                    Flow::Continue
                }
                Node::If(directive) => self.render_if(directive)?,
                Node::Foreach(directive) => self.render_foreach(directive)?,
                Node::Break => Flow::Break,
                Node::Stop => Flow::Stop,
            };
            if flow != Flow::Continue {
                return Ok(flow);
            }
        }
        Ok(Flow::Continue)
    }

    fn render_if(&mut self, directive: &If) -> Result<Flow, RenderError> {
        for (condition, body) in &directive.branches {
            if self.truthy(condition)? {
                return self.render_block(body);
            }
        }
        match &directive.otherwise {
            Some(body) => self.render_block(body),
            None => Ok(Flow::Continue),
        }
    }

    fn render_foreach(&mut self, directive: &Foreach) -> Result<Flow, RenderError> {
        let source = self.value(&directive.source)?;
        let (items, watched) = match &source {
            Value::List(list) => (list.snapshot(), Some(list.clone())),
            Value::Map(map) => (map.entries().into_iter().map(|(_, v)| v).collect(), None),
            _ => return Ok(Flow::Continue),
        };
        let original_len = items.len();
        let outer_loop = self.current_loop.clone();
        let saved = LoopVariables::save(self, &directive.var);
        let mut flow = Flow::Continue;
        for (index, item) in items.into_iter().take(MAX_LOOP_ITERATIONS).enumerate() {
            if let Some(list) = &watched {
                let current = list.len();
                if current != original_len {
                    if index >= current {
                        break;
                    }
                    saved.restore(self);
                    self.current_loop = outer_loop;
                    return Err(RenderError::ConcurrentModification);
                }
            }
            let info = Arc::new(LoopInfo {
                index: i64::try_from(index).unwrap_or(i64::MAX),
                count: i64::try_from(index.saturating_add(1)).unwrap_or(i64::MAX),
                has_next: index.saturating_add(1) < original_len,
                parent: outer_loop.clone(),
            });
            self.current_loop = Some(Arc::clone(&info));
            self.vars.insert(Arc::clone(&directive.var), item);
            self.vars
                .insert("foreach".into(), Value::Loop(Arc::clone(&info)));
            self.vars
                .insert("velocityCount".into(), Value::Int(info.count));
            self.vars
                .insert("velocityHasNext".into(), Value::Bool(info.has_next));
            let result = self.render_block(&directive.body);
            match result {
                Ok(Flow::Continue) => {}
                Ok(Flow::Break) => break,
                Ok(Flow::Stop) => {
                    flow = Flow::Stop;
                    break;
                }
                Err(err) => {
                    saved.restore(self);
                    self.current_loop = outer_loop;
                    return Err(err);
                }
            }
        }
        saved.restore(self);
        self.current_loop = outer_loop;
        Ok(flow)
    }

    fn execute_set(&mut self, set: &Set) -> Result<(), RenderError> {
        let value = self.value(&set.value)?;
        if value.is_null() {
            return Ok(());
        }
        let Some((last, parents)) = set.steps.split_last() else {
            self.vars.insert(Arc::clone(&set.head), value);
            return Ok(());
        };
        let container = self.walk(&set.head, parents)?;
        if matches!(container, Value::Map(_) | Value::List(_)) {
            self.check_acyclic(&container, &value)?;
        }
        match (&container, last) {
            (Value::Map(map), Step::Property(name)) => {
                map.insert(Arc::clone(name), value);
            }
            (Value::Map(map), Step::Index(index)) => {
                let key = self.value(index)?;
                if let Some(key) = Self::map_key(&key)? {
                    map.insert(key, value);
                }
            }
            (Value::List(list), Step::Index(index)) => {
                if let Value::Int(position) = self.value(index)? {
                    let len = list.len();
                    let resolved =
                        resolve_list_index(position, len).ok_or(RenderError::IndexOutOfBounds {
                            index: position,
                            len,
                        })?;
                    list.with(|items| {
                        if let Some(slot) = items.get_mut(resolved) {
                            *slot = value;
                        }
                    });
                }
            }
            _ => {}
        }
        Ok(())
    }

    // ----- references -----

    fn render_reference(&mut self, reference: &Reference) -> Result<(), RenderError> {
        let value = self.resolve(reference)?;
        let backslashes = reference.backslashes;
        let defined = !value.is_null();
        let odd = !backslashes.is_multiple_of(2);
        match (defined, odd) {
            (true, false) => {
                self.push_backslashes(backslashes.div_euclid(2))?;
                self.push_value(&value)
            }
            (true, true) => {
                self.push_backslashes(backslashes.div_euclid(2))?;
                self.push_str(&reference.source)
            }
            (false, false) => {
                self.push_backslashes(backslashes)?;
                if reference.quiet {
                    Ok(())
                } else {
                    self.push_str(&reference.source)
                }
            }
            (false, true) => {
                self.push_backslashes(backslashes.saturating_add(1).div_euclid(2))?;
                self.push_str(&reference.source)
            }
        }
    }

    fn push_value(&mut self, value: &Value) -> Result<(), RenderError> {
        match value {
            Value::Str(text) => self.push_str(text),
            other => {
                let text = other.to_java_string()?;
                self.push_str(&text)
            }
        }
    }

    /// Evaluates a reference to its value, or `null` when any step is unresolved.
    pub(crate) fn resolve(&mut self, reference: &Reference) -> Result<Value, RenderError> {
        self.walk(&reference.head, &reference.steps)
    }

    fn walk(&mut self, head: &str, steps: &[Step]) -> Result<Value, RenderError> {
        let mut current = self.vars.get(head).cloned().unwrap_or(Value::Null);
        for step in steps {
            if current.is_null() {
                return Ok(Value::Null);
            }
            self.charge(1)?;
            current = self.step(&current, step)?;
        }
        Ok(current)
    }

    fn step(&mut self, current: &Value, step: &Step) -> Result<Value, RenderError> {
        match step {
            Step::Property(name) => Ok(self.property(current, name)),
            Step::Method(name, args) => {
                let mut values = Vec::with_capacity(args.len());
                for arg in args {
                    values.push(self.value(arg)?);
                }
                Ok(self
                    .call_method(current, name, &values)?
                    .unwrap_or(Value::Null))
            }
            Step::Index(index) => {
                let index = self.value(index)?;
                Self::index(current, &index)
            }
        }
    }

    fn property(&self, target: &Value, name: &str) -> Value {
        match target {
            Value::Map(map) => map.get(name).unwrap_or(Value::Null),
            Value::Entry(entry) => match name {
                "key" => Value::Str(Arc::clone(&entry.key)),
                "value" => entry.value.clone(),
                _ => Value::Null,
            },
            Value::Loop(info) => match name {
                "index" => Value::Int(info.index),
                "count" => Value::Int(info.count),
                "hasNext" => Value::Bool(info.has_next),
                "first" => Value::Bool(info.index == 0),
                "last" => Value::Bool(!info.has_next),
                "parent" => info.parent.clone().map_or(Value::Null, Value::Loop),
                "topmost" => Value::Loop(info.topmost()),
                _ => Value::Null,
            },
            Value::Input => match name {
                "body" => Value::from(self.input.body()),
                _ => Value::Null,
            },
            Value::List(list) if name == "empty" => Value::Bool(list.is_empty()),
            Value::Str(text) if name == "empty" => Value::Bool(text.is_empty()),
            Value::Null
            | Value::Bool(_)
            | Value::Int(_)
            | Value::Double(_)
            | Value::Str(_)
            | Value::List(_)
            | Value::Util => Value::Null,
        }
    }

    fn index(target: &Value, index: &Value) -> Result<Value, RenderError> {
        match (target, index) {
            (Value::List(list), Value::Int(position)) if list.is_indexed() => {
                let len = list.len();
                let resolved =
                    resolve_list_index(*position, len).ok_or(RenderError::IndexOutOfBounds {
                        index: *position,
                        len,
                    })?;
                Ok(list.get(resolved).unwrap_or(Value::Null))
            }
            (Value::Map(map), key) => Ok(Self::map_key(key)?
                .and_then(|key| map.get(&key))
                .unwrap_or(Value::Null)),
            (
                Value::Str(_)
                | Value::Int(_)
                | Value::Double(_)
                | Value::Bool(_)
                | Value::Entry(_)
                | Value::Input
                | Value::Util
                | Value::Loop(_),
                Value::Int(position),
            ) if *position < 0 => Err(RenderError::IndexOutOfBounds {
                index: *position,
                len: 0,
            }),
            _ => Ok(Value::Null),
        }
    }

    /// The map key a value stands for: Java would box it, here every key is a string.
    pub(crate) fn map_key(key: &Value) -> Result<Option<Arc<str>>, RenderError> {
        match key {
            Value::Null => Ok(None),
            Value::Str(text) => Ok(Some(Arc::clone(text))),
            other => Ok(Some(other.to_java_string()?.into())),
        }
    }

    // ----- expressions -----

    /// Evaluates an expression for its value.
    pub(crate) fn value(&mut self, expr: &Expr) -> Result<Value, RenderError> {
        self.charge(1)?;
        self.enter()?;
        let result = self.value_inner(expr);
        self.leave();
        result
    }

    fn value_inner(&mut self, expr: &Expr) -> Result<Value, RenderError> {
        match expr {
            Expr::Literal(value) => Ok(value.clone()),
            Expr::Interpolated(block) => self.interpolate(block),
            Expr::Reference(reference) => self.resolve(reference),
            Expr::List(items) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    values.push(self.value(item)?);
                }
                Ok(Value::List(List::from_values(values)))
            }
            Expr::Map(entries) => {
                let map = Map::new();
                for (key, value) in entries {
                    let key = self.value(key)?;
                    let value = self.value(value)?;
                    if let Some(key) = Self::map_key(&key)? {
                        map.insert(key, value);
                    }
                }
                Ok(Value::Map(map))
            }
            Expr::Range(from, to) => {
                let (from, to) = (self.value(from)?, self.value(to)?);
                self.range(&from, &to)
            }
            Expr::Not(_) => Ok(Value::Bool(self.truthy(expr)?)),
            Expr::Binary(op, left, right) => match op {
                BinaryOp::Or | BinaryOp::And => Ok(Value::Bool(self.truthy(expr)?)),
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge => {
                    let (l, r) = (self.value(left)?, self.value(right)?);
                    Ok(Value::Bool(Self::compare(*op, &l, &r)))
                }
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
                    let (l, r) = (self.value(left)?, self.value(right)?);
                    Self::arithmetic(*op, &l, &r, left, right)
                }
            },
        }
    }

    fn interpolate(&mut self, block: &Block) -> Result<Value, RenderError> {
        let outer = std::mem::take(&mut self.out);
        let flow = self.render_block(block);
        let rendered = std::mem::replace(&mut self.out, outer);
        flow?;
        Ok(Value::from(rendered))
    }

    fn range(&mut self, from: &Value, to: &Value) -> Result<Value, RenderError> {
        let (Value::Int(from), Value::Int(to)) = (from, to) else {
            return Ok(Value::Null);
        };
        let length = from.abs_diff(*to).saturating_add(1);
        self.charge(length)?;
        let values: Vec<Value> = if from <= to {
            (*from..=*to).map(Value::Int).collect()
        } else {
            (*to..=*from).rev().map(Value::Int).collect()
        };
        Ok(Value::List(List::from_values(values)))
    }

    /// Evaluates an expression as a condition. Velocity gives literals, arithmetic, and
    /// collections no truth value of their own: only references, booleans, comparisons, and
    /// `&&`, `||`, `!` of those can be true.
    pub(crate) fn truthy(&mut self, expr: &Expr) -> Result<bool, RenderError> {
        self.charge(1)?;
        self.enter()?;
        let result = self.truthy_inner(expr);
        self.leave();
        result
    }

    fn truthy_inner(&mut self, expr: &Expr) -> Result<bool, RenderError> {
        match expr {
            Expr::Literal(Value::Bool(value)) => Ok(*value),
            Expr::Literal(_)
            | Expr::Interpolated(_)
            | Expr::List(_)
            | Expr::Map(_)
            | Expr::Range(..) => Ok(false),
            Expr::Reference(reference) => Ok(match self.resolve(reference)? {
                Value::Null => false,
                Value::Bool(value) => value,
                _ => true,
            }),
            Expr::Not(inner) => Ok(!self.truthy(inner)?),
            Expr::Binary(op, left, right) => match op {
                BinaryOp::And => Ok(self.truthy(left)? && self.truthy(right)?),
                BinaryOp::Or => Ok(self.truthy(left)? || self.truthy(right)?),
                BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge => {
                    let (l, r) = (self.value(left)?, self.value(right)?);
                    Ok(Self::compare(*op, &l, &r))
                }
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
                    Ok(false)
                }
            },
        }
    }
}

/// Resolves a possibly negative list index, which counts from the end.
pub(crate) fn resolve_list_index(position: i64, len: usize) -> Option<usize> {
    let len_i = i64::try_from(len).ok()?;
    let resolved = if position < 0 {
        position.checked_add(len_i)?
    } else {
        position
    };
    if (0..len_i).contains(&resolved) {
        usize::try_from(resolved).ok()
    } else {
        None
    }
}

/// Loop variables saved before a `#foreach` and restored after it.
struct LoopVariables {
    entries: Vec<(Arc<str>, Option<Value>)>,
}

impl LoopVariables {
    fn save(interpreter: &Interpreter<'_>, var: &Arc<str>) -> Self {
        let names: [Arc<str>; 4] = [
            Arc::clone(var),
            "foreach".into(),
            "velocityCount".into(),
            "velocityHasNext".into(),
        ];
        Self {
            entries: names
                .into_iter()
                .map(|name| {
                    let previous = interpreter.vars.get(&name).cloned();
                    (name, previous)
                })
                .collect(),
        }
    }

    fn restore(&self, interpreter: &mut Interpreter<'_>) {
        for (name, previous) in &self.entries {
            match previous {
                Some(value) => {
                    interpreter.vars.insert(Arc::clone(name), value.clone());
                }
                None => {
                    interpreter.vars.remove(name);
                }
            }
        }
    }
}
