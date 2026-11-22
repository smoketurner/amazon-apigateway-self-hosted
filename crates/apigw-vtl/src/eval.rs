//! Rendering: evaluating a parsed template against variables.

use std::collections::HashMap;
use std::sync::Arc;

use crate::ast::{BinaryOp, Block, Define, Expr, Foreach, If, Node, Reference, Set, Step};
use crate::error::RenderError;
use crate::ops::int_value;
use crate::value::{BlockRef, List, LoopInfo, MAX_VALUE_DEPTH, Map, Value};
use crate::{Limits, NullReferences, TemplateInput};

/// How many iterations a `#foreach` runs, as in API Gateway.
pub(crate) const MAX_LOOP_ITERATIONS: usize = 1_000;

/// How many times a `#define` block may be rendering inside itself, as Velocity's
/// `directive.define.max.depth`; deeper, its reference renders as `null`.
const MAX_DEFINE_DEPTH: usize = 2;

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
    null_references: NullReferences,
    current_loop: Option<Arc<LoopInfo>>,
    /// How many times each `#define` block is rendering right now, by its address.
    rendering_blocks: HashMap<usize, usize>,
    pub(crate) body_json: Option<Result<Value, RenderError>>,
    pub(crate) regex_cache: Vec<(String, Arc<apigw_regex::JavaRegex>)>,
}

impl<'a> Interpreter<'a> {
    pub(crate) fn new(
        input: &'a dyn TemplateInput,
        context: Map,
        stage_variables: Map,
        limits: Limits,
        null_references: NullReferences,
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
            null_references,
            current_loop: None,
            rendering_blocks: HashMap::new(),
            body_json: None,
            regex_cache: Vec::new(),
        }
    }

    pub(crate) fn render(mut self, template: &Block) -> Result<String, RenderError> {
        self.render_block(template)?;
        if let Some(context) = self.vars.get("context").cloned() {
            self.resolve_blocks(&context, 0)?;
        }
        Ok(self.out)
    }

    /// Replaces the `#define` blocks stored in `$context` with their text, which is what the
    /// gateway reads back: Java renders a block when its `toString` is called.
    fn resolve_blocks(&mut self, value: &Value, depth: usize) -> Result<(), RenderError> {
        if depth > MAX_VALUE_DEPTH {
            return Ok(());
        }
        let next = depth.saturating_add(1);
        match value {
            Value::Map(map) => {
                for (key, item) in map.entries() {
                    if let Value::Block(block) = &item {
                        let text = self.block_to_string(block)?;
                        map.insert_value(key, text.map_or(Value::Null, Value::from));
                    } else {
                        self.resolve_blocks(&item, next)?;
                    }
                }
            }
            Value::List(list) => {
                for (index, item) in list.snapshot().into_iter().enumerate() {
                    if let Value::Block(block) = &item {
                        let text = self
                            .block_to_string(block)?
                            .map_or(Value::Null, Value::from);
                        list.with(|items| {
                            if let Some(slot) = items.get_mut(index) {
                                *slot = text;
                            }
                        });
                    } else {
                        self.resolve_blocks(&item, next)?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
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
                Node::Reference(reference) => self.render_reference(reference)?,
                Node::Set(set) => {
                    self.execute_set(set)?;
                    Flow::Continue
                }
                Node::If(directive) => self.render_if(directive)?,
                Node::Foreach(directive) => self.render_foreach(directive)?,
                Node::Define(define) => {
                    self.execute_define(define);
                    Flow::Continue
                }
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
                index: i32::try_from(index).unwrap_or(i32::MAX),
                count: i32::try_from(index.saturating_add(1)).unwrap_or(i32::MAX),
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

    fn execute_define(&mut self, define: &Define) {
        if let Some(name) = &define.name {
            self.vars.insert(
                Arc::clone(name),
                Value::Block(BlockRef(Arc::clone(&define.body))),
            );
        }
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
                self.check_acyclic(&container, &key)?;
                map.insert_value(key, value);
            }
            (Value::List(list), Step::Index(index)) => {
                if let Value::Int(position) = self.value(index)? {
                    let len = list.len();
                    let position = i64::from(position);
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

    fn render_reference(&mut self, reference: &Reference) -> Result<Flow, RenderError> {
        let value = self.resolve(reference)?;
        let backslashes = reference.backslashes;
        let odd = !backslashes.is_multiple_of(2);
        // Velocity renders a block before it writes any escaping backslashes.
        if let (Value::Block(block), false) = (&value, odd) {
            match self.render_define_block(block)? {
                Some(flow) => return Ok(flow),
                None => return self.render_null_reference(reference),
            }
        }
        let defined = !value.is_null();
        match (defined, odd) {
            (true, false) => {
                self.push_backslashes(backslashes.div_euclid(2))?;
                self.push_value(&value)?;
            }
            (true, true) => {
                self.push_backslashes(backslashes.div_euclid(2))?;
                self.push_str(&reference.source)?;
            }
            (false, false) => return self.render_null_reference(reference),
            (false, true) => {
                self.push_backslashes(backslashes.saturating_add(1).div_euclid(2))?;
                self.push_str(&reference.source)?;
            }
        }
        Ok(Flow::Continue)
    }

    /// A reference without an odd number of backslashes whose value is `null`.
    fn render_null_reference(&mut self, reference: &Reference) -> Result<Flow, RenderError> {
        let backslashes = reference.backslashes;
        match self.null_references {
            NullReferences::Empty => self.push_backslashes(backslashes.div_euclid(2))?,
            NullReferences::Literal => {
                self.push_backslashes(backslashes)?;
                if !reference.quiet {
                    self.push_str(&reference.source)?;
                }
            }
        }
        Ok(Flow::Continue)
    }

    /// Renders a `#define` block into the output. `None` when the block is already rendering
    /// as deeply as Velocity allows, where its reference is `null`. A `#break` ends the block;
    /// a `#stop` stops the whole render.
    fn render_define_block(&mut self, block: &BlockRef) -> Result<Option<Flow>, RenderError> {
        let address = block.address();
        let active = self.rendering_blocks.get(&address).copied().unwrap_or(0);
        if active >= MAX_DEFINE_DEPTH {
            return Ok(None);
        }
        self.rendering_blocks
            .insert(address, active.saturating_add(1));
        let result = self.render_block(&block.0);
        self.rendering_blocks.insert(address, active);
        Ok(Some(match result? {
            Flow::Stop => Flow::Stop,
            Flow::Continue | Flow::Break => Flow::Continue,
        }))
    }

    /// A `#define` block's `toString`: its rendered text, or `None` when it is rendering too
    /// deeply.
    pub(crate) fn block_to_string(
        &mut self,
        block: &BlockRef,
    ) -> Result<Option<String>, RenderError> {
        let outer = std::mem::take(&mut self.out);
        let rendered = self.render_define_block(block);
        let text = std::mem::replace(&mut self.out, outer);
        Ok(rendered?.map(|_| text))
    }

    /// A value's Java `toString`, rendering any `#define` blocks it holds. `None` for a block
    /// whose `toString` is `null`.
    pub(crate) fn java_string(&mut self, value: &Value) -> Result<Option<String>, RenderError> {
        match value {
            Value::Str(text) => Ok(Some(text.to_string())),
            Value::Block(block) => self.block_to_string(block),
            other => {
                self.charge(print_cost(other, 0))?;
                let mut out = String::new();
                other.write_java(&mut out, 0, &mut |block| self.block_to_string(block))?;
                Ok(Some(out))
            }
        }
    }

    fn push_value(&mut self, value: &Value) -> Result<(), RenderError> {
        match value {
            Value::Str(text) => self.push_str(text),
            other => {
                let text = self
                    .java_string(other)?
                    .unwrap_or_else(|| "null".to_owned());
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
                "key" => entry.key.clone(),
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
            | Value::Long(_)
            | Value::BigInt(_)
            | Value::Double(_)
            | Value::BigDecimal(_)
            | Value::Str(_)
            | Value::List(_)
            | Value::Util
            | Value::Block(_) => Value::Null,
        }
    }

    fn index(target: &Value, index: &Value) -> Result<Value, RenderError> {
        match (target, index) {
            (Value::List(list), Value::Int(position)) if list.is_indexed() => {
                let len = list.len();
                let position = i64::from(*position);
                let resolved =
                    resolve_list_index(position, len).ok_or(RenderError::IndexOutOfBounds {
                        index: position,
                        len,
                    })?;
                Ok(list.get(resolved).unwrap_or(Value::Null))
            }
            (Value::Map(map), key) => Ok(map.get_value(key).unwrap_or(Value::Null)),
            (
                Value::Str(_)
                | Value::Int(_)
                | Value::Long(_)
                | Value::BigInt(_)
                | Value::Double(_)
                | Value::BigDecimal(_)
                | Value::Bool(_)
                | Value::Entry(_)
                | Value::Input
                | Value::Util
                | Value::Loop(_)
                | Value::Block(_),
                Value::Int(position),
            ) if *position < 0 => Err(RenderError::IndexOutOfBounds {
                index: i64::from(*position),
                len: 0,
            }),
            _ => Ok(Value::Null),
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
            Expr::Sourced(inner, _) => self.value(inner),
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
                    map.insert_value(key, value);
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
                    Ok(Value::Bool(self.compare(*op, &l, &r)?))
                }
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
                    let (l, r) = (self.value(left)?, self.value(right)?);
                    self.arithmetic(*op, &l, &r, left, right)
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

    /// `[from..to]`: Velocity takes each end's `intValue`.
    fn range(&mut self, from: &Value, to: &Value) -> Result<Value, RenderError> {
        let (Some(from), Some(to)) = (int_value(from), int_value(to)) else {
            return Ok(Value::Null);
        };
        let length = u64::from(from.abs_diff(to)).saturating_add(1);
        self.charge(length)?;
        let values: Vec<Value> = if from <= to {
            (from..=to).map(Value::Int).collect()
        } else {
            (to..=from).rev().map(Value::Int).collect()
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
            Expr::Sourced(inner, _) => self.truthy(inner),
            Expr::Reference(reference) => Ok(match self.resolve(reference)? {
                Value::Null => false,
                Value::Bool(value) => value,
                // `directive.if.tostring.nullcheck`: an object whose `toString` is null is false.
                Value::Block(block) => self.block_to_string(&block)?.is_some(),
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
                    self.compare(*op, &l, &r)
                }
                BinaryOp::Add | BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Rem => {
                    Ok(false)
                }
            },
        }
    }
}

/// The steps formatting a value costs: converting a `BigInteger` or `BigDecimal` to decimal takes
/// time that grows with the square of its size.
fn print_cost(value: &Value, depth: usize) -> u64 {
    if depth > MAX_VALUE_DEPTH {
        return 0;
    }
    let next = depth.saturating_add(1);
    let squared =
        |limbs: usize| u64::try_from(limbs.saturating_mul(limbs) >> 4).unwrap_or(u64::MAX);
    match value {
        Value::BigInt(n) => squared(n.limbs()),
        Value::BigDecimal(d) => squared(d.limbs()),
        Value::List(list) => list
            .snapshot()
            .iter()
            .fold(0, |cost, item| cost.saturating_add(print_cost(item, next))),
        Value::Map(map) => map.entries().iter().fold(0, |cost, (key, item)| {
            cost.saturating_add(print_cost(key, next))
                .saturating_add(print_cost(item, next))
        }),
        Value::Entry(entry) => {
            print_cost(&entry.key, next).saturating_add(print_cost(&entry.value, next))
        }
        Value::Null
        | Value::Bool(_)
        | Value::Int(_)
        | Value::Long(_)
        | Value::Double(_)
        | Value::Str(_)
        | Value::Input
        | Value::Util
        | Value::Loop(_)
        | Value::Block(_) => 0,
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
