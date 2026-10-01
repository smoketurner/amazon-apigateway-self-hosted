//! Velocity's operators: arithmetic, comparison, and equality over Java-like values.

use crate::ast::{BinaryOp, Expr};
use crate::error::RenderError;
use crate::eval::Interpreter;
use crate::value::{Value, doubles_equal};

/// A numeric operand.
#[derive(Debug, Clone, Copy)]
enum Number {
    Int(i64),
    Double(f64),
}

impl Number {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Int(n) => Some(Self::Int(*n)),
            Value::Double(d) => Some(Self::Double(*d)),
            Value::Null
            | Value::Bool(_)
            | Value::Str(_)
            | Value::List(_)
            | Value::Map(_)
            | Value::Entry(_)
            | Value::Input
            | Value::Util
            | Value::Loop(_) => None,
        }
    }

    fn to_f64(self) -> f64 {
        match self {
            Self::Int(n) => int_to_f64(n),
            Self::Double(d) => d,
        }
    }

    fn is_zero(self) -> bool {
        match self {
            Self::Int(n) => n == 0,
            Self::Double(d) => d == 0.0,
        }
    }
}

/// Java widens a `long` to a `double` by rounding to nearest.
#[expect(
    clippy::cast_precision_loss,
    reason = "this is Java's long to double conversion"
)]
pub(crate) const fn int_to_f64(value: i64) -> f64 {
    value as f64
}

/// Java's `%` on doubles takes the sign of the dividend, as Rust's does.
#[expect(
    clippy::modulo_arithmetic,
    reason = "the remainder keeps the dividend's sign, as in Java"
)]
fn java_remainder(a: f64, b: f64) -> f64 {
    a % b
}

impl Interpreter<'_> {
    /// Velocity's `==`, `!=`, `<`, `<=`, `>`, and `>=`.
    pub(crate) fn compare(op: BinaryOp, left: &Value, right: &Value) -> bool {
        match op {
            BinaryOp::Eq => Self::equals(left, right),
            BinaryOp::Ne => !Self::equals(left, right),
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                let (Some(l), Some(r)) = (Number::from_value(left), Number::from_value(right))
                else {
                    return false;
                };
                let ordering = match (l, r) {
                    (Number::Int(a), Number::Int(b)) => Some(a.cmp(&b)),
                    _ => l.to_f64().partial_cmp(&r.to_f64()),
                };
                ordering.is_some_and(|ordering| match op {
                    BinaryOp::Lt => ordering.is_lt(),
                    BinaryOp::Le => ordering.is_le(),
                    BinaryOp::Gt => ordering.is_gt(),
                    _ => ordering.is_ge(),
                })
            }
            BinaryOp::Or
            | BinaryOp::And
            | BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Rem => false,
        }
    }

    /// Velocity's `==`: numbers compare by value, values of the same kind with `equals`, and
    /// anything else by their string forms.
    fn equals(left: &Value, right: &Value) -> bool {
        match (left, right) {
            (Value::Null, Value::Null) => true,
            (Value::Null, _) | (_, Value::Null) => false,
            _ => {
                if let (Some(l), Some(r)) = (Number::from_value(left), Number::from_value(right)) {
                    return match (l, r) {
                        (Number::Int(a), Number::Int(b)) => a == b,
                        _ => doubles_equal(l.to_f64(), r.to_f64()),
                    };
                }
                let same_kind = matches!(
                    (left, right),
                    (Value::Str(_), Value::Str(_))
                        | (Value::Bool(_), Value::Bool(_))
                        | (Value::List(_), Value::List(_))
                        | (Value::Map(_), Value::Map(_))
                        | (Value::Entry(_), Value::Entry(_))
                );
                if same_kind {
                    return left.java_equals(right);
                }
                match (left.to_java_string(), right.to_java_string()) {
                    (Ok(l), Ok(r)) => l == r,
                    _ => false,
                }
            }
        }
    }

    /// Velocity's `+`, `-`, `*`, `/`, and `%`; operands that do not fit make the result `null`.
    pub(crate) fn arithmetic(
        op: BinaryOp,
        left: &Value,
        right: &Value,
        left_expr: &Expr,
        right_expr: &Expr,
    ) -> Result<Value, RenderError> {
        if op == BinaryOp::Add && (matches!(left, Value::Str(_)) || matches!(right, Value::Str(_)))
        {
            let text = format!(
                "{}{}",
                Self::concat_text(left, left_expr)?,
                Self::concat_text(right, right_expr)?
            );
            return Ok(Value::from(text));
        }
        let (Some(l), Some(r)) = (Number::from_value(left), Number::from_value(right)) else {
            return Ok(Value::Null);
        };
        if matches!(op, BinaryOp::Div | BinaryOp::Rem) && r.is_zero() {
            return Ok(Value::Null);
        }
        if let (Number::Int(a), Number::Int(b)) = (l, r) {
            let result = match op {
                BinaryOp::Add => a.checked_add(b),
                BinaryOp::Sub => a.checked_sub(b),
                BinaryOp::Mul => a.checked_mul(b),
                BinaryOp::Div => a.checked_div(b),
                BinaryOp::Rem => Some(a.checked_rem(b).unwrap_or(0)),
                BinaryOp::Or
                | BinaryOp::And
                | BinaryOp::Eq
                | BinaryOp::Ne
                | BinaryOp::Lt
                | BinaryOp::Le
                | BinaryOp::Gt
                | BinaryOp::Ge => return Ok(Value::Null),
            };
            return result.map(Value::Int).ok_or(RenderError::IntegerOverflow);
        }
        let (a, b) = (l.to_f64(), r.to_f64());
        let result = match op {
            BinaryOp::Add => a + b,
            BinaryOp::Sub => a - b,
            BinaryOp::Mul => a * b,
            BinaryOp::Div => a / b,
            BinaryOp::Rem => java_remainder(a, b),
            BinaryOp::Or
            | BinaryOp::And
            | BinaryOp::Eq
            | BinaryOp::Ne
            | BinaryOp::Lt
            | BinaryOp::Le
            | BinaryOp::Gt
            | BinaryOp::Ge => return Ok(Value::Null),
        };
        Ok(Value::Double(result))
    }

    /// The text `+` appends for an operand: its Java string, or for a null reference the
    /// reference as written, which is what Velocity prints for it.
    fn concat_text(value: &Value, expr: &Expr) -> Result<String, RenderError> {
        match (value, expr) {
            (Value::Null, Expr::Reference(reference)) => Ok(reference.source.clone()),
            (Value::Null, _) => Ok("null".to_owned()),
            (other, _) => Ok(other.to_java_string()?),
        }
    }
}
