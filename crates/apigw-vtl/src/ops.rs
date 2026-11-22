//! Velocity's operators: arithmetic, comparison, and equality over Java-like values.
//!
//! Arithmetic follows Velocity 1.7's `MathUtils`: two integers compute as `long` and the result
//! is an `Integer` when both operands were and it fits, a `long` that overflows is redone as
//! `BigInteger`, a `double` makes the operation `double`, and a `BigInteger` meeting a `double`
//! (or any `BigDecimal`) computes as `BigDecimal`.

use std::cmp::Ordering;
use std::sync::Arc;

use crate::ast::{BinaryOp, Expr};
use crate::error::RenderError;
use crate::eval::Interpreter;
use crate::number::{BigDecimal, BigInt, NumberTooLarge};
use crate::value::Value;

/// A numeric operand.
#[derive(Debug, Clone)]
enum Number {
    Int(i32),
    Long(i64),
    Big(Arc<BigInt>),
    Double(f64),
    Decimal(Arc<BigDecimal>),
}

/// `MathUtils.findCalculationBase`: the type an operation computes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Base {
    Long,
    BigInteger,
    Double,
    BigDecimal,
}

impl From<NumberTooLarge> for RenderError {
    fn from(_: NumberTooLarge) -> Self {
        Self::NumberTooLarge
    }
}

impl Number {
    fn from_value(value: &Value) -> Option<Self> {
        match value {
            Value::Int(n) => Some(Self::Int(*n)),
            Value::Long(n) => Some(Self::Long(*n)),
            Value::BigInt(n) => Some(Self::Big(Arc::clone(n))),
            Value::Double(d) => Some(Self::Double(*d)),
            Value::BigDecimal(d) => Some(Self::Decimal(Arc::clone(d))),
            Value::Null
            | Value::Bool(_)
            | Value::Str(_)
            | Value::List(_)
            | Value::Map(_)
            | Value::Entry(_)
            | Value::Input
            | Value::Util
            | Value::Loop(_)
            | Value::Block(_) => None,
        }
    }

    const fn is_integral(&self) -> bool {
        matches!(self, Self::Int(_) | Self::Long(_) | Self::Big(_))
    }

    fn base(a: &Self, b: &Self) -> Base {
        let decimal = matches!(a, Self::Decimal(_)) || matches!(b, Self::Decimal(_));
        let big = matches!(a, Self::Big(_)) || matches!(b, Self::Big(_));
        let integral = a.is_integral() && b.is_integral();
        if decimal || (!integral && big) {
            Base::BigDecimal
        } else if integral && big {
            Base::BigInteger
        } else if integral {
            Base::Long
        } else {
            Base::Double
        }
    }

    fn to_i64(&self) -> i64 {
        match self {
            Self::Int(n) => i64::from(*n),
            Self::Long(n) => *n,
            Self::Big(n) => n.long_value(),
            Self::Double(d) => double_to_long(*d),
            Self::Decimal(d) => d.long_value(),
        }
    }

    fn to_f64(&self) -> f64 {
        match self {
            Self::Int(n) => f64::from(*n),
            Self::Long(n) => long_to_f64(*n),
            Self::Big(n) => n.to_f64(),
            Self::Double(d) => *d,
            Self::Decimal(d) => d.to_f64(),
        }
    }

    fn to_big(&self) -> BigInt {
        match self {
            Self::Big(n) => (**n).clone(),
            Self::Int(_) | Self::Long(_) | Self::Double(_) | Self::Decimal(_) => {
                BigInt::from_i64(self.to_i64())
            }
        }
    }

    /// `MathUtils.toBigDecimal`: a `double`, `Integer`, or `Long` converts through its
    /// `doubleValue`, exactly.
    fn to_decimal(&self) -> Result<BigDecimal, RenderError> {
        match self {
            Self::Decimal(d) => Ok((**d).clone()),
            Self::Big(n) => Ok(BigDecimal::from_bigint((**n).clone())),
            Self::Int(_) | Self::Long(_) | Self::Double(_) => BigDecimal::from_f64(self.to_f64())
                .ok_or_else(|| RenderError::Arithmetic {
                    message: format!("{} has no BigDecimal value", self.to_f64()),
                }),
        }
    }

    /// `MathUtils.isZero`.
    fn is_zero(&self) -> bool {
        match self {
            Self::Int(n) => *n == 0,
            Self::Long(n) => *n == 0,
            Self::Big(n) => n.is_zero(),
            Self::Double(d) => *d == 0.0,
            Self::Decimal(d) => d.is_zero(),
        }
    }

    /// `MathUtils.wrapPrimitive`: an `Integer` when both operands were and the result fits,
    /// else a `Long`.
    fn wrap(result: i64, a: &Self, b: &Self) -> Value {
        if matches!((a, b), (Self::Int(_), Self::Int(_))) {
            Value::integer(result)
        } else {
            Value::Long(result)
        }
    }

    fn compare(a: &Self, b: &Self) -> Result<Ordering, RenderError> {
        Ok(match Self::base(a, b) {
            Base::Long => a.to_i64().cmp(&b.to_i64()),
            Base::BigInteger => a.to_big().cmp(&b.to_big()),
            // Velocity compares with `<` and `>` only, so NaN compares equal to everything.
            Base::Double => {
                let (x, y) = (a.to_f64(), b.to_f64());
                if x < y {
                    Ordering::Less
                } else if x > y {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }
            Base::BigDecimal => a.to_decimal()?.compare(&b.to_decimal()?)?,
        })
    }
}

/// Java widens a `long` to a `double` by rounding to nearest.
#[expect(
    clippy::cast_precision_loss,
    reason = "this is Java's long to double conversion"
)]
pub(crate) const fn long_to_f64(value: i64) -> f64 {
    value as f64
}

/// `(long) double`: truncates, saturates, and maps NaN to zero.
#[expect(
    clippy::cast_possible_truncation,
    reason = "Java's narrowing from double saturates the same way"
)]
pub(crate) const fn double_to_long(value: f64) -> i64 {
    value as i64
}

/// `(int) double`: truncates, saturates, and maps NaN to zero.
#[expect(
    clippy::cast_possible_truncation,
    reason = "Java's narrowing from double saturates the same way"
)]
pub(crate) const fn double_to_int(value: f64) -> i32 {
    value as i32
}

/// `Number.intValue()` of any numeric value, as Velocity's range operator takes it.
pub(crate) fn int_value(value: &Value) -> Option<i32> {
    let low32 = |n: i64| {
        let [a, b, c, d, ..] = n.to_le_bytes();
        i32::from_le_bytes([a, b, c, d])
    };
    match value {
        Value::Int(n) => Some(*n),
        Value::Long(n) => Some(low32(*n)),
        Value::BigInt(n) => Some(n.int_value()),
        Value::Double(d) => Some(double_to_int(*d)),
        Value::BigDecimal(d) => Some(d.int_value()),
        Value::Null
        | Value::Bool(_)
        | Value::Str(_)
        | Value::List(_)
        | Value::Map(_)
        | Value::Entry(_)
        | Value::Input
        | Value::Util
        | Value::Loop(_)
        | Value::Block(_) => None,
    }
}

/// Java's `%` on doubles takes the sign of the dividend, as Rust's does.
#[expect(
    clippy::modulo_arithmetic,
    reason = "the remainder keeps the dividend's sign, as in Java"
)]
fn java_remainder(a: f64, b: f64) -> f64 {
    a % b
}

fn long_op(op: BinaryOp, a: &Number, b: &Number) -> Result<Value, RenderError> {
    let (x, y) = (a.to_i64(), b.to_i64());
    let promoted = |result: Result<BigInt, NumberTooLarge>| -> Result<Value, RenderError> {
        Ok(Value::BigInt(Arc::new(result?)))
    };
    match op {
        BinaryOp::Add => x.checked_add(y).map_or_else(
            || promoted(a.to_big().add(&b.to_big())),
            |sum| Ok(Number::wrap(sum, a, b)),
        ),
        BinaryOp::Sub => x.checked_sub(y).map_or_else(
            || promoted(a.to_big().sub(&b.to_big())),
            |difference| Ok(Number::wrap(difference, a, b)),
        ),
        BinaryOp::Mul => {
            // Velocity's own overflow test, which misses `Long.MIN_VALUE * -1`.
            let product = x.wrapping_mul(y);
            if y != 0 && product.checked_div(y).unwrap_or(product) != x {
                promoted(a.to_big().mul(&b.to_big()))
            } else {
                Ok(Number::wrap(product, a, b))
            }
        }
        // Division by zero is caught before; `Long.MIN_VALUE / -1` wraps, as in Java.
        BinaryOp::Div => Ok(Number::wrap(x.checked_div(y).unwrap_or(x), a, b)),
        BinaryOp::Rem => Ok(Number::wrap(x.checked_rem(y).unwrap_or(0), a, b)),
        BinaryOp::Or
        | BinaryOp::And
        | BinaryOp::Eq
        | BinaryOp::Ne
        | BinaryOp::Lt
        | BinaryOp::Le
        | BinaryOp::Gt
        | BinaryOp::Ge => Ok(Value::Null),
    }
}

fn big_op(op: BinaryOp, a: &Number, b: &Number) -> Result<Value, RenderError> {
    let (x, y) = (a.to_big(), b.to_big());
    let result = match op {
        BinaryOp::Add => x.add(&y)?,
        BinaryOp::Sub => x.sub(&y)?,
        BinaryOp::Mul => x.mul(&y)?,
        BinaryOp::Div => x
            .div_rem(&y)
            .map_or_else(BigInt::zero, |(quotient, _)| quotient),
        BinaryOp::Rem => x.modulo(&y).ok_or_else(|| RenderError::Arithmetic {
            message: "BigInteger: modulus not positive".to_owned(),
        })?,
        BinaryOp::Or
        | BinaryOp::And
        | BinaryOp::Eq
        | BinaryOp::Ne
        | BinaryOp::Lt
        | BinaryOp::Le
        | BinaryOp::Gt
        | BinaryOp::Ge => return Ok(Value::Null),
    };
    Ok(Value::BigInt(Arc::new(result)))
}

fn decimal_op(op: BinaryOp, a: &Number, b: &Number) -> Result<Value, RenderError> {
    let (x, y) = (a.to_decimal()?, b.to_decimal()?);
    let result = match op {
        BinaryOp::Add => x.add(&y)?,
        BinaryOp::Sub => x.sub(&y)?,
        BinaryOp::Mul => x.mul(&y)?,
        BinaryOp::Div => match x.div_half_down(&y)? {
            Some(quotient) => quotient,
            None => return Ok(Value::Null),
        },
        BinaryOp::Rem => {
            return Err(RenderError::Arithmetic {
                message: "Cannot calculate the modulo of BigDecimals.".to_owned(),
            });
        }
        BinaryOp::Or
        | BinaryOp::And
        | BinaryOp::Eq
        | BinaryOp::Ne
        | BinaryOp::Lt
        | BinaryOp::Le
        | BinaryOp::Gt
        | BinaryOp::Ge => return Ok(Value::Null),
    };
    Ok(Value::BigDecimal(Arc::new(result)))
}

fn double_op(op: BinaryOp, a: &Number, b: &Number) -> Value {
    let (x, y) = (a.to_f64(), b.to_f64());
    let result = match op {
        BinaryOp::Add => x + y,
        BinaryOp::Sub => x - y,
        BinaryOp::Mul => x * y,
        BinaryOp::Div => x / y,
        BinaryOp::Rem => java_remainder(x, y),
        BinaryOp::Or
        | BinaryOp::And
        | BinaryOp::Eq
        | BinaryOp::Ne
        | BinaryOp::Lt
        | BinaryOp::Le
        | BinaryOp::Gt
        | BinaryOp::Ge => return Value::Null,
    };
    Value::Double(result)
}

impl Interpreter<'_> {
    /// Velocity's `==`, `!=`, `<`, `<=`, `>`, and `>=`.
    pub(crate) fn compare(
        &mut self,
        op: BinaryOp,
        left: &Value,
        right: &Value,
    ) -> Result<bool, RenderError> {
        match op {
            BinaryOp::Eq => self.equals(left, right),
            BinaryOp::Ne => Ok(!self.equals(left, right)?),
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                let (Some(l), Some(r)) = (Number::from_value(left), Number::from_value(right))
                else {
                    return Ok(false);
                };
                self.charge_numbers(&l, &r, 1)?;
                let ordering = Number::compare(&l, &r)?;
                Ok(match op {
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
            | BinaryOp::Rem => Ok(false),
        }
    }

    /// Velocity's `==`: numbers compare by value, values of the same kind with `equals`, and
    /// anything else by their string forms.
    fn equals(&mut self, left: &Value, right: &Value) -> Result<bool, RenderError> {
        match (left, right) {
            (Value::Null, Value::Null) => Ok(true),
            (Value::Null, _) | (_, Value::Null) => Ok(false),
            _ => {
                if let (Some(l), Some(r)) = (Number::from_value(left), Number::from_value(right)) {
                    self.charge_numbers(&l, &r, 1)?;
                    return Ok(Number::compare(&l, &r)?.is_eq());
                }
                let same_kind = matches!(
                    (left, right),
                    (Value::Str(_), Value::Str(_))
                        | (Value::Bool(_), Value::Bool(_))
                        | (Value::List(_), Value::List(_))
                        | (Value::Map(_), Value::Map(_))
                        | (Value::Entry(_), Value::Entry(_))
                        | (Value::Block(_), Value::Block(_))
                );
                if same_kind {
                    return Ok(left.java_equals(right));
                }
                match (self.java_string(left), self.java_string(right)) {
                    (Ok(Some(l)), Ok(Some(r))) => Ok(l == r),
                    (Err(err), _) | (_, Err(err)) if !matches!(err, RenderError::ValueTooDeep) => {
                        Err(err)
                    }
                    _ => Ok(false),
                }
            }
        }
    }

    /// Charges the work of an operation on large numbers against the step budget.
    fn charge_numbers(&mut self, a: &Number, b: &Number, factor: usize) -> Result<(), RenderError> {
        let limbs = |n: &Number| match n {
            Number::Big(n) => n.limbs(),
            Number::Decimal(d) => d.limbs(),
            Number::Int(_) | Number::Long(_) | Number::Double(_) => 0,
        };
        let work = limbs(a).saturating_mul(limbs(b).max(1));
        // In BigDecimal arithmetic, a double converts to its exact decimal expansion (up to
        // 1,074 digits), and aligning scales multiplies by a power of ten.
        let decimal = |n: &Number| match n {
            Number::Double(_) => 2048,
            Number::Decimal(d) => usize::try_from(d.scale().unsigned_abs())
                .unwrap_or(usize::MAX)
                .saturating_mul(8),
            Number::Int(_) | Number::Long(_) | Number::Big(_) => 0,
        };
        let conversion = if Number::base(a, b) == Base::BigDecimal {
            decimal(a).saturating_add(decimal(b))
        } else {
            0
        };
        let steps = work.saturating_mul(factor).saturating_add(conversion);
        self.charge(u64::try_from(steps).unwrap_or(u64::MAX))
    }

    /// Velocity's `+`, `-`, `*`, `/`, and `%`; operands that do not fit make the result `null`.
    pub(crate) fn arithmetic(
        &mut self,
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
                self.concat_text(left, left_expr)?,
                self.concat_text(right, right_expr)?
            );
            return Ok(Value::from(text));
        }
        let (Some(l), Some(r)) = (Number::from_value(left), Number::from_value(right)) else {
            return Ok(Value::Null);
        };
        if matches!(op, BinaryOp::Div | BinaryOp::Rem) && r.is_zero() {
            return Ok(Value::Null);
        }
        self.charge_numbers(
            &l,
            &r,
            if matches!(op, BinaryOp::Div | BinaryOp::Rem) {
                32
            } else {
                1
            },
        )?;
        match Number::base(&l, &r) {
            Base::Long => long_op(op, &l, &r),
            Base::BigInteger => big_op(op, &l, &r),
            Base::Double => Ok(double_op(op, &l, &r)),
            Base::BigDecimal => decimal_op(op, &l, &r),
        }
    }

    /// The text `+` appends for an operand: its Java string, or for a null operand the text
    /// Velocity prints for the node, which for a reference is the reference as written.
    fn concat_text(&mut self, value: &Value, expr: &Expr) -> Result<String, RenderError> {
        match (value, expr) {
            (Value::Null, Expr::Reference(reference)) => Ok(reference.source.clone()),
            (Value::Null, Expr::Sourced(_, text)) => Ok(text.to_string()),
            (Value::Null, _) => Ok("null".to_owned()),
            (other, _) => Ok(self
                .java_string(other)?
                .unwrap_or_else(|| "null".to_owned())),
        }
    }
}
