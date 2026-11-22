//! Java's `BigInteger` and `BigDecimal`, as far as templates can observe them.
//!
//! Velocity promotes `long` arithmetic that overflows to `BigInteger`, mixes `BigInteger` with
//! `double` as `BigDecimal`, and JSON numbers too long for a `long` or a `double` arrive as either.
//! Both types here are bounded: a value needing more than [`MAX_LIMBS`] 32-bit limbs, or a scale
//! beyond [`MAX_SCALE`], is a [`NumberTooLarge`] error instead of an allocation without limit.

use std::cmp::Ordering;
use std::fmt;

/// The most 32-bit limbs a magnitude may have: 32,768 bits, about 9,860 decimal digits.
pub(crate) const MAX_LIMBS: usize = 1024;

/// The largest scale (digits after the decimal point, or before it when negative) a decimal may
/// have.
pub(crate) const MAX_SCALE: i32 = 10_000;

/// A number beyond 32,768 bits or a scale of 10,000.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumberTooLarge;

impl fmt::Display for NumberTooLarge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "number exceeds {} bits or a scale of {MAX_SCALE}",
            MAX_LIMBS.saturating_mul(32)
        )
    }
}

impl std::error::Error for NumberTooLarge {}

type Result<T> = std::result::Result<T, NumberTooLarge>;

#[expect(
    clippy::cast_possible_truncation,
    reason = "keeps the low 32 bits, which is the point"
)]
const fn low32(value: u64) -> u32 {
    value as u32
}

fn trim(mut limbs: Vec<u32>) -> Vec<u32> {
    while limbs.last() == Some(&0) {
        limbs.pop();
    }
    limbs
}

fn bounded(limbs: Vec<u32>) -> Result<Vec<u32>> {
    let limbs = trim(limbs);
    if limbs.len() > MAX_LIMBS {
        Err(NumberTooLarge)
    } else {
        Ok(limbs)
    }
}

fn mag_cmp(a: &[u32], b: &[u32]) -> Ordering {
    a.len()
        .cmp(&b.len())
        .then_with(|| a.iter().rev().cmp(b.iter().rev()))
}

fn mag_add(a: &[u32], b: &[u32]) -> Vec<u32> {
    let (long, short) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut out = Vec::with_capacity(long.len().saturating_add(1));
    let mut carry = 0_u64;
    for (index, x) in long.iter().enumerate() {
        let y = short.get(index).copied().unwrap_or(0);
        let sum = u64::from(*x).wrapping_add(u64::from(y)).wrapping_add(carry);
        out.push(low32(sum));
        carry = sum.wrapping_shr(32);
    }
    if carry != 0 {
        out.push(low32(carry));
    }
    out
}

/// `a - b` for `a >= b`.
fn mag_sub(a: &[u32], b: &[u32]) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len());
    let mut borrow = false;
    for (index, x) in a.iter().enumerate() {
        let y = b.get(index).copied().unwrap_or(0);
        let (first, borrowed) = x.overflowing_sub(y);
        let (second, borrowed_again) = first.overflowing_sub(u32::from(borrow));
        out.push(second);
        borrow = borrowed || borrowed_again;
    }
    trim(out)
}

fn mag_mul(a: &[u32], b: &[u32]) -> Vec<u32> {
    if a.is_empty() || b.is_empty() {
        return Vec::new();
    }
    let mut out = vec![0_u32; a.len().saturating_add(b.len())];
    for (i, x) in a.iter().enumerate() {
        let mut carry = 0_u64;
        for (j, y) in b.iter().enumerate() {
            if let Some(slot) = out.get_mut(i.saturating_add(j)) {
                let product = u64::from(*x)
                    .wrapping_mul(u64::from(*y))
                    .wrapping_add(u64::from(*slot))
                    .wrapping_add(carry);
                *slot = low32(product);
                carry = product.wrapping_shr(32);
            }
        }
        let mut at = i.saturating_add(b.len());
        while carry != 0 {
            let Some(slot) = out.get_mut(at) else {
                break;
            };
            let sum = u64::from(*slot).wrapping_add(carry);
            *slot = low32(sum);
            carry = sum.wrapping_shr(32);
            at = at.saturating_add(1);
        }
    }
    trim(out)
}

/// `a * factor + addend`.
fn mag_mul_small(a: &[u32], factor: u32, addend: u32) -> Vec<u32> {
    let mut out = Vec::with_capacity(a.len().saturating_add(1));
    let mut carry = u64::from(addend);
    for x in a {
        let product = u64::from(*x)
            .wrapping_mul(u64::from(factor))
            .wrapping_add(carry);
        out.push(low32(product));
        carry = product.wrapping_shr(32);
    }
    if carry != 0 {
        out.push(low32(carry));
    }
    trim(out)
}

/// `(a / divisor, a % divisor)` for a nonzero divisor.
fn mag_divrem_small(a: &[u32], divisor: u32) -> (Vec<u32>, u32) {
    let mut quotient = vec![0_u32; a.len()];
    let mut remainder = 0_u64;
    let divisor = u64::from(divisor.max(1));
    for (index, x) in a.iter().enumerate().rev() {
        let current = remainder.wrapping_shl(32) | u64::from(*x);
        if let Some(slot) = quotient.get_mut(index) {
            *slot = low32(current.checked_div(divisor).unwrap_or(0));
        }
        remainder = current.checked_rem(divisor).unwrap_or(0);
    }
    (trim(quotient), low32(remainder))
}

fn bit_of(a: &[u32], bit: usize) -> bool {
    a.get(bit.wrapping_shr(5))
        .is_some_and(|limb| limb.wrapping_shr(u32::try_from(bit & 31).unwrap_or(0)) & 1 == 1)
}

fn shift_left_one(a: &mut Vec<u32>, low_bit: bool) {
    let mut carry = u32::from(low_bit);
    for limb in a.iter_mut() {
        let next = limb.wrapping_shr(31);
        *limb = limb.wrapping_shl(1) | carry;
        carry = next;
    }
    if carry != 0 {
        a.push(carry);
    }
}

/// `(a / b, a % b)` for a nonzero `b`, by binary long division.
fn mag_divrem(a: &[u32], b: &[u32]) -> (Vec<u32>, Vec<u32>) {
    if mag_cmp(a, b).is_lt() {
        return (Vec::new(), a.to_vec());
    }
    if let [single] = b {
        let (quotient, remainder) = mag_divrem_small(a, *single);
        return (quotient, trim(vec![remainder]));
    }
    let mut quotient = vec![0_u32; a.len()];
    let mut remainder: Vec<u32> = Vec::with_capacity(b.len().saturating_add(1));
    let bits = a.len().saturating_mul(32);
    for bit in (0..bits).rev() {
        shift_left_one(&mut remainder, bit_of(a, bit));
        if !mag_cmp(&remainder, b).is_lt() {
            remainder = mag_sub(&remainder, b);
            if let Some(limb) = quotient.get_mut(bit.wrapping_shr(5)) {
                *limb |= 1_u32.wrapping_shl(u32::try_from(bit & 31).unwrap_or(0));
            }
        }
    }
    (trim(quotient), trim(remainder))
}

/// A Java `BigInteger`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigInt {
    negative: bool,
    /// Little-endian 32-bit limbs without trailing zeros; zero has none and is never negative.
    magnitude: Vec<u32>,
}

impl BigInt {
    fn from_parts(negative: bool, magnitude: Vec<u32>) -> Result<Self> {
        let magnitude = bounded(magnitude)?;
        Ok(Self {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        })
    }

    fn from_magnitude(negative: bool, magnitude: Vec<u32>) -> Self {
        let magnitude = trim(magnitude);
        Self {
            negative: negative && !magnitude.is_empty(),
            magnitude,
        }
    }

    /// Zero.
    #[must_use]
    pub const fn zero() -> Self {
        Self {
            negative: false,
            magnitude: Vec::new(),
        }
    }

    /// The value of a `long`.
    #[must_use]
    pub fn from_i64(value: i64) -> Self {
        let unsigned = value.unsigned_abs();
        Self::from_magnitude(
            value < 0,
            vec![low32(unsigned), low32(unsigned.wrapping_shr(32))],
        )
    }

    /// The value of an unsigned 64-bit integer.
    #[must_use]
    pub fn from_u64(value: u64) -> Self {
        Self::from_magnitude(false, vec![low32(value), low32(value.wrapping_shr(32))])
    }

    /// Parses an optionally signed run of decimal digits, as `new BigInteger(text)` does.
    ///
    /// # Errors
    ///
    /// Fails when the number has more digits than 32,768 bits hold; returns `Ok(None)` when
    /// the text is not a decimal integer.
    pub fn parse(text: &str) -> Result<Option<Self>> {
        let (negative, digits) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text.strip_prefix('+').unwrap_or(text)),
        };
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        if digits.len() > MAX_LIMBS.saturating_mul(10) {
            return Err(NumberTooLarge);
        }
        // Nine digits at a time: one limb multiplication per chunk.
        let mut magnitude = Vec::new();
        for chunk in digits.as_bytes().chunks(9) {
            let mut scale = 1_u32;
            let mut value = 0_u32;
            for digit in chunk {
                scale = scale.wrapping_mul(10);
                value = value
                    .wrapping_mul(10)
                    .wrapping_add(u32::from(digit.wrapping_sub(b'0')));
            }
            magnitude = mag_mul_small(&magnitude, scale, value);
        }
        Self::from_parts(negative, magnitude).map(Some)
    }

    /// Whether the value is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.magnitude.is_empty()
    }

    /// `signum()`: -1, 0, or 1.
    #[must_use]
    pub const fn signum(&self) -> i32 {
        if self.magnitude.is_empty() {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }

    /// The number of limbs, for charging work against a budget.
    pub(crate) const fn limbs(&self) -> usize {
        self.magnitude.len()
    }

    /// `negate()`.
    #[must_use]
    pub fn negate(&self) -> Self {
        Self::from_magnitude(!self.negative, self.magnitude.clone())
    }

    /// `abs()`.
    #[must_use]
    pub fn abs(&self) -> Self {
        Self::from_magnitude(false, self.magnitude.clone())
    }

    /// `add`.
    ///
    /// # Errors
    ///
    /// Fails when the sum exceeds 32,768 bits.
    pub fn add(&self, other: &Self) -> Result<Self> {
        if self.negative == other.negative {
            return Self::from_parts(self.negative, mag_add(&self.magnitude, &other.magnitude));
        }
        match mag_cmp(&self.magnitude, &other.magnitude) {
            Ordering::Less => {
                Self::from_parts(other.negative, mag_sub(&other.magnitude, &self.magnitude))
            }
            Ordering::Equal | Ordering::Greater => {
                Self::from_parts(self.negative, mag_sub(&self.magnitude, &other.magnitude))
            }
        }
    }

    /// `subtract`.
    ///
    /// # Errors
    ///
    /// Fails when the difference exceeds 32,768 bits.
    pub fn sub(&self, other: &Self) -> Result<Self> {
        self.add(&other.negate())
    }

    /// `multiply`.
    ///
    /// # Errors
    ///
    /// Fails when the product exceeds 32,768 bits.
    pub fn mul(&self, other: &Self) -> Result<Self> {
        if self.magnitude.len().saturating_add(other.magnitude.len()) > MAX_LIMBS.saturating_add(1)
        {
            return Err(NumberTooLarge);
        }
        Self::from_parts(
            self.negative != other.negative,
            mag_mul(&self.magnitude, &other.magnitude),
        )
    }

    /// `divideAndRemainder`: the quotient rounded toward zero and the remainder, which has the
    /// dividend's sign. `None` for a zero divisor.
    #[must_use]
    pub fn div_rem(&self, other: &Self) -> Option<(Self, Self)> {
        if other.is_zero() {
            return None;
        }
        let (quotient, remainder) = mag_divrem(&self.magnitude, &other.magnitude);
        Some((
            Self::from_magnitude(self.negative != other.negative, quotient),
            Self::from_magnitude(self.negative, remainder),
        ))
    }

    /// `mod`: the non-negative remainder. `None` unless the modulus is positive, where Java
    /// throws `ArithmeticException`.
    #[must_use]
    pub fn modulo(&self, modulus: &Self) -> Option<Self> {
        if modulus.signum() <= 0 {
            return None;
        }
        let (_, remainder) = self.div_rem(modulus)?;
        if remainder.negative {
            remainder.add(modulus).ok()
        } else {
            Some(remainder)
        }
    }

    /// `10^exponent`.
    fn pow10(exponent: u32) -> Result<Self> {
        let mut magnitude = vec![1_u32];
        for _ in 0..exponent {
            magnitude = mag_mul_small(&magnitude, 10, 0);
            if magnitude.len() > MAX_LIMBS {
                return Err(NumberTooLarge);
            }
        }
        Ok(Self::from_magnitude(false, magnitude))
    }

    /// The value when it fits in a `long`.
    #[must_use]
    pub fn to_i64(&self) -> Option<i64> {
        if self.magnitude.len() > 2 {
            return None;
        }
        let unsigned = self.low_u64();
        if self.negative {
            if unsigned == 1_u64.wrapping_shl(63) {
                Some(i64::MIN)
            } else {
                i64::try_from(unsigned).ok().map(i64::wrapping_neg)
            }
        } else {
            i64::try_from(unsigned).ok()
        }
    }

    fn low_u64(&self) -> u64 {
        let low = self.magnitude.first().copied().unwrap_or(0);
        let high = self.magnitude.get(1).copied().unwrap_or(0);
        u64::from(high).wrapping_shl(32) | u64::from(low)
    }

    /// `longValue()`: the low 64 bits of the two's complement value.
    #[must_use]
    pub fn long_value(&self) -> i64 {
        let low = if self.negative {
            self.low_u64().wrapping_neg()
        } else {
            self.low_u64()
        };
        i64::from_ne_bytes(low.to_ne_bytes())
    }

    /// `intValue()`: the low 32 bits of the two's complement value.
    #[must_use]
    pub fn int_value(&self) -> i32 {
        let low = self.magnitude.first().copied().unwrap_or(0);
        let low = if self.negative {
            low.wrapping_neg()
        } else {
            low
        };
        i32::from_ne_bytes(low.to_ne_bytes())
    }

    /// `doubleValue()`, rounded to nearest.
    #[must_use]
    pub fn to_f64(&self) -> f64 {
        self.to_string().parse().unwrap_or(f64::NAN)
    }

    fn digits(&self) -> String {
        if self.magnitude.is_empty() {
            return "0".to_owned();
        }
        let mut chunks = Vec::new();
        let mut rest = self.magnitude.clone();
        while !rest.is_empty() {
            let (quotient, chunk) = mag_divrem_small(&rest, 1_000_000_000);
            chunks.push(chunk);
            rest = quotient;
        }
        let mut out = String::with_capacity(chunks.len().saturating_mul(9));
        for (index, chunk) in chunks.iter().rev().enumerate() {
            if index == 0 {
                out.push_str(&chunk.to_string());
            } else {
                let padded = format!("{chunk:09}");
                out.push_str(&padded);
            }
        }
        out
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => mag_cmp(&self.magnitude, &other.magnitude),
            (true, true) => mag_cmp(&other.magnitude, &self.magnitude),
        }
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        f.write_str(&self.digits())
    }
}

impl fmt::Debug for BigInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigInt({self})")
    }
}

/// A Java `BigDecimal`: an unscaled integer and a scale.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BigDecimal {
    unscaled: BigInt,
    scale: i32,
}

/// Java's rounding for `BigDecimal.divide(divisor, ROUND_HALF_DOWN)`, which Velocity uses.
fn round_half_down(quotient: BigInt, remainder: &BigInt, divisor: &BigInt) -> Result<BigInt> {
    let twice = remainder.abs().add(&remainder.abs())?;
    if twice.cmp(&divisor.abs()).is_gt() {
        let step = if remainder.negative == divisor.negative {
            BigInt::from_i64(1)
        } else {
            BigInt::from_i64(-1)
        };
        quotient.add(&step)
    } else {
        Ok(quotient)
    }
}

impl BigDecimal {
    fn new(unscaled: BigInt, scale: i32) -> Result<Self> {
        if scale.unsigned_abs() > MAX_SCALE.unsigned_abs() {
            return Err(NumberTooLarge);
        }
        Ok(Self { unscaled, scale })
    }

    /// `new BigDecimal(BigInteger)`.
    #[must_use]
    pub const fn from_bigint(value: BigInt) -> Self {
        Self {
            unscaled: value,
            scale: 0,
        }
    }

    /// `new BigDecimal(double)`: the exact binary value. `None` for NaN and infinities, which
    /// Java rejects with `NumberFormatException`.
    #[must_use]
    pub fn from_f64(value: f64) -> Option<Self> {
        if !value.is_finite() {
            return None;
        }
        let bits = value.to_bits();
        let negative = bits.wrapping_shr(63) == 1;
        let exponent_bits = i32::try_from(bits.wrapping_shr(52) & 0x7ff).unwrap_or(0);
        let fraction = bits & 0x000f_ffff_ffff_ffff;
        let (mut significand, mut exponent) = if exponent_bits == 0 {
            (fraction, -1074_i32)
        } else {
            (
                fraction | 0x0010_0000_0000_0000,
                exponent_bits.wrapping_sub(1075),
            )
        };
        if significand == 0 {
            return Some(Self::from_bigint(BigInt::zero()));
        }
        while significand & 1 == 0 {
            significand = significand.wrapping_shr(1);
            exponent = exponent.wrapping_add(1);
        }
        let mut unscaled = BigInt::from_u64(significand);
        let scale = if exponent >= 0 {
            for _ in 0..exponent {
                unscaled = unscaled.add(&unscaled).ok()?;
            }
            0
        } else {
            let five = BigInt::from_i64(5);
            for _ in 0..exponent.unsigned_abs() {
                unscaled = unscaled.mul(&five).ok()?;
            }
            exponent.wrapping_neg()
        };
        if negative {
            unscaled = unscaled.negate();
        }
        Self::new(unscaled, scale).ok()
    }

    /// `new BigDecimal(text)` for JSON number syntax: digits, an optional fraction, and an
    /// optional exponent.
    ///
    /// # Errors
    ///
    /// Fails when the value exceeds the size limits; returns `Ok(None)` for malformed text.
    pub fn parse(text: &str) -> Result<Option<Self>> {
        let (mantissa, exponent) = match text.find(['e', 'E']) {
            Some(at) => (
                text.get(..at).unwrap_or_default(),
                text.get(at.saturating_add(1)..).unwrap_or_default(),
            ),
            None => (text, "0"),
        };
        let Ok(exponent) = exponent.parse::<i64>() else {
            return Ok(None);
        };
        let (integer, fraction) = mantissa.split_once('.').unwrap_or((mantissa, ""));
        if !fraction.bytes().all(|b| b.is_ascii_digit()) {
            return Ok(None);
        }
        let Some(unscaled) = BigInt::parse(&format!("{integer}{fraction}"))? else {
            return Ok(None);
        };
        let scale = i64::try_from(fraction.len())
            .unwrap_or(i64::MAX)
            .saturating_sub(exponent);
        let scale = i32::try_from(scale).map_err(|_| NumberTooLarge)?;
        Self::new(unscaled, scale).map(Some)
    }

    /// `scale()`.
    #[must_use]
    pub const fn scale(&self) -> i32 {
        self.scale
    }

    /// `signum()`.
    #[must_use]
    pub const fn signum(&self) -> i32 {
        self.unscaled.signum()
    }

    /// Whether the value is zero, at any scale.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.unscaled.is_zero()
    }

    pub(crate) const fn limbs(&self) -> usize {
        self.unscaled.limbs()
    }

    /// The unscaled value multiplied by `10^extra`.
    fn upscaled(&self, extra: u32) -> Result<BigInt> {
        if extra == 0 {
            return Ok(self.unscaled.clone());
        }
        self.unscaled.mul(&BigInt::pow10(extra)?)
    }

    /// Both unscaled values at the larger of the two scales.
    fn aligned(&self, other: &Self) -> Result<(BigInt, BigInt, i32)> {
        match self.scale.cmp(&other.scale) {
            Ordering::Equal => Ok((self.unscaled.clone(), other.unscaled.clone(), self.scale)),
            Ordering::Greater => Ok((
                self.unscaled.clone(),
                other.upscaled(self.scale.abs_diff(other.scale))?,
                self.scale,
            )),
            Ordering::Less => Ok((
                self.upscaled(self.scale.abs_diff(other.scale))?,
                other.unscaled.clone(),
                other.scale,
            )),
        }
    }

    /// `add`.
    ///
    /// # Errors
    ///
    /// Fails when the result exceeds the size limits.
    pub fn add(&self, other: &Self) -> Result<Self> {
        let (a, b, scale) = self.aligned(other)?;
        Self::new(a.add(&b)?, scale)
    }

    /// `subtract`.
    ///
    /// # Errors
    ///
    /// Fails when the result exceeds the size limits.
    pub fn sub(&self, other: &Self) -> Result<Self> {
        let (a, b, scale) = self.aligned(other)?;
        Self::new(a.sub(&b)?, scale)
    }

    /// `multiply`.
    ///
    /// # Errors
    ///
    /// Fails when the result exceeds the size limits.
    pub fn mul(&self, other: &Self) -> Result<Self> {
        let scale = self.scale.checked_add(other.scale).ok_or(NumberTooLarge)?;
        Self::new(self.unscaled.mul(&other.unscaled)?, scale)
    }

    /// `divide(divisor, ROUND_HALF_DOWN)`: the quotient at this value's scale, rounded to
    /// nearest with ties toward zero. `None` for a zero divisor.
    ///
    /// # Errors
    ///
    /// Fails when the result exceeds the size limits.
    pub fn div_half_down(&self, divisor: &Self) -> Result<Option<Self>> {
        if divisor.is_zero() {
            return Ok(None);
        }
        let (numerator, denominator) = if divisor.scale >= 0 {
            (
                self.upscaled(divisor.scale.unsigned_abs())?,
                divisor.unscaled.clone(),
            )
        } else {
            (
                self.unscaled.clone(),
                divisor.upscaled(divisor.scale.unsigned_abs())?,
            )
        };
        let Some((quotient, remainder)) = numerator.div_rem(&denominator) else {
            return Ok(None);
        };
        let rounded = round_half_down(quotient, &remainder, &denominator)?;
        Self::new(rounded, self.scale).map(Some)
    }

    /// `compareTo`: by value, ignoring scale.
    ///
    /// # Errors
    ///
    /// Fails when aligning the scales exceeds the size limits.
    pub fn compare(&self, other: &Self) -> Result<Ordering> {
        let (a, b, _) = self.aligned(other)?;
        Ok(a.cmp(&b))
    }

    /// The integer part, rounded toward zero.
    fn integer_part(&self) -> BigInt {
        if self.scale <= 0 {
            return self.upscaled(self.scale.unsigned_abs()).unwrap_or_default();
        }
        BigInt::pow10(self.scale.unsigned_abs())
            .ok()
            .and_then(|divisor| self.unscaled.div_rem(&divisor))
            .map_or_else(BigInt::zero, |(quotient, _)| quotient)
    }

    /// `longValue()`.
    #[must_use]
    pub fn long_value(&self) -> i64 {
        self.integer_part().long_value()
    }

    /// `intValue()`.
    #[must_use]
    pub fn int_value(&self) -> i32 {
        self.integer_part().int_value()
    }

    /// `doubleValue()`, rounded to nearest.
    #[must_use]
    pub fn to_f64(&self) -> f64 {
        self.to_string().parse().unwrap_or(f64::NAN)
    }

    /// `toPlainString()`.
    #[must_use]
    pub fn to_plain_string(&self) -> String {
        let sign = if self.unscaled.negative { "-" } else { "" };
        let digits = self.unscaled.digits();
        let scale = usize::try_from(self.scale.unsigned_abs()).unwrap_or(0);
        if self.scale <= 0 {
            let zeros = if self.unscaled.is_zero() { 0 } else { scale };
            return format!("{sign}{digits}{}", "0".repeat(zeros));
        }
        if digits.len() > scale {
            let (integer, fraction) = digits.split_at(digits.len().saturating_sub(scale));
            format!("{sign}{integer}.{fraction}")
        } else {
            format!(
                "{sign}0.{}{digits}",
                "0".repeat(scale.saturating_sub(digits.len()))
            )
        }
    }
}

impl Default for BigInt {
    fn default() -> Self {
        Self::zero()
    }
}

impl fmt::Display for BigDecimal {
    /// Java's `BigDecimal.toString`: plain notation unless the scale is negative or the value is
    /// smaller than `1E-6`, then scientific notation with a signed exponent.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digits = self.unscaled.digits();
        let length = i64::try_from(digits.len()).unwrap_or(i64::MAX);
        let adjusted = i64::from(self.scale)
            .wrapping_neg()
            .saturating_add(length.saturating_sub(1));
        if self.scale >= 0 && adjusted >= -6 {
            return f.write_str(&self.to_plain_string());
        }
        if self.unscaled.negative {
            f.write_str("-")?;
        }
        let (head, tail) = digits.split_at(1.min(digits.len()));
        f.write_str(head)?;
        if !tail.is_empty() {
            write!(f, ".{tail}")?;
        }
        if adjusted != 0 {
            let sign = if adjusted > 0 { "+" } else { "" };
            write!(f, "E{sign}{adjusted}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for BigDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BigDecimal({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn big(text: &str) -> BigInt {
        BigInt::parse(text).ok().flatten().unwrap_or_default()
    }

    fn dec(text: &str) -> BigDecimal {
        BigDecimal::parse(text)
            .ok()
            .flatten()
            .unwrap_or_else(|| BigDecimal::from_bigint(BigInt::zero()))
    }

    #[test]
    fn integers_round_trip_through_text() {
        for text in [
            "0",
            "1",
            "-1",
            "4294967296",
            "18446744073709551616",
            "-99999999999999999999",
            "85070591730234615847396907784232501249",
        ] {
            assert_eq!(big(text).to_string(), text);
        }
        assert_eq!(
            BigInt::from_i64(i64::MIN).to_string(),
            "-9223372036854775808"
        );
        assert_eq!(BigInt::parse("12a"), Ok(None));
        assert_eq!(BigInt::parse(&"9".repeat(20_000)), Err(NumberTooLarge));
    }

    #[test]
    fn integer_arithmetic_matches_java() {
        let max = BigInt::from_i64(i64::MAX);
        assert_eq!(
            max.mul(&max).map(|v| v.to_string()),
            Ok("85070591730234615847396907784232501249".to_owned())
        );
        let a = big("99999999999999999999");
        let seven = BigInt::from_i64(7);
        let (q, r) = a.div_rem(&seven).unwrap_or_default();
        assert_eq!(
            (q.to_string(), r.to_string()),
            ("14285714285714285714".to_owned(), "1".to_owned())
        );
        let (q, r) = a.negate().div_rem(&seven).unwrap_or_default();
        assert_eq!(
            (q.to_string(), r.to_string()),
            ("-14285714285714285714".to_owned(), "-1".to_owned())
        );
        assert_eq!(
            a.negate().modulo(&seven).map(|v| v.to_string()),
            Some("6".to_owned())
        );
        assert_eq!(a.modulo(&seven.negate()), None);
        assert_eq!(a.div_rem(&BigInt::zero()), None);
        let b = big("3000000000");
        let (q, r) = a.div_rem(&b).unwrap_or_default();
        assert_eq!(
            (q.to_string(), r.to_string()),
            ("33333333333".to_owned(), "999999999".to_owned())
        );
        assert_eq!(a.long_value(), 7_766_279_631_452_241_919);
        assert_eq!(a.int_value(), 1_661_992_959);
        assert_eq!(a.negate().long_value(), -7_766_279_631_452_241_919);
        assert!((a.to_f64() - 1.0e20).abs() < 1.0);
        assert_eq!(big("-9223372036854775808").to_i64(), Some(i64::MIN));
        assert_eq!(big("9223372036854775808").to_i64(), None);
        assert!(big("-5").cmp(&big("3")).is_lt());
    }

    #[test]
    fn products_beyond_the_limit_are_errors() {
        let mut value = big("99999999999999999999");
        let mut failed = false;
        for _ in 0..20 {
            let Ok(next) = value.mul(&value) else {
                failed = true;
                break;
            };
            value = next;
        }
        assert!(failed);
    }

    #[test]
    fn decimals_print_like_java() {
        assert_eq!(
            dec("1.23456789012345678901").to_string(),
            "1.23456789012345678901"
        );
        assert_eq!(
            dec("12345678901234567890123e-3").to_string(),
            "12345678901234567890.123"
        );
        assert_eq!(dec("123e5").to_string(), "1.23E+7");
        assert_eq!(dec("0.0000001").to_string(), "1E-7");
        assert_eq!(dec("0.000001").to_string(), "0.000001");
        assert_eq!(dec("-1.5").to_string(), "-1.5");
        assert_eq!(
            BigDecimal::from_f64(0.1).map(|d| d.to_string()),
            Some("0.1000000000000000055511151231257827021181583404541015625".to_owned())
        );
        assert_eq!(
            BigDecimal::from_f64(2.0).map(|d| d.to_string()),
            Some("2".to_owned())
        );
        assert_eq!(BigDecimal::from_f64(f64::NAN), None);
        assert_eq!(dec("123e5").to_plain_string(), "12300000");
    }

    #[test]
    fn decimal_arithmetic_matches_java() {
        let a = BigDecimal::from_bigint(big("99999999999999999999"));
        let half = BigDecimal::from_f64(0.5).unwrap_or_else(|| a.clone());
        let b = a.add(&half).unwrap_or_else(|_| a.clone());
        assert_eq!(b.to_string(), "99999999999999999999.5");
        let four = BigDecimal::from_f64(4.0).unwrap_or_else(|| a.clone());
        assert_eq!(
            b.div_half_down(&four).ok().flatten().map(|d| d.to_string()),
            Some("24999999999999999999.9".to_owned())
        );
        let ten = BigDecimal::from_bigint(big("10000000000000000000"));
        let six = BigDecimal::from_f64(6.0).unwrap_or_else(|| a.clone());
        assert_eq!(
            ten.div_half_down(&six)
                .ok()
                .flatten()
                .map(|d| d.to_string()),
            Some("1666666666666666667".to_owned())
        );
        assert_eq!(
            ten.div_half_down(&BigDecimal::from_bigint(BigInt::zero())),
            Ok(None)
        );
        assert_eq!(b.compare(&a), Ok(Ordering::Greater));
        assert_eq!(b.long_value(), 7_766_279_631_452_241_919);
        assert_eq!(dec("-2.5").int_value(), -2);
    }
}
