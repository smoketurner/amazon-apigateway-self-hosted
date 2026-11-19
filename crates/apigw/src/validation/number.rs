//! Numbers as API Gateway's validator compares and prints them.
//!
//! API Gateway reads a request body with Jackson, so a number written with a
//! fraction or an exponent is a Java `double` and prints as
//! `Double.toString` does (`-1e2` is `-100.0`, `-1e7` is `-1.0E7`). The
//! validator compares numbers as exact decimals of that printed form, which is
//! why `0.3` is a multiple of `0.1`.

use std::cmp::Ordering;

use serde_json::Number;

/// A number in scientific notation with the fewest digits that round-trip.
struct Scientific {
    negative: bool,
    /// The significant digits, the first of which is the units digit.
    digits: String,
    exponent: i32,
}

impl Scientific {
    fn of(value: f64) -> Option<Self> {
        let text = format!("{value:e}");
        let (negative, unsigned) = match text.strip_prefix('-') {
            Some(rest) => (true, rest),
            None => (false, text.as_str()),
        };
        let (mantissa, exponent) = unsigned.split_once('e')?;
        let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
        if digits.is_empty() {
            return None;
        }
        Some(Self {
            negative,
            digits,
            exponent: exponent.parse().ok()?,
        })
    }

    /// Java's `Double.toString`: plain notation from `1e-3` up to `1e7`,
    /// otherwise `d.dddE±n`, always with a digit after the point.
    fn java_double(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        match self.exponent {
            0..=6 => {
                let point = usize::try_from(self.exponent)
                    .unwrap_or(0)
                    .saturating_add(1);
                let mut whole: String = self.digits.chars().take(point).collect();
                while whole.len() < point {
                    whole.push('0');
                }
                let fraction: String = self.digits.chars().skip(point).collect();
                format!("{sign}{whole}.{}", Self::or_zero(&fraction))
            }
            -3..=-1 => {
                let zeros = usize::try_from(self.exponent.unsigned_abs())
                    .unwrap_or(1)
                    .saturating_sub(1);
                format!("{sign}0.{}{}", "0".repeat(zeros), self.digits)
            }
            exponent => {
                let lead: String = self.digits.chars().take(1).collect();
                let fraction: String = self.digits.chars().skip(1).collect();
                format!("{sign}{lead}.{}E{exponent}", Self::or_zero(&fraction))
            }
        }
    }

    fn or_zero(fraction: &str) -> &str {
        if fraction.is_empty() { "0" } else { fraction }
    }

    fn decimal(&self) -> Option<Decimal> {
        let fraction_digits = i32::try_from(self.digits.len().checked_sub(1)?).ok()?;
        Some(Decimal::normalized(
            self.negative,
            self.digits.parse().ok()?,
            self.exponent.checked_sub(fraction_digits)?,
        ))
    }
}

/// A JSON number as Jackson's `toString` prints it: integers as written,
/// everything else as a Java `double`.
pub(super) fn java_text(number: &Number) -> String {
    if number.is_u64() || number.is_i64() {
        return number.to_string();
    }
    number
        .as_f64()
        .and_then(Scientific::of)
        .map_or_else(|| number.to_string(), |scientific| scientific.java_double())
}

/// An exact decimal: `magnitude × 10^exponent`, negated when `negative`.
///
/// Normalized so that equal numbers are equal values: the magnitude has no
/// trailing zeros and zero is positive with exponent `0`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Decimal {
    negative: bool,
    magnitude: u128,
    exponent: i32,
}

impl Decimal {
    pub(super) fn of(number: &Number) -> Option<Self> {
        if let Some(value) = number.as_u64() {
            return Some(Self::normalized(false, u128::from(value), 0));
        }
        if let Some(value) = number.as_i64() {
            return Some(Self::normalized(
                value < 0,
                u128::from(value.unsigned_abs()),
                0,
            ));
        }
        Scientific::of(number.as_f64()?)?.decimal()
    }

    fn normalized(negative: bool, magnitude: u128, exponent: i32) -> Self {
        if magnitude == 0 {
            return Self {
                negative: false,
                magnitude: 0,
                exponent: 0,
            };
        }
        let (mut magnitude, mut exponent) = (magnitude, exponent);
        while magnitude.checked_rem(10) == Some(0) {
            magnitude = magnitude.checked_div(10).unwrap_or(magnitude);
            exponent = exponent.saturating_add(1);
        }
        Self {
            negative,
            magnitude,
            exponent,
        }
    }

    pub(super) const fn is_positive(&self) -> bool {
        !self.negative && self.magnitude != 0
    }

    /// A text that two numbers share exactly when they are equal.
    pub(super) fn key(&self) -> String {
        let sign = if self.negative { "-" } else { "" };
        format!("{sign}{}e{}", self.magnitude, self.exponent)
    }

    /// Whether dividing by `divisor` leaves no remainder.
    pub(super) fn is_multiple_of(&self, divisor: &Self) -> bool {
        if self.magnitude == 0 {
            return true;
        }
        let shift = self.exponent.abs_diff(divisor.exponent);
        if self.exponent >= divisor.exponent {
            let Some(mut remainder) = self.magnitude.checked_rem(divisor.magnitude) else {
                return false;
            };
            for _ in 0..shift {
                if remainder == 0 {
                    break;
                }
                remainder = remainder
                    .saturating_mul(10)
                    .checked_rem(divisor.magnitude)
                    .unwrap_or(remainder);
            }
            remainder == 0
        } else {
            // A divisor too large to scale is larger than the dividend.
            10_u128
                .checked_pow(shift)
                .and_then(|scale| divisor.magnitude.checked_mul(scale))
                .and_then(|scaled| self.magnitude.checked_rem(scaled))
                == Some(0)
        }
    }

    /// The position of the leading digit: `digits - 1 + exponent`.
    fn leading_position(&self) -> i64 {
        i64::from(self.magnitude.checked_ilog10().unwrap_or(0))
            .saturating_add(i64::from(self.exponent))
    }

    fn cmp_magnitude(&self, other: &Self) -> Ordering {
        match (self.magnitude == 0, other.magnitude == 0) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Less,
            (false, true) => return Ordering::Greater,
            (false, false) => {}
        }
        let by_position = self.leading_position().cmp(&other.leading_position());
        if by_position != Ordering::Equal {
            return by_position;
        }
        // Equal leading positions: scaling the shorter magnitude to the other's
        // exponent gives it the same number of digits, so it cannot overflow.
        let scale = 10_u128.checked_pow(self.exponent.abs_diff(other.exponent));
        if self.exponent >= other.exponent {
            scale
                .and_then(|scale| self.magnitude.checked_mul(scale))
                .map_or(Ordering::Greater, |scaled| scaled.cmp(&other.magnitude))
        } else {
            scale
                .and_then(|scale| other.magnitude.checked_mul(scale))
                .map_or(Ordering::Less, |scaled| self.magnitude.cmp(&scaled))
        }
    }
}

impl Ord for Decimal {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self.negative, other.negative) {
            (false, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, false) => self.cmp_magnitude(other),
            (true, true) => other.cmp_magnitude(self),
        }
    }
}

impl PartialOrd for Decimal {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
