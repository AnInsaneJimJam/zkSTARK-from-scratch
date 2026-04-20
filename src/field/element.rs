//! # Field Element
//!
//! A single element of a prime field `GF(p)`.  All arithmetic operations are
//! performed modulo `p` and delegate back to the owning [`Field`] instance.

use std::fmt;
use std::sync::Arc;

use num_bigint::BigUint;
use num_traits::{One, Zero};

use super::Field;

// ─── Struct ───────────────────────────────────────────────────────────────────

/// An element of a prime field `GF(p)`.
///
/// Every `FieldElement` holds its residue value and a shared reference to the
/// [`Field`] that defines the prime modulus.  Use the [`Field`] factory methods
/// ([`Field::zero`], [`Field::one`]) or construct directly.
///
/// # Arithmetic
///
/// Rust operator overloads (`+`, `-`, `*`, `/`, `-` unary) are provided.
/// Modular exponentiation is exposed as [`FieldElement::pow`] — Rust's `^`
/// operator means bitwise-XOR and would be misleading here.
///
/// # Panics
///
/// Division by zero panics at runtime.
#[derive(Clone, Debug)]
pub struct FieldElement {
    /// Residue in `[0, p)`.
    pub(crate) value: BigUint,
    /// The field this element belongs to.
    pub(crate) field: Arc<Field>,
}

// ─── Core methods ────────────────────────────────────────────────────────────

impl FieldElement {
    /// Creates a new field element, reducing `value` modulo `p`.
    #[inline]
    pub(crate) fn new(value: BigUint, field: Arc<Field>) -> Self {
        let value = value % &field.p;
        Self { value, field }
    }

    /// Returns `true` if this element is the additive identity (zero).
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use stark::field::Field;
    /// let f = Arc::new(Field::main());
    /// assert!(f.zero().is_zero());
    /// assert!(!f.one().is_zero());
    /// ```
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.value.is_zero()
    }

    /// Modular multiplicative inverse of this element.
    ///
    /// Uses the extended Euclidean algorithm.  Panics if the element is zero.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use stark::field::Field;
    /// let f = Arc::new(Field::main());
    /// let three = f.from_u64(3);
    /// let inv   = three.inverse();
    /// assert_eq!(three * inv, f.one());
    /// ```
    pub fn inverse(&self) -> Self {
        self.field.clone().inverse(self)
    }

    /// Modular exponentiation using binary square-and-multiply.
    ///
    /// Equivalent to the Python `^` overload in the reference implementation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::sync::Arc;
    /// # use stark::field::Field;
    /// let f = Arc::new(Field::main());
    /// let g = f.generator();
    /// // Fermat's little theorem: g^{p-1} == 1
    /// let pm1 = &f.p - 1u32;
    /// // (expensive — just a smoke test with small exponent)
    /// assert_eq!(g.pow(0), f.one());
    /// assert_eq!(g.pow(1), g);
    /// ```
    pub fn pow(&self, exponent: u64) -> Self {
        let one = Self::new(BigUint::one(), self.field.clone());
        if exponent == 0 {
            return one;
        }

        let mut acc = one;
        let val = Self::new(self.value.clone(), self.field.clone());
        let bits = 64 - exponent.leading_zeros();

        for i in (0..bits).rev() {
            acc = acc.clone() * acc;
            if (exponent >> i) & 1 == 1 {
                acc = acc * val.clone();
            }
        }
        acc
    }

    /// Serialises the element to bytes (UTF-8 encoding of the decimal string).
    ///
    /// This matches the Python `__bytes__` behaviour.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.value.to_string().into_bytes()
    }
}

// ─── Operator overloads ──────────────────────────────────────────────────────

impl std::ops::Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let f = self.field.clone();
        f.add(&self, &rhs)
    }
}

impl std::ops::Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let f = self.field.clone();
        f.subtract(&self, &rhs)
    }
}

impl std::ops::Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let f = self.field.clone();
        f.multiply(&self, &rhs)
    }
}

impl std::ops::Div for FieldElement {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        let f = self.field.clone();
        f.divide(&self, &rhs)
    }
}

impl std::ops::Neg for FieldElement {
    type Output = Self;
    fn neg(self) -> Self {
        let f = self.field.clone();
        f.negate(&self)
    }
}

// ─── Equality ────────────────────────────────────────────────────────────────

impl PartialEq for FieldElement {
    fn eq(&self, other: &Self) -> bool {
        self.value == other.value
    }
}

impl Eq for FieldElement {}

// ─── Display ─────────────────────────────────────────────────────────────────

impl fmt::Display for FieldElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

// ─── Unit tests ──────────────────────────────────────────────────────────────
