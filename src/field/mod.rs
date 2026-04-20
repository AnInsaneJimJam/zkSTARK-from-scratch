//! # Field
//!
//! Definition of the prime field `GF(p)` and its arithmetic primitives.

pub mod element;
pub use element::FieldElement;

use std::sync::Arc;
use num_bigint::{BigUint, BigInt};
use num_traits::{Zero, One};
use serde::{Deserialize, Serialize};

use crate::math::xgcd;

// ─── Struct ───────────────────────────────────────────────────────────────────

/// Represents a prime field `GF(p)`.
///
/// Handles the core arithmetic operations (add, subtract, multiply, divide)
/// modulo `p`. Acts as a factory for [`FieldElement`]s.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Field {
    /// The prime modulus `p`.
    pub p: BigUint,
}

impl Field {
    // ─── Core constants & constructors ───────────────────────────────────────

    /// Creates a new `Field` with the given prime `p`.
    pub fn new(p: BigUint) -> Self {
        Self { p }
    }

    /// The default STARK field: `p = 1 + 407 * 2^119`.
    pub fn main() -> Self {
        // p = 1 + 407 * (1 << 119)
        let one = BigUint::one();
        let p = one.clone() + BigUint::from(407u32) * (one << 119);
        Self::new(p)
    }

    /// Helper to construct a `FieldElement` from a simple `u64`.
    pub fn from_u64(self: &Arc<Self>, val: u64) -> FieldElement {
        FieldElement::new(BigUint::from(val), self.clone())
    }

    // ─── Constants ───────────────────────────────────────────────────────────

    /// Returns the additive identity `0`.
    pub fn zero(self: &Arc<Self>) -> FieldElement {
        FieldElement::new(BigUint::zero(), self.clone())
    }

    /// Returns the multiplicative identity `1`.
    pub fn one(self: &Arc<Self>) -> FieldElement {
        FieldElement::new(BigUint::one(), self.clone())
    }

    // ─── Arithmetic operations ───────────────────────────────────────────────

    /// Modular multiplication: `(left * right) % p`.
    pub fn multiply(self: &Arc<Self>, left: &FieldElement, right: &FieldElement) -> FieldElement {
        let v = (&left.value * &right.value) % &self.p;
        FieldElement::new(v, self.clone())
    }

    /// Modular addition: `(left + right) % p`.
    pub fn add(self: &Arc<Self>, left: &FieldElement, right: &FieldElement) -> FieldElement {
        let v = (&left.value + &right.value) % &self.p;
        FieldElement::new(v, self.clone())
    }

    /// Modular subtraction: `(p + left - right) % p`.
    pub fn subtract(self: &Arc<Self>, left: &FieldElement, right: &FieldElement) -> FieldElement {
        // Compute (p + left) - right, taking care not to underflow
        let mut sum = self.p.clone() + &left.value;
        if sum < right.value {
            sum += &self.p;
        }
        let v = (sum - &right.value) % &self.p;
        FieldElement::new(v, self.clone())
    }

    /// Modular negation: `(-operand) % p`.
    pub fn negate(self: &Arc<Self>, operand: &FieldElement) -> FieldElement {
        if operand.is_zero() {
            return self.zero();
        }
        let v = (&self.p - &operand.value) % &self.p;
        FieldElement::new(v, self.clone())
    }

    /// Modular inverse using extended Euclidean algorithm.
    pub fn inverse(self: &Arc<Self>, operand: &FieldElement) -> FieldElement {
        assert!(!operand.is_zero(), "divide by zero");
        
        let op_int = BigInt::from(operand.value.clone());
        let p_int = BigInt::from(self.p.clone());
        
        // a * op + b * p = gcd(op, p)
        let (a, _b, _g) = xgcd(&op_int, &p_int);
        
        // a might be negative, so we do (a % p + p) % p
        let a_mod_p = a % &p_int;
        let mut a_pos = a_mod_p;
        if a_pos < BigInt::zero() {
            a_pos += &p_int;
        }
        
        let inv_uint = a_pos.to_biguint().unwrap();
        FieldElement::new(inv_uint, self.clone())
    }

    /// Modular division: `left * (1 / right)`.
    pub fn divide(self: &Arc<Self>, left: &FieldElement, right: &FieldElement) -> FieldElement {
        assert!(!right.is_zero(), "divide by zero");
        let a = self.inverse(right);
        let v = (&left.value * &a.value) % &self.p;
        FieldElement::new(v, self.clone())
    }

    // ─── STARK Specifics ─────────────────────────────────────────────────────

    /// The canonical generator for the `p = 1 + 407 * 2^119` field.
    pub fn generator(self: &Arc<Self>) -> FieldElement {
        let expected_p = BigUint::one() + BigUint::from(407u32) * (BigUint::one() << 119);
        assert_eq!(self.p, expected_p, "Do not know generator for other fields beyond 1+407*2^119");
        
        let gen_str = "85408008396924667383611388730472331217";
        FieldElement::new(gen_str.parse().unwrap(), self.clone())
    }

    /// Finds a primitive `n`-th root of unity where `n` must be a power of two.
    pub fn primitive_nth_root(self: &Arc<Self>, n: u64) -> FieldElement {
        let expected_p = BigUint::one() + BigUint::from(407u32) * (BigUint::one() << 119);
        if self.p == expected_p {
            assert!(
                n.is_power_of_two(),
                "Field does not have nth root of unity where n is not a power of two."
            );

            let n_bu = BigUint::from(n);
            let max_order: BigUint = BigUint::one() << 119;
            assert!(
                n_bu <= max_order,
                "Field does not have nth root of unity where n > 2^119."
            );
            
            let mut root = self.generator();
            let mut order = max_order;
            
            let two = BigUint::from(2u32);
            while order != n_bu {
                root = root.pow(2);
                order /= &two;
            }
            root
        } else {
            panic!("Unknown field, can't return root of unity.");
        }
    }

    /// Samples a uniform random field element from an array of bytes.
    pub fn sample(self: &Arc<Self>, byte_array: &[u8]) -> FieldElement {
        let mut acc = BigUint::zero();
        for &b in byte_array {
            acc = (acc << 8) ^ BigUint::from(b);
        }
        FieldElement::new(acc % &self.p, self.clone())
    }
}
