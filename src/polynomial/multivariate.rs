//! # Multivariate Polynomial
//!
//! Sparse multivariate polynomials over the prime field.

use std::collections::BTreeMap;
use std::ops::{Add, BitXor, Mul, Neg, Sub};

use crate::field::FieldElement;

use super::Polynomial;

/// Sparse multivariate polynomial keyed by exponent vectors.
///
/// The monomial `x_0^a x_1^b ...` is stored under the exponent vector
/// `[a, b, ...]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MPolynomial {
    dictionary: BTreeMap<Vec<usize>, FieldElement>,
}

impl MPolynomial {
    /// Creates a multivariate polynomial and removes zero-valued terms.
    pub fn new(dictionary: BTreeMap<Vec<usize>, FieldElement>) -> Self {
        let dictionary = dictionary
            .into_iter()
            .filter_map(|(mut exponent, coefficient)| {
                if coefficient.is_zero() {
                    return None;
                }

                while exponent.last().is_some_and(|entry| *entry == 0) {
                    exponent.pop();
                }

                Some((exponent, coefficient))
            })
            .collect();

        Self { dictionary }
    }

    /// Returns the zero polynomial.
    pub fn zero() -> Self {
        Self::new(BTreeMap::new())
    }

    /// Returns a constant multivariate polynomial.
    pub fn constant(element: FieldElement) -> Self {
        if element.is_zero() {
            Self::zero()
        } else {
            Self::new(BTreeMap::from([(Vec::new(), element)]))
        }
    }

    /// Returns `true` when the polynomial has no non-zero terms.
    pub fn is_zero(&self) -> bool {
        self.dictionary.is_empty()
    }

    /// Returns the sparse term dictionary.
    pub fn dictionary(&self) -> &BTreeMap<Vec<usize>, FieldElement> {
        &self.dictionary
    }

    /// Raises the polynomial to a non-negative integer power.
    pub fn pow(&self, exponent: u64) -> Self {
        if self.is_zero() {
            return Self::zero();
        }

        let field = self
            .dictionary
            .values()
            .next()
            .expect("non-zero polynomial must have a coefficient")
            .field
            .clone();

        if exponent == 0 {
            return Self::constant(field.one());
        }

        let mut acc = Self::constant(field.one());
        for bit in (0..(64 - exponent.leading_zeros())).rev() {
            acc = acc.clone() * acc;
            if ((exponent >> bit) & 1) == 1 {
                acc = acc * self.clone();
            }
        }
        acc
    }

    /// Returns the coordinate polynomials `x_0, ..., x_{n-1}`.
    pub fn variables(num_variables: usize, field: &std::sync::Arc<crate::field::Field>) -> Vec<Self> {
        (0..num_variables)
            .map(|index| {
                let mut exponent = vec![0; num_variables];
                exponent[index] = 1;
                Self::new(BTreeMap::from([(exponent, field.one())]))
            })
            .collect()
    }

    /// Lifts a univariate polynomial into the variable at `variable_index`.
    pub fn lift(polynomial: &Polynomial, variable_index: usize) -> Self {
        if polynomial.is_zero() {
            return Self::zero();
        }

        let field = polynomial.coefficients()[0].field.clone();
        let x = Self::variables(variable_index + 1, &field)
            .into_iter()
            .last()
            .expect("at least one variable is required");

        polynomial
            .coefficients()
            .iter()
            .cloned()
            .enumerate()
            .fold(Self::zero(), |acc, (degree, coefficient)| {
                acc + Self::constant(coefficient) * x.clone().pow(degree as u64)
            })
    }

    /// Evaluates the polynomial at a field-valued point.
    pub fn evaluate(&self, point: &[FieldElement]) -> FieldElement {
        let field = self
            .dictionary
            .values()
            .next()
            .map(|coefficient| coefficient.field.clone())
            .or_else(|| point.first().map(|value| value.field.clone()))
            .expect("cannot evaluate without a field context");

        self.dictionary.iter().fold(field.zero(), |acc, (exponent, coefficient)| {
            let term = exponent
                .iter()
                .enumerate()
                .fold(coefficient.clone(), |product, (index, power)| {
                    product * point[index].pow(*power as u64)
                });
            acc + term
        })
    }

    /// Evaluates the polynomial at a symbolic point of univariate polynomials.
    pub fn evaluate_symbolic(&self, point: &[Polynomial]) -> Polynomial {
        self.dictionary
            .iter()
            .fold(Polynomial::new(Vec::new()), |acc, (exponent, coefficient)| {
                let term = exponent.iter().enumerate().fold(
                    Polynomial::new(vec![coefficient.clone()]),
                    |product, (index, power)| product * point[index].pow(*power as u64),
                );
                acc + term
            })
    }
}

impl Add for MPolynomial {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut dictionary = self.dictionary;
        for (exponent, coefficient) in rhs.dictionary {
            dictionary
                .entry(exponent)
                .and_modify(|value| *value = value.clone() + coefficient.clone())
                .or_insert(coefficient);
        }

        Self::new(dictionary)
    }
}

impl Sub for MPolynomial {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Neg for MPolynomial {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self::new(
            self.dictionary
                .into_iter()
                .map(|(exponent, coefficient)| (exponent, -coefficient))
                .collect(),
        )
    }
}

impl Mul for MPolynomial {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        if self.is_zero() || rhs.is_zero() {
            return Self::zero();
        }

        let mut dictionary = BTreeMap::new();
        let num_variables = self
            .dictionary
            .keys()
            .chain(rhs.dictionary.keys())
            .map(Vec::len)
            .max()
            .unwrap_or(0);

        for (left_exponent, left_coefficient) in self.dictionary {
            for (right_exponent, right_coefficient) in &rhs.dictionary {
                let mut exponent = vec![0; num_variables];

                for (index, power) in left_exponent.iter().enumerate() {
                    exponent[index] += power;
                }

                for (index, power) in right_exponent.iter().enumerate() {
                    exponent[index] += power;
                }

                let value = left_coefficient.clone() * right_coefficient.clone();
                dictionary
                    .entry(exponent)
                    .and_modify(|existing: &mut FieldElement| {
                        *existing = existing.clone() + value.clone();
                    })
                    .or_insert(value);
            }
        }

        Self::new(dictionary)
    }
}

impl BitXor<u64> for MPolynomial {
    type Output = Self;

    fn bitxor(self, rhs: u64) -> Self::Output {
        self.pow(rhs)
    }
}
