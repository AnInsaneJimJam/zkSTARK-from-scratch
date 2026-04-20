//! # Polynomial
//!
//! Univariate polynomials over the prime field used by the STARK implementation.

pub mod multivariate;
pub use multivariate::MPolynomial;

use std::ops::{Add, BitXor, Div, Mul, Neg, Rem, Sub};

use crate::field::FieldElement;

/// A polynomial represented by coefficients in ascending degree order.
///
/// `coefficients[i]` stores the coefficient for `x^i`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<FieldElement>,
}

impl Polynomial {
    /// Creates a polynomial and removes trailing zero coefficients so the
    /// internal representation stays canonical.
    pub fn new(mut coefficients: Vec<FieldElement>) -> Self {
        while coefficients.last().is_some_and(FieldElement::is_zero) {
            coefficients.pop();
        }

        Self { coefficients }
    }

    /// Returns the coefficients in ascending degree order.
    pub fn coefficients(&self) -> &[FieldElement] {
        &self.coefficients
    }

    /// Returns the degree of the polynomial, or `-1` for the zero polynomial.
    pub fn degree(&self) -> isize {
        if self.coefficients.is_empty() {
            -1
        } else {
            (self.coefficients.len() - 1) as isize
        }
    }

    /// Returns `true` when this is the zero polynomial.
    pub fn is_zero(&self) -> bool {
        self.coefficients.is_empty()
    }

    /// Returns the leading coefficient, if the polynomial is non-zero.
    pub fn leading_coefficient(&self) -> Option<&FieldElement> {
        self.coefficients.last()
    }

    /// Raises the polynomial to a non-negative integer power.
    pub fn pow(&self, exponent: u64) -> Self {
        if self.is_zero() {
            return Polynomial::new(Vec::new());
        }

        let field = self.coefficients[0].field.clone();
        if exponent == 0 {
            return Polynomial::new(vec![field.one()]);
        }

        let mut acc = Polynomial::new(vec![field.one()]);
        for bit in (0..(64 - exponent.leading_zeros())).rev() {
            acc = acc.clone() * acc;
            if ((exponent >> bit) & 1) == 1 {
                acc = acc * self.clone();
            }
        }

        acc
    }

    /// Evaluates the polynomial at `point`.
    pub fn evaluate(&self, point: &FieldElement) -> FieldElement {
        let field = point.field.clone();
        let mut xi = field.one();
        let mut value = field.zero();

        for coefficient in &self.coefficients {
            value = value + coefficient.clone() * xi.clone();
            xi = xi * point.clone();
        }

        value
    }

    /// Evaluates the polynomial over a full domain.
    pub fn evaluate_domain(&self, domain: &[FieldElement]) -> Vec<FieldElement> {
        domain.iter().map(|point| self.evaluate(point)).collect()
    }

    /// Interpolates the unique polynomial that matches `values` on `domain`.
    pub fn interpolate_domain(domain: &[FieldElement], values: &[FieldElement]) -> Self {
        assert_eq!(
            domain.len(),
            values.len(),
            "number of elements in domain does not match number of values -- cannot interpolate"
        );
        assert!(
            !domain.is_empty(),
            "cannot interpolate between zero points"
        );

        let field = domain[0].field.clone();
        let x = Polynomial::new(vec![field.zero(), field.one()]);

        domain
            .iter()
            .zip(values.iter())
            .enumerate()
            .fold(Polynomial::new(Vec::new()), |acc, (i, (_, value))| {
                let basis = domain.iter().enumerate().fold(
                    Polynomial::new(vec![value.clone()]),
                    |product, (j, point)| {
                        if i == j {
                            return product;
                        }

                        let numerator = x.clone() - Polynomial::new(vec![point.clone()]);
                        let denominator_inverse = (domain[i].clone() - point.clone()).inverse();
                        product
                            * numerator
                            * Polynomial::new(vec![denominator_inverse])
                    },
                );

                acc + basis
            })
    }

    /// Returns the polynomial that vanishes on every point in `domain`.
    pub fn zerofier_domain(domain: &[FieldElement]) -> Self {
        assert!(!domain.is_empty(), "cannot construct zerofier for an empty domain");

        let field = domain[0].field.clone();
        let x = Polynomial::new(vec![field.zero(), field.one()]);

        domain.iter().cloned().fold(
            Polynomial::new(vec![field.one()]),
            |acc, point| acc * (x.clone() - Polynomial::new(vec![point])),
        )
    }

    /// Scales the indeterminate by `factor`, producing `f(factor * x)`.
    pub fn scale(&self, factor: &FieldElement) -> Self {
        Polynomial::new(
            self.coefficients
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, coefficient)| factor.pow(index as u64) * coefficient)
                .collect(),
        )
    }

    /// Divides `numerator` by `denominator`, returning `(quotient, remainder)`.
    ///
    /// Returns `None` when dividing by the zero polynomial.
    pub fn divide(numerator: &Self, denominator: &Self) -> Option<(Self, Self)> {
        if denominator.is_zero() {
            return None;
        }

        if numerator.degree() < denominator.degree() {
            return Some((Polynomial::new(Vec::new()), numerator.clone()));
        }

        let field = denominator.coefficients[0].field.clone();
        let mut remainder = numerator.clone();
        let mut quotient_coefficients =
            vec![field.zero(); numerator.coefficients.len() - denominator.coefficients.len() + 1];

        while !remainder.is_zero() && remainder.degree() >= denominator.degree() {
            let coefficient = remainder
                .leading_coefficient()
                .expect("non-zero remainder must have a leading coefficient")
                .clone()
                / denominator
                    .leading_coefficient()
                    .expect("non-zero denominator must have a leading coefficient")
                    .clone();

            let shift = (remainder.degree() - denominator.degree()) as usize;
            let mut shifted_coefficients = vec![field.zero(); shift];
            shifted_coefficients.push(coefficient.clone());

            let subtractee = Polynomial::new(shifted_coefficients) * denominator.clone();
            quotient_coefficients[shift] = coefficient;
            remainder = remainder - subtractee;
        }

        Some((Polynomial::new(quotient_coefficients), remainder))
    }
}

impl Neg for Polynomial {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Polynomial::new(self.coefficients.into_iter().map(|coefficient| -coefficient).collect())
    }
}

impl Add for Polynomial {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        if self.is_zero() {
            return rhs;
        }
        if rhs.is_zero() {
            return self;
        }

        let field = self.coefficients[0].field.clone();
        let max_len = self.coefficients.len().max(rhs.coefficients.len());
        let mut coefficients = vec![field.zero(); max_len];

        for (index, coefficient) in self.coefficients.into_iter().enumerate() {
            coefficients[index] = coefficients[index].clone() + coefficient;
        }

        for (index, coefficient) in rhs.coefficients.into_iter().enumerate() {
            coefficients[index] = coefficients[index].clone() + coefficient;
        }

        Polynomial::new(coefficients)
    }
}

impl Sub for Polynomial {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self + (-rhs)
    }
}

impl Mul for Polynomial {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        if self.is_zero() || rhs.is_zero() {
            return Polynomial::new(Vec::new());
        }

        let zero = self.coefficients[0].field.zero();
        let mut coefficients = vec![zero; self.coefficients.len() + rhs.coefficients.len() - 1];

        for (i, left) in self.coefficients.into_iter().enumerate() {
            if left.is_zero() {
                continue;
            }

            for (j, right) in rhs.coefficients.iter().cloned().enumerate() {
                coefficients[i + j] =
                    coefficients[i + j].clone() + left.clone() * right;
            }
        }

        Polynomial::new(coefficients)
    }
}

impl Div for Polynomial {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let (quotient, remainder) =
            Polynomial::divide(&self, &rhs).expect("cannot divide by the zero polynomial");
        assert!(
            remainder.is_zero(),
            "cannot perform polynomial division because remainder is not zero"
        );
        quotient
    }
}

impl Rem for Polynomial {
    type Output = Self;

    fn rem(self, rhs: Self) -> Self::Output {
        let (_, remainder) =
            Polynomial::divide(&self, &rhs).expect("cannot divide by the zero polynomial");
        remainder
    }
}

impl BitXor<u64> for Polynomial {
    type Output = Self;

    fn bitxor(self, rhs: u64) -> Self::Output {
        self.pow(rhs)
    }
}

/// Returns `true` when all points lie on a line.
pub fn test_colinearity(points: &[(FieldElement, FieldElement)]) -> bool {
    let domain: Vec<_> = points.iter().map(|(x, _)| x.clone()).collect();
    let values: Vec<_> = points.iter().map(|(_, y)| y.clone()).collect();
    Polynomial::interpolate_domain(&domain, &values).degree() <= 1
}
