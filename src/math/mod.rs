//! # Math utilities
//!
//! Low-level mathematical primitives used by the field arithmetic layer.

use num_bigint::BigInt;
use num_traits::Zero;

/// Extended Greatest Common Divisor (XGCD) algorithm.
///
/// Given integers `x` and `y` this function returns the tuple `(a, b, g)` such that:
///
/// ```text
/// a·x + b·y = g     where g = gcd(x, y)
/// ```
///
/// This is the Bézout-coefficient form of the Euclidean algorithm, used to compute
/// modular inverses: if `gcd(x, p) = 1` then `a` is the inverse of `x` modulo `p`.
///
/// # Examples
///
/// ```
/// # use num_bigint::BigInt;
/// # use stark::math::xgcd;
/// let (a, b, g) = xgcd(&BigInt::from(3), &BigInt::from(7));
/// // 3 and 7 are coprime → g == 1
/// assert_eq!(g, BigInt::from(1));
/// // Check Bézout's identity
/// assert_eq!(&a * 3 + &b * 7, BigInt::from(1));
/// ```
///
/// # Arguments
///
/// * `x` - First integer.
/// * `y` - Second integer (typically the field prime `p`).
///
/// # Returns
///
/// `(a, b, g)` where `a·x + b·y = g = gcd(x, y)`.
pub fn xgcd(x: &BigInt, y: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut old_r, mut r) = (x.clone(), y.clone());
    let (mut old_s, mut s) = (BigInt::from(1), BigInt::zero());
    let (mut old_t, mut t) = (BigInt::zero(), BigInt::from(1));

    while !r.is_zero() {
        let quotient = &old_r / &r;

        let new_r = &old_r - &quotient * &r;
        old_r = r;
        r = new_r;

        let new_s = &old_s - &quotient * &s;
        old_s = s;
        s = new_s;

        let new_t = &old_t - &quotient * &t;
        old_t = t;
        t = new_t;
    }

    (old_s, old_t, old_r) // (a, b, gcd)
}
