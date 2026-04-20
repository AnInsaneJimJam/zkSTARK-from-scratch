mod support;

use std::collections::BTreeMap;

use stark::polynomial::{MPolynomial, Polynomial};

fn poly(values: &[u64]) -> Polynomial {
    let field = support::field();
    Polynomial::new(values.iter().map(|&value| field.from_u64(value)).collect())
}

#[test]
fn addition_combines_like_terms() {
    let field = support::field();
    let left = MPolynomial::new(BTreeMap::from([(vec![1, 0], field.from_u64(2))]));
    let right = MPolynomial::new(BTreeMap::from([(vec![1], field.from_u64(3))]));

    assert_eq!(
        left + right,
        MPolynomial::new(BTreeMap::from([(vec![1], field.from_u64(5))]))
    );
}

#[test]
fn multiplication_adds_exponents() {
    let field = support::field();
    let left = MPolynomial::new(BTreeMap::from([(vec![1, 0], field.from_u64(2))]));
    let right = MPolynomial::new(BTreeMap::from([(vec![0, 1], field.from_u64(3))]));

    assert_eq!(
        left * right,
        MPolynomial::new(BTreeMap::from([(vec![1, 1], field.from_u64(6))]))
    );
}

#[test]
fn exponentiation_uses_repeated_squaring() {
    let field = support::field();
    let x = MPolynomial::variables(1, &field).remove(0);
    let cubic = x.pow(3);

    assert_eq!(cubic, MPolynomial::new(BTreeMap::from([(vec![3], field.one())])));
}

#[test]
fn lift_embeds_univariate_polynomial() {
    let field = support::field();
    let lifted = MPolynomial::lift(&poly(&[5, 0, 2]), 1);

    assert_eq!(
        lifted,
        MPolynomial::new(BTreeMap::from([
            (Vec::new(), field.from_u64(5)),
            (vec![0, 2], field.from_u64(2)),
        ]))
    );
}

#[test]
fn evaluates_at_field_point() {
    let field = support::field();
    let polynomial = MPolynomial::new(BTreeMap::from([
        (vec![2], field.from_u64(3)),
        (Vec::new(), field.from_u64(1)),
    ]));

    assert_eq!(polynomial.evaluate(&[field.from_u64(2)]), field.from_u64(13));
}

#[test]
fn evaluates_symbolically() {
    let field = support::field();
    let x = Polynomial::new(vec![field.zero(), field.one()]);
    let polynomial = MPolynomial::new(BTreeMap::from([
        (vec![2], field.from_u64(3)),
        (Vec::new(), field.from_u64(1)),
    ]));

    assert_eq!(polynomial.evaluate_symbolic(&[x]), poly(&[1, 0, 3]));
}

#[test]
fn zero_polynomial_is_empty() {
    let field = support::field();
    assert!(MPolynomial::zero().is_zero());
    assert!(MPolynomial::constant(field.from_u64(0)).is_zero());
    assert!(!MPolynomial::constant(field.from_u64(1)).is_zero());
}
