mod support;

use stark::polynomial::{Polynomial, test_colinearity};

fn poly(values: &[u64]) -> Polynomial {
    let field = support::field();
    Polynomial::new(values.iter().map(|&value| field.from_u64(value)).collect())
}

#[test]
fn degree_of_zero_polynomial_is_negative_one() {
    assert_eq!(Polynomial::new(Vec::new()).degree(), -1);
    assert_eq!(poly(&[0, 0, 0]).degree(), -1);
}

#[test]
fn canonicalizes_trailing_zeros() {
    assert_eq!(poly(&[1, 2, 0, 0]), poly(&[1, 2]));
}

#[test]
fn addition_handles_different_lengths() {
    assert_eq!(poly(&[1, 2]) + poly(&[3]), poly(&[4, 2]));
}

#[test]
fn subtraction_round_trip() {
    let a = poly(&[5, 4, 3]);
    let b = poly(&[2, 1]);
    assert_eq!(a.clone() - b.clone() + b, a);
}

#[test]
fn multiplication_matches_schoolbook_product() {
    assert_eq!(poly(&[1, 2]) * poly(&[3, 4]), poly(&[3, 10, 8]));
}

#[test]
fn exponentiation_matches_expected_polynomial() {
    assert_eq!(poly(&[1, 1]).pow(3), poly(&[1, 3, 3, 1]));
}

#[test]
fn evaluates_at_point() {
    let field = support::field();
    assert_eq!(
        poly(&[5, 2, 3]).evaluate(&field.from_u64(2)),
        field.from_u64(21)
    );
}

#[test]
fn evaluates_on_domain() {
    let field = support::field();
    let values = poly(&[1, 1]).evaluate_domain(&[field.from_u64(0), field.from_u64(1)]);
    assert_eq!(values, vec![field.from_u64(1), field.from_u64(2)]);
}

#[test]
fn interpolation_recovers_polynomial() {
    let field = support::field();
    let polynomial = poly(&[3, 1, 4]);
    let domain = vec![field.from_u64(0), field.from_u64(1), field.from_u64(2)];
    let values = polynomial.evaluate_domain(&domain);

    assert_eq!(Polynomial::interpolate_domain(&domain, &values), polynomial);
}

#[test]
fn zerofier_vanishes_on_domain() {
    let field = support::field();
    let domain = vec![field.from_u64(3), field.from_u64(5)];
    let zerofier = Polynomial::zerofier_domain(&domain);

    for point in domain {
        assert!(zerofier.evaluate(&point).is_zero());
    }
}

#[test]
fn scaling_reweights_coefficients() {
    let field = support::field();
    assert_eq!(poly(&[1, 2, 3]).scale(&field.from_u64(2)), poly(&[1, 4, 12]));
}

#[test]
fn leading_coefficient_is_last_non_zero_term() {
    let field = support::field();
    let polynomial = poly(&[7, 0, 9, 0]);

    assert_eq!(polynomial.leading_coefficient(), Some(&field.from_u64(9)));
}

#[test]
fn divide_returns_quotient_and_remainder() {
    let numerator = poly(&[1, 3, 3, 1]);
    let denominator = poly(&[1, 1]);

    let (quotient, remainder) =
        Polynomial::divide(&numerator, &denominator).expect("division should succeed");

    assert_eq!(quotient, poly(&[1, 2, 1]));
    assert!(remainder.is_zero());
}

#[test]
fn divide_returns_none_for_zero_denominator() {
    assert!(Polynomial::divide(&poly(&[1, 2]), &Polynomial::new(Vec::new())).is_none());
}

#[test]
fn div_operator_requires_zero_remainder() {
    let quotient = poly(&[1, 3, 3, 1]) / poly(&[1, 1]);
    assert_eq!(quotient, poly(&[1, 2, 1]));
}

#[test]
fn rem_operator_returns_remainder() {
    let remainder = poly(&[1, 0, 1]) % poly(&[1, 1]);
    assert_eq!(remainder, poly(&[2]));
}

#[test]
#[should_panic(expected = "cannot perform polynomial division because remainder is not zero")]
fn div_operator_panics_when_remainder_is_non_zero() {
    let _ = poly(&[1, 0, 1]) / poly(&[1, 1]);
}

#[test]
fn colinearity_detects_lines() {
    let field = support::field();
    let points = vec![
        (field.from_u64(0), field.from_u64(1)),
        (field.from_u64(1), field.from_u64(3)),
        (field.from_u64(2), field.from_u64(5)),
    ];

    assert!(test_colinearity(&points));
}

#[test]
fn colinearity_rejects_non_lines() {
    let field = support::field();
    let points = vec![
        (field.from_u64(0), field.from_u64(1)),
        (field.from_u64(1), field.from_u64(2)),
        (field.from_u64(2), field.from_u64(5)),
    ];

    assert!(!test_colinearity(&points));
}
