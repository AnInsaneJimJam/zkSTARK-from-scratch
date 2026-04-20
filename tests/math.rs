use num_bigint::BigInt;
use num_traits::One;
use stark::math::xgcd;

fn check_bezout(x: i64, y: i64) {
    let bx = BigInt::from(x);
    let by = BigInt::from(y);
    let (a, b, g) = xgcd(&bx, &by);
    assert_eq!(&a * &bx + &b * &by, g, "Bézout identity failed for ({x}, {y})");
}

#[test]
fn bezout_small_coprime() {
    check_bezout(3, 7);
    check_bezout(5, 11);
    check_bezout(17, 31);
}

#[test]
fn bezout_non_trivial_gcd() {
    let (a, b, g) = xgcd(&BigInt::from(12), &BigInt::from(8));
    assert_eq!(g, BigInt::from(4));
    assert_eq!(&a * 12 + &b * 8, BigInt::from(4));
}

#[test]
fn gcd_coprime_is_one() {
    let (_, _, g) = xgcd(&BigInt::from(13), &BigInt::from(17));
    assert_eq!(g, BigInt::one());
}

#[test]
fn inverse_via_xgcd() {
    let p = BigInt::from(7i64);
    let (a, _, _) = xgcd(&BigInt::from(3i64), &p);
    let inv = ((a % &p) + &p) % &p;
    assert_eq!(inv, BigInt::from(5));
}
