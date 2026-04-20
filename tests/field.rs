mod support;

use stark::field::Field;

#[test]
fn zero_and_one() {
    let f = support::field();
    assert!(f.zero().is_zero());
    assert!(!f.one().is_zero());
}

#[test]
fn add_sub_roundtrip() {
    let f = support::field();
    let a = f.from_u64(42);
    let b = f.from_u64(13);
    assert_eq!(a.clone() + b.clone() - b.clone(), a);
}

#[test]
fn mul_div_roundtrip() {
    let f = support::field();
    let a = f.from_u64(1337);
    let b = f.from_u64(7);
    assert_eq!(a.clone() * b.clone() / b.clone(), a);
}

#[test]
fn neg_is_additive_inverse() {
    let f = support::field();
    let a = f.from_u64(99);
    assert_eq!(a.clone() + (-a), f.zero());
}

#[test]
fn inverse_correctness() {
    let f = support::field();
    let a = f.from_u64(12345);
    assert_eq!(a.clone() * a.inverse(), f.one());
}

#[test]
fn pow_zero_is_one() {
    let f = support::field();
    let a = f.from_u64(999);
    assert_eq!(a.pow(0), f.one());
}

#[test]
fn pow_one_is_identity() {
    let f = support::field();
    let a = f.from_u64(7);
    assert_eq!(a.pow(1), f.from_u64(7));
}

#[test]
fn pow_small() {
    let f = support::field();
    let a = f.from_u64(2);
    assert_eq!(a.pow(10), f.from_u64(1024));
}

#[test]
fn display() {
    let f = support::field();
    assert_eq!(f.from_u64(42).to_string(), "42");
}

#[test]
fn to_bytes() {
    let f = support::field();
    assert_eq!(f.from_u64(7).to_bytes(), b"7".to_vec());
}

#[test]
fn primitive_root_of_unity() {
    let f = support::field();
    let root = f.primitive_nth_root(2);
    assert_eq!(root.pow(2), f.one());
    assert_ne!(root, f.one());
}

#[test]
fn sample() {
    let f = support::field();
    let bytes = vec![0x12, 0x34, 0x56];
    let elem = f.sample(&bytes);
    assert!(!elem.is_zero());
}

#[test]
#[should_panic(expected = "divide by zero")]
fn divide_by_zero_panics() {
    let f = support::field();
    f.divide(&f.one(), &f.zero());
}

#[test]
fn default_field_can_be_constructed() {
    let _ = Field::main();
}
