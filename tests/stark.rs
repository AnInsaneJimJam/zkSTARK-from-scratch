mod support;

use stark::polynomial::MPolynomial;
use stark::stark::{Stark, StarkProofItem, StarkProofStream};

fn constant_trace_air() -> (Stark, Vec<MPolynomial>) {
    let field = support::field();
    let stark = Stark::new(field.clone(), 4, 1, 2, 1, 4, 2);
    let mut variables = MPolynomial::variables(3, &field);
    let current = variables.remove(1);
    let next = variables.remove(1);
    let transition_constraint = next - current;
    (stark, vec![transition_constraint])
}

fn constant_trace(value: u64, cycles: usize) -> Vec<Vec<stark::field::FieldElement>> {
    let field = support::field();
    (0..cycles)
        .map(|_| vec![field.from_u64(value)])
        .collect()
}

fn constant_boundary(value: u64, cycles: usize) -> Vec<(usize, usize, stark::field::FieldElement)> {
    let field = support::field();
    (0..cycles)
        .map(|cycle| (cycle, 0, field.from_u64(value)))
        .collect()
}

#[test]
fn constructor_derives_expected_parameters() {
    let (stark, _) = constant_trace_air();
    assert_eq!(stark.num_randomizers(), 4);
    assert_eq!(stark.security_level(), 2);
}

#[test]
fn prove_and_verify_round_trip() {
    let (stark, transition_constraints) = constant_trace_air();
    let trace = constant_trace(7, 4);
    let boundary = constant_boundary(7, 4);

    let proof = stark.prove(&trace, &transition_constraints, &boundary);
    assert!(stark.verify(&proof, &transition_constraints, &boundary));
}

#[test]
fn tampered_root_fails_verification() {
    let (stark, transition_constraints) = constant_trace_air();
    let trace = constant_trace(7, 4);
    let boundary = constant_boundary(7, 4);

    let proof = stark.prove(&trace, &transition_constraints, &boundary);
    let mut objects = StarkProofStream::deserialize(&proof).into_objects();
    match &mut objects[0] {
        StarkProofItem::BoundaryQuotientRoot(root) => root[0] ^= 1,
        _ => panic!("expected boundary quotient root"),
    }

    let tampered = StarkProofStream::from_objects(objects).serialize();
    assert!(!stark.verify(&tampered, &transition_constraints, &boundary));
}
