mod support;

use stark::rescue_prime::RescuePrime;
use stark::stark::Stark;

#[test]
fn trace_ends_at_hash_output() {
    let field = support::field();
    let rescue = RescuePrime::new();
    let input = field.from_u64(42);
    let output = rescue.hash(&input);
    let trace = rescue.trace(&input);

    assert_eq!(trace.len(), rescue.rounds() + 1);
    assert_eq!(trace.last().expect("trace should be non-empty")[0], output);
}

#[test]
fn transition_constraints_match_state_width() {
    let rescue = RescuePrime::new();
    let constraints = rescue.transition_constraints(&support::field().primitive_nth_root(64));
    assert_eq!(constraints.len(), rescue.state_width());
}

#[test]
fn signature_round_trip_and_document_binding() {
    let field = support::field();
    let rescue = RescuePrime::new();
    let stark = Stark::new(field.clone(), 4, 1, 2, rescue.state_width(), rescue.rounds() + 1, 3);

    let secret_key = field.from_u64(7);
    let public_key = rescue.hash(&secret_key);
    let trace = rescue.trace(&secret_key);
    let transition_constraints = rescue.transition_constraints(stark.omicron());
    let boundary_constraints = rescue.boundary_constraints(&public_key);

    let mut signing_stream = stark::rescue_prime::signature_proof_stream(b"hello world");
    let signature = stark.prove_with_stream(
        &trace,
        &transition_constraints,
        &boundary_constraints,
        &mut signing_stream,
    );

    let verification_stream = stark::rescue_prime::signature_proof_stream(b"hello world");
    assert!(stark.verify_with_stream(
        &signature,
        &transition_constraints,
        &boundary_constraints,
        &verification_stream,
    ));

    let wrong_document_stream = stark::rescue_prime::signature_proof_stream(b"wrong document");
    assert!(!stark.verify_with_stream(
        &signature,
        &transition_constraints,
        &boundary_constraints,
        &wrong_document_stream,
    ));
}
