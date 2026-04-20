mod support;

use stark::fri::{Fri, FriProofStream};
use stark::polynomial::Polynomial;

fn sample_polynomial(values: &[u64]) -> Polynomial {
    let field = support::field();
    Polynomial::new(values.iter().map(|&value| field.from_u64(value)).collect())
}

#[test]
fn num_rounds_and_eval_domain_match_configuration() {
    let field = support::field();
    let fri = Fri::new(
        field.one(),
        field.primitive_nth_root(16),
        16,
        2,
        1,
    );

    assert_eq!(fri.num_rounds(), 2);
    assert_eq!(fri.eval_domain().len(), 16);
}

#[test]
fn sample_indices_are_unique_modulo_reduced_size() {
    let field = support::field();
    let fri = Fri::new(
        field.one(),
        field.primitive_nth_root(16),
        16,
        2,
        2,
    );

    let indices = fri.sample_indices(b"seed", 8, 4, 2);
    assert_eq!(indices.len(), 2);
    assert_ne!(indices[0] % 4, indices[1] % 4);
}

#[test]
fn prove_and_verify_round_trip() {
    let field = support::field();
    let fri = Fri::new(
        field.one(),
        field.primitive_nth_root(16),
        16,
        2,
        1,
    );
    let domain = fri.eval_domain();
    let polynomial = sample_polynomial(&[3, 1, 4, 1]);
    let codeword = polynomial.evaluate_domain(&domain);

    let mut prover_stream = FriProofStream::new();
    let sampled_indices = fri.prove(&codeword, &mut prover_stream);
    assert_eq!(sampled_indices.len(), 1);

    let serialized = prover_stream.serialize();
    let mut verifier_stream = FriProofStream::deserialize(&serialized);
    let mut polynomial_values = Vec::new();

    assert!(fri.verify(&mut verifier_stream, &mut polynomial_values));
    assert_eq!(polynomial_values.len(), 2);
}
