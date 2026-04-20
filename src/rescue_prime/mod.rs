//! # Rescue-Prime
//!
//! Rescue-Prime hash and the RPSSS signature wrapper built on the STARK layer.

mod constants;

use std::sync::Arc;

use blake2::{Blake2s256, Digest};
use num_bigint::BigUint;
use rand::{TryRngCore, rngs::OsRng};

use crate::field::{Field, FieldElement};
use crate::polynomial::{MPolynomial, Polynomial};
use crate::stark::{BoundaryConstraint, Stark, StarkProofStream};

/// Rescue-Prime hash over the STARK field.
#[derive(Clone, Debug)]
pub struct RescuePrime {
    field: Arc<Field>,
    m: usize,
    rate: usize,
    _capacity: usize,
    n: usize,
    alpha: u64,
    alpha_inv: BigUint,
    mds: Vec<Vec<FieldElement>>,
    mds_inv: Vec<Vec<FieldElement>>,
    round_constants: Vec<FieldElement>,
}

impl RescuePrime {
    /// Creates the fixed Rescue-Prime instance used by RPSSS.
    pub fn new() -> Self {
        let field = Arc::new(Field::main());
        let m = 2;
        let rate = 1;
        let capacity = 1;
        let n = 27;
        let alpha = 3;
        let alpha_inv = "180331931428153586757283157844700080811"
            .parse()
            .expect("invalid alpha inverse");
        let mds = constants::MDS
            .iter()
            .map(|row| row.iter().map(|value| field.element_from_str(value)).collect())
            .collect();
        let mds_inv = constants::MDS_INV
            .iter()
            .map(|row| row.iter().map(|value| field.element_from_str(value)).collect())
            .collect();
        let round_constants = constants::ROUND_CONSTANTS
            .iter()
            .map(|value| field.element_from_str(value))
            .collect();

        Self {
            field,
            m,
            rate,
            _capacity: capacity,
            n,
            alpha,
            alpha_inv,
            mds,
            mds_inv,
            round_constants,
        }
    }

    /// Hashes one field element.
    pub fn hash(&self, input_element: &FieldElement) -> FieldElement {
        let mut state = vec![input_element.clone()];
        state.extend(std::iter::repeat_with(|| self.field.zero()).take(self.m - 1));

        for round in 0..self.n {
            self.apply_sbox(&mut state, false);
            state = self.apply_mds(&self.mds, &state);
            state = (0..self.m)
                .map(|index| state[index].clone() + self.round_constants[2 * round * self.m + index].clone())
                .collect();

            self.apply_sbox(&mut state, true);
            state = self.apply_mds(&self.mds, &state);
            state = (0..self.m)
                .map(|index| {
                    state[index].clone()
                        + self.round_constants[2 * round * self.m + self.m + index].clone()
                })
                .collect();
        }

        state[0].clone()
    }

    /// Interpolates round-constant polynomials over the supplied cycle root.
    pub fn round_constants_polynomials(&self, omicron: &FieldElement) -> (Vec<MPolynomial>, Vec<MPolynomial>) {
        let first = (0..self.m)
            .map(|column| {
                let domain = (0..self.n).map(|round| omicron.pow(round as u64)).collect::<Vec<_>>();
                let values = (0..self.n)
                    .map(|round| self.round_constants[2 * round * self.m + column].clone())
                    .collect::<Vec<_>>();
                MPolynomial::lift(&Polynomial::interpolate_domain(&domain, &values), 0)
            })
            .collect::<Vec<_>>();

        let second = (0..self.m)
            .map(|column| {
                let domain = (0..self.n).map(|round| omicron.pow(round as u64)).collect::<Vec<_>>();
                let values = (0..self.n)
                    .map(|round| self.round_constants[2 * round * self.m + self.m + column].clone())
                    .collect::<Vec<_>>();
                MPolynomial::lift(&Polynomial::interpolate_domain(&domain, &values), 0)
            })
            .collect::<Vec<_>>();

        (first, second)
    }

    /// Returns the AIR transition constraints for Rescue-Prime.
    pub fn transition_constraints(&self, omicron: &FieldElement) -> Vec<MPolynomial> {
        let (first_step_constants, second_step_constants) = self.round_constants_polynomials(omicron);
        let variables = MPolynomial::variables(1 + 2 * self.m, &self.field);
        let previous_state = &variables[1..(1 + self.m)];
        let next_state = &variables[(1 + self.m)..(1 + 2 * self.m)];

        (0..self.m)
            .map(|row| {
                let lhs = (0..self.m).fold(MPolynomial::constant(self.field.zero()), |acc, column| {
                    acc + MPolynomial::constant(self.mds[row][column].clone())
                        * previous_state[column].clone().pow(self.alpha)
                }) + first_step_constants[row].clone();

                let rhs_linear =
                    (0..self.m).fold(MPolynomial::constant(self.field.zero()), |acc, column| {
                        acc + MPolynomial::constant(self.mds_inv[row][column].clone())
                            * (next_state[column].clone() - second_step_constants[column].clone())
                    });

                lhs - rhs_linear.pow(self.alpha)
            })
            .collect()
    }

    /// Returns boundary constraints for the start and end of the Rescue-Prime trace.
    pub fn boundary_constraints(&self, output_element: &FieldElement) -> Vec<BoundaryConstraint> {
        vec![
            (0, self.rate, self.field.zero()),
            (self.n, 0, output_element.clone()),
        ]
    }

    /// Returns the execution trace for hashing one field element.
    pub fn trace(&self, input_element: &FieldElement) -> Vec<Vec<FieldElement>> {
        let mut trace = Vec::new();
        let mut state = vec![input_element.clone()];
        state.extend(std::iter::repeat_with(|| self.field.zero()).take(self.m - 1));
        trace.push(state.clone());

        for round in 0..self.n {
            self.apply_sbox(&mut state, false);
            state = self.apply_mds(&self.mds, &state);
            state = (0..self.m)
                .map(|index| state[index].clone() + self.round_constants[2 * round * self.m + index].clone())
                .collect();

            self.apply_sbox(&mut state, true);
            state = self.apply_mds(&self.mds, &state);
            state = (0..self.m)
                .map(|index| {
                    state[index].clone()
                        + self.round_constants[2 * round * self.m + self.m + index].clone()
                })
                .collect();
            trace.push(state.clone());
        }

        trace
    }

    /// Returns the state width.
    pub fn state_width(&self) -> usize {
        self.m
    }

    /// Returns the number of permutation rounds.
    pub fn rounds(&self) -> usize {
        self.n
    }

    fn apply_sbox(&self, state: &mut [FieldElement], inverse: bool) {
        for value in state {
            *value = if inverse {
                value.pow_biguint(&self.alpha_inv)
            } else {
                value.pow(self.alpha)
            };
        }
    }

    fn apply_mds(&self, matrix: &[Vec<FieldElement>], state: &[FieldElement]) -> Vec<FieldElement> {
        (0..self.m)
            .map(|row| {
                (0..self.m).fold(self.field.zero(), |acc, column| {
                    acc + matrix[row][column].clone() * state[column].clone()
                })
            })
            .collect()
    }
}

impl Default for RescuePrime {
    fn default() -> Self {
        Self::new()
    }
}

/// Rescue-Prime STARK-based signature scheme.
#[derive(Clone, Debug)]
pub struct RPSSS {
    field: Arc<Field>,
    rp: RescuePrime,
    stark: Stark,
}

impl RPSSS {
    /// Creates the signature scheme with default parameters.
    pub fn new() -> Self {
        let field = Arc::new(Field::main());
        let expansion_factor = 4;
        let num_colinearity_checks = 64;
        let security_level = 2 * num_colinearity_checks;

        let rp = RescuePrime::new();
        let num_cycles = rp.rounds() + 1;
        let state_width = rp.state_width();
        let stark = Stark::new(
            field.clone(),
            expansion_factor,
            num_colinearity_checks,
            security_level,
            state_width,
            num_cycles,
            3,
        );

        Self { field, rp, stark }
    }

    /// Produces a STARK proof for preimage knowledge.
    pub fn stark_prove(&self, input_element: &FieldElement, proof_stream: &mut StarkProofStream) -> Vec<u8> {
        let output_element = self.rp.hash(input_element);
        let trace = self.rp.trace(input_element);
        let transition_constraints = self.rp.transition_constraints(self.stark.omicron());
        let boundary_constraints = self.rp.boundary_constraints(&output_element);
        self.stark
            .prove_with_stream(&trace, &transition_constraints, &boundary_constraints, proof_stream)
    }

    /// Verifies a STARK proof for preimage knowledge.
    pub fn stark_verify(
        &self,
        output_element: &FieldElement,
        stark_proof: &[u8],
        proof_stream: &StarkProofStream,
    ) -> bool {
        let boundary_constraints = self.rp.boundary_constraints(output_element);
        let transition_constraints = self.rp.transition_constraints(self.stark.omicron());
        self.stark.verify_with_stream(
            stark_proof,
            &transition_constraints,
            &boundary_constraints,
            proof_stream,
        )
    }

    /// Generates a signing key and public key.
    pub fn keygen(&self) -> (FieldElement, FieldElement) {
        let secret_key = self.field.sample(&sample_os_random_bytes(17));
        let public_key = self.rp.hash(&secret_key);
        (secret_key, public_key)
    }

    /// Signs a document.
    pub fn sign(&self, secret_key: &FieldElement, document: &[u8]) -> Vec<u8> {
        let mut stream = signature_proof_stream(document);
        self.stark_prove(secret_key, &mut stream)
    }

    /// Verifies a document signature.
    pub fn verify(&self, public_key: &FieldElement, document: &[u8], signature: &[u8]) -> bool {
        let stream = signature_proof_stream(document);
        self.stark_verify(public_key, signature, &stream)
    }

    /// Returns the underlying Rescue-Prime instance.
    pub fn rescue_prime(&self) -> &RescuePrime {
        &self.rp
    }
}

impl Default for RPSSS {
    fn default() -> Self {
        Self::new()
    }
}

/// Constructs a prefixed proof stream for document-bound Fiat-Shamir.
pub fn signature_proof_stream(document: &[u8]) -> StarkProofStream {
    let mut hasher = Blake2s256::new();
    hasher.update(document);
    StarkProofStream::with_prefix(hasher.finalize().to_vec())
}

fn sample_os_random_bytes(num_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; num_bytes];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("operating system randomness should be available");
    bytes
}
