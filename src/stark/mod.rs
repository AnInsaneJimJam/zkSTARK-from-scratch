//! # STARK
//!
//! High-level proving and verification logic built on top of the field,
//! polynomial, Merkle, and FRI layers.

use blake2::{Blake2b512, Digest};
use rand::{TryRngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};

use crate::crypto::{Merkle, ProofStream};
use crate::field::{Field, FieldElement};
use crate::fri::{Fri, FriProofStream};
use crate::polynomial::{MPolynomial, Polynomial};

/// Boundary condition `(cycle, register, value)`.
pub type BoundaryConstraint = (usize, usize, FieldElement);

/// Top-level proof stream items used by the STARK protocol.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StarkProofItem {
    BoundaryQuotientRoot(Vec<u8>),
    RandomizerRoot(Vec<u8>),
    FriProof(Vec<u8>),
    FieldElement(FieldElement),
    AuthenticationPath(Vec<Vec<u8>>),
}

/// A proof stream specialized for STARK proofs.
pub type StarkProofStream = ProofStream<StarkProofItem>;

/// STARK protocol configuration.
#[derive(Clone, Debug)]
pub struct Stark {
    field: std::sync::Arc<Field>,
    expansion_factor: usize,
    security_level: usize,
    num_randomizers: usize,
    num_registers: usize,
    original_trace_length: usize,
    generator: FieldElement,
    omega: FieldElement,
    omicron: FieldElement,
    omicron_domain: Vec<FieldElement>,
    fri: Fri,
}

impl Stark {
    /// Creates a new STARK parameter set.
    pub fn new(
        field: std::sync::Arc<Field>,
        expansion_factor: usize,
        num_colinearity_checks: usize,
        security_level: usize,
        num_registers: usize,
        num_cycles: usize,
        transition_constraints_degree: usize,
    ) -> Self {
        assert!(
            field.p.bits() >= security_level as u64,
            "p must have at least as many bits as security level"
        );
        assert!(
            expansion_factor.is_power_of_two(),
            "expansion factor must be a power of 2"
        );
        assert!(expansion_factor >= 4, "expansion factor must be 4 or greater");
        assert!(
            num_colinearity_checks * 2 >= security_level,
            "number of colinearity checks must be at least half of security level"
        );

        let num_randomizers = 4 * num_colinearity_checks;
        let randomized_trace_length = num_cycles + num_randomizers;
        let omicron_domain_length =
            1usize << bit_length(randomized_trace_length * transition_constraints_degree);
        let fri_domain_length = omicron_domain_length * expansion_factor;

        let generator = field.generator();
        let omega = field.primitive_nth_root(fri_domain_length as u64);
        let omicron = field.primitive_nth_root(omicron_domain_length as u64);
        let omicron_domain = (0..omicron_domain_length)
            .map(|index| omicron.pow(index as u64))
            .collect::<Vec<_>>();
        let fri = Fri::new(
            generator.clone(),
            omega.clone(),
            fri_domain_length,
            expansion_factor,
            num_colinearity_checks,
        );

        Self {
            field,
            expansion_factor,
            security_level,
            num_randomizers,
            num_registers,
            original_trace_length: num_cycles,
            generator,
            omega,
            omicron,
            omicron_domain,
            fri,
        }
    }

    /// Returns the transition degree bounds for each transition constraint.
    pub fn transition_degree_bounds(&self, transition_constraints: &[MPolynomial]) -> Vec<usize> {
        let point_degrees = std::iter::once(1usize)
            .chain(
                std::iter::repeat_n(
                    self.original_trace_length + self.num_randomizers - 1,
                    2 * self.num_registers,
                ),
            )
            .collect::<Vec<_>>();

        transition_constraints
            .iter()
            .map(|constraint| {
                constraint
                    .dictionary()
                    .iter()
                    .map(|(exponents, _)| {
                        point_degrees
                            .iter()
                            .zip(exponents.iter())
                            .map(|(degree, exponent)| degree * exponent)
                            .sum()
                    })
                    .max()
                    .unwrap_or(0)
            })
            .collect()
    }

    /// Returns quotient degree bounds for each transition constraint.
    pub fn transition_quotient_degree_bounds(
        &self,
        transition_constraints: &[MPolynomial],
    ) -> Vec<usize> {
        self.transition_degree_bounds(transition_constraints)
            .into_iter()
            .map(|degree| degree - (self.original_trace_length - 1))
            .collect()
    }

    /// Returns the maximum degree used for the nonlinear combination polynomial.
    pub fn max_degree(&self, transition_constraints: &[MPolynomial]) -> usize {
        let max_degree = self
            .transition_quotient_degree_bounds(transition_constraints)
            .into_iter()
            .max()
            .unwrap_or(0);

        if max_degree == 0 {
            0
        } else {
            (1usize << bit_length(max_degree)) - 1
        }
    }

    /// Returns the transition zerofier.
    pub fn transition_zerofier(&self) -> Polynomial {
        Polynomial::zerofier_domain(&self.omicron_domain[..(self.original_trace_length - 1)])
    }

    /// Returns the boundary zerofier for each register.
    pub fn boundary_zerofiers(&self, boundary: &[BoundaryConstraint]) -> Vec<Polynomial> {
        (0..self.num_registers)
            .map(|register| {
                let points = boundary
                    .iter()
                    .filter(|(_, r, _)| *r == register)
                    .map(|(cycle, _, _)| self.omicron.pow(*cycle as u64))
                    .collect::<Vec<_>>();

                if points.is_empty() {
                    Polynomial::new(vec![self.field.one()])
                } else {
                    Polynomial::zerofier_domain(&points)
                }
            })
            .collect()
    }

    /// Returns the boundary interpolant for each register.
    pub fn boundary_interpolants(&self, boundary: &[BoundaryConstraint]) -> Vec<Polynomial> {
        (0..self.num_registers)
            .map(|register| {
                let points = boundary
                    .iter()
                    .filter(|(_, r, _)| *r == register)
                    .map(|(cycle, _, value)| (self.omicron.pow(*cycle as u64), value.clone()))
                    .collect::<Vec<_>>();

                if points.is_empty() {
                    Polynomial::new(Vec::new())
                } else {
                    let domain = points.iter().map(|(point, _)| point.clone()).collect::<Vec<_>>();
                    let values = points.iter().map(|(_, value)| value.clone()).collect::<Vec<_>>();
                    Polynomial::interpolate_domain(&domain, &values)
                }
            })
            .collect()
    }

    /// Returns boundary quotient degree bounds.
    pub fn boundary_quotient_degree_bounds(
        &self,
        randomized_trace_length: usize,
        boundary: &[BoundaryConstraint],
    ) -> Vec<usize> {
        let randomized_trace_degree = randomized_trace_length - 1;
        self.boundary_zerofiers(boundary)
            .into_iter()
            .map(|zerofier| randomized_trace_degree - zerofier.degree().max(0) as usize)
            .collect()
    }

    /// Samples random linear combination weights from transcript randomness.
    pub fn sample_weights(&self, number: usize, randomness: &[u8]) -> Vec<FieldElement> {
        (0..number)
            .map(|index| {
                let mut hasher = Blake2b512::new();
                hasher.update(randomness);
                hasher.update(vec![0u8; index]);
                self.field.sample(hasher.finalize().as_slice())
            })
            .collect()
    }

    /// Produces a STARK proof.
    pub fn prove(
        &self,
        trace: &[Vec<FieldElement>],
        transition_constraints: &[MPolynomial],
        boundary: &[BoundaryConstraint],
    ) -> Vec<u8> {
        let mut proof_stream = StarkProofStream::new();
        self.prove_with_stream(trace, transition_constraints, boundary, &mut proof_stream)
    }

    /// Produces a STARK proof into a caller-provided transcript.
    pub fn prove_with_stream(
        &self,
        trace: &[Vec<FieldElement>],
        transition_constraints: &[MPolynomial],
        boundary: &[BoundaryConstraint],
        proof_stream: &mut StarkProofStream,
    ) -> Vec<u8> {
        let mut randomized_trace = trace.to_vec();

        for _ in 0..self.num_randomizers {
            randomized_trace.push(
                (0..self.num_registers)
                    .map(|_| self.field.sample(&sample_os_random_bytes(17)))
                    .collect(),
            );
        }

        let trace_domain = (0..randomized_trace.len())
            .map(|index| self.omicron.pow(index as u64))
            .collect::<Vec<_>>();
        let trace_polynomials = (0..self.num_registers)
            .map(|register| {
                let register_trace = randomized_trace
                    .iter()
                    .map(|row| row[register].clone())
                    .collect::<Vec<_>>();
                Polynomial::interpolate_domain(&trace_domain, &register_trace)
            })
            .collect::<Vec<_>>();

        let boundary_interpolants = self.boundary_interpolants(boundary);
        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        let boundary_quotients = (0..self.num_registers)
            .map(|register| {
                (trace_polynomials[register].clone() - boundary_interpolants[register].clone())
                    / boundary_zerofiers[register].clone()
            })
            .collect::<Vec<_>>();

        let fri_domain = self.fri.eval_domain();
        let boundary_quotient_codewords = boundary_quotients
            .iter()
            .map(|quotient| quotient.evaluate_domain(&fri_domain))
            .collect::<Vec<_>>();

        for codeword in &boundary_quotient_codewords {
            proof_stream.push(StarkProofItem::BoundaryQuotientRoot(
                merkle_commit_elements(codeword),
            ));
        }

        let symbolic_point = std::iter::once(Polynomial::new(vec![self.field.zero(), self.field.one()]))
            .chain(trace_polynomials.iter().cloned())
            .chain(trace_polynomials.iter().map(|polynomial| polynomial.scale(&self.omicron)))
            .collect::<Vec<_>>();
        let transition_polynomials = transition_constraints
            .iter()
            .map(|constraint| constraint.evaluate_symbolic(&symbolic_point))
            .collect::<Vec<_>>();
        let transition_quotients = transition_polynomials
            .iter()
            .map(|polynomial| polynomial.clone() / self.transition_zerofier())
            .collect::<Vec<_>>();

        let randomizer_polynomial = Polynomial::new(
            (0..=self.max_degree(transition_constraints))
                .map(|_| self.field.sample(&sample_os_random_bytes(17)))
                .collect(),
        );
        let randomizer_codeword = randomizer_polynomial.evaluate_domain(&fri_domain);
        proof_stream.push(StarkProofItem::RandomizerRoot(
            merkle_commit_elements(&randomizer_codeword),
        ));

        let weights = self.sample_weights(
            1 + 2 * transition_quotients.len() + 2 * boundary_quotients.len(),
            &proof_stream.prover_fiat_shamir(32),
        );

        assert_eq!(
            transition_quotients
                .iter()
                .map(|quotient| quotient.degree().max(0) as usize)
                .collect::<Vec<_>>(),
            self.transition_quotient_degree_bounds(transition_constraints),
            "transition quotient degrees do not match with expectation"
        );

        let x = Polynomial::new(vec![self.field.zero(), self.field.one()]);
        let transition_bounds = self.transition_quotient_degree_bounds(transition_constraints);
        let boundary_bounds =
            self.boundary_quotient_degree_bounds(randomized_trace.len(), boundary);

        let mut terms = vec![randomizer_polynomial];
        for (index, quotient) in transition_quotients.iter().enumerate() {
            terms.push(quotient.clone());
            let shift = self.max_degree(transition_constraints) - transition_bounds[index];
            terms.push(x.pow(shift as u64) * quotient.clone());
        }
        for (index, quotient) in boundary_quotients.iter().enumerate() {
            terms.push(quotient.clone());
            let shift = self.max_degree(transition_constraints) - boundary_bounds[index];
            terms.push(x.pow(shift as u64) * quotient.clone());
        }

        let combination = weights.iter().cloned().zip(terms).fold(
            Polynomial::new(Vec::new()),
            |accumulator, (weight, term)| accumulator + Polynomial::new(vec![weight]) * term,
        );
        let combined_codeword = combination.evaluate_domain(&fri_domain);

        let mut fri_stream = FriProofStream::with_prefix(proof_stream.prefix().to_vec());
        let mut indices = self.fri.prove(&combined_codeword, &mut fri_stream);
        proof_stream.push(StarkProofItem::FriProof(fri_stream.serialize()));

        indices.sort_unstable();
        let mut queried_indices = indices
            .iter()
            .cloned()
            .chain(indices.iter().map(|index| index + (self.fri.domain_length() / 2)))
            .collect::<Vec<_>>();
        queried_indices.sort_unstable();

        let duplicated_indices = queried_indices
            .iter()
            .cloned()
            .chain(
                queried_indices
                    .iter()
                    .map(|index| (index + self.expansion_factor) % self.fri.domain_length()),
            )
            .collect::<Vec<_>>();

        for codeword in &boundary_quotient_codewords {
            for index in &duplicated_indices {
                proof_stream.push(StarkProofItem::FieldElement(codeword[*index].clone()));
                proof_stream.push(StarkProofItem::AuthenticationPath(
                    merkle_open_elements(*index, codeword),
                ));
            }
        }

        for index in &queried_indices {
            proof_stream.push(StarkProofItem::FieldElement(randomizer_codeword[*index].clone()));
            proof_stream.push(StarkProofItem::AuthenticationPath(
                merkle_open_elements(*index, &randomizer_codeword),
            ));
        }

        proof_stream.serialize()
    }

    /// Verifies a STARK proof.
    pub fn verify(
        &self,
        proof: &[u8],
        transition_constraints: &[MPolynomial],
        boundary: &[BoundaryConstraint],
    ) -> bool {
        let proof_stream = StarkProofStream::new();
        self.verify_with_stream(proof, transition_constraints, boundary, &proof_stream)
    }

    /// Verifies a STARK proof using the Fiat-Shamir prefix from a caller-provided transcript.
    pub fn verify_with_stream(
        &self,
        proof: &[u8],
        transition_constraints: &[MPolynomial],
        boundary: &[BoundaryConstraint],
        proof_stream_template: &StarkProofStream,
    ) -> bool {
        let original_trace_length = 1 + boundary.iter().map(|(cycle, _, _)| *cycle).max().unwrap_or(0);
        let randomized_trace_length = original_trace_length + self.num_randomizers;

        let mut proof_stream =
            StarkProofStream::deserialize_with_prefix(proof, proof_stream_template.prefix().to_vec());
        let boundary_quotient_roots = (0..self.num_registers)
            .map(|_| match proof_stream.pull() {
                StarkProofItem::BoundaryQuotientRoot(root) => root,
                _ => panic!("expected boundary quotient Merkle root in proof stream"),
            })
            .collect::<Vec<_>>();
        let randomizer_root = match proof_stream.pull() {
            StarkProofItem::RandomizerRoot(root) => root,
            _ => panic!("expected randomizer Merkle root in proof stream"),
        };

        let weights = self.sample_weights(
            1 + 2 * transition_constraints.len() + 2 * self.boundary_interpolants(boundary).len(),
            &proof_stream.verifier_fiat_shamir(32),
        );

        let fri_proof = match proof_stream.pull() {
            StarkProofItem::FriProof(bytes) => bytes,
            _ => panic!("expected embedded FRI proof in proof stream"),
        };
        let mut fri_stream =
            FriProofStream::deserialize_with_prefix(&fri_proof, proof_stream.prefix().to_vec());
        let mut polynomial_values = Vec::new();
        if !self.fri.verify(&mut fri_stream, &mut polynomial_values) {
            return false;
        }
        polynomial_values.sort_by_key(|(index, _)| *index);

        let indices = polynomial_values
            .iter()
            .map(|(index, _)| *index)
            .collect::<Vec<_>>();
        let values = polynomial_values
            .iter()
            .map(|(_, value)| value.clone())
            .collect::<Vec<_>>();

        let duplicated_indices = indices
            .iter()
            .cloned()
            .chain(
                indices
                    .iter()
                    .map(|index| (index + self.expansion_factor) % self.fri.domain_length()),
            )
            .collect::<Vec<_>>();

        let mut leaves = (0..self.num_registers)
            .map(|_| std::collections::BTreeMap::new())
            .collect::<Vec<_>>();
        for (register, root) in boundary_quotient_roots.iter().enumerate() {
            for index in &duplicated_indices {
                let value = match proof_stream.pull() {
                    StarkProofItem::FieldElement(value) => value,
                    _ => panic!("expected boundary quotient leaf in proof stream"),
                };
                let path = match proof_stream.pull() {
                    StarkProofItem::AuthenticationPath(path) => path,
                    _ => panic!("expected boundary quotient path in proof stream"),
                };
                if !Merkle::verify(root, *index, &path, &value.to_bytes()) {
                    return false;
                }
                leaves[register].insert(*index, value);
            }
        }

        let mut randomizer = std::collections::BTreeMap::new();
        for index in &indices {
            let value = match proof_stream.pull() {
                StarkProofItem::FieldElement(value) => value,
                _ => panic!("expected randomizer leaf in proof stream"),
            };
            let path = match proof_stream.pull() {
                StarkProofItem::AuthenticationPath(path) => path,
                _ => panic!("expected randomizer path in proof stream"),
            };
            if !Merkle::verify(&randomizer_root, *index, &path, &value.to_bytes()) {
                return false;
            }
            randomizer.insert(*index, value);
        }

        let boundary_zerofiers = self.boundary_zerofiers(boundary);
        let boundary_interpolants = self.boundary_interpolants(boundary);
        let transition_zerofier = self.transition_zerofier();
        let transition_bounds = self.transition_quotient_degree_bounds(transition_constraints);
        let boundary_bounds =
            self.boundary_quotient_degree_bounds(randomized_trace_length, boundary);

        for (position, current_index) in indices.iter().enumerate() {
            let domain_current_index =
                self.generator.clone() * self.omega.pow(*current_index as u64);
            let next_index = (current_index + self.expansion_factor) % self.fri.domain_length();
            let domain_next_index =
                self.generator.clone() * self.omega.pow(next_index as u64);

            let mut current_trace = Vec::with_capacity(self.num_registers);
            let mut next_trace = Vec::with_capacity(self.num_registers);
            for register in 0..self.num_registers {
                let current_boundary_quotient = leaves[register]
                    .get(current_index)
                    .expect("missing boundary quotient opening")
                    .clone();
                let next_boundary_quotient = leaves[register]
                    .get(&next_index)
                    .expect("missing next boundary quotient opening")
                    .clone();

                current_trace.push(
                    current_boundary_quotient
                        * boundary_zerofiers[register].evaluate(&domain_current_index)
                        + boundary_interpolants[register].evaluate(&domain_current_index),
                );
                next_trace.push(
                    next_boundary_quotient
                        * boundary_zerofiers[register].evaluate(&domain_next_index)
                        + boundary_interpolants[register].evaluate(&domain_next_index),
                );
            }

            let point = std::iter::once(domain_current_index.clone())
                .chain(current_trace.iter().cloned())
                .chain(next_trace.iter().cloned())
                .collect::<Vec<_>>();
            let transition_values = transition_constraints
                .iter()
                .map(|constraint| constraint.evaluate(&point))
                .collect::<Vec<_>>();

            let mut terms = vec![
                randomizer
                    .get(current_index)
                    .expect("missing randomizer opening")
                    .clone(),
            ];
            for (index, transition_value) in transition_values.iter().enumerate() {
                let quotient =
                    transition_value.clone() / transition_zerofier.evaluate(&domain_current_index);
                terms.push(quotient.clone());
                let shift = self.max_degree(transition_constraints) - transition_bounds[index];
                terms.push(quotient * domain_current_index.pow(shift as u64));
            }
            for register in 0..self.num_registers {
                let boundary_value = leaves[register]
                    .get(current_index)
                    .expect("missing boundary quotient opening")
                    .clone();
                terms.push(boundary_value.clone());
                let shift = self.max_degree(transition_constraints) - boundary_bounds[register];
                terms.push(boundary_value * domain_current_index.pow(shift as u64));
            }

            let combination = terms
                .into_iter()
                .zip(weights.iter().cloned())
                .fold(self.field.zero(), |accumulator, (term, weight)| {
                    accumulator + term * weight
                });
            if combination != values[position] {
                return false;
            }
        }

        true
    }

    /// Returns the number of randomizer rows appended to the trace.
    pub fn num_randomizers(&self) -> usize {
        self.num_randomizers
    }

    /// Returns the configured security level.
    pub fn security_level(&self) -> usize {
        self.security_level
    }

    /// Returns the FRI base-domain generator used by the AIR.
    pub fn omicron(&self) -> &FieldElement {
        &self.omicron
    }
}

fn bit_length(value: usize) -> u32 {
    usize::BITS - value.leading_zeros()
}

fn sample_os_random_bytes(num_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; num_bytes];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("operating system randomness should be available");
    bytes
}

fn merkle_commit_elements(values: &[FieldElement]) -> Vec<u8> {
    Merkle::commit(&values.iter().map(FieldElement::to_bytes).collect::<Vec<_>>())
}

fn merkle_open_elements(index: usize, values: &[FieldElement]) -> Vec<Vec<u8>> {
    Merkle::open(index, &values.iter().map(FieldElement::to_bytes).collect::<Vec<_>>())
}
