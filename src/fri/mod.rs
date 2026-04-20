//! # FRI
//!
//! Fast Reed-Solomon IOP of Proximity commitment and verification logic.

use blake2::{Blake2b512, Digest};
use serde::{Deserialize, Serialize};

use crate::crypto::{Merkle, ProofStream};
use crate::field::FieldElement;
use crate::polynomial::{Polynomial, test_colinearity};

/// Typed transcript objects emitted by the FRI prover and consumed by the verifier.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum FriProofItem {
    MerkleRoot(Vec<u8>),
    LastCodeword(Vec<FieldElement>),
    QueryValues(FieldElement, FieldElement, FieldElement),
    AuthenticationPath(Vec<Vec<u8>>),
}

/// A proof stream specialized for FRI transcripts.
pub type FriProofStream = ProofStream<FriProofItem>;

/// FRI protocol configuration and domain parameters.
#[derive(Clone, Debug)]
pub struct Fri {
    offset: FieldElement,
    omega: FieldElement,
    domain_length: usize,
    field: std::sync::Arc<crate::field::Field>,
    expansion_factor: usize,
    num_colinearity_tests: usize,
}

impl Fri {
    /// Creates a new FRI instance.
    pub fn new(
        offset: FieldElement,
        omega: FieldElement,
        initial_domain_length: usize,
        expansion_factor: usize,
        num_colinearity_tests: usize,
    ) -> Self {
        let field = omega.field.clone();
        Self {
            offset,
            omega,
            domain_length: initial_domain_length,
            field,
            expansion_factor,
            num_colinearity_tests,
        }
    }

    /// Returns the number of folding rounds.
    pub fn num_rounds(&self) -> usize {
        let mut codeword_length = self.domain_length;
        let mut num_rounds = 0;

        while codeword_length > self.expansion_factor
            && 4 * self.num_colinearity_tests < codeword_length
        {
            codeword_length /= 2;
            num_rounds += 1;
        }

        num_rounds
    }

    /// Returns the evaluation domain for the current FRI parameters.
    pub fn eval_domain(&self) -> Vec<FieldElement> {
        (0..self.domain_length)
            .map(|index| self.offset.clone() * self.omega.pow(index as u64))
            .collect()
    }

    /// Returns the FRI evaluation domain length.
    pub fn domain_length(&self) -> usize {
        self.domain_length
    }

    /// Produces a FRI proof for the supplied codeword.
    pub fn prove(
        &self,
        codeword: &[FieldElement],
        proof_stream: &mut FriProofStream,
    ) -> Vec<usize> {
        assert_eq!(
            self.domain_length,
            codeword.len(),
            "initial codeword length does not match length of initial codeword"
        );

        let codewords = self.commit(codeword.to_vec(), proof_stream);
        if codewords.len() <= 1 {
            return Vec::new();
        }

        let mut top_level_indices = self.sample_indices(
            &proof_stream.prover_fiat_shamir(32),
            codewords[1].len(),
            codewords
                .last()
                .expect("commit should return at least one codeword")
                .len(),
            self.num_colinearity_tests,
        );

        let mut indices = top_level_indices.clone();
        for round in 0..(codewords.len() - 1) {
            indices = indices
                .into_iter()
                .map(|index| index % (codewords[round].len() / 2))
                .collect();
            self.query(&codewords[round], &codewords[round + 1], &indices, proof_stream);
        }

        top_level_indices.shrink_to_fit();
        top_level_indices
    }

    /// Commits all FRI layers and returns the intermediate codewords.
    pub fn commit(
        &self,
        mut codeword: Vec<FieldElement>,
        proof_stream: &mut FriProofStream,
    ) -> Vec<Vec<FieldElement>> {
        let one = self.field.one();
        let two = self.field.from_u64(2);
        let mut omega = self.omega.clone();
        let mut offset = self.offset.clone();
        let mut codewords = Vec::new();
        let num_rounds = self.num_rounds();

        for round in 0..num_rounds {
            let root = merkle_commit_codeword(&codeword);
            proof_stream.push(FriProofItem::MerkleRoot(root));

            if round == num_rounds - 1 {
                break;
            }

            let alpha = self.field.sample(&proof_stream.prover_fiat_shamir(32));
            codewords.push(codeword.clone());

            codeword = (0..(codeword.len() / 2))
                .map(|index| {
                    let point = offset.clone() * omega.pow(index as u64);
                    let left_weight = one.clone() + alpha.clone() / point.clone();
                    let right_weight = one.clone() - alpha.clone() / point;

                    two.inverse()
                        * (left_weight * codeword[index].clone()
                            + right_weight * codeword[(codeword.len() / 2) + index].clone())
                })
                .collect();

            omega = omega.pow(2);
            offset = offset.pow(2);
        }

        proof_stream.push(FriProofItem::LastCodeword(codeword.clone()));
        codewords.push(codeword);
        codewords
    }

    /// Appends FRI query openings for one folding round.
    pub fn query(
        &self,
        current_codeword: &[FieldElement],
        next_codeword: &[FieldElement],
        c_indices: &[usize],
        proof_stream: &mut FriProofStream,
    ) -> Vec<usize> {
        let a_indices = c_indices.to_vec();
        let b_indices = c_indices
            .iter()
            .map(|index| index + (current_codeword.len() / 2))
            .collect::<Vec<_>>();

        for sample in 0..self.num_colinearity_tests {
            proof_stream.push(FriProofItem::QueryValues(
                current_codeword[a_indices[sample]].clone(),
                current_codeword[b_indices[sample]].clone(),
                next_codeword[c_indices[sample]].clone(),
            ));
        }

        for sample in 0..self.num_colinearity_tests {
            proof_stream.push(FriProofItem::AuthenticationPath(merkle_open_codeword(
                a_indices[sample],
                current_codeword,
            )));
            proof_stream.push(FriProofItem::AuthenticationPath(merkle_open_codeword(
                b_indices[sample],
                current_codeword,
            )));
            proof_stream.push(FriProofItem::AuthenticationPath(merkle_open_codeword(
                c_indices[sample],
                next_codeword,
            )));
        }

        [a_indices, b_indices].concat()
    }

    /// Samples a single index from a byte array.
    pub fn sample_index(byte_array: &[u8], size: usize) -> usize {
        let mut acc = 0usize;
        for byte in byte_array {
            acc = (acc << 8) ^ usize::from(*byte);
        }
        acc % size
    }

    /// Samples unique indices modulo the reduced codeword size.
    pub fn sample_indices(
        &self,
        seed: &[u8],
        size: usize,
        reduced_size: usize,
        number: usize,
    ) -> Vec<usize> {
        assert!(
            number <= 2 * reduced_size,
            "not enough entropy in indices wrt last codeword"
        );
        assert!(
            number <= reduced_size,
            "cannot sample more indices than available in last codeword; requested: {}, available: {}",
            number,
            reduced_size
        );

        let mut indices = Vec::new();
        let mut reduced_indices = Vec::new();
        let mut counter = 0usize;

        while indices.len() < number {
            let mut hasher = Blake2b512::new();
            hasher.update(seed);
            hasher.update(vec![0u8; counter]);

            let digest = hasher.finalize();
            let index = Self::sample_index(digest.as_slice(), size);
            let reduced_index = index % reduced_size;
            counter += 1;

            if !reduced_indices.contains(&reduced_index) {
                indices.push(index);
                reduced_indices.push(reduced_index);
            }
        }

        indices
    }

    /// Verifies a FRI proof and collects top-layer polynomial values.
    pub fn verify(
        &self,
        proof_stream: &mut FriProofStream,
        polynomial_values: &mut Vec<(usize, FieldElement)>,
    ) -> bool {
        let mut omega = self.omega.clone();
        let mut offset = self.offset.clone();

        let mut roots = Vec::new();
        let mut alphas = Vec::new();
        for _ in 0..self.num_rounds() {
            roots.push(match proof_stream.pull() {
                FriProofItem::MerkleRoot(root) => root,
                _ => panic!("expected FRI Merkle root in proof stream"),
            });
            alphas.push(self.field.sample(&proof_stream.verifier_fiat_shamir(32)));
        }

        let last_codeword = match proof_stream.pull() {
            FriProofItem::LastCodeword(codeword) => codeword,
            _ => panic!("expected final FRI codeword in proof stream"),
        };

        if roots.last() != Some(&merkle_commit_codeword(&last_codeword)) {
            return false;
        }

        let degree = (last_codeword.len() / self.expansion_factor) - 1;
        let mut last_omega = omega.clone();
        let mut last_offset = offset.clone();
        for _ in 0..self.num_rounds().saturating_sub(1) {
            last_omega = last_omega.pow(2);
            last_offset = last_offset.pow(2);
        }

        assert_eq!(
            last_omega.inverse(),
            last_omega.pow((last_codeword.len() - 1) as u64),
            "omega does not have right order"
        );

        let last_domain = (0..last_codeword.len())
            .map(|index| last_offset.clone() * last_omega.pow(index as u64))
            .collect::<Vec<_>>();
        let polynomial = Polynomial::interpolate_domain(&last_domain, &last_codeword);

        assert_eq!(
            polynomial.evaluate_domain(&last_domain),
            last_codeword,
            "re-evaluated codeword does not match original!"
        );

        if polynomial.degree() > degree as isize {
            return false;
        }

        if self.num_rounds() <= 1 {
            return true;
        }

        let top_level_indices = self.sample_indices(
            &proof_stream.verifier_fiat_shamir(32),
            self.domain_length >> 1,
            self.domain_length >> (self.num_rounds() - 1),
            self.num_colinearity_tests,
        );

        for round in 0..(self.num_rounds() - 1) {
            let c_indices = top_level_indices
                .iter()
                .map(|index| index % (self.domain_length >> (round + 1)))
                .collect::<Vec<_>>();
            let a_indices = c_indices.clone();
            let b_indices = a_indices
                .iter()
                .map(|index| index + (self.domain_length >> (round + 1)))
                .collect::<Vec<_>>();

            let mut aa = Vec::new();
            let mut bb = Vec::new();
            let mut cc = Vec::new();

            for sample in 0..self.num_colinearity_tests {
                let (ay, by, cy) = match proof_stream.pull() {
                    FriProofItem::QueryValues(ay, by, cy) => (ay, by, cy),
                    _ => panic!("expected FRI query values in proof stream"),
                };

                aa.push(ay.clone());
                bb.push(by.clone());
                cc.push(cy.clone());

                if round == 0 {
                    polynomial_values.push((a_indices[sample], ay.clone()));
                    polynomial_values.push((b_indices[sample], by.clone()));
                }

                let ax = offset.clone() * omega.pow(a_indices[sample] as u64);
                let bx = offset.clone() * omega.pow(b_indices[sample] as u64);
                let cx = alphas[round].clone();
                if !test_colinearity(&[(ax, ay), (bx, by), (cx, cy)]) {
                    return false;
                }
            }

            for sample in 0..self.num_colinearity_tests {
                let path = match proof_stream.pull() {
                    FriProofItem::AuthenticationPath(path) => path,
                    _ => panic!("expected FRI authentication path in proof stream"),
                };
                if !Merkle::verify(&roots[round], a_indices[sample], &path, &aa[sample].to_bytes()) {
                    return false;
                }

                let path = match proof_stream.pull() {
                    FriProofItem::AuthenticationPath(path) => path,
                    _ => panic!("expected FRI authentication path in proof stream"),
                };
                if !Merkle::verify(&roots[round], b_indices[sample], &path, &bb[sample].to_bytes()) {
                    return false;
                }

                let path = match proof_stream.pull() {
                    FriProofItem::AuthenticationPath(path) => path,
                    _ => panic!("expected FRI authentication path in proof stream"),
                };
                if !Merkle::verify(&roots[round + 1], c_indices[sample], &path, &cc[sample].to_bytes()) {
                    return false;
                }
            }

            omega = omega.pow(2);
            offset = offset.pow(2);
        }

        true
    }
}

fn merkle_commit_codeword(codeword: &[FieldElement]) -> Vec<u8> {
    let leaves = codeword
        .iter()
        .map(FieldElement::to_bytes)
        .collect::<Vec<_>>();
    Merkle::commit(&leaves)
}

fn merkle_open_codeword(index: usize, codeword: &[FieldElement]) -> Vec<Vec<u8>> {
    let leaves = codeword
        .iter()
        .map(FieldElement::to_bytes)
        .collect::<Vec<_>>();
    Merkle::open(index, &leaves)
}
