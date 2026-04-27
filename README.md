# zkSTARK from Scratch

An educational Rust implementation of the core components behind a zkSTARK proving system.

This repository follows the ideas in [STARK Anatomy](https://aszepieniec.github.io/stark-anatomy/) and implements the main building blocks directly in Rust: finite-field arithmetic, polynomial utilities, Merkle commitments, a Fiat-Shamir proof stream, FRI, a STARK prover/verifier flow, and Rescue-Prime-based examples.

## Status

This is a learning and reference project, not a production cryptography library.

The codebase is useful for studying how the layers of a STARK system fit together, but it has not been hardened for adversarial deployment, audited, or optimized for production workloads.

## What Is Implemented

- Prime field arithmetic over the STARK field `p = 1 + 407 * 2^119`
- `FieldElement` operations with inversion, exponentiation, sampling, and roots of unity
- Univariate polynomial arithmetic, interpolation, zerofiers, evaluation on domains, and division
- Multivariate polynomial support used to express AIR transition constraints
- Merkle commitments and authentication-path verification
- A generic typed proof stream for Fiat-Shamir transcripts
- FRI commitment, query generation, and verification
- STARK proof generation and verification over execution traces and boundary constraints
- Rescue-Prime hashing and an RPSSS-style signature wrapper built on top of the STARK layer

## Repository Layout

- `src/field`: prime-field definition and field-element arithmetic
- `src/math`: supporting number-theoretic utilities such as extended GCD
- `src/polynomial`: univariate and multivariate polynomial operations
- `src/crypto`: Merkle trees and proof-stream transcript handling
- `src/fri`: FRI commitment and verification logic
- `src/stark`: high-level STARK prover and verifier
- `src/rescue_prime`: Rescue-Prime permutation, AIR construction, and signature example
- `tests`: integration tests covering each major subsystem

## Getting Started

### Prerequisites

- A recent stable Rust toolchain
- Cargo

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

The full test suite was verified with `cargo test` on April 28, 2026, including integration tests for field arithmetic, polynomials, Merkle proofs, FRI, STARK proving/verification, Rescue-Prime, and doc tests.

### Run the Example Binary

```bash
cargo run
```

The current binary is intentionally minimal. It prints a few field-level values such as the modulus, generator, and a sample root of unity. The repository is primarily structured as a library crate.


## Testing Scope

The test suite currently exercises:

- field identities, inversion, powers, serialization, and roots of unity
- polynomial arithmetic, interpolation, zerofiers, and colinearity checks
- multivariate polynomial algebra and symbolic evaluation
- proof-stream serialization and Fiat-Shamir behavior
- Merkle commitment/open/verify flows
- FRI round structure and prove/verify round trips
- STARK proof generation/verification, including tampering rejection
- Rescue-Prime trace generation, transition constraints, and document-bound signatures

## Design Notes

- The implementation favors readability over optimization.
- The default field and generator are specialized to the STARK field used by the project.
- Several protocol parameters are exposed through constructors, which makes the code easier to inspect and experiment with.
- The Rescue-Prime module demonstrates how an AIR can be built for a concrete computation and then wrapped in a signature-style interface.

## Reference

- [STARK Anatomy](https://aszepieniec.github.io/stark-anatomy/)
