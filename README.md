# ZK-STARK implementation in Rust

This is a supposed to be a learning project and not to be used in Deployment.

Sources: https://aszepieniec.github.io/stark-anatomy

## Features

- **Field Arithmetic**: A full implementation of `GF(p)` for the 128-bit STARK prime `1 + 407 × 2¹¹⁹`. Features a robust `FieldElement` type with standard operator overloading (`+`, `-`, `*`, `/`) and utility methods (modular inverses, roots of unity, and binary exponentiation).
