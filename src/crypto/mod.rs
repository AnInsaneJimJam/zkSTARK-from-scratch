//! # Crypto
//!
//! Transcript and commitment primitives used by the STARK protocol.

pub mod merkle;
pub mod proof_stream;

pub use merkle::Merkle;
pub use proof_stream::ProofStream;
