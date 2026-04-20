//! # Proof Stream
//!
//! A serializable transcript with Fiat-Shamir helpers.

use serde::{Serialize, de::DeserializeOwned};
use sha3::{
    Shake256,
    digest::{ExtendableOutput, Update, XofReader},
};

/// Transcript container used by prover and verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStream<T> {
    objects: Vec<T>,
    read_index: usize,
}

impl<T> Default for ProofStream<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> ProofStream<T> {
    /// Creates an empty proof stream.
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            read_index: 0,
        }
    }

    /// Appends an object to the transcript.
    pub fn push(&mut self, object: T) {
        self.objects.push(object);
    }

    /// Returns the number of objects stored in the transcript.
    pub fn len(&self) -> usize {
        self.objects.len()
    }

    /// Returns `true` when the transcript is empty.
    pub fn is_empty(&self) -> bool {
        self.objects.is_empty()
    }
}

impl<T> ProofStream<T>
where
    T: Clone,
{
    /// Reads the next object from the transcript.
    pub fn pull(&mut self) -> T {
        assert!(
            self.read_index < self.objects.len(),
            "ProofStream: cannot pull object; queue empty."
        );

        let object = self.objects[self.read_index].clone();
        self.read_index += 1;
        object
    }
}

impl<T> ProofStream<T>
where
    T: Serialize + DeserializeOwned,
{
    /// Serializes the full transcript.
    pub fn serialize(&self) -> Vec<u8> {
        bincode::serialize(&self.objects).expect("proof stream serialization should succeed")
    }

    /// Deserializes a transcript from bytes.
    pub fn deserialize(bytes: &[u8]) -> Self {
        Self {
            objects: bincode::deserialize(bytes)
                .expect("proof stream deserialization should succeed"),
            read_index: 0,
        }
    }

    /// Fiat-Shamir transcript challenge for the prover.
    pub fn prover_fiat_shamir(&self, num_bytes: usize) -> Vec<u8> {
        shake_256(&self.serialize(), num_bytes)
    }

    /// Fiat-Shamir transcript challenge for the verifier.
    pub fn verifier_fiat_shamir(&self, num_bytes: usize) -> Vec<u8> {
        let prefix = bincode::serialize(&self.objects[..self.read_index])
            .expect("proof stream prefix serialization should succeed");
        shake_256(&prefix, num_bytes)
    }
}

fn shake_256(input: &[u8], num_bytes: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);

    let mut reader = hasher.finalize_xof();
    let mut output = vec![0u8; num_bytes];
    reader.read(&mut output);
    output
}
