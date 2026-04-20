//! # Merkle Tree
//!
//! Blake2b-based Merkle commitments over byte-serializable leaves.

use blake2::{
    Blake2b512,
    Digest,
};

/// Blake2b Merkle commitment utilities.
pub struct Merkle;

impl Merkle {
    /// Commits already-hashed leaves into a Merkle root.
    pub fn commit_(leaves: &[Vec<u8>]) -> Vec<u8> {
        assert!(leaves.len().is_power_of_two(), "length must be power of two");

        if leaves.len() == 1 {
            return leaves[0].clone();
        }

        let midpoint = leaves.len() / 2;
        hash_bytes(&[&Self::commit_(&leaves[..midpoint]), &Self::commit_(&leaves[midpoint..])])
    }

    /// Opens a Merkle authentication path for already-hashed leaves.
    pub fn open_(index: usize, leaves: &[Vec<u8>]) -> Vec<Vec<u8>> {
        assert!(leaves.len().is_power_of_two(), "length must be power of two");
        assert!(index < leaves.len(), "cannot open invalid index");

        if leaves.len() == 2 {
            return vec![leaves[1 - index].clone()];
        }

        let midpoint = leaves.len() / 2;
        if index < midpoint {
            let mut path = Self::open_(index, &leaves[..midpoint]);
            path.push(Self::commit_(&leaves[midpoint..]));
            path
        } else {
            let mut path = Self::open_(index - midpoint, &leaves[midpoint..]);
            path.push(Self::commit_(&leaves[..midpoint]));
            path
        }
    }

    /// Verifies a Merkle authentication path against a root using a hashed leaf.
    pub fn verify_(root: &[u8], index: usize, path: &[Vec<u8>], leaf: &[u8]) -> bool {
        assert!(
            index < (1usize << path.len()),
            "cannot verify invalid index"
        );
        assert!(!path.is_empty(), "cannot verify without an authentication path");

        if path.len() == 1 {
            if index == 0 {
                root == hash_bytes(&[leaf, &path[0]])
            } else {
                root == hash_bytes(&[&path[0], leaf])
            }
        } else if index.is_multiple_of(2) {
            Self::verify_(
                root,
                index >> 1,
                &path[1..],
                &hash_bytes(&[leaf, &path[0]]),
            )
        } else {
            Self::verify_(
                root,
                index >> 1,
                &path[1..],
                &hash_bytes(&[&path[0], leaf]),
            )
        }
    }

    /// Commits a data array by hashing each element into a leaf first.
    pub fn commit<T>(data_array: &[T]) -> Vec<u8>
    where
        T: AsRef<[u8]>,
    {
        let leaves = hash_data_array(data_array);
        Self::commit_(&leaves)
    }

    /// Opens a data element by hashing each element into a leaf first.
    pub fn open<T>(index: usize, data_array: &[T]) -> Vec<Vec<u8>>
    where
        T: AsRef<[u8]>,
    {
        let leaves = hash_data_array(data_array);
        Self::open_(index, &leaves)
    }

    /// Verifies a data element by hashing it into a leaf first.
    pub fn verify<T>(root: &[u8], index: usize, path: &[Vec<u8>], data_element: &T) -> bool
    where
        T: AsRef<[u8]>,
    {
        Self::verify_(root, index, path, &hash_bytes(&[data_element.as_ref()]))
    }
}

fn hash_data_array<T>(data_array: &[T]) -> Vec<Vec<u8>>
where
    T: AsRef<[u8]>,
{
    data_array
        .iter()
        .map(|element| hash_bytes(&[element.as_ref()]))
        .collect()
}

fn hash_bytes(parts: &[&[u8]]) -> Vec<u8> {
    let mut hasher = Blake2b512::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().to_vec()
}
