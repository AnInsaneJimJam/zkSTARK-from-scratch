use blake2::{Blake2b512, Digest};
use stark::crypto::{Merkle, ProofStream};

#[test]
fn push_and_pull_round_trip() {
    let mut stream = ProofStream::new();
    stream.push(3u64);
    stream.push(5u64);

    assert_eq!(stream.pull(), 3);
    assert_eq!(stream.pull(), 5);
}

#[test]
fn serialization_round_trip() {
    let mut stream = ProofStream::new();
    stream.push(String::from("alpha"));
    stream.push(String::from("beta"));

    let bytes = stream.serialize();
    let restored = ProofStream::<String>::deserialize(&bytes);

    assert_eq!(restored.serialize(), bytes);
}

#[test]
fn prover_and_verifier_challenges_diverge_after_reads() {
    let mut stream = ProofStream::new();
    stream.push(1u64);
    stream.push(2u64);

    let prover = stream.prover_fiat_shamir(32);
    let verifier_before_read = stream.verifier_fiat_shamir(32);
    assert_ne!(prover, verifier_before_read);

    let _ = stream.pull();
    let verifier_after_read = stream.verifier_fiat_shamir(32);
    assert_ne!(verifier_before_read, verifier_after_read);
}

#[test]
#[should_panic(expected = "ProofStream: cannot pull object; queue empty.")]
fn pulling_past_end_panics() {
    let mut stream = ProofStream::<u64>::new();
    let _ = stream.pull();
}

#[test]
fn commit_and_verify_round_trip() {
    let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];

    let root = Merkle::commit(&data);
    let path = Merkle::open(2, &data);

    assert!(Merkle::verify(&root, 2, &path, &data[2]));
}

#[test]
fn verify_rejects_wrong_leaf() {
    let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];

    let root = Merkle::commit(&data);
    let path = Merkle::open(1, &data);

    assert!(!Merkle::verify(&root, 1, &path, &b"z".to_vec()));
}

#[test]
fn open_hashed_leaves_matches_verify_hashed_leaf() {
    let leaves = [b"a", b"b", b"c", b"d"]
        .into_iter()
        .map(|bytes| {
            let mut hasher = Blake2b512::new();
            hasher.update(bytes);
            hasher.finalize().to_vec()
        })
        .collect::<Vec<_>>();

    let root = Merkle::commit_(&leaves);
    let path = Merkle::open_(3, &leaves);

    assert!(Merkle::verify_(&root, 3, &path, &leaves[3]));
}

#[test]
#[should_panic(expected = "length must be power of two")]
fn commit_requires_power_of_two_leaves() {
    let _ = Merkle::commit(&[b"a".to_vec(), b"b".to_vec(), b"c".to_vec()]);
}
