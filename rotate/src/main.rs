//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2::{Blake2b512, Digest};
use ed25519_consensus::{Signature, VerificationKey};
use sha2::{Digest as Sha256Digest, Sha256};

pub fn main() {
    // NOTE: values of n larger than 186 will overflow the u128 type,
    // resulting in output that doesn't match fibonacci sequence.
    // However, the resulting proof will still be valid!
    let pk = sp1_zkvm::io::read_vec();
    let sig = sp1_zkvm::io::read_vec();
    let msg = sp1_zkvm::io::read_vec();

    let vk: VerificationKey = VerificationKey::try_from(pk.as_ref() as &[u8]).unwrap();
    let sig = Signature::try_from(sig.as_ref()).unwrap();

    // 24M cycles for verification for 300 signatures. Only need to verify once
    println!("cycle-tracker-start: setup");
    for _ in 0..300 {
        vk.verify(&sig, msg.as_ref()).unwrap();
    }
    println!("cycle-tracker-end: setup");

    // Double size of msg.
    let msg = msg.repeat(1000);

    // 1.7M cycles for 32K bytes with Blake2b512.
    // 1.7M * 512 ~ 870M cycles
    println!("cycle-tracker-start: blake2b");
    let mut hasher = Blake2b512::new();
    hasher.update(msg.clone());
    let result = hasher.finalize();
    println!("cycle-tracker-end: blake2b");

    // 200K cycles for 32K bytes with Sha256.
    println!("cycle-tracker-start: sha256");
    let mut hasher = Sha256::new();
    hasher.update(msg.clone());
    let result = hasher.finalize();
    println!("cycle-tracker-end: sha256");

    // sp1_zkvm::io::commit_slice(&result);
}
