//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use core::num;

use blake2::{Blake2b512, Digest};
use ed25519_consensus::{Signature, VerificationKey};
use sha2::{Digest as Sha256Digest, Sha256};

use sp1_vectorx_primitives::types::{CircuitJustification, HeaderRotateData};

pub fn main() {
    let current_authority_set_id = sp1_zkvm::io::read::<u64>();
    let current_authority_set_hash = sp1_zkvm::io::read::<Vec<u8>>();
    let justification = sp1_zkvm::io::read::<CircuitJustification>();
    let header_rotate_data = sp1_zkvm::io::read::<HeaderRotateData>();

    // Compute new authority set hash & convert it from binary to bytes32 for the blockchain
    let new_authority_set_hash: Vec<u8> =
        compute_authority_set_commitment(justification.num_authorities, justification.pubkeys);
    let new_authority_set_hash_bytes32: [u8; 32] = new_authority_set_hash
        .try_into()
        .expect("Failed to convert hash to bytes32");
    sp1_zkvm::io::commit_slice(&new_authority_set_hash_bytes32);
}

/// Compute the new authority set hash.
fn compute_authority_set_commitment(
    num_active_authorities: usize,
    pubkeys: Vec<[u8; 32]>,
) -> Vec<u8> {
    assert!(
        num_active_authorities > 0,
        "There must be at least one authority"
    );
    let mut commitment_so_far = Sha256::digest(pubkeys[0]).to_vec();
    for pubkey in pubkeys.iter().skip(1) {
        let mut input_to_hash = Vec::new();
        input_to_hash.extend_from_slice(&commitment_so_far);
        input_to_hash.extend_from_slice(pubkey);
        commitment_so_far = Sha256::digest(&input_to_hash).to_vec();
    }
    commitment_so_far
}
