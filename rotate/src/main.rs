//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use core::num;

use blake2::{Blake2b512, Digest};
use ed25519_consensus::{Signature, VerificationKey};
use sp1_vectorx_primitives::{compute_authority_set_commitment, types::{CircuitJustification, HeaderRotateData, RotateInput}, verify_simple_justification};

pub fn main() {
    let rotate_input: RotateInput = sp1_zkvm::io::read::<RotateInput>();

    // Compute new authority set hash & convert it from binary to bytes32 for the blockchain
    let new_authority_set_hash: Vec<u8> =
        compute_authority_set_commitment(rotate_input.header_rotate_data.num_authorities, rotate_input.header_rotate_data.pubkeys.clone());
    let new_authority_set_hash_bytes32: [u8; 32] = new_authority_set_hash.clone()
        .try_into()
        .expect("Failed to convert hash to bytes32");

    verify_simple_justification(rotate_input.justification, rotate_input.current_authority_set_id, rotate_input.current_authority_set_hash);

    sp1_zkvm::io::commit_slice(&new_authority_set_hash_bytes32);
}

