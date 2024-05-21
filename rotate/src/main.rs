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
    // println!("{}",current_authority_set_hash.len());
    // let current_authority_set_hash_bytes32: [u8; 32] = current_authority_set_hash.try_into().expect("Failed to convert hash to bytes32");
    // println!("Current authority set id: {}", current_authority_set_id);
    // println!("Current authority set hash: {:?}", current_authority_set_hash_bytes32);
    
    let new_authority_set_hash: Vec<u8> = compute_authority_set_commitment(justification.num_authorities, justification.pubkeys);
    let new_authority_set_hash_bytes32: [u8; 32] = new_authority_set_hash.try_into().expect("Failed to convert hash to bytes32");
    sp1_zkvm::io::commit(&new_authority_set_hash_bytes32);
}

fn compute_authority_set_commitment(num_active_authorities: usize, pubkeys: Vec<[u8; 32]>) -> Vec<u8> {
    assert!(num_active_authorities > 0, "There must be at least one authority");

    let mut commitment_so_far = sha256(&pubkeys[0]);
    for pubkey in pubkeys.iter() {
        let mut input_to_hash = Vec::new();
        input_to_hash.extend_from_slice(&commitment_so_far);
        input_to_hash.extend_from_slice(pubkey);

        commitment_so_far = sha256(&input_to_hash);
    }

    commitment_so_far
}

fn sha256(input: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}