//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2::{Blake2b512, Digest};
use ed25519_consensus::{Signature, VerificationKey};
use sha2::{Digest as Sha256Digest, Sha256};

use sp1_vectorx_primitives::types::{CircuitJustification, HeaderRotateData};

pub fn main() {
    let current_authority_set_id = sp1_zkvm::io::read::<u64>();
    let current_authority_set_hash = sp1_zkvm::io::read::<Vec<u8>>();
    let justification = sp1_zkvm::io::read::<CircuitJustification>();
    let header_rotate_data = sp1_zkvm::io::read::<HeaderRotateData>();
}
