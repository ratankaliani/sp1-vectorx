//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2::{Blake2b512, Digest};
use ed25519_consensus::{Signature, VerificationKey};
use sha2::{Digest as Sha256Digest, Sha256};

use sp1_vectorx_primitives::types::{CircuitJustification, HeaderRangeProofRequestData};

pub fn main() {
    let request_data = sp1_zkvm::io::read::<HeaderRangeProofRequestData>();

    let encoded_headers = Vec::new();
    for i in 0..request_data.target_block - request_data.trusted_block + 1 {
        let header_bytes = sp1_zkvm::io::read_vec::<Vec<u8>>();
        encoded_headers.push(header_bytes);
    }

    // The headers in the form of bytes.
    let headers = sp1_zkvm::io::read::<Vec<Vec<u8>>>();

    let target_justification = sp1_zkvm::io::read::<CircuitJustification>();
}
