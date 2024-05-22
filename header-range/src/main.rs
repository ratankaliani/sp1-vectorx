//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use sp1_vectorx_primitives::merkle::get_merkle_root_commitments;
use sp1_vectorx_primitives::{
    decode_scale_compact_int,
    types::{CircuitJustification, DecodedHeaderData, HeaderRangeProofRequestData},
    verify_simple_justification,
};

pub fn main() {
    let request_data = sp1_zkvm::io::read::<HeaderRangeProofRequestData>();

    let mut encoded_headers = Vec::new();
    // Read the encoded headers.
    for _ in 0..request_data.target_block - request_data.trusted_block + 1 {
        let header_bytes = sp1_zkvm::io::read_vec();
        encoded_headers.push(header_bytes);
    }

    let target_justification = sp1_zkvm::io::read::<CircuitJustification>();

    // 1. Decode the headers using: https://github.com/succinctlabs/vectorx/blob/fb83641259aef1f5df33efa73c23d90973d64e24/circuits/builder/decoder.rs#L104-L157
    // 2. Verify the chain of headers is connected from the trusted block to the target block.
    // 3. Verify the justification is valid.
    // 4. Compute the simple merkle tree commitment (start with fixed size of 512) for the headers.

    // Stage 1: Decode the headers.
    // Decode the headers.
    let decoded_headers_data: Vec<DecodedHeaderData> = encoded_headers
        .iter()
        .map(|header_bytes| decode_header(header_bytes.to_vec()))
        .collect();

    // Hash the headers.
    let mut header_hashes = Vec::new();
    const DIGEST_SIZE: usize = 32;
    for header_bytes in encoded_headers {
        let mut hasher = Blake2bVar::new(DIGEST_SIZE).unwrap();
        hasher.update(header_bytes.as_slice());

        let mut digest_bytes = [0u8; DIGEST_SIZE];
        let _ = hasher.finalize_variable(&mut digest_bytes);
        header_hashes.push(digest_bytes.to_vec());
    }

    // Assert the first header hash matches the trusted header hash.
    assert_eq!(header_hashes[0], request_data.trusted_header_hash);
    assert_eq!(
        decoded_headers_data[0].block_number,
        request_data.trusted_block
    );

    // Stage 2: Verify the chain of headers is connected from the trusted block to the target block.
    // Do this by checking the parent hashes are linked and the block numbers are sequential.
    for i in 1..(request_data.target_block - request_data.trusted_block + 1) as usize {
        // Check the parent hashes are linked.
        assert_eq!(header_hashes[i - 1], decoded_headers_data[i].parent_hash);
        // Check the block numbers are sequential.
        assert_eq!(
            decoded_headers_data[i - 1].block_number + 1,
            decoded_headers_data[i].block_number
        );
    }

    // Check that the last header matches the target block.
    assert_eq!(
        decoded_headers_data[decoded_headers_data.len() - 1].block_number,
        request_data.target_block
    );

    // Stage 3: Verify the justification is valid.
    verify_simple_justification(
        target_justification,
        request_data.authority_set_id,
        Vec::from(request_data.authority_set_hash),
    );

    // Stage 4: Compute the simple Merkle tree commitment (start with fixed size of 512) for the headers.
    let (state_root_commitment, data_root_commitment) =
        get_merkle_root_commitments(&decoded_headers_data[1..]);

    // Commit the state root and data root Merkle roots.
    sp1_zkvm::io::commit_slice(&state_root_commitment);
    sp1_zkvm::io::commit_slice(&data_root_commitment);
    // // Commit to the input data.
    sp1_zkvm::io::commit(&request_data.trusted_block);
    sp1_zkvm::io::commit(&request_data.trusted_header_hash);
    sp1_zkvm::io::commit(&request_data.authority_set_id);
    sp1_zkvm::io::commit(&request_data.authority_set_hash);
    sp1_zkvm::io::commit(&request_data.target_block);
}

/// Decode the header into a DecodedHeaderData struct.
fn decode_header(header_bytes: Vec<u8>) -> DecodedHeaderData {
    let parent_hash = header_bytes[..32].to_vec();

    let mut position = 32;

    let (block_nb, num_bytes) = decode_scale_compact_int(&header_bytes[32..37]);
    position += num_bytes;

    let state_root = header_bytes[position..position + 32].to_vec();

    let data_root = header_bytes[header_bytes.len() - 32..header_bytes.len()].to_vec();

    DecodedHeaderData {
        block_number: block_nb as u32,
        parent_hash,
        state_root,
        data_root,
    }
}
