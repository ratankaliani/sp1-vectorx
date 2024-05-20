//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2::{Blake2b512, Digest};

use sp1_vectorx_primitives::{
    decode_scale_compact_int,
    types::{CircuitJustification, DecodedHeaderData, HeaderRangeProofRequestData},
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

    // TODO
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
    for header_bytes in encoded_headers {
        let mut hasher = Blake2b512::new();
        hasher.update(header_bytes);
        let res = hasher.finalize();
        header_hashes.push(res.to_vec());
    }

    // Stage 2: Verify the chain of headers is connected from the trusted block to the target block.
    for i in 1..(request_data.target_block - request_data.trusted_block + 1) as usize {
        // Check the parent hashes are linked.
        assert_eq!(header_hashes[i - 1], decoded_headers_data[i].parent_hash);
        // Check the block numbers are sequential.
        assert_eq!(
            decoded_headers_data[i - 1].block_number + 1,
            decoded_headers_data[i].block_number
        );
    }
}

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
