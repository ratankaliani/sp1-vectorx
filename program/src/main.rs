//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use alloy_sol_types::SolValue;
use blake2::digest::{Update, VariableOutput};
use blake2::Blake2bVar;
use sp1_vectorx_primitives::merkle::get_merkle_root_commitments;
use sp1_vectorx_primitives::{
    compute_authority_set_commitment, decode_scale_compact_int,
    types::{CircuitJustification, DecodedHeaderData, HeaderRangeProofRequestData, RotateInput},
    verify_encoded_validators, verify_simple_justification, types:: ,
};


/// Decode the header into a DecodedHeaderData struct.
fn decode_header(header_bytes: Vec<u8>) -> DecodedHeaderData {
    let parent_hash = B256::from_slice(&header_bytes[..32]);

    let mut position = 32;

    let (block_nb, num_bytes) = decode_scale_compact_int(&header_bytes[32..37]);
    position += num_bytes;

    let state_root = B256::from_slice(&header_bytes[position..position + 32]);

    let data_root = B256::from_slice(&header_bytes[header_bytes.len() - 32..header_bytes.len()]);

    DecodedHeaderData {
        block_number: block_nb as u32,
        parent_hash,
        state_root,
        data_root,
    }
}

/// Verify the encoded epoch end header is formatted correctly, and that the provided new pubkeys match the encoded ones.
fn verify_encoding_epoch_end_header(
    header_bytes: &[u8],
    start_cursor: usize,
    num_authorities: u64,
    pubkeys: Vec<B256>,
) {
    // Verify the epoch end header's consensus log is formatted correctly before the new authority set hash bytes.
    let mut cursor = start_cursor;

    // Verify consensus flag is 4.
    assert_eq!(header_bytes[cursor + 1], 4u8);

    // Verify the consensus engine ID: 0x46524e4b [70, 82, 78, 75]
    // Consensus Id: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/examples/download_digest_items.rs#L41-L56
    assert_eq!(
        header_bytes[cursor + 2..cursor + 6],
        [70u8, 82u8, 78u8, 75u8]
    );

    cursor += 6;

    // Decode the encoded scheduled change message length.
    let (_, decoded_byte_length) = decode_scale_compact_int(&header_bytes[cursor..cursor + 5]);
    cursor += decoded_byte_length;

    // Verify the next byte after encoded scheduled change message is scheduled change enum flags.
    assert_eq!(header_bytes[cursor], 1u8);

    cursor += 1;

    // Decoded the encoded authority set size.
    let (authority_set_size, decoded_byte_length) =
        decode_scale_compact_int(&header_bytes[cursor..cursor + 5]);
    assert_eq!(authority_set_size, num_authorities);
    cursor += decoded_byte_length;

    // Verify that num_authorities validators are correctly encoded and match the pubkeys.
    verify_encoded_validators(header_bytes, cursor, &pubkeys);
}

/// Verify the justification from the current authority set on the epoch end header and return the new
/// authority set commitment.
fn verify_rotation(rotate_input: RotateInput) {
    // Compute new authority set hash & convert it from binary to bytes32 for the blockchain
    let new_authority_set_hash =
        compute_authority_set_commitment(&rotate_input.header_rotate_data.pubkeys);

    // Verify the provided justification is valid.
    verify_simple_justification(
        rotate_input.justification,
        rotate_input.current_authority_set_id,
        rotate_input.current_authority_set_hash,
    );

    // Verify the encoded epoch end header is formatted correctly, and that the provided new pubkeys match the encoded ones.
    verify_encoding_epoch_end_header(
        &rotate_input.header_rotate_data.header_bytes,
        rotate_input.header_rotate_data.consensus_log_position as usize,
        rotate_input.header_rotate_data.num_authorities as u64,
        rotate_input.header_rotate_data.pubkeys.clone(),
    );

    sp1_zkvm::io::commit(&new_authority_set_hash);
}

/// Verify the justification from the current authority set on target block and compute the
/// {state, data}_root_commitments over the range [trusted_block + 1, target_block] inclusive.
fn verify_header_range(request_data: HeaderRangeProofRequestData, target_justification: CircuitJustification) -> HeaderRangeOutputs {
    let encoded_headers = request_data.encoded_headers;

    // 1. Decode the headers using: https://github.com/succinctlabs/vectorx/blob/fb83641259aef1f5df33efa73c23d90973d64e24/circuits/builder/decoder.rs#L104-L157
    // 2. Verify the chain of headers is connected from the trusted block to the target block.
    // 3. Verify the justification is valid.
    // 4. Compute the simple merkle tree commitment for the headers.

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
        header_hashes.push(B256::from(digest_bytes));
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
        request_data.authority_set_hash,
    );

    // Stage 4: Compute the simple Merkle tree commitment for the headers.
    let (state_root_commitment, data_root_commitment) =
        get_merkle_root_commitments(&decoded_headers_data[1..], request_data.merkle_tree_size);

    // Create an instance of the HeaderRangeOutputs struct
    let outputs = HeaderRangeOutputs {
        trusted_block: request_data.trusted_block,
        trusted_header_hash: request_data.trusted_header_hash,
        authority_set_id: request_data.authority_set_id,
        authority_set_hash: request_data.authority_set_hash,
        target_block: request_data.target_block,
        state_root_commitment,
        data_root_commitment,
    };

    // Return the ABI-encoded HeaderRangeOutputs struct
   outputs
}

pub fn main() {
    let request_data = sp1_zkvm::io::read::<HeaderRangeProofRequestData>();
    let target_justification = sp1_zkvm::io::read::<CircuitJustification>();
    let rotate_input: RotateInput = sp1_zkvm::io::read::<RotateInput>();

    let new_authority_set_hash = verify_rotation(rotate_input);
    let header_range_outputs = verify_header_range(request_data, target_justification);

    sp1_zkvm::io::commit(&new_authority_set_hash);
    sp1_zkvm::io::commit_slice(&header_range_outputs.abi_encode());
}
