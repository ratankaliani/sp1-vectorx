//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::B256;
use sp1_vectorx_primitives::{
    compute_authority_set_commitment, decode_scale_compact_int, types::RotateInput,
    verify_encoded_validators, verify_simple_justification,
};

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
pub fn main() {
    let rotate_input: RotateInput = sp1_zkvm::io::read::<RotateInput>();

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
