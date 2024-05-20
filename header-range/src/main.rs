//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use blake2::{Blake2b512, Digest};
// use codec::{Compact, Decode, Encode};
use ed25519_consensus::{Signature, VerificationKey};
use sha2::{Digest as Sha256Digest, Sha256};

use sp1_vectorx_primitives::types::{
    CircuitJustification, DecodedHeaderData, HeaderRangeProofRequestData,
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

    // Decode the headers.
    // Get the header hashes.
    let mut header_hashes = Vec::new();
    for header_bytes in encoded_headers {
        let mut hasher = Blake2b512::new();

        hasher.update(header_bytes);
        let res = hasher.finalize();
        header_hashes.push(res);
    }
}

/// Decode a SCALE-encoded compact int.
fn decode_scale_compact_int(bytes: &[u8]) -> (u64, usize) {
    if bytes.is_empty() {
        panic!("Input bytes are empty");
    }

    let first_byte = bytes[0];
    let flag = first_byte & 0b11;

    match flag {
        0b00 => {
            // Single-byte mode
            (u64::from(first_byte >> 2), 1)
        }
        0b01 => {
            // Two-byte mode
            if bytes.len() < 2 {
                panic!("Not enough bytes for two-byte mode");
            }
            let value = ((u64::from(first_byte) >> 2) | (u64::from(bytes[1]) << 6)) as u64;
            (value, 2)
        }
        0b10 => {
            // Four-byte mode
            if bytes.len() < 4 {
                panic!("Not enough bytes for four-byte mode");
            }
            let value = (u64::from(first_byte) >> 2)
                | (u64::from(bytes[1]) << 6)
                | (u64::from(bytes[2]) << 14)
                | (u64::from(bytes[3]) << 22);
            (value, 4)
        }
        0b11 => {
            // Big integer mode
            let byte_count = ((first_byte >> 2) + 4) as usize;
            if bytes.len() < byte_count + 1 {
                panic!("Not enough bytes for big integer mode");
            }
            let mut value = 0u64;
            for i in 0..byte_count {
                value |= (u64::from(bytes[i + 1])) << (i * 8);
            }
            (value, byte_count + 1)
        }
        _ => unreachable!(),
    }
}

// fn decode_header(header_bytes: Vec<u8>) -> DecodedHeaderData {
//     let parent_hash = header_bytes[..32].to_vec();

//     let state_root = header_bytes[32..48].to_vec();
//     let data_root = header_bytes[header_bytes.len() - 32..].to_vec();
//     let block_number = header_bytes[64..68];
// }

mod tests {
    use super::*;

    // #[test]
    // fn test_decode_scale_compact_int() {
    //     let nums = [
    //         u32::MIN,
    //         1u32,
    //         63u32,
    //         64u32,
    //         16383u32,
    //         16384u32,
    //         1073741823u32,
    //         1073741824u32,
    //         4294967295u32,
    //         u32::MAX,
    //     ];
    //     let encoded_nums: Vec<Vec<u8>> = nums.iter().map(|num| Compact(*num).encode()).collect();
    //     let zipped: Vec<(&Vec<u8>, &u32)> = encoded_nums.iter().zip(nums.iter()).collect();
    //     for (encoded_num, num) in zipped {
    //         let (value, byte_count) = decode_scale_compact_int(encoded_num);
    //         assert_eq!(value, *num as u64);
    //     }
    // }
}
