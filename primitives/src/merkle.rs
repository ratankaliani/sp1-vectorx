use sha2::{Digest, Sha256};

use crate::types::DecodedHeaderData;

/// Computes the simple Merkle root of the leaves.
fn get_merkle_root(leaves: Vec<Vec<u8>>) -> [u8; 32] {
    let mut nodes = leaves;
    while nodes.len() > 1 {
        nodes = (0..nodes.len() / 2)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(&nodes[2 * i]);
                hasher.update(&nodes[2 * i + 1]);
                hasher.finalize().to_vec()
            })
            .collect();
    }
    nodes[0].clone().try_into().unwrap()
}

/// Computes the simple Merkle root commitments for the state root and data root.
/// The size of the Merkle tree is fixed at 512.
pub fn get_merkle_root_commitments(decoded_headers: &[DecodedHeaderData]) -> ([u8; 32], [u8; 32]) {
    let mut state_root_leaves = Vec::new();
    let mut data_root_leaves = Vec::new();

    for header in decoded_headers {
        state_root_leaves.push(header.state_root.clone());
        data_root_leaves.push(header.data_root.clone());
    }

    // Pad the leaves to a fixed size of 512.
    while state_root_leaves.len() < 512 {
        state_root_leaves.push(vec![0u8; 32]);
        data_root_leaves.push(vec![0u8; 32]);
    }

    // Compute the Merkle root for state root leaves.
    let state_root_commitment = get_merkle_root(state_root_leaves);

    // Compute the Merkle root for data root leaves.
    let data_root_commitment = get_merkle_root(data_root_leaves);

    (state_root_commitment, data_root_commitment)
}
