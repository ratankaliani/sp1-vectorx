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
pub fn get_merkle_root_commitments(
    decoded_headers: &[DecodedHeaderData],
    tree_size: usize,
) -> ([u8; 32], [u8; 32]) {
    let mut state_root_leaves = Vec::new();
    let mut data_root_leaves = Vec::new();

    for header in decoded_headers {
        state_root_leaves.push(header.state_root.clone());
        data_root_leaves.push(header.data_root.clone());
    }

    // Confirm tree_size is a power of 2.
    assert!(tree_size.is_power_of_two());

    // Confirm that it's greater than the number of headers that's passed in.
    assert!(tree_size >= decoded_headers.len());

    // Pad the leaves to a fixed size of tree_size.
    while state_root_leaves.len() < tree_size {
        state_root_leaves.push(vec![0u8; 32]);
        data_root_leaves.push(vec![0u8; 32]);
    }

    // Compute the Merkle root for state root leaves.
    let state_root_commitment = get_merkle_root(state_root_leaves);

    // Compute the Merkle root for data root leaves.
    let data_root_commitment = get_merkle_root(data_root_leaves);

    (state_root_commitment, data_root_commitment)
}

// TODO: Should be removed when we read header_range_tree_commitment_size from the contract.
pub fn get_merkle_tree_size(num_headers: u32) -> usize {
    let mut size = 1;
    while size < num_headers {
        size *= 2;
    }
    size.try_into().unwrap()
}

// Computes the simple Merkle root of the leaves.
// If the number of leaves is not a power of 2, the leaves are extended with 0s to the next power of 2.
pub fn get_merkle_root(leaves: Vec<Vec<u8>>) -> Vec<u8> {
    if leaves.is_empty() {
        return vec![];
    }

    // Extend leaves to a power of 2.
    let mut leaves = leaves;
    while leaves.len().count_ones() != 1 {
        leaves.push([0u8; 32].to_vec());
    }

    // In VectorX, the leaves are not hashed.
    let mut nodes = leaves.clone();
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

    nodes[0].clone()
}

/// Get the state root commitment and data root commitment for the range [start_block + 1, end_block].
/// Returns a tuple of the state root commitment and data root commitment.
pub async fn get_merkle_root_commitments(
    &self,
    header_range_commitment_tree_size: u32,
    start_block: u32,
    end_block: u32,
) -> (Vec<u8>, Vec<u8>) {
    // Assert header_range_commitment_tree_size is a power of 2.
    assert!(header_range_commitment_tree_size.is_power_of_two());

    if end_block - start_block > header_range_commitment_tree_size {
        panic!("Range too large!");
    }

    let headers = self
        .get_block_headers_range(start_block + 1, end_block)
        .await;

    let mut data_root_leaves = Vec::new();
    let mut state_root_leaves = Vec::new();
    let num_headers = headers.len();
    for header in headers {
        data_root_leaves.push(header.data_root().0.to_vec());
        state_root_leaves.push(header.state_root.0.to_vec());
    }

    for _ in num_headers..header_range_commitment_tree_size as usize {
        data_root_leaves.push([0u8; 32].to_vec());
        state_root_leaves.push([0u8; 32].to_vec());
    }

    // Uses the simple merkle tree implementation.
    (
        Self::get_merkle_root(state_root_leaves),
        Self::get_merkle_root(data_root_leaves),
    )
}