use alloy_primitives::{B256, B512};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct RotateInputs {
    pub current_authority_set_id: u64,
    pub current_authority_set_hash: B256,
    /// Justification data for the current authority set.
    pub justification: CircuitJustification,
    /// Data for the next authority set rotation.
    pub header_rotate_data: HeaderRotateData,
}

#[derive(Debug, Deserialize, Serialize)]
/// Data for the next set of authorities.
pub struct HeaderRotateData {
    /// Encoded header bytes for the epoch end block.
    pub header_bytes: Vec<u8>,
    pub num_authorities: usize,
    pub new_authority_set_hash: B256,
    pub pubkeys: Vec<B256>,
    /// Index of the new authority set data in the header bytes.
    pub consensus_log_position: usize,
}

#[derive(Debug, Deserialize, Serialize)]
/// Justification data for an authority set.
pub struct CircuitJustification {
    pub authority_set_id: u64,
    /// Message signed by authority set.
    pub signed_message: Vec<u8>,
    pub pubkeys: Vec<B256>,
    pub signatures: Vec<Option<B512>>,
    pub num_authorities: usize,
    pub current_authority_set_hash: B256,
    /// Block number associated with the justification.
    pub block_number: u32,
    /// Hash of the block associated with the justification.
    pub block_hash: B256,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct HeaderRangeInputs {
    pub trusted_block: u32,
    pub trusted_header_hash: B256,
    pub authority_set_id: u64,
    pub authority_set_hash: B256,
    pub target_block: u32,
    pub merkle_tree_size: usize,
    pub encoded_headers: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DecodedHeaderData {
     /// Block number of the decoded header.
    pub block_number: u32,
     /// Hash of the parent block.
    pub parent_hash: B256,
    /// State root of the block.
    pub state_root: B256,  
    /// Data root of the block.
    pub data_root: B256,   
}
