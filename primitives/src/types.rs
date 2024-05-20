use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct HeaderRotateData {
    pub header_bytes: Vec<u8>,
    pub num_authorities: usize,
    pub new_authority_set_hash: Vec<u8>,
    pub pubkeys: Vec<[u8; 32]>,
    pub position: usize,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CircuitJustification {
    pub authority_set_id: u64,
    pub signed_message: Vec<u8>,
    pub pubkeys: Vec<[u8; 32]>,
    pub signatures: Vec<Option<Vec<u8>>>,
    pub num_authorities: usize,
    pub current_authority_set_hash: Vec<u8>,
}
