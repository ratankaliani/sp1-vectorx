use alloy_sol_types::sol;

sol! {
    struct HeaderRangeOutputs {
        uint32 trusted_block;
        bytes32 trusted_header_hash;
        uint64 authority_set_id;
        bytes32 authority_set_hash;
        uint32 target_block;
        bytes32 state_root_commitment;
        bytes32 data_root_commitment;
    }
}