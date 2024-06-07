//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use sp1_vectorx_primitives::{
    compute_authority_set_commitment, decode_scale_compact_int,
    types::{
        CircuitJustification,  HeaderRangeInputs, 
        ProofOutput, RotateInputs,
    },
    header_range::verify_header_range,
    rotate::verify_rotation,
};
use alloy_sol_types::{sol, SolType, SolStruct};

pub fn main() {
    let proof_type = sp1_zkvm::io::read::<u8>(); // 0 for header range proof, 1 for rotate proof.
    let mut output;

    if proof_type == 0 {
        let header_range_inputs = sp1_zkvm::io::read::<HeaderRangeInputs>();
        let target_justification = sp1_zkvm::io::read::<CircuitJustification>();

        let header_range_outputs = verify_header_range(header_range_inputs, target_justification);
        output = ProofOutput::abi_encode(&(0, header_range_outputs, [0u8; 32]));
    } else if proof_type == 1 {
        let rotate_inputs = sp1_zkvm::io::read::<RotateInputs>();

        let new_authority_set_hash = verify_rotation(rotate_inputs);
        output = ProofOutput::abi_encode(&(1, [0u8; 32 * 7], new_authority_set_hash));
    } else {
        panic!("Invalid proof type!");
    }

    sp1_zkvm::io::commit(&output);
}
