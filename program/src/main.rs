//! A simple program to be proven inside the zkVM.

#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_sol_types::SolType;
use sp1_vectorx_primitives::{
    consts::HEADER_OUTPUTS_LENGTH,
    header_range::verify_header_range,
    rotate::verify_rotate,
    types::{CircuitJustification, HeaderRangeInputs, ProofOutput, ProofType, RotateInputs},
};

pub fn main() {
    let proof_type: ProofType = sp1_zkvm::io::read::<ProofType>();
    let mut output;

    match proof_type {
        ProofType::HeaderRangeProof => {
            let header_range_inputs = sp1_zkvm::io::read::<HeaderRangeInputs>();
            let target_justification = sp1_zkvm::io::read::<CircuitJustification>();
            let header_range_outputs =
                verify_header_range(header_range_inputs, target_justification);
            output = ProofOutput::abi_encode(&(0, header_range_outputs, [0u8; 32]));
        }
        ProofType::RotateProof => {
            let rotate_inputs = sp1_zkvm::io::read::<RotateInputs>();
            let new_authority_set_hash = verify_rotate(rotate_inputs);
            output =
                ProofOutput::abi_encode(&(1, [0u8; HEADER_OUTPUTS_LENGTH], new_authority_set_hash));
        }
    }

    sp1_zkvm::io::commit_slice(&output);
}
