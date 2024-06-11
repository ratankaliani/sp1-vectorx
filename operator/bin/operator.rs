//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::{HeaderRangeOutputs, ProofOutput, ProofType, RotateOutputs};
use sp1_vectorx_script::input::RpcDataFetcher;
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
use alloy_sol_types::{sol, SolCall, SolType, SolValue};
use vectorx_operator::ContractClient;

sol! {
    contract VectorX {
        uint64 public latestAuthoritySetId;

        function rotate(bytes calldata proof, bytes calldata publicValues) external;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();
    let contract_client = ContractClient::default();
    // Supply an initial authority set id, trusted block, and target block.
    // TODO: Read from args/contract in the future.
    let authority_set_id = 100u64;
    let trusted_block = 272355;
    let target_block = 272534;

    let proof_type = ProofType::RotateProof;

    let fetcher = RpcDataFetcher::new().await;
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut stdin: SP1Stdin = SP1Stdin::new();
    let mut proof;

    // Fetch & write inputs to proof based on the proof type.
    match proof_type {
        ProofType::HeaderRangeProof => {
            let header_range_inputs = fetcher
                .get_header_range_inputs(trusted_block, target_block)
                .await;
            let (target_justification, _) =
                fetcher.get_justification_data_for_block(target_block).await;

            stdin.write(&proof_type);
            stdin.write(&header_range_inputs);
            stdin.write(&target_justification);
        }
        ProofType::RotateProof => {
            let rotate_input = fetcher.get_rotate_inputs(authority_set_id).await;

            stdin.write(&proof_type);
            stdin.write(&rotate_input);
        }
    }

    proof = client.prove_plonk(&pk, stdin)?;

    println!("Successfully generated and verified proof for the program!");

    // Read outputs.
    let mut output_bytes = [0u8; 544];
    proof.public_values.read_slice(&mut output_bytes);
    let outputs = ProofOutput::abi_decode(&output_bytes, true)?;

    // Log proof outputs.
    log_proof_outputs(outputs);

    // Verify proof.
    client.verify_plonk(&proof, &vk)?;

    // Save proof.
    proof.save("proof-with-io.json")?;
    Ok(())
}

fn log_proof_outputs(outputs: (u8, alloy_primitives::Bytes, alloy_primitives::Bytes)) {
    let proof_type = ProofType::from_uint(outputs.0).unwrap();
    match proof_type {
        ProofType::HeaderRangeProof => {
            let header_range_outputs = HeaderRangeOutputs::abi_decode(&outputs.1, true).unwrap();
            println!("Proof Type: Header Range Proof");
            println!("Header Range Outputs: {:?}", header_range_outputs);
        }
        ProofType::RotateProof => {
            let rotate_outputs = RotateOutputs::abi_decode(&outputs.2, true).unwrap();
            println!("Proof Type: Rotate Proof");
            println!("Rotate Outputs: {:?}", rotate_outputs)
        }
    }
}
