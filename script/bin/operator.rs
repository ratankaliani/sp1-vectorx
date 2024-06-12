//! A simple script to generate and verify the proof of a given program.

use alloy_primitives::U256;
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::{HeaderRangeOutputs, ProofOutput, ProofType, RotateOutputs};
use sp1_vectorx_script::input::RpcDataFetcher;
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
use alloy_sol_types::{sol, SolCall, SolType, SolValue};
use sp1_vectorx_script::contract::ContractClient;

sol! {
    contract VectorX {
        uint64 public latestAuthoritySetId;
        uint32 public latestBlock;

        function rotate(bytes calldata proof, bytes calldata publicValues) external;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv::dotenv().ok();
    setup_logger();

    let contract_client = ContractClient::default();

    // Supply an initial authority set id, trusted block, and target block.
    let authority_set_id_call_data = VectorX::latestAuthoritySetIdCall {}.abi_encode();
    let authority_set_id = contract_client.read(authority_set_id_call_data).await?;
    let authority_set_id = U256::abi_decode(&authority_set_id, true).unwrap();
    let authority_set_id: u64 = authority_set_id.try_into().unwrap();

    let trusted_block_call_data = VectorX::latestBlockCall {}.abi_encode();
    let trusted_block = contract_client.read(trusted_block_call_data).await?;
    let trusted_block = U256::abi_decode(&trusted_block, true).unwrap();
    let trusted_block: u32 = trusted_block.try_into().unwrap();
    let target_block = trusted_block + 512;

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
    let outputs: (u8, alloy_primitives::Bytes, alloy_primitives::Bytes) =
        ProofOutput::abi_decode(&output_bytes, true)?;

    // Log proof outputs.
    log_proof_outputs(outputs);

    // Verify proof.
    client.verify_plonk(&proof, &vk)?;

    // Save proof.
    proof.save("proof-with-io.json")?;

    // Relay the proof to the contract.
    let proof_as_bytes = hex::decode(&proof.proof.encoded_proof).unwrap();
    let verify_vectorx_proof_call_data = VectorX::rotateCall {
        publicValues: proof.public_values.to_vec().into(),
        proof: proof_as_bytes.into(),
    }
    .abi_encode();

    contract_client.send(verify_vectorx_proof_call_data).await?;

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
