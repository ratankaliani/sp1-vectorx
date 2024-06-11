//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::{HeaderRangeOutputs, ProofOutput, ProofType, RotateOutputs};
use sp1_vectorx_script::input::RpcDataFetcher;
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");
use alloy_sol_types::SolType;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    // Supply an initial authority set id, trusted block, and target block.
    // TODO: Read from args/contract in the future.
    let authority_set_id = 74u64;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sp1_vectorx_primitives::compute_authority_set_commitment;

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_compute_authority_set_commitment() {
        let fetcher = RpcDataFetcher::new().await;
        let authority_set_id = 71u64;
        let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;
        let header_rotate_data = fetcher.get_header_rotate(authority_set_id).await;

        // Generate next authority set hash.
        let generated_next_authority_set_hash_bytes32 =
            compute_authority_set_commitment(&header_rotate_data.pubkeys);
        let generated_next_authority_set_hash =
            hex::encode(generated_next_authority_set_hash_bytes32);
        println!("Generated hash: {}", generated_next_authority_set_hash);

        // Get correct next authority set hash.
        let next_authority_set_hash_bytes32 = fetcher
            .compute_authority_set_hash_for_block(epoch_end_block)
            .await
            .0
            .to_vec();
        let next_authority_set_hash = hex::encode(next_authority_set_hash_bytes32);
        println!("Correct hash: {}", next_authority_set_hash);

        // Verify that computed authority set hash is correct.
        assert_eq!(next_authority_set_hash, generated_next_authority_set_hash);
    }
}
