//! A simple script to generate and verify the proof of a given program.
use alloy_primitives::B256;
use alloy_sol_types::{sol, SolType};
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_script::input::RpcDataFetcher;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

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

async fn generate_and_verify_header_range_proof(
    trusted_block: u32,
    target_block: u32,
) -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;

    let request_data = fetcher
        .get_header_range_inputs(trusted_block, target_block)
        .await;

    let (target_justification, _) = fetcher.get_justification_data_for_block(target_block).await;

    // Generate proof.
    let mut stdin: SP1Stdin = SP1Stdin::new();
    stdin.write(&true); // Flag to indicate header range proof.
    stdin.write(&request_data);
    stdin.write(&target_justification);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin)?;

    // Read outputs.
    let mut mutable_buffer = [0u8; 224];
    proof.public_values.read_slice(&mut mutable_buffer);
    let _header_range_outputs = HeaderRangeOutputs::abi_decode(&mutable_buffer, true)?;

    // Verify proof.
    client.verify(&proof, &vk)?;

    // Save proof.
    proof.save("proof-with-io.json")?;

    Ok(())
}

async fn generate_and_verify_rotate_proof(authority_set_id: u64) -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;
    let rotate_input = fetcher.get_rotate_inputs(authority_set_id).await;

    // Generate proof.
    let mut stdin: SP1Stdin = SP1Stdin::new();
    stdin.write(&false); // Flag to indicate rotate proof.
    stdin.write(&rotate_input);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin)?;

    // Read outputs.
    let _new_authority_set_hash = proof.public_values.read::<B256>();

    // Verify proof.
    client.verify(&proof, &vk)?;

    // Save proof.
    proof.save("proof-with-io.json")?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    // Supply an initial authority set id.
    // TODO: Read from args/contract in the future. Set to 1 for testing.
    let authority_set_id = 74u64;
    let trusted_block = 272355;
    let target_block = 272534;

    let header_range_proof = false; // true for header range proof, false for rotate proof.

    if header_range_proof {
        generate_and_verify_header_range_proof(trusted_block, target_block).await?;
    } else {
        generate_and_verify_rotate_proof(authority_set_id).await?;
    }

    println!("Successfully generated and verified proof for the program!");

    Ok(())
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
