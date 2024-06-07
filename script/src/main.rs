//! A simple script to generate and verify the proof of a given program.
use alloy_primitives::B256;
use codec::Encode;
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::merkle::get_merkle_tree_size;
use sp1_vectorx_primitives::types::HeaderRangeProofRequestData;
use sp1_vectorx_primitives::types::RotateInput;
use sp1_vectorx_primitives::types::HeaderRangeOutputs;
use sp1_vectorx_script::input::{RpcDataFetcher};
use subxt::config::Header;

const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

async fn get_header_range_proof_request_data(
    fetcher: &RpcDataFetcher,
    trusted_block: u32,
    target_block: u32,
) -> HeaderRangeProofRequestData {
    let trusted_header = fetcher.get_header(trusted_block).await;
    let trusted_header_hash = B256::from_slice(&trusted_header.hash().0);
    let (authority_set_id, authority_set_hash) = fetcher
        .get_authority_set_data_for_block(trusted_block)
        .await;

    let num_headers = target_block - trusted_block + 1;
    // TODO: Should be fetched from the contract when we take this to production.
    let merkle_tree_size = get_merkle_tree_size(num_headers);

    let headers = fetcher
        .get_block_headers_range(trusted_block, target_block)
        .await;
    let encoded_headers: Vec<Vec<u8>> = headers.iter().map(|header| header.encode()).collect();

    HeaderRangeProofRequestData {
        trusted_block,
        target_block,
        trusted_header_hash,
        authority_set_hash,
        authority_set_id,
        merkle_tree_size,
        encoded_headers,
    }
}

async fn generate_and_verify_proof(
    trusted_block: u32,
    target_block: u32,
    authority_set_id: u64,
) -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;

    let request_data =
        get_header_range_proof_request_data(&fetcher, trusted_block, target_block).await;

    let (target_justification, _) = fetcher.get_justification_data_for_block(target_block).await;

    let rotate_input = get_rotate_input(&fetcher, authority_set_id).await?;

    // Generate proof.
    let mut stdin: SP1Stdin = SP1Stdin::new();
    stdin.write(&request_data);
    stdin.write(&target_justification);
    stdin.write(&rotate_input);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    let mut proof = client.prove(&pk, stdin)?;

    // Read outputs.
    let new_authority_set_hash_bytes32 = proof.public_values.read::<[u8; 32]>();
    let _new_authority_set_hash = hex::encode(new_authority_set_hash_bytes32);
    // let header_range_outputs: HeaderRangeOutputs = proof.public_values.read::<HeaderRangeOutputs>();

    // Verify proof.
    client.verify(&proof, &vk)?;

    // Save proof.
    proof.save("proof-with-io.json")?;

    Ok(())
}

async fn get_rotate_input(
    fetcher: &RpcDataFetcher,
    authority_set_id: u64,
) -> anyhow::Result<RotateInput> {
    let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;

    let authority_set_hash = fetcher
        .compute_authority_set_hash_for_block(epoch_end_block - 1)
        .await;

    let justification = fetcher
        .get_justification_data_rotate(authority_set_id)
        .await;

    let header_rotate_data = fetcher.get_header_rotate(authority_set_id).await;

    Ok(RotateInput {
        current_authority_set_id: authority_set_id,
        current_authority_set_hash: authority_set_hash,
        justification,
        header_rotate_data,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    // Supply an initial authority set id.
    // TODO: Read from args/contract in the future. Set to 1 for testing.
    let authority_set_id = 74u64;
    let trusted_block = 272355;
    let target_block = 272534;

    generate_and_verify_proof(trusted_block, target_block, authority_set_id).await?;

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
