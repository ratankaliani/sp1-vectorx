//! A simple script to generate and verify the proof of a given program.
use codec::Encode;
use crypto::{blake2b::Blake2b, digest::Digest};
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::HeaderRangeProofRequestData;
use sp1_vectorx_script::input::RpcDataFetcher;
use subxt::config::Header;

const HEADER_RANGE_ELF: &[u8] =
    include_bytes!("../../../header-range/elf/riscv32im-succinct-zkvm-elf");

async fn get_header_range_proof_request_data(
    fetcher: &RpcDataFetcher,
    trusted_block: u32,
    target_block: u32,
) -> HeaderRangeProofRequestData {
    let trusted_header = fetcher.get_header(trusted_block).await;
    let trusted_header_hash = trusted_header.hash();
    let (authority_set_id, authority_set_hash) = fetcher
        .get_authority_set_data_for_block(trusted_block)
        .await;

    let num_headers = target_block - trusted_block + 1;
    // TODO: Should be fetched from the contract when we take this to production.
    let merkle_tree_size = fetcher.get_merkle_tree_size(num_headers);

    let headers = fetcher
        .get_block_headers_range(trusted_block, target_block)
        .await;
    let encoded_headers: Vec<Vec<u8>> = headers.iter().map(|header| header.encode()).collect();

    HeaderRangeProofRequestData {
        trusted_block,
        target_block,
        trusted_header_hash: trusted_header_hash.0,
        authority_set_hash: authority_set_hash.0,
        authority_set_id,
        merkle_tree_size,
        encoded_headers,
    }
}

async fn generate_and_verify_proof(trusted_block: u32, target_block: u32) -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;

    let request_data =
        get_header_range_proof_request_data(&fetcher, trusted_block, target_block).await;

    let (target_justification, _) = fetcher.get_justification_data_for_block(target_block).await;

    // Generate proof.
    let mut stdin: SP1Stdin = SP1Stdin::new();
    stdin.write(&request_data);
    stdin.write(&target_justification);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(HEADER_RANGE_ELF);
    let mut proof = client.prove(&pk, stdin)?;

    // Read outputs.
    let mut state_root_commitment = [0u8; 32];
    let mut data_root_commitment = [0u8; 32];
    proof.public_values.read_slice(&mut state_root_commitment);
    proof.public_values.read_slice(&mut data_root_commitment);

    // Verify proof.
    client.verify(&proof, &vk)?;

    // Save proof.
    proof.save("proof-with-io.json")?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    let trusted_block = 237600;
    let target_block = 237960;

    generate_and_verify_proof(trusted_block, target_block).await?;

    println!("Successfully generated and verified proof for the program!");

    Ok(())
}
