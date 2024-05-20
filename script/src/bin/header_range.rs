//! A simple script to generate and verify the proof of a given program.

use codec::Encode;
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::HeaderRangeProofRequestData;
use sp1_vectorx_script::input::RpcDataFetcher;
use subxt::config::Header;

const HEADER_RANGE_ELF: &[u8] =
    include_bytes!("../../../header-range/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    setup_logger();

    let fetcher = RpcDataFetcher::new().await;

    // TODO: Update this to read from args/on-chain.
    let head = fetcher.get_head().await;
    let trusted_block = head.number - 10;

    let trusted_header = fetcher.get_header(trusted_block).await;
    let trusted_header_hash = trusted_header.hash();

    let authority_set_id = fetcher.get_authority_set_id(trusted_block).await;
    let authority_set_hash = fetcher.compute_authority_set_hash(trusted_block).await;

    // TODO: It may make sense to fetch this from an indexer similar to VectorX, this isn't resilient to downtime.
    let (target_justification, target_header) = fetcher.get_latest_justification_data().await;
    let target_block = target_header.number;

    let headers = fetcher
        .get_block_headers_range(trusted_block, target_block)
        .await;
    let encoded_headers: Vec<Vec<u8>> = headers.iter().map(|header| header.encode()).collect();

    // Generate proof.
    let mut stdin = SP1Stdin::new();
    stdin.write(&HeaderRangeProofRequestData {
        trusted_block,
        target_block,
        trusted_header_hash: trusted_header_hash.0,
        authority_set_hash: authority_set_hash.0,
        authority_set_id,
    });
    // Should be target_block - trusted_block + 1 headers.
    for encoded_header in encoded_headers {
        stdin.write_vec(encoded_header);
    }

    stdin.write(&target_justification);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(HEADER_RANGE_ELF);
    let proof = client.prove(&pk, stdin).expect("proving failed");
    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
