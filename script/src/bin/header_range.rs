//! A simple script to generate and verify the proof of a given program.

use crypto::{blake2b::Blake2b, digest::Digest};

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
    // let head = fetcher.get_head().await;
    let trusted_block = 237600;
    let target_block = 237960;

    let trusted_header = fetcher.get_header(trusted_block).await;
    let trusted_header_hash = trusted_header.hash();

    let (authority_set_id, authority_set_hash) = fetcher
        .get_authority_set_data_for_block(trusted_block)
        .await;

    // TODO: It may make sense to fetch this from an indexer similar to VectorX, this isn't resilient to downtime.
    let (target_justification, _) = fetcher.get_justification_data_for_block(target_block).await;

    let headers = fetcher
        .get_block_headers_range(trusted_block, target_block)
        .await;
    let encoded_headers: Vec<Vec<u8>> = headers.iter().map(|header| header.encode()).collect();

    // TODO(remove): Sanity check that trusted header hash matches the encoded header when hashed.
    const DIGEST_SIZE: usize = 32;
    let mut hasher = Blake2b::new(DIGEST_SIZE);
    hasher.input(encoded_headers[0].as_slice());

    let mut digest_bytes = [0u8; DIGEST_SIZE];
    hasher.result(&mut digest_bytes);

    assert_eq!(headers[0].hash().0.to_vec(), trusted_header_hash.0.to_vec());
    assert_eq!(trusted_header_hash.0.to_vec(), digest_bytes.to_vec());

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
    let mut proof = client.prove(&pk, stdin).expect("proving failed");

    // Read outputs.
    let mut state_root_commitment = [0u8; 32];
    let mut data_root_commitment = [0u8; 32];
    proof.public_values.read_slice(&mut state_root_commitment);
    proof.public_values.read_slice(&mut data_root_commitment);
    let st = hex::encode(state_root_commitment);
    let da = hex::encode(data_root_commitment);

    println!("State root commitment: {}", st);
    println!("Data root commitment: {}", da);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
