//! A simple script to generate and verify the proof of a given program.

use std::env;

use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_script::input::RpcDataFetcher;

const ROTATE_ELF: &[u8] = include_bytes!("../../../rotate/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    setup_logger();

    let fetcher = RpcDataFetcher::new().await;

    // Supply an initial authority set id.
    // TODO: Read from args/contract in the future. Set to 1 for testing.
    let authority_set_id = 1u64;
    let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;

    // Fetch the authority set hash for the specified authority set id.
    // TODO: In the future, this will be read from the contract, along with the epoch end block number.
    let authority_set_hash = fetcher.compute_authority_set_hash(epoch_end_block - 1);

    // Fetch the justification for the epoch end block of the specified authority set id.
    let justification = fetcher
        .get_justification_data_rotate(authority_set_id)
        .await;

    // Fetch the header rotate data for the specified authority set id.
    let header_rotate_data = fetcher.get_header_rotate(authority_set_id).await;

    // Generate proof.
    let mut stdin = SP1Stdin::new();

    env::set_var("SP1_PROVER", "mock");
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ROTATE_ELF);

    env::set_var("SP1_PROVER", "mock");
    let proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}
