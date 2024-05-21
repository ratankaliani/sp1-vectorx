//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_script::input::RpcDataFetcher;

const ROTATE_ELF: &[u8] = include_bytes!("../../../rotate/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    setup_logger();

    let fetcher = RpcDataFetcher::new().await;

    // Supply an initial authority set id.
    // TODO: Read from args/contract in the future. Set to 1 for testing.
    let authority_set_id = 71u64;
    let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;

    // Fetch the authority set hash for the specified authority set id.
    // TODO: In the future, this will be read from the contract, along with the epoch end block number.
    let authority_set_hash = fetcher
        .compute_authority_set_hash(epoch_end_block - 1)
        .await;

    // Fetch the justification for the epoch end block of the specified authority set id.
    let justification = fetcher
        .get_justification_data_rotate(authority_set_id)
        .await;

    let header_rotate_data = fetcher.get_header_rotate(authority_set_id).await;

    // Generate proof.
    let mut stdin = SP1Stdin::new();
    stdin.write(&authority_set_id);
    stdin.write(&authority_set_hash);
    stdin.write(&justification);
    stdin.write(&header_rotate_data);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ROTATE_ELF);
    let mut proof = client.prove(&pk, stdin).expect("proving failed");
    
    // Read outputs.    
    let new_authority_set_hash_bytes32 = proof.public_values.read::<[u8; 32]>();
    let new_authority_set_hash = hex::encode(new_authority_set_hash_bytes32);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}