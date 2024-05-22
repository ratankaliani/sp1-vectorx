//! A simple script to generate and verify the proof of a given program.

use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::RotateInput;
use sp1_vectorx_script::input::RpcDataFetcher;

const ROTATE_ELF: &[u8] = include_bytes!("../../../rotate/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() {
    setup_logger();

    let fetcher = RpcDataFetcher::new().await;

    // Supply an initial authority set id.
    // TODO: Read from args/contract in the future. Set to 1 for testing.
    let authority_set_id = 74u64;
    let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;

    // Fetch the authority set hash for the specified authority set id.
    // TODO: In the future, this will be read from the contract, along with the epoch end block number.
    let authority_set_hash = fetcher
        .compute_authority_set_hash_for_block(epoch_end_block - 1)
        .await;

    // Fetch the justification for the epoch end block of the specified authority set id.
    let justification = fetcher
        .get_justification_data_rotate(authority_set_id)
        .await;

    let header_rotate_data = fetcher.get_header_rotate(authority_set_id).await;

    // Generate proof.
    let mut stdin = SP1Stdin::new();
    let rotate_input = RotateInput {
        current_authority_set_id: authority_set_id,
        current_authority_set_hash: authority_set_hash.0.to_vec(),
        justification,
        header_rotate_data,
    };
    stdin.write(&rotate_input);

    let client = ProverClient::new();
    let (pk, vk) = client.setup(ROTATE_ELF);
    let mut proof = client.prove(&pk, stdin).expect("proving failed");

    // Read outputs.
    let new_authority_set_hash_bytes32 = proof.public_values.read::<[u8; 32]>();
    let new_authority_set_hash = hex::encode(new_authority_set_hash_bytes32);
    println!("New authority set hash: {}", new_authority_set_hash);

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}

#[cfg(test)]
mod tests {
    use sp1_vectorx_primitives::compute_authority_set_commitment;

    use super::*;

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_compute_authority_set_commitment() {
        let fetcher = RpcDataFetcher::new().await;

        let authority_set_id = 71u64;
        let epoch_end_block = fetcher.last_justified_block(authority_set_id).await;

        let header_rotate_data = fetcher.get_header_rotate(authority_set_id).await;

        // Generate next authority set hash.
        let generated_next_authority_set_hash_bytes32 = compute_authority_set_commitment(
            header_rotate_data.num_authorities,
            header_rotate_data.pubkeys.clone(),
        );
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
