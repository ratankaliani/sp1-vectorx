//! A simple script to test the generation of proofs.

use services::input::RpcDataFetcher;
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};
use sp1_vectorx_primitives::types::ProofType;
const ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    setup_logger();

    // Supply an initial authority set id, trusted block, and target block.
    let authority_set_id = 74u64;
    let trusted_block = 272355;
    let target_block = 272534;

    let proof_type = ProofType::HeaderRangeProof;

    let fetcher = RpcDataFetcher::new().await;
    let client = ProverClient::new();
    let mut stdin: SP1Stdin = SP1Stdin::new();

    // Fetch & write inputs to proof based on the proof type.
    match proof_type {
        ProofType::HeaderRangeProof => {
            let header_range_inputs = fetcher
                .get_header_range_inputs(trusted_block, target_block)
                .await;
            let justification_data = fetcher
                .get_justification_data_for_block(target_block)
                .await
                .unwrap();

            stdin.write(&proof_type);
            stdin.write(&header_range_inputs);
            stdin.write(&justification_data.0);
        }
        ProofType::RotateProof => {
            let rotate_input = fetcher.get_rotate_inputs(authority_set_id).await;

            stdin.write(&proof_type);
            stdin.write(&rotate_input);
        }
    }

    let (_, report) = client.execute(ELF, stdin)?;

    println!("Exeuction Report: {:?}", report);

    Ok(())
}
