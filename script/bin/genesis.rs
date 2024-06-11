//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!
use avail_subxt::config::Header;
use sp1_sdk::{HashableKey, ProverClient};
use sp1_vectorx_script::input::RpcDataFetcher;
const VECTORX_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;
    let client = ProverClient::new();
    let (_pk, vk) = client.setup(VECTORX_ELF);

    let header = fetcher.get_head().await;
    let block_number = header.number - 20_000;
    let header_hash = header.hash();
    let authority_set_id = fetcher.get_authority_set_id(block_number).await;
    let authority_set_hash = fetcher
        .compute_authority_set_hash_for_block(block_number)
        .await;

    println!("GENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nGENESIS_AUTHORITY_SET_ID={}\nGENESIS_AUTHORITY_SET_HASH={}\nVECTORX_PROGRAM_VKEY={}\nHEADER_RANGE_COMMITMENT_TREE_SIZE={}",
             block_number,
             format!("{:#x}", header_hash),
             authority_set_id,
             format!("{:#x}", authority_set_hash),
             vk.bytes32(),
             512,
             );

    Ok(())
}
