//! To build the binary:
//!
//!     `cargo build --release --bin genesis`
//!
//!
//!
//!
//!
use avail_subxt::config::Header;
use clap::Parser;
use sp1_sdk::{HashableKey, ProverClient};
use sp1_vectorx_script::input::RpcDataFetcher;
const VECTORX_ELF: &[u8] = include_bytes!("../../program/elf/riscv32im-succinct-zkvm-elf");

#[derive(Parser, Debug, Clone)]
#[command(about = "Get the genesis parameters from a block.")]
pub struct GenesisArgs {
    #[arg(long)]
    pub block: Option<u32>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let fetcher = RpcDataFetcher::new().await;
    let client = ProverClient::new();
    let (_pk, vk) = client.setup(VECTORX_ELF);

    let args = GenesisArgs::parse();

    let header;
    if let Some(block) = args.block {
        header = fetcher.get_header(block).await;
    } else {
        header = fetcher.get_head().await;
    }
    let header_hash = header.hash();
    let authority_set_id = fetcher.get_authority_set_id(header.number).await;
    let authority_set_hash = fetcher
        .compute_authority_set_hash_for_block(header.number)
        .await;

    println!("GENESIS_HEIGHT={:?}\nGENESIS_HEADER={}\nGENESIS_AUTHORITY_SET_ID={}\nGENESIS_AUTHORITY_SET_HASH={}\nVECTORX_PROGRAM_VKEY={}\nHEADER_RANGE_COMMITMENT_TREE_SIZE={}",
             header.number,
             format!("{:#x}", header_hash),
             authority_set_id,
             format!("{:#x}", authority_set_hash),
             vk.bytes32(),
             512,
    );

    Ok(())
}
