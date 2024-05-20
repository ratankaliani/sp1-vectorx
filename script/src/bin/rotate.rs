//! A simple script to generate and verify the proof of a given program.

use std::env;

use ed25519_consensus::{Signature, SigningKey, VerificationKey, VerificationKeyBytes};
use rand::{thread_rng, Rng};
use sp1_sdk::{utils::setup_logger, ProverClient, SP1Stdin};

const ELF: &[u8] = include_bytes!("../../../program/elf/riscv32im-succinct-zkvm-elf");

fn main() {
    setup_logger();

    // Supply an initial authority set id.
    // TODO: Read from args, then read from contract. Reading from contract do at the end.
    let authority_set_id = 1u64;

    // Fetch the authority set hash for the specified authority set id.
    // TODO: In the future, this will be read from the contract, along with the epoch end block number.
    let authority_set_hash = "0x0000000000000000000000000000000000000000000000000000000000000000";

    // Fetch the justification for the epoch end block of the specified authority set id.

    //

    // Generate proof.
    let mut stdin = SP1Stdin::new();
    let sk = SigningKey::new(thread_rng());
    let pk = VerificationKey::from(&sk);
    // Random message with thread_rng.
    let msg = thread_rng().gen::<[u8; 32]>();

    let sig = sk.sign(&msg[..]);

    let pk_array: [u8; 32] = pk.into();
    let sig_array: [u8; 64] = sig.into();

    stdin.write_vec(pk_array.to_vec());
    stdin.write_vec(sig_array.to_vec());
    stdin.write_vec(msg.to_vec());

    env::set_var("SP1_PROVER", "mock");
    let client = ProverClient::new();
    let (pk, vk) = client.setup(ELF);
    env::set_var("SP1_PROVER", "mock");
    let mut proof = client.prove(&pk, stdin).expect("proving failed");

    // Verify proof.
    client.verify(&proof, &vk).expect("verification failed");

    // Save proof.
    proof
        .save("proof-with-io.json")
        .expect("saving proof failed");

    println!("successfully generated and verified proof for the program!")
}