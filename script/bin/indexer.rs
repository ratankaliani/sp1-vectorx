use std::collections::HashMap;
use std::env;

use alloy_primitives::B512;
use avail_subxt::config::Header as HeaderTrait;
use avail_subxt::{api, AvailClient, RpcParams};
use codec::Encode;
use log::debug;
use sp1_vectorx_primitives::types::CircuitJustification;
use sp1_vectorx_script::input::RpcDataFetcher;
use sp1_vectorx_script::types::{GrandpaJustification, SignerMessage};
use sp_core::ed25519::{self};
use sp_core::{blake2_256, Pair, H256};
use subxt::backend::rpc::RpcSubscription;

async fn listen_for_justifications(mut fetcher: RpcDataFetcher) {
    let sub: Result<RpcSubscription<GrandpaJustification>, _> = fetcher
        .client
        .rpc()
        .subscribe(
            "grandpa_subscribeJustifications",
            RpcParams::new(),
            "grandpa_unsubscribeJustifications",
        )
        .await;
    let mut sub = sub.unwrap();

    // Wait for new justification.
    while let Some(Ok(justification)) = sub.next().await {
        debug!(
            "New justification from block {}",
            justification.commit.target_number
        );

        // Get the header corresponding to the new justification.
        let header = fetcher
            .client
            .legacy_rpc()
            .chain_get_header(Some(justification.commit.target_hash))
            .await
            .unwrap()
            .unwrap();

        // A bit redundant, but just to make sure the hash is correct. This confirms that the
        // header encoding + block encoding match.
        let block_hash = justification.commit.target_hash;
        let header_hash = header.hash();
        let calculated_hash: H256 = Encode::using_encoded(&header, blake2_256).into();
        if header_hash != calculated_hash || block_hash != calculated_hash {
            panic!("Header hash does not match block hash, avail-subxt crate is out of sync.");
        }

        // Get current authority set ID.
        let set_id_key = api::storage().grandpa().current_set_id();
        let authority_set_id = fetcher
            .client
            .storage()
            .at(block_hash)
            .fetch(&set_id_key)
            .await
            .unwrap()
            .unwrap();

        // Form a message which is signed in the justification.
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &authority_set_id,
        ));

        // Verify all the signatures of the justification and extract the public keys. The ordering
        // of the authority set will already be canonical and sorted in the justification on ID.

        let validators = justification
            .commit
            .precommits
            .iter()
            .filter_map(|precommit| {
                let is_ok = <ed25519::Pair as Pair>::verify(
                    &precommit.clone().signature,
                    signed_message.as_slice(),
                    &precommit.clone().id,
                );
                if is_ok {
                    Some((
                        precommit.clone().id.0.to_vec(),
                        precommit.clone().signature.0.to_vec(),
                    ))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let pubkeys = validators.iter().map(|v| v.0.clone()).collect::<Vec<_>>();
        let signatures = validators.iter().map(|v| v.1.clone()).collect::<Vec<_>>();

        // Create map from pubkey to signature.
        let mut pubkey_to_signature = HashMap::new();
        for (pubkey, signature) in pubkeys.iter().zip(signatures.iter()) {
            pubkey_to_signature.insert(pubkey.to_vec(), signature.to_vec());
        }

        // Check that more than 2/3 of the validators signed the justification.
        // Note: Assumes the validator set have equal voting power.
        let authorities = fetcher.get_authorities(header.number - 1).await;
        let num_authorities = authorities.len();
        let signed_count = pubkeys.len();
        let required_signatures = (num_authorities * 2) / 3;
        if signed_count <= required_signatures {
            continue;
        }

        // Create justification data.
        let mut justification_pubkeys = Vec::new();
        let mut justification_signatures = Vec::new();
        for authority_pubkey in authorities.iter() {
            if let Some(signature) = pubkey_to_signature.get(&authority_pubkey.0.to_vec()) {
                justification_pubkeys.push(*authority_pubkey);
                let sig = B512::from_slice(&signature);
                justification_signatures.push(Some(sig));
            } else {
                justification_pubkeys.push(*authority_pubkey);
                justification_signatures.push(None);
            }
        }

        // Get the authority set that attested to block_number.
        let (authority_set_id, authority_set_hash) = fetcher
            .get_authority_set_data_for_block(header.number - 1)
            .await;

        // Add justification to Redis.
        let store_justification_data = CircuitJustification {
            block_number: header.number,
            signed_message: signed_message.clone(),
            pubkeys: justification_pubkeys,
            signatures: justification_signatures,
            num_authorities: authorities.len(),
            authority_set_id,
            current_authority_set_hash: authority_set_hash,
            block_hash: block_hash.0.into(),
        };
        fetcher
            .redis
            .add_justification(&fetcher.avail_chain_id, store_justification_data)
            .await;
    }
}

#[tokio::main]
pub async fn main() {
    env::set_var("RUST_LOG", "debug");
    dotenv::dotenv().ok();
    env_logger::init();

    // Get the chain from the environment.
    let avail_url = env::var("AVAIL_URL").unwrap();
    let avail_chain_id = env::var("AVAIL_CHAIN_ID").unwrap();

    let fetcher = RpcDataFetcher {
        client: AvailClient::new(avail_url.clone()).await.unwrap(),
        redis: vectorx::input::RedisClient::new().await,
        avail_chain_id,
    };

    listen_for_justifications(fetcher).await;
}
