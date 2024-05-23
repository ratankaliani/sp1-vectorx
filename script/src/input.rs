use anyhow::Result;
use ethers::types::H256;
use sp1_vectorx_primitives::types::{CircuitJustification, HeaderRotateData};
use sp1_vectorx_primitives::verify_signature;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::env;
use subxt::backend::rpc::RpcSubscription;

use avail_subxt::avail_client::AvailClient;
use avail_subxt::config::substrate::DigestItem;
use avail_subxt::primitives::Header;
use avail_subxt::{api, RpcParams};
use codec::{Compact, Decode, Encode};

use futures::future::join_all;
use sha2::{Digest, Sha256};
use sp_core::ed25519;

use crate::consts::{HASH_SIZE, PUBKEY_LENGTH, VALIDATOR_LENGTH};
use crate::redis::RedisClient;
use crate::types::{EncodedFinalityProof, FinalityProof, GrandpaJustification, SignerMessage};

// Compute the chained hash of the authority set.
pub fn compute_authority_set_hash_from_authorities(authorities: &[[u8; 32]]) -> Vec<u8> {
    let mut hash_so_far = Vec::new();
    for authority in authorities {
        let mut hasher = sha2::Sha256::new();
        hasher.update(hash_so_far);
        hasher.update(authority);
        hash_so_far = hasher.finalize().to_vec();
    }
    hash_so_far
}

pub struct RpcDataFetcher {
    pub client: AvailClient,
    pub redis: RedisClient,
    pub avail_chain_id: String,
}

impl RpcDataFetcher {
    pub async fn new() -> Self {
        dotenv::dotenv().ok();

        let url = env::var("AVAIL_URL").expect("AVAIL_URL must be set");
        let avail_chain_id = env::var("AVAIL_CHAIN_ID").expect("AVAIL_CHAIN_ID must be set");
        let client = AvailClient::new(url.as_str()).await.unwrap();
        let redis = RedisClient::new();
        RpcDataFetcher {
            client,
            redis,
            avail_chain_id,
        }
    }

    // TODO: Should be removed when we read header_range_tree_commitment_size from the contract.
    pub fn get_merkle_tree_size(&self, num_headers: u32) -> usize {
        let mut size = 1;
        while size < num_headers {
            size *= 2;
        }
        size.try_into().unwrap()
    }

    // This function returns the last block justified by target_authority_set_id. This block
    // also specifies the new authority set, which starts justifying after this block.
    // Returns 0 if curr_authority_set_id <= target_authority_set_id.
    pub async fn last_justified_block(&self, target_authority_set_id: u64) -> u32 {
        let mut low = 0;
        let head_block = self.get_head().await;
        let mut high = head_block.number;
        let mut epoch_end_block_number = 0;

        while low <= high {
            let mid = (low + high) / 2;
            let mid_authority_set_id = self.get_authority_set_id(mid).await;

            match mid_authority_set_id.cmp(&(target_authority_set_id + 1)) {
                Ordering::Equal => {
                    if mid == 0 {
                        // Special case: there is no block "mid - 1", just return the found block.
                        epoch_end_block_number = mid;
                        break;
                    }
                    let prev_authority_set_id = self.get_authority_set_id(mid - 1).await;
                    if prev_authority_set_id == target_authority_set_id {
                        epoch_end_block_number = mid;
                        break;
                    } else {
                        high = mid - 1;
                    }
                }
                Ordering::Less => low = mid + 1,
                Ordering::Greater => high = mid - 1,
            }
        }
        epoch_end_block_number
    }

    pub async fn get_block_hash(&self, block_number: u32) -> H256 {
        let block_hash = self
            .client
            .legacy_rpc()
            .chain_get_block_hash(Some(block_number.into()))
            .await;

        block_hash.unwrap().unwrap()
    }

    // Computes the simple Merkle root of the leaves.
    // If the number of leaves is not a power of 2, the leaves are extended with 0s to the next power of 2.
    pub fn get_merkle_root(leaves: Vec<Vec<u8>>) -> Vec<u8> {
        if leaves.is_empty() {
            return vec![];
        }

        // Extend leaves to a power of 2.
        let mut leaves = leaves;
        while leaves.len().count_ones() != 1 {
            leaves.push([0u8; 32].to_vec());
        }

        // In VectorX, the leaves are not hashed.
        let mut nodes = leaves.clone();
        while nodes.len() > 1 {
            nodes = (0..nodes.len() / 2)
                .map(|i| {
                    let mut hasher = Sha256::new();
                    hasher.update(&nodes[2 * i]);
                    hasher.update(&nodes[2 * i + 1]);
                    hasher.finalize().to_vec()
                })
                .collect();
        }

        nodes[0].clone()
    }

    /// Get the state root commitment and data root commitment for the range [start_block + 1, end_block].
    /// Returns a tuple of the state root commitment and data root commitment.
    pub async fn get_merkle_root_commitments(
        &self,
        header_range_commitment_tree_size: u32,
        start_block: u32,
        end_block: u32,
    ) -> (Vec<u8>, Vec<u8>) {
        // Assert header_range_commitment_tree_size is a power of 2.
        assert!(header_range_commitment_tree_size.is_power_of_two());

        if end_block - start_block > header_range_commitment_tree_size {
            panic!("Range too large!");
        }

        let headers = self
            .get_block_headers_range(start_block + 1, end_block)
            .await;

        let mut data_root_leaves = Vec::new();
        let mut state_root_leaves = Vec::new();
        let num_headers = headers.len();
        for header in headers {
            data_root_leaves.push(header.data_root().0.to_vec());
            state_root_leaves.push(header.state_root.0.to_vec());
        }

        for _ in num_headers..header_range_commitment_tree_size as usize {
            data_root_leaves.push([0u8; 32].to_vec());
            state_root_leaves.push([0u8; 32].to_vec());
        }

        // Uses the simple merkle tree implementation.
        (
            Self::get_merkle_root(state_root_leaves),
            Self::get_merkle_root(data_root_leaves),
        )
    }

    /// This function returns a vector of headers for a given range of block numbers, inclusive of the start and end block numbers.
    pub async fn get_block_headers_range(
        &self,
        start_block_number: u32,
        end_block_number: u32,
    ) -> Vec<Header> {
        // Fetch the headers in batches of MAX_CONCURRENT_WS_REQUESTS. The WS connection will error if there
        // are too many concurrent requests with Rpc(ClientError(MaxSlotsExceeded)).
        const MAX_CONCURRENT_WS_REQUESTS: usize = 200;
        let mut headers = Vec::new();
        let mut curr_block = start_block_number;
        while curr_block <= end_block_number {
            let end_block = std::cmp::min(
                curr_block + MAX_CONCURRENT_WS_REQUESTS as u32 - 1,
                end_block_number,
            );
            let header_futures: Vec<_> = (curr_block..end_block + 1)
                .map(|block_number| self.get_header(block_number))
                .collect();

            // Await all futures concurrently
            let headers_batch: Vec<Header> = join_all(header_futures)
                .await
                .into_iter()
                .collect::<Vec<_>>();

            headers.extend_from_slice(&headers_batch);
            curr_block += MAX_CONCURRENT_WS_REQUESTS as u32;
        }
        headers
    }

    pub async fn get_header(&self, block_number: u32) -> Header {
        let block_hash = self.get_block_hash(block_number).await;
        let header_result = self
            .client
            .legacy_rpc()
            .chain_get_header(Some(block_hash))
            .await;
        header_result.unwrap().unwrap()
    }

    pub async fn get_head(&self) -> Header {
        let head_block_hash = self
            .client
            .legacy_rpc()
            .chain_get_finalized_head()
            .await
            .unwrap();
        let header = self
            .client
            .legacy_rpc()
            .chain_get_header(Some(head_block_hash))
            .await;
        header.unwrap().unwrap()
    }

    pub async fn get_authority_set_id(&self, block_number: u32) -> u64 {
        let block_hash = self.get_block_hash(block_number).await;

        let set_id_key = api::storage().grandpa().current_set_id();
        self.client
            .storage()
            .at(block_hash)
            .fetch(&set_id_key)
            .await
            .unwrap()
            .unwrap()
    }

    // This function returns the authorities (as AffinePoint and public key bytes) for a given block number
    // by fetching the "authorities_bytes" from storage and decoding the bytes to a VersionedAuthorityList.
    // Note: The authorities returned by this function attest to block_number + 1.
    pub async fn get_authorities(&self, block_number: u32) -> Vec<[u8; 32]> {
        let block_hash = self.get_block_hash(block_number).await;

        let grandpa_authorities = self
            .client
            .runtime_api()
            .at(block_hash)
            .call_raw::<Vec<(ed25519::Public, u64)>>("GrandpaApi_grandpa_authorities", None)
            .await
            .unwrap();

        let mut authorities: Vec<[u8; 32]> = Vec::new();
        for (pub_key, weight) in grandpa_authorities {
            authorities.push(pub_key.0);
            let expected_weight = 1;
            // Assert the LE representation of the weight of each validator is 1.
            assert_eq!(
                weight, expected_weight,
                "The weight of the authority is not 1!"
            );
        }

        authorities
    }

    /// Gets the authority set id and authority set hash that are defined in block_number. This authority set
    /// attests to block_number + 1.
    pub async fn get_authority_set_data_for_block(&self, block_number: u32) -> (u64, H256) {
        let authority_set_id = self.get_authority_set_id(block_number).await;
        let authority_set_hash = self
            .compute_authority_set_hash_for_block(block_number)
            .await;
        (authority_set_id, authority_set_hash)
    }

    /// Computes the authority_set_hash for a given block number. Note: This is the authority set hash
    /// that validates the next block after the given block number.
    pub async fn compute_authority_set_hash_for_block(&self, block_number: u32) -> H256 {
        let authorities = self.get_authorities(block_number).await;

        let mut hash_so_far = Vec::new();
        for authority in authorities {
            let mut hasher = sha2::Sha256::new();
            hasher.update(hash_so_far);
            hasher.update(authority);
            hash_so_far = hasher.finalize().to_vec();
        }
        H256::from_slice(&hash_so_far)
    }

    /// Get the justification data necessary for the circuit using GrandpaJustification and the block number.
    async fn compute_data_from_justification(
        &self,
        justification: GrandpaJustification,
        block_number: u32,
    ) -> CircuitJustification {
        // Get the authority set that attested to block_number.
        let (authority_set_id, authority_set_hash) = self
            .get_authority_set_data_for_block(block_number - 1)
            .await;

        // Form a message which is signed in the justification.
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &authority_set_id,
        ));

        // List of valid pubkeys to signatures from the justification.
        let mut pubkey_to_signature = HashMap::new();
        for precommit in justification.commit.precommits {
            let pubkey = precommit.clone().id;
            let signature = precommit.clone().signature.0;
            let pubkey_bytes = pubkey.0;

            // Verify the signature by this validator over the signed_message which is shared.
            verify_signature(&pubkey_bytes, &signed_message, &signature);

            pubkey_to_signature.insert(
                precommit.clone().id.0,
                precommit.clone().signature.0.to_vec(),
            );
        }

        // Get the authority set for the block number.
        let authorities = self.get_authorities(block_number - 1).await;
        let num_authorities = authorities.len();

        let mut signatures = Vec::new();
        for authority in authorities.clone() {
            signatures.push(pubkey_to_signature.get(&authority).cloned());
        }
        // Total votes is the total number of entries in pubkey_to_signature.
        let total_votes = pubkey_to_signature.len();
        if total_votes * 3 < num_authorities * 2 {
            panic!("Not enough voting power");
        }

        let block_hash = self.get_block_hash(block_number).await.0;
        CircuitJustification {
            signed_message,
            authority_set_id,
            current_authority_set_hash: authority_set_hash.0.to_vec(),
            pubkeys: authorities.clone(),
            signatures,
            num_authorities,
            block_number,
            block_hash,
        }
    }

    /// Get the justification for a block using the Redis cache from the justification indexer.
    /// TODO: Move justification indexer into this repo, for now, we need to convert it from the
    /// type stored by the VectorX repo.
    pub async fn get_justification_data_for_block(
        &self,
        block_number: u32,
    ) -> (CircuitJustification, Header) {
        // Note: The redis justification type is from VectorX, and we need to map it onto the
        // CircuitJustification SP1 VectorX type.
        let redis_justification = self
            .redis
            .get_justification(&self.avail_chain_id, block_number)
            .await
            .unwrap();

        let block_hash = self.get_block_hash(redis_justification.block_number).await;

        let authority_set_id = self
            .get_authority_set_id(redis_justification.block_number - 1)
            .await;
        let authority_set_hash = self
            .compute_authority_set_hash_for_block(redis_justification.block_number - 1)
            .await;
        let header = self.get_header(redis_justification.block_number).await;

        // Convert pubkeys from Redis into [u8; 32]
        let pubkeys: Vec<[u8; 32]> = redis_justification
            .pubkeys
            .iter()
            .map(|pubkey| pubkey.clone().try_into().unwrap())
            .collect();

        let mut signatures: Vec<Option<Vec<u8>>> = Vec::new();
        for i in 0..redis_justification.signatures.len() {
            if redis_justification.validator_signed[i] {
                signatures.push(Some(redis_justification.signatures[i].clone()));
            } else {
                signatures.push(None);
            }
        }

        // Convert Redis stored justification into CircuitJustification.
        let circuit_justification = CircuitJustification {
            signed_message: redis_justification.signed_message,
            authority_set_id,
            current_authority_set_hash: authority_set_hash.0.to_vec(),
            pubkeys,
            signatures,
            num_authorities: redis_justification.num_authorities,
            block_number: redis_justification.block_number,
            block_hash: block_hash.0,
        };
        (circuit_justification, header)
    }

    /// Get the latest justification data. Because Avail does not store the justification data for
    /// all blocks, we can only generate a proof using the latest justification data or the justification data for a specific block.
    pub async fn get_latest_justification_data(&self) -> (CircuitJustification, Header) {
        let sub: Result<RpcSubscription<GrandpaJustification>, _> = self
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
        if let Some(Ok(justification)) = sub.next().await {
            // Get the header corresponding to the new justification.
            let header = self
                .client
                .legacy_rpc()
                .chain_get_header(Some(justification.commit.target_hash))
                .await
                .unwrap()
                .unwrap();
            let block_number = header.number;
            return (
                self.compute_data_from_justification(justification, block_number)
                    .await,
                header,
            );
        }
        panic!("No justification found")
    }

    /// Get the justification data for a rotate from the curr_authority_set_id to the next authority set id.
    /// Fetch the authority set and justification proof for the last block in the current epoch. If the finality proof is a
    /// simple justification, return a CircuitJustification with the encoded precommit that all
    /// authorities sign, the validator signatures, and the authority set's pubkeys.
    pub async fn get_justification_data_rotate(
        &self,
        curr_authority_set_id: u64,
    ) -> CircuitJustification {
        let epoch_end_block = self.last_justified_block(curr_authority_set_id).await;
        if epoch_end_block == 0 {
            panic!("Current authority set is still active!");
        }

        // If epoch end block, use grandpa_proveFinality to get the justification.
        let mut params = RpcParams::new();
        let _ = params.push(epoch_end_block);

        let encoded_finality_proof = self
            .client
            .rpc()
            .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
            .await
            .unwrap();

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

        self.compute_data_from_justification(justification, epoch_end_block)
            .await
    }

    /// This function takes in a block_number as input, and fetches the new authority set specified
    /// in the epoch end block. It returns the data necessary to prove the new authority set, which
    /// specifies the new authority set hash, the number of authorities, and the start and end
    /// position of the encoded new authority set in the header.
    pub async fn get_header_rotate(&self, authority_set_id: u64) -> HeaderRotateData {
        let epoch_end_block = self.last_justified_block(authority_set_id).await;
        if epoch_end_block == 0 {
            panic!("Current authority set is still active!");
        }

        let header = self.get_header(epoch_end_block).await;

        let header_bytes = header.encode();

        // Fetch the new authority set specified in the epoch end block.
        let new_authorities = self.get_authorities(epoch_end_block).await;

        let num_authorities = new_authorities.len();
        let encoded_num_authorities_len = Compact(num_authorities as u32).encode().len();

        let mut position = 0;
        let number_encoded = Compact(epoch_end_block).encode();
        // Skip past parent_hash, number, state_root, extrinsics_root.
        position += HASH_SIZE + number_encoded.len() + HASH_SIZE + HASH_SIZE;
        let mut found_correct_log = false;
        for log in header.digest.logs {
            let encoded_log = log.clone().encode();
            // Note: Two bytes are skipped between the consensus id and value.
            if let DigestItem::Consensus(consensus_id, value) = log {
                if consensus_id == [70, 82, 78, 75] {
                    found_correct_log = true;

                    // Denotes that this is a `ScheduledChange` log.
                    assert_eq!(value[0], 1);

                    // The bytes after the prefix are the compact encoded number of authorities.
                    // Follows the encoding format: https://docs.substrate.io/reference/scale-codec/#fn-1
                    // If the number of authorities is <=63, the compact encoding is 1 byte.
                    // If the number of authorities is >63 & < 2^14, the compact encoding is 2 bytes.
                    let mut cursor = 1 + encoded_num_authorities_len;
                    let authorities_bytes = &value[cursor..];

                    for (i, authority_chunk) in
                        authorities_bytes.chunks_exact(VALIDATOR_LENGTH).enumerate()
                    {
                        let pubkey = &authority_chunk[..PUBKEY_LENGTH];
                        let weight = &authority_chunk[PUBKEY_LENGTH..];

                        let expected_weight = &[1u8, 0, 0, 0, 0, 0, 0, 0];

                        // Assert the pubkey in the encoded log is correct.
                        assert_eq!(*pubkey, new_authorities[i]);

                        // Assert the weight is correct.
                        assert_eq!(weight, expected_weight);

                        cursor += VALIDATOR_LENGTH;
                    }

                    // Assert delay is [0, 0, 0, 0]
                    let delay = &value[cursor..];
                    assert_eq!(delay[..], [0, 0, 0, 0]);

                    break;
                }
            }
            // If this is not the correct log, increment position by the length of the encoded log.
            if !found_correct_log {
                position += encoded_log.len();
            }
        }

        // Panic if there is not a consensus log.
        if !found_correct_log {
            panic!(
                "Block: {:?} should be an epoch end block, but did not find corresponding consensus log!",
                epoch_end_block
            );
        }

        let new_authority_set_hash = compute_authority_set_hash_from_authorities(&new_authorities);

        HeaderRotateData {
            header_bytes,
            num_authorities: new_authorities.len(),
            new_authority_set_hash,
            pubkeys: new_authorities,
            consensus_log_position: position,
        }
    }
}

#[cfg(test)]
mod tests {
    use avail_subxt::config::Header;
    use sp1_vectorx_primitives::decode_precommit;

    use super::*;

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_simple_justification_change_authority_set() {
        let fetcher = RpcDataFetcher::new().await;

        // This is an block in the middle of an era.
        let block = 645570;

        let authority_set_id = fetcher.get_authority_set_id(block - 1).await;
        let authority_set_hash = fetcher
            .compute_authority_set_hash_for_block(block - 1)
            .await;
        let header = fetcher.get_header(block).await;
        let header_hash = header.hash();

        println!("authority_set_id {:?}", authority_set_id);
        println!("authority_set_hash {:?}", hex::encode(authority_set_hash.0));
        println!("header_hash {:?}", hex::encode(header_hash.0));

        let _ = fetcher
            .get_justification_data_rotate(authority_set_id)
            .await;
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_get_new_authority_set() {
        dotenv::dotenv().ok();
        env_logger::init();

        let fetcher = RpcDataFetcher::new().await;

        // A binary search given a target_authority_set_id, returns the last block justified by
        // target_authority_set_id. This block also specifies the new authority set,
        // target_authority_set_id + 1.
        let target_authority_set_id = 2;
        let epoch_end_block_number = fetcher.last_justified_block(target_authority_set_id).await;

        // Verify that this is an epoch end block.
        assert_ne!(epoch_end_block_number, 0);
        println!("epoch_end_block_number {:?}", epoch_end_block_number);

        let previous_authority_set_id = fetcher
            .get_authority_set_id(epoch_end_block_number - 1)
            .await;
        let new_authority_set_id = fetcher.get_authority_set_id(epoch_end_block_number).await;

        // Verify this is an epoch end block.
        assert_eq!(previous_authority_set_id + 1, new_authority_set_id);
        assert_eq!(previous_authority_set_id, target_authority_set_id);

        let rotate_data = fetcher.get_header_rotate(new_authority_set_id).await;
        println!(
            "new authority set hash {:?}",
            rotate_data.new_authority_set_hash
        );
    }

    #[tokio::test]
    #[cfg_attr(feature = "ci", ignore)]
    async fn test_grandpa_prove_finality() {
        let fetcher = RpcDataFetcher::new().await;

        let block_number = 642000;
        let authority_set_id = fetcher.get_authority_set_id(block_number - 1).await;

        let last_justified_block = fetcher.last_justified_block(authority_set_id).await;

        let header = fetcher.get_header(last_justified_block).await;
        println!("header hash {:?}", hex::encode(header.hash().0));
        let authority_set_hash = fetcher
            .compute_authority_set_hash_for_block(block_number - 1)
            .await;
        println!("authority set hash {:?}", hex::encode(authority_set_hash.0));

        let new_authority_set_id = fetcher.get_authority_set_id(last_justified_block).await;

        println!(
            "last justified block from authority set {:?} is: {:?}",
            authority_set_id, last_justified_block
        );

        println!("new authority set id is: {:?}", new_authority_set_id);

        let mut params = RpcParams::new();
        let _ = params.push(last_justified_block + 1);

        let encoded_finality_proof = fetcher
            .client
            .rpc()
            .request::<EncodedFinalityProof>("grandpa_proveFinality", params)
            .await
            .unwrap();

        let finality_proof: FinalityProof =
            Decode::decode(&mut encoded_finality_proof.0 .0.as_slice()).unwrap();
        let justification: GrandpaJustification =
            Decode::decode(&mut finality_proof.justification.as_slice()).unwrap();

        let authority_set_id = fetcher.get_authority_set_id(block_number - 1).await;

        // Form a message which is signed in the justification.
        let signed_message = Encode::encode(&(
            &SignerMessage::PrecommitMessage(justification.commit.precommits[0].clone().precommit),
            &justification.round,
            &authority_set_id,
        ));

        let (_, block_number, _, _) = decode_precommit(signed_message.clone());

        println!("block number {:?}", block_number);
    }
}
