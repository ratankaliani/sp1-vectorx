use std::env;

use anyhow::Result;
use log::debug;
use redis::JsonCommands;

use crate::types::RedisStoredJustificationData;

#[derive(Clone)]
pub struct RedisClient {
    pub redis: redis::Client,
}

impl Default for RedisClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RedisClient {
    pub fn new() -> Self {
        dotenv::dotenv().ok();

        let redis_url = env::var("REDIS_URL").expect("REDIS_URL must be set");
        let redis = redis::Client::open(redis_url).expect("Redis client not created");
        RedisClient { redis }
    }

    /// Stores justification data in Redis. Errors if setting the key fails.
    pub fn add_justification(
        &self,
        avail_chain_id: &str,
        justification: RedisStoredJustificationData,
    ) {
        let mut con = self.redis.get_connection().unwrap();

        let justification_key = format!(
            "{}:justification:{}",
            avail_chain_id, justification.block_number
        );

        // Justification is stored as a JSON object.
        let _: () = con
            .json_set(justification_key, "$", &justification)
            .expect("Failed to set key");

        debug!(
            "Added justification for block {:?}",
            justification.block_number
        )
    }

    /// Gets justification data from Redis. Errors if getting the key fails.
    pub async fn get_justification(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> Result<RedisStoredJustificationData> {
        let mut con = self.redis.get_connection().unwrap();

        let key = format!("{}:justification:{}", avail_chain_id, block_number).to_lowercase();

        // Result is always stored as serialized bytes: https://github.com/redis-rs/redis-rs#json-support.
        let serialized_justification: Vec<u8> = con.json_get(key, "$").expect("Failed to get key");

        match serde_json::from_slice::<Vec<RedisStoredJustificationData>>(&serialized_justification)
        {
            Ok(justification) => Ok(justification[0].clone()),
            Err(e) => Err(anyhow::anyhow!(
                "Failed to deserialize justification: {}",
                e
            )),
        }
    }
}
