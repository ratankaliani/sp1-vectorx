use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::{Client, Error};

use anyhow::Result;
use log::info;
use std::collections::HashMap;

use crate::types::StoredJustificationData;

pub struct AWSClient {
    client: Client,
}

const JUSTIFICATION_TABLE: &str = "justifications";

impl AWSClient {
    pub async fn new() -> Self {
        let shared_config = aws_config::load_from_env().await;
        let client = Client::new(&shared_config);
        AWSClient { client }
    }

    pub async fn add_justification(
        &self,
        avail_chain_id: &str,
        justification: StoredJustificationData,
    ) -> Result<(), Error> {
        let key = format!("{}-{}", avail_chain_id, justification.block_number).to_lowercase();

        let mut item = serde_json::to_value(justification)
            .unwrap()
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| (k.clone(), AttributeValue::S(v.to_string())))
            .collect::<HashMap<_, _>>();

        item.insert("id".to_string(), AttributeValue::S(key.to_string()));

        info!(
            "Adding justification for block number: {}",
            justification.block_number
        );

        self.client
            .put_item()
            .table_name(JUSTIFICATION_TABLE)
            .set_item(Some(item))
            .send()
            .await?;
        Ok(())
    }

    pub async fn get_justification(
        &self,
        avail_chain_id: &str,
        block_number: u32,
    ) -> Result<StoredJustificationData> {
        let key = format!("{}-{}", avail_chain_id, block_number).to_lowercase();

        let resp = self
            .client
            .get_item()
            .table_name(JUSTIFICATION_TABLE)
            .key("id", AttributeValue::S(key.to_string()))
            .send()
            .await?;

        if let Some(item) = resp.item {
            let justification_map = item
                .into_iter()
                .map(|(k, v)| (k, v.as_s().unwrap().to_string()))
                .collect::<HashMap<_, _>>();
            let justification: StoredJustificationData =
                serde_json::from_value(serde_json::to_value(justification_map).unwrap()).unwrap();
            Ok(justification)
        } else {
            Err(anyhow::anyhow!("Justification not found"))
        }
    }
}
