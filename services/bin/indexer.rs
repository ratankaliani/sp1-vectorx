use avail_subxt::RpcParams;
use log::debug;
use services::aws::AWSClient;
use services::input::RpcDataFetcher;
use services::types::GrandpaJustification;
use subxt::backend::rpc::RpcSubscription;

async fn listen_for_justifications(fetcher: RpcDataFetcher, aws_client: AWSClient) {
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

        aws_client
            .add_justification(&fetcher.avail_chain_id, justification)
            .await
            .unwrap();
    }
}

#[tokio::main]
pub async fn main() {
    dotenv::dotenv().ok();
    env_logger::init();

    let fetcher = RpcDataFetcher::new().await;
    let aws_client = AWSClient::new().await;

    listen_for_justifications(fetcher, aws_client).await;
}
