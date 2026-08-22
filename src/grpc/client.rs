use crate::config::Config;
use crate::grpc::waf_sync::{waf_sync_client::WafSyncClient, PolicySyncRequest};
use std::sync::Arc;
use tokio::time::{sleep, Duration};
use tonic::metadata::MetadataValue;
use tonic::transport::Channel;
use tracing::{error, info};

pub async fn run_agent_client(config: Arc<Config>) {
    let manager_url = match &config.global.manager_url {
        Some(url) => url.clone(),
        None => {
            error!("Agent mode enabled but no manager_url provided in config.");
            return;
        }
    };

    let token = config.global.grpc_token.clone().unwrap_or_default();

    loop {
        match connect_and_sync(&manager_url, &token).await {
            Ok(_) => {
                info!("Disconnected from manager gracefully. Retrying in 5s...");
            }
            Err(e) => {
                error!("gRPC Client error: {}. Retrying in 5s...", e);
            }
        }
        sleep(Duration::from_secs(5)).await;
    }
}

#[allow(clippy::result_large_err)]
async fn connect_and_sync(
    manager_url: &str,
    token: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let channel = Channel::from_shared(manager_url.to_string())?
        .connect()
        .await?;

    let token_metadata = MetadataValue::try_from(&format!("Bearer {}", token))?;
    let mut client = WafSyncClient::with_interceptor(channel, move |mut req: tonic::Request<()>| {
        req.metadata_mut()
            .insert("authorization", token_metadata.clone());
        Ok(req)
    });

    let host_agent_id = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("HOST"))
        .unwrap_or_else(|_| "agent-default".to_string());

    let request = tonic::Request::new(PolicySyncRequest {
        agent_id: host_agent_id,
        current_version: "1.0.0".to_string(),
    });

    let mut response_stream = client.sync_policies(request).await?.into_inner();

    info!("Connected to WAF Manager, listening for policy updates...");

    while let Some(response) = response_stream.message().await? {
        info!("Received policy update version: {}", response.version);
        // Apply rules_payload if non-empty valid JSON
        if !response.rules_payload.is_empty() && response.rules_payload != "{}" {
            if let Ok(new_cfg) =
                serde_json::from_str::<crate::config::Config>(&response.rules_payload)
            {
                crate::proxy_engine::update_global_config(new_cfg);
                info!("Successfully updated WAF global config from gRPC policy sync");
            }
        }
        // Sync blocklist IPs to XDP map
        if !response.blocklist_ips.is_empty() {
            let parsed_ips: Vec<std::net::Ipv4Addr> = response
                .blocklist_ips
                .iter()
                .filter_map(|ip_str| ip_str.parse().ok())
                .collect();
            if !parsed_ips.is_empty() {
                let mut xdp = crate::xdp::XdpManager::new();
                let _ = xdp.block_ips(&parsed_ips);
            }
        }
    }

    Ok(())
}
