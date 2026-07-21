use crate::grpc::waf_sync::waf_sync_server::{WafSync, WafSyncServer};
use crate::grpc::waf_sync::{PolicySyncRequest, PolicySyncResponse, TelemetryAck, TelemetryEvent};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct WafManagerService {
    pub auth_token: String,
}

#[tonic::async_trait]
impl WafSync for WafManagerService {
    type SyncPoliciesStream =
        Pin<Box<dyn Stream<Item = Result<PolicySyncResponse, Status>> + Send + Sync + 'static>>;

    async fn sync_policies(
        &self,
        request: Request<PolicySyncRequest>,
    ) -> Result<Response<Self::SyncPoliciesStream>, Status> {
        let req = request.into_inner();
        info!("Agent {} connected for policy sync.", req.agent_id);

        let (tx, rx) = tokio::sync::mpsc::channel(4);

        // Send an initial payload
        let initial_payload = PolicySyncResponse {
            version: "v1.0.1".to_string(),
            rules_payload: "{}".to_string(),
            blocklist_ips: vec![],
        };

        if tx.send(Ok(initial_payload)).await.is_err() {
            warn!("Failed to send initial payload to agent {}", req.agent_id);
        }

        // Return the receiver stream
        Ok(Response::new(Box::pin(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        )))
    }

    async fn stream_telemetry(
        &self,
        request: Request<tonic::Streaming<TelemetryEvent>>,
    ) -> Result<Response<TelemetryAck>, Status> {
        let mut stream = request.into_inner();

        while let Some(event) = stream.message().await? {
            info!(
                "Received telemetry from {}: {} - {}",
                event.agent_id, event.event_type, event.details
            );
        }

        Ok(Response::new(TelemetryAck { success: true }))
    }
}

pub async fn run_manager_server(
    port: u16,
    token: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = format!("0.0.0.0:{}", port).parse()?;
    let service = WafManagerService { auth_token: token };

    info!("WAF Manager gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(WafSyncServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
