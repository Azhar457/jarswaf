use crate::grpc::waf_sync::waf_sync_server::{WafSync, WafSyncServer};
use crate::grpc::waf_sync::{PolicySyncRequest, PolicySyncResponse, TelemetryAck, TelemetryEvent};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct WafManagerService {
    pub auth_token: String,
}

impl WafManagerService {
    /// Verify the `authorization: Bearer <token>` metadata against the configured agent token.
    /// Fail-closed: an empty configured token refuses ALL requests rather than granting
    /// anonymous access to the control plane. Previously this returned Ok(()) on an empty
    /// token, which combined with the `"default_token"` fallback in `controller/mod.rs`
    /// left the gRPC management port effectively unauthenticated.
    #[allow(clippy::result_large_err)] // tonic::Status is large by design; the error path is cold
    fn verify_token<T>(&self, req: &Request<T>) -> Result<(), Status> {
        if self.auth_token.is_empty() {
            return Err(Status::unauthenticated(
                "gRPC auth token not initialized — refusing request (fail-closed)",
            ));
        }
        match req.metadata().get("authorization") {
            Some(val) => {
                let token_str = val
                    .to_str()
                    .map_err(|_| Status::unauthenticated("Invalid auth header"))?;
                let token = token_str
                    .strip_prefix("Bearer ")
                    .unwrap_or(token_str)
                    .trim();
                if token == self.auth_token {
                    Ok(())
                } else {
                    Err(Status::unauthenticated("Invalid gRPC authorization token"))
                }
            }
            None => Err(Status::unauthenticated("Missing authorization metadata")),
        }
    }
}

#[tonic::async_trait]
impl WafSync for WafManagerService {
    type SyncPoliciesStream =
        Pin<Box<dyn Stream<Item = Result<PolicySyncResponse, Status>> + Send + Sync + 'static>>;

    async fn sync_policies(
        &self,
        request: Request<PolicySyncRequest>,
    ) -> Result<Response<Self::SyncPoliciesStream>, Status> {
        self.verify_token(&request)?;
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
        self.verify_token(&request)?;
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
    // Bind loopback by default — the gRPC manager is a control plane and must not be
    // exposed broadly. Cross-host deployments should front it with TLS/mTLS or a reverse
    // proxy and set JARSWAF_GRPC_BIND explicitly (e.g. "0.0.0.0"). Never expose port 9000
    // to untrusted networks with only a bearer token.
    let bind_host = std::env::var("JARSWAF_GRPC_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", bind_host, port).parse()?;
    let service = WafManagerService { auth_token: token };

    info!("WAF Manager gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(WafSyncServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
