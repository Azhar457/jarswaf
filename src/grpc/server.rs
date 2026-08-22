use crate::grpc::waf_sync::waf_sync_server::{WafSync, WafSyncServer};
use crate::grpc::waf_sync::{PolicySyncRequest, PolicySyncResponse, TelemetryAck, TelemetryEvent};
use std::pin::Pin;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

pub struct WafManagerService {
    pub auth_token: String,
    pub config_path: String,
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
                // Constant-time comparison to avoid timing side-channels.
                if constant_time_eq(token.as_bytes(), self.auth_token.as_bytes()) {
                    Ok(())
                } else {
                    Err(Status::unauthenticated("Invalid gRPC authorization token"))
                }
            }
            None => Err(Status::unauthenticated("Missing authorization metadata")),
        }
    }
}

/// Constant-time byte comparison (avoids timing side-channels for token checks).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
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

        // Load real config snapshot and blocklist from disk
        let current_cfg = crate::config::load_config(&self.config_path).unwrap_or_default();
        let rules_payload =
            serde_json::to_string(&current_cfg).unwrap_or_else(|_| "{}".to_string());
        let blocklist_ips: Vec<String> = current_cfg
            .blacklists
            .iter()
            .filter(|b| b.enabled)
            .flat_map(|b| b.ips.clone())
            .collect();

        let initial_payload = PolicySyncResponse {
            version: format!("v{}", chrono::Utc::now().timestamp()),
            rules_payload,
            blocklist_ips,
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
    config_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Bind loopback by default — the gRPC manager is a control plane and must not be
    // exposed broadly. Cross-host deployments should front it with TLS/mTLS or a reverse
    // proxy and set JARSWAF_GRPC_BIND explicitly (e.g. "0.0.0.0"). Never expose port 9000
    // to untrusted networks with only a bearer token.
    let bind_host = std::env::var("JARSWAF_GRPC_BIND").unwrap_or_else(|_| "127.0.0.1".to_string());
    let addr = format!("{}:{}", bind_host, port).parse()?;
    let service = WafManagerService {
        auth_token: token,
        config_path,
    };

    info!("WAF Manager gRPC server listening on {}", addr);

    tonic::transport::Server::builder()
        .add_service(WafSyncServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
