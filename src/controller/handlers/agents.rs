use super::super::state::ControllerState;
use crate::types::{format_uptime, AgentInfo, AgentMetrics};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::info;

#[derive(serde::Deserialize)]
pub struct AgentRegisterRequest {
    pub hostname: String,
    pub ip: String,
    pub port: u16,
    pub os: String,
    pub region: Option<String>,
    pub cloud_provider: Option<String>,
}

pub async fn register_agent_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<AgentRegisterRequest>,
) -> impl IntoResponse {
    info!(
        "Registered agent: {} at {}:{} running {}",
        payload.hostname, payload.ip, payload.port, payload.os
    );

    let info = AgentInfo {
        hostname: payload.hostname.clone(),
        ip: payload.ip.clone(),
        os: payload.os.clone(),
        cpu: 0.0,
        ram: 0.0,
        disk: 0.0,
        uptime: "0m".to_string(),
        status: "online".to_string(),
        network_interfaces: vec![],
        discovered_services: vec![],
        region: payload.region.clone(),
        cloud_provider: payload.cloud_provider.clone(),
        active_connections: Some(0),
        last_seen: std::time::Instant::now(),
    };

    if let Ok(mut lock) = state.agent_registry.write() {
        lock.insert(payload.hostname, info);
    }

    StatusCode::CREATED
}

pub async fn receive_metrics_handler(
    State(state): State<ControllerState>,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    Json(mut payload): Json<AgentMetrics>,
) -> impl IntoResponse {
    let client_ip = addr.ip().to_string();
    payload.ip = client_ip.clone();

    let uptime_str = format_uptime(payload.uptime);

    let info = AgentInfo {
        hostname: payload.hostname.clone(),
        ip: client_ip,
        os: payload.os.clone(),
        cpu: payload.cpu,
        ram: payload.ram,
        disk: payload.disk,
        uptime: uptime_str,
        status: "online".to_string(),
        network_interfaces: payload.network_interfaces.clone(),
        discovered_services: payload.discovered_services.clone(),
        region: payload.region.clone(),
        cloud_provider: payload.cloud_provider.clone(),
        active_connections: payload.active_connections,
        last_seen: std::time::Instant::now(),
    };

    if let Ok(mut lock) = state.agent_registry.write() {
        lock.insert(payload.hostname, info);
    }

    StatusCode::OK
}

pub async fn get_agents_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let mut agents = Vec::new();

    // Auto-populate local embedded agent node for Standalone mode
    let is_standalone = {
        if let Ok(cfg) = crate::config::load_config(&state.config_path) {
            cfg.global.mode == "standalone"
        } else {
            true
        }
    };

    if is_standalone {
        // Use shared, cached local-node collector (single source of truth,
        // avoids full sysinfo inventory on every 5s poll).
        let local_node = crate::agent::metrics::collect_local_agent_info(5);

        if let Ok(mut lock) = state.agent_registry.write() {
            lock.insert(local_node.hostname.clone(), local_node);
        }
    }

    if let Ok(lock) = state.agent_registry.read() {
        let now = std::time::Instant::now();
        for info in lock.values() {
            let mut agent_clone = info.clone();
            if now.duration_since(info.last_seen) > std::time::Duration::from_secs(15) {
                agent_clone.status = "offline".to_string();
                agent_clone.cpu = 0.0;
                agent_clone.ram = 0.0;
            }
            agents.push(agent_clone);
        }
    }
    agents.sort_by(|a, b| a.hostname.cmp(&b.hostname));
    (StatusCode::OK, Json(agents))
}

#[derive(serde::Deserialize)]
pub struct AgentSyncRequest {
    pub hostname: String,
    pub region: Option<String>,
}

pub async fn sync_agent_handler(
    State(state): State<ControllerState>,
    Json(_payload): Json<AgentSyncRequest>,
) -> impl IntoResponse {
    // Basic sync: returns the full config.
    // Future enhancement: filter VHosts based on payload.region
    let config = {
        let lock = state.config_lock.lock().await;
        let c = std::fs::read_to_string(&state.config_path).unwrap_or_default();
        drop(lock);
        c
    };

    if let Ok(parsed) = toml::from_str::<crate::config::Config>(&config) {
        (StatusCode::OK, Json(parsed)).into_response()
    } else {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to parse config").into_response()
    }
}
