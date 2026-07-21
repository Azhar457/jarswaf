use crate::config;
use futures_util::SinkExt;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tracing::{error, info};

const MIN_BACKOFF: u64 = 1; // 1s
const MAX_BACKOFF: u64 = 300; // 5m
const PING_INTERVAL_SECS: u64 = 30;

pub async fn start_config_sync_websocket(
    controller_url: String,
    token: Option<String>,
    config_arc: Arc<std::sync::RwLock<config::Config>>,
    blocklist: Option<Arc<dashmap::DashMap<std::net::IpAddr, std::time::Instant>>>,
) {
    let mut backoff = MIN_BACKOFF;

    loop {
        let ws_url = format!("{}/ws/agent", controller_url.trim_end_matches('/'))
            .replace("http://", "ws://")
            .replace("https://", "wss://");

        info!("Connecting to Controller config WebSocket at {}...", ws_url);

        use tokio_tungstenite::tungstenite::client::IntoClientRequest;
        let mut request = match ws_url.into_client_request() {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to build WebSocket client request: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };

        if let Some(ref t) = token {
            if let Ok(protocol_val) = t.parse() {
                request.headers_mut().insert("Sec-WebSocket-Protocol", protocol_val);
            }
        }

        match tokio_tungstenite::connect_async(request).await {
            Ok((mut ws_stream, _)) => {
                info!("Connected to Controller configuration WebSocket");
                // Reset backoff on successful connection
                backoff = MIN_BACKOFF;

                // Heartbeat ping timer
                let mut ping_interval =
                    tokio::time::interval(tokio::time::Duration::from_secs(PING_INTERVAL_SECS));
                ping_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                loop {
                    tokio::select! {
                        msg = ws_stream.next() => {
                            match msg {
                                Some(Ok(tokio_tungstenite::tungstenite::Message::Text(text))) => {
                                    // Try block-command envelope first, fall back to config update
                                    if let Ok(envelope) = serde_json::from_str::<serde_json::Value>(&text) {
                                        // Handle application-level pong (optional heartbeat confirmation)
                                        if envelope.get("type").and_then(|t| t.as_str()) == Some("pong") {
                                            continue;
                                        }
                                        if envelope.get("type").and_then(|t| t.as_str()) == Some("block_command") {
                                            if let Some(blocklist_ref) = &blocklist {
                                                if let Some(data) = envelope.get("data") {
                                                    let action = data.get("action").and_then(|a| a.as_str()).unwrap_or("");
                                                    let ip_str = data.get("ip").and_then(|i| i.as_str()).unwrap_or("");
                                                    if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                                                        match action {
                                                            "block" => { blocklist_ref.insert(ip, std::time::Instant::now() + std::time::Duration::from_secs(31536000)); info!("Real-time block: {ip} added via Controller push"); }
                                                            "unblock" => { blocklist_ref.remove(&ip); info!("Real-time unblock: {ip} removed via Controller push"); }
                                                            "sync" => { blocklist_ref.clear(); info!("Blocklist synced (cleared for full reload)"); }
                                                            _ => {}
                                                        }
                                                    }
                                                }
                                            }
                                            continue;
                                        }
                                    }
                                    // Fallback: try to parse as Config for backwards compat
                                    if let Ok(new_cfg) = serde_json::from_str::<config::Config>(&text) {
                                        if let Ok(mut lock) = config_arc.write() {
                                            *lock = new_cfg;
                                            info!("Dynamic configuration updated via Controller WebSocket push");
                                        }
                                    }
                                }
                                Some(Ok(tokio_tungstenite::tungstenite::Message::Ping(_))) => {
                                    // tungstenite auto-responds to Ping frames — nothing extra needed
                                }
                                Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => {
                                    info!("Controller configuration WebSocket closed");
                                    break;
                                }
                                Some(Err(e)) => {
                                    error!("WebSocket error: {e}");
                                    break;
                                }
                                None => {
                                    // Stream ended — Controller likely disconnected
                                    info!("WebSocket stream ended");
                                    break;
                                }
                                _ => {}
                            }
                        }
                        _ = ping_interval.tick() => {
                            // Send WebSocket Ping frame to keep connection alive and detect half-open
                            if let Err(e) = ws_stream.send(tokio_tungstenite::tungstenite::Message::Ping(Vec::new())).await {
                                error!("Failed to send WebSocket ping: {e}");
                                break;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to Controller config WebSocket: {e}. Falling back to HTTP Long-polling...");
                if let Err(poll_err) = run_config_sync_long_poll(&controller_url, token.as_deref(), config_arc.clone()).await {
                    error!("Long-polling fallback failed: {poll_err}");
                }
            }
        }

        // Exponential backoff before reconnect
        tokio::time::sleep(tokio::time::Duration::from_secs(backoff)).await;
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

async fn run_config_sync_long_poll(
    controller_url: &str,
    token: Option<&str>,
    config_arc: Arc<std::sync::RwLock<config::Config>>,
) -> Result<(), String> {
    let client = crate::logging::build_client();
    let url = format!("{}/api/v1/config/poll", controller_url.trim_end_matches('/'));
    
    let mut req = client.get(&url).timeout(std::time::Duration::from_secs(40));
    if let Some(t) = token {
        req = req.header("Sec-WebSocket-Protocol", t); // Use same auth token scheme or custom header
    }
    
    match req.send().await {
        Ok(res) => {
            if res.status() == reqwest::StatusCode::OK {
                if let Ok(new_cfg) = res.json::<config::Config>().await {
                    if let Ok(mut lock) = config_arc.write() {
                        *lock = new_cfg;
                        info!("Dynamic configuration updated via Controller HTTP Long-polling");
                    }
                }
            }
            Ok(())
        }
        Err(e) => {
            Err(format!("HTTP long-polling request failed: {e}"))
        }
    }
}
