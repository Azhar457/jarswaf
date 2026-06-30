use crate::config;
use std::sync::Arc;
use tokio_stream::StreamExt;
use tracing::{error, info};

pub async fn start_config_sync_websocket(
    controller_url: String,
    token: Option<String>,
    config_arc: Arc<std::sync::RwLock<config::Config>>,
) {
    loop {
        let ws_url = format!("{}/ws/agent", controller_url.trim_end_matches('/'))
            .replace("http://", "ws://")
            .replace("https://", "wss://");

        info!("Connecting to Controller config WebSocket at {}...", ws_url);

        let mut request =
            tokio_tungstenite::tungstenite::handshake::client::Request::builder().uri(&ws_url);

        if let Some(ref t) = token {
            request = request.header("Sec-WebSocket-Protocol", t);
        }

        let request = match request.body(()) {
            Ok(req) => req,
            Err(e) => {
                error!("Failed to build WebSocket handshake request: {:?}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
                continue;
            }
        };

        match tokio_tungstenite::connect_async(request).await {
            Ok((mut ws_stream, _)) => {
                info!("Connected to Controller configuration WebSocket");
                while let Some(msg) = ws_stream.next().await {
                    match msg {
                        Ok(tokio_tungstenite::tungstenite::Message::Text(text)) => {
                            if let Ok(new_cfg) = serde_json::from_str::<config::Config>(&text) {
                                if let Ok(mut lock) = config_arc.write() {
                                    *lock = new_cfg;
                                    info!("Dynamic configuration updated via Controller WebSocket push");
                                }
                            }
                        }
                        Ok(tokio_tungstenite::tungstenite::Message::Close(_)) => {
                            info!("Controller configuration WebSocket closed");
                            break;
                        }
                        Err(e) => {
                            error!("WebSocket error: {}", e);
                            break;
                        }
                        _ => {}
                    }
                }
            }
            Err(e) => {
                error!("Failed to connect to Controller configuration WebSocket: {}. Retrying in 5s...", e);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
    }
}
