use crate::api::state::ApiState;
use crate::control_bus::ws_broadcaster::WsEvent;
use axum::{
    extract::{
        ws::{Message, WebSocket},
        State, WebSocketUpgrade,
    },
    response::IntoResponse,
};
use tracing::{debug, warn};

pub async fn ws_events(ws: WebSocketUpgrade, State(state): State<ApiState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_ws_socket(socket, state))
}

async fn handle_ws_socket(mut socket: WebSocket, state: crate::api::state::ApiState) {
    debug!("WebSocket client connected");

    // Subscribe to events
    let mut rx = state.ws_broadcaster.subscribe();

    loop {
        tokio::select! {
            // Send events to client
            event = rx.recv() => {
                match event {
                    Ok(event) => {
                        let json = match serde_json::to_string(&event) {
                            Ok(j) => j,
                            Err(e) => {
                                warn!("Failed to serialize WS event: {}", e);
                                continue;
                            }
                        };

                        if socket.send(Message::Text(json)).await.is_err() {
                            debug!("WebSocket client disconnected");
                            break;
                        }
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        warn!("WebSocket client lagged by {} messages, continuing", n);
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        debug!("WebSocket broadcaster closed");
                        break;
                    }
                }
            }

            // Handle incoming messages (ping/pong, close)
            msg = socket.recv() => {
                match msg {
                    Some(Ok(Message::Ping(data))) => {
                        if socket.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        debug!("WebSocket client sent close or disconnected");
                        break;
                    }
                    Some(Ok(Message::Text(text))) => {
                        // Handle commands from client if needed
                        debug!("WebSocket text message: {}", text);
                    }
                    _ => {}
                }
            }
        }
    }

    debug!("WebSocket client disconnected");
}

/// Separate WebSocket endpoint for metrics only
pub async fn ws_metrics(ws: WebSocketUpgrade, State(state): State<ApiState>) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_metrics_socket(socket, state))
}

async fn handle_metrics_socket(mut socket: WebSocket, state: crate::api::state::ApiState) {
    let mut rx = state.ws_broadcaster.subscribe();

    while let Ok(event) = rx.recv().await {
        if let WsEvent::Metrics { .. } = event {
            if let Ok(json) = serde_json::to_string(&event) {
                if socket.send(Message::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    }
}
