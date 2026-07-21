use super::state::ControllerState;
use crate::config;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
};
use tracing::warn;

pub async fn auth_middleware(
    State(state): State<ControllerState>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let admin_token = match config::load_config(&state.config_path) {
        Ok(cfg) => cfg.global.admin_token,
        Err(_) => None,
    };

    if let Some(expected_token) = admin_token {
        if !expected_token.is_empty() {
            let mut auth_valid = false;

            let check_token = |token: &str| -> bool {
                // 1. Exact match (for UI / legacy clients)
                if token == expected_token {
                    return true;
                }
                
                // 2. Stateless Machine ID Binding: <MachineID>.<Hash>
                if let Some((machine_id, hash)) = token.split_once('.') {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}:{}", machine_id, expected_token).as_bytes());
                    let expected_hash = format!("{:x}", hasher.finalize());
                    if hash == expected_hash {
                        return true;
                    }
                }
                false
            };

            if let Some(auth_header) = req.headers().get(axum::http::header::AUTHORIZATION) {
                if let Ok(auth_str) = auth_header.to_str() {
                    if auth_str.starts_with("Bearer ") {
                        let token = auth_str.trim_start_matches("Bearer ");
                        auth_valid = check_token(token);
                    }
                }
            }

            if !auth_valid {
                if let Some(ws_protocol) = req.headers().get("sec-websocket-protocol") {
                    if let Ok(proto_str) = ws_protocol.to_str() {
                        for p in proto_str.split(',') {
                            if check_token(p.trim()) {
                                auth_valid = true;
                                break;
                            }
                        }
                    }
                }
            }

            if !auth_valid {
                warn!(
                    "Unauthorized WAF API access attempt to {}",
                    req.uri().path()
                );
                return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
            }
        }
    }

    next.run(req).await
}
