use super::state::ControllerState;
use crate::config;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Ensure an admin password exists on startup.
/// If no password is defined, generate a 16-character random password, save to config, and print console banner.
pub fn ensure_admin_credentials(config_path: &str) -> String {
    let mut config = config::load_config(config_path).unwrap_or_default();

    if let Some(ref token) = config.global.admin_token {
        if !token.trim().is_empty() {
            return token.clone();
        }
    }

    // Generate random 16-character password
    let random_password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();

    config.global.admin_token = Some(random_password.clone());
    let _ = config::save_config(config_path, &config);

    println!(
        "\n===============================================================\n\
         🛡️  jarsWAF CONTROLLER INITIALIZED (FIRST BOOT)\n\
         ===============================================================\n\
           Dashboard URL:   http://0.0.0.0:9443 / http://localhost:9443\n\
           Admin Username:  admin\n\
           Admin Password:  {}\n\
         ===============================================================\n\
           PLEASE LOG IN AND CHANGE YOUR PASSWORD IMMEDIATELY.\n\
         ===============================================================\n",
        random_password
    );

    random_password
}

#[derive(Debug, Deserialize)]
pub struct LoginPayload {
    pub username: Option<String>,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub status: String,
    pub token: String,
    pub message: String,
}

/// POST /api/v1/auth/login — Authenticate admin and return token
pub async fn login_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<LoginResponse>, (StatusCode, &'static str)> {
    let current_token = ensure_admin_credentials(&state.config_path);

    if payload.password == current_token {
        info!("Successful admin login to jarsWAF Controller");
        Ok(Json(LoginResponse {
            status: "success".into(),
            token: current_token,
            message: "Authentication successful".into(),
        }))
    } else {
        warn!("Failed admin login attempt to jarsWAF Controller");
        Err((StatusCode::UNAUTHORIZED, "Invalid admin password"))
    }
}

#[derive(Debug, Deserialize)]
pub struct ChangePasswordPayload {
    pub old_password: String,
    pub new_password: String,
}

/// POST /api/v1/auth/change-password — Update admin password
pub async fn change_password_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<ChangePasswordPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let current_token = ensure_admin_credentials(&state.config_path);

    if payload.old_password != current_token {
        return Err((StatusCode::UNAUTHORIZED, "Old password is incorrect"));
    }

    if payload.new_password.trim().len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            "New password must be at least 8 characters",
        ));
    }

    let mut cfg = config::load_config(&state.config_path)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Config read error"))?;
    cfg.global.admin_token = Some(payload.new_password.clone());
    config::save_config(&state.config_path, &cfg)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Config write error"))?;

    info!("Admin password updated successfully");
    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Password updated successfully"
    })))
}

pub async fn auth_middleware(
    State(state): State<ControllerState>,
    req: Request<Body>,
    next: axum::middleware::Next,
) -> Response {
    let path = req.uri().path();
    // Allow public endpoints (login, onboarding status, health, metrics)
    if path == "/health"
        || path == "/api/v1/auth/login"
        || path == "/api/v1/onboarding/status"
        || path == "/metrics"
    {
        return next.run(req).await;
    }

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
