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

use sha2::{Digest, Sha256};

/// Salted SHA-256 password hashing helper
pub fn hash_password(password: &str) -> String {
    let salt: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect();
    let mut hasher = Sha256::new();
    hasher.update(format!("{}:{}", salt, password).as_bytes());
    format!("$sha256${}${:x}", salt, hasher.finalize())
}

/// Verify input password against stored hash (or legacy plaintext)
pub fn verify_password(password: &str, stored: &str) -> bool {
    if stored.starts_with("$sha256$") {
        let parts: Vec<&str> = stored.split('$').collect();
        if parts.len() == 4 {
            let salt = parts[2];
            let expected_hash = parts[3];
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}", salt, password).as_bytes());
            let actual_hash = format!("{:x}", hasher.finalize());
            return actual_hash == expected_hash;
        }
    }
    // Backward compatibility for legacy unhashed tokens
    password == stored
}

/// Ensure an admin password exists on startup.
/// If no password is defined, generate a 20-character random password, save hash to config, and print console banner.
pub fn ensure_admin_credentials(config_path: &str) -> String {
    let mut config = config::load_config(config_path).unwrap_or_default();

    if let Some(ref token) = config.global.admin_token {
        if !token.trim().is_empty() {
            return token.clone();
        }
    }

    // Generate random 20-character password
    let random_password: String = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(20)
        .map(char::from)
        .collect();

    config.global.admin_token = Some(hash_password(&random_password));
    config.global.must_change_password = Some(true);
    let _ = config::save_config(config_path, &config);

    println!(
        "\n===============================================================\n\
         🛡️  jarsWAF CONTROLLER INITIALIZED (FIRST BOOT)\n\
         ===============================================================\n\
           Dashboard URL:   http://0.0.0.0:9443 / http://localhost:9443 (or :8080)\n\
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
    pub must_change_password: bool,
    pub message: String,
}

/// POST /api/v1/auth/login — Authenticate admin and return token
pub async fn login_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<LoginResponse>, (StatusCode, &'static str)> {
    let stored_token = ensure_admin_credentials(&state.config_path);

    if verify_password(&payload.password, &stored_token) {
        let must_change = config::load_config(&state.config_path)
            .ok()
            .and_then(|c| c.global.must_change_password)
            .unwrap_or(false);

        // Auto-upgrade legacy plaintext tokens to hashed format
        if !stored_token.starts_with("$sha256$") {
            if let Ok(mut cfg) = config::load_config(&state.config_path) {
                cfg.global.admin_token = Some(hash_password(&payload.password));
                let _ = config::save_config(&state.config_path, &cfg);
            }
        }

        info!(
            "Successful admin login to jarsWAF Controller (must_change={})",
            must_change
        );
        Ok(Json(LoginResponse {
            status: "success".into(),
            token: payload.password.clone(),
            must_change_password: must_change,
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
    let stored_token = ensure_admin_credentials(&state.config_path);

    if !verify_password(&payload.old_password, &stored_token) {
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
    cfg.global.admin_token = Some(hash_password(&payload.new_password));
    cfg.global.must_change_password = Some(false);
    config::save_config(&state.config_path, &cfg)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Config write error"))?;

    info!("Admin password updated and hashed successfully");
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
    // Allow public endpoints (login, onboarding status, health)
    if path == "/health" || path == "/api/v1/auth/login" || path == "/api/v1/onboarding/status" {
        return next.run(req).await;
    }

    let admin_token = match config::load_config(&state.config_path) {
        Ok(cfg) => cfg.global.admin_token,
        Err(_) => None,
    };

    let expected_token = match admin_token {
        Some(token) if !token.trim().is_empty() => token,
        _ => {
            warn!("Rejecting request: admin_token is unconfigured or empty");
            return (
                StatusCode::UNAUTHORIZED,
                "Unauthorized - Controller token not initialized",
            )
                .into_response();
        }
    };

    let mut auth_valid = false;

    let check_token = |token: &str| -> bool {
        // 1. Salted Hash / Plaintext match
        if verify_password(token, &expected_token) {
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
        if let Some(metrics_header) = req.headers().get("x-metrics-token") {
            if let Ok(metrics_str) = metrics_header.to_str() {
                auth_valid = check_token(metrics_str.trim());
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

    next.run(req).await
}
