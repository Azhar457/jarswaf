use super::state::ControllerState;
use crate::config;
use crate::rules::rate_limit::RateLimiterStore as _; // bring check_and_increment into scope
use axum::{
    body::Body,
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use rand::distributions::Alphanumeric;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

/// In-memory login attempt limiter (per source IP). Brute-force protection on the login
/// endpoint itself — the WAF proxy rate limiter does not cover controller API endpoints.
/// `ponytail:` a shared Redis store would make this multi-controller; per-process LocalStore
/// is sufficient for the standalone (single controller) deployment model.
static LOGIN_LIMITER: once_cell::sync::Lazy<Arc<crate::rules::rate_limit::LocalStore>> =
    once_cell::sync::Lazy::new(|| Arc::new(crate::rules::rate_limit::LocalStore::new()));
/// Login attempts allowed per source IP per minute before we start refusing.
const LOGIN_RATE_LIMIT_PER_MIN: u32 = 10;

/// Constant-time byte comparison for two equal-length slices. Returns false immediately on
/// length mismatch (length is already public — the stored hash format has a fixed-ish length);
/// for equal lengths the comparison time is independent of where the first difference occurs,
/// removing a byte-timing oracle that `==` on String would otherwise leak across every API
/// request. `ponytail:` a dedicated constant-time crate (`subtle`/`constant_time_eq`) would
/// also cover length-equal orthogonal cases — swap in if one is added for other reasons.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Salted SHA-256 password hashing helper. Stored format: `$sha256$<salt>$<hexhash>`.
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

/// Verify an input password/token against a stored value. Accepts the salted SHA-256 form
/// (`$sha256$...`) via constant-time compare, and falls back to a constant-time plaintext
/// compare for legacy unhashed tokens (still not `==`, to avoid timing leaks).
pub fn verify_password(password: &str, stored: &str) -> bool {
    if let Some(rest) = stored.strip_prefix("$sha256$") {
        if let Some((salt, expected_hash)) = rest.split_once('$') {
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}", salt, password).as_bytes());
            let actual_hash = format!("{:x}", hasher.finalize());
            return constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes());
        }
        return false;
    }
    // Legacy unhashed token — compare constant-time.
    constant_time_eq(password.as_bytes(), stored.as_bytes())
}

/// Ensure an admin password exists on startup.
/// If no password is defined, generate a 16-character random password, hash it, save the
/// hash to config, and print console banner. The plain password is returned to the caller
/// exactly once (first boot) so it can be shown — it is never persisted in plaintext.
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

    // Persist only the salted hash, not the plaintext password.
    config.global.admin_token = Some(hash_password(&random_password));
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<LoginResponse>, (StatusCode, &'static str)> {
    // Brute-force guard: refuse when the source IP has exceeded the per-minute attempt
    // budget — do this BEFORE the (expensive) password verification.
    let status = LOGIN_LIMITER
        .check_and_increment(addr.ip(), LOGIN_RATE_LIMIT_PER_MIN, None)
        .await;
    if !status.allowed {
        return Err((
            StatusCode::TOO_MANY_REQUESTS,
            "Too many login attempts — try again later",
        ));
    }

    // Make sure a credential exists (first boot). We then verify the supplied password
    // against the *stored* (hashed) admin_token in config — never against an in-memory
    // plaintext. ensure_admin_credentials returns the plaintext only so the first-boot
    // banner can print it; login does not use that return value for verification.
    let _ = ensure_admin_credentials(&state.config_path);
    let stored_token = match config::load_config(&state.config_path) {
        Ok(cfg) => cfg.global.admin_token.unwrap_or_default(),
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Config read error")),
    };

    if verify_password(&payload.password, &stored_token) {
        info!("Successful admin login to jarsWAF Controller");
        // TODO(P1 session): returning the plaintext password as the bearer token means it
        // cannot be revoked without a password change and is replayable from any captured
        // header/log. Replace with a server-generated session token (UUID) stored with TTL
        // in SQLite/config so the dashboard sends the session id, not the password itself.
        Ok(Json(LoginResponse {
            status: "success".into(),
            token: payload.password.clone(),
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
    // Make sure a credential exists, then verify old_password against the *stored* hash.
    let _ = ensure_admin_credentials(&state.config_path);
    let stored_token = match config::load_config(&state.config_path) {
        Ok(cfg) => cfg.global.admin_token.unwrap_or_default(),
        Err(_) => return Err((StatusCode::INTERNAL_SERVER_ERROR, "Config read error")),
    };

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
    // Persist the new password as a salted hash — never as plaintext.
    cfg.global.admin_token = Some(hash_password(&payload.new_password));
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
                // 1. Verify the supplied token against the stored (hashed) admin_token via
                //    constant-time compare. Handles both hashed and legacy plaintext storage.
                if verify_password(token, &expected_token) {
                    return true;
                }

                // 2. Stateless Machine ID Binding: <MachineID>.<Hash>
                //    hash = sha256(machine_id:expected_token). Compared constant-time.
                if let Some((machine_id, hash)) = token.split_once('.') {
                    let mut hasher = Sha256::new();
                    hasher.update(format!("{}:{}", machine_id, expected_token).as_bytes());
                    let expected_hash = format!("{:x}", hasher.finalize());
                    if constant_time_eq(hash.as_bytes(), expected_hash.as_bytes()) {
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
