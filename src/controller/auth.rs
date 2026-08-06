use super::state::ControllerState;
use crate::config;
use crate::rules::rate_limit::RateLimiterStore as _; // check_and_increment
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
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::{info, warn};

use sha2::{Digest, Sha256};

/// Constant-time byte comparison for equal-length slices. Returns false on length mismatch
/// (length is already public — the hash format has a fixed length); for equal lengths the
/// time is independent of the first differing byte, removing a timing oracle that `==` on
/// String leaks across every API request.
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

/// In-memory login attempt limiter (per source IP). Brute-force protection on the login
/// endpoint itself — the WAF proxy rate limiter does not cover controller API endpoints.
/// `ponytail:` a shared Redis store would make this multi-controller; per-process LocalStore
/// is sufficient for the standalone (single controller) deployment model.
static LOGIN_LIMITER: once_cell::sync::Lazy<Arc<crate::rules::rate_limit::LocalStore>> =
    once_cell::sync::Lazy::new(|| Arc::new(crate::rules::rate_limit::LocalStore::new()));
/// Login attempts allowed per source IP per minute before we start refusing.
const LOGIN_RATE_LIMIT_PER_MIN: u32 = 10;

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

/// Verify input password against stored hash (or legacy plaintext), constant-time.
pub fn verify_password(password: &str, stored: &str) -> bool {
    if stored.starts_with("$sha256$") {
        let parts: Vec<&str> = stored.split('$').collect();
        if parts.len() == 4 {
            let salt = parts[2];
            let expected_hash = parts[3];
            let mut hasher = Sha256::new();
            hasher.update(format!("{}:{}", salt, password).as_bytes());
            let actual_hash = format!("{:x}", hasher.finalize());
            return constant_time_eq(actual_hash.as_bytes(), expected_hash.as_bytes());
        }
    }
    // Backward compatibility for legacy unhashed tokens — constant-time compare.
    constant_time_eq(password.as_bytes(), stored.as_bytes())
}

/// True when `candidate` is a currently-valid session token in `store` (present + not
/// expired), compared constant-time. Caller should hold the sessions read lock.
pub fn is_valid_session(store: &std::collections::HashMap<String, i64>, candidate: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    store
        .iter()
        .any(|(k, &exp)| exp >= now && constant_time_eq(k.as_bytes(), candidate.as_bytes()))
}

/// Ensure an admin password exists on startup.
/// If no password is defined, generate a 20-character random password, save hash to config, and print console banner.
pub fn ensure_admin_credentials(config_path: &str) -> String {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::io::IsTerminal as _;

    let mut config = config::load_config(config_path).unwrap_or_default();

    if let Some(ref token) = config.global.admin_token {
        if !token.trim().is_empty() {
            // Check if the token is already hashed
            if token.starts_with("$sha256$") {
                return token.clone();
            } else {
                // The token is plaintext! Let's hash it and save it back to config!
                let hashed = hash_password(token);
                config.global.admin_token = Some(hashed.clone());
                config.global.must_change_password = Some(true);
                let _ = config::save_config(config_path, &config);
                info!("Automatically hashed plaintext admin_token in config file on boot.");
                return hashed;
            }
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

    // Security: Check if we are running as a systemd service or if stdout is not a TTY.
    // In those cases, printing the plaintext password to stdout would leak it into journald/syslog.
    // Write it to a secure onboarding file instead, or print the banner if running in a terminal.
    let is_systemd = std::env::var("INVOCATION_ID").is_ok();
    let is_tty = std::io::stdout().is_terminal();

    if is_systemd || !is_tty {
        // Write to a secure file in the same directory as config
        let parent_dir = std::path::Path::new(config_path)
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."));
        let credential_file = parent_dir.join("admin_onboarding_credential");

        // Write with 0600 permissions using OpenOptions on Unix
        let mut options = OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        if let Ok(mut file) = options.open(&credential_file) {
            let _ = writeln!(file, "{}", random_password);
            warn!(
                "\n===============================================================\n\
                 🛡️  jarsWAF SECURITY WARNING: NON-TTY / SYSTEMD ENVIRONMENT DETECTED\n\
                 ===============================================================\n\
                   Generated onboarding password has been written to a secure file:\n\
                   {}\n\
                   Please read this file, log in, and DELETE the file immediately.\n\
                 ===============================================================\n",
                credential_file.display()
            );
        } else {
            // Fallback to stderr if writing to file failed (e.g. read-only filesystem)
            eprintln!(
                "Warning: Generated onboarding password (failed to write to file): {}",
                random_password
            );
        }
    } else {
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
    }

    config.global.admin_token.unwrap()
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

        // Issue a revocable session token. The client sends THIS (not the password) as the
        // bearer token; `auth_middleware` checks it against the session store and clears it
        // on expiry/password change. The admin password is never returned again.
        // `ponytail:` sessions are in-memory (lost on restart) and per-controller; swap in a
        // SQLite-backed store if persistence or multi-controller revocation is required.
        let session_id = uuid::Uuid::new_v4().simple().to_string();
        let ttl_secs: i64 = 24 * 3600; // 24h
        let expiry = chrono::Utc::now().timestamp() + ttl_secs;
        state
            .sessions
            .write()
            .unwrap()
            .insert(session_id.clone(), expiry);

        info!(
            "Successful admin login to jarsWAF Controller (must_change={}) — issued session",
            must_change
        );
        Ok(Json(LoginResponse {
            status: "success".into(),
            token: session_id,
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
    // Password changed → revoke ALL previously issued sessions so the old credential
    // (and any stolen bearer token minted from it) stops working immediately.
    state.sessions.write().unwrap().clear();
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
        // 1. Revocable session token (issued by /auth/login). Preferred path.
        {
            let sessions = state.sessions.read().unwrap();
            if is_valid_session(&sessions, token) {
                return true;
            }
        }

        // 2. Salted Hash / Plaintext match (legacy dashboard/agent flows).
        if verify_password(token, &expected_token) {
            return true;
        }

        // 3. Stateless Machine ID Binding: <MachineID>.<Hash>
        if let Some((machine_id, hash)) = token.split_once('.') {
            use sha2::{Digest, Sha256};
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
