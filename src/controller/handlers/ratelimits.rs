use super::super::state::ControllerState;
use crate::config;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use tracing::{error, info};

pub async fn get_ratelimits_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<config::RateLimitPolicy>::new()),
            )
                .into_response();
        }
    };

    if cfg.rate_limit_policies.is_empty() {
        let _lock = state.config_lock.lock().await;
        if let Ok(mut reloaded_cfg) = config::load_config(&state.config_path) {
            if reloaded_cfg.rate_limit_policies.is_empty() {
                reloaded_cfg.rate_limit_policies = vec![
                    config::RateLimitPolicy {
                        name: "Default API/Website Traffic".to_string(),
                        limit: "600 requests / minute".to_string(),
                        burst: 100,
                        path: "/*".to_string(),
                        description: "Default threshold protecting backend sites from general automated scans.".to_string(),
                    },
                    config::RateLimitPolicy {
                        name: "Authentication Endpoints".to_string(),
                        limit: "10 requests / minute".to_string(),
                        burst: 5,
                        path: "/login, /api/auth/*".to_string(),
                        description: "Aggressive brute-force protection preventing credentials guessing.".to_string(),
                    },
                    config::RateLimitPolicy {
                        name: "WebDAV / Cloud File Storage".to_string(),
                        limit: "2000 requests / minute".to_string(),
                        burst: 200,
                        path: "/remote.php/dav/*, /api/upload/*".to_string(),
                        description: "Permissive tier optimized for photo synching and Nextcloud/Immich desktop clients.".to_string(),
                    },
                    config::RateLimitPolicy {
                        name: "Static Assets & Media".to_string(),
                        limit: "Unlimited".to_string(),
                        burst: 0,
                        path: "/static/*, *.css, *.js, *.png".to_string(),
                        description: "Exempted assets to reduce WAF engine evaluation overhead.".to_string(),
                    },
                ];
                let _ = config::save_config(&state.config_path, &reloaded_cfg);
                cfg = reloaded_cfg;
            } else {
                cfg = reloaded_cfg;
            }
        }
    }

    (StatusCode::OK, Json(cfg.rate_limit_policies)).into_response()
}

fn validate_policies(policies: &[config::RateLimitPolicy]) -> Result<(), &'static str> {
    for policy in policies {
        if policy.name.trim().is_empty() {
            return Err("Policy name cannot be empty");
        }
        if policy.path.trim().is_empty() {
            return Err("Policy path cannot be empty");
        }
        if policy.limit.trim().is_empty() {
            return Err("Policy limit cannot be empty");
        }
    }
    Ok(())
}

pub async fn post_ratelimits_handler(
    State(state): State<ControllerState>,
    Json(policies): Json<Vec<config::RateLimitPolicy>>,
) -> impl IntoResponse {
    if let Err(msg) = validate_policies(&policies) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": msg})),
        )
            .into_response();
    }

    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.rate_limit_policies = policies;

    match config::save_config(&state.config_path, &cfg) {
        Ok(_) => {
            info!(
                "Rate limiting policies updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg.clone());

            let _ = crate::logging::write_audit_log(
                &state.db_path,
                "controller",
                "RATELIMIT_UPDATE",
                &format!(
                    "{} rate limit policies applied",
                    cfg.rate_limit_policies.len()
                ),
            );

            StatusCode::OK.into_response()
        }
        Err(e) => {
            error!("Failed to write updated config to disk: {:?}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to write config file",
            )
                .into_response()
        }
    }
}
