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
        cfg.rate_limit_policies = vec![
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
        if let Ok(toml_str) = toml::to_string(&cfg) {
            let _ = std::fs::write(&state.config_path, toml_str);
        }
    }

    (StatusCode::OK, Json(cfg.rate_limit_policies)).into_response()
}

pub async fn post_ratelimits_handler(
    State(state): State<ControllerState>,
    Json(policies): Json<Vec<config::RateLimitPolicy>>,
) -> impl IntoResponse {
    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to load config from {}: {:?}", state.config_path, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to load config").into_response();
        }
    };

    cfg.rate_limit_policies = policies;

    let toml_str = match toml::to_string(&cfg) {
        Ok(t) => t,
        Err(e) => {
            error!("Failed to serialize updated config to TOML: {:?}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to serialize config",
            )
                .into_response();
        }
    };

    match std::fs::write(&state.config_path, toml_str) {
        Ok(_) => {
            info!(
                "Rate limiting policies updated successfully in {}",
                state.config_path
            );
            let _ = state.config_tx.send(cfg);
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
