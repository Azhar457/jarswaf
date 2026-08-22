pub mod auth;
pub mod dto;
pub mod error;
pub mod middleware;
pub mod routes;
pub mod state;

pub use state::ApiState;

use axum::{
    middleware as axum_middleware,
    routing::{delete, get, post, put},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

pub fn build_router(state: ApiState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let auth_routes = Router::new()
        .route("/login", post(auth_routes::login))
        .route("/change-password", post(auth_routes::change_password));

    let protected_routes = Router::new()
        // Dashboard
        .route("/dashboard/summary", get(routes::dashboard::get_summary))
        // Config
        .route("/config", get(routes::config::get_config))
        .route("/config/reload", post(routes::config::reload_config))
        // Rules
        .route("/rules", get(routes::rules::list_rules))
        .route("/rules", post(routes::rules::create_rule))
        .route("/rules/:id", get(routes::rules::get_rule))
        .route("/rules/:id", put(routes::rules::update_rule))
        .route("/rules/:id", delete(routes::rules::delete_rule))
        .route("/rules/:id/enable", post(routes::rules::set_rule_enabled))
        // Rate limits
        .route("/rate-limits", get(routes::rules::list_rate_limits))
        // Vhosts
        .route("/vhosts", get(routes::vhosts::list_vhosts))
        .route("/vhosts", post(routes::vhosts::create_vhost))
        .route("/vhosts/:name", get(routes::vhosts::get_vhost))
        .route("/vhosts/:name", put(routes::vhosts::update_vhost))
        .route("/vhosts/:name", delete(routes::vhosts::delete_vhost))
        // Blocklist
        .route("/blocklist", get(routes::blocklist::list_blocklist))
        .route("/blocklist", post(routes::blocklist::block_ip))
        .route("/blocklist/:ip", delete(routes::blocklist::unblock_ip))
        .route("/blocklist/sync", post(routes::blocklist::sync_blocklist))
        .route("/blocklist/clear", post(routes::blocklist::clear_blocklist))
        // Logs
        .route("/logs", get(routes::logs::query_logs))
        // Agents
        .route("/agents", get(routes::agents::list_agents))
        .route("/agents/:hostname", get(routes::agents::get_agent))
        // Apply authentication middleware to all protected routes
        .layer(axum_middleware::from_fn(middleware::require_auth))
        .layer(axum::Extension(state.auth.clone()));

    Router::new()
        .route("/health", get(routes::health::health_check))
        .route("/metrics", get(routes::metrics::prometheus_metrics))
        // WebSockets
        .route("/ws/events", get(routes::ws::ws_events))
        .route("/ws/metrics", get(routes::ws::ws_metrics))
        // Log stream via SSE
        .route("/logs/stream", get(routes::logs::stream_logs))
        .nest(
            "/api/v1",
            Router::new().merge(auth_routes).merge(protected_routes),
        )
        .layer(axum_middleware::from_fn(middleware::log_requests))
        .layer(cors)
        .with_state(state)
}

// Auth routes (separate module for clarity)
mod auth_routes {
    use crate::api::dto::requests::{ChangePasswordRequest, LoginRequest};
    use crate::api::dto::responses::ApiResponse;
    use crate::api::error::ApiError;
    use crate::api::state::ApiState;
    use axum::{extract::State, Json};
    use serde::Serialize;

    #[derive(Debug, Serialize)]
    pub struct LoginResponse {
        pub token: String,
        pub expires_in: u64,
    }

    pub async fn login(
        State(state): State<ApiState>,
        Json(req): Json<LoginRequest>,
    ) -> Result<Json<ApiResponse<LoginResponse>>, ApiError> {
        let token = state.auth.login(&req.password)?;

        Ok(Json(ApiResponse::new(LoginResponse {
            token,
            expires_in: 86400,
        })))
    }

    pub async fn change_password(
        State(_state): State<ApiState>,
        Json(_req): Json<ChangePasswordRequest>,
    ) -> Result<Json<ApiResponse<String>>, ApiError> {
        Err(ApiError::new("INTERNAL_ERROR", "Not implemented"))
    }
}
