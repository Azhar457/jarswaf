use crate::api::dto::requests::{CreateVhostRequest, UpdateVhostRequest};
use crate::api::dto::responses::{ApiResponse, MessageResponse, VhostResponse};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::control_bus::commands::ControlCommand;
use crate::control_bus::state::VhostConfig;
use axum::{
    extract::{Path, State},
    Json,
};

pub async fn list_vhosts(State(state): State<ApiState>) -> Json<ApiResponse<Vec<VhostResponse>>> {
    let rules = state.published_state.get_rules();
    let list: Vec<VhostResponse> = rules
        .vhosts
        .iter()
        .cloned()
        .map(VhostResponse::from)
        .collect();

    Json(ApiResponse::new(list))
}

pub async fn create_vhost(
    State(state): State<ApiState>,
    Json(req): Json<CreateVhostRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let vhost = req.into_vhost_config();
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::AddVhost {
            vhost,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        "Vhost created",
    ))))
}

pub async fn get_vhost(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<VhostResponse>>, ApiError> {
    let rules = state.published_state.get_rules();
    let vhost = rules
        .vhosts
        .iter()
        .find(|v| v.name == name)
        .ok_or_else(|| ApiError::not_found("Vhost"))?;

    Ok(Json(ApiResponse::new(VhostResponse::from(vhost.clone()))))
}

pub async fn update_vhost(
    State(state): State<ApiState>,
    Path(name): Path<String>,
    Json(req): Json<UpdateVhostRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let existing = {
        let rules = state.published_state.get_rules();
        rules
            .vhosts
            .iter()
            .find(|v| v.name == name)
            .ok_or_else(|| ApiError::not_found("Vhost"))?
            .clone()
    };

    let vhost = VhostConfig {
        name: existing.name.clone(),
        hosts: req.hosts.unwrap_or(existing.hosts.clone()),
        backend: req.backend.unwrap_or(existing.backend.clone()),
        tenant: req.tenant.or(existing.tenant.clone()),
        rule_patterns: req.rule_patterns.unwrap_or(existing.rule_patterns.clone()),
        blocked_countries: req
            .blocked_countries
            .unwrap_or(existing.blocked_countries.clone()),
        geoblock_type: req.geoblock_type.unwrap_or(existing.geoblock_type.clone()),
        custom_rule_ids: req
            .custom_rule_ids
            .unwrap_or(existing.custom_rule_ids.clone()),
        max_body: req.max_body.unwrap_or(existing.max_body.clone()),
        rate_limit: req.rate_limit.unwrap_or(existing.rate_limit.clone()),
        is_default: req.is_default.unwrap_or(existing.is_default),
        max_conns_per_ip: req.max_conns_per_ip.unwrap_or(existing.max_conns_per_ip),
        max_concurrent_requests: req
            .max_concurrent_requests
            .unwrap_or(existing.max_concurrent_requests),
        bot_challenge_enabled: req
            .bot_challenge_enabled
            .unwrap_or(existing.bot_challenge_enabled),
        websocket_security_enabled: req
            .websocket_security_enabled
            .unwrap_or(existing.websocket_security_enabled),
        blocked_asns: req.blocked_asns.unwrap_or(existing.blocked_asns.clone()),
    };

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::UpdateVhost {
            name: name.clone(),
            vhost,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        "Vhost updated",
    ))))
}

pub async fn delete_vhost(
    State(state): State<ApiState>,
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::RemoveVhost {
            name,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        "Vhost deleted",
    ))))
}
