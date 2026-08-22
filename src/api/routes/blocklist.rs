use crate::api::dto::requests::{BlockIpRequest, SyncBlocklistRequest};
use crate::api::dto::responses::{ApiResponse, MessageResponse};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::control_bus::commands::ControlCommand;
use crate::control_bus::state::BlockSource;
use axum::{
    extract::{Path, State},
    Json,
};
use std::time::Duration;

pub async fn list_blocklist(
    State(state): State<ApiState>,
) -> Result<Json<ApiResponse<Vec<String>>>, ApiError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::GetBlocklist(reply_tx))
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    let ips = reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))?;

    let ip_strings: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    Ok(Json(ApiResponse::new(ip_strings)))
}

pub async fn block_ip(
    State(state): State<ApiState>,
    Json(req): Json<BlockIpRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let ip: std::net::IpAddr = req
        .ip
        .parse()
        .map_err(|_| ApiError::validation("Invalid IP address"))?;

    let duration = Duration::from_secs(req.duration_secs.unwrap_or(86400));
    let reason = req.reason.unwrap_or_else(|| "Manual block".to_string());

    state
        .cmd_tx
        .send(ControlCommand::BlockIp {
            ip,
            duration,
            reason,
            source: BlockSource::Manual,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    Ok(Json(ApiResponse::new(MessageResponse::new("IP blocked"))))
}

pub async fn unblock_ip(
    State(state): State<ApiState>,
    Path(ip): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let ip: std::net::IpAddr = ip
        .parse()
        .map_err(|_| ApiError::validation("Invalid IP address"))?;

    state
        .cmd_tx
        .send(ControlCommand::UnblockIp { ip })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    Ok(Json(ApiResponse::new(MessageResponse::new("IP unblocked"))))
}

pub async fn sync_blocklist(
    State(state): State<ApiState>,
    Json(req): Json<SyncBlocklistRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let mut ips = Vec::new();
    for ip_str in req.ips {
        let ip: std::net::IpAddr = ip_str
            .parse()
            .map_err(|_| ApiError::validation(&format!("Invalid IP: {}", ip_str)))?;
        ips.push(ip);
    }

    state
        .cmd_tx
        .send(ControlCommand::SyncBlocklist {
            ips,
            source: BlockSource::Manual,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        "Blocklist synced",
    ))))
}

pub async fn clear_blocklist(
    State(state): State<ApiState>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    state
        .cmd_tx
        .send(ControlCommand::ClearBlocklist)
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        "Blocklist cleared",
    ))))
}
