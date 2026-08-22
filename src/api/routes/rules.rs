use crate::api::dto::requests::{
    CreateCustomRuleRequest, SetRuleEnabledRequest, UpdateCustomRuleRequest,
};
use crate::api::dto::responses::{ApiResponse, MessageResponse, RateLimitResponse, RuleResponse};
use crate::api::error::ApiError;
use crate::api::state::ApiState;
use crate::control_bus::commands::ControlCommand;
use axum::{
    extract::{Path, State},
    Json,
};

pub async fn list_rules(State(state): State<ApiState>) -> Json<ApiResponse<Vec<RuleResponse>>> {
    let rules = state.published_state.get_rules();
    let list: Vec<RuleResponse> = rules
        .custom_rules
        .iter()
        .cloned()
        .map(RuleResponse::from)
        .collect();

    Json(ApiResponse::new(list))
}

pub async fn create_rule(
    State(state): State<ApiState>,
    Json(req): Json<CreateCustomRuleRequest>,
) -> Result<Json<ApiResponse<RuleResponse>>, ApiError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let new_rule = req.into_rule_def();
    let rule_id = new_rule.id.clone();

    state
        .cmd_tx
        .send(ControlCommand::AddCustomRule {
            rule: new_rule,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    let rules = state.published_state.get_rules();
    let rule = rules
        .get_custom_rule(&rule_id)
        .ok_or_else(|| ApiError::internal("Created rule not found in state"))?;

    Ok(Json(ApiResponse::new(RuleResponse::from(rule.clone()))))
}

pub async fn get_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<RuleResponse>>, ApiError> {
    let rules = state.published_state.get_rules();
    let rule = rules
        .get_custom_rule(&id)
        .ok_or_else(|| ApiError::not_found("Rule"))?;

    Ok(Json(ApiResponse::new(RuleResponse::from(rule.clone()))))
}

pub async fn update_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateCustomRuleRequest>,
) -> Result<Json<ApiResponse<RuleResponse>>, ApiError> {
    let existing = {
        let rules = state.published_state.get_rules();
        rules
            .get_custom_rule(&id)
            .ok_or_else(|| ApiError::not_found("Rule"))?
            .clone()
    };

    let updated = req.into_rule_def(id.clone(), &existing);
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::UpdateCustomRule {
            id: id.clone(),
            rule: updated,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    // Fetch updated rule
    let rules = state.published_state.get_rules();
    let rule = rules
        .get_custom_rule(&id)
        .ok_or_else(|| ApiError::internal("Updated rule not found in state"))?;

    Ok(Json(ApiResponse::new(RuleResponse::from(rule.clone()))))
}

pub async fn delete_rule(
    State(state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::RemoveCustomRule {
            id,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    Ok(Json(ApiResponse::new(MessageResponse::new("Rule deleted"))))
}

pub async fn set_rule_enabled(
    State(state): State<ApiState>,
    Path(id): Path<String>,
    Json(req): Json<SetRuleEnabledRequest>,
) -> Result<Json<ApiResponse<MessageResponse>>, ApiError> {
    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

    state
        .cmd_tx
        .send(ControlCommand::SetRuleEnabled {
            id,
            enabled: req.enabled,
            reply: reply_tx,
        })
        .await
        .map_err(|_| ApiError::internal("Control bus not responding"))?;

    reply_rx
        .await
        .map_err(|_| ApiError::internal("Control bus dropped response"))??;

    Ok(Json(ApiResponse::new(MessageResponse::new(
        if req.enabled {
            "Rule enabled"
        } else {
            "Rule disabled"
        },
    ))))
}

// === RATE LIMITS ===

pub async fn list_rate_limits(
    State(state): State<ApiState>,
) -> Json<ApiResponse<Vec<RateLimitResponse>>> {
    let rules = state.published_state.get_rules();
    let policies: Vec<RateLimitResponse> = rules
        .rate_limit_policies
        .iter()
        .cloned()
        .map(RateLimitResponse::from)
        .collect();

    Json(ApiResponse::new(policies))
}
