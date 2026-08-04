use crate::config;
use crate::controller::state::ControllerState;
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct OnboardingStatusResponse {
    pub is_first_boot: bool,
    pub vhosts_count: usize,
    pub has_admin_token: bool,
    pub message: String,
}

/// GET /api/v1/onboarding/status — Check if WAF requires initial onboarding wizard
pub async fn get_onboarding_status_handler(
    State(state): State<ControllerState>,
) -> Result<Json<OnboardingStatusResponse>, StatusCode> {
    let cfg = config::load_config(&state.config_path).unwrap_or_default();
    let vhosts_count = cfg.vhosts.len();
    let is_first_boot = vhosts_count == 0;

    Ok(Json(OnboardingStatusResponse {
        is_first_boot,
        vhosts_count,
        has_admin_token: cfg.global.admin_token.is_some(),
        message: if is_first_boot {
            "First boot detected. Onboarding wizard recommended.".into()
        } else {
            "Onboarding completed.".into()
        },
    }))
}

#[derive(Debug, Deserialize)]
pub struct CompleteOnboardingPayload {
    pub new_admin_password: Option<String>,
    pub initial_vhost: Option<config::VHost>,
}

/// POST /api/v1/onboarding/complete — Fast-track onboarding wizard completion
pub async fn post_complete_onboarding_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<CompleteOnboardingPayload>,
) -> Result<Json<serde_json::Value>, (StatusCode, &'static str)> {
    let mut cfg = config::load_config(&state.config_path)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed reading config"))?;

    if let Some(new_pass) = payload.new_admin_password {
        if new_pass.trim().len() >= 8 {
            // Hash the password before persisting — never store it in plaintext. This must
            // match the hashing used by `change_password_handler` (`auth::hash_password`),
            // which a prior version of this onboarding path bypassed (stored raw password).
            cfg.global.admin_token = Some(crate::controller::auth::hash_password(&new_pass));
        }
    }

    if let Some(vhost) = payload.initial_vhost {
        cfg.vhosts.push(vhost);
    }

    config::save_config(&state.config_path, &cfg)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed saving config"))?;

    Ok(Json(serde_json::json!({
        "status": "success",
        "message": "Onboarding completed successfully"
    })))
}
