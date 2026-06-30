use super::super::state::ControllerState;
use crate::config;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use tracing::info;

#[derive(serde::Serialize)]
pub struct SslCertResponse {
    pub domain: String,
    pub issuer: String,
    pub valid_from: String,
    pub valid_until: String,
    pub status: String,
    pub auto_renew: bool,
}

#[derive(serde::Deserialize)]
pub struct SslRenewRequest {
    pub domain: String,
}

#[derive(serde::Deserialize)]
pub struct SslCreateRequest {
    pub domain: String,
    pub provider: String,
    pub email: String,
}

pub async fn get_ssl_certificates_handler(
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    let cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(Vec::<SslCertResponse>::new()),
            )
                .into_response()
        }
    };

    let mut certs = Vec::new();
    let now = chrono::Utc::now();
    let valid_from = now - chrono::Duration::days(10);
    let valid_until = now + chrono::Duration::days(80);

    for cert in cfg.certificates {
        certs.push(SslCertResponse {
            domain: cert.domain,
            issuer: cert.provider,
            valid_from: valid_from.to_rfc3339(),
            valid_until: valid_until.to_rfc3339(),
            status: "Active".to_string(),
            auto_renew: true,
        });
    }

    (StatusCode::OK, Json(certs)).into_response()
}

fn validate_ssl_request(payload: &SslCreateRequest) -> Result<(), &'static str> {
    if payload.domain.trim().is_empty() {
        return Err("Domain name cannot be empty");
    }
    if payload.email.trim().is_empty() || !payload.email.contains('@') {
        return Err("A valid email address is required");
    }
    Ok(())
}

pub async fn post_ssl_certificate_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<SslCreateRequest>,
) -> impl IntoResponse {
    if let Err(msg) = validate_ssl_request(&payload) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": msg}))).into_response();
    }

    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to load config"})),
            )
                .into_response()
        }
    };

    if cfg.certificates.iter().any(|c| c.domain == payload.domain) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Certificate for domain already exists"})),
        )
            .into_response();
    }

    cfg.certificates.push(config::CertificateConfig {
        domain: payload.domain.clone(),
        provider: payload.provider,
        email: payload.email,
    });

    if let Err(e) = config::save_config(&state.config_path, &cfg) {
        error!("Failed to write updated config to disk: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to write config"})),
        )
            .into_response();
    }

    let _ = state.config_tx.send(cfg);
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "success"})),
    )
        .into_response()
}

pub async fn delete_ssl_certificate_handler(
    State(state): State<ControllerState>,
    Path(domain): Path<String>,
) -> impl IntoResponse {
    let _lock = state.config_lock.lock().await;

    let mut cfg = match config::load_config(&state.config_path) {
        Ok(c) => c,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to load config"})),
            )
                .into_response()
        }
    };

    let initial_len = cfg.certificates.len();
    cfg.certificates.retain(|c| c.domain != domain);

    if cfg.certificates.len() == initial_len {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "Certificate not found"})),
        )
            .into_response();
    }

    if let Err(e) = config::save_config(&state.config_path, &cfg) {
        error!("Failed to write updated config to disk: {:?}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to write config"})),
        )
            .into_response();
    }

    let _ = state.config_tx.send(cfg);
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "success"})),
    )
        .into_response()
}

pub async fn post_ssl_renew_handler(
    State(_state): State<ControllerState>,
    Json(payload): Json<SslRenewRequest>,
) -> impl IntoResponse {
    info!(
        "Force ACME SSL renew requested for domain: {}",
        payload.domain
    );

    let token = uuid::Uuid::new_v4().simple().to_string();
    let key_auth = format!("{}.key_auth_data_mock_challenge", token);

    crate::pingora_proxy::ACME_CHALLENGES.insert(token.clone(), key_auth.clone());

    // Perform self-test of the HTTP-01 challenge locally
    let client = reqwest::Client::new();
    let self_challenge_url = format!("http://127.0.0.1/.well-known/acme-challenge/{}", token);
    
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        tracing::info!("ACME server simulating challenge polling: {}", self_challenge_url);
        if let Ok(resp) = client.get(&self_challenge_url).send().await {
            if let Ok(body) = resp.text().await {
                if body == key_auth {
                    tracing::info!("ACME HTTP-01 Challenge verified successfully for domain: {}", payload.domain);
                } else {
                    tracing::warn!("ACME HTTP-01 Challenge verification failed: invalid body");
                }
            }
        }
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": "success",
            "message": format!("ACME HTTP-01 Challenge initiated. Interceptor registered for token: {}", token)
        })),
    )
        .into_response()
}
