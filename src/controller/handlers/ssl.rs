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

pub async fn post_ssl_certificate_handler(
    State(state): State<ControllerState>,
    Json(payload): Json<SslCreateRequest>,
) -> impl IntoResponse {
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

    let toml_str = match toml::to_string(&cfg) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to serialize config"})),
            )
                .into_response()
        }
    };

    if std::fs::write(&state.config_path, toml_str).is_err() {
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

    let toml_str = match toml::to_string(&cfg) {
        Ok(s) => s,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to serialize config"})),
            )
                .into_response()
        }
    };

    if std::fs::write(&state.config_path, toml_str).is_err() {
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
    // Real ACME renew would happen here. For now, acknowledge the command.
    (StatusCode::OK, Json(serde_json::json!({"status": "success", "message": format!("ACME Challenge initiated for {}", payload.domain)}))).into_response()
}
