use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

/// API error response format
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: ErrorDetail,
}

#[derive(Debug, Serialize)]
pub struct ErrorDetail {
    pub code: String,
    pub message: String,
}

impl ApiError {
    pub fn new(code: &str, message: &str) -> Self {
        Self {
            error: ErrorDetail {
                code: code.to_string(),
                message: message.to_string(),
            },
        }
    }

    pub fn not_found(resource: &str) -> Self {
        Self::new("NOT_FOUND", &format!("{} not found", resource))
    }

    pub fn validation(message: &str) -> Self {
        Self::new("VALIDATION_ERROR", message)
    }

    pub fn auth_required() -> Self {
        Self::new("AUTH_REQUIRED", "Authentication required")
    }

    pub fn forbidden() -> Self {
        Self::new("FORBIDDEN", "Insufficient permissions")
    }

    pub fn conflict(resource: &str) -> Self {
        Self::new("CONFLICT", &format!("{} already exists", resource))
    }

    pub fn internal(message: &str) -> Self {
        Self::new("INTERNAL_ERROR", message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.error.code.as_str() {
            "NOT_FOUND" => StatusCode::NOT_FOUND,
            "VALIDATION_ERROR" => StatusCode::BAD_REQUEST,
            "AUTH_REQUIRED" => StatusCode::UNAUTHORIZED,
            "FORBIDDEN" => StatusCode::FORBIDDEN,
            "CONFLICT" => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, Json(self)).into_response()
    }
}

impl From<crate::control_bus::commands::CommandError> for ApiError {
    fn from(err: crate::control_bus::commands::CommandError) -> Self {
        match err {
            crate::control_bus::commands::CommandError::NotFound(msg) => {
                Self::new("NOT_FOUND", &msg)
            }
            crate::control_bus::commands::CommandError::AlreadyExists(msg) => {
                Self::new("CONFLICT", &msg)
            }
            crate::control_bus::commands::CommandError::Validation(msg) => {
                Self::new("VALIDATION_ERROR", &msg)
            }
            crate::control_bus::commands::CommandError::Internal(msg) => {
                Self::new("INTERNAL_ERROR", &msg)
            }
        }
    }
}

/// Helper trait for converting Option to ApiError
pub trait OptionExt<T> {
    fn ok_or_not_found(self, resource: &str) -> Result<T, ApiError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_not_found(self, resource: &str) -> Result<T, ApiError> {
        self.ok_or_else(|| ApiError::not_found(resource))
    }
}
