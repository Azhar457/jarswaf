use axum::http::HeaderMap;
use axum::{extract::Request, middleware::Next, response::Response};
use tracing::info;

use crate::api::auth::AuthService;
use crate::api::error::ApiError;

/// Authentication middleware
pub async fn require_auth(
    headers: HeaderMap,
    auth: axum::extract::Extension<std::sync::Arc<AuthService>>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = headers.get("Authorization").and_then(|h| h.to_str().ok());

    let token = auth_header
        .and_then(AuthService::extract_token)
        .ok_or(ApiError::auth_required())?;

    let claims = auth.validate_token(&token)?;

    // Inject claims into request extensions for handlers to use
    request.extensions_mut().insert(claims);

    Ok(next.run(request).await)
}

/// Request logging middleware
pub async fn log_requests(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let start = std::time::Instant::now();

    let response = next.run(req).await;

    let status = response.status();
    let elapsed = start.elapsed();

    info!(
        "{} {} -> {} ({:.2}ms)",
        method,
        path,
        status.as_u16(),
        elapsed.as_secs_f64() * 1000.0
    );

    response
}

/// CORS preflight handler
pub async fn cors_handler(_method: axum::http::Method, _headers: HeaderMap) -> Response {
    use axum::http::{header, StatusCode};

    let mut response = Response::new(axum::body::Body::empty());

    *response.status_mut() = StatusCode::NO_CONTENT;

    let headers = response.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*".parse().unwrap());
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        "GET, POST, PUT, DELETE, PATCH, OPTIONS".parse().unwrap(),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        "Authorization, Content-Type".parse().unwrap(),
    );
    headers.insert(header::ACCESS_CONTROL_MAX_AGE, "86400".parse().unwrap());

    response
}
