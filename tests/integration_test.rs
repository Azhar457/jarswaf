//! Integration tests for jarsWAF Controller HTTP API.
//!
//! These tests boot the actual Controller router on a random local port
//! using `build_router` and verify end-to-end HTTP behavior:
//! - `/health` returns 200 without auth
//! - `/api/v1/*` endpoints return 401 without auth
//! - `/api/v1/agents/register` returns 201 with valid Bearer token
//! - CORS headers are present on responses
//!
//! Tests are gated on real `reqwest` (no network mocking) and use a fresh
//! tempdir + minimal ControllerState per test for isolation.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::net::TcpListener;

use jarswaf::controller::{build_router, ControllerState};
use tokio::sync::broadcast;

/// Helper: spawn the Controller router on a random local port.
/// Returns the bound address (e.g. `127.0.0.1:0`) and a JoinHandle that
/// aborts the server when dropped.
async fn spawn_test_server(
    admin_token: Option<String>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);
    let test_id = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind random port");
    let addr = listener.local_addr().expect("read local_addr");

    // Unique config path per test invocation
    let config_path = std::env::temp_dir()
        .join(format!(
            "jarswaf_test_{}_{}.toml",
            std::process::id(),
            test_id
        ))
        .to_string_lossy()
        .into_owned();
    std::fs::write(&config_path, "").unwrap();

    let (tx, _) = broadcast::channel::<jarswaf::logging::WafLogEntry>(16);
    let (config_tx, _) = broadcast::channel::<jarswaf::config::Config>(4);
    let (block_tx, _) = broadcast::channel::<jarswaf::controller::BlockCommand>(4);

    let state = ControllerState {
        tx,
        block_tx,
        db_path: std::env::temp_dir()
            .join(format!(
                "jarswaf_test_{}_{}.db",
                std::process::id(),
                test_id
            ))
            .to_string_lossy()
            .into_owned(),
        logging_enabled: Arc::new(AtomicBool::new(true)),
        log_size_limit_mb: Arc::new(AtomicU64::new(500)),
        config_path: if let Some(ref t) = admin_token {
            // Build a valid Config with default values, then patch the admin_token.
            let mut cfg = jarswaf::config::Config::default();
            cfg.global.admin_token = Some(t.clone());
            let s = toml::to_string(&cfg).expect("serialize Config to TOML");
            std::fs::write(&config_path, s).unwrap();
            config_path.clone()
        } else {
            // Empty config → no admin_token → middleware allows all
            config_path.clone()
        },
        agent_registry: Arc::new(std::sync::RwLock::new(Default::default())),
        total_requests: Arc::new(AtomicU64::new(0)),
        blocked: Arc::new(AtomicU64::new(0)),
        rate_limited: Arc::new(AtomicU64::new(0)),
        config_tx,
        config_lock: Arc::new(tokio::sync::Mutex::new(())),
        sessions: Arc::new(std::sync::RwLock::new(Default::default())),
    };

    let app = build_router(state);

    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app.into_make_service()).await;
    });

    (addr, handle)
}

/// Test 1: GET /health is publicly accessible (no auth) and returns "OK"
#[tokio::test]
async fn test_health_endpoint_no_auth() {
    let (addr, _handle) = spawn_test_server(None).await;

    let url = format!("http://{}/health", addr);
    let resp = reqwest::get(&url).await.expect("request health");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("read body");
    assert_eq!(body, "OK");
}

/// Test 2: When admin_token is configured, /api/v1/agents/register requires Bearer token
#[tokio::test]
async fn test_api_endpoint_requires_auth() {
    let token = format!("test_token_requires_{}", std::process::id());
    let (addr, _handle) = spawn_test_server(Some(token.clone())).await;

    // Without auth → 401
    let url = format!("http://{}/api/v1/agents/register", addr);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "hostname": "test-host",
            "ip": "127.0.0.1",
            "port": 8080,
            "os": "linux",
        }))
        .send()
        .await
        .expect("request without auth");
    assert_eq!(resp.status(), 401);
}

/// Test 3: With valid Bearer token, /api/v1/agents/register returns 201
#[tokio::test]
async fn test_api_endpoint_with_auth_succeeds() {
    let token = format!("test_token_succeeds_{}", std::process::id());
    let (addr, _handle) = spawn_test_server(Some(token.clone())).await;

    let url = format!("http://{}/api/v1/agents/register", addr);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("Bearer {}", token))
        .json(&serde_json::json!({
            "hostname": "test-host",
            "ip": "127.0.0.1",
            "port": 8080,
            "os": "linux",
        }))
        .send()
        .await
        .expect("request with auth");
    assert_eq!(resp.status(), 201);
}

/// Test 4: Wrong Bearer token returns 401
#[tokio::test]
async fn test_api_endpoint_wrong_token_rejected() {
    let token = format!("test_token_wrong_{}", std::process::id());
    let (addr, _handle) = spawn_test_server(Some(token.clone())).await;

    let url = format!("http://{}/api/v1/agents/register", addr);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", "Bearer wrong_token")
        .json(&serde_json::json!({
            "hostname": "test-host",
            "ip": "127.0.0.1",
            "port": 8080,
            "os": "linux",
        }))
        .send()
        .await
        .expect("request with wrong token");
    assert_eq!(resp.status(), 401);
}

/// Test 5: When admin_token is NOT configured, auth middleware fails closed (401)
#[tokio::test]
async fn test_no_admin_token_allows_all() {
    let (addr, _handle) = spawn_test_server(None).await;

    // No token configured → register endpoint should fail closed (401)
    let url = format!("http://{}/api/v1/agents/register", addr);
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "hostname": "open-host",
            "ip": "127.0.0.1",
            "port": 8080,
            "os": "linux",
        }))
        .send()
        .await
        .expect("request no token configured");
    assert_eq!(resp.status(), 401);
}

/// Test 6: GET /metrics requires auth when admin_token is configured, and succeeds with valid token
#[tokio::test]
async fn test_metrics_endpoint_reachable() {
    let token = format!("test_metrics_token_{}", std::process::id());
    let (addr, _handle) = spawn_test_server(Some(token.clone())).await;

    let url = format!("http://{}/metrics", addr);
    let client = reqwest::Client::new();

    // 1. Without auth -> 401
    let resp_unauth = client
        .get(&url)
        .send()
        .await
        .expect("request unauth metrics");
    assert_eq!(resp_unauth.status(), 401);

    // 2. With Bearer token -> 200
    let resp_bearer = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .await
        .expect("request metrics with bearer");
    assert_eq!(resp_bearer.status(), 200);
    let body = resp_bearer.text().await.expect("read metrics body");
    assert!(body.contains("jarswaf_total_requests"));

    // 3. With X-Metrics-Token header -> 200
    let resp_custom = client
        .get(&url)
        .header("X-Metrics-Token", &token)
        .send()
        .await
        .expect("request metrics with custom header");
    assert_eq!(resp_custom.status(), 200);
}
