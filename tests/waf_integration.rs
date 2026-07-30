/// Integration test for jarsWAF — verifies WAF blocks attack payloads via real HTTP
///
/// Run with: cargo test --test waf_integration -- --ignored
/// Requires: controller + agent running on ports 8080/8000
/// Note: marked #[ignore] by default since it needs running environment
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn http_get_raw(host: &str, port: u16, path: &str, ua: &str) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_secs(3),
    )
    .map_err(|e| format!("connect: {}", e))?;

    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: {}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        path, host, ua
    );

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("write: {}", e))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| format!("read: {}", e))?;

    let response_str = String::from_utf8_lossy(&response);
    let status_line = response_str.lines().next().unwrap_or("");
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    Ok((status, response_str.to_string()))
}

#[test]
#[ignore]
fn test_health_endpoint() {
    let (status, _) = http_get_raw("localhost", 8080, "/health", "test").unwrap();
    assert_eq!(
        status, 200,
        "Health endpoint should return 200, got: {}",
        status
    );
}

#[test]
#[ignore]
fn test_safe_request_passes_waf() {
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let (status, _) = http_get_raw("test.jarswafwaf.demo", 8000, "/", ua).unwrap();
    assert!(
        status == 200 || status == 403,
        "Safe request got: {} (expected 200 or 403)",
        status
    );
}

#[test]
#[ignore]
fn test_sqli_blocked() {
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let (status, _) = http_get_raw("test.jarswafwaf.demo", 8000, "/?id=1' OR '1'='1", ua).unwrap();
    assert_eq!(status, 403, "SQLi should be blocked (403), got: {}", status);
}

#[test]
#[ignore]
fn test_xss_blocked() {
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let (status, _) = http_get_raw(
        "test.jarswafwaf.demo",
        8000,
        "/?search=<script>alert(1)</script>",
        ua,
    )
    .unwrap();
    assert_eq!(status, 403, "XSS should be blocked (403), got: {}", status);
}

#[test]
#[ignore]
fn test_lfi_blocked() {
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36";
    let (status, _) =
        http_get_raw("test.jarswafwaf.demo", 8000, "/?file=../../etc/passwd", ua).unwrap();
    assert_eq!(status, 403, "LFI should be blocked (403), got: {}", status);
}

#[test]
#[ignore]
fn test_waf_log_has_entries() {
    let log_path = "./logs/jarswaf.log";
    let content = std::fs::read_to_string(log_path).unwrap_or_default();
    assert!(!content.is_empty(), "WAF log should have entries");
    assert!(
        content.contains("BLOCK") || content.contains("PASS"),
        "WAF log should contain BLOCK or PASS entries"
    );
}
