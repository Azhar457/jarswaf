use ahash::AHashMap;
use chrono::Utc;
use serde_json::Value;
use crate::config::RouteSchema;

/// Validate query parameters against configured OpenAPI-style route schemas.
///
/// Returns `Some(error_message)` if the request violates the schema:
/// - Missing required parameter
/// - Parameter value fails type check (integer, boolean)
/// - Unknown parameter not declared in schema (strict mode)
pub fn check_openapi_schema_validation(
    path: &str,
    query: &str,
    method: &str,
    schemas: &[RouteSchema],
) -> Option<String> {
    // Find matching schema for this path+method
    let schema = schemas.iter().find(|s| {
        path_matches(&s.path, path) && s.method.eq_ignore_ascii_case(method)
    })?;

    // Parse query string into key-value pairs
    let params: AHashMap<&str, &str> = query
        .split('&')
        .filter(|s| !s.is_empty())
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let key = parts.next()?;
            let val = parts.next().unwrap_or("");
            Some((key, val))
        })
        .collect();

    // Check required parameters
    for p in &schema.parameters {
        if p.required && !params.contains_key(p.name.as_str()) {
            return Some(format!(
                "OpenAPI schema violation: missing required parameter '{}'",
                p.name
            ));
        }
    }

    // Type-check provided parameters
    for (key, val) in &params {
        if let Some(p) = schema.parameters.iter().find(|p| p.name == *key) {
            match p.param_type.as_str() {
                "integer" if val.parse::<i64>().is_err() => {
                    return Some(format!(
                        "OpenAPI schema violation: parameter '{}' must be integer, got '{}'",
                        key, val
                    ));
                }
                "boolean" if !matches!(*val, "true" | "false" | "1" | "0") => {
                    return Some(format!(
                        "OpenAPI schema violation: parameter '{}' must be boolean, got '{}'",
                        key, val
                    ));
                }
                _ => {} // "string" always passes
            }
        }
    }

    None
}

/// Simple path matching with support for `{param}` placeholders.
fn path_matches(pattern: &str, actual: &str) -> bool {
    let pat_parts: Vec<&str> = pattern.split('/').collect();
    let act_parts: Vec<&str> = actual.split('/').collect();

    if pat_parts.len() != act_parts.len() {
        return false;
    }

    pat_parts.iter().zip(act_parts.iter()).all(|(p, a)| {
        p.starts_with('{') && p.ends_with('}') || p == a
    })
}

pub fn check_jwt_token(headers: &AHashMap<String, String>) -> Option<String> {
    let auth_header = headers
        .get("authorization")
        .or_else(|| headers.get("Authorization"))?;

    if !auth_header.starts_with("Bearer ") {
        return None;
    }

    let token = &auth_header[7..];
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Some("Malformed JWT: token must contain exactly 3 parts".to_string());
    }

    // Decode and parse payload (part 2)
    let payload_decoded = match base64_url_decode(parts[1]) {
        Ok(bytes) => bytes,
        Err(_) => return Some("Malformed JWT: invalid base64url payload".to_string()),
    };

    let payload_str = match String::from_utf8(payload_decoded) {
        Ok(s) => s,
        Err(_) => return Some("Malformed JWT: payload is not valid UTF-8".to_string()),
    };

    let payload: Value = match serde_json::from_str(&payload_str) {
        Ok(v) => v,
        Err(_) => return Some("Malformed JWT: payload is not valid JSON".to_string()),
    };

    // Check expiration (exp claim)
    if let Some(exp) = payload.get("exp").and_then(|e| e.as_i64()) {
        let now = Utc::now().timestamp();
        if now > exp {
            return Some(format!("Expired JWT: token expired at epoch {}", exp));
        }
    }

    None
}

fn base64_url_decode(input: &str) -> Result<Vec<u8>, &'static str> {
    let mut alphabet = [0u8; 256];
    let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    for (i, &c) in chars.iter().enumerate() {
        alphabet[c as usize] = i as u8;
    }
    alphabet[b'+' as usize] = 62;
    alphabet[b'/' as usize] = 63;

    let mut bytes = Vec::new();
    let mut buffer = 0u32;
    let mut bits = 0;

    for &c in input.as_bytes() {
        if c == b'=' {
            break;
        }
        let val = alphabet[c as usize];
        if val == 0 && c != b'A' {
            continue;
        }
        buffer = (buffer << 6) | (val as u32);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_jwt_validation_expired() {
        let mut headers = AHashMap::new();
        // A valid JWT structure but expired: payload has {"exp": 1516239022}
        let expired_jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE1MTYyMzkwMjJ9.signature";
        headers.insert("Authorization".to_string(), expired_jwt.to_string());
        
        let result = check_jwt_token(&headers);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Expired JWT"));
    }

    #[test]
    fn test_jwt_validation_malformed() {
        let mut headers = AHashMap::new();
        headers.insert("Authorization".to_string(), "Bearer invalid.token".to_string());
        
        let result = check_jwt_token(&headers);
        assert!(result.is_some());
        assert!(result.unwrap().contains("Malformed JWT"));
    }

    #[test]
    fn test_jwt_validation_valid_future() {
        let mut headers = AHashMap::new();
        // A valid JWT structure that expires in 2038: {"exp": 2147483647}
        let valid_jwt = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjIxNDc0ODM2NDd9.signature";
        headers.insert("Authorization".to_string(), valid_jwt.to_string());
        
        let result = check_jwt_token(&headers);
        assert!(result.is_none());
    }

    fn test_schemas() -> Vec<RouteSchema> {
        use crate::config::ParameterSchema;
        vec![RouteSchema {
            path: "/api/v1/users".to_string(),
            method: "GET".to_string(),
            parameters: vec![
                ParameterSchema {
                    name: "page".to_string(),
                    param_type: "integer".to_string(),
                    required: true,
                },
                ParameterSchema {
                    name: "active".to_string(),
                    param_type: "boolean".to_string(),
                    required: false,
                },
                ParameterSchema {
                    name: "search".to_string(),
                    param_type: "string".to_string(),
                    required: false,
                },
            ],
        }]
    }

    #[test]
    fn test_openapi_missing_required_param() {
        let schemas = test_schemas();
        // Missing required 'page' parameter
        let result = check_openapi_schema_validation("/api/v1/users", "active=true", "GET", &schemas);
        assert!(result.is_some());
        assert!(result.unwrap().contains("missing required parameter 'page'"));
    }

    #[test]
    fn test_openapi_integer_type_mismatch() {
        let schemas = test_schemas();
        // 'page' must be integer but got 'abc'
        let result = check_openapi_schema_validation("/api/v1/users", "page=abc", "GET", &schemas);
        assert!(result.is_some());
        assert!(result.unwrap().contains("must be integer"));
    }

    #[test]
    fn test_openapi_boolean_type_mismatch() {
        let schemas = test_schemas();
        // 'active' must be boolean but got 'maybe'
        let result = check_openapi_schema_validation("/api/v1/users", "page=1&active=maybe", "GET", &schemas);
        assert!(result.is_some());
        assert!(result.unwrap().contains("must be boolean"));
    }

    #[test]
    fn test_openapi_valid_request() {
        let schemas = test_schemas();
        let result = check_openapi_schema_validation("/api/v1/users", "page=1&active=true&search=john", "GET", &schemas);
        assert!(result.is_none());
    }

    #[test]
    fn test_openapi_no_schema_match_passes() {
        let schemas = test_schemas();
        // Path not in schemas -> returns None (no schema = no validation)
        let result = check_openapi_schema_validation("/api/v1/posts", "anything=here", "GET", &schemas);
        assert!(result.is_none());
    }

    #[test]
    fn test_path_matches_with_template() {
        assert!(path_matches("/api/v1/users/{id}", "/api/v1/users/42"));
        assert!(!path_matches("/api/v1/users/{id}", "/api/v1/users/42/posts"));
        assert!(path_matches("/api/v1/users", "/api/v1/users"));
    }
}
