use hyper::HeaderMap;
use serde_json::Value;

/// Basic JWT structural validation
pub fn validate_jwt_structure(headers: &HeaderMap) -> Result<(), &'static str> {
    if let Some(auth_header) = headers.get("authorization") {
        if let Ok(auth_str) = auth_header.to_str() {
            if auth_str.to_lowercase().starts_with("bearer ") {
                let token = &auth_str[7..];
                // A standard JWT has exactly 3 parts separated by dots
                let parts: Vec<&str> = token.split('.').collect();
                if parts.len() != 3 {
                    return Err("Invalid JWT structure detected");
                }

                // We can also decode the header/payload to ensure it's valid base64url,
                // but for a lightweight check, just the structure is a good start.
            }
        }
    }
    Ok(())
}

/// GraphQL Query Depth Limiter
/// Prevents nested query denial of service (DoS).
pub fn check_graphql_depth(body: &[u8], max_depth: usize) -> Result<(), &'static str> {
    if let Ok(json) = serde_json::from_slice::<Value>(body) {
        if let Some(query) = json.get("query").and_then(|q| q.as_str()) {
            let mut current_depth = 0;
            let mut max_observed = 0;

            for c in query.chars() {
                if c == '{' {
                    current_depth += 1;
                    if current_depth > max_observed {
                        max_observed = current_depth;
                    }
                    if current_depth > max_depth {
                        return Err("GraphQL query exceeds maximum allowed depth");
                    }
                } else if c == '}' {
                    current_depth = current_depth.saturating_sub(1);
                }
            }
        }
    }
    Ok(())
}
