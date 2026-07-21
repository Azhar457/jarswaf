//! Zero Trust Architecture — Trust Scoring & Identity Verification
//!
//! Calculates a composite trust score per request based on multiple signals:
//! - Identity verification (Bearer token / OIDC)
//! - Geo consistency
//! - Fingerprint stability
//! - IP reputation
//!
//! Requests below the configured trust threshold are blocked or challenged.

use ahash::AHashMap;

/// Signals collected per request for trust scoring.
#[derive(Debug, Clone)]
pub struct TrustSignals {
    /// Whether a valid identity token was presented (Bearer/OIDC)
    pub identity_verified: bool,
    /// Whether the issuer of the identity token is in the allowed list
    pub issuer_trusted: bool,
    /// Whether client IP geo matches expected regions
    pub geo_match: bool,
    /// Whether the request fingerprint is consistent with session history
    pub fingerprint_stable: bool,
    /// Whether the client IP has a clean reputation (no blocks/rate limits)
    pub reputation_clean: bool,
    /// Whether the request uses TLS
    pub tls_verified: bool,
}

impl Default for TrustSignals {
    fn default() -> Self {
        Self {
            identity_verified: false,
            issuer_trusted: false,
            geo_match: true,       // default pass if geo not configured
            fingerprint_stable: true, // default pass if fingerprint not tracked
            reputation_clean: true,
            tls_verified: false,
        }
    }
}

/// Weight configuration for each trust signal.
/// Sum of all weights determines the maximum possible score.
struct TrustWeights {
    identity: f64,
    issuer: f64,
    geo: f64,
    fingerprint: f64,
    reputation: f64,
    tls: f64,
}

impl Default for TrustWeights {
    fn default() -> Self {
        Self {
            identity: 30.0,   // identity is the heaviest signal
            issuer: 15.0,
            geo: 10.0,
            fingerprint: 15.0,
            reputation: 20.0,
            tls: 10.0,
        }
    }
}

/// Calculate a normalized trust score (0.0 = untrusted, 1.0 = fully trusted).
pub fn calculate_trust_score(signals: &TrustSignals) -> f64 {
    let w = TrustWeights::default();
    let max_score = w.identity + w.issuer + w.geo + w.fingerprint + w.reputation + w.tls;

    let mut score = 0.0;
    if signals.identity_verified {
        score += w.identity;
    }
    if signals.issuer_trusted {
        score += w.issuer;
    }
    if signals.geo_match {
        score += w.geo;
    }
    if signals.fingerprint_stable {
        score += w.fingerprint;
    }
    if signals.reputation_clean {
        score += w.reputation;
    }
    if signals.tls_verified {
        score += w.tls;
    }

    score / max_score
}

/// Check identity from Authorization header.
/// Supports: `Bearer <base64.base64.base64>` (JWT-like structure).
/// Validates:
/// 1. Token has 3 dot-separated parts
/// 2. Payload contains `exp` claim (not expired)
/// 3. Payload contains `iss` claim (in allowed issuers list)
///
/// Returns (identity_verified, issuer_trusted).
pub fn check_identity_token(
    headers: &AHashMap<String, String>,
    allowed_issuers: &[String],
) -> (bool, bool) {
    let auth = match headers.get("authorization").or_else(|| headers.get("x-identity-token")) {
        Some(v) => v,
        None => return (false, false),
    };

    let token = if let Some(stripped) = auth.strip_prefix("Bearer ") {
        stripped.trim()
    } else {
        auth.trim()
    };

    // Must have 3 parts (header.payload.signature)
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return (false, false);
    }

    // Decode payload (middle part) — base64url
    let payload_b64 = parts[1];
    let padded = match payload_b64.len() % 4 {
        2 => format!("{}==", payload_b64),
        3 => format!("{}=", payload_b64),
        _ => payload_b64.to_string(),
    };

    let payload_bytes = match base64_url_decode(&padded) {
        Some(b) => b,
        None => return (false, false),
    };

    let payload_str = match std::str::from_utf8(&payload_bytes) {
        Ok(s) => s,
        Err(_) => return (false, false),
    };

    // Parse as JSON manually (avoid serde dependency for this simple check)
    let identity_verified = true; // token structure is valid

    // Check expiry: look for "exp":NUMBER
    let expired = if let Some(exp_val) = extract_json_number(payload_str, "exp") {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        exp_val < now
    } else {
        false // no exp claim = not expired (lenient)
    };

    if expired {
        return (false, false);
    }

    // Check issuer
    let issuer_trusted = if let Some(iss) = extract_json_string(payload_str, "iss") {
        if allowed_issuers.is_empty() {
            true // no issuers configured = trust all
        } else {
            allowed_issuers.iter().any(|a| a == &iss)
        }
    } else {
        allowed_issuers.is_empty() // no iss claim: trusted only if no issuers configured
    };

    (identity_verified, issuer_trusted)
}

/// Evaluate Zero Trust policy for a request.
/// Returns `Some(message)` if the trust score is below threshold (block).
pub fn check_zero_trust(
    headers: &AHashMap<String, String>,
    reputation_clean: bool,
    fingerprint_stable: bool,
    geo_match: bool,
    tls_verified: bool,
    allowed_issuers: &[String],
    min_trust_score: f64,
) -> Option<String> {
    let (identity_verified, issuer_trusted) =
        check_identity_token(headers, allowed_issuers);

    let signals = TrustSignals {
        identity_verified,
        issuer_trusted,
        geo_match,
        fingerprint_stable,
        reputation_clean,
        tls_verified,
    };

    let score = calculate_trust_score(&signals);

    if score < min_trust_score {
        Some(format!(
            "Zero Trust score {:.2} below threshold {:.2} — signals: id={}, iss={}, geo={}, fp={}, rep={}, tls={}",
            score, min_trust_score,
            signals.identity_verified, signals.issuer_trusted,
            signals.geo_match, signals.fingerprint_stable,
            signals.reputation_clean, signals.tls_verified,
        ))
    } else {
        None
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Minimal base64url decoder (no padding required, handles URL-safe alphabet).
fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    let standard: String = input
        .chars()
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();

    // Simple base64 decode
    let chars: Vec<u8> = standard.bytes().collect();
    let mut output = Vec::new();
    let mut i = 0;

    while i < chars.len() {
        let a = b64_val(chars.get(i).copied()?)?;
        let b = b64_val(chars.get(i + 1).copied()?)?;
        output.push((a << 2) | (b >> 4));

        if let Some(&c) = chars.get(i + 2) {
            if c == b'=' {
                break;
            }
            let c = b64_val(c)?;
            output.push((b << 4) | (c >> 2));

            if let Some(&d) = chars.get(i + 3) {
                if d == b'=' {
                    break;
                }
                let d = b64_val(d)?;
                output.push((c << 6) | d);
            }
        }
        i += 4;
    }

    Some(output)
}

fn b64_val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Extract a numeric value for a key from a JSON string (simple scanner).
fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    // Skip whitespace and colon
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();

    // Parse number
    let end = rest.find(|c: char| !c.is_ascii_digit() && c != '-').unwrap_or(rest.len());
    rest[..end].parse::<i64>().ok()
}

/// Extract a string value for a key from a JSON string (simple scanner).
fn extract_json_string(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('"')?;
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(payload_json: &str) -> String {
        // header: {"alg":"none","typ":"JWT"}
        let header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        let payload = base64_url_encode(payload_json.as_bytes());
        let sig = "signature";
        format!("{}.{}.{}", header, payload, sig)
    }

    fn base64_url_encode(data: &[u8]) -> String {
        let mut result = String::new();
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < data.len() {
            let a = data[i];
            let b = data.get(i + 1).copied().unwrap_or(0);
            let c = data.get(i + 2).copied().unwrap_or(0);

            result.push(chars[(a >> 2) as usize] as char);
            result.push(chars[(((a & 3) << 4) | (b >> 4)) as usize] as char);
            if i + 1 < data.len() {
                result.push(chars[(((b & 0xf) << 2) | (c >> 6)) as usize] as char);
            } else {
                result.push('=');
            }
            if i + 2 < data.len() {
                result.push(chars[(c & 0x3f) as usize] as char);
            } else {
                result.push('=');
            }
            i += 3;
        }
        // Make URL-safe
        result.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string()
    }

    #[test]
    fn test_trust_score_all_signals_high() {
        let signals = TrustSignals {
            identity_verified: true,
            issuer_trusted: true,
            geo_match: true,
            fingerprint_stable: true,
            reputation_clean: true,
            tls_verified: true,
        };
        let score = calculate_trust_score(&signals);
        assert!((score - 1.0).abs() < 0.001);
    }

    #[test]
    fn test_trust_score_no_signals() {
        let signals = TrustSignals {
            identity_verified: false,
            issuer_trusted: false,
            geo_match: false,
            fingerprint_stable: false,
            reputation_clean: false,
            tls_verified: false,
        };
        let score = calculate_trust_score(&signals);
        assert!((score - 0.0).abs() < 0.001);
    }

    #[test]
    fn test_trust_score_partial() {
        let signals = TrustSignals {
            identity_verified: false,
            issuer_trusted: false,
            geo_match: true,       // +10
            fingerprint_stable: true, // +15
            reputation_clean: true,  // +20
            tls_verified: true,     // +10
        };
        // 55/100 = 0.55
        let score = calculate_trust_score(&signals);
        assert!((score - 0.55).abs() < 0.001);
    }

    #[test]
    fn test_identity_token_valid() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(r#"{{"sub":"user1","iss":"https://auth.jarswaf.local","exp":{}}}"#, future_exp);
        let token = make_jwt(&payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, iss_ok) = check_identity_token(&headers, &issuers);
        assert!(id_ok);
        assert!(iss_ok);
    }

    #[test]
    fn test_identity_token_expired() {
        let payload = r#"{"sub":"user1","iss":"https://auth.jarswaf.local","exp":1000000}"#;
        let token = make_jwt(payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, _) = check_identity_token(&headers, &issuers);
        assert!(!id_ok); // expired = not verified
    }

    #[test]
    fn test_identity_token_untrusted_issuer() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(r#"{{"sub":"user1","iss":"https://evil.com","exp":{}}}"#, future_exp);
        let token = make_jwt(&payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, iss_ok) = check_identity_token(&headers, &issuers);
        assert!(id_ok);   // structure valid
        assert!(!iss_ok); // issuer not in allowed list
    }

    #[test]
    fn test_identity_no_header() {
        let headers = AHashMap::new();
        let (id_ok, iss_ok) = check_identity_token(&headers, &[]);
        assert!(!id_ok);
        assert!(!iss_ok);
    }

    #[test]
    fn test_zero_trust_blocks_low_score() {
        let headers = AHashMap::new(); // no identity token
        let result = check_zero_trust(
            &headers,
            true,  // reputation clean
            true,  // fingerprint stable
            true,  // geo match
            false, // no TLS
            &[],   // no issuers
            0.80,  // high threshold
        );
        assert!(result.is_some()); // should block — no identity = low score
    }

    #[test]
    fn test_zero_trust_passes_high_score() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(r#"{{"sub":"admin","iss":"https://auth.local","exp":{}}}"#, future_exp);
        let token = make_jwt(&payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let result = check_zero_trust(
            &headers,
            true, true, true, true,
            &[], // no issuers configured = trust all
            0.50,
        );
        assert!(result.is_none()); // should pass
    }
}
