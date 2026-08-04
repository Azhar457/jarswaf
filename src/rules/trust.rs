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
            geo_match: true,          // default pass if geo not configured
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
            identity: 30.0, // identity is the heaviest signal
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
    shared_secret: &str,
) -> (bool, bool) {
    let auth = match headers
        .get("authorization")
        .or_else(|| headers.get("x-identity-token"))
    {
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
    // URL_SAFE_NO_PAD rejects '=' — strip any padding before decode
    let payload_b64 = payload_b64.trim_end_matches('=');

    let payload_bytes = match crate::utils::base64_url_decode(payload_b64) {
        Ok(b) => b,
        Err(_) => return (false, false),
    };

    let payload_str = match std::str::from_utf8(&payload_bytes) {
        Ok(s) => s,
        Err(_) => return (false, false),
    };

    // Reject alg:none and empty signatures — even before full verification these must
    // never count as a verified identity.
    let header_b64 = parts[0];
    let header_padded = match header_b64.len() % 4 {
        2 => format!("{}==", header_b64),
        3 => format!("{}=", header_b64),
        _ => header_b64.to_string(),
    };
    let header_json = crate::utils::base64_url_decode(&header_padded)
        .ok()
        .and_then(|b| String::from_utf8(b).ok());
    let alg_is_none = header_json
        .as_deref()
        .and_then(|h| crate::utils::extract_json_string(h, "alg"))
        .map(|a| a.eq_ignore_ascii_case("none"))
        .unwrap_or(true);
    if alg_is_none || parts[2].trim().is_empty() {
        return (false, false);
    }

    // C-01 fix: a token counts as a verified identity ONLY if its signature actually
    // verifies. When `shared_secret` is non-empty we verify HS256 signatures; otherwise we
    // stay fail-closed (identity_verified stays false). Treating an unsigned/unverified
    // token as verified would let anyone who knows `allowed_issuers` forge a token and max
    // out the Zero-Trust score.
    let identity_verified = if shared_secret.is_empty() {
        false
    } else {
        verify_hs256_signature(shared_secret, &parts, header_json.as_deref())
    };

    // Check expiry: look for "exp":NUMBER
    let expired = if let Some(exp_val) = crate::utils::extract_json_number(payload_str, "exp") {
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
    let issuer_trusted = if let Some(iss) = crate::utils::extract_json_string(payload_str, "iss") {
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
#[allow(clippy::too_many_arguments)] // single call site; grouping into a struct is overkill
pub fn check_zero_trust(
    headers: &AHashMap<String, String>,
    reputation_clean: bool,
    fingerprint_stable: bool,
    geo_match: bool,
    tls_verified: bool,
    allowed_issuers: &[String],
    min_trust_score: f64,
    shared_secret: &str,
) -> Option<String> {
    let (identity_verified, issuer_trusted) =
        check_identity_token(headers, allowed_issuers, shared_secret);

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

/// Verify an HS256 JWT signature: recompute HMAC-SHA256 over `header.payload` and compare
/// constant-time with the supplied signature part. Returns false on any malformed input or
/// when `alg` is not HS256 (fail-closed). Uses `ring::hmac` (already a rustls dependency) —
/// no new crate needed.
fn verify_hs256_signature(secret: &str, parts: &[&str], header_json: Option<&str>) -> bool {
    use ring::hmac;

    // Require alg == HS256 (case-insensitive); anything else rejects.
    let alg = header_json
        .and_then(|h| crate::utils::extract_json_string(h, "alg"))
        .map(|a| a.to_ascii_lowercase())
        .unwrap_or_default();
    if alg != "hs256" {
        return false;
    }

    // signing input = base64url(header).base64url(payload)
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let expected_sig = match crate::utils::base64_url_decode(parts[2]) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let tag = hmac::sign(&key, signing_input.as_bytes());
    let mac = tag.as_ref();
    if mac.len() != expected_sig.len() {
        return false;
    }
    // Constant-time compare so a wrong signature doesn't leak timing.
    crate::controller::auth::constant_time_eq(mac, &expected_sig)
}

// ─── Helpers ────────────────────────────────────────────────────────────────

// Base64url decode + JSON extraction live in crate::utils (shared with api.rs,
// dlp.rs). See src/utils.rs.

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_jwt(payload_json: &str) -> String {
        // header: {"alg":"HS256","typ":"JWT"}
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
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
        result
            .replace('+', "-")
            .replace('/', "_")
            .trim_end_matches('=')
            .to_string()
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
            geo_match: true,          // +10
            fingerprint_stable: true, // +15
            reputation_clean: true,   // +20
            tls_verified: true,       // +10
        };
        // 55/100 = 0.55
        let score = calculate_trust_score(&signals);
        assert!((score - 0.55).abs() < 0.001);
    }

    fn hmac_sign_b64url(secret: &str, signing_input: &str) -> String {
        use ring::hmac;
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
        let tag = hmac::sign(&key, signing_input.as_bytes());
        base64_url_encode(tag.as_ref())
    }

    #[test]
    fn test_identity_token_hs256_verified_with_secret() {
        // C-01 fix: with a configured HMAC secret, a correctly-signed HS256 token IS
        // treated as verified; identity_verified becomes true.
        let secret = "s3cret!";
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://auth.jarswaf.local","exp":{}}}"#,
            future_exp
        );
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"; // {"alg":"HS256","typ":"JWT"}
        let body = base64_url_encode(payload.as_bytes());
        let signing_input = format!("{}.{}", header, body);
        let sig = hmac_sign_b64url(secret, &signing_input);
        let token = format!("{}.{}", signing_input, sig);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, iss_ok) = check_identity_token(&headers, &issuers, Some(secret));
        assert!(id_ok);
        assert!(iss_ok);
    }

    #[test]
    fn test_identity_token_hs_wrong_signature_rejected() {
        // A token signed with the wrong secret must NOT be treated as verified.
        let secret = "s3cret!";
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://auth.jarswaf.local","exp":{}}}"#,
            future_exp
        );
        let header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        let body = base64_url_encode(payload.as_bytes());
        // Sign with the WRONG secret.
        let bad_sig = hmac_sign_b64url("wrong-secret", &format!("{}.{}", header, body));
        let token = format!("{}.{}.{}", header, body, bad_sig);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, _) = check_identity_token(&headers, &issuers, Some(secret));
        assert!(!id_ok);
    }

    #[test]
    fn test_identity_token_no_secret_fail_closed() {
        // Without a configured secret, even a well-formed token is NOT verified.
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://auth.jarswaf.local","exp":{}}}"#,
            future_exp
        );
        let token = make_jwt(&payload); // HS256 header, non-empty sig, but no secret to verify
        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, _) = check_identity_token(&headers, &issuers, "");
        assert!(!id_ok);
    }

    #[test]
    fn test_identity_token_valid() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://auth.jarswaf.local","exp":{}}}"#,
            future_exp
        );
        let token = make_jwt(&payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, iss_ok) = check_identity_token(&headers, &issuers, "");
        // Signature is not verified without a shared_secret (see check_identity_token
        // security note), so identity_verified is held false regardless of structural
        // validity. The issuer is still parsed and trusted if it is in the allowlist.
        assert!(!id_ok);
        assert!(iss_ok);
    }

    #[test]
    fn test_identity_token_expired() {
        let payload = r#"{"sub":"user1","iss":"https://auth.jarswaf.local","exp":1000000}"#;
        let token = make_jwt(payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, _) = check_identity_token(&headers, &issuers, "");
        assert!(!id_ok); // expired = not verified
    }

    #[test]
    fn test_identity_token_untrusted_issuer() {
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://evil.com","exp":{}}}"#,
            future_exp
        );
        let token = make_jwt(&payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, iss_ok) = check_identity_token(&headers, &issuers, "");
        // identity_verified is false without a shared_secret (C-01 fix).
        assert!(!id_ok);
        assert!(!iss_ok); // issuer not in allowed list
    }

    #[test]
    fn test_identity_no_header() {
        let headers = AHashMap::new();
        let (id_ok, iss_ok) = check_identity_token(&headers, &[], "");
        assert!(!id_ok);
        assert!(!iss_ok);
    }

    #[test]
    fn test_identity_token_alg_none_rejected() {
        // C-01 regression guard: a token with alg:none must never be treated as verified,
        // even with a valid-looking payload and non-empty signature. Previously the
        // structure-only check accepted alg:none and set identity_verified=true.
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://auth.jarswaf.local","exp":{}}}"#,
            future_exp
        );
        // header: {"alg":"none","typ":"JWT"}
        let none_header = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0";
        let body = base64_url_encode(payload.as_bytes());
        let token = format!("{}.{}.{}", none_header, body, "sig");

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
        let issuers = vec!["https://auth.jarswaf.local".to_string()];
        let (id_ok, iss_ok) = check_identity_token(&headers, &issuers, "");
        assert!(!id_ok);
        assert!(!iss_ok);
    }

    #[test]
    fn test_identity_token_empty_signature_rejected() {
        // An empty signature part is never a legitimate JWT — reject up front.
        let future_exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;
        let payload = format!(
            r#"{{"sub":"user1","iss":"https://auth.local","exp":{}}}"#,
            future_exp
        );
        let token = format!(
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.{}.",
            base64_url_encode(payload.as_bytes())
        );
        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));
        let (id_ok, _) = check_identity_token(&headers, &[], "");
        assert!(!id_ok);
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
            "",    // no shared secret → fail-closed
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
        let payload = format!(
            r#"{{"sub":"admin","iss":"https://auth.local","exp":{}}}"#,
            future_exp
        );
        let token = make_jwt(&payload);

        let mut headers = AHashMap::new();
        headers.insert("authorization".to_string(), format!("Bearer {}", token));

        let result = check_zero_trust(
            &headers,
            true,
            true,
            true,
            true,
            &[], // no issuers configured = trust all
            0.50,
            "",
            None, // no JWT secret → identity_verified stays false
        );
        assert!(result.is_none()); // should pass (score 0.55 ≥ 0.50 even without identity)
    }
}
