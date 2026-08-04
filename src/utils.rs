// ─── Shared utilities ───────────────────────────────────────────────────────
//
// Single source of truth for helpers that were previously duplicated across
// rule modules (base64url decoding, JSON extraction, UTF-8 safe truncation).
// Keep these small, dependency-free, and side-effect-free.

use base64::Engine;

/// Base64url decode (URL-safe alphabet, no padding).
///
/// Accepts both URL-safe (`-_`) and standard (`+/`) alphabets via fallback for
/// backwards compatibility with tokens issued before the alphabet tightened.
pub fn base64_url_decode(input: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(input))
        .map_err(|e| format!("invalid base64url: {e}"))
}

/// UTF-8 safe slice: never panics on a multi-byte char boundary.
/// Returns the longest prefix of `s` that is ≤ `max_bytes` and ends at a char
/// boundary. If `s.len() <= max_bytes`, returns the original slice.
pub fn safe_truncate(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while !s.is_char_boundary(end) && end > 0 {
        end -= 1;
    }
    &s[..end]
}

/// Extract a numeric value for a key from a minimal JSON string (no serde).
/// Used by the JWT zero-trust path where we already have a parsed payload
/// string and want to avoid pulling in a JSON dep.
pub fn extract_json_number(json: &str, key: &str) -> Option<i64> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    let rest = rest.trim_start();
    let rest = rest.strip_prefix(':')?;
    let rest = rest.trim_start();
    let end = rest
        .find(|c: char| !c.is_ascii_digit() && c != '-')
        .unwrap_or(rest.len());
    rest[..end].parse::<i64>().ok()
}

/// Extract a string value for a key from a minimal JSON string (no serde).
/// Returns the raw, unescaped string content (no \" unescaping).
pub fn extract_json_string(json: &str, key: &str) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_url_decode_roundtrip() {
        let enc = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"hello");
        let dec = base64_url_decode(&enc).unwrap();
        assert_eq!(dec, b"hello");
    }

    #[test]
    fn base64_url_decode_accepts_standard_alphabet() {
        // Standard alphabet (with + and /) is accepted via fallback.
        let enc = base64::engine::general_purpose::STANDARD_NO_PAD.encode(b"hello");
        let dec = base64_url_decode(&enc).unwrap();
        assert_eq!(dec, b"hello");
    }

    #[test]
    fn safe_truncate_respects_char_boundary() {
        let s = "abc🙂def"; // 4-byte emoji at offset 3
                            // Truncate at byte 5 — would split emoji if no boundary check.
        let truncated = safe_truncate(s, 5);
        assert!(s.is_char_boundary(truncated.len()));
        // Truncate within ascii prefix
        let truncated = safe_truncate(s, 4);
        assert_eq!(truncated, "abc");
    }

    #[test]
    fn extract_json_string_parses_simple_value() {
        let json = r#"{"iss":"https://x","exp":123}"#;
        assert_eq!(
            extract_json_string(json, "iss").as_deref(),
            Some("https://x")
        );
    }

    #[test]
    fn extract_json_number_parses_value() {
        let json = r#"{"iss":"x","exp":1234567890}"#;
        assert_eq!(extract_json_number(json, "exp"), Some(1234567890));
    }
}
