use ahash::AHashMap;
use tracing::warn;

/// Checks for WAF evasion techniques such as HTTP Request Smuggling and Path Traversal Bypass.
/// Returns `Some((reason, detail))` if evasion is detected, otherwise `None`.
pub fn check_evasion(path: &str, headers: &AHashMap<String, String>) -> Option<(&'static str, String)> {
    // 1. HTTP Request Smuggling Checks
    if check_smuggling(headers) {
        return Some((
            "EVASION-SMUGGLING",
            "HTTP Request Smuggling evasion detected (CL.TE or duplicate headers)".to_string(),
        ));
    }

    // 2. Path Traversal & Encoding Bypass Checks
    if check_encoding_bypass(path) {
        return Some((
            "EVASION-PATH",
            "Path Traversal encoding evasion detected (Double encoding/Unicode)".to_string(),
        ));
    }

    None
}

/// Detects HTTP Request Smuggling anomalies.
fn check_smuggling(headers: &AHashMap<String, String>) -> bool {
    let has_cl = headers.contains_key("content-length");
    let has_te = headers.contains_key("transfer-encoding");

    // CL.TE or TE.CL attack vector: both headers present
    if has_cl && has_te {
        warn!("Request Smuggling detected: Both Content-Length and Transfer-Encoding present");
        return true;
    }

    // Check for obfuscated Transfer-Encoding
    if has_te {
        if let Some(v_str) = headers.get("transfer-encoding") {
            // If it's something weird like 'chunked, chunked' or contains spaces 'chunked '
            if v_str.contains("  ") || v_str.to_lowercase() != *v_str {
                warn!("Request Smuggling detected: Obfuscated Transfer-Encoding");
                return true;
            }
        }
    }

    false
}

/// Detects double encoding and unicode bypasses for path traversal.
fn check_encoding_bypass(raw_url: &str) -> bool {
    // Double encoded dot %252e, double encoded slash %252f, %255c
    // Unicode traversal: %c0%af, %c1%9c, %u2215, %u002f
    let lower_url = raw_url.to_lowercase();
    
    if lower_url.contains("%252e") || lower_url.contains("%252f") || lower_url.contains("%255c") {
        warn!("Evasion detected: Double URL encoding");
        return true;
    }

    if lower_url.contains("%c0%af") || lower_url.contains("%c1%9c") || lower_url.contains("%u2215") {
        warn!("Evasion detected: Unicode overlong encoding for path traversal");
        return true;
    }

    // Self-referencing weirdness (/// or /././.)
    if lower_url.contains("///") || lower_url.contains("/././.") {
        warn!("Evasion detected: Path obfuscation");
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_smuggling_cl_te() {
        let mut headers = AHashMap::new();
        headers.insert("content-length".to_string(), "100".to_string());
        headers.insert("transfer-encoding".to_string(), "chunked".to_string());
        
        assert!(check_evasion("/", &headers).is_some());
    }

    #[test]
    fn test_double_encoding() {
        let headers = AHashMap::new();
        assert!(check_evasion("/?path=%252e%252e%252fetc%252fpasswd", &headers).is_some());
    }
}

