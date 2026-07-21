//! DLP (Data Loss Prevention) — scan response bodies for sensitive data.
//!
//! Checks for credit cards, JWT tokens, cloud secrets, and custom patterns.
//! Returns a list of findings; caller decides action (log / block).

use once_cell::sync::Lazy;
use regex::Regex;

/// A single DLP finding.
#[derive(Debug, Clone)]
pub struct DlpFinding {
    pub rule: &'static str,
    pub description: String,
    pub sample: String,
}

// ── Built-in pattern regexes ────────────────────────────────────────────────

static CC_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Generic credit card: 13-19 digits, optionally grouped by space/dash.
    // We do NOT validate Luhn here (that's O(n) per match); false positives
    // are acceptable for "log" mode.  If action=="block" the caller may refine.
    Regex::new(r"\b(?:\d[ -]*?){13,19}\b").unwrap()
});

static JWT_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?i)\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b").unwrap()
});

static CLOUD_SECRETS_REGEX: Lazy<Regex> = Lazy::new(|| {
    // AWS access key, AWS secret, Azure key, GCP service-account key, GitHub token, Slack token
    Regex::new(
        r#"(?i)\b(AKIA[0-9A-Z]{16}|(?:aws|amazon).{0,20}secret.{0,20}['"]?[A-Za-z0-9/+=]{40}|azure.{0,20}(?:key|secret).{0,20}['"]?[A-Za-z0-9_/=]{44}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9]{10,})\b"#,
    )
    .unwrap()
});

static PASSWORD_REGEX: Lazy<Regex> = Lazy::new(|| {
    // Heuristic: "password" or "secret" followed by a value-like token.
    // High false-positive rate; only meaningful in "password_in_body" mode.
    Regex::new(r#"(?i)"(?:password|passwd|secret|token|api_key)"\s*[:=]\s*"[^"]{6,}"#).unwrap()
});

static EMAIL_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b").unwrap());

// ── Scanner ─────────────────────────────────────────────────────────────────

/// Run all enabled DLP checks against `body`.  Returns findings.
pub fn scan_body(body: &str, cfg: &crate::config::DlpConfig) -> Vec<DlpFinding> {
    if !cfg.enabled || body.len() > 10 * 1024 * 1024 {
        return Vec::new();
    }

    // Quick allow-list check: if body contains any allowlisted string → skip
    for item in &cfg.allowlist {
        if body.contains(item) {
            return Vec::new();
        }
    }

    let mut findings = Vec::new();

    if cfg.credit_card {
        if let Some(m) = CC_REGEX.find(body) {
            let sample = mask(m.as_str(), 4);
            findings.push(DlpFinding {
                rule: "DLP-CC",
                description: "credit card number".into(),
                sample,
            });
        }
    }

    if cfg.jwt_token {
        if let Some(m) = JWT_REGEX.find(body) {
            findings.push(DlpFinding {
                rule: "DLP-JWT",
                description: "JWT / Bearer token".into(),
                sample: format!("{}…", &m.as_str()[..30.min(m.len())]),
            });
        }
    }

    if cfg.cloud_secrets {
        if let Some(m) = CLOUD_SECRETS_REGEX.find(body) {
            findings.push(DlpFinding {
                rule: "DLP-CLOUD",
                description: "cloud provider secret key".into(),
                sample: format!("{}…", &m.as_str()[..30.min(m.len())]),
            });
        }
    }

    if cfg.password_in_body {
        if let Some(m) = PASSWORD_REGEX.find(body) {
            findings.push(DlpFinding {
                rule: "DLP-PASS",
                description: "password / secret in response body".into(),
                sample: format!("{}…", &m.as_str()[..40.min(m.len())]),
            });
        }
    }

    if cfg.email {
        if let Some(m) = EMAIL_REGEX.find(body) {
            findings.push(DlpFinding {
                rule: "DLP-EMAIL",
                description: "email address in response body".into(),
                sample: m.as_str().to_string(),
            });
        }
    }

    // Custom patterns
    for (name, pattern) in &cfg.custom_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(m) = re.find(body) {
                findings.push(DlpFinding {
                    rule: "DLP-CUSTOM",
                    description: format!(r#"custom pattern "{}""#, name),
                    sample: format!("{}…", &m.as_str()[..40.min(m.len())]),
                });
            }
        }
    }

    findings
}

fn mask(s: &str, show: usize) -> String {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() <= show + 4 {
        return digits;
    }
    let prefix = &digits[..show];
    let suffix = &digits[digits.len() - 4..];
    format!("{}…{}", prefix, suffix)
}

/// Mask all sensitive patterns in `body` with `[REDACTED]`.
pub fn mask_body(body: &str, cfg: &crate::config::DlpConfig) -> String {
    if !cfg.enabled || body.len() > cfg.response_body_limit {
        return body.to_string();
    }

    // Quick allow-list check: if body contains any allowlisted string → skip
    for item in &cfg.allowlist {
        if body.contains(item) {
            return body.to_string();
        }
    }

    let mut result = body.to_string();

    if cfg.credit_card {
        result = CC_REGEX.replace_all(&result, "[REDACTED-CC]").into_owned();
    }

    if cfg.jwt_token {
        result = JWT_REGEX.replace_all(&result, "[REDACTED-JWT]").into_owned();
    }

    if cfg.cloud_secrets {
        result = CLOUD_SECRETS_REGEX.replace_all(&result, "[REDACTED-SECRET]").into_owned();
    }

    if cfg.password_in_body {
        result = PASSWORD_REGEX.replace_all(&result, |caps: &regex::Captures| {
            let matched = &caps[0];
            if let Some(pos) = matched.find(':').or_else(|| matched.find('=')) {
                let key_part = &matched[..=pos];
                format!("{} \"[REDACTED-PASSWORD]\"", key_part)
            } else {
                "[REDACTED-PASSWORD]".to_string()
            }
        }).into_owned();
    }

    if cfg.email {
        result = EMAIL_REGEX.replace_all(&result, "[REDACTED-EMAIL]").into_owned();
    }

    // Custom patterns
    for (name, pattern) in &cfg.custom_patterns {
        if let Ok(re) = Regex::new(pattern) {
            result = re.replace_all(&result, |_: &regex::Captures| {
                format!("[REDACTED-CUSTOM-{}]", name)
            }).into_owned();
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DlpConfig;

    fn test_dlp_config() -> DlpConfig {
        DlpConfig {
            enabled: true,
            action: "log".to_string(),
            credit_card: true,
            jwt_token: true,
            cloud_secrets: true,
            password_in_body: true,
            email: true,
            allowlist: vec![],
            custom_patterns: ahash::AHashMap::new(),
            response_body_limit: 1024 * 1024,
        }
    }

    #[test]
    fn test_scan_and_mask_dlp() {
        let mut cfg = test_dlp_config();
        
        let cc_body = "My visa is 4111 1111 1111 1111.";
        let findings = scan_body(cc_body, &cfg);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "DLP-CC");
        
        let masked = mask_body(cc_body, &cfg);
        assert_eq!(masked, "My visa is [REDACTED-CC].");

        let email_body = "Send info to test@example.com please.";
        let masked_email = mask_body(email_body, &cfg);
        assert_eq!(masked_email, "Send info to [REDACTED-EMAIL] please.");

        // Test allowlist bypass
        cfg.allowlist.push("test@example.com".to_string());
        let masked_allowlist = mask_body(email_body, &cfg);
        assert_eq!(masked_allowlist, email_body);
    }
}

