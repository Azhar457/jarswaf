//! Webhook / SIEM Alerting — fire-and-forget HTTP POST to external endpoints
//! when blocked requests or reputation events occur.

use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::time::{Duration, Instant};

/// Cooldown tracker: rule_id → last fired Instant
static WEBHOOK_COOLDOWN: Lazy<DashMap<String, Instant>> = Lazy::new(DashMap::new);

/// Fire a webhook alert if the cooldown for this `rule_id` has elapsed.
///
/// Returns immediately (fire-and-forget via tokio::spawn).
pub fn maybe_fire_webhook(
    webhooks: &[crate::config::WebhookConfig],
    rule_id: &str,
    severity: &str,
    client_ip: &str,
    method: &str,
    path: &str,
    reason: &str,
) {
    let sev_order = |s: &str| -> u8 {
        match s.to_lowercase().as_str() {
            "low" => 1,
            "medium" => 2,
            "high" => 3,
            "critical" => 4,
            _ => 0,
        }
    };
    let event_sev = sev_order(severity);

    for wh in webhooks {
        if sev_order(&wh.min_severity) > event_sev {
            continue;
        }

        // Cooldown check
        let cooldown_key = format!("{}:{}", wh.name, rule_id);
        if let Some(last) = WEBHOOK_COOLDOWN.get(&cooldown_key) {
            if last.elapsed() < Duration::from_secs(wh.cooldown_secs) {
                continue;
            }
        }
        WEBHOOK_COOLDOWN.insert(cooldown_key, Instant::now());

        // Fire (fire-and-forget)
        let url = wh.url.clone();
        let secret = wh.secret.clone();
        let payload = serde_json::json!({
            "event": "jarsWAF Alert",
            "rule_id": rule_id,
            "severity": severity,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "reason": reason,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap_or_default();

            let mut req = client.post(&url).json(&payload);
            if let Some(ref token) = secret {
                req = req.header("Authorization", format!("Bearer {}", token));
            }

            match req.send().await {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        tracing::warn!("Webhook {} returned HTTP {}", url, resp.status());
                    }
                }
                Err(e) => {
                    tracing::debug!("Webhook {} failed: {}", url, e);
                }
            }
        });
    }
}
