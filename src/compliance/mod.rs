use crate::logging::WafLogEntry;
use serde::{Deserialize, Serialize};

/// Represents an Elastic Common Schema (ECS) compatible compliance event
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ComplianceEvent {
    #[serde(rename = "@timestamp")]
    pub timestamp: String,

    pub event: EventMeta,
    pub source: SourceMeta,
    pub http: HttpMeta,
    pub rule: RuleMeta,

    /// List of compliance tags, e.g., ["PCI-DSS-Req-10", "HIPAA-Audit"]
    pub compliance_tags: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EventMeta {
    pub action: String,   // "allowed", "blocked", "rate_limited"
    pub category: String, // "web", "network", "api"
    pub reason: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SourceMeta {
    pub ip: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HttpMeta {
    pub request: HttpRequestMeta,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct HttpRequestMeta {
    pub method: String,
    pub url: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct RuleMeta {
    pub id: String,
}

/// Maps a standard WAF log entry into a structured ECS compliance event
pub fn map_to_compliance_event(log: &WafLogEntry) -> ComplianceEvent {
    // Map WAF action to ECS action
    let ecs_action = match log.action.as_str() {
        "BLOCK" | "DROP" => "blocked",
        "RATE_LIMIT" => "rate_limited",
        "PASS" | "ALLOW" => "allowed",
        _ => "unknown",
    };

    // Determine compliance tags based on rule_id and action
    let mut tags = vec!["PCI-DSS-Req-10".to_string()]; // Req 10 is logging and monitoring

    // If it's a block related to SQLi or XSS, it fulfills Req 6 (Secure systems against known attacks)
    if log.rule_id.contains("XSS") {
        tags.push("HIPAA-164.312(b)".to_string());
        tags.push("NIST-PR.PT-4".to_string());
        tags.push("PCI-DSS-Req-6".to_string());
    } else if log.rule_id.contains("SQLI") {
        tags.push("ISO-27001-A.14.2.1".to_string());
        tags.push("PCI-DSS-Req-6".to_string());
    } else if log.rule_id.contains("LFI") || log.rule_id.contains("RFI") {
        tags.push("CCPA-Security-Requirement".to_string());
    } else if log.rule_id.contains("XDP") {
        tags.push("PCI-DSS-Req-6".to_string());
    }

    // If it's related to API or JWT, might be related to Req 4 (Protect data in transit) or generic access control
    if log.rule_id.contains("JWT") || log.rule_id.contains("API") {
        tags.push("PCI-DSS-Req-4".to_string());
    }

    ComplianceEvent {
        timestamp: log.timestamp.clone(),
        event: EventMeta {
            action: ecs_action.to_string(),
            category: "web".to_string(),
            reason: log.reason.clone(),
        },
        source: SourceMeta {
            ip: log.client_ip.clone(),
        },
        http: HttpMeta {
            request: HttpRequestMeta {
                method: log.method.clone(),
                url: log.path.clone(),
            },
        },
        rule: RuleMeta {
            id: log.rule_id.clone(),
        },
        compliance_tags: tags,
    }
}
