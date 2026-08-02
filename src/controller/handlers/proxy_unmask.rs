use crate::rules::proxy_unmask::{calculate_proxy_risk_score, ProxyTestResults};
use axum::{http::header, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize)]
pub struct WebRtcPayload {
    pub client_ip: String,
    pub ice_candidates: Vec<String>,
    pub timezone: Option<String>,
    pub accept_language: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProxyUnmaskResponse {
    pub status: String,
    pub risk_score: u32,
    pub verdict: String,
    pub client_ip: String,
    pub unmasked_ip: Option<String>,
    pub is_proxy_detected: bool,
}

/// Serve JS challenge harvester script for client-side WebRTC ICE discovery.
pub async fn get_webrtc_challenge_js() -> impl IntoResponse {
    let js_script = r#"
/* WebRTC ICE Candidate Harvester */
(function() {
    function harvestICE(callback) {
        var pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
        pc.createDataChannel("");
        pc.createOffer().then(function(offer) { return pc.setLocalDescription(offer); });
        
        var candidates = [];
        pc.onicecandidate = function(event) {
            if (!event || !event.candidate) {
                callback(candidates);
                return;
            }
            var cand = event.candidate.candidate;
            var ipMatch = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7})/.exec(cand);
            if (ipMatch && candidates.indexOf(ipMatch[1]) === -1) {
                candidates.push(ipMatch[1]);
            }
        };
        setTimeout(function() { callback(candidates); }, 1500);
    }

    harvestICE(function(candidates) {
        fetch('/api/v1/proxy-unmask/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                client_ip: window.location.hostname,
                ice_candidates: candidates,
                timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
                accept_language: navigator.language
            })
        }).catch(function(e) { console.error('Proxy verify err', e); });
    });
})();
"#;

    (
        [(header::CONTENT_TYPE, "application/javascript")],
        js_script,
    )
}

/// Process WebRTC candidates & client signals to compute Proxy Risk Score & unmask real IP.
pub async fn verify_proxy_unmask_handler(Json(payload): Json<WebRtcPayload>) -> impl IntoResponse {
    let mut leaked_real_ip = None;
    let mut webrtc_test = false;

    for cand in &payload.ice_candidates {
        if cand != &payload.client_ip
            && !cand.starts_with("127.")
            && !cand.starts_with("10.")
            && !cand.starts_with("192.168.")
        {
            webrtc_test = true;
            leaked_real_ip = Some(cand.clone());
            break;
        }
    }

    let results = ProxyTestResults {
        header_test: false,
        rdns_test: payload.client_ip.contains("datacenter") || payload.client_ip.contains("vps"),
        wimia_test: webrtc_test,
        location_test: payload
            .timezone
            .as_deref()
            .is_some_and(|tz| tz.contains("Asia") && payload.client_ip.starts_with("37.")),
        webrtc_test,
        ja4_test: false,
        leaked_real_ip,
    };

    let report = calculate_proxy_risk_score(&payload.client_ip, &results);

    Json(ProxyUnmaskResponse {
        status: "success".to_string(),
        risk_score: report.risk_score,
        verdict: report.verdict.to_string(),
        client_ip: report.client_ip,
        unmasked_ip: report.unmasked_ip,
        is_proxy_detected: report.risk_score > 50,
    })
}
