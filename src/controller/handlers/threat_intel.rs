use super::super::state::ControllerState;
use crate::types::is_local_ip;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};

#[derive(serde::Serialize)]
pub struct ThreatEvent {
    pub ip: String,
    pub lat: f64,
    pub lng: f64,
    pub rule_id: String,
    pub timestamp: String,
    pub magnitude: f64,
    pub action: String,
    pub country: String,
}

pub async fn get_blocklist_handler(State(state): State<ControllerState>) -> impl IntoResponse {
    let db_path = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)?;
        let since = chrono::Utc::now() - chrono::Duration::minutes(5);
        let since_str = since.to_rfc3339();
        let mut stmt = conn.prepare(
            "SELECT client_ip FROM request_log 
             WHERE action = 'BLOCK' AND timestamp > ?1 
             GROUP BY client_ip 
             HAVING count() >= 5",
        )?;
        let rows = stmt.query_map([since_str], |row| {
            let ip: String = row.get(0)?;
            Ok(ip)
        })?;
        let mut ips = Vec::new();
        for ip in rows.flatten() {
            if let Ok(parsed_ip) = ip.parse::<std::net::IpAddr>() {
                if !is_local_ip(&parsed_ip) {
                    ips.push(ip);
                }
            }
        }
        Ok::<_, rusqlite::Error>(ips)
    })
    .await;

    match res {
        Ok(Ok(ips)) => (StatusCode::OK, Json(ips)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Vec::<String>::new()),
        )
            .into_response(),
    }
}

pub fn get_country_and_coords_for_ip(ip: &str) -> (&'static str, f64, f64) {
    let mut hash = 5381u32;
    for c in ip.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(c as u32);
    }

    let countries = [
        ("ID", -0.7893, 113.9213),  // Indonesia
        ("US", 37.0902, -95.7129),  // United States
        ("CN", 35.8617, 104.1954),  // China
        ("SG", 1.3521, 103.8198),   // Singapore
        ("JP", 36.2048, 138.2529),  // Japan
        ("GB", 55.3781, -3.4360),   // United Kingdom
        ("DE", 51.1657, 10.4515),   // Germany
        ("FR", 46.2276, 2.2137),    // France
        ("AU", -25.2744, 133.7751), // Australia
        ("NL", 52.1326, 5.2913),    // Netherlands
    ];

    let idx = (hash as usize) % countries.len();
    countries[idx]
}

pub async fn get_threat_intel_events_handler(
    State(state): State<ControllerState>,
) -> impl IntoResponse {
    let db_path = state.db_path.clone();
    let res = tokio::task::spawn_blocking(move || {
        let conn = rusqlite::Connection::open(&db_path)?;
        let mut stmt = conn.prepare(
            "SELECT timestamp, client_ip, rule_id, action FROM request_log 
             ORDER BY timestamp DESC LIMIT 100",
        )?;
        let rows = stmt.query_map([], |row| {
            let timestamp: String = row.get(0)?;
            let client_ip: String = row.get(1)?;
            let rule_id: String = row.get(2)?;
            let action: String = row.get(3)?;
            Ok((timestamp, client_ip, rule_id, action))
        })?;
        let mut events = Vec::new();
        for (ts, ip, rule, action) in rows.flatten() {
            let (country, lat, lng) = get_country_and_coords_for_ip(&ip);
            events.push(ThreatEvent {
                ip,
                lat,
                lng,
                rule_id: rule,
                timestamp: ts,
                magnitude: 0.1,
                action,
                country: country.to_string(),
            });
        }
        Ok::<_, rusqlite::Error>(events)
    })
    .await;

    match res {
        Ok(Ok(events)) => (StatusCode::OK, Json(events)).into_response(),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(Vec::<ThreatEvent>::new()),
        )
            .into_response(),
    }
}
