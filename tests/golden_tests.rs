use bytes::Bytes;
use hyper::header::HeaderMap;
use hyper::Method;
use jarswaf::data_bus::context::InspectionContext;
use jarswaf::data_bus::inspectors::sql_injection::SqlInjectionInspector;
use jarswaf::data_bus::inspectors::Inspector;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
struct GoldenVector {
    id: String,
    category: String,
    technique: String,
    target: String,
    raw: String,
    #[serde(default)]
    encoded_variant: Vec<String>,
    expect_action: String,
    #[serde(default)]
    min_rules: Vec<String>,
    #[serde(default)]
    notes: Option<String>,
}

#[tokio::test]
async fn test_all_50_golden_vectors() {
    let yaml_path = "tests/golden/sqli.yaml";
    let content =
        fs::read_to_string(yaml_path).unwrap_or_else(|_| panic!("Failed to read {}", yaml_path));
    let vectors: Vec<GoldenVector> = serde_yaml_ng::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse YAML from {}: {}", yaml_path, e));

    assert_eq!(
        vectors.len(),
        50,
        "Golden vector suite MUST contain exactly 50 vectors, found {}",
        vectors.len()
    );

    let inspector = SqlInjectionInspector::new();
    let client_ip = "192.168.1.100".parse::<IpAddr>().unwrap();

    let mut passed = 0;

    for vec in &vectors {
        let should_block = vec.expect_action == "would_block";

        let mut headers = HeaderMap::new();
        let mut method = Method::GET;
        let mut path = "/".to_string();
        let mut query = String::new();
        let mut body = None;

        match vec.target.as_str() {
            "query" => {
                path = "/search".to_string();
                query = vec.raw.clone();
            }
            "path" => {
                path = vec.raw.clone();
            }
            "header_ua" => {
                headers.insert(
                    "user-agent",
                    vec.raw.parse().unwrap_or_else(|_| "".parse().unwrap()),
                );
            }
            "cookie" => {
                headers.insert(
                    "cookie",
                    vec.raw.parse().unwrap_or_else(|_| "".parse().unwrap()),
                );
            }
            "body_form" => {
                method = Method::POST;
                headers.insert(
                    "content-type",
                    "application/x-www-form-urlencoded".parse().unwrap(),
                );
                body = Some(Bytes::from(vec.raw.clone()));
            }
            "body_json" => {
                method = Method::POST;
                headers.insert("content-type", "application/json".parse().unwrap());
                body = Some(Bytes::from(vec.raw.clone()));
            }
            other => panic!("Unknown target surface: {}", other),
        }

        let mut ctx = InspectionContext::new(
            client_ip,
            method,
            path,
            query,
            headers,
            body,
            "example.com".to_string(),
            8080,
        );

        let result = inspector.inspect(&mut ctx).await;
        let is_blocked = result.verdict.is_some();

        assert_eq!(
            is_blocked, should_block,
            "FAILED Golden Vector [{}] {} (category={}, target={}, min_rules={:?}, variants={:?}): expected expect_action={}, got blocked={} (score={:?}, notes: {:?})",
            vec.id, vec.technique, vec.category, vec.target, vec.min_rules, vec.encoded_variant, vec.expect_action, is_blocked, result.score_delta, vec.notes
        );

        passed += 1;
    }

    println!("✅ All {}/50 golden vectors PASSED successfully!", passed);
}
