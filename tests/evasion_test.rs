use hyper::header::HeaderMap;
use hyper::Method;
use jarswaf::data_bus::context::InspectionContext;
use jarswaf::data_bus::inspectors::sql_injection::SqlInjectionInspector;
use jarswaf::data_bus::inspectors::Inspector;
use serde::Deserialize;
use std::fs;
use std::net::IpAddr;

#[derive(Debug, Deserialize)]
struct EvasionTestCase {
    id: String,
    category: String,
    technique: String,
    payload: String,
    expect_block: bool,
    notes: Option<String>,
}

#[tokio::test]
async fn test_evasion_suite_parser_differential() {
    let yaml_path = "tests/evasion/sqli/parser_differential.yaml";
    let content =
        fs::read_to_string(yaml_path).unwrap_or_else(|_| panic!("Failed to read {}", yaml_path));
    let test_cases: Vec<EvasionTestCase> = serde_yaml_ng::from_str(&content)
        .unwrap_or_else(|e| panic!("Failed to parse YAML from {}: {}", yaml_path, e));

    let inspector = SqlInjectionInspector::new();

    for case in test_cases {
        println!(
            "Running Evasion Test [{}]: {} ({})",
            case.id, case.technique, case.category
        );

        let path = format!("/search?q={}", case.payload);
        let mut ctx = InspectionContext::new(
            "127.0.0.1".parse::<IpAddr>().unwrap(),
            Method::GET,
            path,
            String::new(),
            HeaderMap::new(),
            None,
            "example.com".to_string(),
            8080,
        );

        let result = inspector.inspect(&mut ctx).await;
        let is_blocked = result.verdict.is_some();

        assert_eq!(
            is_blocked, case.expect_block,
            "Failed evasion case [{} - {}]: expected block={}, got blocked={} (notes: {:?})",
            case.id, case.technique, case.expect_block, is_blocked, case.notes
        );
    }
}
