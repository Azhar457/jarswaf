use reqwest::Client;
use std::time::{Duration, Instant};

const PAYLOADS: &[(&str, &str)] = &[
    ("SQLi", "' OR '1'='1"),
    ("SQLi", "UNION SELECT null, version()"),
    ("XSS", "<script>alert(1)</script>"),
    ("XSS", "\"><img src=x onerror=prompt(1)>"),
    ("Path Traversal", "../../../../etc/passwd"),
    ("Path Traversal", "..%2F..%2F..%2Fetc%2Fpasswd"),
    ("LFI", "file:///etc/hosts"),
    ("RCE", "; cat /etc/shadow"),
    ("RCE", "`ping -c 1 8.8.8.8`"),
];

pub async fn run_redteam(target: &str) {
    println!("🛡️  jarsWAF Automated Red Team / Security Testing Lab");
    println!("Targeting: {}", target);
    println!("--------------------------------------------------");

    let client = Client::builder()
        .timeout(Duration::from_secs(5))
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();

    let mut blocked = 0;
    let mut bypassed = 0;
    let mut failed = 0;
    let mut total_ms = 0;

    for (attack_type, payload) in PAYLOADS {
        let url = format!("{}/?q={}", target, urlencoding::encode(payload));
        let start = Instant::now();

        match client.get(&url).send().await {
            Ok(resp) => {
                let status = resp.status();
                let elapsed = start.elapsed().as_millis();
                total_ms += elapsed;

                if status == 403 {
                    println!(
                        "✅ [{}] BLOCKED ({}ms) | Payload: {}",
                        attack_type, elapsed, payload
                    );
                    blocked += 1;
                } else {
                    println!(
                        "❌ [{}] BYPASSED (Status {}) | Payload: {}",
                        attack_type, status, payload
                    );
                    bypassed += 1;
                }
            }
            Err(e) => {
                println!("⚠️  [{}] FAILED to connect: {}", attack_type, e);
                failed += 1;
            }
        }
    }

    println!("--------------------------------------------------");
    println!("🧪 Testing API Security (JWT & GraphQL)");

    // 1. JWT Test
    let start = Instant::now();
    match client
        .get(&format!("{}/api/test", target))
        .header("Authorization", "Bearer invalid_token_without_dots")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let elapsed = start.elapsed().as_millis();
            total_ms += elapsed;
            if status == 401 {
                println!("✅ [JWT] BLOCKED ({}ms) | Invalid Structure", elapsed);
                blocked += 1;
            } else {
                println!("❌ [JWT] BYPASSED (Status {}) | Invalid Structure", status);
                bypassed += 1;
            }
        }
        Err(e) => {
            println!("⚠️  [JWT] FAILED to connect: {}", e);
            failed += 1;
        }
    }

    // 2. GraphQL Test
    let start = Instant::now();
    let nested_gql = r#"{"query": "{ user { posts { comments { author { id } } } } }"}"#;
    match client
        .post(&format!("{}/api/graphql", target))
        .body(nested_gql)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let elapsed = start.elapsed().as_millis();
            total_ms += elapsed;
            if status == 400 {
                println!(
                    "✅ [GraphQL] BLOCKED ({}ms) | Depth Limit Exceeded",
                    elapsed
                );
                blocked += 1;
            } else {
                println!(
                    "❌ [GraphQL] BYPASSED (Status {}) | Depth Limit Exceeded",
                    status
                );
                bypassed += 1;
            }
        }
        Err(e) => {
            println!("⚠️  [GraphQL] FAILED to connect: {}", e);
            failed += 1;
        }
    }

    let total_tests = PAYLOADS.len() + 2;
    println!("--------------------------------------------------");
    println!("📊 Red Team Results:");
    println!("Total Payloads: {}", total_tests);
    println!("Blocked (CIA Preserved): {}", blocked);
    println!("Bypassed (Risk!): {}", bypassed);
    println!("Connection Failed: {}", failed);
    if blocked + bypassed > 0 {
        println!("Avg Latency: {}ms", total_ms / (blocked + bypassed) as u128);
    }

    if bypassed > 0 {
        std::process::exit(1);
    }
}
