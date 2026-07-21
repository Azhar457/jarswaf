//! Advanced Bot Detection - Captive Portal & Active JS Fingerprinting
//!
//! Generates a lightweight HTML+JS payload that forces the client to compute
//! Proof-of-Work (SHA-256) and extract Canvas/WebGL fingerprints before
//! they can access the backend.

use sha2::{Digest, Sha256};
use uuid::Uuid;

pub static CHALLENGE_SECRET: once_cell::sync::Lazy<String> =
    once_cell::sync::Lazy::new(|| Uuid::new_v4().to_string());

/// Generate the JS injection HTML challenge.
pub fn get_challenge_html(client_ip: &str, salt: &str, original_path: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Security Check - jarsWAF</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding: 50px; background-color: #f7f9fa; color: #333; }}
        .card {{ max-width: 500px; margin: 0 auto; padding: 40px; background: white; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); }}
        h1 {{ color: #d93025; font-size: 24px; margin-bottom: 20px; }}
        p {{ font-size: 16px; line-height: 1.5; color: #5f6368; }}
        .spinner {{ border: 4px solid #f3f3f3; border-top: 4px solid #3498db; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 20px auto; }}
        @keyframes spin {{ 0% {{ transform: rotate(0deg); }} 100% {{ transform: rotate(360deg); }} }}
    </style>
</head>
<body>
    <div class="card">
        <h1>Security Check</h1>
        <p>Please wait while we verify your connection. This will only take a moment...</p>
        <div class="spinner"></div>
    </div>
    <script>
        async function sha256(message) {{
            const msgBuffer = new TextEncoder().encode(message);
            const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        }}
        async function getFingerprints() {{
            // 1. Canvas Fingerprint
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125,1,62,20);
            ctx.fillStyle = '#069';
            ctx.fillText('jarsWAF,bot,detect', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('jarsWAF,bot,detect', 4, 17);
            const canvasData = canvas.toDataURL();
            const canvasHash = await sha256(canvasData);

            // 2. WebGL Fingerprint
            let webgl = "unknown";
            try {{
                const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                if (gl) {{
                    const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                    if (debugInfo) {{
                        webgl = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                    }}
                }}
            }} catch(e) {{}}

            return {{ canvas: canvasHash.substring(0, 16), webgl: encodeURIComponent(webgl) }};
        }}

        async function solve() {{
            const ip = "{client_ip}";
            const salt = "{salt}";
            const target_prefix = "000";
            
            // Wait for 3 mouse movements to prove human interaction
            let mouseMoves = 0;
            const mousePromise = new Promise(resolve => {{
                window.addEventListener('mousemove', () => {{
                    mouseMoves++;
                    if (mouseMoves >= 3) resolve();
                }});
                // Fallback for mobile (touch)
                window.addEventListener('touchstart', () => {{
                    mouseMoves += 3;
                    resolve();
                }});
            }});
            await mousePromise;
            
            const fp = await getFingerprints();

            let nonce = 0;
            while (true) {{
                const hash = await sha256(ip + salt + nonce);
                if (hash.startsWith(target_prefix)) {{
                    const original_path = encodeURIComponent("{original_path}");
                    window.location.href = `/jarswaf-challenge-verify?sol=${{nonce}}&fp_c=${{fp.canvas}}&fp_w=${{fp.webgl}}&m=${{mouseMoves}}&r=${{original_path}}`;
                    break;
                }}
                nonce++;
            }}
        }}
        solve();
    </script>
</body>
</html>"#,
        client_ip = client_ip,
        salt = salt,
        original_path = original_path
    )
}

/// Generates the HMAC signature for the verified cookie.
pub fn generate_challenge_signature(timestamp: &str, client_ip: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(b"|");
    hasher.update(client_ip.as_bytes());
    hasher.update(b"|");
    hasher.update(secret.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Checks if the client has already solved the challenge within the last hour.
pub fn is_challenge_cookie_valid(cookie_header: &str, client_ip: &str, secret: &str) -> bool {
    for cookie in cookie_header.split(';') {
        let parts: Vec<&str> = cookie.trim().split('=').collect();
        if parts.len() == 2 && parts[0] == "jarswaf-challenge-token" {
            let token = parts[1];
            let token_parts: Vec<&str> = token.split('.').collect();
            if token_parts.len() == 3 {
                let timestamp_str = token_parts[0];
                let ip = token_parts[1];
                let signature = token_parts[2];

                if ip == client_ip {
                    let expected_sig = generate_challenge_signature(timestamp_str, ip, secret);
                    if expected_sig == signature {
                        if let Ok(ts) = timestamp_str.parse::<i64>() {
                            let now = chrono::Utc::now().timestamp();
                            if now >= ts && now - ts < 3600 {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

/// Validates the WebGL renderer string to block known headless browsers.
pub fn is_headless_renderer(webgl_string: &str) -> bool {
    let s = webgl_string.to_lowercase();
    s.contains("swiftshader")
        || s.contains("llvmpipe")
        || s.contains("mesa offscreen")
        || s.contains("unknown")
}
