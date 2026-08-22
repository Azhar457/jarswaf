//! Advanced Bot Detection - Captive Portal & Active JS Fingerprinting
//!
//! Generates a lightweight HTML+JS payload that forces the client to compute
//! Proof-of-Work (SHA-256) and extract Canvas/WebGL fingerprints before
//! they can access the backend.

use sha2::{Digest, Sha256};
use uuid::Uuid;

pub static CHALLENGE_SECRET: once_cell::sync::Lazy<String> = once_cell::sync::Lazy::new(|| {
    std::env::var("JARSWAF_BOT_SECRET").unwrap_or_else(|_| Uuid::new_v4().to_string())
});

/// Escape a string for safe embedding inside a JavaScript double-quoted string literal,
/// and neutralize `</script>` so an attacker-controlled value cannot break out of the
/// inline `<script>` block. Returns a value safe to interpolate as `"...{escaped}..."`.
/// `ponytail:` only what's needed for inline JS-in-HTML; for JSON use serde_json instead.
fn js_str_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 8);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\'' => out.push_str("\\'"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '/' => out.push_str("\\/"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            other => out.push(other),
        }
    }
    out
}

/// Generate the JS injection HTML challenge.
pub fn get_challenge_html(client_ip: &str, salt: &str, original_path: &str) -> String {
    // Escape all interpolated values before embedding them in inline JS string literals to
    // prevent stored XSS via the challenge page. original_path is attacker-controlled (the
    // inbound request path/query); client_ip/salt are server-derived but escaped too as
    // defense-in-depth.
    let client_ip_js = js_str_escape(client_ip);
    let salt_js = js_str_escape(salt);
    let original_path_js = js_str_escape(original_path);
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
            if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {{
                try {{
                    const msgBuffer = new TextEncoder().encode(message);
                    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
                    const hashArray = Array.from(new Uint8Array(hashBuffer));
                    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
                }} catch(e) {{}}
            }}
            var K = [
                0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef4a9f7, 0xc67178f2
            ];
            var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
            var bytes = new TextEncoder().encode(message);
            var l = bytes.length;
            var w = new Uint8Array(((l + 9 + 63) >> 6) << 6);
            w.set(bytes);
            w[l] = 0x80;
            var view = new DataView(w.buffer);
            view.setUint32(w.length - 4, l * 8, false);
            for (var i = 0; i < w.length; i += 64) {{
                var W = new Uint32Array(64);
                for (var j = 0; j < 16; j++) W[j] = view.getUint32(i + j * 4, false);
                for (var j = 16; j < 64; j++) {{
                    var s0 = ((W[j-15]>>>7)|(W[j-15]<<25)) ^ ((W[j-15]>>>18)|(W[j-15]<<14)) ^ (W[j-15]>>>3);
                    var s1 = ((W[j-2]>>>17)|(W[j-2]<<15)) ^ ((W[j-2]>>>19)|(W[j-2]<<13)) ^ (W[j-2]>>>10);
                    W[j] = (W[j-16] + s0 + W[j-7] + s1) | 0;
                }}
                var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
                for (var j = 0; j < 64; j++) {{
                    var S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
                    var ch = (e & f) ^ ((~e) & g);
                    var temp1 = (h + S1 + ch + K[j] + W[j]) | 0;
                    var S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
                    var maj = (a & b) ^ (a & c) ^ (b & c);
                    var temp2 = (S0 + maj) | 0;
                    h = g; g = f; f = e; e = (d + temp1) | 0; d = c; c = b; b = a; a = (temp1 + temp2) | 0;
                }}
                H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
                H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
            }}
            return H.map(function(v) {{ return ('0000000' + (v >>> 0).toString(16)).slice(-8); }}).join('');
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

            // 3. Headless Automation Inspection (Playwright / Puppeteer / Selenium)
            let isHeadless = 0;
            try {{
                if (navigator.webdriver) isHeadless = 1;
                if (!navigator.languages || navigator.languages.length === 0) isHeadless = 1;
                if (window.outerWidth === 0 && window.outerHeight === 0) isHeadless = 1;
                if (navigator.userAgent.indexOf("Chrome") !== -1 && !window.chrome) isHeadless = 1;
            }} catch(e) {{}}

            return {{ canvas: canvasHash.substring(0, 16), webgl: encodeURIComponent(webgl), headless: isHeadless }};
        }}

        async function solve() {{
            const ip = "{client_ip}";
            const salt = "{salt}";
            const target_prefix = "000";
            
            // Wait for mouse movement or auto-resolve after 800ms
            let mouseMoves = 0;
            const mousePromise = new Promise(resolve => {{
                const timer = setTimeout(() => resolve(), 800);
                window.addEventListener('mousemove', () => {{
                    mouseMoves++;
                    if (mouseMoves >= 2) {{ clearTimeout(timer); resolve(); }}
                }});
                window.addEventListener('touchstart', () => {{
                    mouseMoves += 2;
                    clearTimeout(timer);
                    resolve();
                }});
            }});
            await mousePromise;
            
            const fp = await getFingerprints();
            if (fp.headless === 1) {{
                // Block or fail headless automation
                document.body.innerHTML = '<h1>Access Denied</h1><p>Automated browser framework detected (Playwright/Puppeteer).</p>';
                return;
            }}

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
        client_ip = client_ip_js,
        salt = salt_js,
        original_path = original_path_js
    )
}

/// Generates the HMAC signature for the verified cookie using ARX Construction
/// (Addition, Bitwise Rotation, XOR + Stateful Key Evolution) for ultra-hard anti-reversing.
pub fn generate_challenge_signature(timestamp: &str, client_ip: &str, secret: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(timestamp.as_bytes());
    hasher.update(b"|");
    hasher.update(client_ip.as_bytes());
    hasher.update(b"|");

    // ARX (Addition, Rotate, XOR) Cryptographic Transformation with Stateful Key Evolution
    let mut stateful_key: u8 = 0x5A;
    let obfuscated_secret: Vec<u8> = secret
        .bytes()
        .enumerate()
        .map(|(idx, byte)| {
            // 1. Stateful Key Evolution (LFSR/Rolling key per step)
            stateful_key = stateful_key.wrapping_mul(33).wrapping_add(idx as u8);

            // 2. Non-Linear Addition (Modulo 256 ADD)
            let add_step = byte.wrapping_add(stateful_key);

            // 3. Bitwise Rotation (ROL 3 bits) for bit diffusion
            let rot_step = add_step.rotate_left(3);

            // 4. XOR Combination (Linear XOR layer with evolved key)
            rot_step ^ (stateful_key ^ 0xA5)
        })
        .collect();

    hasher.update(&obfuscated_secret);
    format!("{:x}", hasher.finalize())
}

/// Checks if the client has already solved the challenge within the last hour.
pub fn is_challenge_cookie_valid(cookie_header: &str, client_ip: &str, secret: &str) -> bool {
    let mut crypto_checks = 0;
    const MAX_CRYPTO_CHECKS: u8 = 2; // Anti-CPU DoS: Maksimal 2x hash per request
    const MAX_COOKIE_PARSED: usize = 50; // Anti-Memory DoS: Maksimal 50 cookie

    // Batasi iterasi pemisahan cookie menggunakan .take()
    for cookie in cookie_header.split(';').take(MAX_COOKIE_PARSED) {
        let cookie = cookie.trim();

        // Menggunakan .split_once() mengembalikan Option<(&str, &str)>
        // ZERO heap allocation (hanya stack memory)
        if let Some((key, token)) = cookie.split_once('=') {
            if key == "jarswaf-challenge-token" {
                // Proteksi CPU: Hentikan jika sudah mencapai batas crypto checks
                if crypto_checks >= MAX_CRYPTO_CHECKS {
                    tracing::warn!(
                        "Max crypto checks reached for cookie validation. Potential DoS attempt from IP: {}", 
                        client_ip
                    );
                    break;
                }
                crypto_checks += 1;

                // Gunakan iterator manual tanpa .collect::<Vec<&str>>() untuk mencegah alokasi Heap
                let mut token_parts = token.split('.');
                let timestamp_str = token_parts.next();
                let ip_str = token_parts.next();
                let signature = token_parts.next();
                let extra = token_parts.next(); // Memastikan format tidak memiliki lebih dari 3 bagian

                // Pattern matching yang elegan untuk memvalidasi token_parts
                if let (Some(ts_str), Some(ip), Some(sig), None) =
                    (timestamp_str, ip_str, signature, extra)
                {
                    if ip == client_ip {
                        // Proses Kriptografi yang "mahal" (dijamin maksimal jalan 2x berkat counter di atas)
                        let expected_sig = generate_challenge_signature(ts_str, ip, secret);

                        if expected_sig == sig {
                            if let Ok(ts) = ts_str.parse::<i64>() {
                                let now = chrono::Utc::now().timestamp();
                                // Validasi TTL (1 jam)
                                if now >= ts && now - ts < 3600 {
                                    return true; // Sukses divalidasi (Short-circuit!)
                                }
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
