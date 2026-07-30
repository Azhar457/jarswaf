#!/usr/bin/env python3
"""jarsWAF WAF Testing v2 — test via root proxy endpoint"""
import sys, json, time, urllib.request, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
PAYLOAD_DIR = sys.argv[2] if len(sys.argv) > 2 else "/home/testing/seclists"
results = {}
FP = 0; FT = 0

def test(name, filepath, param="q", endpoint="/"):
    with open(filepath, 'r', errors='ignore') as f:
        payloads = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    print(f"\n═══ {name} ({len(payloads)} payloads) ═══")
    blocked = passed = errors = 0
    for i, p in enumerate(payloads):
        url = f"{TARGET}{endpoint}?{param}={urllib.parse.quote(p)}"
        try:
            r = urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent':'Mozilla/5.0'}), timeout=3)
            passed += 1
        except urllib.error.HTTPError as e:
            if e.code == 403: blocked += 1
            else: errors += 1
        except: errors += 1
        if (i+1) % 50 == 0:
            print(f"  {i+1}/{len(payloads)}  🛡️{blocked}  ✅{passed}  ❌{errors}", end='\r')
    t = len(payloads)
    print(f"  🛡️ Blocked: {blocked}/{t} ({blocked*100//t}%)  ✅ Passed: {passed}/{t}  ❌ Errors: {errors}")
    results[name] = {'total': t, 'blocked': blocked, 'passed': passed, 'errors': errors}

# False positive test
print("═══ FALSE POSITIVE ═══")
for path in ["/", "/api/list?dir=", "/api/read/README.md", "/api/list?dir=documents", "/hello"]:
    try:
        r = urllib.request.urlopen(urllib.request.Request(f"{TARGET}{path}", headers={'User-Agent':'Mozilla/5.0'}), timeout=3)
        print(f"  ✅ {path} = {r.getcode()}")
        FP += 1
    except Exception as e:
        print(f"  ❌ {path} = BLOCKED!")
    FT += 1

# Attack tests — via root (WAF catches all params)
test("LFI (Jhaddix)", f"{PAYLOAD_DIR}/lfi.txt", "file", "/")
test("XSS (Jhaddix)", f"{PAYLOAD_DIR}/xss.txt", "q", "/")
test("SQLi (Generic)", f"{PAYLOAD_DIR}/sqli.txt", "id", "/")

# Summary
print("\n" + "="*55)
print("📊 FINAL SUMMARY")
print("="*55)
print(f"✅ False Positive: {FP}/{FT} clean ({FP*100//FT}% pass)")
for n, r in results.items():
    b_rate = r['blocked'] * 100 // r['total'] if r['total'] else 0
    print(f"  {n:20s}: 🛡️ {b_rate:3d}% blocked ({r['blocked']}/{r['total']})  ✅ {r['passed']} pass  ❌ {r['errors']} err")
