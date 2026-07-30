#!/usr/bin/env python3
"""jarsWAF WAF Testing — batch test against SecLists payloads"""
import subprocess, sys, json, time, urllib.request, urllib.parse

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
PAYLOAD_DIR = sys.argv[2] if len(sys.argv) > 2 else "/home/testing/seclists"

results = {}

def test_payloads(name, filepath, param="q"):
    """Send each payload as ?param=<payload> and record status"""
    payloads = []
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('#'):
                payloads.append(line)
    
    print(f"\n═══ Testing {name} ({len(payloads)} payloads) ═══")
    blocked = 0
    passed = 0
    errors = 0
    sample_blocked = []
    sample_passed = []
    
    for i, payload in enumerate(payloads):
        url = f"{TARGET}/api/read?{param}={urllib.parse.quote(payload)}"
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0.0.0'})
            resp = urllib.request.urlopen(req, timeout=3)
            passed += 1
            if len(sample_passed) < 3:
                sample_passed.append(payload[:60])
        except urllib.error.HTTPError as e:
            if e.code == 403:
                blocked += 1
                if len(sample_blocked) < 3:
                    sample_blocked.append(payload[:60])
            else:
                errors += 1
        except Exception:
            errors += 1
        
        if (i+1) % 100 == 0:
            print(f"  Progress: {i+1}/{len(payloads)}  blocked={blocked}  passed={passed}", end='\r')
    
    print(f"  \n  ✅ Blocked: {blocked}/{len(payloads)} ({blocked*100//len(payloads)}%)")
    print(f"  ⚠️  Passed:  {passed}/{len(payloads)} ({passed*100//len(payloads)}%)")
    if errors:
        print(f"  ❌ Errors:  {errors}")
    
    results[name] = {'total': len(payloads), 'blocked': blocked, 'passed': passed, 'errors': errors}
    
    if sample_passed:
        print(f"\n  ⚠️  Sample PASSED (false negatives?):")
        for s in sample_passed:
            print(f"    · {s}")
    if sample_blocked:
        print(f"\n  ✅ Sample BLOCKED:")
        for s in sample_blocked:
            print(f"    · {s}")

# Test false positives first (clean operations)
print("═══ FALSE POSITIVE TEST ═══")
fp_tests = [
    ("List root", "/api/list?dir="),
    ("Read README", "/api/read/README.md"),
    ("List documents", "/api/list?dir=documents"),
    ("Config JSON", "/api/read/config.json"),
    ("Root index", "/"),
]
fp_blocked = 0
for name, path in fp_tests:
    try:
        req = urllib.request.Request(f"{TARGET}{path}", headers={'User-Agent': 'Mozilla/5.0'})
        resp = urllib.request.urlopen(req, timeout=3)
        print(f"  ✅ {name}: {resp.getcode()}")
    except urllib.error.HTTPError as e:
        print(f"  ❌ {name}: {e.code} BLOCKED!")
        fp_blocked += 1
    except Exception as e:
        print(f"  ❌ {name}: ERROR {e}")

print(f"\n📊 False Positive Rate: {fp_blocked}/{len(fp_tests)} ({fp_blocked*100//len(fp_tests)}%)")

# Attack tests
test_payloads("LFI (Jhaddix)", f"{PAYLOAD_DIR}/lfi.txt", "file")
test_payloads("XSS (Jhaddix)", f"{PAYLOAD_DIR}/xss.txt", "q")
test_payloads("SQLi (Generic)", f"{PAYLOAD_DIR}/sqli.txt", "id")

# Summary
print("\n" + "="*60)
print("📊 TEST SUMMARY")
print("="*60)
print(f"\nFalse Positives: {fp_blocked}/{len(fp_tests)} ({fp_blocked*100//len(fp_tests)}%)")
for name, r in results.items():
    rate = r['blocked'] * 100 // r['total']
    print(f"  {name:20s}: {r['blocked']:4d}/{r['total']} blocked ({rate:3d}%)  (passed: {r['passed']}, errors: {r['errors']})")
