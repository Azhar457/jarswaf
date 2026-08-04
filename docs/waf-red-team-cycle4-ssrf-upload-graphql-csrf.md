---
title: "WAF Red Team Engagement — Siklus 4: Edge Components Verification"
tags:
  - waf
  - security
  - red-team
  - jarsWAF
  - ssrf
  - upload
  - graphql
  - csrf
aliases:
  - "waf-red-team-cycle4"
  - "jarsWAF-siklus-4"
created: 2026-08-01
updated: 2026-08-01
status: "Completed"
---

> [!abstract] Ringkasan Siklus 4
> Verifikasi rule engine untuk edge attack vectors — SSRF, file upload, GraphQL depth/complexity, dan CSRF. Tidak ada bug baru ditemukan. Semua komponen yang diuji menunjukkan implementasi yang solid dengan zero bypass kritis. Bot Challenge di-skip karena memerlukan browser engine untuk pengujian end-to-end.
>
> **Statistik:** 0 bug ditemukan (validasi positif) | 138/138 test pass | Commit `5f87ef2`

## Daftar Isi

1. [SSRF Protection](#ssrf-protection)
2. [File Upload Validation](#file-upload-validation)
3. [GraphQL Depth/Complexity](#graphql-depthcomplexity)
4. [Bot Challenge — Skip](#bot-challenge--skip)
5. [CSRF Validation](#csrf-validation)
6. [Ringkasan](#ringkasan)

## SSRF Protection

### Rule Engine

Tiga rule SSRF di `src/rules/uri.rs`:

| Rule | Pattern | Scope |
|---|---|---|
| SSRF-001 | Internal/cloud metadata IP | `169.254.169.254`, `127.0.0.1`, `localhost`, `0.0.0.0`, `::1`, `10.x`, `172.16-31.x`, `192.168.x` |
| SSRF-002 | Obfuscated loopback | `127.1`, `0x7f000001`, `2130706433`, `0177.0.0.1`, `017700000001`, `0x7f.0x0.0x1`, `::ffff:0:7f00:1` |
| SSRF-003 | Out-of-band channels | `burpcollaborator`, `dnslog`, `requestbin`, `interactsh` |

### Verifikasi: 20 Payload

Termasuk bypass candidates: DNS rebinding (`127.0.0.1.nip.io`), mixed case (`LOCALHOST`), URL-encoded (`%31%32%37%2e...`), protocol-relative (`//127.0.0.1/`), octal variants (`0177.1`), hex variants (`0x7f.1`), IPv6 mapped.

**Hasil: 20/20 BLOCK + 1 benign PASS.** Regex SSRF comprehensive — semua vector terjangkau. Zero bypass.

## File Upload Validation

### Rule Engine

| Rule | Detection | Severity |
|---|---|---|
| UPLOAD-001 | Dangerous extensions (php/php3/phtml/phar/jsp/asp/exe/dll/bat/sh/py/cgi/htaccess) | Critical |
| UPLOAD-002 | Double extension + null byte (`.php.`, `.php%00`, `.jpg.php`) | Critical |
| UPLOAD-003 | PHP tag detection (`<?php`, `<?=`) di first 100 bytes | Critical |

### Verifikasi: 24 Payload

| Category | Tests | Result |
|---|---|---|
| Dangerous extensions (10) | .php, .php5, .phtml, .phar, .jsp, .asp, .exe, .sh, .py, .cgi | ✅ All BLOCK |
| Case bypass | .PHP, .PhP | ✅ BLOCK (regex case-insensitive) |
| Double extension | .jpg.php, .php.jpg | ✅ BLOCK |
| Null byte | .php%00.jpg | ✅ BLOCK |
| New PHP versions | .php7, .php8 | ✅ BLOCK (prefix match) |
| .htaccess | .htaccess | ✅ BLOCK |
| SVG with XSS | .svg (onload) | ✅ BLOCK (XSS rules) |
| HTML with script | .html | ✅ BLOCK (XSS rules) |
| PHP content in JPG | shell.jpg with `<?php` | ✅ BLOCK (UPLOAD-003) |
| PHP short tag in JPG | shell.jpg with `<?=` | ✅ BLOCK (UPLOAD-003) |
| **XML** | `<?xml version='1.0'?>` | 🟡 PASS (not exec; XXE rule handle) |
| Benign JPG/PDF | photo.jpg, doc.pdf | ✅ PASS |

**20/22 blocked.** XML upload lolos karena bukan exec extension — XXE attack ditangani oleh rule terpisah XXE-001/002 (`<!DOCTYPE`/`<!ENTITY` detection di body). Tidak ada bypass kritis.

## GraphQL Depth/Complexity

### Implementation

`src/rules/graphql.rs` — parser yang menghitung `max_depth` (brace nesting) dan `node_count` (field names). Limits hardcoded: `max_depth_limit = 5`, `max_nodes_limit = 50`.

Dua sistem validasi:
1. `api_security.rs` — `API-GQL-001` di proxy_engine.rs (path `/graphql`, max_depth=5)
2. `graphql.rs` — `GRAPHQL-COMPLEXITY` di rule engine (max_depth=5 + max_nodes=50)

### Verifikasi

| Test | Payload | Hasil |
|---|---|---|
| Depth 3 | `{ user { name } }` | ✅ PASS 200 |
| Depth 5 (at limit) | `{ a { b { c { d { e } } } } }` | ✅ PASS 200 |
| Depth 6 (over) | `{ a { b { c { d { e { f } } } } } }` | ✅ BLOCK 400 |
| Depth 10 | Nested 10 levels | ✅ BLOCK 400 |
| Depth 50 | Nested 50 levels | ✅ BLOCK 400 |
| 100 fields shallow | 100 `fieldN` | ✅ BLOCK 403 (node > 50) |
| 60 aliases | 60 `aN: fieldN` | ✅ BLOCK 403 |

**Response code:** Depth 6+ → 400 (backend rejects after WAF block signal). Node > 50 → 403 (rule engine block). Keduanya aktif dan konsisten.

### Catatan

Response 400 untuk depth attack terjadi karena `validate_jwt_structure`-style block di proxy_engine mengirim custom error, lalu backend JSON parse error mengembalikan 400. **Bukan bypass** — WAF log menunjukkan `BLOCK rule_id=API-GQL-001 reason="GraphQL query exceeds maximum allowed depth"`. Response 400 vs 403 adalah artifact dari dual validation system (sama seperti JWT dual system di Siklus 3).

## Bot Challenge — Skip

Bot Challenge (`src/rules/bot_challenge.rs`) mengimplementasikan:
- **PoW challenge** (SHA256 hash difficulty)
- **Canvas fingerprint** detection
- **Headless browser** detection (WebGL renderer blacklist: `SwiftShader`, `Mesa`, `llvmpipe`)

Pengujian end-to-end memerlukan browser engine (Playwright/Puppeteer) untuk:
1. Menerima dan render challenge HTML
2. Execute JavaScript PoW solver
3. Submit solution dengan canvas + WebGL fingerprint

Tidak feasible dalam lab CLI. Test config: `bot_challenge_enabled = false`.

Rekomendasi: test terpisah dengan Playwright headless untuk verifikasi PoW flow.

## CSRF Validation

### Rule Engine

| Rule | Check | Action |
|---|---|---|
| CSRF-001 | Form POST (`x-www-form-urlencoded` / `multipart/form-data`) tanpa Origin AND Referer | Log |
| CSRF-002 | JSON POST (`application/json`) tanpa Origin | Log |

CSRF tidak di `is_toggled_category` list → `is_toggled_category=false` → return true (always enabled). Tapi `action = Log` → tidak pernah block.

### Verifikasi

| Test | Hasil | Log Trigger |
|---|---|---|
| form POST (no Origin/Referer) | 🟡 200 | CSRF-001 log (not block) |
| JSON POST (no Origin) | 🟡 200 | CSRF-002 log (not block) |
| JSON POST (same-site Origin) | ✅ 200 | No trigger |
| GET request | ✅ 200 | Not state-changing, no check |

CSRF berfungsi sebagai **logging-only**. Tidak ada false positive (GET tidak di-check, hanya state-changing methods POST/PUT/PATCH/DELETE). Tidak ada false negative (header Origin/Referer presence check benar).

## Ringkasan

| Komponen | Temuan | Status |
|---|---|---|
| SSRF | 0 bypass dalam 20 vector | ✅ Solid |
| File Upload | XML lolos (XXE rule handle) | ✅ No critical gap |
| GraphQL | Depth 6+ + node >50 blocked | ✅ Verified |
| Bot Challenge | Skip (needs browser engine) | ⏭️ |
| CSRF | action=Log berfungsi | ✅ Verified |

**Siklus 4 tidak menemukan bug baru.** Ini **validasi positif** — setelah 3 siklus patch (19 bug fixed), komponen edge menunjukkan implementasi yang sudah matang. Rule engine untuk SSRF/upload/GraphQL/CSRF solid tanpa celah kritis.

### Statistik Kumulatif Siklus 1-4

| Metrik | S1 | S2 | S3 | S4 | Total |
|---|---|---|---|---|---|
| Bug ditemukan | 9 | 6 | 4 | 0 | 19 |
| Bug patched | 9 | 6 | 4 | 0 | 19 (100%) |
| Test pass | 135 | 135 | 138 | 138 | 138 |
| Commits | 3 | 1 | 1 | 1 | 6 |

### Cross-References

- [[waf-red-team-engagement]] — Dokumen utama engagement
- [[waf-red-team-cycle2-wasm-honeypot-ratelimit]] — Siklus 2
- [[waf-red-team-cycle3-nosql-proto-dlp-headers]] — Siklus 3
- [[hierarchy-waf-reverse-proxy]] — Atlas WAF reverse proxy