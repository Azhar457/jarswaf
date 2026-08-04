# 📚 WAF Research & Reference Compendium

> **Tujuan:** Referensi terstruktur dari project WAF open-source terkemuka untuk pengembangan jarsWAF.
> Berisi analisis arsitektur, mekanisme deteksi, dan ide yang bisa diadopsi.

---

## 📦 Lokasi di Project

Semua repo sudah di-clone ke `jarswaf/external/` (shallow clone, depth=1):

| Repo | Path | Ukuran |
|------|------|--------|
| **PayloadsAllTheThings** | `external/PayloadsAllTheThings/` | 22MB |
| **Awesome-WAF** | `external/Awesome-WAF/` | 56MB |
| **OWASP CRS v4** | `external/coreruleset/` | 7.6MB |
| **Coraza** | `external/coraza/` | 4.9MB |
| **ModSecurity** | `external/ModSecurity/` | 7.6MB |
| **BunkerWeb** | `external/bunkerweb/` | 432MB |
| **GoTestWAF** | `external/gotestwaf/` | 3.4MB |
| **wafw00f** | `external/wafw00f/` | 1.2MB |
| **SecLists** | `external/SecLists/` | 95MB |

---

## 1. OWASP Coraza WAF (Go)

**Repo:** https://github.com/corazawaf/coraza  
**Stars:** 3.7k · **Lisensi:** Apache 2.0  
**Use case:** Enterprise-grade WAF framework Go, 100% kompatibel ModSecurity SecLang + OWASP CRS.

### 🏗️ Arsitektur Kunci

```
Request → [Phase 1: REQUEST_HEADERS]
        → [Phase 2: REQUEST_BODY]
        → [Phase 3: RESPONSE_HEADERS]
        → [Phase 4: RESPONSE_BODY]
        → Decision (ALLOW/BLOCK)
```

Coraza menggunakan **phase-based processing model** warisan ModSecurity — tiap request melewati 4 fase secara berurutan. Ini memungkinkan rule berjalan di titik spesifik dari lifecycle request.

### 🔧 Komponen Utama yang Bisa Dipelajari

| Komponen | Fungsi | Relevansi jarsWAF |
|----------|--------|-------------------|
| **Rule Engine** | Compiler aturan SecLang → AST → executable matchers | rules/ yang sekarang ~3314 lines bisa di-refactor |
| **Plugins/Actions** | chainable actions (block, pass, log, setvar, t: transformations) | WASM plugin system bisa diperluas |
| **Operators** | rx, pm, within, contains, validateUrl, detectXSS, detectSQLi | AST semantic yang sudah ada perlu operator mapping |
| **Transformations** | NormalizePath, removeNulls, cmdLine, sqlHexDecode | Normalisasi yang sudah ada (recursive URL decode → NFKC) bisa ditambah |
| **Connectors** | WASM, Nginx, Caddy, HTTP reverse proxy | jarsWAF sudah punya Pingora proxy — ini competitive advantage |
| **AuditLog** | Concurrent, serial, concurrency-aware logging | logging.rs bisa dipelajari format audit log-nya |

### 💡 Yang Bisa Diadopsi ke jarsWAF

1. **SecLang Parser** — Parsing aturan ModSecurity/CRS format langsung ke rules engine jarsWAF. Ini **game changer**: tiba-tiba jarsWAF bisa jalan dengan 200+ rule dari CRS.
2. **Phase-based rule execution** — Sekarang jarsWAF inspeksi di request body doang. Dengan phase, kita split:
   - **Phase 1:** Header inspection, rate limiting, IP reputation
   - **Phase 2:** Body deep inspection, AST tokenizer, DLP
   - **Phase 3/4:** Response inspection, data leak prevention
3. **Variable interpolation** — `TX:blocking_flag`, `IP:src_ip` — konsep variabel yang bisa di-refer oleh rule.

### 🔗 Link Penting
- [Coraza Package Reference](https://pkg.go.dev/github.com/corazawaf/coraza/v3)
- [OWASP Coraza Project](https://owasp.org/www-project-coraza-web-application-firewall/)
- [SecLang Documentation](https://coraza.io/docs/seclang/)

---

## 2. OWASP Core Rule Set (CRS) v4

**Repo:** https://github.com/coreruleset/coreruleset  
**Use case:** Standard industri deteksi serangan web — 200+ rule untuk SQLi, XSS, LFI, RCE, dll.

### 🎯 Anomaly Scoring System

CRS **tidak langsung block** request — dia kumpulkan skor anomali di beberapa kategori:

```
REQUEST-901-INITIALIZATION    → Init vars, define paranoia level
REQUEST-905-TOOL-EXCLUSION    → Whitelist monitoring/healthcheck tools
REQUEST-910-IP-REPUTATION     → IP blocklists, GeoIP, proxy detection
REQUEST-911-METHOD-ENFORCEMENT → HTTP method validation
REQUEST-912-DOS-PROTECTION    → Rate limiting, DoS detection
REQUEST-913-SCANNER-DETECTION → Scanner/security tool detection
REQUEST-920-PROTOCOL-ENFORCEMENT → HTTP protocol compliance
REQUEST-921-PROTOCOL-ATTACK   → Protocol attacks
REQUEST-930-APPLICATION-ATTACK-LFI → Local File Inclusion
REQUEST-931-APPLICATION-ATTACK-RFI → Remote File Inclusion
REQUEST-932-APPLICATION-ATTACK-RCE → Remote Code Execution
REQUEST-933-APPLICATION-ATTACK-PHP → PHP Injection
REQUEST-934-APPLICATION-ATTACK-GENERIC → Generic attacks
REQUEST-941-APPLICATION-ATTACK-XSS → XSS
REQUEST-942-APPLICATION-ATTACK-SQLI → SQL Injection
REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION → Session fixation
REQUEST-944-APPLICATION-ATTACK-JAVA → Java attacks
REQUEST-949-BLOCKING-EVALUATION → Block decision based on anomaly score
```

**Cara kerja:**
1. Tiap rule yang match menambah skor ke kategori tertentu
2. **Anomaly Score Threshold** (default: 5 untuk inbound, 4 untuk outbound)
3. Jika threshold terlampaui → request diblok
4. **Paranoia Level** (1-4): Makin tinggi, makin banyak rule aktif, makin sensitif

### 💡 Yang Bisa Diadopsi

1. **Anomaly Scoring berbasis kategori** — jarsWAF sudah punya anomaly scoring (`rules/anomaly.rs`) tapi bisa diperluas dengan kategori-kategori CRS.
2. **Paranoia Level** — Set level konfigurasi yang scalable: PL1 untuk production ringan, PL4 untuk maximum security.
3. **Tool Exclusion** — Whitelist tools legitimate kayak Googlebot, healthcheck, monitoring.
4. **Inbound vs Outbound scoring** — Skor terpisah untuk request vs response.

### 🔗 Link Penting
- [CRS Documentation](https://coreruleset.org/docs/)
- [Anomaly Scoring Explained](https://coreruleset.org/20211016/anomaly-scoring/)
- [CRS Rule Structure](https://coreruleset.org/docs/configuring/rule_structure/)

---

## 3. BunkerWeb (Nginx-based WAF)

**Repo:** https://github.com/bunkerity/bunkerweb  
**Stars:** 10.8k  
**Use case:** Next-gen WAF yang "secure by default" — otomatis konfigurasi security berdasarkan reverse proxy.

### 🏗️ Arsitektur

```
Internet → Nginx → BunkerWeb Services → Backend
                │
                ├── ModSecurity WAF (CRS)
                ├── Fail2Ban integration
                ├── Let's Encrypt (ACME)
                ├── ClamAV (antivirus)
                ├── CrowdSec integration
                └── Custom Lua scripts
```

### 🔧 Unique Features

| Fitur | Deskripsi | Relevansi |
|-------|-----------|-----------|
| **Auto Ban** | IP otomatis diblok setelah N failed requests dalam M detik | Mirip rate limiting jarsWAF tapi dengan sliding window |
| **CrowdSec Integration** | Threat intelligence community-based | Threat intel yang sudah ada (`threat_intel.rs`) bisa ditambah CrowdSec API |
| **Multisite Config** | Banyak domain dalam single instance | jarsWAF sudah punya vhost.rs — bisa dipelajari |
| **Automated TLS** | Let's Encrypt auto-provision per domain | tls.rs sudah ada ACME |
| **Security Headers** | Auto inject HSTS, CSP, X-Frame-Options, dll | `security_headers` di proxy_engine.rs |

### 💡 Yang Bisa Diadopsi

1. **CrowdSec bouncer** — Konek ke CrowdSec API biar jarsWAF pake threat intelligence global.
2. **Fail2Ban integration** — Failed login thresholding yang lebih canggih.
3. **Lua scripting layer** — Di Pingora bisa pake WASM (udah ada) — lebih modern dari Lua.

---

## 4. Awesome-WAF (Curated List)

**Repo:** https://github.com/0xInfection/Awesome-WAF  
**Stars:** 7.6k  
**Use case:** Referensi lengkap semua aspek WAF — dari detection, evasion, bypass, tools, papers.

### 📂 Struktur Konten

| Section | Isi | Manfaat |
|---------|-----|---------|
| **Detection Techniques** | Signature-based, behavior-based, learning-based | Validasi AST semantic sudah di jalur yang benar |
| **Evasion Techniques** | Case shifting, encoding, comment injection, parameter pollution | Sudah di-test sebagian (SQL comment injection bypass) |
| **Known Bypasses** | CVE-specific bypasses (ModSecurity, AWS WAF, Cloudflare) | Test case untuk red team loop |
| **Fuzzing Tools** | wafw00f, waf-tester, bypasser, antifuzz | Tools buat test WAF sendiri |
| **Research Papers** | Academic papers tentang WAF effectiveness | Referensi formal |

### 💡 Yang Paling Berguna
- **Fuzzing tools** — `wafw00f`, `waf-tester` buat fingerprint detection test
- **Bypass techniques** — Koleksi teknik yang udah diketahui, bisa langsung di-test ke jarsWAF
- **Detection technique** — Klasifikasi: signature, behavior, learning, hybrid

---

## 5. Referensi Tambahan

### ModSecurity (The OG)
- **Repo:** https://github.com/owasp-modsecurity/ModSecurity
- **Pelajaran:** Phase model, SecLang syntax, rule variable system
- **Kenapa penting:** Standar de facto — semua WAF modern kompatibel atau terinspirasi dari sini

### waf-brain (ML-based)
- **Repo:** https://github.com/bbu/useragent
- **Pelajaran:** ML-driven WAF dengan ekstraksi fitur + classifier
- **Relevansi:** jarsWAF sudah punya ONNX runtime — bisa integrate model-based detection

### oastify (OAS-driven WAF)
- **Repo:** https://github.com/oastify/oashield
- **Pelajaran:** Auto-generate WAF rules dari OpenAPI spec (positive security model)
- **Relevansi:** Positive security model — complement untuk negative security model jarsWAF

### detection-as-code
- **Praktik:** Treat detection rules as code — CI/CD, test harness, version control
- **Implementasi:** GitHub Actions untuk test rule set sebelum deploy

---

## 🎯 Prioritas Implementasi untuk jarsWAF

Berdasarkan analisis di atas, ini prioritas yang recommended:

### 🔴 P0 — High Impact
```
1. SecLang/CRS Parser   → Bisa jalanin 200+ rule OWASP CRS
2. Phase-based engine   → Inspeksi di request_headers + request_body + response
3. Anomaly scoring CRS  → Skor kategorikal (SQLi 50pt, XSS 50pt, LFI 50pt)
```

### 🟡 P1 — Medium Impact
```
4. CrowdSec integration → Threat intelligence global
5. Paranoia Levels      → PL1-PL4 scalable security
6. Tool Exclusion       → Whitelist Googlebot, monitoring
```

### 🟢 P2 — Enhancement
```
7. Fuzzing via wafw00f   → Test coverage detection
8. Evasion techniques    → Integrated bypass test suite
9. Positive security model → OpenAPI-based rule generation
10. Machine learning     → ONNX model untuk anomaly detection
```

---

**Dibuat:** 2026-07-29  
**Sumber:** OWASP Coraza, OWASP CRS v4, BunkerWeb v6, Awesome-WAF, ModSecurity
