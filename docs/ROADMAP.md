# 🛡️ JARSWAF Development Tracker & Roadmap

> **Dokumen roadmap + referensi pengembangan jarsWAF.**  
> Berdasarkan analisis OWASP Coraza, OWASP CRS v4, BunkerWeb, Awesome-WAF, dan ModSecurity.  
> Lihat `docs/references/waf-research-references.md` untuk detail analisis.

---

## ✅ Selesai (Completed)

### 0. Custom Rule Engine — YAML + DSL + SecLang + Transforms (NEW!)
- **YAML Rule Parser** (`src/rule_engine/`): `serde_yaml`-based rule definition (10 rules: SQLi, XSS, LFI, RCE, Scanner)
- **SecLang / CRS Parser** (`src/rule_engine/seclang.rs`): `SecRule`, `SecAction`, `SecRuleRemoveById` parser for ModSecurity & OWASP CRS compatibility
- **DSL Parser** (`src/rule_engine/dsl.rs`): `.jwaf` file format — `@id`, `match any/all { field ~ "regex" }`, `---` separator
- **Profile System** (`rules/profiles.yaml`): 4 profiles (moderate, strict, permissive, sqli-only) — batch enable/disable ruleset
- **CRS Anomaly Scoring & Paranoia Levels** (`src/rules/anomaly.rs`): Categorical attack scoring (SQLi, XSS, LFI, RCE, Scanner) + Paranoia Levels (PL1-PL4)
- **Tool Exclusion & Whitelist** (`src/rules/whitelist.rs`): OWASP CRS REQUEST-905 equivalent for Googlebot, Bingbot, UptimeRobot, Datadog, Grafana, k6
- **WAF Fingerprint Resistance** (`src/config.rs`, `src/proxy_engine.rs`): Customizable `server_header_mask` (e.g., `Server: nginx`)
- **Transforms Pipeline**: UrlDecode, Lowercase, NormalizePath, RemoveNulls, CompressWhitespace, HtmlEntityDecode, Base64Decode
- **LRU Eval Cache**: 1024 entry cache for repeated requests
- **Penetration Tests**: 145 total unit tests — 100% passing

### 1. Arsitektur Proxy & Load Balancing
- **Proxy Engine (Pingora):** Reverse proxy menggunakan Cloudflare Pingora (Rust) untuk keamanan memori (memory safety) dan *zero-copy forwarding*.
- **WebSocket Security Proxy:** Berhasil meneruskan upgrade WebSocket.
- **Load Balancing (Round Robin):** Implementasi failover ke first backend apabila *health check* gagal.
- **Phase-Based Engine** (`src/rule_engine/phase.rs`): 4-phase request processing (Phase 1 Headers, Phase 2 Body, Phase 3 Response Headers, Phase 4 Response Body).

### 2. Rate Limiting & Proteksi (Token Bucket)
- **Token Bucket Algoritma:** Terintegrasi menggunakan memori *cache* berkecepatan tinggi (`moka` DashMap dengan kapasitas 10k IP).
- **HTTP Headers (Best Practice):** Inject header `X-RateLimit-Limit`, `X-RateLimit-Remaining`, dan `X-RateLimit-Reset`.

### 3. Keamanan Tingkat Kernel (eBPF & XDP)
- **Persistent IP Blocking:** Otomatis memasukkan IP ke kernel *blocklist map*.
- **Multi-environment:** Parameter `xdp_interface` (eth0, podman0).
- **Auto-Remediation:** Unblock otomatis via tokio::spawn.
- **Threshold:** 3 pelanggaran → blokir (sebelumnya 5).
- **Network Byte Order Fix:** Konversi `u32::from().to_be()`.

### 4. Semantic AST WAF Engine
- **Mitigasi ReDoS:** Hapus regex raksasa SQLi/XSS dari body rule.
- **Deteksi Cerdas:** Parser AST token-based (`check_sql_injection_semantic`).
- **16 rule modules:** anomaly, api, body, headers, graphql, multipart, trust, dll (~3314 lines).

---

## 🔴 PRIORITAS 0 — Fondasi WAF Modern (Bulan Ini)

Berdasarkan arsitektur OWASP Coraza + CRS v4:

### 1. [P0] Phase-Based Request Processing Engine

> **Inspirasi:** Coraza 4-phase model (REQUEST_HEADERS → REQUEST_BODY → RESPONSE_HEADERS → RESPONSE_BODY)

```
Current:  body → inspect → block/allow
Target:   headers → [Phase1] → body → [Phase2] → backend → response_headers → [Phase3] → response_body → [Phase4]
```

**Kenapa:** Sekarang inspeksi cuma di request body. Dengan phase:
- Phase 1: Header validation, rate limiting, IP reputation, HTTP method enforcement (sebelum body dibaca — hemat resource)
- Phase 2: Body deep inspection, AST tokenizer, multipart, DLP, GraphQL query depth
- Phase 3: Response headers — leak detection, server info masking
- Phase 4: Response body — data exfiltration prevention, content injection

**Todo:**
- [ ] Refactor `proxy_engine.rs` → split request_handler jadi phase functions
- [ ] `early_reject()` di Phase 1 — block sebelum body parsing kalau header mencurigakan
- [ ] Add phase-specific timeout (header lebih cepat dari body)

---

### 2. [P0] SecLang / CRS Rule Parser

> **Inspirasi:** Coraza SecLang compiler, ModSecurity SecLang syntax  
> **Repo:** `github.com/corazawaf/coraza` — 100% CRS compatible

**Kenapa:** Dengan parser SecLang, jarsWAF tiba-tiba bisa menjalankan **200+ rule OWASP CRS** tanpa nulis ulang.

**Kompatibilitas Aturan CRS:**
| Aturan | Format | Parser yang Dibutuhkan |
|--------|--------|----------------------|
| `SecRule REQUEST_HEADERS|ARGS "@rx pattern" "id:1234,phase:1,block"` | SecLang regex | Parser regex + variable resolver |
| `SecAction "id:9000,phase:1,setvar:'tx.blocking_flag=1'"` | SecAction | Variable assignment engine |
| `SecRuleRemoveById 9500` | Rule exclusion | Rule metadata DB |

**Todo:**
- [ ] Implement SecLang tokenizer (regex + state machine)
- [ ] Implement variable resolver (`ARGS`, `REQUEST_HEADERS`, `TX:var`, `IP:src`)
- [ ] Implement action chain (`block`, `pass`, `setvar`, `t: transformations`)
- [ ] Implement operator mapping (`@rx`, `@pm`, `@within`, `@contains`)
- [ ] Test dengan rule CRS REQUEST-942-SQLI

---

### 3. [P0] CRS Anomaly Scoring System

> **Inspirasi:** OWASP CRS anomaly scoring — skor kategorikal per attack type  
> **Docs:** [coreruleset.org/docs/configuring/anomaly_scoring/](https://coreruleset.org/docs/configuring/anomaly_scoring/)

**Arsitektur Target:**
```
REQUEST-942-100 (SQLi) → match → anomaly_score += 50 (Critical)
REQUEST-941-100 (XSS) → match → anomaly_score += 50 (Critical)  
REQUEST-930-100 (LFI) → match → anomaly_score += 50 (Critical)
Total: 150 → threshold exceeded (default 5) → BLOCK
```

**Todo:**
- [ ] Extend `rules/anomaly.rs` dengan kategori CRS (SQLi=50pt, XSS=50pt, LFI=50pt, RCE=100pt)
- [ ] Implement separate inbound_score + outbound_score
- [ ] Implement threshold config (per-VHost, default 5)
- [ ] Add anomaly_score injection ke response header (`X-WAF-Anomaly-Score: 150`)
- [ ] Add **Paranoia Level** (PL1-PL4): PL1 = safe, PL4 = strict

---

## 🟡 PRIORITAS 1 — Detection & Intelligence (Minggu Ini)

### 4. [P1] CrowdSec / Threat Intelligence Integration

**Inspirasi:** BunkerWeb CrowdSec bouncer  
**Ganti:** IP reputation statis (`ip_reputation.rs`) → real-time community threat intel

**Todo:**
- [ ] CrowdSec API bouncer — query `/v1/decisions` untuk IP check
- [ ] AbuseIPDB API — report + check IP reputation
- [ ] Cache reputation result dengan TTL (1 jam)
- [ ] Feed hasil ke eBPF blocklist untuk kernel-level blocking

### 5. [P1] Tool Exclusion & Whitelist

**Inspirasi:** CRS REQUEST-905-TOOL-EXCLUSION  
**Kenapa:** Googlebot, healthcheck, monitoring tools jangan kena block

**Todo:**
- [ ] Pre-define whitelist: Googlebot, Bingbot, UptimeRobot, Datadog, k6, Grafana
- [ ] Configurable user-agent whitelist per VHost
- [ ] Skip anomaly scoring untuk IP whitelist

### 6. [P1] Bypass Detection Engine

**Inspirasi:** Awesome-WAF evasion techniques  
**Test case existing:** SQL comment injection bypass ✅ (udah di-fix)

**Todo:**
- [ ] Integrasi test suite bypass ke `/tests/`
- [ ] Test case: case shifting, double encoding, parameter pollution, comment injection, null byte
- [ ] Automated red team loop: bypass → detect → fix → verify

---

## 🟢 PRIORITAS 2 — Enhancement & Tools

### 7. [P2] Detection-as-Code Pipeline
- **Todo:** GitHub Actions: lint rules → test rule set → build → deploy
- **Todo:** JSON/YAML rule format sebagai alternatif SecLang
- **Todo:** Rule versioning + changelog

### 8. [P2] WASM Plugin System Expansion
- **Existing:** `wasm.rs` — sudah ada WASM runtime
- **Target:** Plugin hooks di semua 4 phase
- **Todo:** WASM SDK (Rust SDK + API docs)

8. [P2] Fuzzing & WAF Fingerprint Resistance
- **Tool:** wafw00f test (`external/wafw00f/`) — apakah jarsWAF bisa di-fingerprint?
- **Target:** Jangan return `Server: jarswaf` — gunakan `Server: nginx` atau kustom
- **Tool:** GoTestWAF (`external/gotestwaf/`) — automated WAF effectiveness test suite

### 10. [P2] ML-Based Anomaly Detection
- **Existing:** `agent/` — sudah ada ONNX runtime
- **Target:** Train model dari request logs — deteksi anomaly berdasarkan request pattern
- **Todo:** Feature extraction (path length, param count, char distribution, entropy)

---

## ⏳ Sedang Berjalan

- [ ] **Uji Coba Rate Limit (cURL):** HTTP 429 + Retry-After verification
- [ ] **Pengujian Multi-Agent VM vs Podman:** eBPF XDP sync stability
- [ ] **Gossip Protocol:** UDP multicast antar node jarsWAF

---

## 📊 Gap Analysis: jarsWAF vs Standar Industri

| Fitur | jarsWAF | Coraza | BunkerWeb | CRS v4 |
|-------|---------|--------|-----------|--------|
|| Reverse proxy (async) | ✅ Pingora | ❌ Perlu connector | ✅ Nginx | ❌ |
|| eBPF XDP blocking | ✅ | ❌ | ❌ | ❌ |
|| WASM plugins | ✅ | ❌ | ❌ | ❌ |
|| AST semantic engine | ✅ | ❌ | ❌ | ❌ |
|| Rate limiting | ✅ Token bucket | ❌ | ✅ | ❌ |
|| **CRS rule parsing** | **❌** | **✅** | **✅ (ModSec)** | **✅** |
|| **Phase-based engine** | **❌** | **✅** | **✅** | **✅** |
|| **Anomaly scoring CRS** | **❌ Parsial** | **✅** | **✅** | **✅** |
|| **Custom YAML/DSL rules** | **✅ 124 tests** | ❌ | ❌ | ❌ |
|| **Transforms pipeline** | **✅ 7 transforms** | ✅ t: | ✅ | ✅ t: |
|| **Rule profiles (batch)** | **✅ 4 profiles** | ❌ | ❌ | ❌ |
|| **DSL parser (.jwaf)** | **✅** | ❌ | ❌ | ❌ ||
| CrowdSec integration | ❌ | ❌ | ✅ | ❌ |
| Paranoia levels | ❌ | ✅ | ✅ | ✅ |
| SecLang compatibility | ❌ | ✅ | ✅ | N/A |

**Catatan:** jarsWAF unggul di layer low-level (eBPF, WASM, AST) karena pure Rust.  
**Fokus:** Tutup gap di rule engine + phase processing — itu yang bikin WAF enterprise-grade.

---

## 📚 Referensi

Baca `docs/references/waf-research-references.md` untuk analisis lengkap:
1. **OWASP Coraza** — Phase model, SecLang, CRS compatibility
2. **OWASP CRS v4** — Anomaly scoring, paranoia level, rule structure
3. **BunkerWeb** — CrowdSec, automated TLS, fail2ban
4. **Awesome-WAF** — Evasion, bypass, fuzzing, tools
5. **ModSecurity** — OG WAF, SecLang origin
