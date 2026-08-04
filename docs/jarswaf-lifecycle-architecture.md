---
title: "jarsWAF — Request Lifecycle & Architecture"
tags:
  - jarswaf
  - waf
  - reverse-proxy
  - rust
  - pingora
aliases:
  - jarsWAF Lifecycle
  - jarsWAF Architecture
created: 2026-07-09
updated: 2026-07-09
status: pending
---
zhar# jarsWAF — Request Lifecycle & Architecture

> **WARNING:** Document ini adalah dump analisis langsung dari source code `/mnt/data_d/Desktop/KERJA/jarswaf/src/`. Tidak cocok untuk investor — ganti judul jadi "Architecture Overview" sebelum presentasi.

---

## Stack

| Layer | Teknologi | Fungsi |
|-------|-----------|--------|
| Reverse Proxy | **Pingora** (Cloudflare) | Zero-copy forwarding, async HTTP, connection pool |
| Rule Engine | **Rust + Regex + AST** | Semantic tokenizer (SQLi/XSS) + 300+ signature + custom rules |
| DDoS Mitigation | **eBPF XDP** (aya) | Drop di kernel level sebelum TCP stack |
| Rate Limiter | **Token Bucket** | In-memory (DashMap) + distributed (Redis) |
| Logging | **Async MPSC + SQLite/ClickHouse** | Non-blocking pipeline |
| Auto-Remediation | **Escalating block tiers** | 1m → 5m → 30m → 24h |
| TLS | **Rustls** (ring) | Zero-conf via ACME (Let's Encrypt) + custom cert |
| Dashboard | **Svelte + WebSocket** | Real-time attack map, live log, terminal |
| Orchestration | **Agent-Controller** | Distributed: banyak Agent, satu Controller panel |

---

## Entry Point

```
main.rs
├── Cli parse (clap)
├── tracing_subscriber init (JSON structured logging)
├── jarswaf::agent::run_agent()   →  WAF Agent mode (default)
└── jarswaf::controller::run_controller()  →  Central panel mode
```

**Agent mode** (`run_agent`):
1. Load config from `config.toml`
2. Init SQLite/ClickHouse jika dikonfigurasi
3. Start log worker (MPSC channel, 10k buffer)
4. Start config reloader (polling setiap 2 detik, atomic swap via `ArcSwap`)
5. Load blocklist from file → `DashMap<IpAddr, ()>`
6. Jika `--controller` diberikan: register ke Controller, kirim metrics periodik
7. **Start Pingora server** dengan `JarsWafProxy` sebagai `ProxyHttp` implementation

---

## Request Lifecycle (Pingora Phases)

```
Client → pingora::Server
    │
    ├─ 1. new_ctx()         ← buat per-request context
    ├─ 2. request_filter()  ← VALIDASI AWAL (block/kill sebelum upstream)
    ├─ 3. upstream_peer()   ← PILIH BACKEND (load balancing)
    ├─ 4. upstream_request_filter()  ← MODIFY request ke backend
    ├─ 5. request_body_filter()     ← INSPECT body (streaming)
    ├─ 6. response_body_filter()    ← INSPECT response dari backend
    ├─ 7. response_filter()         ← MODIFY response
    ├─ 8. logging()                 ← LOG + cleanup
    ├─ 9. fail_to_proxy()           ← ERROR handler upstream
    └─ 10. error_while_proxy()      ← ERROR handler proxy
```

---

## Phase Detail

### 0. `new_ctx()` — Context Init

File: `proxy_engine.rs` baris 563–579

```rust
struct JarsWafCtx {
    client_ip: Option<IpAddr>,
    vhost_backend: Option<String>,
    vhost_name: Option<String>,
    body_buffer: Vec<u8>,           // buffered body untuk WAF inspection
    body_limit: usize,               // max body size (default 1MB)
    is_blocked: bool,                // flag block setelah rule trigger
    security_headers: Option<...>,
    dlp_config: Option<...>,
    response_body_buffer: Vec<u8>,
    request_id: String,              // UUID per request
    websocket_security_enabled: bool,
    max_concurrent_requests: usize,
    vhost_backend_resolved: Option<String>,
}
```

**Dibuat per request.** `request_id` = UUID v4 untuk correlation logging.

---

### 1. `request_filter()` — Pre-Upstream Validation

**Pingora hook**: Return `Ok(true)` = handled/blocked (no upstream call).  
`Ok(false)` = lanjut ke upstream.

Urutan eksekusi **exact** (baris 581–978):

```
request_filter()
│
├─ 1.1 Client IP Extraction
│   └─ session.client_addr() → parse InetSocketAddr
│
├─ 1.2 Header Snapshot
│   └─ Copy semua headers ke HashMap (avoid hold-borrow Pingora session)
│
├─ 1.3 ACME Challenge Intercept
│   ├─ path == "/.well-known/acme-challenge/{token}"
│   └─ Serve challenge content langsung (tanpa backend)
│
├─ 1.4 VHost Matching
│   ├─ crate::vhost::match_vhost(host, config)
│   ├─ Inject vhost config ke ctx (body_limit, security_headers, dll)
│   └─ 400 "Bad Request" jika host tidak dikenal
│
├─ 1.5 Direct IP Access Block
│   └─ Host header adalah IP literal → BLOCK + log "DIRECT-IP-001"
│
├─ 1.6 Slowloris Protection
│   ├─ ACTIVE_CONNECTIONS[client_ip]++
│   └─ Jika > max_conns_per_ip → 429 "SLOWLORIS-001"
│
├─ 1.7 Request Fingerprinting
│   ├─ SHA256(User-Agent + Accept + Accept-Language + Accept-Encoding)
│   ├─ Jika fingerprint berubah mid-session → ANOMALY log
│   └─ Tanda: session hijacking / bot rotation
│
├─ 1.8 Bot Challenge (JS PoW)
│   ├─ Jika vhost_cfg.bot_challenge_enabled:
│   │   ├─ Cek cookie "jarswaf-challenge-token" (HMAC valid, < 1 jam)
│   │   ├─ Tidak valid → redirect ke /jarswaf-challenge?orig_path
│   │   │   └─ Client jalankan SHA256 PoW (target prefix "000")
│   │   ├─ Verifikasi di /jarswaf-challenge-verify?sol=N&r=path
│   │   └─ Set cookie → redirect balik
│   └─ Juga trigger jika reputation_score ≥ 5.0 (tanpa cookie)
│
├─ 1.9 Reputation Blocklist Check
│   ├─ self.blocklist.contains_key(&client_ip)
│   └─ Jika ada → 403 "COLLAB-001" (Collaborative Threat Intelligence)
│
├─ 1.10 Geoblocking (MaxMind GeoIP)
│    ├─ resolve_ip_country(&client_ip)
│    ├─ allowlist mode: hanya negara tertentu diizinkan
│    ├─ denylist mode: blok negara tertentu
│    └─ Jika kena → 403 "GEO-001"
│
├─ 1.11 Rate Limiting (Token Bucket)
│    ├─ Cari rate limit policy matching (path glob)
│    ├─ Token bucket: per-IP, rate per second, burst capacity
│    ├─ Opsional distributed via Redis
│    └─ Jika token habis → 429 "RATELIMIT-001"
│
└─ 1.12 WAF Rule Check (Headers)
    └─ rule_engine.check_request(path, query, headers, ...)
        ├─ Built-in rules (SQLi, XSS, CMD injection via AST)
        ├─ Custom rules dari config.toml (regex, contains, prefix, suffix)
        ├─ Dynamic rules dari plugins/*.toml (auto-reload via config polling)
        └─ Jika match → 403 + log rule_id
```

---

### 2. `upstream_peer()` — Backend Selection

**File**: baris 980–1074

```
upstream_peer()
│
├─ 2.1 Load Balancing (Round Robin)
│   ├─ LOAD_BALANCER[vhost_name] → Vec<Backend>
│   ├─ Filter hanya healthy backend (health check tiap 15 detik via TCP connect)
│   ├─ Round robin counter atomic increment
│   └─ Jika semua unhealthy → fallback ke first backend
│
├─ 2.2 Backpressure Protection
│   ├─ BACKEND_ACTIVE_REQUESTS[backend_addr]++
│   ├─ Jika > max_concurrent_requests → return 503 "Backend Overloaded"
│   └─ Mencegah OOM saat backend lambat
│
├─ 2.3 WebSocket Routing
│   ├─ Jika websocket_security_enabled && Upgrade: websocket
│   └─ Route ke 127.0.0.1:24601 (WebSocket Security Proxy, bukan backend)
│
└─ 2.4 Peer Resolution
    ├─ Parse backend URL (http://, https://, atau bare host:port)
    ├─ Tentukan TLS (rustls) atau plain
    └─ Set connection timeout 5 detik
```

---

### 3. `upstream_request_filter()` — Outbound Request Modify

**File**: baris 1076–1108

```rust
// Inject header
X-Forwarded-For: <client_ip>
X-Request-ID: <uuid>

// Untuk WebSocket security proxy:
X-Jarswaf-Real-Backend: <actual_backend_url>
```

---

### 4. `request_body_filter()` — Body Inspection

**File**: baris 1172–1278

```
Pingora hook: dipanggil per chunk body (streaming)
│
├─ 4.1 Skip jika ctx.is_blocked sudah true
│
├─ 4.2 Buffer chunk
│   └─ Jika total buffer > body_limit → 413 "WAF-BODY-LIMIT"
│
└─ 4.3 end_of_stream → Full body ready
    ├─ String::from_utf8_lossy(&body_buffer)
    ├─ rule_engine.check_request(path, query, headers, body, ...)
    └─ Jika match → ctx.is_blocked = true + return 403
```

**Optimasi**: Setelah block, `body_buffer.clear()` + `shrink_to_fit()`.

---

### 5. `logging()` — Post-Request Cleanup & Log

**File**: baris 1110–1170

```rust
│
├─ 5.1 Decrement ACTIVE_CONNECTIONS[client_ip]
├─ 5.2 Decrement BACKEND_ACTIVE_REQUESTS[backend_addr]
└─ 5.3 Kirim WafLogEntry ke log channel (MPSC async)
    ├─ timestamp, client_ip, method, path
    ├─ action: PASS / ERROR / BLOCK
    ├─ rule_id + reason
    └─ Hanya dikirim jika log_level >= threshold
```

---

### 6. `fail_to_proxy()` — Upstream Error Handler

**File**: baris 1280–1298

```rust
│
├─ Match error type:
│   ├─ HTTPStatus(status) → gunakan status code asli
│   └─ Lainnya → 502 Bad Gateway
└─ Tampilkan custom error page (CSS glassmorphism dark theme)
```

---

## Rule Engine (rules.rs)

Lokasi: `src/rules/` — 3 submodul: `uri.rs`, `headers.rs`, `body.rs`.

### Built-in Rules

Stored as array `static RULES: &[Rule]`. Masing-masing punya:

| Field | Contoh |
|-------|--------|
| `id` | `SQLI-AST-001` |
| `name` | `Semantic SQL Injection` |
| `phase` | `Headers`, `Uri`, `Body` |
| `action` | `Block`, `Log` |
| `severity` | `Low`–`Critical` |
| `check` | `fn(&RequestInfo) -> bool` |

### Custom Rules (Config + Plugins)

```toml
`custom_rules`
id = "BLOCK-PHP-ADMIN"
name = "Block PHP Admin"
condition_type = "path"
operator = "contains"
condition_value = "/wp-admin"
action = "block"
action_value = "403"
enabled = true
```

Operator: `contains`, `prefix`, `suffix`, `regex`, `equals`.

Reload otomatis: config reloader polling `config.toml` tiap 2 detik. Perubahan → atomic swap via `ArcSwap<Config>`.

### AST Tokenizer

Untuk SQLi, XSS, CMD injection — bukan regex mentah:
1. Normalize input: recursive URL decode → HTML entity → NFKC Unicode → lowercase
2. Parse ke token tree (keyword, operator, string literal, number)
3. Match pattern terhadap tree (bukan string)

### Rate Limiter

- **Token Bucket**: per-IP. Rate (token/detik) + capacity (burst)
- **Distributed**: Opsional via Redis (set `[redis]` di config)
- **Cleanup**: Setiap 60 detik hapus entry idle > 5 menit
- **Kombinasi dengan Reputation**: Rate limit hit → tambah reputation score

### Auto-Remediation (Escalating)

```
record_block(ip)
│
├─ Sliding window 5 menit
├─ Setiap 5 block dalam window → escalation tier:
│   Tier 0 → 1:   60 detik   + XDP block
│   Tier 1 → 2:  300 detik
│   Tier 2 → 3: 1800 detik
│   Tier 3 → 4: 86400 detik (24 jam)
└─ Semua tier adalah temporary — auto-expire
```

### IP Reputation

- **LRU Cache**: 10.000 entries via `quick_cache`
- **Decay**: −1 point per menit, floor 0
- **Penalty**: Rate limit hit = +5, Blocked attack = +15
- **Threshold**: Reputation ≥ 50 → auto-blocklist + bot challenge trigger
- **Resets**: Tidak pernah reset manual — decay otomatis turunkan

---

## Memory Safety

### DashMap Cleanup

```rust
// Periodic cleanup setiap 30 menit
ACTIVE_CONNECTIONS.retain(|_, _| false);        // reset semua
SESSION_FINGERPRINTS.retain(|_, _| false);       // reset semua
BACKEND_ACTIVE_REQUESTS.retain(|_, _| false);    // reset semua
```

### Bounded Structures

| Map | Batas | Mekanisme |
|-----|-------|-----------|
| `ACTIVE_CONNECTIONS` | unbounded | Cleaned tiap 30 menit |
| `IP_REPUTATION` | 10.000 | LRU cache (quick_cache auto-evict) |
| `BLOCKED_IPS` | unbounded | Cleaned tiap 60 detik (>5 menit idle) |
| `RATE_LIMITER` | unbounded | Cleaned tiap 60 detik (>5 menit idle) |
| Blocklist | 100.000 | `BLOCKLIST_MAX_ENTRIES` + trim |

---

## eBPF XDP Module

Lokasi: `jarswaf-ebpf/`

```rust
pub async fn block_ip(&mut self, ip: Ipv4Addr) {
    // Insert IP ke eBPF map → kernel drop at XDP hook
    // BEFORE TCP/IP stack processing
}
```

- **Requires**: Linux ≥ 5.8, `aya` crate
- **Fungsi**: Drop paket dari IP terblokir sebelum habiskan CPU buat TCP handshake
- **Trigger**: Auto-remediation tier 0→1 (setelah 5 block dalam 5 menit)
- **Fallback**: Jika kernel tidak support eBPF → application-level block saja

---

## WebSocket Security Proxy

Lokasi: port `127.0.0.1:24601`

```
Client WS → Pingora detect Upgrade → route ke 127.0.0.1:24601
  → WebSocket Security Proxy:
     ├─ Parse WS frame
     ├─ Rule engine check tiap frame text (SQLi, XSS, CMD injection)
     └─ Forward aman ke backend asli (via X-Jarswaf-Real-Backend header)
```

---

## Diagram Alir Latar Belakang (Background Tasks)

```
Agent Process
├─ Pingora Server (JarsWafProxy)
├─ Log Worker (MPSC receiver → file/SQLite/ClickHouse/Controller)
├─ Config Reloader (polling config.toml tiap 2 detik)
├─ Memory Cleanup (tiap 30 menit, clear ACTIVE_CONNECTIONS etc.)
├─ Rate Limiter Cleanup (tiap 60 detik, clear idle entries)
├─ Health Checker (tiap 15 detik, TCP connect ke backend)
├─ WebSocket Security Proxy (127.0.0.1:24601)
├─ Metrics Reporter (jika Controller mode, kirim system metrics)
├─ Blocklist Sync (jika distributed, sync reputation antar node)
└─ XDP Manager (kernel-level blocklist update)
```

---

## Koneksi ke Vault

- [[cloudflare-ruleset-engine-phases]] — Inspirasi phase design jarsWAF
- [[waf-reverse-proxy-deepdive]] — Perbandingan WAF (jarsWAF vs ModSecurity vs Coraza vs Safeline)
- [[network-security]] — Konsep dasar firewall
- [[blueteam-detection-matrix]] — Logging & SIEM integration

---

## Cheatsheet: Kalau Interview / Investor Tanya

> **Q: "What happens when a request hits jarsWAF?"**
> A: 11 phases. Request masuk → extract IP + headers → match VHost → cek direct IP → slowloris → fingerprint → bot challenge → blocklist → geoblocking → rate limit → WAF rules. All in `request_filter()` BEFORE touching upstream. Body inspected separately streaming. Then load balance, backpressure, upstream. All logged async.

> **Q: "How is jarsWAF different from ModSecurity/Coraza?"**
> A: Rust + Pingora (same stack as Cloudflare). eBPF XDP for kernel-level DDoS. AST semantic tokenizer not regex-only. Distributed Agent-Controller architecture. Auto-remediation escalating tiers. Real-time dashboard.

> **Q: "How do you prevent OOM?"**
> A: Every unbounded DashMap has periodic cleanup (30 min wipe or 60 sec idle evict). Blocklist capped at 100k. Reputation LRU at 10k. Body buffer cleared + shrink after inspection. Backpressure prevents backend overload.

> **Q: "Can you explain the WebSocket security?"**
> A: Separate proxy on 127.0.0.1:24601. All WS upgrade requests from Pingora route here. Every text frame inspected by rule engine. Malicious frames get connection close.
