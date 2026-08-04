---
title: "NAH Lifecycle — Peta Semua Lifecycle di jarsWAF"
tags:
  - jarswaf
  - lifecycle
  - architecture
  - waf
  - rust
aliases:
  - NAH Lifecycle
  - jarsWAF Lifecycle Master
created: 2026-07-10
updated: 2026-07-10
status: pending
---

# NAH Lifecycle — Peta Semua Lifecycle jarsWAF

> **NAH** = Not Another Hack (proyek WAF).  
> Lifecycle ada **di mana-mana**: proxy, agent, controller, eBPF, log, config, memory, rule engine, blocklist, rate limiter, circuit breaker, health checker, auto-remediation.  
> Dokumen ini peta jalan semua lifecycle dan hubungannya.

---

## 1. Agent Startup Lifecycle

**Source**: `src/agent/mod.rs` — `run_agent()`

```
main.rs
  └─ Cli parse (agent vs controller)
      └─ run_agent(config, controller_url, token)
           │
           ├─ 1.1 load_config → Config struct
           ├─ 1.2 rate_limiter_cleanup() → background task
           ├─ 1.3 SQLite init → (jika mode=sqlite/clickhouse)
           ├─ 1.4 MPSC channel (log_tx, log_rx) — buffer 10000
           ├─ 1.5 spawn log_worker(log_rx, cfg)
           ├─ 1.6 spawn config_reloader (poll 2s)
           ├─ 1.7 load blocklist from file → DashMap
           ├─ 1.8 build AppState { config, log_tx, blocklist }
           ├─ 1.9 jika controller_url ada:
           │    ├─ spawn metrics_collector
           │    ├─ spawn config_sync_websocket
           │    └─ status → "distributed agent mode"
           ├─ 1.10 spawn blocklist_sync
           ├─ 1.11 start_memory_cleanup() — 30 min periodic
           ├─ 1.12 spawn metrics_pusher (jika push_url ada)
           └─ 1.13 server::run_server(cfg, state) → Axum

FAILURE MODE:
  - Config gagal load → exit (expect)
  - SQLite gagal init → error log, lanjut tanpa SQLite
  - Blocklist file gak ada → DashMap kosong, lanjut
  - Controller unreachable → retry di background tasks
```

---

## 2. Pingora Request Lifecycle (10 Phase)

**Source**: `src/proxy_engine.rs`

```
Client → pingora::Server
    │
    ├─ 0. new_ctx()         ← JarsWafCtx per request
    ├─ 1. request_filter()  ← 12 sub-fase (lihat doc existing)
    ├─ 2. upstream_peer()   ← round-robin + backpressure
    ├─ 3. upstream_request_filter() ← inject X-Forwarded-For
    ├─ 4. request_body_filter() ← streaming + WAF body check
    ├─ 5. response_body_filter() ← inspect response
    ├─ 6. response_filter() ← modify response
    ├─ 7. logging()         ← decrement counters + kirim log
    ├─ 8. fail_to_proxy()   ← error handler upstream
    └─ 9. error_while_proxy() ← error handler proxy
```

**Lihat dokumentasi lengkap**: [[jarswaf-lifecycle-architecture]]

---

## 3. Controller Startup Lifecycle

**Source**: `src/controller/mod.rs` — `run_controller()`

```
controller --port 8080
  │
  ├─ 3.1 Generate admin_token (UUID) jika belum ada → simpan ke config
  ├─ 3.2 load_config → Config
  ├─ 3.3 SQLite init (request_log table + index)
  ├─ 3.4 Init broadcast channels:
  │    ├─ tx/rx (logs — 10000 buffer)
  │    ├─ config_tx/rx (config changes — 100 buffer)
  │    └─ block_tx/rx (block commands — 1000 buffer)
  ├─ 3.5 Load stats from SQLite (24h window)
  ├─ 3.6 Build ControllerState
  ├─ 3.7 Build Axum router:
  │    ├─ /api/v1/agents/* (register, metrics, list)
  │    ├─ /api/v1/logs/* (stream, query, export, clear)
  │    ├─ /api/v1/config/* (get, update, history, rollback)
  │    ├─ /api/v1/vhosts, /custom-rules, /allowlists, /blacklists
  │    ├─ /api/v1/stats, /reputation/blocklist, /threat-intel
  │    ├─ /api/v1/ssl/* (certificates, renew)
  │    ├─ /ws/dashboard, /ws/agent
  │    └─ Svelte dashboard (ServeDir fallback)
  ├─ 3.8 CORS → any origin (dev mode)
  ├─ 3.9 TcpListener → 0.0.0.0:8080
  └─ 3.10 axum::serve → forever

FAILURE MODE:
  - Port 8080 terpakai → crash (expect)
  - SQLite korup → crash di init_sqlite_db
  - Dashboard dist/ gak ada → 404 fallback
```

---

## 4. Log Pipeline Lifecycle

**Source**: `src/logging.rs`

```
WafLogEntry (dari proxy_engine)
  → log_tx.send(entry)  ─async MPSC channel (10k buffer)─→  log_worker(rx)

3 mode:
                          ┌─ file: write JSONL + rotate per 1MB/1000 line
  log_worker(rx, cfg) ───├─ remote: file + batch push ke controller (interval + size)
                          └─ sqlite/clickhouse: batch insert via persistent conn

PERSISTENCE FLOW:
  File:     entry → writeln → rotate_if_needed (1000 line check)
  SQLite:   batch → Vec<WafLogEntry> → tiap 1 detik → spawn_blocking → INSERT tx
  Remote:   batch → Vec<WafLogEntry> → tiap push_interval → HTTP POST ke controller
  ClickHouse: same as SQLite (via HTTP POST, bukan native protocol)

ROTATION:
  max_log_size_mb reach → jarswaf.log → jarswaf.log.1 → ... → jarswaf.log.N (delete oldest)

FAILURE MODE:
  - Channel overflow (10k buffer penuh) → oldest drop (tokio MPSC behavior)
  - SQLite write gagal → error log, batch skip
  - Controller unreachable → retry next interval, logs safe di local
```

---

## 5. Config Reloader Lifecycle

**Source**: `src/agent/mod.rs` baris 51-85

```
Background task (spawn loop 2s):
  ├─ 5.1 fs::metadata(config_path).modified()
  ├─ 5.2 Bandingkan last_modified
  ├─ 5.3 Jika berubah:
  │    ├─ config::load_config(path)
  │    ├─ GLOBAL_CONFIG.store(Arc::new(new_cfg))  ← ArcSwap atomic
  │    └─ info log
  └─ 5.4 Jika error → error log, config lama tetap dipakai

Atomic swap → zero race window:
  - proxy_engine membaca GLOBAL_CONFIG.load() tiap request
  - Config baru langsung berlaku untuk request berikutnya
  - Tidak perlu restart process

FAILURE MODE:
  - Config baru corrupt → config lama tetap aktif
  - File dihapus → error terus tiap 2s, config lama dipakai
```

---

## 6. Memory Cleanup Lifecycle

**Source**: `src/proxy_engine.rs` — `start_memory_cleanup()`

```
Background task (tiap 30 menit):
  ├─ ACTIVE_CONNECTIONS.retain(|_, _| false)     → reset
  ├─ SESSION_FINGERPRINTS.retain(|_, _| false)    → reset
  └─ BACKEND_ACTIVE_REQUESTS.retain(|_, _| false) → reset

Background tasks (tiap 60 detik):
  ├─ BLOCKED_IPS → retain jika < 5 menit idle
  ├─ RATE_LIMITER → retain jika < 5 menit idle
  └─ IP_REPUTATION → LRU auto-evict (quick_cache)

BOUNDED STRUCTURES:
  - BLOCKLIST_MAX_ENTRIES = 100.000 → retain order trim
  - IP_REPUTATION = 10.000 → quick_cache LRU
  - body_buffer → clear + shrink_to_fit per request

FAILURE MODE:
  - Cleanup lambat → DashMap tumbuh unbounded (memory leak gradual)
  - HR timer drift → periodic task bisa melebar
```

---

## 7. eBPF XDP Lifecycle

**Source**: `src/xdp.rs`

```
XdpManager::new()
  ├─ 7.1 Load Ebpf::load_file("/app/jarswaf-ebpf")
  │    └─ fallback: "target/bpfel-unknown-none/release/jarswaf-ebpf"
  ├─ 7.2 Jika gagal → warn + None, eBPF disabled
  └─ 7.3 Self { bpf: Option<Ebpf> }

.attach(interface)
  ├─ 7.4 bpf.as_mut()? → program_mut("jarswaf_ebpf")
  ├─ 7.5 program.load() → XDP program
  └─ 7.6 program.attach(interface, XdpMode::default())

.block_ip(ip) — dipanggil oleh auto-remediation tier 0→1
  ├─ 7.7 bpf.map_mut("BLOCKLIST") → HashMap<u32, u8>
  ├─ 7.8 INSERT ip_u32 → 1
  └─ 7.9 Kernel drop paket dari IP ini SEBELUM TCP/IP stack

NOT IMPLEMENTED:
  - Tidak ada detach() — XDP permanen attach
  - Tidak ada remove_ip() — IP tetap di blocklist kernel sampai process mati
  - Tidak ada graceful shutdown

FAILURE MODE:
  - Kernel < 5.8 / CONFIG_BPF=n → disabled silently
  - Interface gak ada → error di attach
  - eBPF bytecode mismatch → crash di program_mut
```

---

## 8. Rule Engine Lifecycle

**Source**: `src/rules.rs`, `src/rules/{uri,headers,body}.rs`

```
INIT (compile time):
  static RULES: &[Rule] = [...]  // array literal
  ├─ id, name, phase, action, severity, check: fn()
  └─ 3 fase: Uri, Headers, Body

CUSTOM RULES (runtime):
  config.toml → `custom_rules`
  ├─ condition_type: path/header/cookie/body/query/method
  ├─ operator: contains/prefix/suffix/regex/equals
  └─ action: block/log

PER-REQUEST EXECUTION:
  request_filter() → rule_engine.check_request(path, query, headers)
    ├─ Normalize: URL decode → HTML entity → NFKC → lowercase
    ├─ AST tokenizer (SQLi/XSS/CMD injection — bukan regex mentah)
    └─ Match pattern → semantic tree

  request_body_filter() → rule_engine.check_request(...+ body)
    └─ Sama, tapi body (streaming, per chunk)

RELOAD METHOD:
  - Config change → GLOBAL_CONFIG.store() → next request baca config baru
  - Custom rules dari config → hot reload, tidak perlu restart

FAILURE MODE:
  - Regex bomb → WAF_SEMAPHORE (4 concurrent) → lewati inspeksi jika penuh
  - AST parser panic → catch di phase → allow (bukan block)
```

---

## 9. Agent-Controller WebSocket Lifecycle

**Source**: `src/agent/websocket.rs`, `src/controller/websocket.rs`

```
AGENT STARTUP:
  ├─ 9.1 HTTP POST /api/v1/agents/register → token + metadata
  ├─ 9.2 Receive agent_id dari controller
  └─ 9.3 WebSocket connect /ws/agent → persistent

CONTROLLER SIDE:
  ├─ 9.4 Agent terdaftar di agent_registry HashMap
  ├─ 9.5 Metrics masuk via HTTP POST /api/v1/agents/metrics
  └─ 9.6 Block command via broadcast channel → agent WS

AGENT SIDE:
  ├─ 9.7 Terima config update dari controller
  ├─ 9.8 Terima block/unblock command
  ├─ 9.9 Kirim metrics periodik ke controller
  └─ 9.10 Reconnect logic (backoff)

FAILURE MODE:
  - WS disconnect → backoff reconnect + log
  - Token invalid → 401 → stop reconnect
  - Controller down → agent lanjut standalone
```

---

## 10. Blocklist Lifecycle

**Source**: `src/agent/blocklist.rs`

```
FILE → MEMORY — SYNC — XDP
  ├─ 10.1 Load dari file JSON (blocklist.json) startup
  ├─ 10.2 Store di DashMap<IpAddr, ()> — shared Arc
  ├─ 10.3 Update dari 3 source:
  │    ├─ WAF rule trigger → auto-block
  │    ├─ Controller push via WS → block/unblock
  │    └─ Sync dengan controller periodik
  ├─ 10.4 Jika IP mencapai threshold → trigger XDP block
  └─ 10.5 Auto-expire: block temporary (Tier 1-4 lifetime)

FILE SYNC:
  - save_blocklist_to_file: atomic write (tmp → rename)
  - load_blocklist_from_file: startup + periodic reload

FAILURE MODE:
  - File corrupt → HashSet kosong
  - Disk full → save gagal → error log
  - XDP map full? → cap terbatas di eBPF (biasanya 16k)
```

---

## 11. Rate Limiter Lifecycle

**Source**: `src/rules.rs` (internal)

```
INIT:
  Static DashMap<IpAddr, TokenBucket>
  TokenBucket { tokens: f64, last_refill: Instant }

PER-REQUEST:
  ├─ 11.1 Cari rate limit policy (path glob match)
  ├─ 11.2 Refill token berdasarkan waktu
  ├─ 11.3 Jika token ≥ cost → kurangi, allow
  └─ 11.4 Jika token < cost → 429 + reputation +5

CLEANUP (60 detik):
  Retain entries idle > 5 menit

DISTRIBUTED:
  Opsional via Redis (set [redis] di config)
  └─ Token bucket sync antar node

REPUTATION INTEGRATION:
  Rate limit hit → reputation_score +5
  Reputation ≥ 50 → auto-blocklist + bot challenge trigger
```

---

## 12. Circuit Breaker Lifecycle

**Source**: `src/proxy_engine.rs` — `BACKEND_FAILURE_COUNTS`

```
STRUCTURE:
  DashMap<String {backend_url}, AtomicUsize>

FLOW:
  ├─ 12.1 Backend response error → counter++
  ├─ 12.2 Jika counter ≥ CIRCUIT_BREAKER_THRESHOLD (5):
  │    ├─ Backend marked "tripped"
  │    └─ Excluded dari round-robin selection
  └─ 12.3 Health checker sukses → counter reset 0 → backend kembali

  BACKEND_ACTIVE_REQUESTS:
    - Increment di upstream_peer()
    - Decrement di logging() post-request
    - Jika > max_concurrent → 503 "Backend Overloaded"
```

---

## 13. Health Checker Lifecycle

**Source**: `src/agent/server.rs` (implied)

```
BACKGROUND (15 detik):
  ├─ 13.1 Iterasi semua backend registered
  ├─ 13.2 TCP connect (timeout 5s)
  ├─ 13.3 Jika sukses → backend healthy
  └─ 13.4 Jika gagal → backend unhealthy

LOAD BALANCER:
  - Filter hanya healthy backend
  - Jika semua unhealthy → fallback ke first backend
  - Round-robin counter (atomic increment)
```

---

## 14. Auto-Remediation Escalation Lifecycle

**Source**: `src/agent/blocklist.rs` (implied from jarswaf-lifecycle-architecture doc)

```
record_block(ip) — dipanggil setiap block decision
  └─ Sliding window 5 menit
      ├─ Tier 0 (baseline): aplikasi block saja
      ├─ Tier 0→1 (5 block/5m): 60 detik + eBPF XDP block
      ├─ Tier 1→2: 300 detik
      ├─ Tier 2→3: 1800 detik
      └─ Tier 3→4: 86400 detik (24 jam)

  Semua tier temporary — auto-expire via cleanup 60 detik.

  XDP trigger path:
  auto-remediation → blocklist.insert(ip) → XDP::block_ip(ip)
  → kernel drop at XDP hook → zero CPU untuk TCP handshake
```

---

## Matriks Koneksi Antar Lifecycle

| Lifecycle | Dipicu oleh | Memicu | Data shared |
|-----------|-------------|--------|-------------|
| Agent Startup | `main.rs` | Semua lifecycle di proses yang sama | Config Arc |
| Controller Startup | `main.rs` | WS, logs, agent registry | ControllerState, broadcast |
| Request Phase | Pingora event loop | Log pipeline, Rule engine, Auto-remediation | JarsWafCtx, GLOBAL_CONFIG |
| Log Pipeline | request_filter → logging() | — | WafLogEntry via MPSC |
| Config Reloader | Timer (2s) | GLOBAL_CONFIG.store() | ArcSwap<Config> |
| Memory Cleanup | Timer (30m/60s) | — | DashMap retain |
| eBPF XDP | Auto-remediation tier 0→1 | — | XDP BLOCKLIST map |
| Rule Engine | Request phase | — | GLOBAL_CONFIG |
| Agent-Controller WS | Agent startup | — | WebSocket, ControllerState |
| Blocklist | File load + rule trigger + WS push | eBPF XDP | DashMap + file + XDP |
| Rate Limiter | Timer (60s) | Reputation score | DashMap + Redis |
| Circuit Breaker | Backend error | Backend exclusion | DashMap<AtomicUsize> |
| Health Checker | Timer (15s) | Load balancer state | — |
| Auto-Remediation | Rule match | eBPF block + escalation | Sliding window |

---

## Debugging Checklist: Kalau "Ada di Mana-mana"

| Gejala | Cek Lifecycle |
|--------|---------------|
| Config berubah tapi gak ngefek | Config Reloader (5) — cek mtime, path |
| Memory naek terus | Memory Cleanup (6) — DashMap leak |
| Log gak sampai controller | Log Pipeline (4) — controller_url, batch size |
| XDP gak jalan | eBPF (7) — kernel version, .o path |
| Backend sering 503 | Circuit Breaker (12) + Health Checker (13) |
| Agent gak terdaftar | Agent-Controller WS (9) — token, backoff |
| Block IP gak hilang2 | eBPF (7) — remove_ip belum implement |
| Rate limit gak konsisten | Rate Limiter (11) — distributed sync, Redis |

---

## Koneksi Vault

- [[jarswaf-lifecycle-architecture]] — detail 10 phase Pingora + sub-fase request_filter
- [[waf-reverse-proxy-deepdive]] — perbandingan WAF
- [[cloudflare-ruleset-engine-phases]] — inspirasi phase design
- [[osquery-build-methodology]] — inspirasi monitoring
