# Update Plan — jarsWAF Gen-3

> **Tanggal:** 2026-07-02
> **Status:** 🟡 Aktif
> **Target:** Stable, memory-safe, real-time distributed blocking

---

## 🎯 Phase 1: Memory Safety (Prevent OOM on 1GB VPS)

| # | Item | File | Effort | Status |
|---|------|------|--------|--------|
| 1 | **Periodic cleanup** `ACTIVE_CONNECTIONS`, `SESSION_FINGERPRINTS`, `BACKEND_ACTIVE_REQUESTS` — retensi 30 menit | `src/proxy_engine.rs` | ~15 baris | ✅ |
| 2 | **Body buffer limit** turunin default 10MB → 1MB | `src/proxy_engine.rs:378` | 1 baris | ✅ |
| 3 | **Bounded blocklist** — limit jumlah entry + TTL-based eviction | `src/agent/blocklist.rs`, `src/proxy_engine.rs` | ~30 baris | ✅ |
| 4 | **Connection counter guard** — periodic cleanup | `src/proxy_engine.rs` | ✅ Done | ✅ |

### Detail Teknis

```rust
// Periodic cleanup — tiap 30 menit
tokio::spawn(async {
    let mut interval = tokio::time::interval(Duration::from_secs(1800));
    loop {
        interval.tick().await;
        ACTIVE_CONNECTIONS.retain(|_, _| false);
        SESSION_FINGERPRINTS.retain(|_, _| false);
        BACKEND_ACTIVE_REQUESTS.retain(|_, _| false);
    }
});
```

---

## 🎯 Phase 2: Real-time Block Push (Wazuh-like)

| # | Item | File | Effort | Status |
|---|------|------|--------|--------|
| 5 | **Broadcast channel** untuk block commands di Controller | `src/controller/mod.rs` | ~10 baris | ✅ |
| 6 | **Handler `handle_agent_socket`** — kirim block command via WS | `src/controller/websocket.rs` | ~20 baris | ✅ |
| 7 | **Agent WS receiver** — parse command langsung insert ke DashMap | `src/agent/websocket.rs` | ~15 baris | ✅ |
| 8 | **REST API** `POST /api/v1/agent/block` — trigger dari Controller | `src/controller/handlers/threat_intel.rs` | ~30 baris | ✅ |

### Alur

```
POST /api/v1/agent/block { ip, ttl }
  → Controller broadcast::send BlockCommand
  → handle_agent_socket reads from rx
  → sends JSON over established WS to all connected agents
  → agent_websocket receives → inserts into blocklist DashMap
  → Agent's proxy_engine checks blocklist on next request
  → IP blocked immediately (200ms latency max)
```

---

## 🎯 Phase 3: Observability (Prometheus + Grafana)

| # | Item | File | Effort | Status |
|---|------|------|--------|--------|
| 9 | **Prometheus metrics module** — counters, gauges, histograms | `src/metrics.rs` | ~100 baris | ✅ |
| 10 | **`/metrics` endpoint** — serve prometheus-native + controller stats | `src/controller/handlers/metrics.rs` | ~20 baris | ✅ |
| 11 | **VictoriaMetrics push agent** — config + push task | `src/metrics.rs`, `src/config.rs`, `src/agent/mod.rs` | ~30 baris | ✅ |
| 12 | **Grafana dashboard JSON** | `docs/grafana-dashboard.json` | ~100 baris | ✅ |

### Resource Usage

| Mode | RAM (agent) | RAM (total) | Cocok |
|------|-------------|-------------|-------|
| SQLite-only (sekarang) | ~5MB | ~30MB | VPS 1GB |
| Prometheus Pushgateway | ~20MB | ~80MB | VPS 2GB |
| VictoriaMetrics agent | ~15MB | ~50MB | VPS 1GB |
| Full Prometheus server | ~200-500MB | ~500MB | Controller 4GB |

---

## 🎯 Phase 4: LRU & Bounded Caches

| # | Item | File | Effort | Status |
|---|------|------|--------|--------|
| 13 | **Bounded DashMap blocklist** — MAX_ENTRIES 100k + trim_dashmap | `src/proxy_engine.rs` | ✅ covered (Phase 1) | ✅ |
| 14 | **LRU reputation cache** — quick_cache 10k entries | `src/rules.rs` | ~20 baris | ✅ |
| 15 | **Rate limiter token bucket** — bounded per IP, cleanup tiap 5 menit | `src/rules.rs` | ✅ done (pre-existing) | ✅ |

---

## 🎯 Phase 5: Agent-Controller Reliability

| # | Item | File | Effort | Status |
|---|------|------|--------|--------|
| 16 | **WebSocket reconnect with exponential backoff** — 1s → 5m | `src/agent/websocket.rs` | ~15 baris | ✅ |
| 17 | **Agent heartbeat/ping** — deteksi dead agent (120s timeout) | `src/controller/websocket.rs` + `src/agent/websocket.rs` | ~20 baris | ✅ |
| 18 | **Blocklist sync priority** — WS push > poll | `src/agent/blocklist.rs` | ✅ done (Phase 2) | ✅ |

---

## 📋 Status Checklist Global

```
Phase 1: [✅✅✅✅] 4/4 — Memory Safety
Phase 2: [✅✅✅✅] 4/4 — Real-time Block Push
Phase 3: [✅✅✅✅] 4/4 — Observability (Prometheus + VictoriaMetrics + Grafana)
Phase 4: [✅✅✅]   3/3 — LRU & Bounded Caches
Phase 5: [✅✅✅]   3/3 — Agent-Controller Reliability
```

### Progress Detail

```
✅ 1. ACTIVE_CONNECTIONS / SESSION_FINGERPRINTS periodic cleanup — proxy_engine.rs:start_memory_cleanup()
✅ 2. Body buffer limit 10MB → 1MB — proxy_engine.rs:378
✅ 3. Bounded blocklist (MAX_ENTRIES + trim_dashmap() integration in agent/blocklist.rs)
✅ 4. Connection counter cleanup in start_memory_cleanup() — ACTIVE_CONNECTIONS purge tiap 30 menit
✅ 5-8. Real-time block push via WebSocket — Controller → Agent broadcast implemented
        (BlockCommand, block_tx channel, POST /api/v1/agent/block, agent WS receiver)
✅ 9-12. Prometheus native metrics module + /metrics endpoint + Grafana Dashboard JSON
✅ 13. Bounded DashMap blocklist — covered by Phase 1 (MAX_ENTRIES + trim_dashmap)
✅ 14. LRU reputation cache — quick_cache 10k entries (rules.rs: IP_REPUTATION)
✅ 16. WS reconnect exponential backoff 1s→5m (agent/websocket.rs)
✅ 17. Agent heartbeat: Ping frames tiap 30s + controller timeout 120s
✅ 18. Blocklist sync priority — WS push inserts directly, poll is backup
```

---

## ⚡ Quick Start Build

```bash
# Build & test
cargo build --release
cargo clippy --all-targets --all-features

# Test low-RAM scenario
docker run --memory=1g --memory-swap=1g -v $(pwd):/app rust:latest cargo build --release

# Monitor memory
watch -n 1 'ps aux | grep jarswaf | grep -v grep'
```
