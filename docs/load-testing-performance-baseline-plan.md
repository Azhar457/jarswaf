# jarsWAF — Rencana E2E Load Testing & Performance Baseline

**Status:** Planned (2026-08-02)
**Terkait:** [[waf-red-team-cycle2-wasm-honeypot-ratelimit]], REDTEAM-REPORT.md

---

## Konteks

Pengujian keamanan jarsWAF sudah kuat (cycle 2-4, REDTEAM-REPORT, bypass 6-7). Namun **belum ada satu angka pun** tentang performa: throughput, latency, memory di bawah serangan. Hierarchy WAF menyebut trade-off performance overhead per level, tapi tidak ada baseline numerik untuk jarsWAF sendiri.

## Scope

1. **Baseline tanpa WAF** — proxy passthrough murni (Pingora tanpa rule engine):
   - Throughput (req/s), p50/p95/p99 latency, error rate
2. **Baseline dengan WAF aktif** — rule engine penuh:
   - Overhead % vs baseline
3. **Di bawah serangan**:
   - SQLi/XSS flood → throughput drop, CPU/memory
   - Rate limiter activation → 429 behavior
   - WASM plugin aktif vs non-aktif
   - DLP response scan aktif
4. **Stabilitas** — soak test 10 menit, memory leak check (RSS growth)

## Tools

- `wrk` / `oha` (HTTP benchmark)
- `hey` untuk concurrency
- GoTestWAF (sudah ada di external/) untuk attack simulation + timing
- `/proc/<pid>/status` VmRSS monitoring

## Deliverables

- [ ] Note: `waf-performance-baseline.md` di docs/
- [ ] Tabel angka: {mode} × {req/s, p50, p99, mem}
- [ ] Rekomendasi config (thread pool, buffer, batch size)

## Referensi

- REDTEAM-REPORT.md — metrik keamanan (sudah ada)
- `algorithmic_cost_analysis.md` — analisis biaya algoritma
- `waf-reverse-proxy-deepdive.md` — trade-off performance per level
