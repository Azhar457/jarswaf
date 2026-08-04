# jarsWAF — Rencana Siklus 5: AI/ML Anomaly Detection Audit

**Status:** Planned (2026-08-02)
**Terkait:** [[waf-red-team-cycle2-wasm-honeypot-ratelimit]], [[waf-red-team-cycle3-nosql-proto-dlp-headers]], [[waf-red-team-cycle4-ssrf-upload-graphql-csrf]], [[waf-ml-anomaly-detection]]

---

## Konteks

Cycle 2–4 sudah menutup rule engine (WASM, honeypot, rate limiter, NoSQL, prototype pollution, DLP, security headers) dan edge components (SSRF, upload, GraphQL, CSRF). Gap terbesar berikutnya sesuai `DEVELOPMENT-REFERENCE.md` dan `jarswaf-plan.md` adalah **AI/ML-based detection** — signature-based rule engine lemah terhadap zero-day dan payload yang berevolusi.

## Scope Audit

1. **ONNX Runtime integration** (`tract-onnx` di Cargo.toml) — verifikasi model loading, inference path, dan error handling (fail-open vs fail-closed).
2. **Anomaly scoring pipeline** — apakah feature extraction (header entropy, payload length, token frequency) benar-benar di-wire ke decision path atau hanya dead code.
3. **ML payload classification** — apakah model benar-benar mengklasifikasi SQLi/XSS/RCE yang tidak match signature database.
4. **Threshold tuning** — static vs adaptive threshold; false positive rate di traffic normal.
5. **Performance overhead** — inferensi ONNX di critical path vs async; p99 latency impact.

## Deliverables

- [ ] Cycle 5 note: `waf-red-team-cycle5-ml-anomaly-detection.md` (format sama dengan cycle 2-4)
- [ ] Test cases untuk ML engine (bukan cuma rule engine)
- [ ] Benchmark: throughput/latency dengan ML aktif vs non-aktif

## Referensi

- `waf-ml-anomaly-detection.md` (vault, umum) — ONNX & feature engineering
- `jarswaf-plan.md` §1 — Kecerdasan Buatan untuk Deteksi Anomali
- DEVELOPMENT-REFERENCE.md — gap analysis P0/P1
