# Audit Report: jarsWAF

**Project**: `jarsWAF`
**Path**: `/mnt/data_d/Projects/jarswaf`
**Audit Date**: 2026-08-02
**Overview**: Rust WAF (Web Application Firewall) with eBPF/XDP layer, proxy engine, rule engine, agent, dashboard. 73 Rust source files, 21,062 LOC, 55 rule IDs, 150 unit tests, 651 dependencies.

73 files / ~800 KB pure code across 221 tracked files

## 1. Overall Statistics

| Metric | Value |
|--------|-------|
| Rust source files | 73 |
| Rust LOC | 21,062 |
| Tracked files (git) | 221 |
| Dependencies (Cargo.lock) | 651 |
| Rule IDs (unique) | 55 |
| Unit tests | 150 |
| Commits | 83 |
| Contributors | 1 (azhar457/Azhar) |
| Branch | dev (ahead of origin by 3) |

## Directory Breakdown

| Directory | Files | Role |
|-----------|-------|------|
| `src/` | 73 | Core WAF (proxy, rules, rule_engine, agent, controller, grpc, wasm) |
| `src/rules/` | 18 | Attack detection rules (SQLi, XSS, REVSHELL ×10, etc.) |
| `src/controller/` | 21 | API handlers, threat intel |
| `src/rule_engine/` | 4 | DSL + SecLang parser + phase engine |
| `dashboard/` | ~30 | Svelte dashboard (dist, node_modules) |
| `jarswaf-ebpf/` | 3 | eBPF/XDP layer (XDP_DROP, blocklist map) |
| `tests/` | 2 | Integration tests |
| `xtask/` | 4 | Build tasks |
| `helm/` | 1 | Helm chart |
| `docs/` | ~20 | Architecture, audit, redteam cycle plans |
| `external/` | 95MB | 3rd-party reference repos (gitignored) |

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Rust (edition 2021) |
| Proxy | pingora 0.4 (cloudflare) |
| HTTP | axum 0.7, hyper 1, hyper-util |
| TLS | rustls 0.23 (ring), tokio-rustls, rustls-acme |
| WASM sandbox | wasmtime 29 |
| ML | tract-onnx 0.21 (anomaly detection) |
| gRPC | tonic 0.11, prost 0.12 |
| Redis | redis 0.25 |
| SQLite | rusqlite 0.31 (bundled) |
| Dashboard | Svelte (npm) |
| eBPF | aya (jarswaf-ebpf) |
| Crypto | chacha20poly1305, sha2 |

## 7. Git Repositories & Activity

| Repo | Total Commits | Recent Commits | Last Commit |
|------|--------------|----------------|-------------|
| jarswaf | 83 | 3 unpushed | 2026-08-02 (4067a7a) |

## Audit Summary

### Project Profile
1. Single-maintainer project (azhar457, 83 commits, active daily). Branch `dev` is 3 commits ahead of origin — recent work not yet pushed.
2. Layered WAF: eBPF/XDP (L3/L4) → proxy_engine (L7) → rule engine (4-phase CRS-style + DSL + SecLang parser) → WASM plugins → agent (gossip) → dashboard.
3. Mature detection surface: 55 rule IDs across 18 rule modules, 150 unit tests, 2 integration test files, OWASP ZAP CI job.
4. Heavy dependency surface: 651 Cargo.lock deps (pingora, wasmtime, tract-onnx, tonic/prost pinned older versions — cargo audit mitigated via .cargo/audit.toml ignore list).
5. Target artifact bloat: `target/` 26GB, `external/` 95MB (gitignored reference repos).

### Key Risks
1. **26GB build artifacts in `target/`** — disk pressure; periodic `cargo clean` needed (or use a CI cache instead of local builds).
2. **Pinned older deps** (pingora 0.4, wasmtime 29, protobuf 2, tract-onnx 0.21) — transitive vulnerabilities mitigated only via `.cargo/audit.toml` ignore list; upgrade requires major refactor.
3. **MULTIPART-PART-LIMIT rule exists but NOT wired** — parser in `src/rules/multipart.rs` (max 100 parts) but rule not in test_config.toml rules list / not in `is_toggled_category()` — 1000-part uploads bypass multipart inspection.
4. **3 unpushed commits** on `dev` — risk of local-only work loss.
5. Single maintainer + 26GB target means no CI artifact caching strategy; devsecops.yml runs `cargo audit` (reads .cargo/audit.toml).

### Priority Actions
1. Wire MULTIPART-PART-LIMIT into the rule engine (`is_toggled_category()`) — parser exists, detection gap.
2. `cargo clean` + verify CI rebuilds from scratch (26GB → ~1GB).
3. Push the 3 local commits to origin/dev.
4. Schedule dependency upgrade window for pingora/wasmtime (P1), audit.toml is a stopgap.
5. Consider `sccache` or CI-only builds to avoid local 26GB target.

## Asset Triage

| Module | Function | Third-Party | Deps | Activity | Quality | Verdict |
|--------|----------|-------------|------|----------|---------|---------|
| `src/proxy_engine.rs` | Reverse-proxy hot path (2,231 LOC) | pingora 0.4, rustls | heavy | high | solid layering, monolith | **Core Cornerstone** |
| `src/rules.rs` | Rule registry + dispatch (2,620 LOC) | — | none | high | central rule table, 55 IDs | **Core Cornerstone** |
| `src/rule_engine/mod.rs` | 4-phase CRS-style engine (2,020 LOC) | — | none | high | well-structured phases | **Core Cornerstone** |
| `src/rule_engine/dsl.rs` | DSL + SecLang parser (608+541 LOC) | nom 7 | low | medium | active development | **Purify & Merge** |
| `src/rules/body.rs` | Body deep inspection (705 LOC) | regex | low | high | AST parsing, DLP | **Core Cornerstone** |
| `src/config.rs` | Config handling (963 LOC) | toml, serde | low | high | solid | **Core Cornerstone** |
| `src/logging.rs` | Audit logging (631 LOC) | tracing | low | high | PASS/BLOCK logging | **Core Cornerstone** |
| `src/rules/trust.rs` | IP trust (494 LOC) | maxminddb | medium | medium | geo/trust lists | **Purify & Merge** |
| `src/rules/redteam.rs` | Red-team rules (452 LOC) | — | low | high | adversarial rules | **Core Cornerstone** |
| `src/rules/headers.rs` | Header rules (429 LOC) | — | low | high | XFF, HPP, smuggling | **Core Cornerstone** |
| `src/rules/multipart.rs` | Multipart parser (315 LOC) | — | low | medium | **rule NOT wired to engine** | **Purify & Merge** |
| `src/rules/api.rs` | API rules (316 LOC) | — | low | medium | REST API protection | **Core Cornerstone** |
| `src/rules/anomaly.rs` | Anomaly scoring (313 LOC) | — | low | medium | ML-anomaly rules | **Purify & Merge** |
| `src/wasm.rs` | WASM plugin sandbox (307 LOC) | wasmtime 29 | medium | medium | fail-closed + fuel 50k | **Core Cornerstone** |
| `src/honeypot.rs` | Fake service listeners (305 LOC) | — | low | medium | MySQL/PG/Redis handshake | **Purify & Merge** |
| `src/agent/mod.rs` | Gossip agent (386 LOC) | — | low | medium | anti-replay + TTL | **Purify & Merge** |
| `src/controller/` | API handlers (21 files) | axum | medium | high | threat intel, dashboard API | **Core Cornerstone** |
| `src/grpc/` | gRPC layer (3 files) | tonic 0.11 | low | low | Phase 10 | **Reshape & Extract** |
| `jarswaf-ebpf/` | eBPF/XDP layer | aya | low | medium | XDP_DROP, blocklist map | **Core Cornerstone** |
| `dashboard/` | Svelte dashboard | svelte, npm | medium | high | dist built, node_modules | **Core Cornerstone** |
| `external/` | Reference repos (95MB) | gitignored | none | static | reference only | **Completely Retire** (from repo — move out) |

### 1.1 Proxy Engine — hot path

**Physical Location**: `src/proxy_engine.rs`
- **Capability Matrix**: reverse proxy, TLS termination, rule dispatch
  - **Core Code Modules**:
    - `ProxyEngine` / `PhaseProcessor`
  - **Dependencies**: pingora 0.4, rustls 0.23, hyper 1, ahash
  - **Third-Party Libs**:
    - pingora 0.4 (proxy)
    - rustls 0.23 (TLS, ring provider)
  - **Code Size**: 2,231 lines, ~80 KB
  - **Quality Assessment**:
    - Architecture: solid layering, monolith hot path
    - Legacy: none
  - **Activity**: high (commits in last 2 weeks)
  - **Verdict**: **Core Cornerstone**

### 1.2 Rule Registry — dispatch table

**Physical Location**: `src/rules.rs`
- **Capability Matrix**: rule ID registry, enable/disable, match dispatch
  - **Core Code Modules**:
    - `RuleRegistry` / `is_rule_enabled`
  - **Dependencies**: none external
  - **Third-Party Libs**: none
  - **Code Size**: 2,620 lines, ~95 KB
  - **Quality Assessment**:
    - Architecture: central table, 55 unique rule IDs (no dup match arms; 5 apparent dups are unit-test asserts)
    - Legacy: none
  - **Activity**: high
  - **Verdict**: **Core Cornerstone**

### 1.3 Rule Engine — phase pipeline

**Physical Location**: `src/rule_engine/mod.rs`
- **Capability Matrix**: 4-phase CRS-style inspection (header/body/response), anomaly scoring
  - **Core Code Modules**:
    - `PhaseProcessor` / `RuleEngine`
  - **Dependencies**: regex, dashmap
  - **Third-Party Libs**: none
  - **Code Size**: 2,020 lines, ~75 KB
  - **Quality Assessment**:
    - Architecture: well-structured phase pipeline
    - Legacy: none
  - **Activity**: high
  - **Verdict**: **Core Cornerstone**

### 1.4 Multipart Parser — orphaned rule

**Physical Location**: `src/rules/multipart.rs`
- **Capability Matrix**: multipart/form-data parsing, part limit enforcement (100)
  - **Core Code Modules**:
    - `MULTIPART-PART-LIMIT` rule (line 14)
  - **Dependencies**: none
  - **Third-Party Libs**: none
  - **Code Size**: 315 lines, ~12 KB
  - **Quality Assessment**:
    - Architecture: parser solid, but rule NOT in test_config.toml rules list and NOT in `is_toggled_category()` — **never enabled**; 1000-part uploads bypass inspection (verified gap)
    - Legacy: none
  - **Activity**: medium
  - **Verdict**: **Purify & Merge** — wire into rule engine

## Appendix

| Library | Version | Location | Size | Used By | Usage | Assessment |
|---------|---------|----------|------|---------|-------|------------|
| pingora | 0.4.0 | Cargo.lock | — | proxy_engine.rs | reverse proxy | Core (pinned old) |
| rustls | 0.23 | Cargo.lock | — | proxy_engine, wasm | TLS ring | Core |
| wasmtime | 29 | Cargo.lock | — | wasm.rs | WASM sandbox | Core (pinned old) |
| axum | 0.7 | Cargo.lock | — | controller/ | API server | Core |
| tract-onnx | 0.21.7 | Cargo.lock | — | rules/anomaly.rs | ML anomaly | Core (pinned old) |
| tonic/prost | 0.11/0.12 | Cargo.lock | — | grpc/ | gRPC | Secondary |
| redis | 0.25.3 | Cargo.lock | — | rate limiter | Redis | Secondary |
| rusqlite | 0.31 | Cargo.lock | — | threat intel | SQLite | Secondary |
| aya | — | jarswaf-ebpf | — | eBPF | XDP | Core |
| svelte | — | dashboard/ | node_modules | dashboard | UI | Core |
| external/ | 14 repos | external/ | 95MB | reference | study only | Retire (move out) |

```text
jarswaf/
├── src/                  # Core WAF (73 .rs)
│   ├── proxy_engine.rs   # hot path
│   ├── rules.rs          # registry
│   ├── rule_engine/      # DSL + SecLang + phases
│   ├── rules/            # 18 detection modules
│   ├── controller/       # API handlers
│   ├── agent/            # gossip
│   ├── grpc/             # Phase 10
│   ├── wasm.rs           # plugin sandbox
│   └── honeypot.rs
├── jarswaf-ebpf/         # eBPF/XDP layer
├── dashboard/            # Svelte UI
├── tests/                # integration
├── helm/                 # chart
├── docs/                 # architecture + plans
├── external/             # [3rd-party] reference repos (95MB)
├── target/               # [3rd-party] build artifacts (26GB)
└── xtask/                # build tasks
```
