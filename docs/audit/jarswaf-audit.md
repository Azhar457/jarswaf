# jarsWAF Source Asset Audit Report

**Project**: `jarsWAF`
**Path**: `/mnt/data_d/Projects/jarswaf`
**Audit Date**: 2026-08-02
**Overview**: High-performance WAF — Rust + Pingora + eBPF XDP + Svelte dashboard + WASM plugins. ~21k lines of Rust core, 8.8k lines Svelte, 651 locked crates.

## Audit Summary

### Project Profile
1. Cross-stack monorepo: Rust core (~21,047 LOC), Svelte/TS dashboard (8,827 LOC), eBPF XDP probe (102 LOC), xtask tooling (348 LOC), tests (311 LOC). Total tracked ~39,912 LOC across 221 files.
2. Zero third-party source vendored in-tree — all deps via Cargo/npm, external/ is reference-only (gitignored). `plugins/block-admin.wasm` is a prebuilt artifact.
3. 100% single-author codebase (Azhar457, 81 commits). No legacy migration debt — everything is first-party and actively maintained.

### Key Risks
1. Monolithic `src/rules.rs` (2,620 lines) mixes 11+ rule engines (SQLi/XSS/LFI/HPP/BOT/API/GraphQL/headers/URI/evasion/whitelist) — high cognitive load, merge conflicts, no per-feature isolation.
2. `src/proxy_engine.rs` (2,231 lines) — the critical hot path — bundles proxy lifecycle + rule dispatch + TLS + upgrade handling; hard to test in isolation.
3. `src/rule_engine/mod.rs` (2,020 lines) — DSL + phase + seclang orchestration co-located; DSL grammar changes risk breaking the phase engine.
4. 26GB of untracked build artifacts: `target/` 26GB, `jarswaf-ebpf/target/` 478MB, `dashboard/node_modules/` 262MB — disk waste, not in git (gitignored, so low severity).
5. `external/` (95MB, 6 reference WAF repos) sits inside the project dir — cleanly gitignored but bloats backups and IDE indexing.
6. `src/rules.rs` contains duplicate rule_id references (HPP-001 ×3, BOT-001 ×3, SQLI-001 ×2, LFI-001/2 ×2) — likely duplicated match logic or dead branches.

### Priority Actions
1. Split `src/rules.rs` into per-category modules (sql.rs, xss.rs, lfi.rs, hpp.rs, bot.rs) matching `src/rules/` pattern — 2,620 → ~250 LOC each.
2. Extract `proxy_engine.rs` hot-path into traits: `ProxyHandler` + `PhaseProcessor` so the rule dispatch can be unit-tested without a live socket.
3. Deduplicate rule_id references in `rules.rs` — verify each of the 11 rule IDs maps to exactly one match arm.
4. Move `external/` out of the repo dir (e.g. sibling `~/reference/waf/`) and add a symlink if needed — keeps backups lean.
5. After refactors, bump Cargo.toml version from 0.1.0 (still 0.1.0 despite v1.0.0-ce release tag).

## 1. Overall Statistics

| Metric | Value |
|--------|-------|
| Total Tracked Files | 221 |
| Total Tracked Size | ~1.5 MB (source) |
| **Project Source Files** | **~170** |
| **Project Source Size** | **~40 KB pure code (39,912 LOC tracked)** |
| Third-Party Files | 0 (vendored) — 651 crates via Cargo.lock |
| Noise Files (build artifacts) | ~26 GB untracked (target/, node_modules/, dist/) |
| Project Code Ratio | 100% of tracked source is first-party |

## 2. Top-Level Directory Breakdown

| Directory | Project Files | Project Size | Build Systems | Notes |
|-----------|--------------|-------------|---------------|-------|
| `src/` | 73 .rs | 21,047 LOC | Cargo | Core WAF (proxy, rules, engine) |
| `dashboard/` | 47 .svelte + 4 .ts | 8,827 LOC | Vite/Svelte | Admin UI (dist gitignored) |
| `jarswaf-ebpf/` | 2 .rs | 102 LOC | Cargo | XDP probe (veth-testable only, WiFi no XDP) |
| `xtask/` | 4 .rs | 348 LOC | Cargo | Red-team/report tooling |
| `tests/` | 2 .rs | 311 LOC | Cargo | Integration tests |
| `rules/` | 3 files | 309 LOC | custom .jwaf/.yaml | Rule profiles (advanced-rules, custom, profiles) |
| `external/` | 6 repos | 95 MB | — | [3rd-party] reference only, gitignored |
| `helm/` | 3 files | — | Helm | K8s deployment charts |
| `.github/` | workflows | — | CI | ZAP DAST, devsecops audit, release |

## 3. Source File Statistics by Tech Stack (project files only)

| Tech Stack | File Count | Total Size |
|------------|------------|------------|
| Rust | 82 | 21,815 LOC (incl. eBPF + xtask + tests) |
| Web/JS/TS | 51 | ~9,200 LOC (Svelte 8,827 + Vite config) |
| Rules DSL (.jwaf/.yaml) | 3 | 309 LOC |
| Shell/Python tooling | 8 | ~2,500 LOC (manager.sh, install.sh, load_test.py) |
| Helm/CI YAML | 12 | ~1,200 LOC |

## 4. Third-Party Dependencies Detected

| Library | Version | Location | Size | Used By | Usage | Assessment |
|---------|---------|----------|------|---------|-------|------------|
| pingora + pingora-core/proxy/http/load-balancing | 0.4.0 | Cargo.lock | — | proxy_engine.rs | Reverse proxy core (Cloudflare) | **Core** — pinned, audit-exempt |
| axum | 0.7 | Cargo.lock | — | controller/ | REST API framework | Core — stable |
| rustls + tokio-rustls | 0.23 / 0.26.4 | Cargo.lock | — | tls.rs, proxy_engine.rs | TLS termination (ring) | Core — pinned |
| wasmtime | 29 | Cargo.lock | — | wasm.rs | WASM plugin sandbox (fuel 50k) | Core — heavy dep |
| tract-onnx | 0.21.7 | Cargo.lock | — | (ml inference) | ONNX model runtime | Pinned — audit-exempt |
| tonic + prost | 0.11 / 0.12 | Cargo.lock | — | grpc/ | gRPC control plane | Core |
| rusqlite | 0.31 (bundled) | Cargo.lock | — | (state) | SQLite storage | Bundled — no system dep |
| redis | 0.25.3 | Cargo.lock | — | rate_limit.rs | Rate-limit store | Core |
| maxminddb | 0.27.0 | Cargo.lock | — | rules/ip_reputation.rs | GeoIP lookups | Core |
| prometheus | 0.13 | Cargo.lock | — | metrics.rs | Metrics (locks protobuf 2.x) | Pinned — audit-exempt |
| chacha20poly1305 | 0.11.0 | Cargo.lock | — | gossip.rs | Gossip encryption | Core |
| Svelte + Vite | 5.x / 6.x | dashboard/package-lock.json | — | dashboard/ | Admin UI | Core |
| block-admin.wasm | (plugin) | plugins/ | 8 KB | wasm.rs | Admin-blocking plugin | Prebuilt — rebuild from src if changed |

## 5. Suspected Code Duplication (directories appearing 3+ times)

| Pattern | Locations | Risk |
|---------|-----------|------|
| Rule ID duplication | `src/rules.rs` HPP-001 ×3, BOT-001 ×3, SQLI-001 ×2, LFI-001 ×2, LFI-002 ×2 | Duplicated match arms or dead branches — verify each ID maps to exactly one arm |
| `proxy_engine.rs` vs `proxy.rs` | Both contain reverse-proxy logic (2,231 + 161 LOC) | proxy.rs may be a leftover stub — check if still referenced |
| Controller handlers | 17 files in `controller/handlers/` share auth/state patterns | Acceptable — per-resource isolation is idiomatic |

## 6. Directory Tree (noise filtered, third-party marked)

```text
jarswaf/
├── src/                          # Rust core (21,047 LOC)
│   ├── main.rs / lib.rs / bin/   # entrypoints (controller, agent)
│   ├── proxy_engine.rs           # 2,231 LOC hot path
│   ├── rules.rs                  # 2,620 LOC — 11+ engines, DUPLICATE IDs
│   ├── rule_engine/              # mod.rs 2,020 + dsl.rs + seclang.rs + phase.rs
│   ├── rules/                    # 18 files — body, headers, uri, graphql, api,
│   │                             #   rate_limit, anomaly, trust, redteam, evasion,
│   │                             #   bot_challenge, multipart, proxy_unmask, threat_intel
│   ├── controller/               # 21 files — REST + websocket + 17 handlers
│   ├── agent/                    # 6 files — discovery, blocklist, metrics
│   ├── grpc/                     # 3 files
│   ├── compliance/               # 1 file
│   └── (root)                    # config, tls, dlp, gossip, honeypot, rasp, vhost,
│                                 #   wasm, xdp, metrics, logging, webhook
├── dashboard/                    # Svelte UI (47 .svelte, 8,827 LOC)
├── jarswaf-ebpf/                 # XDP probe (102 LOC)
├── xtask/                        # red-team tooling (348 LOC)
├── tests/                        # integration (311 LOC)
├── rules/                        # .jwaf/.yaml rule profiles
├── external/                     # [3rd-party] 6 ref repos, gitignored
├── helm/                         # K8s charts
└── plugins/block-admin.wasm      # prebuilt WASM
```

## 7. Git Repositories & Activity

| Repo | Total Commits | Recent Commits | Last Commit |
|------|--------------|----------------|-------------|
| jarswaf | 81 | 5 (ci ZAP fix, postcss patch, proxy-unmask, audit.toml, v1.0.0-ce) | 2026-08-02 |
| Author | 43 azhar457 + 30 Azhar + 8 Azhar457 | — | — |
| Pack size | 832 KB (330 objects) | — | — |

## Modules

### 1.1 Proxy Engine — reverse-proxy hot path
**Physical Location**: `src/proxy_engine.rs`
**Capability Matrix**: TLS termination, HTTP/1.1 upgrade handling, rule dispatch, connection lifecycle — the single busiest file in the codebase
**Core Code Modules**:
- `ProxyEngine` / `handle_request` / `dispatch_rules`
**Dependencies**: pingora 0.4, rustls 0.23, tokio, hyper
**Third-Party Libs**:
- pingora 0.4.0 (reverse proxy core)
- rustls 0.23 (TLS, ring provider)
**Code Size**: 2,231 LOC
**Quality Assessment**:
- Architecture: solid layering but monolith — proxy lifecycle + rule dispatch + TLS co-located
- Tech Debt: hard to unit-test without a live socket; extract `ProxyHandler` + `PhaseProcessor` traits
**Activity**: high (recent commits)
Verdict: **Core Cornerstone**

### 1.2 Rules Registry — 11+ rule engines co-located
**Physical Location**: `src/rules.rs`
**Capability Matrix**: SQLi/XSS/LFI/HPP/BOT/API/GraphQL/header/URI/evasion/whitelist inspection in one file
**Core Code Modules**:
- `check_rules` / `RuleMatcher` / `process_match`
**Dependencies**: regex, serde, toml
**Third-Party Libs**:
- regex 1.x
**Code Size**: 2,620 LOC
**Quality Assessment**:
- Architecture: needs split into per-category modules (sql.rs, xss.rs, lfi.rs, hpp.rs, bot.rs) matching `src/rules/` pattern
- Tech Debt: duplicate rule_id refs (HPP-001 ×3, BOT-001 ×3, SQLI-001 ×2) — verify each ID maps to exactly one match arm
**Activity**: high
Verdict: **Purify & Merge**

### 1.3 Rule Engine — DSL + seclang + phase orchestration
**Physical Location**: `src/rule_engine/`
**Capability Matrix**: phase-based engine (4-phase CRS-style), SecLang parser, custom DSL
**Core Code Modules**:
- `RuleEngine` / `DslParser` / `SecLangParser` / `PhaseProcessor`
**Dependencies**: nom 7, serde
**Third-Party Libs**:
- nom 7 (parsing)
**Code Size**: 3,416 LOC (mod.rs 2,020 + dsl.rs 608 + seclang.rs 541 + phase.rs 247)
**Quality Assessment**:
- Architecture: clean layering — DSL grammar isolated from phase engine
- Tech Debt: DSL grammar changes risk breaking phase engine; keep integration tests green
**Activity**: high
Verdict: **Core Cornerstone**

### 1.4 Rule Inspectors — per-category inspection modules
**Physical Location**: `src/rules/` (18 files)
**Capability Matrix**: body, headers, uri, graphql, api, rate_limit, anomaly, trust, redteam, evasion, bot_challenge, multipart, proxy_unmask, threat_intel, ip_reputation, whitelist, api_security
**Core Code Modules**:
- `body.rs` / `headers.rs` / `rate_limit.rs` / `threat_intel.rs` / `proxy_unmask.rs`
**Dependencies**: regex, maxminddb, redis, dashmap
**Third-Party Libs**:
- maxminddb 0.27 (GeoIP)
- redis 0.25 (rate-limit store)
**Code Size**: 4,490 LOC
**Quality Assessment**:
- Architecture: good modular split — per-category files with clear boundaries
- Tech Debt: rate-limit key scheme changed (ip|scope) — keep policy-match tests updated
**Activity**: high
Verdict: **Core Cornerstone**

### 1.5 Controller — REST API + websocket
**Physical Location**: `src/controller/` (21 files)
**Capability Matrix**: 17 handlers (config, logs, stats, redteam, metrics, ratelimits, ssl, vhosts, rasp, rules, compliance, threat_intel, lists, agents, onboarding, proxy_unmask), auth, websocket, state
**Core Code Modules**:
- `handlers/*` / `auth.rs` / `websocket.rs` / `state.rs`
**Dependencies**: axum 0.7, tokio, serde
**Third-Party Libs**:
- axum 0.7 (REST framework)
**Code Size**: 2,734 LOC
**Quality Assessment**:
- Architecture: idiomatic per-resource handler split
- Tech Debt: 17 handlers share auth/state patterns — consider middleware extraction
**Activity**: high
Verdict: **Core Cornerstone**

### 1.6 Agent — node discovery & blocklist
**Physical Location**: `src/agent/` (6 files)
**Capability Matrix**: discovery, blocklist, metrics, websocket, server
**Core Code Modules**:
- `discovery.rs` / `blocklist.rs` / `metrics.rs` / `server.rs`
**Dependencies**: tokio, reqwest
**Third-Party Libs**:
- reqwest 0.12 (rustls-tls)
**Code Size**: 1,137 LOC
**Quality Assessment**:
- Architecture: clean, self-contained agent node
- Tech Debt: low
**Activity**: high
Verdict: **Core Cornerstone**

### 1.7 gRPC — control plane
**Physical Location**: `src/grpc/` (3 files)
**Capability Matrix**: server, client, mod
**Core Code Modules**:
- `server.rs` / `client.rs`
**Dependencies**: tonic 0.11, prost 0.12
**Third-Party Libs**:
- tonic 0.11, prost 0.12
**Code Size**: 146 LOC
**Quality Assessment**:
- Architecture: thin layer, isolated
- Tech Debt: low
**Activity**: medium
Verdict: **Core Cornerstone**

### 1.8 Compliance — compliance checks
**Physical Location**: `src/compliance/mod.rs`
**Capability Matrix**: compliance validation
**Core Code Modules**:
- `ComplianceChecker`
**Dependencies**: serde
**Code Size**: 100 LOC
**Quality Assessment**:
- Architecture: small, isolated module
- Tech Debt: low
**Activity**: low
Verdict: **Core Cornerstone**

### 1.9 Proxy Stub — leftover?
**Physical Location**: `src/proxy.rs`
**Capability Matrix**: reverse-proxy logic overlap with proxy_engine
**Core Code Modules**:
- `proxy` (161 LOC)
**Dependencies**: none significant
**Code Size**: 161 LOC
**Quality Assessment**:
- Architecture: overlap with proxy_engine.rs — check if still referenced
- Tech Debt: likely dead code or legacy stub
**Activity**: low
Verdict: **Reshape & Extract**

### 1.10 Cross-cutting infra — config, tls, dlp, gossip, honeypot, rasp, vhost, wasm, xdp, metrics, logging, webhook
**Physical Location**: `src/` root files
**Capability Matrix**: config parsing (960 LOC), TLS (111), DLP (262), gossip (251), honeypot (305), RASP (94), vhost (199), WASM (307), XDP (222), metrics (211), logging (631), webhook (85)
**Core Code Modules**:
- `config.rs` / `wasm.rs` / `honeypot.rs` / `gossip.rs` / `dlp.rs`
**Dependencies**: rustls, wasmtime 29, chacha20poly1305, tokio
**Third-Party Libs**:
- wasmtime 29 (WASM sandbox, fuel 50k, fail-closed)
- chacha20poly1305 0.11 (gossip encryption)
**Code Size**: 3,637 LOC
**Quality Assessment**:
- Architecture: good separation of cross-cutting concerns
- Tech Debt: wasmtime is a heavy dep — pin and audit-exempt
**Activity**: high
Verdict: **Core Cornerstone**

### 1.11 Dashboard — Svelte admin UI
**Physical Location**: `dashboard/`
**Capability Matrix**: admin UI, 47 Svelte components, proxy-unmask modal, theme switcher
**Core Code Modules**:
- `App.svelte` / `pages/` / `components/` / `lib/`
**Dependencies**: Svelte 5, Vite 6
**Third-Party Libs**:
- Svelte 5.x, Vite 6.x
**Code Size**: 8,827 LOC
**Quality Assessment**:
- Architecture: clean component split
- Tech Debt: node_modules 262MB untracked (gitignored)
**Activity**: high
Verdict: **Core Cornerstone**

### 1.12 eBPF XDP probe
**Physical Location**: `jarswaf-ebpf/`
**Capability Matrix**: XDP_DROP on BLOCKLIST, veth-pair testable (WiFi no XDP)
**Core Code Modules**:
- `main.rs` (100 LOC)
**Dependencies**: aya
**Code Size**: 102 LOC
**Quality Assessment**:
- Architecture: minimal, focused
- Tech Debt: WiFi (iwlwifi) unsupported — veth pair only
**Activity**: medium
Verdict: **Core Cornerstone**

### 1.13 xtask — red-team tooling
**Physical Location**: `xtask/`
**Capability Matrix**: red-team automation, report generation
**Core Code Modules**:
- `redteam.rs` / `report.rs` / `main.rs`
**Dependencies**: clap 4
**Third-Party Libs**:
- clap 4.6
**Code Size**: 348 LOC
**Quality Assessment**:
- Architecture: standalone tooling, separate crate
- Tech Debt: low
**Activity**: medium
Verdict: **Core Cornerstone**

### 1.14 external — reference WAF repos
**Physical Location**: `external/`
**Capability Matrix**: 6 reference repos (Awesome-WAF, coraza, gotestwaf, ModSecurity, PayloadsAllTheThings, wafw00f)
**Core Code Modules**:
- (none — reference only)
**Dependencies**: none
**Third-Party Libs**:
- (all — research clones, gitignored)
**Code Size**: 95 MB
**Quality Assessment**:
- Architecture: NOT part of build — reference only
- Tech Debt: bloats backups + IDE indexing; move out of tree to sibling dir
**Activity**: none
Verdict: **Completely Retire** (move out of tree)

## Asset Triage

| Module | Function | Third-Party | Deps | Activity | Quality | Verdict |
|--------|----------|-------------|------|----------|---------|---------|
| `src/proxy_engine.rs` | Reverse-proxy hot path: TLS, upgrade, rule dispatch | pingora 0.4 | heavy | high | architecture: solid, but monolith | **Core Cornerstone** |
| `src/rules.rs` | 11+ rule engines co-located | — | low | high | architecture: needs split | **Purify & Merge** |
| `src/rule_engine/` | DSL + seclang + phase orchestration | nom 7 | medium | high | architecture: clean layering | **Core Cornerstone** |
| `src/rules/*` (18 files) | Per-category inspection (body/headers/uri/graphql/api/rate_limit/anomaly/trust/redteam/evasion/bot/multipart/proxy_unmask/threat_intel) | regex, maxminddb, redis | low | high | architecture: good modular split | **Core Cornerstone** |
| `src/controller/` | REST API + websocket + 17 handlers | axum | low | high | architecture: idiomatic | **Core Cornerstone** |
| `src/agent/` | Agent node: discovery, blocklist, metrics | tokio | low | high | architecture: clean | **Core Cornerstone** |
| `src/grpc/` | gRPC control plane | tonic 0.11, prost 0.12 | low | medium | architecture: thin layer | **Core Cornerstone** |
| `src/compliance/` | Compliance checks | — | low | low | architecture: small, isolated | **Core Cornerstone** |
| `src/proxy.rs` | Possibly leftover stub | — | none | low | architecture: overlap with proxy_engine | **Reshape & Extract** |
| `src/root files` (config/tls/dlp/gossip/honeypot/rasp/vhost/wasm/xdp/metrics/logging/webhook) | Cross-cutting infra | rustls, wasmtime, chacha20poly1305 | medium | high | architecture: good separation | **Core Cornerstone** |
| `dashboard/` | Admin UI (Svelte) | Svelte 5, Vite | low | high | architecture: clean | **Core Cornerstone** |
| `jarswaf-ebpf/` | XDP probe | aya | low | medium | architecture: minimal | **Core Cornerstone** |
| `xtask/` | Red-team automation | clap | low | medium | architecture: tooling, standalone | **Core Cornerstone** |
| `external/` | 6 reference WAF repos | — | none | — | — | **Completely Retire** (move out of tree) |

## Appendix: Third-Party Dependency Detail

| Library | Version | Location | Size | Used By | Usage | Assessment |
|---------|---------|----------|------|---------|-------|------------|
| pingora | 0.4.0 | Cargo.lock | — | proxy_engine.rs | reverse proxy | Core |
| axum | 0.7 | Cargo.lock | — | controller/ | REST API | Core |
| rustls | 0.23 | Cargo.lock | — | tls.rs | TLS (ring) | Core |
| wasmtime | 29 | Cargo.lock | — | wasm.rs | WASM sandbox | Core |
| tract-onnx | 0.21.7 | Cargo.lock | — | ml | ONNX | Pinned |
| tonic/prost | 0.11/0.12 | Cargo.lock | — | grpc/ | gRPC | Core |
| rusqlite | 0.31 | Cargo.lock | — | state | SQLite | Core |
| redis | 0.25.3 | Cargo.lock | — | rate_limit | rate store | Core |
| maxminddb | 0.27.0 | Cargo.lock | — | ip_reputation | GeoIP | Core |
| prometheus | 0.13 | Cargo.lock | — | metrics | metrics | Pinned |
| chacha20poly1305 | 0.11.0 | Cargo.lock | — | gossip | encryption | Core |
| Svelte/Vite | 5/6 | dashboard lock | — | dashboard | UI | Core |
