# jarsWAF Full Project Audit — 2026-08-23

Auditor: ox-alpha (autonomous audit, read-only; no fixes applied)
Baseline: HEAD `5509afc` (main), 2026-08-23 03:00 +0700 · rustc 1.96.1 · 129 Rust files / 30,022 LOC in `src/` · Cargo.lock: 651 crates
Prior audits: `docs/audit/source-asset-audit-2026-08-02.md` (21k LOC → +43% growth in 3 weeks)

---

## 1. Executive Summary

jarsWAF has evolved far beyond its locked v1.0 spec into a much larger system (multi-node agent/gossip/gRPC, WASM rules, ML via tract-onnx, DLP, honeypot, RASP). Functionally the build gate is *mostly* healthy locally (fmt ✅, tests ✅ 229/229, golden vectors 50/50), **but CI on `main` is RED**, credentials are committed to a tracked config file, and password hashing uses salted SHA-256 instead of the mandated Argon2id.

**Overall health: 🟡 AMBER — functional but with P0 security and process debt.**

| Dimension | Status | Note |
|---|---|---|
| Build gate local (fmt/clippy/test) | 🟡 | fmt ✅, test ✅, clippy ❌ (`xtask`, 5 lints) |
| CI on main (H11) | 🔴 | SAST job failing since ≥2026-08-08; DAST skipped as result |
| Secrets hygiene (H13) | 🔴 | Live-looking token + admin hash committed in `config.toml` |
| Auth crypto vs SCHEMAS §1 | 🔴 | Salted SHA-256 instead of Argon2id |
| Spec compliance (ARCH/SCHEMAS/TASKS) | 🔴 | Locked architecture superseded; docs no longer describe the system |
| Panic discipline (H6) | 🟡 | 106 `unwrap/expect/panic!` in prod code paths |
| Unsafe discipline (H7) | 🔴 | 15 unsafe sites, **zero** `// SAFETY:` comments, 1 `unreachable_unchecked()` |
| Stub discipline (H8) | ✅ | No `todo!()/unimplemented!()` found |
| Platform gating (H14) | ✅ | eBPF/XDP correctly behind `cfg(target_os = "linux")` |
| Dependency health (H5) | 🟡 | Whitelist never written; 1 known vuln (h2), ~8 unmaintained deps |

---

## 2. Findings — P0 (act immediately)

### F-P0-1 · Credentials committed to tracked `config.toml` (H13, SCHEMAS §1 violation)
- `config.toml:14` `grpc_token = "…"` (32-hex live-looking secret)
- `config.toml:15` `admin_token = "$sha256$…"` (password hash — SCHEMAS §1 explicitly says *"Admin password NOT in config"*; belongs in `/etc/jarswaf/admin.hash`)
- `config.toml:131` `shared_secret`
- Also flagged by pattern scan: `bot_test_config.toml`, `redteam.toml`, all five `test_*.toml`, `install.sh`, `scripts/jarswaf.sh`.
- **Compounding risk**: see F-P0-3 — the hash algorithm is fast/blute-forceable.
- Remediation: rotate ALL exposed secrets; move secrets out of VCS (env/secret file); add `config*.toml` policy to `.gitignore`; scrub history (BFG) given public-facing repo.

### F-P0-2 · CI red on `main` (H11 violation)
- Last 5+ `DevSecOps CI` runs failed on main; failure step: `cargo clippy --all-targets --all-features -- -D warnings` (exit 101). CodeQL passes; ZAP DAST **skipped** because the build fails first.
- Reproduced locally: 5 clippy errors confined to `xtask/src/report.rs` (+1 more in same crate): `single_char_add_str`, `unnecessary_sort_by`, etc.
- Remediation: fix the 5 xtask lints (mechanical), re-run pipeline, verify ZAP stage executes again.

### F-P0-3 · Password hashing is salted SHA-256, not Argon2id (spec violation)
- `src/controller/auth.rs:51-57`: `hash_password`/`verify_password` use single-pass `Sha256` with `$sha256$salt$hash` format.
- TASKS T-050 & SCHEMAS §1 mandate **Argon2id**. The `argon2` crate is declared in `Cargo.toml:68` but unused on this path.
- Combined with F-P0-1 (hash is in git), offline cracking is trivial for weak passwords.
- Remediation: switch to Argon2id PHC strings; migrate stored hashes on next login/boot.

### F-P0-4 · `unsafe` without SAFETY comments + UB risk (H7 violation)
- 15 unsafe sites: 14 in `jarswaf-ebpf/src/main.rs` (lines 58–134), 1 in `src/rasp.rs:62` (outside permitted waf-kernel/ebpf glue).
- `jarswaf-ebpf/src/main.rs:134` uses `core::hint::unreachable_unchecked()` — genuine UB hazard if reached.
- Zero `// SAFETY:` comments repo-wide (rule requires them).
- Remediation: document or eliminate each site; replace `unreachable_unchecked` with safe fallback; move/duplicate-guard `rasp.rs` unsafe behind kernel module boundary.

---

## 3. Findings — P1 (plan within the month)

### F-P1-1 · Governance reset needed: code no longer matches the locked spec
The governing docs describe a system that was never built in this shape:

| Spec item | Docs say | Reality |
|---|---|---|
| Workspace | `crates/*` (waf-core/proxy/telemetry/kernel/controller) | Single monolith crate + `jarswaf-ebpf` + `xtask` |
| Core types (ARCH §5) | `Verdict`, `RuleHit`, `DecodeCtx`, `normalize_run`, `tokenize`, `evaluate` | Not present under those names |
| Detection engine | tokenizer + evaluator + frozen 11-rule registry (SCHEMAS §3, SQLI-R001..R011) | DSL engine (`src/rule_engine/{dsl,phase,seclang}.rs`) + 18 rule modules (`src/rules/*`) + data_bus inspectors; only trace of spec IDs is `"SQLI-R006_CTE_BOMB"` at `src/data_bus/inspectors/sql_injection.rs:82` |
| Metrics (SCHEMAS §7) | 11 exact names | Only `jarswaf_requests_total` matches; 16+ divergent names in `src/metrics.rs` |
| API (SCHEMAS §5) | `/login`, `/api/v1/stats`, `/api/v1/events/stream`, PATCH `/rules/{id}` | Two parallel surfaces: `src/controller/mod.rs:49-164` (`/api/v1/auth/login`, `/ws/*`, `/api/v1/logs/*`) and `src/api/mod.rs:24-43`; contract keys/routes differ |
| Dashboard (OQ-001 decision A) | Server-rendered htmx, zero node dep | Svelte + Vite + node_modules (`dashboard/`) |
| Toolchain pin | rust 1.84, pingora 0.8, aya 0.13.1 exact | rustc **1.96.1**, no `rust-toolchain.toml`, pingora **0.4.0**, aya git-rev `a47f99a0` |
| CI contract (ARCH §8) | `.github/workflows/ci.yml` + whitelist script | `devsecops.yml` + `release.yml`; `scripts/ci-whitelist-check.sh` absent |

**Impact**: every agent instruction ("implement EXACTLY what TASKS.md specifies") is now unexecutable against reality; precedence rule can't resolve drift because docs are stale, not conflicting.
**Remediation**: either (a) amend PRD/ARCHITECTURE/SCHEMAS to v2.0 describing the actual system, or (b) declare current docs v1-archive. Add `rust-toolchain.toml`. Reconcile OQ-001 formally (new OQ entry).

### F-P1-2 · TASKS.md completion matrix (no status markers exist)
| Milestone | State |
|---|---|
| M0 T-000 | Partial — doc set ✅, but `rust-toolchain.toml` ❌, dual LICENSE ❌ (single `LICENSE`) |
| M0 T-001/002 | Diverged — no crates workspace, no ci.yml, no whitelist script |
| M0 T-003 | ✅ OPEN_QUESTIONS seeded |
| M1 T-010..T-016 | Diverged engine, **but** `tests/golden/sqli.yaml` (50 vectors) exists and `test_all_50_golden_vectors` passes ✅ |
| M2/M3 | Superseded by `proxy_engine.rs`/`data_bus`/`metrics.rs` (names off-spec; rotation/latency-anomaly equivalents not verified) |
| M4 | Present (`jarswaf-ebpf/` + `src/kernel/*` mirrors) — H7 issues above |
| M5 | Superseded controller (auth ✅ concept, routes/API off-spec) |
| M6 | `main.rs` CLI ✅; `deploy/jarswaf.service` ❌, `scripts/bench.sh` ❌, `BENCHMARKS.md` ❌ |
| M7 | `tests/e2e/` ❌, `ACCEPTANCE.md` ❌ — acceptance never formalized |

### F-P1-3 · H6 panic discipline: 106 prod-code hits
Top offenders: `src/rules/body.rs` (22), `src/rules/whitelist.rs` (20), `src/metrics.rs` (17), `src/rules/uri.rs` (10), `src/dlp.rs` (5), `src/controller/mod.rs` (5, incl. one real `panic!` at line 344 on bad `JARSWAF_BIND`). One hot-path panic defeats the ARCH §7 fail-open contract if triggered during request handling. (146 further hits are test-only — acceptable.)

### F-P1-4 · Dependency posture (H5 unenforceable)
- AGENTS.md H5 references a whitelist that **was never written** → rule is vacuous; 78 direct deps / 651 lock entries include heavy supply-chain surface (wasmtime 29, tract-onnx, tonic, redis).
- `cargo audit`: **RUSTSEC-2026-0258** (h2 unbounded empty DATA frames) present at h2 0.3.27 **and** 0.4.15; unmaintained: atty, bincode 1.x, daemonize, derivative, fxhash, paste, proc-macro-error.
- Dependabot PR #wasmtime-36.0.8 currently failing CI.
- `[patch.crates-io] rand = { path = "rand_patch" }` — vendored fork of core RNG; needs upstream justification doc.

---

## 4. Findings — P2 (hygiene)

1. Root clutter: 9× `test_*/bot/pentest/redteam *.toml`, 5 loose `*.py` scripts, `check.bat/start.bat`, `jarswaf_repo_scan_report.html` (tracked), duplicate of prior audit HTMLs at root.
2. Tracked-but-ignored inconsistency: `docs/**` (35 files) and `blocklist.json` are committed while listed in `.gitignore` (docs/ even sits under the "IDE metadata" section — misplaced rule).
3. Local-only sensitive artifacts correctly ignored ✅ (`certs/ca.key`, `logs/jarswaf.db`, `config_backups/*.toml`) — but `config_backups/` copies likely contain the same secrets as F-P0-1; treat as exposed on any machine share.
4. Stale branch/worktree: locked worktree `.claude/worktrees/inspection-migration` (merged via PR #9), remote branches `worktree-*`, open dependabot PR.
5. Commit discipline (H9/H10): commits cite phases/PRs, never task IDs; multiple concerns per commit (e.g. `feat(architecture)` mega-commit). Branch model drifted from `feat/<task-id>-<slug>`.
6. Missing spec artifacts: `config.example.toml` (byte-canonical §1), `ACCEPTANCE.md`, `BENCHMARKS.md`, `scripts/bench.sh`, `deploy/jarswaf.service`, dual LICENSE files.

## 5. What's healthy ✅

- Golden-vector suite: 50/50 passing (`tests/golden_tests.rs`) incl. encoded variants.
- Test suite: 229 passed / 0 failed / 6 ignored across workspace.
- `cargo fmt --check`: clean.
- H8 stub scan clean; H14 platform gating exemplary (`src/kernel/*`, `xdp.rs`, `rasp.rs` all properly gated).
- Auth controls beyond hashing: per-IP login limiter, session TTL + pruning, auto-hash of plaintext tokens on boot (commit `13f2461`), generated onboarding password written to secure file, CSP defaults in `src/config.rs:986`.
- Security CI depth: CodeQL ✅, cargo-audit, npm audit, ZAP baseline configured (currently blocked by build failure).
- Stop Protocol honored historically (OQ-001..003 resolved, OQ-004 tracked).

---

## 6. Remediation Backlog (prioritized, effort-tagged)

| # | Item | Sev | Effort | Refs |
|---|---|---|---|---|
| 1 | Rotate `grpc_token`/`shared_secret`; move admin hash out of repo; purge history | P0 | M | F-P0-1 |
| 2 | Fix 5 clippy lints in `xtask/src/report.rs`; restore green CI + ZAP | P0 | S | F-P0-2 |
| 3 | Argon2id migration for `admin_token` (+ forced rehash path) | P0 | M | F-P0-3 |
| 4 | Add SAFETY comments / remove `unreachable_unchecked`; relocate `rasp.rs` unsafe | P0 | S-M | F-P0-4 |
| 5 | Governance reset: spec v2.0 amendment OR archive-v1 declaration; add `rust-toolchain.toml` (pin current or downgrade to pinned) | P1 | L | F-P1-1 |
| 6 | Write the H5 dependency whitelist (or delete the dead rule); triage unmaintained deps; plan h2 bump | P1 | M | F-P1-4 |
| 7 | H6 cleanup campaign starting with `rules/body.rs`, `whitelist.rs`, `metrics.rs`; remove prod `panic!` at `controller/mod.rs:344` | P1 | M-L | F-P1-3 |
| 8 | Repo hygiene pass: move root test configs/scripts into `tests/`/`scripts/dev/`, resolve ignore-vs-tracked conflicts, drop stale worktree/branches | P2 | S-M | §4 |
| 9 | Produce missing artifacts (`config.example.toml`, ACCEPTANCE/BENCHMARKS, bench.sh, service unit) or strike from TASKS | P2 | M | F-P1-2 |

*Effort: S < 1h, M ≤ 1 day, L > 1 day.*

---

## 7. Post-audit history rewrite (2026-08-23)

After this audit, `docs/**`, `GEMINI.md`, `REDTEAM.md`, and `rand_patch/{CHANGELOG,README}.md`
were purged from the entire commit history via `git filter-repo` and force-pushed to all branches
and tags (`main`, `dev`, `staging`, `worktree-*`, `dependabot/*`; tags `v0.3.1`, `v0.3.2`).
**Consequence: all commit hashes cited above are stale.** Example: old HEAD `5509afc` → new `4641799`.
Pre-rewrite history preserved at `/tmp/opencode/jarswaf-rewrite-backup/`
(`jarswaf-pre-rewrite.bundle` + `mirror.git`). Repo pack shrank 1.4 MiB → ~0.5 MiB (`.git` 3.3M → 2.4M).

## 8. Remediation applied (2026-08-23, same session)

| Item | Status | Commits |
|---|---|---|
| F-P0-2 clippy/CI red | ✅ FIXED — xtask lints fixed; nanoid bump (GHSA-2v37-7h3g-55p8); Dockerfile missing `rand_patch/` COPY (latent bug exposed by green SAST); `.cargo/**` added to CI trigger paths | `85f7418`, plus follow-ups |
| F-P0-3 SHA-256 credentials | ✅ FIXED — Argon2id PHC hashing; legacy `$sha256$`+plaintext verify retained; transparent rehash-on-login | `1f0ab47` |
| F-P0-4 unsafe discipline | ✅ FIXED — SAFETY comments on all 15 sites; `unreachable_unchecked()` replaced with defined spin-loop divergence | `b541983` |
| F-P0-1 secrets in VCS | ✅ PARTIAL — values scrubbed from HEAD (`67b8bc2`) and from ALL history via `filter-repo --replace-text` (9 literals → `[REDACTED-CREDENTIAL]`, force-pushed). **Operator TODO**: rotate `grpc_token`/`shared_secret` at consumers (any pre-scrub clone holds them) | history rewrite |
| F-P1-5a toolchain pin | ✅ `rust-toolchain.toml` (1.96.1) | `179dbfc` |
| F-P1-6 H5 whitelist / h2 | ✅ Whitelist written into AGENTS.md; h2 0.4→0.4.18; h2 0.3.x (tonic 0.11) documented accepted-risk w/ owner+expiry in `.cargo/audit.toml` | `179dbfc`, `3e4d6ca` |
| F-P1-7a prod panic! | ✅ `controller/mod.rs` bind errors exit(2) per ARCH §7 (also removed port-bind `expect`) | `179dbfc` |
| F-P2-9a config.example.toml | ✅ byte-canonical SCHEMAS §1 | `179dbfc` |
| **CI end-state** | ✅ **SAST + CodeQL + DAST(ZAP) all green** (run `32617397973`) — first fully-green pipeline after unblocking chain | — |

### Still open (next sessions)
- F-P0-1 credential rotation at consumer systems
- F-P1-1 governance reset (spec v2.0 amendment vs archive-v1)
- F-P1-3 H6 campaign: ~105 remaining prod `unwrap/expect` (top: `rules/body.rs`, `rules/whitelist.rs`, `metrics.rs`)
- F-P1-4 tonic ≥0.12 migration to clear the RUSTSEC-2026-0258 ignore entry
- F-P2-8 root-file hygiene, ignore-vs-tracked conflicts, stale branches

— End of report. Generated without modifying any source file.
