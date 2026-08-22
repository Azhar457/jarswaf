# jarsWAF Task Plan v1.0 — Sequential, Milestone-Gated

Gate after EVERY task: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo test --workspace` must be GREEN. Red gate => fix before any next task. Ambiguity => AGENTS.md StopProtocol. Tasks are sequential; do not parallelize.

## M0 Bootstrap
- T-000 Commit doc set (PRD/ARCHITECTURE/SCHEMAS/TASKS/AGENTS/TREE.txt/llms.txt/ERRATA-v1.0.1.md/OPEN_QUESTIONS.md/BOOTSTRAP.md), dual LICENSE files, rust-toolchain.toml(channel 1.84), .gitignore.
- T-001 Create workspace skeleton: all crates with lib.rs stubs containing ONLY module decls; workspace Cargo.toml excludes ebpf; commit initial Cargo.lock.
- T-002 CI workflow per ARCHITECTURE §8 including whitelist-check script.
- T-003 Seed OPEN_QUESTIONS.md with resolved OQ-001, OQ-002, OQ-003.

## M1 waf-core foundations
- T-010 error.rs: NormalizeError{DecodeLimit, InvalidUtf8}.
- T-011 normalize.rs implementing FR-WAF-01 exact order + NormalizeMeta counters.
- T-012 tokenizer.rs grammar per SCHEMAS §2 + ERRATA E-02.
- T-013 rules/builtin.rs: 11 rules EXACT predicates/scores SCHEMAS §3 + ERRATA E-04/E-05/E-07.
- T-014 evaluator.rs merge + threshold.
- T-015 golden.rs loader parsing YAML vectors.
- T-016 50 golden vectors suite in tests/golden/sqli.yaml asserting 50/50 green.

## M2 waf-proxy
- T-020 config loading (toml crate) validating SCHEMAS §1 constraints.
- T-021 extract.rs: targets per FR-PRX-02 + HPP join FR-PRX-03 + oversize skip.
- T-022 app.rs Pingora wiring: proxy phase calls inspect pipeline; enforce/detect branching; block_page 403; send_rst path; timeouts 504.
- T-023 Wire telemetry emission points.

## M3 waf-telemetry
- T-030 logging.rs JSONL writer + stdout mirror + truncation limits.
- T-031 rotation.rs size-based rotate/delete-oldest/atomic rename.
- T-032 metrics.rs registry all SCHEMAS §7 names.
- T-033 latency.rs rolling window p99 baseline vs current; anomaly event once per breach.

## M4 waf-kernel + ebpf (feature-gated)
- T-040 ebpf crate: no_std, maps per ARCHITECTURE §6, program logic exact order.
- T-041 loader.rs/maps.rs: config injection, attach driver->generic, marker file lifecycle.
- T-042 userspace mirror-harness replicating §6 predicate order.

## M5 waf-controller
- T-050 auth.rs: argon2 verify, session issue/store(SHA256)/revoke/expiry, login limiter 5/900s.
- T-051 api.rs routes EXACT SCHEMAS §5 incl. stats payload keys and PATCH toggle via ArcSwap.
- T-052 sse.rs broadcast bridge + heartbeat.
- T-053 views: server-rendered htmx dashboard with runtime-only toggles.

## M6 bin + packaging
- T-060 cli.rs/main.rs: serve/status subcommands; graceful shutdown SIGTERM.
- T-061 deploy/jarswaf.service unit file.
- T-062 install.sh idempotent installer.
- T-063 scripts/bench.sh oha performance benchmarker.

## M7 E2E + acceptance
- T-070 tests/e2e/run_e2e.sh orchestrator.
- T-071 tests/e2e/stealth.sh nmap/masscan scanner assertion.
- T-072 ACCEPTANCE.md generator.
