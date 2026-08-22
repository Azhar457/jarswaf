# jarsWAF PRD v1.0 — LOCKED SPECIFICATION

Status: LOCKED. Changes require version bump to v1.1 with changelog entry.
Audience: autonomous LLM coding agents (mixed vendors), human maintainers.
Normative language: RFC 2119. MUST = mandatory. Numbers in SCHEMAS.md are canonical.

## 1. Overview
jarsWAF is a high-performance WAF in Rust operating as inline L7 reverse proxy. It detects
SQL injection via deterministic normalize→tokenize→AST-rule→score pipeline, drops TCP
reconnaissance at kernel level via eBPF/XDP, and exposes a loopback-only dashboard.

## 2. Goals
- G-01 Deterministic SQLi detection resistant to: parser differential, multi-layer encoding,
  comment obfuscation, unicode tricks.
- G-02 nmap -sS/-sT and masscan MUST NOT discover any TCP port outside protected_ports.
- G-03 >=10,000 req/s throughput; p99 added latency <=5ms on reference hardware (K4).
- G-04 Zero compiler/clippy warnings; 100% green tests as merge gate.
- G-05 An LLM agent with ONLY this document set produces conforming code. No external context.

## 3. Non-Goals (v1.0)
NG-01 XSS/SSRF/LFI/RCE engines (existing modules stay compilable, OUT of acceptance scope).
NG-02 TLS termination (operator fronts with LB/nginx).
NG-03 Config hot-reload (restart suffices).
NG-04 IPv6 XDP filtering (IPv4 only; IPv6 documented as host-firewall concern).
NG-05 Multi-agent clustering modes (exist in repo, not acceptance-gated).
NG-06 ML/ONNX, WASM plugins, JA4, DLP/RASP.

## 4. Actors
A-01 Untrusted internet client. A-02 Upstream origin app. A-03 Admin via SSH tunnel.
A-04 Adversarial scanner (nmap/masscan). A-05 Coding agent executing this doc set.

## 5. Functional Requirements

### FR-PRX Proxy
- FR-PRX-01 Listen `proxy.listen` (default 0.0.0.0:8080); forward accepted requests to
  `proxy.upstream` preserving method/path/query/headers/body.
  AC: mock-origin echo test shows byte-identical forwarding of clean requests.
- FR-PRX-02 Inspection targets: URI path, query values, Cookie values, User-Agent, Referer,
  body (form-urlencoded values + JSON string leaves). Body > max_inspect_bytes (65536) is
  forwarded uninspected with event action=inspect_skipped, reason=body_too_large.
  AC: unit tests per target; oversize-body integration test emits skip event.
- FR-PRX-03 HPP policy: repeated parameter names have ALL values joined with single space
  before inspection. AC: ?id=1&id=' UNION SELECT yields WouldBlock in detect mode.
- FR-PRX-04 Enforcement: general.mode=enforce returns block_action (default 403 + custom HTML);
  mode=detect forwards and logs action=would_block. AC: integration tests both modes.
- FR-PRX-05 Fail-open on internal engine error: forward + ERROR event action=engine_error.
  Worker MUST NOT panic on any input. AC: 10k-random-input property test panics=0.
- FR-PRX-06 Timeouts: request 30000ms, upstream connect 5000ms. Timeout => 504 to client.
  AC: stalled-origin integration test.

### FR-WAF Detection Engine
- FR-WAF-01 Normalization pipeline EXACT order (FR numbering binds SCHEMAS section 2):
  (1) URL-decode, '+'=>space only in Query/FormBody ctx; (2) HTML entity decode (named subset
  lt gt amp quot apos nbsp + &#NNN; + &#xHH;); (3) NFKC; (4) strip SQL/C comments (--,#,/* */)
  replacing each with ONE space; (5) ASCII lowercase; (6) tokenize.
  Each decode stage iterates <= detection.max_decode_iterations (5); hitting cap sets
  meta.hit_decode_cap=true (event field only, no score).
  AC: unit tests: %2527 chain resolves to '; fullwidth SELECT -> select; nested /*/*/ closes;
  iteration-cap flag set on %25252525252527.
- FR-WAF-02 Hand-written tokenizer (NO sqlparser crate). Grammar = SCHEMAS §2. Total function:
  no panic on arbitrary UTF-8. AC: property test 10k random inputs.
- FR-WAF-03 Hybrid verdict: AST predicate rules accumulate integer scores per inspected target;
  target-total >= detection.block_threshold (50) => WouldBlock. Rule registry EXACTLY SCHEMAS §3.
  AC: golden suite green.
- FR-WAF-04 Golden evasion suite >=50 vectors category sqli distributed per SCHEMAS §4 Matrix.
  Vectors IMMUTABLE post-merge. AC: count assertion == 50 in test.
- FR-WAF-05 NormalizeMeta captures comment_count (stripped occurrences) and version_comments
  (payloads inside /*!...*/) feeding SQLI-R007/R008. AC: crafted-input unit tests.
- FR-WAF-06 Latency monitor: rolling 60s window p99 upstream latency; breach of
  baseline+latency.delta_alert_ms (250ms) emits action=latency_anomaly + gauge. Alert only,
  never blocks in v1.0. AC: synthetic series unit test fires exactly once per breach.

### FR-KRN Kernel Anti-Recon
- FR-KRN-01 Attach XDP: driver mode -> generic fallback. Unavailable (non-root/non-Linux/no
  iface) => WARN event xdp_unavailable, continue L7-only; e2e stealth tests SKIP exit 77.
- FR-KRN-02 Ingress IPv4 rule: TCP SYN-without-ACK AND dport NOT IN protected_ports AND src
  NOT in trusted_cidrs => XDP_DROP + STAT_DROPPED++. Everything else PASS unchanged
  (established flows, ICMP, UDP, ARP untouched).
- FR-KRN-03 SYN rate guard: per-src-IP per-minute bucket, LRU_HASH cap 65536;
  count > syn_rate_limit_per_min (100) => BANNED_UNTIL = now + ban_seconds (60), DROP while banned.
- FR-KRN-04 Trusted CIDR sources bypass ALL drops.
- FR-KRN-05 Stealth acceptance: with protected_ports=[8080]:
  `nmap -Pn -sS -p1-1000 TARGET` => exactly {8080} open, rest filtered/closed;
  masscan => zero open except 8080. AC: tests/e2e/stealth.sh exit 0.

### FR-DASH Dashboard/API
- FR-DASH-01 Bind dashboard.listen = 127.0.0.1:9443 ONLY. Config validation rejects
  non-loopback bind with startup error (exit != 0).
- FR-DASH-02 Auth: user admin; Argon2id verify (m=19456,t=2,p=1); session cookie name
  jarswaf_session, 32 random bytes base64url, server stores SHA-256(token), HttpOnly,
  SameSite=Lax, TTL 28800s, revoked on logout. All routes except /login,/metrics fail-closed 401.
- FR-DASH-03 Login limiter: 5 failures / src IP / 900s window => 429 until expiry.
- FR-DASH-04 Routes EXACTLY SCHEMAS §5. No extra endpoints in v1.0. AC: route enumeration test.
- FR-DASH-05 Features: SSE live stream, counters, per-rule enable/disable toggles.
  Toggles mutate RUNTIME STATE ONLY (ArcSwap snapshot); never persist to TOML; reset on
  restart. UI displays label "runtime-only".

### FR-TLM Telemetry
- FR-TLM-01 JSON Lines to stdout + file, keys EXACTLY SCHEMAS §6; every decision event carries
  event.id UUIDv4 + req_id. AC: snapshot tests.
- FR-TLM-02 Prometheus /metrics on dashboard listener. Names EXACTLY SCHEMAS §7.
- FR-TLM-03 Rotation size-based: max_file_mb 100, max_files 10, oldest deleted, atomic rename.
  AC: forced-rotation unit test.

## 6. Non-Functional
- NFR-PERF-01 >=10k req/s clean GET via scripts/bench.sh (oha -z 60s -c 256), results in BENCHMARKS.md.
- NFR-PERF-02 p99 overhead <=5ms vs direct-origin baseline, same run.
- NFR-SEC-01 No unwrap/expect outside tests+main bootstrap; unsafe only in waf-kernel glue with SAFETY comments.
- NFR-SEC-02 Dependency whitelist enforced; Cargo.lock committed+frozen.
- NFR-REL-01 Panic-free fuzz-lite: 10k inputs through normalize/tokenize/evaluate nightly.
- NFR-OPS-01 Single binary; deploy/jarswaf.service; install.sh idempotent on Debian 12.
- NFR-OPS-02 Self-contained docs; agents need zero network access (A4).

## 7. Decision Register (overrides prose on conflict)
A1=mixed-agents A2=english-docs A3=multi-doc A4=self-contained A5=specs+pseudocode
B1=proxy+sqli+xdp+dashboard B2=inline-L7 B3=debian12/ubuntu2204 B4=fail-open-traffic+fail-closed-auth
C1=rust-toolchain-pin C2=aya-pinned-rev C3=kernel>=5.15 C4=handwritten-tokenizer C5=closed-whitelist
D1=pipeline-fixed-order D2=hybrid-score-threshold D3=configurable-action D4=detect-default D5=sig+latency
E1=nmap+masscan E2=silent-XDP_DROP E3=static-cidr E4=loopback-9443 E5=filtered-criterion
F1=toml F2=restart-apply F3=evasion-schema-fixed
G1=axum G2=server-rendered-htmx[OQ-01] G3=session+argon2 G4=stream+counters+toggles
H1=ecs-jsonl H2=prometheus H3=size-rotation
I1=50-per-category I2=10k-rps-5ms I3=stealth.sh I4=strict-ci I5=inprocess-hyper-mock
J1=locked-tree J2=conventional-commits J3=hard-constraints J4=milestone-gating J5=open-questions-protocol
K1=dual-apache-mit K2=jarswaf-binary K3=proxy-default-8080[OQ-02] K4=refhw-4vcpu-4gb

## 8. Glossary
Verdict: Allow|WouldBlock per target. ProtectedPorts: TCP ports jarsWAF exposes intentionally.
ControlBus: ArcSwap config snapshots + tokio broadcast events (cap 4096).
