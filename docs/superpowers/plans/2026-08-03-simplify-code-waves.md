# simplify-code Wave 1-3 Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clean up working jarsWAF code without changing behavior — dedup, typed-enum tightening, dead-code wiring, and security hardening (fail-closed auth, peer-trusted header sanitize).

**Architecture:** Lazy-refactor pass over the existing Rust codebase. Each fix is isolated to its owning module; shared truncation/base64 helpers consolidate into `src/utils.rs`. No new abstractions where stdlib or existing crates suffice (base64, serde).

**Tech Stack:** Rust (edition 2021 — do NOT bump, pre-existing lints from the edition-2021-vs-async lint quirk are pre-existing noise, not new), cargo, serde, base64, ahash, pingora.

## Global Constraints
- **Never simplify away:** input validation at trust boundaries, error handling preventing data loss, security, accessibility. Specifically: fail-closed auth, constant-time token compare, un-spoofable peer IP for trusted-proxy checks.
- **Chesterton's Fence:** don't delete working code before `git blame`; `confidence: low` → keep.
- Exclude pre-existing lint noise: the `async fn ... Rust 2015/2018` errors and `edition 2021` lint are **pre-existing** — do not "fix the edition". Ignore them; only fix warnings introduced by our changes.
- Every change: `cargo fmt` + `cargo clippy -D warnings` (only NEW warnings matter) + `cargo test`. If `cargo test` breaks, revert the patch.
- After finishing all tasks, run `cargo test` — baseline is **164 pass (158 lib + 6 utils), 0 fail**. That is the acceptance gate.
- Do NOT rename public contracts (function names, struct fields, config schema values that are in the wild).

---

## Task 1: Shared truncation + base64 helpers in `src/utils.rs`

**Files:**
- Create: `src/utils.rs` (106 lines)
- Modify: `src/lib.rs` — add `pub mod utils;`

**Interfaces:**
- Produces:
  - `pub fn base64_url_decode(s: &str) -> Result<Vec<u8>, String>` — hybrid 2-engine leniency (accept URL_SAFE_NO_PAD and STANDARD), strips trailing `=` padding before decoding.
  - `pub fn extract_json_string(s: &str, key: &str) -> Option<String>`
  - `pub fn extract_json_number(s: &str, key: &str) -> Option<f64>`
  - `pub fn safe_truncate(s: &str, max: usize) -> &str` — char-boundary safe truncation (never splits a multi-byte UTF-8 char).

- [ ] Step 1: Write `src/utils.rs` with the four helpers above + 5 unit tests (valid base64, padded base64, invalid base64, truncate mid-char, extract json).
- [ ] Step 2: Add `pub mod utils;` to `src/lib.rs` alphabetical position.
- [ ] Step 3: Commit.

---

## Task 2: Harden base64url decoding (trust.rs + api.rs)

**Files:**
- Modify: `src/rules/trust.rs` — replace hand-rolled decoder + padding logic
- Modify: `src/rules/api.rs` — replace local hybrid decoder
- Modify: `src/rules/body.rs` — replace `safe_payload_slice` with `crate::utils::safe_truncate`
- Modify: `src/dlp.rs` — replace `&raw_body[..scan_len.min(1MB)]` slice with `safe_truncate` (this is a latent panic fix: slicing could split a multi-byte UTF-8 char)

**Interfaces:**
- Consumes: `src/utils.rs` (Task 1)
- Produces: no new public API. Removes private duplicate decoders.

- [ ] Step 1: In `trust.rs`, replace inline decoder and call `crate::utils::base64_url_decode` at the 5 call sites (payload_bytes, header_bytes, alg, exp, iss). **Important:** `base64_url_decode` uses URL_SAFE_NO_PAD which REJECTS padded input — strip trailing `=` (via `trim_end_matches('=')`) at the caller before passing (option (a) chosen over engine swap).
- [ ] Step 2: In `api.rs`, delete local decoder, call `crate::utils::base64_url_decode` (note the signature change `Result<Vec<u8>, &'static str>` → `Result<Vec<u8>, String>`).
- [ ] Step 3: In `body.rs`, delete `safe_payload_slice`, call `crate::utils::safe_truncate` (MAX_INSPECT_BYTES 128KB lives in `matches_payload`).
- [ ] Step 4: In `dlp.rs`, replace the risky byte-slice with `crate::utils::safe_truncate` using the same limit.
- [ ] Step 5: `cargo test src/utils.rs` + `cargo test` — trust.rs tests must be 9/9 green. Full suite must be 164 pass.
- [ ] Step 6: Commit.

---

## Task 3: Dedup peer-trust + crawler whitelist (proxy_engine.rs + whitelist.rs)

**Files:**
- Modify: `src/proxy_engine.rs` — extract `is_peer_trusted(config, peer_ip)` helper; reuse `is_whitelisted_bot_ctx`
- Modify: `src/rules/whitelist.rs` — add social-bot patterns to `BOT_WHITELIST`
- Modify: `src/rules.rs` — call site for `is_whitelisted_bot_ctx`

**Interfaces:**
- Consumes: existing `sanitize_proxy_headers`, `is_whitelisted_bot_ctx`
- Produces: `fn is_peer_trusted(&Config, IpAddr) -> bool` (private helper)

- [ ] Step 1: Extract `is_peer_trusted(config, peer_ip)` from the duplicated TCP-peer check (inside `sanitize_proxy_headers` vs the ~line 859-862 call site). Fix the `E0308` by derefing the `ArcSwap` guard → `&config`.
- [ ] Step 2: Extend `BOT_WHITELIST` regex with anchored social-bot patterns (facebookexternalhit, twitterbot, linkedinbot, whatsapp, applebot, slurp, duckduckbot, yandexbot, baiduspider, sogou) — keep the anchored regexes so substring scanner spoofs stay blocked.
- [ ] Step 3: Replace the inline 13-bot crawler list in `proxy_engine.rs` with `is_whitelisted_bot_ctx`.
- [ ] Step 4: Build + test — 164 pass. Commit.

---

## Task 4: Dedup sysinfo collection + cache (agent/metrics.rs + controller/handlers/agents.rs)

**Files:**
- Modify: `src/agent/metrics.rs`
- Modify: `src/controller/handlers/agents.rs`
- Modify: `src/rules/whitelist.rs` — drop dead `_client_ip` param (`is_whitelisted_bot_ctx`)
- Modify: `src/rules.rs` — update call site (was `rules.rs:503`)

**Interfaces:**
- Produces: `collect_local_agent_info()` (shared, single source) + `OnceLock<TTL 5s>` cache for sysinfo.

- [ ] Step 1: Create shared `collect_local_agent_info()`; add `OnceLock` cache (TTL 5s) to kill the `sysinfo::new_all` per-poll.
- [ ] Step 2: Refactor standalone branch in `handlers/agents.rs` to use the collector.
- [ ] Step 3: Drop `_client_ip` param from `is_whitelisted_bot_ctx` (verify `IpAddr` import still used at line 89 — keep import if used elsewhere, else remove).
- [ ] Step 4: Build + test + commit.

---

## Task 5: Config single-source cleanup (gossip.rs, honeypot.rs, controller/mod.rs)

**Files:**
- Modify: `src/gossip.rs` — remove `JARSWAF_GOSSIP_PSK` env override (config.rs is single source of truth for PSK)
- Modify: `src/honeypot.rs` + `src/proxy_engine.rs` — replace magic `"127.0.0.1:9999"` with `unwrap_or_else(|| default_honeypot_upstream())`; make `default_honeypot_upstream()` pub
- Modify: `src/controller/mod.rs` — replace 3-way hardcoded `static_dir` fallback with `JARSWAF_STATIC_DIR` env override + `probe_static_dir()` helper

**Chesterton's Fence:** If `gossip` PSK env override is used by any deployed config, this is a behavior change — confirm with `git blame` that it's genuinely redundant before removing.

- [ ] Steps 1-3: Apply each patch.
- [ ] Step 4: Build + test + commit.

---

## Task 6: Single atomic EngineState store (proxy_engine.rs) — security torn-read fix

**Files:**
- Modify: `src/proxy_engine.rs`

**Interfaces:**
- Produces: `pub struct EngineState { pub config: Arc<Config>, pub rule_engine: Arc<crate::rules::RuleEngine> }` + `static GLOBAL_ENGINE: Lazy<OnceLock<...>>`

**Goal:** Replace `GLOBAL_CONFIG` + `GLOBAL_RULE_ENGINE` (two separate `ArcSwap`) with ONE `GLOBAL_ENGINE` holding both. Prevents torn reads during SIGHUP reload — a request never sees a config from one generation and a rule_engine from another.

- [ ] Step 1: Define `EngineState` struct. **Must be `pub struct` with `pub` fields** — clippy warns `type EngineState is more private than the item GLOBAL_ENGINE` if not.
- [ ] Step 2: Define `static GLOBAL_ENGINE`. Remove `GLOBAL_CONFIG` and `GLOBAL_RULE_ENGINE`.
- [ ] Step 3: Migrate every call site. Pattern:
  - `GLOBAL_ENGINE.load().config.clone()` → `let _config = ...`
  - `GLOBAL_ENGINE.load().config.global.log_level...`
  - `GLOBAL_ENGINE.load().rule_engine.clone()`
  When the local var is only used for field reads, you may hold the `engine` guard directly: `let engine = GLOBAL_ENGINE.load(); engine.config.global.log_level...` — but if you cross an `await`, clone out (`engine.config.clone()`) to avoid holding the guard across the await.
- [ ] Step 4: Call sites to update (proxy_engine.rs): ~559, 746, 861, 994, 1558, 1989, 2069. Verify zero residual `GLOBAL_CONFIG`/`GLOBAL_RULE_ENGINE` with grep.
- [ ] Step 5: Build + test + commit.

**Pitfall:** `USE `GLOBAL_ENGINE.load().config.clone()` (config becomes `Arc<Config>`) — field access still works via deref. Don't blindly clone the whole EngineState; clone only what each scope needs.

---

## Task 7: LOAD_BALANCER reconcile on reload (proxy_engine.rs)

**Files:**
- Modify: `src/proxy_engine.rs` (~line 1395-1405)

**Goal:** The LOAD_BALANCER map used `.entry().or_insert_with()` which builds backends ONCE and never reconciles after SIGHUP reload. If config reload changes backend addrs, the map stays stale.

- [ ] Step 1: Replace the lazy-init so it reconcile on every request: if `entry.len() != desired_backends.len()` OR any addr differs, replace the whole list with the current config's backends (dropping health state is unnecessary — backends are fresh on change).
- [ ] Step 2: Clippy fix — use `.or_default()` not `.or_insert_with(Vec::new)` (clippy `or_fun_call` warning appears once entry exists).
- [ ] Step 3: Build + test + commit.

---

## Task 8: gRPC auth fail-closed + ephemeral token (grpc/server.rs + controller/mod.rs) — SECURITY

**Files:**
- Modify: `src/grpc/server.rs`
- Modify: `src/controller/mod.rs`

**Goal:** (1) Replace hardcoded known fallback `"default_token"` (public in README/config examples) with a random 24-char ephemeral token (fail-closed default). (2) `verify_token` must be fail-closed: empty `auth_token` → REJECT all (currently returns `Ok(())` — fail-open = auth bypass). (3) Compare tokens constant-time.

- [ ] Step 1: controller/mod.rs — replace `.unwrap_or_else(|| "default_token".to_string())` with a 24-char random alphanumeric generator (use `rand::thread_rng`; the dev-dependency `rand` is available) + a `tracing::warn!` explaining to set `grpc_token` config for stability. Keep the `tokio::spawn(run_manager_server(...))` block this patch wraps.
- [ ] Step 2: grpc/server.rs `verify_token`: change empty-token branch from `Ok(())` → `Err(Status::unauthenticated("gRPC auth not configured"))` (fail-closed).
- [ ] Step 3: Add `fn constant_time_eq(a: &[u8], b: &[u8]) -> bool` (len check + XOR accumulation) and use it for token compare instead of `==`.
- [ ] Step 4: Build + test + commit.

---

## Task 9: Body-path peer-IP sanitize (proxy_engine.rs) — SECURITY

**Files:**
- Modify: `src/proxy_engine.rs`

**Goal:** In `request_body_filter`, the `sanitize_proxy_headers` call (body inspection path) was using `ctx.client_ip` as the peer IP. `ctx.client_ip` is the **visitor IP** (header-derived, spoofable if the peer is a trusted proxy). An attacker spoofing `CF-Connecting-IP: <trusted_proxy>` could make `is_peer_trusted` return true → skip sanitize → inject X-Forwarded-For. Use the real TCP peer instead.

- [ ] Step 1: Add `pub peer_ip: Option<IpAddr>` field to `JarsWafCtx`.
- [ ] Step 2: Set it in `new_ctx()` → `peer_ip: None`.
- [ ] Step 3: In `request_filter`, right after `ctx.client_ip = Some(client_ip)`, add `ctx.peer_ip = Some(peer_ip)`.
- [ ] Step 4: In `request_body_filter`, change the sanitize block from `if let Some(peer_ip) = ctx.client_ip` to `if let Some(peer_ip) = ctx.peer_ip` + a comment explaining why (unspoofable TCP peer vs header-derived visitor).
- [ ] Step 5: Build + test + commit.

---

## Task 10: Wire dead IPv6 XDP block + ScoringMode enum (rules.rs + config.rs + xdp.rs) — Wave 3

**#18 — IPv6 block wiring (xdp.rs + rules.rs):**
`block_ip_v6(&mut self, _ip: Ipv6Addr) -> Result<(), String>` is fully implemented (XDP BLOCKLIST_V6 map, `#[cfg(target_os="linux")]`) but never called. All callers only handle `IpAddr::V4`.

- [ ] Determine the call site that should also handle V6. In `rules.rs:178` the escalation block does `if let IpAddr::V4(v4) = ip_clone { ... }` — it can also match V6. There are ~6 callers of `xdp.block_ip(...)`, all IPv4-only; the **first** (threat-triggered blocklist at `rules.rs:178`) is the correct wire point because it's where raw `IpAddr` (may be V6) is matched.
- [ ] In rules.rs replace the `if let IpAddr::V4(v4)` arm with a `match` that also does `IpAddr::V6(v6) => { let _ = xdp.block_ip_v6(v6); }`.
- [ ] Leave the gossip/threat-intel broadcast only on the V4 arm (agent nodes are IPv4-only in this codebase).

**#1 — ScoringMode enum (config.rs + rules.rs + vhost.rs):**
Replace `scoring_mode: String` (2 values: `"immediate"`/`"anomaly"`) with a typed enum, but **keep serde string-compat** so existing config files keep parsing.

- [ ] config.rs: add
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize, Default)]
  #[serde(rename_all = "lowercase")]
  pub enum ScoringMode { #[default] Immediate, Anomaly }
  impl ScoringMode { pub fn as_str(&self) -> &'static str { match self {
    ScoringMode::Immediate => "immediate", ScoringMode::Anomaly => "anomaly" } } }
  fn default_scoring_mode() -> ScoringMode { ScoringMode::default() }
  ```
- [ ] config.rs: change `GlobalConfig.scoring_mode: String → ScoringMode`.
- [ ] rules.rs: `RuleEngine.scoring_mode: String → crate::config::ScoringMode`; line 533 `self.scoring_mode == "anomaly"` → `== crate::config::ScoringMode::Anomaly`.
- [ ] rules.rs + vhost.rs: all `scoring_mode: "immediate".to_string()` literal fixtures → `crate::config::ScoringMode::default()`. Test setters `= "anomaly"/"immediate".to_string()` → `= ScoringMode::Anomaly/Immediate`.
- [ ] Build + test + commit. Verify `serde(rename_all="lowercase")` round-trips TOML `scoring_mode = "anomaly"`.

---

## Final Verification Gate

- [ ] `cargo fmt`
- [ ] `cargo clippy --all-targets` — only pre-existing exceptions allowed (edition lint, `Err` too large in grpc/server.rs). **