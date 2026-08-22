# jarsWAF Architecture v1.0 — LOCKED

## 1. Components & Dependency Direction (acyclic, enforced by review)
waf-core (pure, no IO) <- waf-proxy <- bin jarswaf
waf-core <- waf-kernel (linux+feature xdp)
waf-core, waf-telemetry <- waf-controller <- bin jarswaf
waf-telemetry <- everyone. bin jarswaf = composition root only.

## 2. Request Flow (numbered, implement exactly)
1. Pingora accepts on proxy.listen.
2. Extract inspect targets (FR-PRX-02) incl. HPP join (FR-PRX-03).
3. Per target: normalize.run(bytes, ctx) -> NormalizeOutput{text,meta}.
4. tokenizer.tokenize(text) -> Vec<Token>.
5. evaluator.evaluate(tokens, meta, raw_lower, cfg) -> Verdict.
6. Cross-target merge: worst severity wins; report max per-target total.
7. Enforce per mode; emit telemetry; forward or block.
8. Stream upstream response back (headers+body passthrough).

Budget: steps 3-5 <=1ms CPU typical; guarded by NFR-PERF-02.

## 3. Control Plane
AppState = ArcSwap<RuntimeSnapshot{ rule_enabled: HashMap<&'static str,bool>,
threshold: u32, mode: RunMode }>. Toggle endpoint builds new snapshot via arc_swap::store.
Events: broadcast::Sender<WafEvent> cap 4096; SSE lag => counter increment, no backpressure.

## 4. File Tree (LOCKED, J1)
See companion file TREE.txt in repo root (generated at M0 from this doc; single source here).

## 5. Core Types (signatures LOCKED)
```rust
// waf-core
pub enum Verdict { Allow, WouldBlock { total_score: u32, hits: Vec<RuleHit> } }
pub struct RuleHit { pub rule_id: &'static str, pub score: u32 }
pub enum DecodeCtx { Path, QueryOrFormBody, JsonValue, HeaderValue } // HeaderValue used for UA/Referer/Cookie
pub struct NormalizeMeta { pub iterations_used: u8, pub hit_decode_cap: bool,
  pub comment_count: u32, pub version_comments: Vec<String> }
pub struct NormalizeOutput { pub text: String, pub meta: NormalizeMeta }
pub fn normalize_run(input: &[u8], ctx: DecodeCtx) -> NormalizeOutput;
pub enum Token { Kw(&'static str), Ident(String), Num(String), Str(String), Op(&'static str), Punct(char) }
pub fn tokenize(input: &str) -> Vec<Token>;
pub struct EvalCfg { pub threshold: u32 }
pub fn evaluate(tokens: &[Token], meta: &NormalizeMeta, raw_lower: &str, cfg: &EvalCfg) -> Verdict;
```

## 6. XDP Behavioral Contract (ebpf/src/main.rs)
Maps: TRUSTED_V4 lpm_trie key{prefixlen u32, addr u32} val u8;
PROTECTED_PORTS hash u16->u8; SYN_RATE lru_hash u32->u64(cap 65536);
BANNED_UNTIL lru_hash u32->u64(cap 65536); STAT_DROPPED array u64 len 1.
Logic order: !eth_ipv4 PASS; !tcp PASS; !(SYN&&!ACK) PASS; TRUSTED PASS;
PORT_ALLOWED PASS; banned DROP; bucket=count+1, count>limit => set banned, DROP; else PASS.
Loader injects config values before attach; writes marker /tmp/jarswaf-xdp-active on success,
removes on detach. Userspace mirror-harness implements identical predicate table for CI.

## 7. Failure Modes (binds B4)
Engine internal error => forward + engine_error event (fail-open).
Origin timeout/unreachable => 504.
XDP unavailable => warn + L7-only; stealth.sh SKIP 77.
Auth store poisoned => admin routes 503 (fail-closed), proxy unaffected.
Invalid config => exit!=0 BEFORE any socket bind.

## 8. CI Contract (.github/workflows/ci.yml)
job lint-test ubuntu-24.04, toolchain 1.84:
  cargo fmt --check
  cargo clippy --workspace --all-targets --all-features -- -D warnings
  cargo test --workspace
  bash scripts/ci-whitelist-check.sh   # diffs Cargo.lock names vs AGENTS whitelist; extra crate => exit 1
job ebpf: nightly + bpf-linker; cargo check -p ebpf --target bpfel-unknown-none
schedule nightly: fuzz-lite job (cargo test --features fuzzlite)
