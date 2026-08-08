# jarsWAF Architecture Specification

## STATUS: AUTHORITATIVE

This document is the SINGLE SOURCE OF TRUTH for jarsWAF architecture.
If code contradicts this document, the CODE IS WRONG.
If this document is ambiguous, raise an issue — do not interpret.

---

## 1. LAYER MODEL

jarsWAF has exactly 4 layers. Code MUST be placed in the correct layer.
There are NO exceptions.

```
┌─────────────────────────────────────────┐
│  LAYER 4: API (src/api/)               │  HTTP/gRPC → Commands
│  - No business logic                    │  Read-only state access
│  - Only translates requests to commands │  Auth + validation only
├─────────────────────────────────────────┤
│  LAYER 3: CONTROL BUS (src/control_bus/)│  Decision making
│  - Owns ALL mutable state               │  Receives events from L2
│  - Publishes state via ArcSwap          │  Sends commands to L1
│  - Rule evaluation, policy decisions    │  
├─────────────────────────────────────────┤
│  LAYER 2: DATA BUS (src/data_bus/)     │  Request processing
│  - Processes EVERY request              │  Runs inspector chain
│  - NO state mutation                    │  Emits events to L3
│  - Reads state via ArcSwap (lock-free)  │  Never blocks
├─────────────────────────────────────────┤
│  LAYER 1: KERNEL (src/kernel/)         │  eBPF interface
│  - ONLY code that touches eBPF maps     │  Batch I/O only
│  - No business logic                    │  Single entry point
│  - No direct access from L2/L3/L4      │  
└─────────────────────────────────────────┘
```

### Layer Communication Rules

| From | To | Mechanism | Direction |
|------|----|-----------|-----------|
| L2 → L3 | Events | `tokio::sync::mpsc` | One-way async |
| L3 → L2 | State | `arc_swap::ArcSwap` | Lock-free read |
| L4 → L3 | Commands | `tokio::sync::mpsc` | One-way async |
| L3 → L1 | Operations | Batched function calls | Periodic flush |
| L1 → L3 | Data | PerfEventArray poll | L3 pulls |

### WHAT IS FORBIDDEN

- L2 code MUST NOT write to DashMap, HashMap, or any mutable state
- L3 code MUST NOT process HTTP requests directly
- L4 code MUST NOT contain rule evaluation logic
- L1 code MUST NOT be called from anywhere except L3
- NO layer may import from a non-adjacent layer (L4 cannot import L1)

---

## 2. DIRECTORY STRUCTURE — MANDATORY

```
src/
├── main.rs
├── kernel/
│   ├── mod.rs
│   ├── interface.rs          # BpfMapInterface — ONLY place for map operations
│   ├── xdp.rs
│   ├── tc.rs
│   ├── rasp.rs
│   └── types.rs              # Shared structs with eBPF (must match exactly)
│
├── data_bus/
│   ├── mod.rs
│   ├── context.rs            # InspectionContext struct
│   ├── chain.rs              # InspectionChain
│   ├── events.rs             # DataEvent enum
│   └── inspectors/
│       ├── mod.rs
│       ├── sql_injection.rs
│       ├── xss.rs
│       ├── lfi_rfi.rs
│       ├── ssrf.rs
│       ├── command_injection.rs
│       ├── rate_limit.rs
│       ├── geoip.rs
│       ├── bot_detection.rs
│       ├── behavioral.rs
│       ├── ip_reputation.rs
│       └── custom_rules.rs
│
├── control_bus/
│   ├── mod.rs                # ControlBus struct + run() loop
│   ├── commands.rs           # ControlCommand enum
│   ├── config_manager.rs
│   ├── rule_engine.rs
│   ├── policy_engine.rs
│   ├── blocklist_manager.rs
│   ├── certificate_manager.rs
│   ├── gossip_manager.rs
│   └── honeypot_manager.rs
│
├── api/
│   ├── mod.rs
│   ├── state.rs              # ApiState struct
│   ├── auth.rs
│   ├── middleware.rs
│   ├── routes/
│   │   ├── mod.rs
│   │   ├── dashboard.rs
│   │   ├── rules.rs
│   │   ├── vhosts.rs
│   │   ├── blocklist.rs
│   │   ├── logs.rs
│   │   ├── agents.rs
│   │   ├── metrics.rs
│   │   └── ws.rs
│   └── dto/
│       ├── mod.rs
│       ├── requests.rs
│       └── responses.rs
│
├── proxy/
│   ├── mod.rs
│   ├── server.rs
│   └── adapter.rs           # Pingora → Data Bus bridge
│
├── storage/
│   ├── mod.rs
│   ├── sqlite.rs
│   ├── clickhouse.rs
│   └── file.rs
│
├── types/
│   ├── mod.rs
│   ├── config.rs
│   ├── rules.rs
│   ├── vhost.rs
│   ├── events.rs
│   └── network.rs
│
└── bin/
    ├── jarswaf.rs
    ├── controller.rs
    └── agent.rs
```

DO NOT create files outside this structure.
DO NOT create "utils.rs", "helpers.rs", or similar catch-all files.

---

## 3. CORE TYPES — EXACT DEFINITIONS

These types MUST be used exactly as defined. Do not add fields, do not rename.

### DataEvent (L2 → L3)

```rust
// src/data_bus/events.rs
#[derive(Debug, Clone)]
pub enum DataEvent {
    RequestInspected {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        vhost: String,
        verdict: Verdict,
        score: f64,
        matched_rules: Vec<RuleMatch>,
        latency_us: u64,
    },
    RequestBlocked {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        reason: BlockReason,
        rule_id: String,
    },
    RequestForwarded {
        request_id: uuid::Uuid,
        client_ip: std::net::IpAddr,
        backend: String,
        status_code: u16,
        latency_us: u64,
    },
    BackendError {
        request_id: uuid::Uuid,
        backend: String,
        error: String,
    },
    RateLimitExceeded {
        client_ip: std::net::IpAddr,
        limit: u32,
        window_secs: u64,
    },
}
```

### ControlCommand (L4 → L3)

```rust
// src/control_bus/commands.rs
#[derive(Debug, Clone)]
pub enum ControlCommand {
    // Config
    ReloadConfig,
    GetConfig(tokio::sync::oneshot::Sender<RuntimeConfig>),
    
    // Rules
    AddRule {
        rule: RuleDefinition,
        reply: tokio::sync::oneshot::Sender<Result<RuleId, CommandError>>,
    },
    RemoveRule {
        id: RuleId,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    SetRuleEnabled {
        id: RuleId,
        enabled: bool,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    
    // Blocklist
    BlockIp {
        ip: std::net::IpAddr,
        duration: std::time::Duration,
        reason: String,
    },
    UnblockIp {
        ip: std::net::IpAddr,
    },
    
    // Vhosts
    AddVhost {
        vhost: VhostConfig,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    RemoveVhost {
        name: String,
        reply: tokio::sync::oneshot::Sender<Result<(), CommandError>>,
    },
    
    // Internal
    Shutdown,
}
```

### InspectionContext (L2 internal)

```rust
// src/data_bus/context.rs
pub struct InspectionContext {
    // Request data (immutable after creation)
    pub request_id: uuid::Uuid,
    pub client_ip: std::net::IpAddr,
    pub method: http::Method,
    pub path: String,
    pub query_string: String,
    pub headers: http::HeaderMap,
    pub body: Option<bytes::Bytes>,
    pub vhost: String,
    pub timestamp: std::time::Instant,
    
    // Mutable state (accumulated through chain)
    pub verdict: Verdict,
    pub score: f64,
    pub matched_rules: Vec<RuleMatch>,
    pub tags: std::collections::HashSet<String>,
}

#[derive(Default, Clone, Debug)]
pub enum Verdict {
    #[default]
    Undecided,
    Allow,
    Block {
        reason: BlockReason,
        action: BlockAction,
    },
    Challenge {
        challenge_type: ChallengeType,
    },
    Redirect {
        url: String,
    },
}

#[derive(Debug, Clone)]
pub struct RuleMatch {
    pub inspector_name: String,
    pub rule_id: String,
    pub score_delta: f64,
    pub details: String,
}
```

### Inspector Trait

```rust
// src/data_bus/mod.rs (re-exported)
#[async_trait::async_trait]
pub trait Inspector: Send + Sync + 'static {
    fn name(&self) -> &str;
    fn priority(&self) -> u32;
    
    fn should_run(&self, ctx: &InspectionContext) -> bool {
        true
    }
    
    async fn inspect(&self, ctx: &mut InspectionContext) -> InspectionResult;
}

#[derive(Debug, Clone)]
pub struct InspectionResult {
    pub verdict: Option<Verdict>,
    pub score_delta: f64,
    pub details: String,
}
```

---

## 4. NAMING CONVENTIONS — MANDATORY

### Files
- `snake_case.rs` — always
- One primary type per file
- File name matches primary type: `sql_injection.rs` contains `SqlInjectionInspector`

### Types
- Structs: `PascalCase`
- Enums: `PascalCase`, variants: `PascalCase`
- Traits: `PascalCase` (no `Trait` suffix — use context to distinguish)
- Type aliases: `PascalCase` with `Type` suffix if ambiguous

### Functions
- `snake_case`
- No prefixes like `get_` or `set_` for simple accessors
- Use `is_`, `has_`, `should_` for boolean returns
- Async functions: NO `_async` suffix — Rust already has `.await`

### Variables
- `snake_case`
- Short names for local scope: `ctx`, `rx`, `tx`, `cfg`
- Descriptive names for module-level: `default_rate_limit`, `max_blocklist_entries`

### Constants
- `SCREAMING_SNAKE_CASE`
- No magic numbers — always name them

---

## 5. ERROR HANDLING PATTERN

ALL modules MUST use this pattern:

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ModuleNameError {
    #[error("kernel operation failed: {0}")]
    Kernel(#[from] KernelError),
    
    #[error("not found: {0}")]
    NotFound(String),
    
    #[error("invalid input: {0}")]
    InvalidInput(String),
    
    #[error("{0}")]
    Internal(String),
}

// For operations that can fail:
pub fn do_thing() -> Result<Thing, ModuleNameError> {
    // ...
}
```

NEVER use `unwrap()` in library code.
NEVER use `expect()` except in tests.
NEVER panic in non-test code.
Use `?` operator for error propagation.
Use `map_err()` to convert between error types.

---

## 6. ASYNC PATTERNS

### Channels
- Use `tokio::sync::mpsc` for command/event channels
- Buffer size: 1000 for events, 100 for commands
- NEVER use `std::sync::mpsc` (blocking)

### Locking
- Use `arc_swap::ArcSwap` for read-heavy state (rules, config, blocklist)
- Use `tokio::sync::RwLock` ONLY when ArcSwap is not possible
- Use `tokio::sync::Mutex` ONLY when both read and write need async
- NEVER use `std::sync::Mutex` in async context
- NEVER hold a lock across an `.await`

### Spawning
- Use `tokio::spawn` for background tasks
- ALWAYS use `tokio::select!` with a shutdown signal
- EVERY spawned task MUST have error logging

```rust
// CORRECT pattern for background tasks
pub fn start_background_task(shutdown: tokio::sync::watch::Receiver<bool>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = do_work().await {
                        tracing::error!("Background task failed: {}", e);
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("Background task shutting down");
                    break;
                }
            }
        }
    });
}
```

---

## 7. LOGGING PATTERNS

```rust
// TRACE: Very verbose, disabled in production
tracing::trace!("Parsing header: {:?} = {:?}", name, value);

// DEBUG: Useful for debugging, enabled in development
tracing::debug!("Inspector {} running for request {}", self.name(), ctx.request_id);

// INFO: Normal operations
tracing::info!("Configuration reloaded successfully");

// WARN: Recoverable problems
tracing::warn!("Rate limit exceeded for IP {}, but not blocking (score too low)", ip);

// ERROR: Failures that need attention
tracing::error!("Failed to sync blocklist from controller: {}", e);
```

NEVER log sensitive data (passwords, tokens, full request bodies).
NEVER log at INFO level inside request processing path (use DEBUG).

---

## 8. TESTING REQUIREMENTS

Every module MUST have:
- Unit tests for pure logic
- At least one integration test for trait implementations

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspector_blocks_sqli() {
        let inspector = SqlInjectionInspector::default();
        let mut ctx = make_test_context("GET /?id=1' OR '1'='1");
        
        let result = tokio_test::block_on(inspector.inspect(&mut ctx));
        
        assert!(matches!(result.verdict, Some(Verdict::Block { .. })));
        assert!(result.score_delta > 0.0);
    }
}
```

---

## 9. API ENDPOINT SPECIFICATION

All endpoints MUST follow this pattern:

```
Method  Path                          Auth    Description
------  ----                          ----    -----------
GET     /api/v1/health                No      Health check
GET     /api/v1/dashboard/summary     Yes     Dashboard stats
GET     /api/v1/config                Yes     Get current config
POST    /api/v1/config/reload         Yes     Trigger config reload

GET     /api/v1/rules                 Yes     List all rules
POST    /api/v1/rules                 Yes     Add rule
GET     /api/v1/rules/:id             Yes     Get rule detail
PUT     /api/v1/rules/:id             Yes     Update rule
DELETE  /api/v1/rules/:id             Yes     Delete rule
PATCH   /api/v1/rules/:id/enabled     Yes     Enable/disable rule

GET     /api/v1/vhosts                Yes     List vhosts
POST    /api/v1/vhosts                Yes     Add vhost
GET     /api/v1/vhosts/:name          Yes     Get vhost detail
PUT     /api/v1/vhosts/:name          Yes     Update vhost
DELETE  /api/v1/vhosts/:name          Yes     Delete vhost

GET     /api/v1/blocklist             Yes     List blocked IPs
POST    /api/v1/blocklist             Yes     Block IP
DELETE  /api/v1/blocklist/:ip         Yes     Unblock IP
POST    /api/v1/blocklist/sync        Yes     Trigger sync

GET     /api/v1/logs                  Yes     Query logs (paginated)
GET     /api/v1/logs/stream           Yes     SSE log stream

GET     /api/v1/agents                Yes     List agents
GET     /api/v1/agents/:hostname      Yes     Agent detail
GET     /api/v1/agents/:hostname/metrics  Yes  Agent metrics

GET     /api/v1/metrics               Yes     Prometheus metrics

WS      /ws/events                    Yes     Real-time events
WS      /ws/metrics                   Yes     Real-time metrics
```

### Response Format

```rust
// Success
{ "data": <T> }

// Error
{ "error": { "code": "RULE_NOT_FOUND", "message": "Rule 'XSS-001' not found" } }

// List (paginated)
{ 
    "data": [<T>, ...],
    "pagination": { "page": 1, "per_page": 50, "total": 234 }
}
```

### Error Codes

```
NOT_FOUND          404  Resource does not exist
VALIDATION_ERROR   400  Invalid request body/params
AUTH_REQUIRED      401  Missing or invalid token
FORBIDDEN          403  Valid token but insufficient permissions
CONFLICT           409  Resource already exists
INTERNAL_ERROR     500  Unexpected server error
```

---

## 10. FRONTEND CONTRACT

The frontend team MUST only depend on:
1. This document
2. The API endpoint specification (Section 9)
3. The response format (Section 9)
4. The WebSocket event types (defined below)

Frontend MUST NOT depend on internal Rust types or implementation details.

### WebSocket Events (Server → Client)

```typescript
// These are the ONLY event types the frontend should handle

type WsEvent = 
  | { type: "log"; data: LogEntry }
  | { type: "metrics"; data: MetricsUpdate }
  | { type: "blocklist_update"; data: BlocklistUpdate }
  | { type: "rule_change"; data: RuleChange }
  | { type: "alert"; data: Alert }
  | { type: "config_reload"; data: ConfigReloadEvent };

interface LogEntry {
  timestamp: string;        // ISO 8601
  request_id: string;       // UUID
  client_ip: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS";
  path: string;
  action: "ALLOW" | "BLOCK" | "CHALLENGE" | "REDIRECT";
  rule_id?: string;
  score: number;
  latency_ms: number;
  vhost: string;
}

interface MetricsUpdate {
  timestamp: string;
  requests_per_sec: number;
  blocked_per_sec: number;
  active_connections: number;
  cpu_percent: number;
  ram_percent: number;
  top_blocked_ips: Array<{ ip: string; count: number }>;
  top_triggered_rules: Array<{ rule_id: string; count: number }>;
}

interface BlocklistUpdate {
  added: string[];   // IP addresses
  removed: string[];
}

interface RuleChange {
  rule_id: string;
  change: "added" | "removed" | "enabled" | "disabled" | "updated";
}

interface Alert {
  level: "warning" | "error" | "critical";
  message: string;
  timestamp: string;
  source: string;
}

interface ConfigReloadEvent {
  success: boolean;
  error?: string;
  timestamp: string;
}
```

---

## 11. CONFIGURATION SCHEMA

```toml
[global]
port_http = 8000
port_https = 8443
mode = "standalone"  # "standalone" | "agent" | "controller"
log_level = "info"   # "trace" | "debug" | "info" | "warn" | "error"
admin_token = ""     # MUST be set via env var JARSWAF_ADMIN_TOKEN

[global.ebpf]
tc_interface = "eth0"
ebpf_load_failure = "pass"  # "pass" | "drop_all"

[global.performance]
cleanup_interval_secs = 300
rate_limiter_max_entries = 100000
log_channel_buffer = 10000

[tls]
mode = "local_ca"  # "disabled" | "local_ca" | "letsencrypt"
cert_dir = "./certs"

[logging]
mode = "sqlite"  # "sqlite" | "clickhouse" | "file"
db_path = "/var/log/jarswaf/jarswaf.db"

[redis]
enabled = false
url = "redis://127.0.0.1:6379"

[gossip]
enabled = false
bind_addr = "0.0.0.0:7946"
psk = ""  # REQUIRED if gossip.enabled = true
seeds = []

[honeypot]
enabled = false
upstream_addr = "127.0.0.1:9999"
```

---

## CHANGELOG

| Date | Change | Author |
|------|--------|--------|
| 2024-XX-XX | Initial architecture spec | - |
