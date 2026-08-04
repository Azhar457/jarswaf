# Pingora Architecture for jarsWAF

## ProxyHttp Trait Implementation

The core of jarsWAF's new reverse proxy engine will be implemented using Pingora's `ProxyHttp` trait.

### 1. `request_filter` (Phase: Client Request Received)
This hook is executed immediately after the HTTP request headers are parsed.
**Responsibilities:**
- Blacklist/Allowlist check (IP and Path)
- Rate limiting check
- Geoblocking check
- (Optional) Fast signature-based block

**Return:**
- `Ok(true)`: Request is blocked/handled directly (e.g., returning 403 Forbidden).
- `Ok(false)`: Proceed to upstream selection.

### 2. `upstream_peer` (Phase: Upstream Selection)
This hook determines where the request should be forwarded.
**Responsibilities:**
- Read the lock-free routing table (via `ArcSwap`).
- Match the `Host` header against configured VHosts.
- Select the `HttpPeer` (backend address).
- Apply SNI (if upstream is HTTPS).

**Return:**
- `Ok(Some(Box::new(HttpPeer)))`: Forward to the specified peer.
- `Ok(None)`: No matching VHost (returns 400 Bad Request).

### 3. `upstream_filter` (Phase: Before Sending Upstream)
Modify headers before they are sent to the backend.
**Responsibilities:**
- Inject `X-Forwarded-For`, `X-Real-IP`.
- Remove internal jarsWAF headers.

### 4. `logging` (Phase: Request Completed)
Executed after the entire request/response cycle finishes.
**Responsibilities:**
- Send request metrics, status code, and latency to the async logging channel (`log_tx`).

## Connection Pooling & Load Balancing
Pingora handles connection pooling natively. We will use `pingora_load_balancing::LoadBalancer` if multiple backends are configured per VHost. For single backends, standard `HttpPeer` will automatically utilize Pingora's connection reuse.

## Error Handling
If the upstream peer is unreachable or times out, Pingora will invoke `fail_to_connect` or return a 502/504 automatically. We can hook into `fail_to_connect` to log specific backend failures.
