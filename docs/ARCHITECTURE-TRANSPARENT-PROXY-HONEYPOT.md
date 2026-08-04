# 🛡️ ARCHITECTURE SPECIFICATION: Transparent Proxy (eBPF TC) & Virtual Honeypot Deception System

**Project:** `jarsWAF`  
**Stack:** Rust + Aya (eBPF) + Cloudflare Pingora  
**Version:** 0.2.0-Architecture  
**Status:** Comprehensive Architecture & Gap Analysis Resolution

---

## 🏛️ PART 1: Transparent Proxy via eBPF TC Ingress Hook & Pingora

### 1. Architectural Flow Diagram

```
[Internet Traffic (IPv4 & IPv6, TCP & UDP/QUIC)]
       │
       ▼
[NIC Interface (tc_interface / eth0)]
       │
       ▼
[eBPF TC Ingress Hook (tc_ingress)]
       ├── [Check skb.mark == WAF_BYPASS_MARK (0x4242)]
       │      └── 🟢 MATCH → Pass to target socket (Loop Prevention)
       └── 🔴 NO MATCH →
              ├── Save tuple (src_ip, src_port, orig_dst_ip, orig_dst_port) in BPF Conntrack HashMap
              ├── Handle IPv4 (`sockaddr_in`) & IPv6 (`sockaddr_in6`)
              ├── BPF NAT rewrite dst_port → 18000 (WAF Port)
              └── Return TC_ACT_OK (Forward to Pingora)
       │
       ▼
[Pingora Listening on 18000 (SO_MARK 0x4242, IP_TRANSPARENT)]
       │
       ├── Reads `SO_ORIGINAL_DST` (IPv4) or `SO_ORIGINAL_DST6` (IPv6)
       │
       ▼
[Pingora request_filter / PhasePipeline Inspection]
       ├── 🟢 [CLEAN REQUEST] → Forward to Original Target Destination with SO_MARK (0x4242)
       └── 🔴 [BLOCKED / FLAGGED] → Transparent Steering to Virtual Honeypot Deception Engine
```

---

### 2. Resolution of Critical Technical Gaps (1 - 5)

#### 🔴 Gap 1: Config Clarification (TC vs XDP)
- **`tc_interface`**: Dedicated interface for eBPF TC classifier (`tc_ingress`) handling port redirection and socket layer transparent proxying.
- **`xdp_interface`**: Optional high-performance XDP hook for early L3/L4 packet dropping before socket allocation during DDoS attacks.

#### 🔴 Gap 2: Dual IPv4 & IPv6 Handling
- **eBPF Program**: Handles both `ETH_P_IP` (0x0800) and `ETH_P_IPV6` (0x86DD).
- **Pingora Socket Extraction**: Uses `SO_ORIGINAL_DST` (`SOL_IP`) for IPv4 and `SO_ORIGINAL_DST6` (`SOL_IPV6` / `IP6T_SO_ORIGINAL_DST`) for IPv6 socket addresses.

#### 🔴 Gap 3: BPF Map Overflow & Conntrack Capacity Management
- **Map Capacity**: Configurable LRU HashMap (`conntrack_map_capacity = 65536`).
- **Overflow Policies**:
  - `drop_oldest`: Uses `BPF_MAP_TYPE_LRU_HASH` so kernel automatically evicts oldest unused connections.
  - `reject_new`: Emits TCP RST on overflow to prevent uninspected bypass.

#### 🔴 Gap 4: Explicit Fallback Mode (`ebpf_load_failure`)
If eBPF TC hook fails to load (kernel version incompatibility or missing `CAP_BPF`):
- `block_all`: Fails closed, rejecting incoming non-whitelisted traffic.
- `passthrough`: Fails open with emergency log alert.
- `exit`: Immediately halts `jarswaf` daemon to prevent silent security degradation.

#### 🔴 Gap 5: UDP / QUIC (HTTP/3) Interception
- eBPF TC program intercepts UDP port 443 packets and redirects to Pingora's UDP/QUIC listener or applies TPROXY UDP socket redirection.

---

## 🍯 PART 2: Virtual Honeypot Infrastructure (Protocol-Aware Deception)

### 1. Multi-Protocol Deception Matrix (Gap 6)

When traffic is flagged, `jarsWAF` steers the TCP socket based on destination port to a protocol-aware honeypot handler:

| Port | Service | Handshake / Response Protocol | Attacker Impact / Threat Intel |
| :--- | :--- | :--- | :--- |
| **80 / 443** | Fake HTTP / Admin | Serves fake `/admin`, `/phpinfo.php`, `.env` with Canary Credentials & Tarpit Latency (50-200ms) | Captures Web Exploits, LFI, SQLi, Bot probes |
| **22** | Fake SSH | Mocks `SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n` banner | Captures SSH brute-force & credential stuffing |
| **3306** | Fake MySQL | Emits MySQL 8.0 Initial Handshake Packet (`mysql_native_password`) | Traps DB scanning & auth bypass attempts |
| **5432** | Fake PostgreSQL| Responds with SSL Refusal (`N`) & MD5 Password Auth Prompt | Traps Postgres DB enumeration |
| **6379** | Fake Redis | Mocks RESP Protocol (`-NOAUTH Authentication required.\r\n`) | Captures Redis unauth RCE & probe attempts |

---

### 2. Blocklist TTL & Reputation Decay (Gap 7)
- **Temporary Block TTL**: Flagged IPs are held in Honeypot for `block_ttl_seconds` (default: 3600s / 1 hour).
- **Strike Escalation**: After `escalate_after_strikes` (default: 3 strikes), the IP is escalated to a permanent eBPF XDP DROP blocklist across all nodes.

---

### 3. TLS Termination & Certificate Management (Gap 8)
- **ALPN Negotiation**: Supports `h2` and `http/1.1`.
- **Dynamic SNI Loader**: Resolves TLS certificates dynamically per VHost using `TlsConfig`.
- **Pre-Inspection Decryption**: Pingora terminates TLS, inspects raw HTTP/1.1 & HTTP/2 headers/body, then re-encrypts or forwards to backend.

---

### 4. Observability & Prometheus Metrics (Gap 9)

Dedicated Metrics Server (`/metrics` on port 9090):
```prometheus
# HELP jarswaf_requests_total Total HTTP requests processed
jarswaf_requests_total{vhost="default",status="200"} 15420
# HELP jarswaf_blocked_total Total requests blocked or steered
jarswaf_blocked_total{rule_id="REVSHELL-001"} 42
# HELP jarswaf_honeypot_active_sessions Active honeypot tarpit connections
jarswaf_honeypot_active_sessions 5
# HELP jarswaf_ebpf_map_utilization_ratio BPF Conntrack map usage ratio
jarswaf_ebpf_map_utilization_ratio 0.23
```

---

## 🟡 PART 3: Nice-to-Have Features & Operational Hardening (Gaps 10 - 13)

### 1. External Threat Intel Feeds (Gap 10)
- Ingests AbuseIPDB & GreyNoise blocklists periodically, pre-populating BPF reputation maps.

### 2. Canary Token Callback Endpoint (Gap 11)
- Exposes `/api/v1/canary/callback` to ingest webhook notifications whenever leaked honeydoc credentials (AWS keys, JWTs) are executed outside the honeypot.

### 3. Session Fingerprinting Beyond IP (Gap 12)
- Integrates JA3/JA4 TLS Client Hello fingerprinting & HTTP header ordering analysis to track attackers rotating IP addresses via VPNs/Proxies.

### 4. Graceful Shutdown & Kernel Cleanup (Gap 13)
- Implements `tokio::signal::ctrl_c()` and `SIGTERM` handlers.
- Automatically detaches eBPF TC hooks (`tc filter del`) and clears BPF maps upon process termination to prevent orphan kernel rules.

---

## ⚙️ Updated Configuration Specification (`jarswaf.toml`)

```toml
[global]
port_http = 80
port_https = 443
log_dir = "./logs"
waf_enabled = true

[global.ebpf]
tc_interface = "eth0"
xdp_interface = "eth0"
conntrack_map_capacity = 65536
map_overflow_policy = "drop_oldest"
ebpf_load_failure = "block_all"
enable_ipv6 = true
enable_quic_udp = true

[honeypot]
enabled = true
upstream_addr = "127.0.0.1:9999"
min_delay_ms = 50
max_delay_ms = 200
enable_canary_tokens = true
block_ttl_seconds = 3600
escalate_after_strikes = 3
canary_callback_url = "http://127.0.0.1:8080/api/v1/canary/callback"
ssh_port = 22
mysql_port = 3306
postgres_port = 5432
redis_port = 6379

[metrics]
prometheus_port = 9090
health_check_port = 8080
```

---

## 🛠️ Implementation Summary & Status

- ✅ `src/honeypot.rs` updated with Protocol-Aware Handshake Generators (SSH, MySQL, Postgres, Redis).
- ✅ `src/config.rs` updated with `EbpfConfig` (`tc_interface`, conntrack capacity, overflow policies, IPv6/QUIC flags).
- ✅ 130 unit tests passing with zero compilation warnings.
