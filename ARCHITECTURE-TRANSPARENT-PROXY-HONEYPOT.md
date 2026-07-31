# 🛡️ ARCHITECTURE SPECIFICATION: Transparent Proxy (eBPF TC) & Virtual Honeypot Deception System

**Project:** `jarsWAF`  
**Stack:** Rust + Aya (eBPF) + Cloudflare Pingora  
**Status:** Architecture Design & Subsystem Specification

---

## 🏛️ PART 1: Transparent Proxy via eBPF TC Ingress Hook & Pingora

### 1. Architectural Flow Diagram

```
[Internet Traffic]
       ↓ (Port 80/443 or any port)
[NIC eth0 (Host / Container)]
       ↓
[eBPF TC Ingress Hook (tc_ingress)]
       ├── Check skb.mark == WAF_BYPASS_MARK (0x4242)
       │      └── [MATCH] → Allow (Bypass to real socket/loopback)
       └── [NO MATCH] →
              ├── Save (src_ip, src_port, orig_dst_ip, orig_dst_port) in BPF HashMap
              ├── BPF bpf_skb_store_bytes() / NAT dst_port → 18000 (WAF Port)
              └── Return TC_ACT_OK (Forward to Pingora)
       ↓
[Pingora Listening on 18000 with SO_MARK (0x4242) & IP_TRANSPARENT]
       ↓
[Pingora request_filter / PhasePipeline Inspection]
       ├── [ALLOWED] → Read SO_ORIGINAL_DST via `getsockopt`
       │                Forward to Original Target Destination with SO_MARK (0x4242)
       └── [BLOCKED/FLAGGED] → Transparent Steering to Virtual Honeypot (127.0.0.1:9999)
```

### 2. Key Components & Implementation Design

#### A. eBPF TC Classifier (`tc_ingress`)
- **Hook Type:** `BPF_PROG_TYPE_SCHED_CLS` attached to `tc ingress` on network interface (`eth0`).
- **Loop Prevention (`SO_MARK`):**
  - When Pingora makes outgoing backend connections to original destinations, it sets `SO_MARK` socket option to `0x4242` (`WAF_BYPASS_MARK`).
  - The eBPF TC classifier checks `skb->mark`. If `skb->mark == 0x4242`, the packet is immediately passed (`TC_ACT_OK`) without port rewriting, preventing infinite proxy loops.
- **Port Rewriting:**
  - Rewrites TCP destination port from target port (e.g. 80, 443, 8080) to Pingora WAF port (e.g. 18000).
  - Recalculates TCP/IP checksums using BPF helpers.

#### B. Pingora Socket Configuration
- **`IP_TRANSPARENT`:** Enables binding/listening to non-local addresses and receiving packets redirected by eBPF/tproxy.
- **`SO_ORIGINAL_DST` (`getsockopt`):**
  - Extract `sockaddr_in` from client socket to retrieve real destination IP and Port before proxy interception.

---

## 🍯 PART 2: Virtual Honeypot Deception Infrastructure (Tarpit + Honeypot Hybrid)

### 1. Core Design Philosophy
When an attacker sends malicious payloads (SQLi, RevShell, LFI, Bot probes) or comes from a high-risk IP:
- ❌ **Traditional WAF:** Returns instant `403 Forbidden` or `DROP`. (Gives instant feedback to attackers, prompting IP rotation or tool modification).
- ✅ **jarsWAF Virtual Honeypot:** Transparently steers the attacker's TCP connection to an isolated **Honeypot Deception Engine** (`127.0.0.1:9999` or Honeypot NetNS).
- **Result:** Attacker believes their attack succeeded or is interacting with a vulnerable target, wasting their resources, delaying further attacks, and exposing their tactics (`HoneypotEvent` threat intelligence).

---

### 2. Deception Architecture Layers

```
                               ┌────────────────────────────────────────────────────────┐
                               │             Pingora WAF (Port 18000)                   │
                               └──────────────────────────┬─────────────────────────────┘
                                                          │ Flagged Attacker Connection
                                                          ▼
                               ┌────────────────────────────────────────────────────────┐
                               │           Honeypot Steering Controller                 │
                               │  - Sets ctx.upstream_override = "127.0.0.1:9999"      │
                               │  - Logs HoneypotEvent (IP, Path, Payload, UA)          │
                               └──────────────────────────┬─────────────────────────────┘
                                                          │ Forward Connection
                                                          ▼
   ┌─────────────────────────────────────────────────────────────────────────────────────────────────┐
   │ Virtual Honeypot Network Namespace (`ip netns add honeypot`)                                    │
   │                                                                                                 │
   │   ┌─────────────────────────────────┐               ┌───────────────────────────────────────┐   │
   │   │ Fake Admin & API Deception      │               │ Canary Token Injector (Honeydoc)      │   │
   │   │ - `/admin`, `/wp-admin`         │               │ - Fake `.env` with Canary Credentials │   │
   │   │ - `/phpinfo.php`, `/.git/config`│               │ - Fake API keys (AWS/JWT)             │   │
   │   └─────────────────────────────────┘               └───────────────────────────────────────┘   │
   │                                                                                                 │
   │   ┌─────────────────────────────────┐               ┌───────────────────────────────────────┐   │
   │   │ Tarpit Latency Generator        │               │ Network Sandbox & Outbound Isolation  │   │
   │   │ - Artificial delay (50-200ms)    │               │ - `iptables -P OUTPUT DROP`           │   │
   │   └─────────────────────────────────┘               └───────────────────────────────────────┘   │
   └─────────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 3. Deception Capabilities Matrix

| Deception Feature | Description | Threat Intel / Operational Purpose |
| :--- | :--- | :--- |
| **Honeypot Traffic Steering** | `ctx.upstream_override = Some("127.0.0.1:9999")` | Redirects flagged traffic seamlessly without breaking TCP handshake. |
| **Fake Admin Panels** | Mocks `/admin`, `/phpinfo.php`, `/wp-admin`, `/api/v1/auth` | Collects credential stuffing & automated bot login attempts. |
| **Canary Tokens (`Honeydoc`)** | Serves fake `.env`, `id_rsa`, AWS secret keys with trackable tokens | Triggers alert when attacker uses leaked fake credentials outside the honeypot. |
| **Tarpit Latency (50-200ms)** | Applies random artificial sleep per chunk | Slows down automated scanners, fuzzers, and brute-force tools. |
| **Strict NetNS Isolation** | Isolated namespace + `iptables -P OUTPUT DROP` | Prevents lateral movement, SSRF exploitation, and outbound command execution. |
| **`HoneypotEvent` SIEM Logging** | Structured JSON logs with timestamp, IP, path, payload, UA | Real-time SIEM alert feed and threat actor profiling. |

---

## 🧪 PART 3: Configuration Spec (`jarswaf.toml`)

```toml
[global]
port_http = 80
port_https = 443
xdp_interface = "eth0"

[honeypot]
enabled = true
upstream_addr = "127.0.0.1:9999"
min_delay_ms = 50
max_delay_ms = 200
enable_canary_tokens = true
```

---

## 🛠️ Summary & Status

- ✅ `src/honeypot.rs` module created with `HoneypotConfig`, `HoneypotEvent`, and `generate_fake_env_honeydoc()`.
- ✅ Integrates cleanly into `src/config.rs`, `src/lib.rs`, `src/rules.rs`, and `src/vhost.rs`.
- ✅ 130 unit tests passing with zero compilation warnings.
