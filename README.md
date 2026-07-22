# 🛡️ jarsWAF

**High-performance Web Application Firewall** — reverse proxy yang menginspeksi, memfilter, dan memblokir HTTP traffic real-time. Dibangun dengan **Rust + Pingora (Cloudflare) + eBPF XDP + Svelte + WASM**.

> *"Secepat Pingora, sekuat Safeline."*

---

## 🔥 Status Build

| Komponen | Binary | Status |
|----------|--------|--------|
| **Workspace** | `cargo build` | ✅ 0 error, 0 warning |
| **Controller** | `./target/debug/controller` | ✅ Management & Analytics API Server (port `8080`) |
| **Agent** | `./target/debug/agent` | ✅ Layer 7 WAF Proxy Node (Pingora + Wasmtime + ONNX) |

**jarsWAF telah 100% sukses di-build. Kedua binary (`controller` dan `agent`) berdiri sendiri dan siap dijalankan.**

### Cara Menjalankan (Development)

```bash
cd /mnt/data_d/Desktop/KERJA/jarswaf

# Controller (REST API + Dashboard)
./target/debug/controller

# Agent (WAF Proxy)
./target/debug/agent --controller http://localhost:8080
```

Atau lewat launcher interaktif:
```bash
./start.sh
```

Akses:
- 🛡️ **Dashboard UI**: `http://localhost:5173/`
- ⚙️ **Controller API**: `http://localhost:8080/`
- ⚡ **WAF Agent Proxy**: `http://localhost:8000/`

---

## Fitur Utama

| Lapisan | Kemampuan |
|---------|-----------|
| **L7 Proxy** | Reverse proxy berbasis Pingora (asinkron, zero-copy forwarding) |
| **Deteksi** | AST Semantic tokenizer (SQLi, XSS) + Signature-based regex 300+ rules |
| **Normalisasi** | Recursive URL decode → HTML entity → NFKC Unicode → lowercase |
| **Rate Limiting** | Per-VHost token bucket, opsi distributed via Redis |
| **TLS** | Auto-provisioned Local CA, custom cert upload, ACME (Let's Encrypt) |
| **GeoBlok** | MaxMind GeoIP per negara per VHost |
| **eBPF XDP** | DDoS mitigation di level kernel (Linux ≥ 5.8) |
| **Trust Scoring** | JA4 fingerprint, JWT validation, Zero-Trust architecture |
| **Anomaly Scoring** | Cumulative anomaly scoring + Markov chain detection |
| **ML Detection** | ONNX runtime untuk anomaly detection berbasis ML |
| **WASM Plugins** | Custom plugin system via WebAssembly |
| **DLP** | Data Loss Prevention — mask credit card, NIK, token dll. |
| **RASP** | Runtime Application Self-Protection |
| **OpenAPI** | OpenAPI 3.x schema validation |
| **GraphQL** | depth-limiting + complexity analysis |
| **Reputasi** | Cross-node IP reputation blocklist sync |
| **Dashboard** | Svelte real-time UI, WebSocket, Globe attack map, xterm.js terminal |
| **Logging** | Async pipeline: file JSON → SQLite → remote controller |

---

## Arsitektur

jarsWAF mendukung **3 mode deployment** tergantung skala dan kebutuhan:

### Opsi A: Agent Only (Standalone)

```
┌──────────────┐     ┌─────────────────┐     ┌──────────────┐
│   Clients    │────▶│  jarsWAF Agent  │────▶│   Backend    │
│  (Internet)  │     │  (Pingora Proxy)│     │   (App Anda) │
└──────────────┘     │ port 80/443     │     └──────────────┘
                     │ + WAF Engine    │
                     │ + Log ke file   │
                     └─────────────────┘
```

**Cocok untuk:** VPS minim (1 core, 512 MB RAM), proteksi satu aplikasi tanpa dashboard.

**Cara jalanin:**
```bash
# Binary langsung
./target/debug/agent

# Atau via install.sh one-shot
bash -c "$(curl -fsSLk https://raw.githubusercontent.com/Azhar457/jarswaf/main/install.sh)"
```

Logging: file JSON lokal atau SQLite lokal. **Zero dependencies.**

### Opsi B: Controller + Agent di Satu Mesin (All-in-One)

```
┌──────────────────────────────────────────────────┐
│                   Satu Server                     │
│                                                    │
│  ┌──────────┐   ┌──────────────┐   ┌────────────┐│
│  │  Clients  │──▶│jarsWAF Agent│──▶│  Backend   ││
│  │(Internet) │   │(Pingora:80) │   │ (App Anda) ││
│  └──────────┘   └──────┬───────┘   └────────────┘│
│                        │                          │
│                        ▼                          │
│  ┌──────────────────────────┐                    │
│  │  Controller API :8080     │                    │
│  │  + Dashboard Svelte       │                    │
│  │  + Database (SQLite/CH)   │                    │
│  └──────────────────────────┘                    │
└──────────────────────────────────────────────────┘
```

**Cocok untuk:** Server produksi tunggal (4 GB+ RAM), mau lihat dashboard real-time.

**Cara jalanin:**
```bash
# Terminal 1 — Controller
./target/debug/controller

# Terminal 2 — Agent (ngarah ke controller lokal)
./target/debug/agent --controller http://localhost:8080

# Atau pake Docker Compose
docker compose up -d --build
```

### Opsi C: Controller + Agent di Mesin Berbeda (Distributed)

```
┌─────────────────┐       ┌──────────────────────┐
│  Server A        │       │   Server B (VM/Cloud) │
│  (Controller)    │       │   (Agent)              │
│                   │       │                        │
│  ┌─────────────┐ │ HTTP  │  ┌──────────────────┐ │
│  │ Controller  │◀┤◀──────│──│  jarsWAF Agent   │ │
│  │ API :8080   │ │ Push  │  │  (Pingora:80)    │─┼──▶ Backend
│  │ + Dashboard │ │ Logs  │  │  + WAF Engine    │ │
│  │ + Database  │ │       │  └──────────────────┘ │
│  └─────────────┘ │       └──────────────────────┘
└─────────────────┘
                   │ HTTP   ┌──────────────────────┐
                   │ Push   │   Server C (VM/Cloud) │
                   │ Logs   │   (Agent)              │
                   ├────────┤  ┌──────────────────┐ │
                   │        │  │  jarsWAF Agent   │ │
                   └────────▶  │  (Pingora:80)    │─┼──▶ Backend
                              │  + WAF Engine    │ │
                              └──────────────────┘ │
                              └──────────────────────┘
```

**Cocok untuk:** Skala besar, multi-cloud, agent tersebar di berbagai VM/region.

**Cara jalanin:**
```bash
# Di mesin Controller
./target/debug/controller

# Di setiap mesin Agent (VM/Cloud)
./target/debug/agent --controller http://<IP_CONTROLLER>:8080
```

### ⚙️ Fail-Safe Mechanism

jarsWAF dirancang dengan prinsip **"Traffic Tidak Boleh Berhenti"** (*Fail-Open*):

| Skenario | Dampak pada Traffic | Mekanisme |
|----------|-------------------|-----------|
| **Controller mati** | ✅ Traffic tetap jalan | Agent buffer log lokal, sync saat controller hidup |
| **eBPF gagal** (< Linux 5.8) | ✅ Traffic tetap jalan | Fallback otomatis ke L7 (User-space drop) |
| **SQLite poison** | ✅ Traffic tetap jalan | Poison recovery reset koneksi DB tanpa ganggu proxy |
| **Disk penuh** | ✅ Traffic tetap jalan | Log dibuang, proxy tetap jalan |

---

## Persyaratan Sistem

### Full Stack (Controller + Dashboard)
| Spesifikasi | Minimum | Recommended |
|-------------|---------|-------------|
| CPU | 2 core | 4+ core |
| RAM | 4 GB | 8+ GB |
| OS | Ubuntu 22.04+ / Debian 12+ | Fedora / RHEL 9+ |
| Deps | Rust ≥ 1.75 | Rust ≥ 1.96 |

### Agent Only (Lightweight)
| Spesifikasi | Minimum |
|-------------|---------|
| CPU | 1 core |
| RAM | 512 MB |
| Binary size | ~22 MB (static musl) |
| OS | Semua Linux (static binary) |

### Dukungan OS

| OS | eBPF XDP | L7 Proxy | Catatan |
|----|----------|----------|---------|
| Linux ≥ 5.8 | ✅ | ✅ Pingora | Produksi — rekomendasi utama |
| Linux < 5.8 | ❌ | ✅ Pingora | Tetap jalan, tanpa DDoS kernel |
| macOS | ❌ | ✅ Pingora | Develop & testing |
| Windows | ❌ | ❌ | **WSL2 required** |

---

## Quick Start

### 1. One-Command Install (Agent — Static Binary)

```bash
sudo bash -c "$(curl -fsSLk https://raw.githubusercontent.com/Azhar457/jarswaf/main/install.sh)"
```

**Binary MUSL static — jalan di SEMUA Linux tanpa dependensi GLIBC.**

### 2. Manual Build

```bash
git clone https://github.com/Azhar457/jarswaf.git && cd jarswaf

# Build semua binary
cargo build --release

# Binary ada di:
# - target/release/controller
# - target/release/agent

# Start Controller
./target/release/controller

# Start Agent (terhubung ke controller)
./target/release/agent --controller http://localhost:8080
```

### 3. Docker Compose (All-in-One)

```bash
git clone https://github.com/Azhar457/jarswaf.git && cd jarswaf
docker compose up -d --build
# Dashboard: http://<IP>:8080
```

### 4. MUSL Static Build (Cross-Distro)

```bash
# Pastikan reqwest pake rustls-tls (static, no OpenSSL dep)
cargo build --release --target x86_64-unknown-linux-musl
# Binary static: target/x86_64-unknown-linux-musl/release/jarswaf
# Jalan di Ubuntu, Debian, Alpine, Fedora — semua Linux!
```

---

## Konfigurasi Multi-Domain

```toml
[[vhosts]]
name = "python-app"
hosts = ["app.example.com"]
backend = "127.0.0.1:9500"
rules = ["SQLI-*", "XSS-*", "LFI-*", "BOT-*"]
ssl = "Auto (Local CA)"
```

Edit `/opt/jarswaf/config.toml` lalu restart Agent.

---

## Struktur Project

```
src/
├── main.rs           # CLI entry (controller / agent)
├── proxy_engine.rs   # Pingora proxy — hot path
├── agent/            # Agent node (server, discovery, websocket, metrics)
├── rules.rs          # WAF engine (AST semantic + regex signature)
├── logging.rs        # Log worker (file/remote/sqlite)
├── config.rs         # TOML config schema
├── proxy.rs          # GeoIP, CIDR matching
├── vhost.rs          # Virtual host router
├── controller/       # REST API controller
├── dashboard/        # Svelte SPA frontend
├── jarswaf-ebpf/     # eBPF XDP programs (Linux)
└── xtask/            # Build utilities
```

---

## Port Default

| Port | Service | Keperluan | Opsi |
|------|---------|-----------|------|
| 8080 | Controller API + Dashboard | Wajib (Controller) | Opsional di Agent-Only |
| 8000 | WAF Agent Proxy | Development | |
| 80 | HTTP Proxy (Agent) | Produksi | |
| 443 | HTTPS Proxy (Agent) | Produksi | |

---

## Pengujian

### Fungsional Dasar
```bash
# SQLi — harus 403
curl -v "http://<IP>/?id=1' OR '1'='1"

# XSS — harus 403
curl -v "http://<IP>/?search=<script>alert(1)</script>"
```

### Stress Test (Vegeta)
```bash
echo "GET http://<IP>/" | vegeta attack -rate=2000 -duration=30s | vegeta report
```

### Vulnerability Scan (Nuclei)
```bash
nuclei -u http://<IP> -t cves/
```

---

## Perintah Manager

```bash
./manager.sh deps         # Install semua dependensi
./manager.sh build        # Build release + Svelte
./manager.sh install      # Deploy Docker production
./manager.sh agent-deploy # Deploy Agent-only
./manager.sh logs         # Stream log
./manager.sh status       # Cek health
./manager.sh uninstall    # Hapus total
```

---

## Roadmap

- [x] eBPF XDP DDoS mitigation
- [x] Real-time metrics & dashboard
- [x] Phase 12-13 Enterprise: AHashMap, Cumulative Scoring, DLP, GeoIP/ASN, Multipart, RASP, WASM
- [x] MUSL fully static binary (cross-distro)
- [ ] Helm chart Kubernetes
- [ ] Gossip protocol config sync

---

## Lisensi

MIT — lihat [LICENSE](LICENSE).
Untuk security policy, lihat [SECURITY.md](SECURITY.md).
