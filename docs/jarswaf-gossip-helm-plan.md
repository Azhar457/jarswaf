---
tags: [jarswaf, gossip, k8s, helm, architecture]
aliases: [gossip-plan, helm-plan]
status: pending
created: 2026-07-13
---

# jarsWAF — Gossip Protocol & Helm Chart Plan

## 1. Layer Separation (keputusan arsitektur)

| Layer | Source of truth | Mekanisme | Contoh data |
|-------|---------------|-----------|-------------|
| **Control plane** (config) | Controller API (single authoritative) | Agent **pull** via long-poll/gRPC stream | rate limit policies, vhost, blocklist, custom rules |
| **Data plane** (threat intel) | Gossip ring (eventual consensus) | `memberlist` UDP broadcast | IP + confidence score + TTL + source node |

**Config tidak pernah lewat gossip.** Semua perubahan config harus melalui API Controller → disimpan → di-propagasi ke agent via pull. Gossip hanya untuk state yang: (a) perlu cepat tanpa nunggu controller, (b) boleh eventually consistent, (c) loss-toleran.

## 2. Gossip — Threat Intel Real-time

### Payload format
```rust
struct ThreatIntelMessage {
    ip: Ipv4Addr,
    score: f32,           // 0.0 - 100.0 (confidence)
    ttl_secs: u32,        // 60 - 3600
    source_node: String,  // node_id pengirim
    signature: [u8; 32],  // HMAC-SHA256(psk, ip|score|ttl|source)
}
```

### Alur
1. Agent A deteksi serangan (WAF rule triggered, rate limit exceeded, dll)
2. Agent A hitung confidence score
3. Agent A broadcast ke gossip ring
4. Agent B-Z terima → update local threat intel cache → block IP kalau score > threshold
5. TTL decay otomatis → entry expire dari cache

### Discovery
- **K8s**: headless Service DNS `jarswaf-gossip.<ns>.svc.cluster.local`
- **Non-K8s**: seed list di config.toml (`gossip.seeds = ["10.0.0.1:7946", "10.0.0.2:7946"]`)

### Security
- MVP: pre-shared key (HMAC payload signature — node palsu ditolak)
- Upgrade path: mTLS via `memberlist` TLS transport wrapper

### Port
- `7946` UDP (memberlist default)

## 3. Helm Chart

Struktur:
```
helm/jarswaf/
├── Chart.yaml
├── values.yaml
├── templates/
│   ├── _helpers.tpl
│   ├── configmap.yaml
│   ├── secrets.yaml
│   ├── service.yaml          (proxy + controller)
│   ├── service-headless.yaml (gossip discovery)
│   ├── deployment-proxy.yaml
│   ├── deployment-controller.yaml
│   ├── hpa.yaml
│   └── ingress.yaml
```

### Komponen
| Deployment | Fungsi | Replicas | Ports |
|-----------|--------|----------|-------|
| proxy | Pingora WAF proxy + gossip agent | 2+ | 80, 443, 7946 |
| controller | Admin API + config source of truth | 1 | 8080 |

### Config via ConfigMap + secret
- `config.toml` template → ConfigMap
- Redis password → Kubernetes Secret (opsional)
- Gossip pre-shared key → Kubernetes Secret

### Ingress
- Controller API dibelakang Ingress (domain admin, basic-auth)
- Proxy bisa pakai hostPort / LoadBalancer / Ingress controller

## 4. Implementasi Order

1. **Helm chart** — mechanical, langsung template
2. **Gossip skeleton** — trait `GossipPayload`, `MemberlistNode` struct, integrasi di agent startup
3. **Threat intel logic** — hubungin ke WAF engine (trigger → broadcast)
4. **Config sync (pull)** — agent HTTP long-poll ke controller

Phase 1-2 parallel. Phase 3-4 nanti setelah gossip skeleton jalan.
