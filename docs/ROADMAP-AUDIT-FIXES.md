# 🗺️ jarsWAF ROADMAP — Dari 2 Hasil Percakapan (2026-08-02)

> **Sumber:** (1) Architectural Audit 13 issue, (2) WAF vs SEO / Repo Indexing.
> Dokumen ini = rencana eksekusi, bukan analisis ulang. Detail tiap issue ada di
> `docs/audit/jarswaf-audit.md` (hasil audit model frontier).

---

## Fase 0 — Quick Wins (Bisa Fix Hari Ini, Tanpa Redesign)

Target: patch kecil, aman, langsung di-merge. Semua punya satu-line fix.

| # | Issue | Fix | File |
|---|-------|-----|------|
| 3 | Memory cleanup nukes active connections | Hapus 2 baris `retain(\|_, \|_ \| false)` — sisakan `trim_dashmap` saja | `src/proxy_engine.rs` |
| 5 | CF-Connecting-IP tidak disanitasi | Tambah `"cf-connecting-ip"` ke `SPOOFABLE_PROXY_HEADERS` | `src/proxy_engine.rs` |
| 6 | eBPF map 10,240 vs userspace 100,000 | Naikkan `with_max_entries` ke 100_000 (sesuai `BLOCKLIST_MAX_ENTRIES`) | `jarswaf-ebpf/src/main.rs` |
| 10 | LOAD_BALANCER TOCTOU | Ganti check+insert dengan `entry().or_insert_with()` | `src/proxy_engine.rs` |
| 13 | Gossip PSK tanpa KDF | HKDF-SHA256(psk, salt=node_id) sebelum jadi ChaCha20Poly1305 key | `src/gossip.rs` |
| 12 | Bundle mode sleep 1s | Ganti sleep dengan retry/ready-check loop (max 10x, interval 200ms) | `src/main.rs` |
| 11 | Health checker di request_filter | Pindah `start_health_checker` + `start_websocket_security_proxy` ke init | `src/main.rs` |

**Verifikasi Fase 0:** `cargo build --release` + `cargo test` + `cargo clippy -D warnings` → 0 error. Re-run `cargo audit` (pastikan ignore list di `.cargo/audit.toml` masih valid).

---

## Fase 1 — Performance & State Consistency (1-2 Hari)

Target: hapus overhead hot-path + state yang bisa divergen.

| # | Issue | Fix |
|---|-------|-----|
| 8 | RuleEngine 3x init per request | Buat sekali saat config load → share via `Arc<RuleEngine>` (atau `ArcSwap` kalau hot-reload) |
| 4 | Dual config state divergence | Hapus `config_arc` — semua baca `GLOBAL_CONFIG` (`ArcSwap`) |
| 9 | XDP_MANAGER async mutex di hot path | Batch `block_ip` → satu `block_many(&[u32])` di sisi eBPF; atau pindah lock keluar loop |
| 7 | XDP IPv4-only vs config IPv6=true | Pilih: implement IPv6 parsing (L3/L4 header) ATAU set `enable_ipv6: false` default + dokumentasikan limit |

**Catatan #4:** `ArcSwap` sudah dipakai `GLOBAL_CONFIG` — jadi unify ke situ, `config_arc` (RwLock) tinggal dihapus. Ini juga bikin SIGHUP hot-reload konsisten.

---

## Fase 2 — Feature Gaps (Prioritas Tertinggi, Butuh Desain)

Target: 2 feature yang ada di architecture doc tapi TIDAK ada di implementasi.

### #1 TC Transparent Proxy (eBPF TC ingress)

**Status sekarang:** hanya XDP program (drop packet IPv4). Tidak ada:
- `BPF_PROG_TYPE_SCHED_CLS` / `tc ingress` attachment
- Port rewriting (`dst_port → 18000`)
- BPF HashMap `(src_ip, src_port, orig_dst, orig_port)`
- `IP_TRANSPARENT` socket di Pingora

**Rencana:**
1. Tulis TC program baru di `jarswaf-ebpf/src/tc.rs` (pertahankan XDP untuk early-drop)
2. Attach via `tc` CLI / `aya` — ingress hook di interface
3. Rewrite dst_port → port Pingora; simpan original dst di map
4. Pingora bind `IP_TRANSPARENT` + baca original dst dari map
5. Test: curl ke port acak (mis. 9999) → harus ke-intercept WAF

**⚠️ Risiko:** WiFi (iwlwifi) tidak support XDP/TC dengan baik — pakai veth pair untuk testing (pola yang sudah dipakai di pentest eBPF/XDP).

### #2 Honeypot Steering (Routing asli, bukan stub)

**Status sekarang:** `deception_mode` → respond JSON hardcoded + close. `upstream_addr: "127.0.0.1:9999"` tidak pernah dipakai.

**Rencana:**
1. Tambah `ctx.upstream_override` di proxy path
2. Saat `deception_mode` aktif → route ke honeypot service (port 9999)
3. Honeypot service handle fake handshake (MySQL 8.0.35 / Postgres / Redis NOAUTH — sudah ada di `honeypot.rs`)
4. Tambah tarpit latency (configurable delay) biar attacker "merasa berhasil"
5. Canary token: Action::Pass (tripwire, jangan pernah block)

---

## Fase 3 — WAF vs SEO (Crawler Allowlist)

Target: WAF tidak menghalangi indexing Google/Bing — SEBELUM deploy produksi.

### 3a. Allowlist crawler (config)

```toml
[[allowlists]]
name = "Search Engine Crawlers"
user_agents = ["Googlebot", "Googlebot-Image", "Googlebot-Video", "AdsBot-Google",
               "Bingbot", "Slurp", "DuckDuckBot", "YandexBot", "Sogou",
               "facebookexternalhit", "Twitterbot", "LinkedInBot", "WhatsApp", "Applebot"]
# Googlebot verified IPs: https://developers.google.com/search/apis/ipranges/googlebot.json
action = "allow"
```

### 3b. Bypass bot_challenge + rate limit untuk verified crawler

- Tambah field `ctx.skip_bot_challenge` di `JarsWafCtx`
- Di `request_filter`, SEBELUM bot challenge check:
  - UA contains Googlebot/Bingbot/... → `skip_bot_challenge = true`
  - Rate limiter: tier khusus `1000/min` untuk crawler (bukan default)
  - **TETAP** jalankan rule engine (SQLi/XSS) — allowlist ≠ free pass

### 3c. GeoIP

Kalau `geoblock_type = "allowlist"` → pastikan US masuk whitelist (mayoritas Googlebot crawl dari US).

### 3d. GitHub repo indexing

- Topics: `waf, web-application-firewall, ebpf, rust, pingora, security, honeypot, rate-limiting, reverse-proxy, xdp`
- Aktifkan GitHub Pages dari `docs/` (Google index halaman docs terpisah)
- Backlink: Show HN, r/netsec, r/rust, r/selfhosted, Dev.to

---

## Fase 4 — Validasi & Audit Ulang

1. Re-run full test suite + clippy + audit
2. Re-audit dengan model frontier (pakai `/tmp/jarswaf-audit.tar.gz` yang sudah di-zip) — minta diff-check: apakah 13 issue sudah closed?
3. Update `docs/ROADMAP.md` tracker dengan status baru
4. Bump version (v0.3.0) + release binary workflow (`cargo build --release` → tar → `gh release create`)

---

## Tabel Ringkasan Prioritas

| Fase | Isi | Effort | Dampak |
|------|-----|--------|--------|
| 0 | 7 quick wins (bug + security patch) | 1 hari | 🔴 High — fix bug nyata |
| 1 | Performance + state consistency | 1-2 hari | 🟠 Medium — hot path + reload |
| 2 | TC Transparent Proxy + Honeypot routing | 1-2 minggu | 🔴 High — feature utama doc |
| 3 | Crawler allowlist + SEO | 2-3 hari | 🟡 Medium — deploy-ready |
| 4 | Validasi + re-audit + release | 1 hari | ✅ Closure |

**Urutan eksekusi yang disarankan:** Fase 0 → Fase 1 → Fase 3 (sebelum deploy) → Fase 2 (butuh desain, bisa paralel dengan 3) → Fase 4.
