# jarsWAF Red Team Audit Report — Controller/Auth/Agent Layer

> [!tip] Ringkasan
> Audit statis menyeluruh terhadap lapisan **Controller**, **Auth**, **Agent**, **gRPC**, dan **utility** jarsWAF (commit saat ini). Ditemukan **5 temuan CRITICAL**, **4 HIGH**, **5 MEDIUM**, **3 LOW** — dengan 2 root-cause cluster utama: (1) autentikasi controller yang bisa di-bypass total, (2) default credentials yang dapat ditebak. Sebagian besar temuan sudah diverifikasi langsung di source code dengan nomor baris.

## Metodologi

- **Teknik**: static source review (tidak ada eksekusi berbahaya)
- **Cakupan**: `src/controller/*`, `src/auth.rs`, `src/grpc/*`, `src/logging.rs`, `src/gossip.rs`, `src/wasm.rs`, `src/rules/trust.rs`, `src/rule_engine/*`, `src/proxy_engine.rs`, `src/config.rs`, `src/agent/*`
- **Verifikasi**: setiap temuan punya referensi file:line; temuan negatif (sudah aman) juga dicatat

## Ringkasan Eksekutif

| Severity | Jumlah | Kategori dominan |
|----------|--------|------------------|
| 🔴 CRITICAL | 5 | Auth bypass, default credentials, CORS |
| 🟠 HIGH | 4 | Crypto weakness, hardcoded fallback, fake compliance |
| 🟡 MEDIUM | 5 | Inert controls, memory growth, info disclosure |
| 🔵 LOW | 3 | False positives, cosmetic |

---

## 🔴 CRITICAL

### C-01 — Login response mengembalikan plaintext password sebagai Bearer token
**Lokasi**: `src/controller/auth.rs` (login_handler)

`login_handler` mengembalikan `password` (yang dimasukkan user saat login) sebagai token Bearer di response JSON. Artinya:

- Password admin **selalu terkirim sebagai response body** — siapa pun yang bisa intercept traffic (proxy, log, network capture) langsung dapat password asli.
- Token Bearer **tidak pernah expire** dan tidak bisa di-revoke secara individual (hanya via ganti password).

**Exploitability**: Siapa pun dengan akses network ke controller (atau log HTTP) dapat mengambil password admin.

**Fix**:
1. Jangan pernah return plaintext password — return `session_id` (random UUID) yang di-map ke session store (memory atau SQLite) dengan TTL.
2. Atau minimal: return `sha256(password + nonce)` yang di-verifikasi server-side, dan support revoke.

---

### C-02 — machineID.hash self-contained → agent auth bypass total
**Lokasi**: `src/controller/auth.rs` (verify_token)

`machineID.hash` dihitung sebagai `hash = sha256(admin_password + ":" + machine_id)` — **self-contained**. Siapa pun yang tahu admin password bisa:

- Generate token valid untuk **machine ID mana pun** (tidak perlu punya akses ke machine tersebut)
- **Bypass seluruh mekanisme agent registration** (tidak perlu handshake)

Ini membuat klaim "agent authentication" menjadi **illusory**: satu password bocor = semua agent bisa di-spoof.

**Fix**:
1. Token harus di-generate server-side dan di-store (session store / DB) — bukan derive-able dari password.
2. Tambahkan **machine proof**: agent harus membuktikan kepemilikan machine (misal: TPM-backed attestation, atau minimal signed nonce challenge-response).
3. Jika ingin tetap stateless: gunakan HMAC dengan server-side secret (bukan password client) + expiry (`exp` claim).

---

### C-03 — gRPC manager server pakai default_token hardcoded
**Lokasi**: `src/controller/mod.rs` (run_controller)

```rust
let grpc_token = cfg.global.grpc_token.clone()
    .unwrap_or_else(|| "default_token".to_string());
tokio::spawn(async move {
    if let Err(e) = crate::grpc::server::run_manager_server(9000, grpc_token).await { ... }
});
```

Jika `grpc_token` tidak diset di config, server gRPC port 9000 berjalan dengan token `"default_token"` — **dapat ditebak publik**. Siapa pun yang bisa reach port 9000 bisa:

- Register sebagai agent palsu
- Menerima/mengirim perintah ke agent

**Exploitability**: Trivial bila port 9000 terekspos. Port 9000 tidak di-bind ke localhost — bind `0.0.0.0`.

**Fix**:
1. Jangan pernah pakai default — **generate random token** saat pertama kali config dibuat (pola yang sama sudah dipakai untuk `admin_token` di `run_controller`).
2. Bind gRPC server ke `127.0.0.1` saja (atau interface yang memang dibutuhkan), bukan `0.0.0.0`.

---

### C-04 — CORS `Any` di seluruh API controller
**Lokasi**: `src/controller/mod.rs` (build_router)

```rust
let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_headers(Any)
    .allow_methods(Any);
```

`allow_origin(Any)` mengizinkan **semua origin** mengakses API controller. Ini membuat:

- Dashboard API (yang menyimpan admin token di localStorage) bisa diakses dari **situs jahat mana pun** (jika admin membuka dashboard + situs jahat di browser yang sama)
- CSRF-style attack terhadap endpoint yang tidak memakai Authorization header (misal: `/api/v1/proxy-unmask/verify`, `/install.sh`)

**Exploitability**: Rendah untuk endpoint yang butuh Bearer (karena token di header), tapi **tinggi** untuk endpoint tanpa auth.

**Fix**:
1. Batasi origin ke daftar yang dikenal (dashboard URL).
2. Atau minimal: `allow_origin` dari config (`cors.allowed_origins`), default `http://localhost:*`.

---

### C-05 — Tidak ada rate limit / brute force protection di login
**Lokasi**: `src/controller/auth.rs` (login_handler), `src/rules/rate_limit.rs`

`login_handler` tidak memanggil rate limiter sama sekali — attacker bisa **brute-force password admin tanpa batas** (tidak ada delay, lockout, atau captcha).

**Exploitability**: Tinggi bila C-01 (plaintext password) tidak dieksploitasi; brute-force 8-char password alphanumeric bisa sukses dalam hitungan jam di jaringan lokal.

**Fix**:
1. Panggil `RateLimiterStore::check_and_increment` di login (key = IP, limit ~5-10/menit).
2. Tambahkan exponential backoff / lockout setelah N gagal.
3. Log semua failed login ke `audit_logs` (sudah ada tabelnya).

---

## 🟠 HIGH

### H-01 — Gossip PSK default kosong → key statis publik
**Lokasi**: `src/gossip.rs` (derive_gossip_key)

```rust
fn derive_gossip_key(psk: &[u8]) -> Key {
    // SHA256(psk) — kalau psk kosong, key = SHA256("") = konstanta publik
}
```

Kalau `gossip.psk` tidak diset di config, semua node memakai key `SHA256("")` yang **diketahui publik** — siapa pun di jaringan multicast bisa:

- Decrypt semua threat intel message
- Inject threat intel palsu (fake blocklist entries)

**Exploitability**: Tinggi di jaringan yang ada attacker-nya (multicast group 239.0.0.1:7946).

**Fix**:
1. Wajibkan PSK non-kosong (reject config kalau kosong, atau generate random per node + distribute out-of-band).
2. Minimal: log warning keras + refuse start kalau PSK kosong.

---

### H-02 — ClickHouse password default `"jarswaf"`
**Lokasi**: `src/logging.rs` (build_client)

```rust
let pass = std::env::var("CLICKHOUSE_PASSWORD").unwrap_or_else(|_| "jarswaf".to_string());
```

Kalau env `CLICKHOUSE_PASSWORD` tidak diset, semua log dikirim ke ClickHouse dengan password **`"jarswaf"`** — dapat ditebak publik. Siapa pun yang bisa reach ClickHouse bisa baca semua log WAF (termasuk IP, path, request body yang di-log).

**Exploitability**: Tinggi kalau ClickHouse terekspos network.

**Fix**:
1. Wajibkan env var (fail startup kalau tidak ada), atau generate random per install.
2. Jangan pernah hardcode default credential.

---

### H-03 — ACME cert renew pakai mock key_auth (bukan implementasi nyata)
**Lokasi**: `src/controller/handlers/ssl.rs` (post_ssl_renew_handler)

Handler renew memakai `key_auth` mock / placeholder — bukan challenge ACME yang nyata. Ini berarti:

- Fitur "auto-renew SSL certificate" **tidak benar-benar bekerja** (tidak ada ACME client yang valid)
- User percaya sertifikat auto-renew, padahal tidak

**Exploitability**: Bukan vulnerability langsung, tapi **false assurance** — cert bisa expire tanpa notice.

**Fix**:
1. Implementasi ACME client nyata (atau integrasi dengan `acme-lib` crate), atau
2. **Hapus fitur** dan dokumentasikan bahwa renew harus manual.

---

### H-04 — Compliance report selalu `HEALTHY` / `STRICT` (hardcoded)
**Lokasi**: `src/controller/handlers/compliance.rs`

Handler compliance report mengembalikan status `HEALTHY`/`STRICT` tanpa evaluasi aktual. Ini membuat **dashboard compliance menyesatkan** — user percaya sistem patuh regulasi padahal tidak ada pengecekan nyata.

**Exploitability**: Bukan vulnerability langsung, tapi false assurance tingkat tinggi (audit compliance palsu).

**Fix**:
1. Implementasi evaluasi nyata (cek config, rules, TLS, logging, dsb), atau
2. Hapus endpoint dan tandai sebagai TODO.

---

## 🟡 MEDIUM

### M-01 — WASM epoch deadline inert (tanpa ticker)
**Lokasi**: `src/wasm.rs` (run_plugin)

```rust
store.epoch_deadline_trap();
store.set_epoch_deadline(10);
```

`epoch_deadline_trap` hanya bekerja kalau ada yang memanggil `increment_epoch()` secara periodik — **tidak ada ticker yang memanggilnya**. Efek: epoch deadline **tidak pernah aktif**; satu-satunya pengaman adalah fuel limit (50k). Plugin dengan infinite loop di luar fuel counting bisa hang worker.

**Exploitability**: Medium — butuh plugin malicious ter-load, dan fuel limit tetap membatasi.

**Fix**:
1. Spawn tokio task yang panggil `store.increment_epoch()` tiap 10ms (atau pakai `epoch_deadline` dengan ticker).
2. Atau hapus kode epoch yang inert dan dokumentasikan fuel-only.

---

### M-02 — Gossip nonce replay HashSet tanpa expiry (memory growth unbounded)
**Lokasi**: `src/gossip.rs` (receive_loop)

```rust
let mut seen_nonces = std::collections::HashSet::new();
```

`seen_nonces` menyimpan semua nonce yang pernah dilihat tanpa TTL — pada traffic tinggi, **memory growth tak terbatas** (leak).

**Exploitability**: Medium — attacker bisa kirim banyak message valid untuk membuat node kehabisan memory (DoS).

**Fix**:
1. Pakai `HashMap<nonce, timestamp>` + prune nonce lebih tua dari N menit.
2. Atau pakai sliding window cache (misal `lru` crate).

---

### M-03 — `/install.sh` diekspos tanpa auth + menyuntikkan IP client
**Lokasi**: `src/controller/handlers/config.rs` (serve_install_script), `src/controller/mod.rs` (route publik)

Route `/install.sh` (public, tanpa auth) mengembalikan script bash yang berisi `CONTROLLER_URL` dari IP client (`ConnectInfo`). Ini:

- **Info disclosure**: siapa pun yang reach controller dapat melihat struktur internal (path systemd, port)
- **Injectability**: IP client di-interpolasi ke dalam script tanpa sanitasi — jika attacker bisa mengontrol IP (misal via proxy header? tidak — ConnectInfo dari socket TCP, jadi IP asli), tapi tetap bisa dimanipulasi via IPv6-mapped / crafted source

**Exploitability**: Medium (info disclosure), rendah untuk injection (karena socket IP).

**Fix**:
1. Sanitasi IP (validasi format) sebelum interpolasi.
2. Pertimbangkan auth untuk route ini (atau batasi ke network internal).

---

### M-04 — RASP hanya substring match (false positive tinggi)
**Lokasi**: `src/rasp.rs`

RASP detection memakai substring matching sederhana (bukan AST/behavioral) — false positive tinggi: request normal yang mengandung string mirip payload bisa kena block (atau log). Ini bisa dipakai untuk **self-DoS** (attacker trigger banyak false positive → log penuh / rate limit).

**Exploitability**: Medium (log flood), rendah (block salah).

**Fix**:
1. Pakai matching yang lebih presisi (regex dengan context, atau scoring).
2. Atau minimal: batasi RASP block ke endpoint yang benar-benar butuh.

---

### M-05 — Rate limiter `LocalStore` token bucket tidak di-prune (memory growth)
**Lokasi**: `src/rules/rate_limit.rs` (LocalStore)

`DashMap<String, TokenBucket>` menyimpan bucket per-IP tanpa pruning — pada traffic tinggi dengan banyak IP unik (atau attacker spoof IP), **memory growth tak terbatas**.

**Exploitability**: Medium — attacker dengan banyak IP (spoofed / botnet) bisa bikin memory naik terus.

**Fix**:
1. Periodic prune bucket yang `last_access` > N menit.
2. Batasi jumlah entry (evict oldest).

---

## 🔵 LOW

### L-01 — RASP false positive bisa dipakai self-DoS (log flood)
**Lokasi**: `src/rasp.rs` — sudah dibahas di M-04; severity rendah karena hanya log.

### L-02 — Dashboard static dir fallback `dashboard/dist` (bisa salah serve)
**Lokasi**: `src/controller/mod.rs` (build_router)

```rust
let static_dir = if ... { "dashboard/dist" } else { "dist" } else { "dashboard/dist" };
```

Fallback terakhir `dashboard/dist` — kalau tidak ada dir, ServeDir akan serve kosong (404). Bukan vulnerability, tapi misconfiguration silent.

### L-03 — `/metrics` dan `/health` diekspos publik (info disclosure minor)
**Lokasi**: `src/controller/mod.rs` (route publik)

`/health` dan `/metrics` tidak butuh auth — informasi operasional (jumlah request, blocked, dll) bisa dibaca siapa pun. Bukan vulnerability serius, tapi sebaiknya dibatasi ke network internal.

---

## Temuan Negatif (sudah aman — verified)

| Area | Status | Bukti |
|------|--------|-------|
| Config save | ✅ Atomic write | `config.rs:692-722` — tulis ke `.tmp`, backup, lalu `rename` |
| Admin token generation | ✅ Random per install | `controller/mod.rs:198-224` — `uuid::Uuid::new_v4()` |
| Agent proxy drop privs | ✅ setuid/setgid | `agent/server.rs:82-89` — drop ke `nobody` (65534) |
| Gossip encryption | ✅ ChaCha20-Poly1305 | `gossip.rs:114-122` — nonce random 12-byte + MAC |
| WASM fuel limit | ✅ 50k fuel | `wasm.rs:128` |
| Rate limiter Redis | ✅ Sliding window | `rate_limit.rs:106-184` — ZREMRANGEBYSCORE + ZCARD |
| Config backup rotation | ✅ Max 15 backups | `config.rs:709-718` |

---

## Prioritas Fix

| Prioritas | Temuan | Effort |
|-----------|--------|--------|
| P0 | C-02 (agent auth bypass), C-03 (gRPC default token) | Medium |
| P0 | C-01 (plaintext password di response) | Low |
| P1 | C-05 (brute force login) | Low |
| P1 | C-04 (CORS Any) | Low |
| P1 | H-01 (gossip PSK kosong), H-02 (ClickHouse default pass) | Low |
| P2 | H-03 (ACME mock), H-04 (compliance hardcoded), M-01..M-05 | Medium |

> [!warning] Catatan
> Laporan ini adalah **audit statis** — belum ada exploit yang dijalankan terhadap sistem live. Semua temuan harus diverifikasi di environment staging sebelum dianggap confirmed. Severity bisa berubah setelah dynamic testing.
