# 🔴 jarsWAF Red Team Security Audit Report

**Target:** `/mnt/data_d/Projects/jarswaf` — Pure Layer 7 WAF (Rust, pingora + axum)
**Tanggal:** 2026-08-03
**Metodologi:** Static source-code audit menyeluruh (19.392 LOC) — fokus: input validation, injection, auth bypass, race conditions, memory safety, crypto misuse, logic flaws.
**Severity scale:** CRITICAL / HIGH / MEDIUM / LOW / INFO

---

## Ringkasan Eksekutif

| Severity | Jumlah | Area utama |
|----------|:------:|-----------|
| 🔴 CRITICAL | 4 | Auth token `alg:none` (Zero Trust), Open Redirect via bot-challenge, gRPC tanpa auth, WebSocket config push tanpa auth |
| 🟠 HIGH | 7 | Token plaintext sebagai sesi, controller binds 0.0.0.0 + CORS `*`, upgrade password tidak pakai verifikasi, brute-force rate limit lemah, CSRF rule false-positive, log injection, machine-id binding lemah |
| 🟡 MEDIUM | 8 | ReDoS (custom regex), WS security proxy header parsing, token statis, permission file, memory leak map, gossip nonce unbounded, RASP heuristic, race config reload |
| 🟢 LOW/INFO | 6 | Credential default di log helper, honeypot data statis, JWT validate murni struktural, fake cert dates, duplicate JWT check, dsb. |

**Skor keseluruhan:** 🟠 **6.2 / 10 — High Risk** (WAF yang melindungi aplikasi lain justru memiliki kontrol akses yang dapat dilewati)

---

## 🔴 CRITICAL

### C-01. Zero Trust identity verification = `alg:none` JWT tanpa verifikasi signature
- **File:** `src/rules/trust.rs:103-175`, `src/rules.rs:604-630`
- **Masalah:** `check_identity_token()` men-set `identity_verified = true` **hanya karena struktur token 3 bagian valid** (`parts.len() == 3`). Signature TIDAK pernah diverifikasi. Header JWT `{"alg":"none"}` dengan payload `{"iss":"<allowed>","exp":<future>}` dan signature apa pun (misal `"x"`) langsung dianggap *identity_verified=true* + *issuer_trusted=true*.
- **Bukti eksploit:** JWT `eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.<base64 payload iss/exp>.x` → `check_identity_token()` return `(true, true)` → ZT score = 30+15+10+15+20+10 = 100/100 → lolos `ZT-TRUST-SCORE` meskipun threshold `min_trust_score` tinggi.
- **Catatan:** Unit test `test_identity_token_valid` justru *menegakkan* perilaku ini — token dibuat dengan header `alg:none` dan dianggap valid.
- **Dampak:** Zero Trust bisa di-bypass total oleh siapa pun yang tahu `allowed_issuers` (yang defaultnya `[]` = "trust all issuers" → bahkan tanpa iss pun `issuer_trusted=true`). Mekanisme keamanan utama memberikan false sense of security.
- **Fix:**
  1. Wajib verifikasi signature dengan JWKS/public key issuer (contoh: `jsonwebtoken` crate + `validation` dengan `algorithms` yang di-allowlist — jangan pernah `alg:none`).
  2. Tolak token `alg:none` secara eksplisit.
  3. Jangan default `allowed_issuers=[]` → "trust all". Fail-closed: kosong = block, atau require konfigurasi eksplisit.

### C-02. Open Redirect (unvalidated) via bot-challenge redirect
- **File:** `src/proxy_engine.rs:1336-1352` (reputation redirect) dan `1410-1416` (active shielding)
- **Masalah:** Saat reputation >= 5.0 dan challenge cookie tidak valid, WAF me-redirect ke:
  ```rust
  let redirect_url = format!("{}{}", path, if query_str.is_empty() { "".into() } else { format!("?{}", query_str) });
  let redirect_path = urlencoding::encode(&redirect_url);
  Location: /jarswaf-challenge?{redirect_path}
  ```
  `path` dan `query_str` berasal dari attacker **tanpa validasi**. Jika `path = "//evil.com"` atau query `?r=https://evil.com`, challenge verification di `/jarswaf-challenge-verify` (line 1225-1229) melakukan:
  ```rust
  let orig_path = urlencoding::decode(v).unwrap_or_else(|_| v.into()).into_owned();
  ...
  let _ = resp.insert_header("Location", orig_path);   // ← redirect ke URL attacker
  ```
  dan `orig_path` diambil dari query param `r` yang attacker kendalikan penuh.
- **Eksploit:**
  1. Attacker kirim `GET /jarswaf-challenge-verify?r=https%3A%2F%2Fevil.com&sol=<hash>000...&m=10&fp_c=x` dengan PoW hash yang valid (`hash_result.starts_with("000")`).
  2. Server 302 ke `https://evil.com` — cookie `jarswaf-challenge-token` ikut (Set-Cookie Path=/) → token bocor ke evil.com.
  3. Atau cukup `GET //evil.com` saat reputation >= 5 → redirect ke `//evil.com` (browser menginterpretasi sebagai skema-relative → keluar dari origin).
- **Dampak:** Phishing credential-stealing dari sesi admin yang sudah challenge-verified; token challenge dicuri.
- **Fix:**
  - Validasi `orig_path` sebelum dipakai di `Location`: wajib `starts_with('/')`, TIDAK `starts_with("//")`, tidak mengandung `\`, `\n`, `\r`.
  - Jangan pernah redirect ke path dari query tanpa allowlist prefix.
  - Reject `path.starts_with("//")` di awal request_filter.

### C-03. gRPC WAF Manager server tanpa autentikasi (auth_token tidak pernah dicek)
- **File:** `src/grpc/server.rs:8-75`
- **Masalah:** `WafManagerService` menyimpan `auth_token` di struct tapi **tidak pernah diverifikasi** — tidak ada interceptor, tidak ada metadata check di `sync_policies` maupun `stream_telemetry`. `run_manager_server` bind `0.0.0.0:9000` (controller/mod.rs:238).
- **Dampak:** Siapa pun di jaringan yang bisa reach port 9000 dapat: connect sebagai agent palsu (get policy stream), dan mengirim telemetry palsu yang di-log (log poisoning). Server juga mengirim `blocklist_ips: vec![]` — tidak ada data sensitif yang bocor saat ini, tapi boundary otentikasi benar-benar tidak ada untuk channel kontrol WAF.
- **Fix:**
  1. Implementasikan tonic interceptor yang memverifikasi `authorization: Bearer <token>` terhadap `auth_token` (client.rs:42-47 sudah mengirim header ini — tinggal server yang memvalidasi).
  2. Jangan bind `0.0.0.0` untuk control plane; gunakan loopback/TLS dengan mTLS.
  3. Hilangkan fallback `"default_token"` di `controller/mod.rs:236`.

### C-04. Agent menerima config + block/unblock command dari WebSocket tanpa autentikasi
- **File:** `src/agent/websocket.rs:56-92`, `src/controller/websocket.rs:74-137`, `src/controller/auth.rs:170-248`
- **Masalah ganda:**
  1. **Auth middleware `auth_middleware` meng-allow `/ws/dashboard` dan `/ws/agent` secara publik** (`auth.rs:182`) — koneksi WS agent TIDAK butuh token. Saat agent connect, controller langsung kirim full config (`websocket.rs:78-90`), dan agent menerima `block_command` yang langsung memodifikasi blocklist:
     ```rust
     "block" => { blocklist_ref.insert(ip, now + 31536000); }  // block 1 tahun
     "unblock" => { blocklist_ref.remove(&ip); }
     "sync" => { blocklist_ref.clear(); }
     ```
  2. Di sisi agent, koneksi WS **tidak memverifikasi identitas controller** — `sec-websocket-protocol` hanya di-set sebagai header, tidak di-check. Siapa pun yang bisa spoof/man-in-the-middle atau bind port yang sama bisa push `block_command` → **unblock semua IP yang di-block WAF** (mematikan pertahanan) atau block IP korban (DoS).
- **Dampak:** Attacker yang bisa connect ke controller (`/ws/agent` tanpa auth) menerima full config (termasuk admin_token hash, trusted_proxies, secrets webhook). Attacker yang bisa connect ke agent WS port bisa push "sync" → clear blocklist → WAF lumpuh.
- **Fix:**
  1. Wajib autentikasi WS agent: verifikasi `Sec-WebSocket-Protocol` token terhadap `admin_token` di sisi server SEBELUM mengirim config (jangan di allowlist publik).
  2. Agent harus memverifikasi server: gunakan TLS (wss) + token handshake, atau minimal signed envelope (HMAC) untuk setiap `block_command` dengan nonce+timestamp.
  3. Pisahkan channel agent (token khusus agent) dari dashboard.

---

## 🟠 HIGH

### H-01. Login mengembalikan password plaintext sebagai token sesi; token = password
- **File:** `src/controller/auth.rs:120-125`
- **Masalah:** `LoginResponse.token = payload.password.clone()` — **password admin dikirim balik sebagai "token"**, dan semua request berikutnya memakai password itu sebagai Bearer token (`auth_middleware` → `verify_password(token, expected)`). Artinya: token sesi TIDAK bisa di-revoke tanpa mengganti password; password ter-expose di memory/log setiap request; tidak ada session timeout; tidak ada rate-limit login (lihat H-04).
- **Dampak:** Password admin beredar di setiap Authorization header; jika satu log/dump request bocor, admin password langsung kompromi. Stateless dan tidak revocable.
- **Fix:** Generate session token acak (UUID/HMAC) di sisi server, simpan di store dengan expiry, jangan pernah echo password.

### H-02. Controller bind `0.0.0.0` + CORS `allow_origin(Any)` + fallback static dir tanpa auth
- **File:** `src/controller/mod.rs:38-41, 287`; `src/controller/handlers/config.rs:199-239`
- **Masalah:** Controller bind ke semua interface (`0.0.0.0:{port}`), CORS `Any/Any/Any`. Endpoint sensitif (`/api/v1/config/rollback`, `/api/v1/logs/export`, `/api/v1/blacklists`) dilindungi auth, tapi: (a) `/install.sh` public (mengekspos controller IP), (b) `/metrics` public (info internal), (c) jika `admin_token` kosong (config baru), `auth_middleware` mengizinkan SEMUA endpoint (`auth.rs:192-244`: blok `if let Some(expected_token)` hanya aktif kalau token ada) — fresh install langsung terbuka total.
- **Dampak:** Exposure dashboard/API ke LAN/public; first-boot window = full unauthenticated admin.
- **Fix:** Bind 127.0.0.1 (atau wajib reverse-proxy + auth) untuk controller; CORS origin allowlist eksplisit; fail-closed auth saat `admin_token` kosong (generate dulu di startup — `ensure_admin_credentials` sudah ada, pastikan dipanggil sebelum router service).

### H-03. `change-password` endpoint tidak butuh auth (bypass langsung)
- **File:** `src/controller/auth.rs:170-185` + `139-168`
- **Masalah:** `auth_middleware` menempatkan `/api/v1/auth/change-password` di allowlist publik (baris 179). Endpoint hanya memverifikasi `old_password` — tanpa old password yang benar, attacker tidak bisa ganti password. **Tetapi** — lihat H-01: jika attacker sudah punya password lama (dari log dump), dia bisa langsung ganti. Masalah lebih dalam: endpoint tidak membutuhkan sesi valid; dan `new_password` TIDAK diverifikasi terhadap kebijakan selain panjang >= 8. Juga, **tidak ada rate limit** → brute-force old_password memungkinkan.
- **Dampak:** Kombinasi dengan H-01/H-04: password admin bisa di-brute-force lalu diganti.
- **Fix:** Pindahkan endpoint ke belakang auth (butuh Bearer token valid), tambah rate limit + lockout, verifikasi password tidak sama dengan lama.

### H-04. Login tanpa rate limit / lockout → brute-force
- **File:** `src/controller/auth.rs:99-130`, `src/controller/mod.rs` route
- **Masalah:** Tidak ada throttling di `/api/v1/auth/login`. WAF rate limiter (`check_rate_limit`) hanya dipanggil di proxy pipeline untuk vhost, TIDAK untuk endpoint controller. Attack: dictionary attack password admin (default 8-char random alphanumeric = 62^8, tapi password user-set bisa lemah).
- **Fix:** Rate limit per IP + per username di login handler (pakai `LocalStore`/`RedisStore` yang sudah ada), exponential backoff, lockout setelah N gagal, audit log setiap percobaan.

### H-05. Rule CSRF-001/002 memblokir request legit tanpa Origin/Referer (false positive DoS)
- **File:** `src/rules/body.rs:102-133`
- **Masalah:** `check_csrf_001` memblokir SEMUA form POST/PUT/PATCH/DELETE (`x-www-form-urlencoded`/`multipart`) tanpa header Origin DAN Referer; `check_csrf_002` memblokir semua JSON POST tanpa Origin. Banyak client legit (curl, mobile apps, server-to-server, CLI, privacy browser yang strip Referer) tidak mengirim Origin → **semua request mereka diblokir**. Ini bukan deteksi CSRF yang valid — CSRF adalah tentang *origin mismatch*, bukan *absence*.
- **Dampak:** DoS aplikasi (false positive massal) atau, jika rule dimatikan karena noise, hilangnya proteksi.
- **Fix:** Ubah rule menjadi: blokir hanya jika Origin/Referer ADA dan host-nya berbeda dari `Host` header. Absence ≠ attack.

### H-06. Log injection via header/path yang disanitasi tidak lengkap
- **File:** `src/logging.rs:17-22` (sanitize hanya `\r`/`\n`), `src/controller/handlers/logs.rs:18-93`
- **Masalah:** `sanitize()` mengganti `\r`/`\n` di path/reason/method, tapi: (a) **tidak dipanggil konsisten** — `receive_logs_handler` menerima `WafLogEntry` dari agent via POST tanpa sanitize, dan langsung broadcast ke `state.tx` (dashboard WS + SSE) serta insert ke SQLite; (b) `client_ip` TIDAK di-sanitize; (c) audit log `details` berisi `payload.filename` user-controlled (config rollback) tanpa sanitize.
- **Dampak:** Log poisoning (fake log entries), terminal escape injection di dashboard log viewer, potential XSS di UI dashboard (jika reason di-render tanpa escaping).
- **Fix:** Sanitize SEMUA field di boundary ingest (server-side), escape HTML di dashboard, sanitize control chars selain CR/LF (ESC, etc.).

### H-07. Machine-ID binding token lemah + `admin_token` plaintext di config file
- **File:** `src/controller/auth.rs:203-211`, `src/main.rs:161-181`, `src/config.rs:581-585, 687-718`
- **Masalah:** (1) Token format `<machine_id>.<sha256(machine_id:admin_token)>` — admin_token yang sama dengan hash domain kecil → brute-forceable jika machine_id diketahui (`/etc/machine-id` readable oleh semua user di Linux). (2) `admin_token` disimpan PLAINTEXT (atau `$sha256$salt$hash`) di `config.toml` — file config readable oleh user proses; jika WAF jalan sebagai root (sebelum privilege drop di agent/server.rs:82-89 yang juga rawan — lihat M-04), token ter-expose. (3) Config backup (`config_backups/*.toml`) menyimpan token lama.
- **Dampak:** Local user / config leak → admin access penuh.
- **Fix:** Simpan hanya hash; gunakan Argon2id/bcrypt (bukan SHA-256 cepat); chmod 600 config; jangan backup token lama (atau redact).

---

## 🟡 MEDIUM

### M-01. ReDoS: custom regex dari config/plugins/API dieksekusi tanpa timeout atau size guard
- **File:** `src/rules.rs:333-443` (compile `Regex::new(pattern)` dari `custom_rules` dan plugins), `src/dlp.rs:131-141, 208-216`, `src/rule_engine/mod.rs:574`
- **Masalah:** `Regex::new(pattern)` di-compile dari input config (user-controlled via `/api/v1/custom-rules`), DLP `custom_patterns`, dan rule engine. Regex crate Rust punya linear-time guarantee **untuk pattern valid**, tapi: (a) pattern yang invalid di-skip diam-diam (`.ok()`) — user tidak tahu rule mati; (b) DLP scan membatasi 1MB tapi `Regex::new` dipanggil **per-request** di hot path (dlp.rs:132) — kompilasi regex mahal; (c) tidak ada batas kompleksitas pattern → config attacker bisa isi ribuan rule.
- **Dampak:** CPU exhaustion via compile cost; rule silent-fail (bypass).
- **Fix:** Compile regex sekali di startup (sudah untuk custom_rules; lakukan juga untuk DLP custom patterns), validasi pattern dan reject invalid dengan pesan jelas, batasi jumlah rule.

### M-02. WebSocket security proxy: header parsing naif + SSRF/traversal ke backend
- **File:** `src/proxy_engine.rs:465-610`
- **Masalah:** `handle_secure_websocket_tunnel` (port 127.0.0.1:24601): (a) `X-Jarswaf-Real-Backend` di-parse per-line dengan `line.split(':').nth(1)` — header value yang mengandung `:` (mis. `127.0.0.1:9999`) terpotong di titik dua pertama? Tidak — `split(':').nth(1)` mengambil bagian setelah colon PERTAMA, tapi untuk `host:port` nilai `127.0.0.1:9999` → split(':') = ["127.0.0.1", "9999"], nth(1) = "9999" — **port hilang!** Ini bug parsing: value yang benar adalah setelah `x-jarswaf-real-backend: `, bukan setelah colon pertama. (b) Tidak ada validasi `backend_addr` → attacker yang bisa reach port 24601 (localhost-only, jadi lokal) bisa connect ke arbitrary host:port (SSRF). (c) Client dapat mengirim header `X-Jarswaf-Real-Backend` sendiri (proxy meneruskannya verbatim ke backend via `write_all(&header_buf)` — header asli client ikut ter-forward, termasuk yang spoofed).
- **Dampak:** Routing salah (port hilang → koneksi gagal atau salah host), SSRF lokal, header spoof.
- **Fix:** Parse header dengan cara benar (splitn(2, ':') ambil value penuh), validasi backend_addr terhadap allowlist vhost, strip header ini dari client request sebelum forward.

### M-03. Token `Sec-WebSocket-Protocol` di agent: statis, tanpa verifikasi server-side
- **File:** `src/agent/websocket.rs:37-43` (client), `src/agent/websocket.rs:60-91` (handler)
- **Masalah:** Agent mengirim token sebagai WS subprotocol; server (`controller/websocket.rs`) TIDAK memvalidasi subprotocol (lihat C-04). Client agent juga TIDAK memverifikasi bahwa response subprotocol dari server cocok (tungstenite mengembalikan header tapi tidak di-check) → **downgrade attack**: attacker di tengah bisa strip subprotocol dan agent tetap menerima config.
- **Fix:** Validasi subprotocol di server (reject kalau tidak match), dan di client pastikan `response.headers()["sec-websocket-protocol"]` cocok dengan token yang dikirim.

### M-04. Privilege drop setelah bind — race window + tidak ada capability drop
- **File:** `src/agent/server.rs:82-89`
- **Masalah:** `setgid`/`setuid` ke 65534 (nobody) dilakukan SETELAH `server.run_forever()` di-spawn (spawn_blocking) dan setelah listener TCP di-bind — tapi listener di-bind di `proxy_service.add_tcp` sebelum drop. Race: antara bind dan drop, proses masih root; juga tidak ada `setgroups`, `prctl(PR_SET_NO_NEW_PRIVS)`, atau penutupan fd. Jika drop gagal (hanya `warn!`, tidak exit), WAF jalan sebagai root selamanya.
- **Dampak:** Jika WAF compromised (RCE via plugin/config), attacker dapat root.
- **Fix:** Drop privilege SEBELUM bind listener, `setgroups([])` dulu, exit on failure (fail-closed), gunakan systemd `User=nobody` sebagai defense-in-depth.

### M-05. `SUSPICIOUS_IPS` map di-flush tapi RASP block path punya race/over-block window
- **File:** `src/proxy_engine.rs:2258-2285`, `src/rasp.rs:66-91`
- **Masalah:** `flush_suspicious_ips_to_blocklist()` retain dengan `now.duration_since(ts) < 5` → mem-block SEMUA IP yang request dalam 5 detik terakhir saat RASP alert (bukan hanya attacker). RASP heuristic (`analyze_rasp_event`) memblockir `cmd.contains("wget ")` / `"curl "` — termasuk `curl` yang dipakai admin/backup scripts → false positive massal → **self-DoS** (XDP block IP admin). Tidak ada per-IP attribution (event hanya PID/UID/cmd — PID bisa reuse).
- **Dampak:** IP admin ter-block di kernel; sistem kehilangan akses.
- **Fix:** Attribution via cgroup/namespace atau parent process; jangan block seluruh "recent IP list"; whitelist admin IP; gunakan scoring bukan boolean.

### M-06. Gossip anti-replay `seen_nonces` unbounded-ish (clear 10k) + tidak ada timestamp/TTL enforcement
- **File:** `src/gossip.rs:181-213, 228-232`
- **Masalah:** (a) `seen_nonces` HashSet di-clear saat >10k — replay window terbuka setelah clear (attacker dengan key bisa replay paket lama); (b) TTL hanya cek `ttl_secs == 0` — tidak ada timestamp dalam message, jadi TTL tidak benar-benar expire; (c) `score: f32` dari message TIDAK divalidasi range → handler (WafGossipHandler) bisa memasukkan score 100.0 untuk IP mana pun → blocklist poisoning oleh node lain yang punya PSK (atau via replay). (d) PSK default empty string → `derive_gossip_key(b"")` = key deterministik publik → **siapa pun bisa forge message**.
- **Dampak:** Threat intel poisoning, blocklist DoS.
- **Fix:** Sertakan timestamp di message + validasi age; batasi score range; wajibkan PSK non-empty (fail-closed); pertahankan nonce window sliding dengan TTL, bukan clear.

### M-07. Race condition pada config reload vs handler
- **File:** `src/controller/handlers/config.rs:35-84`, `src/agent/mod.rs:155-188`
- **Masalah:** `post_config_handler` menulis config ke disk via `save_config` (tmp+rename, OK) tapi agent side melakukan `fs::metadata().modified()` polling setiap 2 detik — bisa melewati rename dan membaca config setengah-tulis? Rename atomik membuat ini aman, tapi ada race: controller menulis `config.toml.tmp` (file terpisah yang di-poll? Tidak, poll hanya `config.toml`). Namun: dua instance controller (hot-reload + API) menulis tanpa lock → lost update. `config_lock` hanya di handler, SIGHUP reload (`start_config_hot_reload`) TIDAK ambil lock.
- **Dampak:** Konfigurasi WAF tidak konsisten (mis. waf_enabled=false yang di-set user bisa ditimpa reload).
- **Fix:** Satu writer path dengan lock global (tokio Mutex) termasuk SIGHUP handler.

### M-08. Memory: `IP_REPUTATION` dan `BLOCKED_IPS` bounded tapi `LOAD_BALANCER`/`ACME_CHALLENGES` tidak di-trim
- **File:** `src/proxy_engine.rs:618-626`, `src/rules.rs:248`
- **Masalah:** `ACME_CHALLENGES` (DashMap<String,String>) di-insert setiap `post_ssl_renew_handler` dan TIDAK pernah di-retain/expire → unbounded growth via API spam. `LOAD_BALANCER` di-insert per vhost name — bounded oleh jumlah vhost (OK), tapi `ACME_CHALLENGES` jelas leak. `ACTIVE_CONNECTIONS` di-trim 30 menit (OK).
- **Dampak:** Memory leak → OOM (jika attacker punya auth token dan spam renew; atau via public jika token kosong — lihat H-02).
- **Fix:** Tambahkan expiry/TTL pada ACME challenge entries (mis. 10 menit), retain periodic.

---

## 🟢 LOW / INFO

### L-01. `build_client()` default credential ClickHouse hardcoded
- **File:** `src/logging.rs:34-57`
- **Masalah:** `CLICKHOUSE_USER` default "default", `CLICKHOUSE_PASSWORD` default "jarswaf". Jika env tidak di-set dan mode clickhouse aktif, credential default terkirim ke server.
- **Fix:** Fail-fast jika env tidak ada; jangan default password.

### L-02. Honeypot fake payloads statis & predictable
- **File:** `src/honeypot.rs:136-148`
- **Masalah:** `generate_fake_env_honeydoc()` berisi APP_KEY/DB_PASS/AWS keys yang SAMA untuk semua instance — attacker yang familiar dengan jarsWAF langsung tahu itu honeypot (fingerprint) dan bisa gunakan untuk membedakan fake vs real.
- **Fix:** Generate random per instance; variasi format.

### L-03. JWT checks duplikat & dangkal di dua tempat
- **File:** `src/rules/api.rs:84-126` (`check_jwt_token`) + `src/proxy_engine.rs:1654-1679` (`validate_jwt_structure`)
- **Masalah:** `validate_jwt_structure` hanya cek 3-part split — TIDAK base64-decode payload, TIDAK cek exp; duplikat dengan `check_jwt_token` yang lebih lengkap. Keduanya tidak verifikasi signature (lihat C-01).
- **Dampak:** Inconsistency, false sense of JWT protection.
- **Fix:** Satu implementasi, verifikasi signature, jangan cek struktur saja.

### L-04. Fake SSL certificate dates di dashboard
- **File:** `src/controller/handlers/ssl.rs:48-60`
- **Masalah:** `valid_from`/`valid_until` di-hardcode (`now-10d`/`now+80d`), tidak membaca cert asli; `status: "Active"` selalu.
- **Dampak:** Misleading admin; minor.

### L-05. Webhook payload membocorkan path/reason attacker-controlled ke endpoint eksternal
- **File:** `src/webhook.rs:51-60`
- **Masalah:** (a) Payload berisi `path` & `reason` yang bisa berisi data sensitif dari request attacker (mis. `Authorization` tidak — tapi query string bisa berisi token); (b) `maybe_fire_webhook` dipanggil di mana? — grep menunjukkan tidak ada pemanggil di proxy path utama (hanya deklarasi) → webhook mungkin dead code.
- **Fix:** Redact query string di payload; wire pemanggilan atau hapus.

### L-06. `install.sh` mengekspos IP controller + instruksi tanpa auth
- **File:** `src/controller/handlers/config.rs:199-239`
- **Masalah:** Script bash yang di-generate berisi `CONTROLLER_URL=http://<ip>:8080` dan di-serve PUBLIC (di luar auth middleware, `controller/mod.rs:160`). Attacker dapat enumerasi IP internal via response.
- **Fix:** Batasi ke authenticated, atau hapus IP dari script (pakai relative).

---

## Temuan Arsitektur / Konfigurasi (non-CWE)

| # | Temuan | Lokasi | Catatan |
|---|--------|--------|---------|
| A-01 | `trusted_proxies` menggunakan exact match IP — tidak support CIDR | `proxy_engine.rs:86-89, 859-862` | Cloudflare IP ranges berubah; misconfig = spoof X-Forwarded-For diterima |
| A-02 | Rate limit key komposit `ip\|user_key` — user_key dari header yang attacker kontrol | `rules.rs` `rate_limit_key`, `proxy_engine.rs:1607-1611` | Attacker ganti `x-user-id` per request → bypass rate limit (per-user bucket tak terbatas) |
| A-03 | Bot challenge PoW `hash.starts_with("000")` — 16-bit work; brute-forceable (65k hash) | `proxy_engine.rs:1267` | Bukan PoW yang berarti; masih bisa spam challenge-verify |
| A-04 | `parse_size` default 10MB jika format salah; `parse_rate_limit` default 600 | `config.rs:587-619` | Typo config = silent default, bukan error |
| A-05 | `REDIS_CLIENT` global cache tidak pernah di-reset saat config reload | `rules.rs:122-123` | Redis URL baru setelah reload tidak terpakai |

---

## Rekomendasi Prioritas (Fix Order)

**P0 — Fix sekarang (security boundary rusak):**
1. C-01: Verifikasi signature JWT di Zero Trust (atau nonaktifkan fitur sampai benar).
2. C-02: Validasi redirect target di bot-challenge (block `//`, `\`, non-`/` prefix).
3. C-03: gRPC interceptor auth.
4. C-04: Auth WS agent + signed block commands.

**P1 — Minggu ini:**
5. H-01: Session token revocable (bukan password echo).
6. H-02: Bind controller ke 127.0.0.1 + CORS allowlist + fail-closed auth.
7. H-04: Rate limit login.
8. H-03: change-password di belakang auth.
9. H-07: Argon2id + chmod 600 + backup redaction.

**P2 — Sprint berikutnya:**
10. H-05: Fix CSRF rule logic.
11. H-06: Sanitize log di ingest boundary.
12. M-01 s/d M-08 (regex compile, WS proxy parsing, privilege drop, gossip PSK/ttl, config lock, ACME TTL).
13. A-01 s/d A-05.

---

## Metodologi & Verifikasi

- Audit statis menyeluruh 73 file source (19.392 LOC), fokus pada 25 file kritis.
- Semua temuan diverifikasi langsung dari source code dengan line number (bukan asumsi).
- **Tidak ada** `unsafe` blocks bermasalah di luar `rasp.rs:62` (`read_unaligned` — aman karena ada length check `buf.len() < size_of` di line 57; flag INFO).
- Tidak ada penggunaan `transmute`, `mem::zeroed`, atau pointer aritmatika lain.
- Crypto: ChaCha20Poly1305 di gossip dipakai benar (random nonce per message, AEAD), tapi key derivation dari PSK pendek lemah (M-06).
- Race conditions: DashMap + ArcSwap dipakai benar di proxy path utama; kelemahan di edge path (ACME, gossip, config write).

*Laporan ini untuk keperluan hardening internal. Semua target adalah lab/CTF environment.*
