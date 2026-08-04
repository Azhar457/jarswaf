---
tags: [security, waf, sql-injection]
aliases: [SQL Comment Injection WAF Bypass]
status: pending
created: 2026-07-24
updated: 2026-07-24
cssclasses: [wide-table]
---

> [!abstract] SQL comment injection adalah teknik bypass WAF yang memanfaatkan karakter comment SQL (`--`, `#`, `/*`) setelah single quote untuk menutup query tanpa membuat statement boolean. Teknik ini berhasil melewati AST semantic engine karena tidak menghasilkan boolean tautology (`'1'='1`) yang biasa dideteksi — dan diperparah oleh fitur safe AST profile learning yang bisa di-poisoning.

# SQL Comment Injection — WAF Bypass & Mitigation

## Daftar Isi
1. [[#1. Attack Vector Overview]]
2. [[#2. Root Cause Analysis]]
3. [[#3. Exploit Flow]]
4. [[#4. Fix Implementation]]
5. [[#5. Verification]]
6. [[#6. Architectural Lesson]]
7. [[#7. Mitigation for Production]]

## 1. Attack Vector Overview

| Aspect | Detail |
|--------|--------|
| **Type** | SQL Injection — Comment Termination |
| **Layer** | L7 (HTTP) via WAF proxy |
| **Severity** | **Critical** — full bypass, 5 varian terkonfirmasi |
| **Varian Diuji** | `'--`, `admin'--`, `'#`, `'/*`, `'%23` |
| **Hasil** | Semua return 200 (bypass) sebelum fix |
| **Root Cause** | AST engine cuma detek tautology + UNION, gak detek comment termination |
| **Fix Level** | 1 file: `src/rules.rs` — fast pre-check sebelum safe AST profile |

### Attack Surface

```
SQL injection → comment termination
  ├── '--          (SQL single-line comment)
  ├── '--         (with dash variations)
  ├── '#           (MySQL comment)
  ├── '/*          (block comment open)
  ├── '/*!OR*/'    (conditional comment, MySQL)
  └── '%23         (URL-encoded #)
```

Semua varian menghasilkan **HTTP 200** — request lolos ke backend seolah-olah SAFE.

---

## 2. Root Cause Analysis

Dua bug terpisah yang bekerja **bersamaan** menghasilkan eternal bypass:

### Bug 1: AST engine tidak handle comment tokens

Path kritis: `src/rules.rs:930-960`

```rust
// Semantic engine hanya detek PATTERN ini:
if contains("' OR '1'='1") || contains("' AND '1'='1") {
    return Some("tautology");
}
// Tapi TIDAK detek:
if contains("'--") || contains("'#") || contains("'/*") {
    // Nothing! Langsung passing
}
```

Token SQL `'--` di-parse oleh tokenizer sebagai `Symbol('\'')` + `Comment`, tapi `check_sql_injection_semantic()` hanya mencari tautology (`OR '1'='1`) dan UNION. **Comment termination gak pernah dicek.**

### Bug 2: Safe AST Profile Poisoning

Path kritis: `src/rules.rs:932-933`

```rust
fn check_request(...) {
    // ...
    // Setelah semua rule check
    learn_safe_ast_profile(path, &norm_query); // ← line 932
    learn_safe_ast_profile(path, &norm_body);   // ← line 933
}
```

Setiap request yang lolos dari WAF **otomatis dipelajari** sebagai safe profile. Artinya:

```
Request 1: id=1 → lolos → profile belajar signature "=" untuk path "/"
Request 2: id=1'-- → lolos karena Bug 1 → belajar signature "'--" juga
Request 3: id=1'-- → CLOBBERED! is_safe_ast_signature return TRUE
```

**Astute reader akan melihat:** ini bukan cuma bypass — ini **eternal bypass**. Setelah signature "'--" dipelajari, request selanjutnya gak akan pernah masuk semantic engine. Safe profile poisoning mengunci bypass secara permanen sampai WAF di-restart.

### Diagram alur bypass

```
         ┌──────────────────────┐
         │  Tokenizer          │
         │  "'--" → [Symbol,   │
         │          Comment]    │
         └────────┬─────────────┘
                  │
         ┌────────▼─────────────┐
         │  check_sql_injection │
         │  _semantic()         │ ← hanya cek tautology + UNION
         │  '1'='1? NO          │
         │  UNION? NO           │
         └────────┬─────────────┘
                  │ return None (no match)
         ┌────────▼─────────────┐
         │  is_safe_ast_        │
         │  signature()         │ ← cek profile
         │  TRUE (or akan       │
         │  belajar setelah ini)│
         └────────┬─────────────┘
                  │ return true → skip
         ┌────────▼─────────────┐
         │ learn_safe_ast_      │
         │ profile()            │ ← fitur ini alternatif block
         └────────┬─────────────┘
                  │ poison: "=" + "'--" → safe profile
         ┌────────▼─────────────┐
         │  Forward to backend  │ ← 200 OK!
         │  (BYPS)              │
         └──────────────────────┘
```

---

## 3. Exploit Flow

```
Attacker → HTTP GET /?id=1'--
  → WAF Pingora proxy :8000
  → check_request() dipanggil
  → Phase 0: Canary check → NO
  → Rule loop: SQLI-*, XSS-*, ... → gak match
  → SQLI-AST: tokenize → [Symbol('\''), Comment]
  → check_sql_injection_semantic() → None (no tautology)
  → is_safe_ast_signature() → TRUE || akan belajar → skip
  → learn_safe_ast_profile() → poison profile
  → Proxy forward ke backend (localhost:8080)
  → Backend: SELECT * FROM users WHERE id = '1'-- ' ← SQL valid!
  → Response 200 OK
```

### Kenapa `--` adalah comment yang sangat berbahaya?

Di SQL standar (ANSI), `--` adalah **line comment** — semua karakter setelahnya sampai akhir baris diabaikan. Di kubus:

```sql
SELECT * FROM users WHERE id = '1'--'
                                      ^^
                                      comment! sisa string
                                      penutup diabaikan
```

Query yang valid:
```sql
SELECT * FROM users WHERE id = '1'
```

Ini return **semua users** — classic SQLi.

---

## 4. Fix Implementation

### Strategi: Fast Pre-Check Sebelum Safe AST Check

**File:** `src/rules.rs:689-706`

```rust
// AST / Semantic WAF Engine checks
if is_rule_enabled("SQLI-AST", enabled_rules) {
    // Fast pre-check: comment injection patterns ('--, '#, '/*)
    // Must run BEFORE safe AST profile check to prevent profile poisoning
    let sqli_comment_patterns = ["'--", "\"--", "'#", "\"#", "'/*", "\"/*"];
    let has_comment_injection = sqli_comment_patterns.iter().any(|p| {
        norm_query.contains(p) || norm_body.contains(p) || norm_path.contains(p)
    });
    if has_comment_injection {
        if let Some(res) = process_match(
            "SQLI-AST".to_string(),
            "SQL comment injection detected (pre-check)".to_string(),
            5,  // severity score
        ) {
            return Some(res);
        }
    }
    // THEN proceed with semantic engine + safe profile check
    if let Some(msg) = check_sql_injection_semantic(&norm_query) {
        if !is_safe_ast_signature(path, &norm_query) {
            // block
        }
    }
}
```

### Key Design Decision

| Option | Detail | Dipilih? |
|--------|--------|:--------:|
| **A: Pre-check di awal rules.rs** | Detek pattern `'--`/`'#`/`'/*` di query/path/body langsung sebelum semantic engine jalan. Tidak terpengaruh safe profile poisoning karena return **sebelum** profile check. | ✅ |
| B: Tambah pattern di semantic engine | `check_sql_injection_semantic` jadi tambah deteksi comment. Tapi masih kena safe profile poisoning. | ❌ |
| C: Disable safe profile learning | Mudah tapi menghilangkan fitur False Positive reduction. | ❌ |
| D: Fix tokenizer block comment | Hanya handle `/*` bukan `--`/`#`. Parsial. | ❌ |

### Alasan Pre-Check Menang

1. **Posisi:** Sebelum `is_safe_ast_signature()` — jadi gak terpoison
2. **Sederhana:** String matching, gak perlu tokenize ulang
3. **Deterministik:** Gak ada false negative — pattern `--` setelah quote hampir pasti injection
4. **Non-destruktif:** Gak ngubah mekanisme safe profile untuk attack lain

### Kenapa pattern ini cukup?

Di aplikasi web normal, parameter yang mengandung `'--`, `'#`, atau `'/*` **sangat jarang** legitimate. Hampir semua framework modern pake prepared statement atau ORM. Kalaupun ada legitimate use case (search dengan special chars), anomaly score bisa di-lower untuk path tertentu.

---

## 5. Verification

### End-to-End Test Results

| Test | Payload | Before | After | Status |
|------|---------|:------:|:-----:|:------:|
| SAFE baseline | `?q=hello` | 200 | 200 | ✅ |
| SQLi comment `'--` | `?id=1'--` | **200** | **403** | 🔥 FIXED |
| SQLi comment `'#` | `?id=1'#` | **200** | **403** | 🔥 FIXED |
| SQLi comment `'/*` | `?id=1'/*` | **200** | **403** | 🔥 FIXED |
| SQLi tautology | `?id=1' OR '1'='1` | 403 | 403 | ✅ (unchanged) |
| SQLi UNION | `?id=1 UNION SELECT *` | 403 | 403 | ✅ (unchanged) |
| XSS | `<svg/onload>` | 403 | 403 | ✅ (unchanged) |

### Unit Test Count

```bash
$ cargo test
test result: ok. 65 passed; 0 failed
```

---

## 6. Architectural Lesson

### Anti-Pattern: Self-Learning Bypass (Safe AST Profile)

Fitur `learn_safe_ast_profile` di line 932-933 adalah **anti-pattern klasik machine learning in security**:

```
Pendekatan: 
  "Learn what's safe, block everything else"

Masalah:
  Attacker bisa memanipulasi "safe" set dengan mengirim 
  request malicious yang untested (0-day bypass)
  → Menjadi safe profile → eternal bypass
```

Ini mirip dengan **SQL injection through Bayesian filter poisoning** — tapi di level AST signature, bukan email spam.

### The Real Fix Is Architectural

Pre-check adalah **patch-layer**, bukan fix-struktural. Fix jangka panjang:

1. **Immutable safe profiles** — jangan auto-learn. Gunakan curated, versioned profile database.
2. **Context-aware learning** — jangan learn query dengan special chars (`'`, `--`, `/*`)
3. **Decay mechanism** — profile punya TTL, perlu di-re-verify
4. **Honest about gap** — fitur learning ini pada dasarnya adalah **allowlist builder** untuk false positive reduction, BUKAN security feature. Naming yang jujur akan mencegah salah asumsi.

### Pattern Recognition: Quote-Wrapped Injection

Ini adalah kelas serangan yang lebih luas dari comment injection:

```sql
' OR '1'='1         -- Boolean tautology (detected by AST)
' OR SLEEP(5)       -- Time-based (not always detected)
' UNION SELECT ...  -- UNION-based (detected by AST)
'--                 -- Comment termination (was BYPASS, now fixed)
'||'1'='1           -- String concatenation (detected by body rules)
```

Setiap injection yang dimulai dengan `'` butuh **quote balancing** — WAF harus cek apakah quote ditutup dengan benar atau di-terminate oleh comment.

---

## 7. Mitigation for Production

### Immediate

1. **Deploy fix** — fast pre-check di `rules.rs`
2. **Restart WAF** — clear poisoned safe profiles (profile adalah in-memory, reset on restart)
3. **Review audit log** untuk `learn_safe_ast_profile` entries — identifikasi apakah ada 0-day yang sudah ter-poison

### Monitoring

Di WAF audit log, cari:

- `SQL comment injection detected (pre-check)` — attack blocked ✅
- `Semantic SQLi block: ...` — existing semantic detection
- Anomaly score meningkat untuk path yang sebelumnya "safe"

### Long-term

| Rekomendasi | Priority | Effort |
|-------------|:--------:|:------:|
| Immutable profile database (tidak auto-learn) | High | 2-3 days |
| Curated safe profile per application | Medium | 1 week |
| Profile decay/age-out mechanism | Low | 1 day |

## References

1. Source: `src/rules.rs:689-706` — Fast pre-check implementation
2. Source: `src/rules.rs:930-960` — Safe AST profile learning (vulnerable)
3. Source: `src/rules.rs:720-725` — `check_sql_injection_semantic`
4. [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
5. [OWASP WAF Evasion Techniques](https://owasp.org/www-community/attacks/SQL_Injection_Bypassing_WAF)
6. [PortSwigger: SQL injection cheat sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

## Koneksi ke Vault

| Catatan | Koneksi |
|---------|---------|
| [[waf-reverse-proxy-deepdive]] | WAF architecture & reverse proxy flow |
| [[waf-ebpf-xdp-pentest]] | Network-layer (XDP) testing complement |
| [[purple-team-osi-killchain]] | Purple team killchain integration |
| [[web-hacking-exploitation]] | Web app exploitation techniques |
