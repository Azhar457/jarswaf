# jarsWAF Development Reference & Supply Chain Safety

Panduan referensi untuk pengembangan jarsWAF yang terarah — berdasarkan repositori eksternal Awesome-WAF dan PayloadsAllTheThings, plus praktik aman cloning repo publik.

---

## 1. Integrasi Referensi Awesome-WAF

Repo: `https://github.com/0xInfection/Awesome-WAF`

### 1.1 WAF Fingerprinting → Pengembangan Detection Engine

Awesome-WAF mendokumentasikan **100+ WAF vendor fingerprints** — cara setiap WAF ketahuan dari response headers, cookies, dan block page content.

**Relevansi ke jarsWAF:**
- Implementasi `fingerprint.rs`: Deteksi WAF upstream (Cloudflare, AWS WAF, etc.) dari response headers
- Bisa dipakai untuk: auto-adjust rule berdasarkan WAF upstream yang terdeteksi
- Contoh header yang dicek: `cf-ray`, `server: cloudflare`, `X-Sucuri-ID`, `x-iinfo`

```rust
// Potensi implementasi: fingerprint.rs
pub fn detect_upstream_waf(headers: &AHashMap<String, String>) -> Option<&'static str> {
    if headers.get("server").map_or(false, |v| v.contains("cloudflare")) {
        return Some("Cloudflare");
    }
    if headers.contains_key("x-sucuri-id") {
        return Some("Sucuri CloudProxy");
    }
    if headers.get("x-iinfo").is_some() {
        return Some("Imperva Incapsula");
    }
    None
}
```

### 1.2 Evasion Techniques Database → Rule Enhancement

Awesome-WAF mengkatalogkan **70+ teknik bypass WAF** terstruktur per kategori:
- Obfuscation → **Relevan ke** `src/rules/evasion.rs`
- HTTP Parameter Pollution → **Relevan ke** `src/rules/evasion.rs`
- Null byte injection → **Relevan ke** `src/rules/body.rs`
- Unicode normalization → **Relevan ke** `src/rules/evasion.rs`
- Charset bugs → **Relevan ke** phase header inspection

**Prioritas implementasi:**

| # | Teknik Bypass | Status di jarsWAF | Action |
|---|---|---|---|
| 1 | Case toggling (`SeLeCt`) | Covered oleh AST engine | ✅ |
| 2 | URL encoding | Parsed oleh proxy engine | ✅ |
| 3 | Comments injection (`/**/`) | AST engine handles | ✅ |
| 4 | Unicode normalization | Belum ada | 🎯 Target |
| 5 | HTTP Parameter Pollution | Belum ada | 🎯 Target |
| 6 | Null byte (`%00`) | Belum ada | 🎯 Target |
| 7 | Mixed encoding bypass | Belum ada | 🎯 Target |
| 8 | Chunked transfer encoding | SMUGGLE-001 covers | ✅ |

### 1.3 Known Bypasses per WAF Vendor → Regression Testing

Awesome-WAF mencatat bypass spesifik per vendor WAF (Cloudflare, Imperva, ModSecurity, dll). Data ini bisa dipakai untuk **regression testing** rule jarsWAF:

```bash
# Contoh: test apakah jarsWAF bisa block payload yang bypass Cloudflare
curl -X POST http://localhost:8080/test \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'input=<svg onx=() onload=(confirm)(1)>'
# → Expected: 403 Blocked
```

### 1.4 Tooling Reference

| Tool dari Awesome-WAF | Fungsi | Integrasi ke jarsWAF |
|---|---|---|
| **GoTestWAF** | Test WAF detection logic | Run sebagai CI step |
| **FTW (Framework for Testing WAFs)** | OWASP CRS test suite | Import test cases |
| **WAFW00F** | Fingerprinting WAF | Referensi fingerprint table |
| **SQLMap tamper scripts** | Bypass teknik database | Rule enhancement inspiration |

---

## 2. Integrasi PayloadsAllTheThings

Repo: `https://github.com/swisskyrepo/PayloadsAllTheThings`

### 2.1 Attack Coverage Mapping

Berikut mapping kategori PayloadsAllTheThings ke implementasi jarsWAF saat ini:

| Kategori PAT | jarsWAF Rule | Status |
|---|---|---|
| **SQL Injection** | `src/rules/sql_injection.rs` + AST engine | ✅ Active |
| **Command Injection** | `src/rules/body.rs` (CMDI-001/002) | ✅ Active |
| **XSS Injection** | `src/rules/evasion.rs` | ✅ Active |
| **File Inclusion (LFI/RFI)** | Path traversal di headers.rs | ✅ Active |
| **Reverse Shell** | `src/rules/body.rs` (REVSHELL-001 s/d -006) | ✅ **Baru** |
| **XXE Injection** | `src/rules/body.rs` (XXE-001/002) | ✅ Active |
| **Server Side Template Injection** | `src/rules/body.rs` (SSTI-001/002) | ✅ Active |
| **Request Smuggling** | `src/rules/body.rs` (SMUGGLE-001/002) | ✅ Active |
| **Upload Insecure Files** | `src/rules/body.rs` (UPLOAD-001/002/003) | ✅ Active |
| **JWT Attacks** | `src/rules/api_security.rs` | ✅ Active |
| **NoSQL Injection** | ❌ **Belum ada** | 🎯 **Prioritas** |
| **Prototype Pollution** | ❌ **Belum ada** | 🎯 Target |
| **GraphQL Injection** | `src/rules/graphql.rs` | ✅ Active |
| **SSRF** | `src/rules/api.rs` | ✅ Active |
| **LDAP Injection** | ❌ **Belum ada** | Target |
| **ORM Leak** | ❌ **Belum ada** | Target |

### 2.2 Prioritas Pengembangan dari PAT

Berdasarkan gap analysis di atas, prioritas pengembangan ke depan:

#### 🔴 High Priority: NoSQL Injection

PayloadsAllTheThings punya daftar payload NoSQL injection lengkap. Implementasi perlu:

```rust
// src/rules/nosql.rs (potensi file baru)
static NOSQL_MONGO: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\$\ne|\$gt|\$lt|\$regex|\$where|\$nin|\$exists|\$type|"},"\$|\btrue\b.*\$|\bne\b.*\d)"#).unwrap()
});

static NOSQL_EXPRESS: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(\|\|\s*1\s*==\s*1|&\&\s*1\s*==\s*1|\|\|\s*true\s*==\s*true)"#).unwrap()
});
```

**Sumber PAT:** `NoSQL Injection/README.md` → 50+ payload variants.

#### 🟡 Medium Priority: Prototype Pollution

```rust
// Detect prototype pollution in JSON body
static PROTO_POLLUTE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?i)(__proto__|constructor\.prototype|\bprototype\b)"#).unwrap()
});
```

**Sumber PAT:** `Prototype Pollution/README.md`

#### 🟢 Low Priority: LDAP Injection

Jarang ditemui di web modern, tapi tetap perlu coverage.

### 2.3 Payload Test Suite dari PAT

Rekomendasi: extract payload files dari PAT untuk regression testing jarsWAF:

```bash
# Direktori PAT yang relevan
PayloadsAllTheThings/SQL Injection/Intruder/   # SQLi payloads → test AST engine
PayloadsAllTheThings/XSS Injection/Intruder/   # XSS payloads → test evasion.rs
PayloadsAllTheThings/Command Injection/Intruder/ # CMDI payloads → test body.rs
PayloadsAllTheThings/Reverse Shell/             # Revshell payloads → test revshell rules
```

---

## 3. 🛡️ Safe Cloning: Supply Chain Safety untuk Repo Publik

Ada kasus di mana repositori publik di-GitHub dimodifikasi attacker untuk menyisipkan **cookie stealer**, **backdoor**, atau **malicious CI/CD scripts**. Berikut praktik aman:

### 3.1 Risiko Supply Chain di GitHub

| Risiko | Contoh Kasus | Dampak |
|---|---|---|
| **Compromised maintainer** | Attacker dapat akses maintainer, inject malicious commit | Code backdoor, CI credential theft |
| **Dependency confusion** | npm/PyPI package dengan nama mirip | Remote code execution |
| **Malicious GitHub Actions** | Action pihak ketiga yang dicompromise (tj-actions/changed-files) | Secret exfiltration via workflow |
| **Repo takeover** | Repo tidak aktif → attacker claim nama | User clone repo berbahaya |

### 3.2 Safe Clone Workflow

```bash
# ── LEVEL 1: Read-only, non-executable clone ──
# Clone untuk REFERENSI saja (baca file, jangan run script)
git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git
# Flag --depth 1: hanya commit terakhir, minimal history
# Setelah clone: baca manual, jangan run setup/install script

# ── LEVEL 2: Isolated inspection ──
# Clone dan scan dulu sebelum digunakan
git clone --depth 1 https://github.com/0xInfection/Awesome-WAF.git
cd Awesome-WAF

# 1. Cek commits mencurigakan
git log --oneline | head -20

# 2. Cari file executable mencurigakan
find . -name "*.exe" -o -name "*.bat" -o -name "*.ps1" -o -name "*.sh" | grep -v README

# 3. Cari base64/encoded strings mencurigakan di non-code files
grep -r "eval\|base64_decode\|exec\|system" --include="*.md" --include="*.txt" .

# 4. Cek GitHub Security Advisories
# Buka: https://github.com/swisskyrepo/PayloadsAllTheThings/security/advisories

# ── LEVEL 3: Sandboxed execution ──
# Hanya jalankan script di container/VM
docker run --rm -it -v $(pwd):/repo alpine:latest /bin/sh
# Di dalam container baru copy file yang diperlukan
```

### 3.3 Reputable Sources vs Unknown Forks

| Sumber | Trust Level | Cara Verifikasi |
|---|---|---|
| **swisskyrepo/PayloadsAllTheThings** | ⭐ Tinggi (79.5K stars, 2K watchers) | Cek commit history panjang, maintainer aktif |
| **0xInfection/Awesome-WAF** | ⭐ Tinggi (7.6K stars, 244 watchers) | Cek issues/PR active |
| **Forks dari repo di atas** | ⚠️ Sedang | Bandingkan commit dengan upstream |
| **Unknown/small repo (< 100 stars)** | ❌ Rendah | Jangan clone langsung — baca via web dulu |

### 3.4 Verifikasi Setelah Clone

```bash
# Cek GPG signature (jika maintainer sign commits)
git log --show-signature

# Bandingkan dengan upstream URL resmi
git remote -v
# Expected: origin https://github.com/swisskyrepo/PayloadsAllTheThings.git

# Cek branch — pastikan di branch utama, bukan branch aneh
git branch -a

# Cek jumlah contributors vs stars ratio
# Repo legitimate biasanya punya banyak contributors
```

### 3.5 Golden Rule: "Baca Dulu, Run Kemudian"

Untuk repositori referensi seperti Awesome-WAF dan PayloadsAllTheThings:

1. **Clone dangkal** (`--depth 1`) — cukup untuk baca file
2. **Baca README** di browser dulu sebelum clone
3. **Jangan run** `setup.sh`, `install.sh`, atau `make` dari repo publik tanpa audit
4. **Ekstrak manual** file yang diperlukan — jangan run entire toolchain
5. **Cek GitHub Issues** — cari laporan "malicious", "backdoor", "security"

---

## 4. Quick Start: Implementasi Langsung

### Langsung action dari Awesome-WAF:

1. **Implementasi fingerprint detection** — lihat tabel fingerprints Awesome-WAF → buat `src/rules/fingerprint.rs`
2. **Evasion technique coverage** — lihat daftar evasion di Awesome-WAF → tambah rule di `src/rules/evasion.rs`
3. **Test with GoTestWAF** — download GoTestWAF, jalankan test suite terhadap jarsWAF

### Langsung action dari PayloadsAllTheThings:

1. **NoSQL Injection** — buat file baru `src/rules/nosql.rs` dengan rule dari PAT
2. **Extract payload files** untuk regression test — `rsync` file Intruder/ ke `tests/payloads/`
3. **Update CMDI regex** — bandingkan daftar command injection payload dari PAT dengan existing regex

---

*Referensi: Awesome-WAF (0xInfection) · PayloadsAllTheThings (swisskyrepo) · jarsWAF*
