# Panduan Pengembangan jarsWAF (Gemini AI Rules)

Berikut adalah aturan-aturan penting yang harus selalu dipatuhi sebelum melakukan commit kode ke dalam repositori jarsWAF:

## 1. ⚙️ Pre-Commit Checks (Format & Linting)
Wajib menjalankan perintah berikut di lokal untuk memastikan kode mematuhi standar format dan bebas dari kesalahan statis sebelum melakukan `git push`:

```bash
# 1. Format kode Rust secara otomatis
cargo fmt --all

# 2. Verifikasi format (harus bersih tanpa perbedaan)
cargo fmt --all -- --check

# 3. Verifikasi clippy lints (harus lulus tanpa error)
cargo clippy --all-targets --all-features
```

## 2. 🔒 Keamanan Credential (PTES Compliance)
- **Auto-Hashing**: Pastikan token plaintext (seperti `admin_token`) yang dibuat oleh installer otomatis di-hash menggunakan Salted SHA-256 pada startup pertama oleh Controller.
- **Syslog Protection**: Jangan pernah mencetak password/token plaintext ke stdout/stderr jika terdeteksi berjalan di bawah systemd (`INVOCATION_ID` aktif) atau mode non-TTY untuk mencegah *Information Disclosure* via journald. Tuliskan password tersebut ke berkas onboard secure `/opt/jarswaf/admin_onboarding_credential` dengan hak akses `0600`.
