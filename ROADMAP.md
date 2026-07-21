# JARSWAF Development Tracker & Roadmap

Dokumen ini berfungsi untuk melacak semua pengembangan, perbaikan arsitektur, dan pencapaian pada **JARSWAF** agar standar **Elite/Gold Standard Best Practices** tetap terarah dan tidak terlupakan pada sesi-sesi berikutnya.

---

## ✅ Selesai (Completed)

### 1. Arsitektur Proxy & Load Balancing
- **Proxy Engine (Pingora):** Reverse proxy menggunakan Cloudflare Pingora (Rust) untuk keamanan memori (memory safety) dan *zero-copy forwarding*.
- **WebSocket Security Proxy:** Berhasil meneruskan upgrade WebSocket. *(Tugas selanjutnya: menambahkan AST Tokenizer untuk memeriksa frame di dalam WebSocket).*
- **Load Balancing (Round Robin):** Implementasi failover ke first backend apabila *health check* gagal.

### 2. Rate Limiting & Proteksi (Token Bucket)
- **Token Bucket Algoritma:** Terintegrasi menggunakan memori *cache* berkecepatan tinggi (`moka` DashMap dengan kapasitas 10k IP).
- **HTTP Headers (Best Practice):** Inject header `X-RateLimit-Limit`, `X-RateLimit-Remaining`, dan `X-RateLimit-Reset` ke setiap respons melalui `response_filter` Pingora.

### 3. Keamanan Tingkat Kernel (eBPF & XDP)
- **Persistent IP Blocking:** Otomatis memasukkan IP ke kernel *blocklist map* jika melakukan percobaan penyerangan melebihi *threshold*.
- **Konfigurasi Interface (Multi-environment):** Parameter `xdp_interface` pada `config.toml` (mendukung `eth0` untuk VM, `podman0` untuk Podman) agar `XDP_MANAGER.attach()` selalu berjalan saat startup.
- **Auto-Remediation (Unblock):** Sinkronisasi otomatis menggunakan `tokio::spawn(xdp.unblock_ip(ipv4))` ketika tier/waktu hukuman telah kedaluwarsa.
- **Threshold Ketat:** Penurunan threshold pelanggaran beruntun (strikes) menjadi **3 pelanggaran** (sebelumnya 5).
- **Network Byte Order Fix:** Konversi `u32::from().to_be()` sehingga format IP sama persis dengan yang diharapkan oleh modul eBPF di Kernel.

### 4. Semantic AST WAF Engine (Refaktor Selesai)
- **Mitigasi ReDoS:** Menghapus sepenuhnya Regex raksasa untuk SQLi dan XSS dari modul aturan *body* konvensional.
- **Deteksi Cerdas:** Mengalihkan seluruh analisis payload SQLi/XSS ke parser *Abstract Syntax Tree (AST)* yang token-based (`check_sql_injection_semantic`). Jauh lebih cepat, presisi, dan aman dari obfuskasi.

---

## ⏳ Sedang Berjalan (In Progress / Verification)

- [ ] **Uji Coba Rate Limit (cURL):** Memeriksa secara manual bahwa WAF menolak trafik berlebih dengan HTTP 429 dan memberikan informasi *Retry-After*.
- [ ] **Pengujian Multi-Agent VM vs Podman:** Menguji ketangguhan sinkronisasi eBPF Block/Unblock menggunakan jaringan (`xdp_interface`) yang berbeda.

---

## 🎯 Target Utama Selanjutnya (To-Do)

### 1. Sinkronisasi Intelijen Ancaman (Gossip Protocol)
- **Penyempurnaan `gossip.rs`:** Memastikan fitur UDP Multicast untuk sinkronisasi intelijen ancaman antar node JARSWAF (misalnya antara VM dan Podman) berjalan secara *real-time* dengan payload enkripsi.

### 2. Pengembangan Library UI Sendiri (`jars-ui`)
- Menyelesaikan komponen standar UI `jars-ui` dari referensi React Bits dan berpegang pada panduan `README-AGENT.md` yang telah dibuat.
