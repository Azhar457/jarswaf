# 🛡️ Aegis WAF (Web Application Firewall)

Aegis WAF adalah project *Proof of Concept* (PoC) Web Application Firewall modern yang dibangun menggunakan **Rust** (Backend Proxy & Controller) dan **Svelte** (Frontend Dashboard).

Project ini dirancang sebagai WAF *reverse proxy* yang ringan, berkecepatan tinggi, dan mampu menyajikan log penyerangan secara *real-time* dengan visualisasi yang futuristik. 

## 🏗️ Architecture Diagram

```mermaid
flowchart LR
    %% Clients & Sources
    subgraph Sources [Log Sources & Traffic]
        Clients((Web Clients))
        Bots((Malicious Bots))
    end

    %% WAF Agent
    subgraph Agent [Aegis WAF Agent Node]
        WAF_Engine{Aegis Security Engine}
        Rules[Pattern Matching / SQLi / XSS]
        RateLimit[Rate Limiting]
        WAF_Engine --> Rules
        WAF_Engine --> RateLimit
    end

    %% Web Servers
    subgraph Targets [Protected Targets]
        Nginx[NGINX]
        Apache[Apache]
        NodeJS[Node.js]
    end

    %% Central Brain
    subgraph Central [Aegis Central Controller]
        API(REST API)
        WebSocket(Realtime Broadcast)
        Reputation[Reputation Blocklist Sync]
    end
    
    %% Analytics
    subgraph Data [Analytics & Storage]
        ClickHouse[(ClickHouse DB)]
    end

    %% Dashboard
    subgraph UI [Online Console]
        Dashboard([Svelte Real-Time Dashboard])
    end

    %% Connections
    Clients -- "HTTP Requests" --> WAF_Engine
    Bots -- "Malicious Payloads" --> WAF_Engine

    WAF_Engine -- "Clean Traffic" --> Targets
    WAF_Engine -. "Block Bad IPs" .-> Bots

    WAF_Engine -- "Stream Logs & Stats" --> API
    API --> ClickHouse

    ClickHouse -. "Distribute Blocklist" .-> Reputation
    Reputation -. "Sync Rules" .-> WAF_Engine

    ClickHouse -- "Query Logs" --> API
    API -- "SSE / WS" --> WebSocket
    WebSocket -- "Live Alerts & Metrics" --> Dashboard
```

## ✨ Pros (Kelebihan & Keunggulan)

- **High-Performance Rust Proxy**: Menggunakan `tokio`, `axum`, dan `hyper`. Proxy didesain secara asinkron (async) tanpa proses blocking pada *hot path*, sehingga overhead latensi analisis WAF sangat kecil.
- **Enterprise-Ready Database (ClickHouse)**: Kini Aegis beralih sepenuhnya ke **ClickHouse**. Semua *log* dan *metrics* disiram melalui *batching* (`JSONEachRow`) ke arsitektur analitik terdistribusi, menghilangkan *bottleneck* I/O pada SQLite.
- **Real-Time Data Streaming**: Dashboard menggunakan Svelte Stores dan `Server-Sent Events (SSE)`. Log penyerangan akan dirender secara hardware-accelerated di UI melalui `@xterm/xterm` tanpa menyebabkan *freeze* pada browser meskipun pada saat terjadi DDoS.
- **Modern & Beautiful UI**: Antarmuka dashboard didesain seperti terminal pengawasan (NOC) yang dilengkapi peta lalu-lintas jaringan (SVG Attack Map), Svelte stores reactivity, dan animasi micro-interactions.
- **Reputation Blocklist Engine**: Mendeteksi IP nakal yang melebihi limit blokir secara konstan dan mem- *ban* IP tersebut di seluruh node Agent WAF.

---

## ⚠️ Cons & Limitations (Kekurangan Secara Jujur)

Walaupun tampilan terlihat canggih, mohon diperhatikan bahwa project ini **belum sepenuhnya siap untuk production** dan masih memiliki banyak *mockup* serta keterbatasan teknis:

1. **Dashboard Rate Limiting Hanya Mockup**: 
   UI konfigurasi *Rate Limiting Tiers* (Default, Auth, WebDAV, dll) saat ini **100% hardcoded (palsu)**. Backend Rust baru mendukung *Rate Limiting* sederhana berupa batas RPM (*Requests Per Minute*) global atau per *virtual host*. Tidak ada penyimpanan tier di database.
   
2. **Metrik Node Agent Adalah Simulasi (Palsu)**: 
   Panel "WAF Node Agent Diagnostics" di dashboard yang menampilkan informasi penggunaan CPU, RAM, Disk, dan Uptime saat ini hanya **menggunakan fungsi matematika `Math.random()` di Svelte**. Belum ada integrasi eBPF atau `sysinfo` untuk mengukur *hardware usage* secara nyata.

3. **Tidak Ada Sinkronisasi Real-Time Config (Gossip Protocol)**:
   Ketika rule atau blocklist diubah via UI, controller saat ini menyebar IP Blocklist, namun belum mendukung penyebaran Custom Rules atau sertifikat SSL secara dinamis tanpa *restart* Agent.

---

## Kesimpulan

Aegis WAF adalah landasan / prototipe yang **sangat bagus** secara arsitektur dasar. Performa Rust Proxy ditambah skalabilitas basis data ClickHouse dan reaktivitas Svelte UI menyajikan _User Experience_ yang luar biasa cepat. 

**Next Steps yang dibutuhkan (Roadmap):**
- **eBPF Integration**: Menanamkan probe eBPF (XDP) untuk mem- *drop* koneksi pada level kernel sehingga konsumsi CPU server target mendekati 0% saat DDoS (Phase 5).
- Mengganti simulasi *hardware metrics* dengan metrik sungguhan.
- Membuat Endpoint API untuk mengatur *Rate Limiting Tiers* yang kompleks.

---

## 🚀 Tata Cara Instalasi

Aegis WAF terbagi menjadi dua komponen utama: **Central Controller** (sebagai otak & penyimpan log) dan **Agent Node** (sebagai shield yang dipasang di server target).

### 1. Menjalankan Central Controller & Dashboard (Windows / Linux / macOS)
Sangat direkomendasikan menjalankan Controller menggunakan **Docker Desktop** (Windows/Mac) atau **Docker Engine** (Linux) karena sudah me-*bundling* ClickHouse Database.

```bash
# 1. Masuk ke direktori aegis-waf
cd aegis-waf

# 2. Nyalakan Controller, Dashboard UI, dan ClickHouse dalam 1x perintah
docker-compose up -d --build
```
*Akses Dashboard WAF di Browser: `http://localhost:8080`*

### 2. Memasang Agent Node di Target Server (Linux / macOS)
Gunakan *install script* yang di-_host_ oleh Controller Anda untuk mengonfigurasi Agent target:

```bash
# Ganti <CONTROLLER_IP> dengan IP Private/Public dari mesin Central Controller Anda
curl -sSL http://<CONTROLLER_IP>:8080/install.sh | CONTROLLER_IP=<CONTROLLER_IP>:8080 bash
```

*(Catatan PoC: Pada tahap pengembangan saat ini, Anda mungkin perlu melakukan `cargo build --release` secara manual di VM target jika rilis _binary_ belum dipublikasikan).*

---

## 💻 Perbedaan Fitur Berdasarkan Sistem Operasi (OS Compatibility)

Aegis WAF dirancang untuk mendukung *cross-platform compatibility*, yang secara otomatis (gracefully) beradaptasi berdasarkan Sistem Operasi yang digunakan oleh Server Target.

### 🐧 Linux (eBPF XDP Enabled) - Rekomendasi Produksi
Pada sistem Linux modern (Kernel >= 5.8), Aegis WAF memanfaatkan **eBPF (Extended Berkeley Packet Filter) XDP (eXpress Data Path)** untuk membuang paket berbahaya di level kernel sebelum paket tersebut mencapai *user-space networking stack*.

**Pros:**
- **Extreme Performance:** Trafik berbahaya didrop langsung di level Network Interface Card (NIC) driver. Memastikan CPU overhead mendekati 0% saat terjadi Volumetric DDoS.
- **True Zero-Day Defense:** Karena payload diblokir sebelum TCP/IP stack melakukan parsing, kerentanan pada HTTP parser atau OS networking stack tidak dapat dieksploitasi.
- **Resource Efficiency:** Proxy *user-space* Axum tidak membuang-buang memori atau CPU untuk memproses koneksi dari *bad actors*.

**Cons:**
- Membutuhkan hak akses *root* Linux (CAP_BPF/CAP_NET_ADMIN).

### 🪟 Windows & 🍎 macOS (L7 Proxy Fallback) - Pengembangan & Testing
Pada Windows dan macOS, kode Rust secara pintar akan me- *disable* modul eBPF. Ketika Aegis WAF menerima perintah untuk memblokir IP, sistem akan otomatis melakukan *fallback* sepenuhnya ke **Layer 7 Application Proxy (Axum)**.

**Pros:**
- **Universal Portability:** Berjalan mulus di *local environment* para Developer tanpa perlu setup Linux VM.
- **Full Deep Packet Inspection:** Tetap menjalankan Regex, *signature matching*, pembatasan akses (*rate-limiting*), dan virtual host routing sama persis seperti pada Linux.
- **Mudah di-debug:** Bebas dari panic Kernel atau error eBPF Verifier.

**Cons:**
- **Rentan terhadap Volumetric DDoS:** Karena semua koneksi diizinkan masuk ke *user-space* (Layer 7) untuk dievaluasi oleh proxy Axum sebelum diberikan `403 Forbidden`, serangan jutaan *request* secara simultan tetap akan membebani CPU dan RAM server proxy.
- **Latensi Tinggi saat Heavy Load:** Menangani serangan di Layer 7 jauh lebih berat dan lambat daripada men- *drop* koneksi di Layer 4 / Kernel.

### Kesimpulan
Secara arsitektur, **Aegis WAF siap digunakan di semua OS**. Anda bebas mengembangkan aplikasi ini di Windows/Mac menggunakan `start.bat`. Namun, saat WAF ini dipasang di *production server* ber-OS Linux, modul eBPF XDP akan otomatis aktif dan menjadikannya sebuah WAF berskala Enterprise sesungguhnya!
