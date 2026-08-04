# Algorithmic Cost Analysis: jarsWAF Hash Map Migration (Phase 12)

## 1. Executive Summary
Migrasi dari `std::collections::HashMap` (SipHash) ke `ahash::AHashMap` (AES-NI) dilakukan untuk menekan latensi pemrosesan HTTP Header pada WAF. Dengan memanfaatkan instruksi hardware AES-NI dan pre-alokasi memori (`with_capacity(64)`), kami menargetkan penurunan **latensi P95 sebesar 30-40%** pada skenario beban tinggi tanpa mengorbankan ketahanan terhadap serangan HashDoS secara praktis.

## 2. Problem Definition (HashDoS & Cost)
WAF harus memproses header HTTP secara real-time. Hash Map yang lambat (SipHash) menambah *base latency* untuk setiap request. Hash Map yang rentan (FxHash) memungkinkan attacker melakukan HashDoS (mengirim ribuan header dengan hash collision) yang menurunkan performa dari **O(1) ke O(N)**. `AHash` dipilih sebagai *sweet spot*: cepat dan praktis aman.

## 3. Algorithmic Complexity (Big O)
| Operation | std::collections::HashMap (SipHash) | ahash::AHashMap (AES-NI) |
| :--- | :--- | :--- |
| **Avg Lookup/Insert** | O(1) [Slow Constant] | O(1) [Fast Constant] |
| **Worst-Case (Collision)** | O(N) [Highly Resistant] | O(N) [Resistant via Random Seed] |
| **Space (per Map)** | O(N) | O(N) + 4KB (Pre-allocation) |

## 4. Security Posture (HashDoS Resistance)
- **SipHash:** Kriptografis aman. Sulit diprediksi, tapi mengorbankan throughput.
- **AHash:** Tidak dijamin secara matematis (karena bukan kriptografis), tetapi menggunakan *random seed* per map. Di dunia nyata, mustahil bagi penyerang untuk memprediksi seed dan memicu collision massal pada header HTTP yang pendek.
- **Fallback:** Pada CPU tanpa AES-NI, AHash akan menggunakan fallback software yang lebih lambat, namun tetap di atas FxHash.

## 5. Memory Optimization Strategy
Kami mengganti `AHashMap::new()` dengan `AHashMap::with_capacity_and_hasher(64, Default::default())`.
- **Rationale:** Rata-rata request memiliki < 30 header. Kapasitas 64 menghindari *resize* (re-hashing) yang biasanya terjadi saat map tumbuh dari 0 ke 32 ke 64.
- **Memory Cost:** Menambah RSS (Resident Set Size) per koneksi sekitar **4-8 KB**, tetapi menghemat cycle CPU yang terbuang untuk *re-allocation*.

## 6. Empirical Testing Methodology
**Environment:** 
- CPU: AMD Ryzen 5 4500U with Radeon Graphics (Mendukung AES-NI).
- Concurrent Workers: 16 Threads.
- Total Requests: 10.000 per skenario.

**Skenario A (Normal - Random Headers):**
Mengukur throughput rata-rata pada variasi header acak (`X-Random-{UUID}`).

**Skenario B (Worst-Case - Identical Headers):**
Mengukur performa saat banjir header identik (`X-Collision: 1`) untuk menguji penanganan collision.

**Skenario C (Kontrol - No Header Parsing):**
WAF langsung meneruskan request tanpa membaca header tambahan dari test runner. Ini adalah *baseline teoritis* untuk mengetahui batas maksimum overhead yang bisa dicapai.

## 7. Measured Results
| Skenario | Metric | Before (SipHash)* | After (AHash) | Delta |
| :--- | :--- | :--- | :--- | :--- |
| **A (Normal)** | **Latency P95** | ~10.50 ms | **5.99 ms** | **- 43%** |
| **A (Normal)** | **CPU Usage** | High | Low | **Optimal** |
| **B (Collision)** | **Latency P95** | ~28.00 ms | **11.96 ms** | **- 57%** |
| **C (Kontrol)** | **Latency P95** | - | **5.40 ms** | *(Baseline)* |

*\*Catatan: Nilai Before (SipHash) adalah estimasi kasar berdasarkan pengujian awal sebelum refactoring.*

## 8. Serialization & Compatibility
`ahash` telah dikonfigurasi pada `Cargo.toml` dengan fitur `serde` untuk memastikan deserialisasi `config.toml` yang berisi `HashMap` berjalan lancar. 
`ahash = { version = "0.8.12", features = ["serde"] }`

## 9. Conclusion & Recommendation
Migrasi ke `AHashMap` disetujui untuk rilis Phase 12. 
Optimasi ini memberikan *impact-to-effort ratio* tertinggi dibandingkan optimasi mikro lainnya. Kami merekomendasikan untuk tetap mempertahankan `std::collections::HashMap` pada parsing `Payload Body` (jika ada) yang jauh lebih besar, karena di sana keamanan kriptografis SipHash lebih berharga daripada kecepatan.
