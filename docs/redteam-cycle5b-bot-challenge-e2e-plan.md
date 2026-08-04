# jarsWAF — Rencana Siklus 5b: Bot Challenge E2E (Headless Browser)

**Status:** Planned (2026-08-02)
**Terkait:** [[waf-red-team-cycle4-ssrf-upload-graphql-csrf]]

---

## Konteks

Di Cycle 4, **Bot Challenge di-skip** karena membutuhkan browser engine untuk pengujian end-to-end. Ini gap yang diakui sendiri di vault. Siklus ini menutup loop yang menggantung.

## Scope

1. **Setup headless browser harness** — Playwright (Chromium) untuk mensimulasikan browser asli:
   - JS challenge execution (proof-of-work)
   - Cookie issuance & re-validation
   - Canvas/WebGL fingerprinting (jika ada)
2. **Bypass analysis**:
   - Playwright biasa (headless default) — apakah terdeteksi sebagai bot?
   - Playwright dengan stealth flags (WebGL vendor, navigator props)
   - HTTP client tanpa JS (curl) — harus diblokir
   - Replay cookie tanpa menjalankan JS — apakah valid?
3. **Rate limiting interaksi** — challenge setelah N request, token bucket reset.
4. **False positive check** — browser asli (Firefox/Chromium GUI) harus LOLOS challenge.

## Deliverables

- [ ] Cycle 5b note: `waf-red-team-cycle5-bot-challenge-e2e.md`
- [ ] Harness script di `scripts/` (Playwright)
- [ ] Test matrix: {headless, stealth, curl, replay} × {challenge flow}

## Risiko

- Playwright membutuhkan Chromium download (~150MB) — sekali setup
- Challenge bisa break UX jika JS gagal load di browser lama

## Referensi

- Cycle 4 note — bagian "Bot Challenge — Skip"
- `waf-red-team-cycle4-ssrf-upload-graphql-csrf.md`
