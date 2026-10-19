# Audit pentest-toolkit.zip (versi ADE, 2026-10-15)

Original TIDAK diubah. Upgrade dibangun di folder ini sebagai salinan kerja.

## Yang sudah bagus (dipertahankan)
- 100% Python stdlib, tanpa dependensi tool luar (nmap/nuclei/dll) — sesuai niat desain ADE.
- Pemisahan passive (observasi) vs active (intrusif) + profil bertingkat.
- Finding sudah membawa severity, CWE, OWASP, CVSS, remediasi.
- SQLi error-based lama sudah pakai pola verifikasi `'` rusak / `''` pulih, dan XSS pakai marker unik.
- Login + SQLite history + export DOCX/HTML + live process log.

## Bug terkonfirmasi (bukti, bukan tebakan)
1. `report.py:42` memakai variabel `sev` yang tidak pernah didefinisikan → export HTML
   **selalu crash** `NameError: name 'sev' is not defined` (direproduksi 2026-10-15).
2. Dashboard detail scan rusak: `viewScanDetail()` di `templates/app.html` memanggil
   `renderFindings()` tanpa menyertakan `d.findings` dari API → `j.findings` undefined → halaman detail error.
3. `MARKER` di `vulnscan2.py` dibuat sekali saat import modul, bukan per-scan —
   semua scan dalam satu proses server berbagi marker yang sama.
4. `store.verify_user` membandingkan hash dengan `==` (bukan `hmac.compare_digest`) dan
   tidak ada rate-limit login → brute-force password bebas.
5. Tidak ada tombol/stop untuk job berjalan; `JOBS` tidak pernah dibersihkan; tidak ada timeout job.

## Kelemahan akurasi (false positive / false negative)
- **File sensitif**: hanya cek `status==200` + tidak ada kata "not found" di 60 byte pertama.
  SPA/catch-all yang selalu 200 akan menghasilkan banyak FP; file asli yang halamannya
  mengandung "not found" di awal akan lolos (FN). Tidak ada *content signature* per file
  dan tidak ada baseline soft-404.
- **SQLi**: hanya error-based dengan syarat kaku (harus HTTP 500 + `''` harus 200 persis).
  Boolean-based & time-based tidak diuji sama sekali → mayoritas SQLi nyata tidak terdeteksi.
  Setelah 1 SQLi ditemukan fungsi langsung `return` → parameter lain dan XSS tidak pernah diuji.
- **XSS**: 1 payload saja, tanpa variasi konteks (attribute/JS/single-quote).
- **Discovery**: `discover_paths()` hanya membaca `href/action/src="..."` (double-quote saja),
  maks 14 path, sisanya tebakan hardcoded yang tidak diverifikasi keberadaannya —
  injection diuji ke endpoint yang sering tidak ada.
- **CORS**: hanya diuji ke path `/api` yang mungkin tidak ada.
- **Cookie**: `Set-Cookie` dibaca sebagai satu string gabungan; cookie ke-2 dst tidak dianalisis per-cookie,
  flag `SameSite` tidak dicek.
- **TLS**: loop deteksi legacy protocol di `scanners.ssl_audit` cacat (ada loop mati),
  tidak ada cek cipher bits, hostname mismatch, self-signed, atau masa berlaku `not_before`.
- **Port scan**: banner grabbing hanya `recv()` pasif tanpa mengirim probe —
  service yang menunggu request (HTTP dll) banner-nya selalu kosong.
- **CVE probes**: daftar sangat kecil + hanya berdasar `status==200` → rawan FP, tanpa
  pencocokan produk/versi sama sekali.
- **Dedup finding hanya berdasar judul** → kerentanan yang sama di parameter berbeda hilang.

## Coverage yang hilang sama sekali (ditambahkan di upgrade)
SSTI, path traversal/LFI, command injection (echo + time), CRLF injection, SSRF
(cloud metadata + internal-fetch oracle), GraphQL introspection, Swagger/OpenAPI exposure,
CSRF (form POST tanpa token), JWT analysis (alg=none, secret lemah via wordlist kecil,
tanpa exp), weak CSP/HSTS quality, technology fingerprinting + kandidat CVE berbasis versi
(dilabeli *candidate*, bukan klaim terkonfirmasi), unauthenticated service APIs
(Docker 2375, Elasticsearch 9200, kubelet 10250), port/service tambahan, soft-404 baseline,
confidence level per finding (confirmed/probable/candidate), lokasi+parameter per finding,
crawler beneran (form, JS endpoint, robots/sitemap), authenticated scan (custom header/cookie),
stop/cancel scan, authorization gate + allowlist opsional, diff antar-scan, export JSON/CSV.
