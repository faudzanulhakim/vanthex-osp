# 🛡️ VANTHEX v3.2 Enterprise — Self-Built, Zero 3rd-Party Tools

Tool pentesting yang **dibangun sendiri 100% dari Python standard library** —
tidak ada nmap/gobuster/nikto/dependensi eksternal apapun. Versi 3.1 adalah upgrade dari toolkit v2 ADE: engine ditulis ulang akurasinya,
coverage diperluas ke spektrum penuh LOW→CRITICAL (OWASP Top 10 + API Top 10),
dashboard dilengkapi panel Coverage OWASP & Risk Score. Detail: `AUDIT.md`,
`UPGRADE_NOTES.md`, `ENTERPRISE_NOTES.md` (matriks coverage enterprise).

> ⚠️ **AUTHORIZED TESTING ONLY** — hanya untuk sistem yang Anda punya izin resmi
> (CTF, lab, aset kantor dengan scope jelas). Scan aktif dari dashboard **wajib**
> mencentang pernyataan otorisasi (server menolak tanpa itu).

## Menjalankan

```bash
cd pentest-toolkit-upgraded
python3 app2.py            # default port 5000
PTK_ADMIN_PW="PasswordKuat" python3 app2.py 5000
```

Login default: `admin` / `changeme123` (ganti via `PTK_ADMIN_PW` saat DB pertama dibuat).

## Profil scan

| Profil | Sifat | Isi |
|---|---|---|
| `passive-quick` | Pasif | Version disclosure, security headers, TLS |
| `passive-full` | Pasif | + fingerprint teknologi, cookie per-item, CORS |
| `active-standard` | Aktif | + file sensitif (signature-verified), directory listing, admin panel, HTTP methods/TRACE, open redirect, CSRF form, JWT, API exposure |
| `active-deep` | Aktif | + port & service API, injection suite (SQLi/XSS/SSTI/LFI/CMDi/XXE/LDAP/NoSQL), CRLF, SSRF, IDOR, kandidat CVE |
| `enterprise-full` | Aktif penuh | + kredensial default, uji rate-limit login, subdomain takeover, SPF/DMARC — 41 check, hanya dengan scope tertulis |

## Akurasi — cara v3 menekan false positive
- **Baseline soft-404** per target + **content signature** wajib untuk file sensitif/API docs/actuator.
- SQLi dibuktikan 3 cara (error vs baseline, boolean TRUE/FALSE, time 2x konfirmasi).
- Setiap finding punya **confidence**: `confirmed` / `probable` / `candidate` (kandidat CVE selalu candidate).
- Marker injeksi **unik per scan**; command injection anti-refleksi (payload terpantul ≠ eksekusi).

## Tool lain di dashboard
Port Scan (dengan banner probe), Subdomain Enum, Dir Discovery, SSL Audit, Header Audit —
semua tersimpan di riwayat, bisa diekspor.

## Fitur dashboard v3
Live log + **tombol Stop**, riwayat dengan cari/filter risk, detail temuan dengan filter &
badge confidence/lokasi, **Diff vs scan sebelumnya**, export **DOCX / HTML / JSON / CSV**,
scan terautentikasi (cookie/header, tidak disimpan), opsi timeout/crawl/proxy per scan.

## Proxy egress
Bila jaringan mewajibkan proxy, isi field Proxy di opsi lanjutan, set `PTK_PROXY`,
atau biarkan mengikuti env `HTTP_PROXY/HTTPS_PROXY` (NO_PROXY dihormati).
Catatan: port-scan & audit TLS memakai socket langsung — di jaringan ber-proxy bagian itu bisa kosong.

## Env opsional
- `PTK_ADMIN_PW` — password admin awal.
- `PTK_ALLOWED_TARGETS="example.com,*.example.com"` — allowlist host (scan di luar daftar ditolak 403).
- `PTK_PROXY="http://user:pass@proxy:8080"` — proxy egress default.
- `PTK_COOKIE_SECURE=1` — cookie session diberi flag Secure (untuk deployment HTTPS).

## Test
```bash
python3 tests/test_smoke.py   # fixture rentan lokal + uji anti-FP mode SPA + regresi report/store
```

## Struktur
```
app2.py           server + API + auth + authorization gate + job manager (bisa di-cancel)
vulnscan2.py      engine vuln scan v3 (profil passive/active, 20 check)
netclient.py      HTTP client: header list utuh, gzip, proxy env, timing per request
crawler.py        crawler: link/form/JS endpoint/robots/sitemap
scanners.py       TCP port scan + banner probe, TLS audit, header audit, DNS
store.py          SQLite layer (scans, findings +confidence/lokasi, users) + diff
report.py         laporan HTML  ·  docx_report.py  laporan DOCX (OOXML self-built)
templates/        UI (login.html, app.html)
tests/            fixture target rentan + smoke test
```
