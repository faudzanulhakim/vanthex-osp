# UPGRADE NOTES — Pentest Toolkit v2 → v3 (2026-10-15)

Paket ini adalah salinan upgrade; **file original ADE tidak diubah**.
Prinsip desain dipertahankan penuh: **100% Python standard library, tanpa tool luar**
(nmap/nuclei/dll tetap tidak dipakai — semua check hasil build sendiri).

## Bug yang diperbaiki (terbukti, lihat AUDIT.md)
1. Export laporan **HTML selalu crash** (`NameError: sev` di `report.py`) → diperbaiki + kini menampilkan confidence & lokasi.
2. **Halaman detail scan di dashboard rusak** (findings tidak diteruskan ke renderer) → diperbaiki.
3. Marker XSS/SQLi dulu dibuat **sekali per proses server** → sekarang **unik per scan**.
4. Perbandingan hash password `==` → `hmac.compare_digest` + pbkdf2 dummy untuk user tak dikenal.
5. Crawl terbatas (pasif) dulu **mengunci** crawl penuh di scan yang sama → cache dibedakan per kedalaman crawl.
6. Deteksi legacy TLS di `ssl_audit` ditulis ulang (loop mati dibuang) + verifikasi sertifikat standar, cipher bits, SAN, `not_before`.

## Akurasi (false positive / false negative)
- **Baseline soft-404 per target**: satu request acak yang pasti tidak ada menjadi pembanding;
  semua check penemuan path (file sensitif, admin panel, API docs, actuator, phpMyAdmin) wajib lolos filter ini.
- **File sensitif wajib lolos content signature** per jenis file (mis. `.env` harus memuat pola `KEY=value`/`DB_*`,
  `.git/HEAD` harus `ref: refs/`, dump SQL harus `CREATE TABLE/INSERT INTO`, dst.) — status 200 saja tidak cukup lagi.
  Terverifikasi: fixture SPA catch-all-200 menghasilkan **0** temuan file sensitif.
- **SQLi 3 lapis**: error-based (signature DB diperluas, dibandingkan ke baseline) → boolean-based
  (pasangan TRUE/FALSE diukur kemiripan bodinya) → time-based (delay >=2,6 dtk, dikonfirmasi 2x, maks 3 parameter).
  Temuan di satu parameter **tidak lagi menghentikan** pengujian parameter/teknik lain.
- **XSS multi-konteks** (4 payload: double-quote, single-quote, bare, img) — wajib terpantul *utuh*.
- **Command injection anti-refleksi**: marker harus muncul **tanpa** payload ikut terpantul
  (refleksi verbatim = bukan eksekusi; ini menekan FP di parameter yang memang reflective).
- **CORS** diuji di root + endpoint API hasil crawl, termasuk origin `null` + credentials dan wildcard+credentials.
- **Cookie dianalisis per-item** (dulu satu string gabungan): Secure/HttpOnly/SameSite per cookie.
- **Dedup per (judul + lokasi + parameter)** — kerentanan sama di parameter berbeda tidak lagi hilang.
- **Confidence per finding**: `confirmed` (lolos verifikasi otomatis) / `probable` (indikasi kuat) /
  `candidate` (dugaan berbasis versi — kandidat CVE **selalu** candidate, tidak pernah diklaim terkonfirmasi).
- **Dukungan proxy egress** (`netclient.py`): menghormati env `HTTP_PROXY/HTTPS_PROXY/NO_PROXY`, field Proxy di UI,
  atau env `PTK_PROXY`. Di jaringan yang egress-nya wajib proxy (termasuk VM Muse ini), v2 buta total ke target
  internet; v3 tidak. Port-scan & audit TLS tetap koneksi langsung (dicatat di log & README).

## Coverage baru
| Area | Check baru |
|---|---|
| Injeksi | SSTI (hasil komputasi diverifikasi), Path Traversal/LFI (signature `/etc/passwd` & `win.ini`), Command Injection (echo terverifikasi + time), CRLF/Response Splitting (header suntikan terbukti) |
| SSRF | Cloud metadata `169.254.169.254` (signature) + oracle fetch internal via `127.0.0.1` (judul homepage internal) |
| API | Swagger/OpenAPI/ReDoc exposure (signature), **GraphQL introspection** (query `__schema` nyata) |
| Auth | **JWT analysis**: alg=none, HMAC secret lemah (wordlist kecil, diverifikasi kriptografis), tanpa `exp`; **CSRF**: form POST tanpa token |
| Service | Port diperluas (Docker 2375, etcd 2379, ES 9200/9300, kubelet 10250, Kibana 5601, RabbitMQ 15672, dll) + **verifikasi API tanpa autentikasi** untuk Docker/ES/etcd/kubelet; banner grabbing kini mengirim probe |
| Fingerprint | Teknologi + versi (Apache/nginx/IIS/Jetty/Tomcat/PHP/WordPress/Joomla/Drupal) → **kandidat CVE berbasis versi** + probe aktif konfirmasi khusus CVE-2021-41773 (Apache 2.4.49/2.4.50) |
| TLS | Verifikasi CA/hostname, cipher <128-bit, SAN tidak mencakup host, legacy TLS1.0/1.1 (handshake ter-pin) |
| Header | Kualitas CSP (unsafe-inline/eval/wildcard) & HSTS max-age lemah; HSTS tidak lagi dilaporkan hilang di target HTTP murni (noise) |
| Discovery | **Crawler beneran**: BFS same-host, form (action/method/input), endpoint API dari file JS, `robots.txt` Disallow, `sitemap.xml`; endpoint tebakan hanya dipakai bila terbukti hidup |

Profil: `passive-quick` (3 check), `passive-full` (6), `active-standard` (14), `active-deep` (20 check).

## Dashboard & server (app2.py v3)
- **Tool klasik hidup lagi** sebagai scan type tersendiri & tersimpan di history: Port Scan, Subdomain Enum,
  Dir Discovery, SSL Audit, Header Audit (di v2 hanya vulnscan yang bisa jalan dari UI).
- **Tombol Stop** untuk job berjalan (engine berhenti rapi antar-check & antar-parameter), job selesai dibersihkan berkala.
- **Authorization gate**: scan aktif ditolak server (HTTP 400) tanpa `authorized=true` dari checkbox otorisasi di UI.
  Allowlist host opsional via env `PTK_ALLOWED_TARGETS` (host persis / `*.domain` / suffix domain).
- **Login rate-limit** per IP (5 gagal/5 menit → kunci 60 detik, HTTP 429).
- **Scan terautentikasi**: cookie session + header ekstra (mis. `Authorization: Bearer`) dari UI — tidak disimpan di DB.
- Opsi per scan: timeout, maks halaman crawl, proxy.
- **Export temuan JSON & CSV** per scan; **Diff antar-scan** (baru / resolved / tetap) vs scan sebelumnya target+profil sama.
- Dashboard: kartu target unik, findings by confidence, filter temuan di detail, cari + filter risk di history,
  badge confidence & lokasi/parameter di setiap finding.
- DB lama v2 **tetap bisa dibuka**: kolom `confidence/location/param` ditambahkan otomatis (migrasi ALTER).

## Verifikasi (bukti, 2026-10-15)
- `tests/test_smoke.py` — fixture target rentan lokal (`tests/fixture_vuln_server.py`):
  active-deep menemukan **37 temuan** termasuk SQLi error/time, XSS, SSTI, LFI, CMDi (echo terverifikasi di /ping),
  open redirect, CORS, CSRF, JWT secret lemah `'secret'`, GraphQL introspection, OpenAPI, file sensitif
  signature-verified, kandidat CVE-2021-41773. Fixture SPA: **0 FP file sensitif**. Semua assertion LULUS.
- E2E app: login salah 401 / benar 200, gate otorisasi 400, job passive selesai, report HTML 200
  (dulu crash), DOCX valid (PK), export CSV 200, diff 200, tool Headers jalan, **cancel → status cancelled**.
- Target nyata in-scope ADE (`http://demo.testfire.net`, passive-full, via proxy):
  **8 temuan confirmed** — CSP & X-Frame-Options hilang (konsisten dengan temuan nikto 2026-10-15),
  `Server: Apache-Coyote/1.1` disclosure, cookie `JSESSIONID` tanpa SameSite, dll.
  (v2/v3-tanpa-proxy di VM ini: hanya 1 temuan INFO karena koneksi langsung ditolak egress.)

## Batasan yang jujur
- Time-based checks dibatasi jumlah parameternya agar scan tidak meledak waktunya; SQLi di parameter ke-15+ bisa terlewat.
- Kandidat CVE hanya dari versi ter-fingerprint — patch level (backport distro) tidak terlihat dari versi saja.
- Port-scan/TLS lewat socket langsung: di jaringan ber-proxy wajib, bagian itu bisa kosong padahal web check normal —
  log scan menyatakan ini secara eksplisit.
- SSRF tanpa OOB server: yang dilaporkan hanya yang terbukti (metadata signature / oracle fetch internal);
  SSRF buta (blind) tidak dapat dikonfirmasi tanpa listener kolaborator.

## Addendum v3.1 — Enterprise (2026-10-15)
Lapisan enterprise ditambahkan di atas v3 tanpa mengubah prinsip akurasinya:
profil `enterprise-full` (34 check), coverage XXE/LDAP/NoSQL, IDOR/BOLA, upload
unauth terkonfirmasi, kredensial default Basic Auth, uji rate-limit login,
API bocorkan PII, library JS usang + source map, SRI/session-di-URL, verbose error,
deserialization surface, SPF/DMARC via DNS-over-HTTPS, subdomain takeover,
Risk Score 0–100 per scan, dan panel Coverage OWASP di dashboard.
Matriks lengkap + daftar yang jujur tidak dicakup: lihat `ENTERPRISE_NOTES.md`.
Verifikasi: fixture lokal enterprise-full = 64 temuan (34/34 check), SPA tetap 0 FP
file sensitif; E2E dashboard lulus; passive testfire.net 8 temuan, risk score 26,
cek email tidak salah menuduh (SPF/DMARC testfire.net sehat).

## Addendum v3.2 — Standar Perusahaan (2026-10-15)
Dashboard diperluas menjadi platform manajemen kerentanan (Findings+triage, Assets,
Schedules dengan scheduler server, Audit Log, Users, bulk scan, rescan, posture score,
donut & tren SVG). Engine 41 check (WAF, DOM XSS, UNION SQLi, statistik anti-FP,
cache/reset poisoning, session fixation, WP plugin enum, source disclosure,
verification pass, peringatan WAF/rate-limit). Laporan DOCX/HTML distandarkan ke
format pentest profesional (Document Control, Methodology, F-ID, Roadmap, Appendix;
env PTK_COMPANY untuk nama perusahaan). Detail: ENTERPRISE_NOTES.md.
