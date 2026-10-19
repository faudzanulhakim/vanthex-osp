# ENTERPRISE NOTES — Pentest Toolkit v3.2 (2026-10-15)

Lapisan enterprise di atas v3: coverage diperluas ke seluruh spektrum severity
**LOW → CRITICAL** dan dipetakan ke **OWASP Top 10 2021 + API Security Top 10**,
dengan profil baru **`enterprise-full`** (34 check) dan **Risk Score 0–100** di dashboard.
Prinsip akurasi v3 tidak berubah: verifikasi berlapis dulu, klaim kemudian —
confidence `confirmed / probable / candidate` di setiap finding.

## Matriks coverage (check → OWASP → rentang severity)

| Area | Check | OWASP | Severity |
|---|---|---|---|
| SQL Injection (error/boolean/time) | `c_web_injection` | A03 Injection | CRITICAL |
| XSS reflected multi-konteks | `c_web_injection` | A03 | HIGH |
| SSTI | `c_web_injection` | A03 | CRITICAL |
| Command Injection (echo/time) | `c_web_injection` | A03 | CRITICAL |
| Path Traversal / LFI | `c_web_injection` | A01 | CRITICAL |
| **XXE** (entitas ter-expand, signature passwd) | `c_web_injection` | A05 | CRITICAL |
| **LDAP Injection** (signature error LDAP) | `c_web_injection` | A03 | HIGH (probable) |
| **NoSQL Injection** (operator $gt/$ne, param + API JSON) | `c_web_injection`, `c_nosql_api` | A03 / API8 | HIGH |
| CRLF / Response Splitting | `c_crlf_injection` | A03 | HIGH |
| SSRF (metadata cloud + oracle internal) | `c_ssrf` | A10 | CRITICAL–HIGH |
| **IDOR / BOLA** (objek tetangga tanpa auth) | `c_broken_access_idor` | A01 / API1 | HIGH (probable) |
| **Upload tanpa autentikasi** (probe benign ter-serve kembali) | `c_upload_surface` | A01 | HIGH confirmed / MEDIUM form |
| **Kredensial default Basic Auth** (8 pasangan umum) | `c_default_credentials` | A07 | CRITICAL |
| **Login tanpa rate-limit** (6x gagal, user tak terdaftar) | `c_rate_limit_login` | A07 | MEDIUM (probable) |
| JWT (alg=none, secret lemah kriptografis, tanpa exp) | `c_jwt_analysis` | A07 | CRITICAL–MEDIUM |
| Login via HTTP polos, session di URL, autocomplete | `c_auth_surface`, `c_sri_and_session` | A02/A07 | HIGH–LOW |
| File sensitif & arsip backup (signature wajib) | `c_sensitive_files` | A05 | CRITICAL–LOW |
| Directory listing, admin panel, actuator | `c_directory_listing`, `c_admin_panels`, `c_cve_candidates` | A05 | HIGH–MEDIUM |
| Verbose error / stack trace | `c_error_disclosure` | A05 | MEDIUM (probable) |
| Security headers + kualitas CSP/HSTS | `c_security_headers` | A05/A02 | MEDIUM–LOW |
| Cookie per-item (Secure/HttpOnly/SameSite) | `c_cookie_security` | A05 | MEDIUM–LOW |
| CORS (echo origin, null+credentials, wildcard+credentials) | `c_cors` | A05 | HIGH–MEDIUM |
| HTTP methods, TRACE/XST, **WebDAV PROPFIND** | `c_http_methods` | A05 | MEDIUM |
| Open Redirect | `c_open_redirect` | A01 | HIGH |
| CSRF (form POST tanpa token) | `c_csrf_forms` | A01 | MEDIUM (probable) |
| GraphQL introspection, Swagger/OpenAPI exposure | `c_api_exposure` | A05 | HIGH–MEDIUM |
| **API bocorkan field sensitif/PII tanpa auth** | `c_api_sensitive_data` | API3 | HIGH–MEDIUM |
| TLS (verify, legacy 1.0/1.1, cipher <128, SAN, expiry) | `c_tls` | A02 | CRITICAL–MEDIUM |
| Port & service berisiko + API service tanpa auth | `c_services` | A05 | CRITICAL–LOW |
| Fingerprint teknologi + kandidat CVE versi | `c_tech_fingerprint`, `c_cve_candidates` | A06 | CRITICAL–INFO (candidate) |
| **Library JS usang** (jQuery/Bootstrap/AngularJS/Lodash) | `c_js_libraries` | A06 | MEDIUM (candidate) |
| **Source map ter-expose** (sourcesContent) | `c_js_libraries` | A05 | HIGH |
| **SRI hilang / mixed content** | `c_sri_and_session` | A08/A02 | MEDIUM–LOW |
| **Data terserialisasi** (Java/PHP/ViewState) | `c_deserialization_surface` | A08 | LOW (candidate) |
| **SPF/DMARC domain** (via DNS-over-HTTPS) | `c_email_security` | A07 | MEDIUM–LOW |
| **Subdomain takeover** (CNAME yatim + signature layanan) | `c_subdomain_takeover` | A05 | HIGH (probable) |
| security.txt absen, robots.txt bocorkan path | `c_security_txt_robots` | A05 | INFO–LOW |
| Host-header injection | `c_host_header` | A05 | MEDIUM |

## Profil
- `passive-quick` 3 check · `passive-full` 7 check (termasuk postur email domain)
- `active-standard` 22 check · `active-deep` 27 check
- **`enterprise-full` 34 check** — semua di atas + kredensial default, uji rate-limit login,
  subdomain takeover. Paling intrusif: gunakan hanya dengan scope tertulis.

## Risk Score
Skor 0–100 per scan = Σ(bobot severity × faktor confidence), ditampilkan sebagai
badge di hasil scan & detail, dan tersimpan bersama scan. Dashboard kini juga
menampilkan panel **Coverage OWASP** (agregasi semua temuan per kategori OWASP).

## Verifikasi v3.1 (2026-10-15)
- Smoke test fixture lokal: **enterprise-full menemukan 64 temuan, 34/34 check jalan,
  risk score 100/100** — semua kategori baru tertangkap (XXE, IDOR, NoSQL API,
  kredensial default `tomcat:tomcat`, upload unauth terkonfirmasi, rate-limit absen,
  error disclosure, jQuery 1.11.1, source map, session-di-URL, login-via-HTTP,
  API bocorkan `password_hash`, deserialization surface, SRI, robots, security.txt).
  Fixture SPA catch-all tetap **0 false positive** file sensitif.
- E2E dashboard: gate otorisasi enterprise 400 tanpa centang; job enterprise selesai
  28,6 dtk; risk score tersimpan & tampil di detail; statistik OWASP teragregasi (13 kategori).
- Target nyata in-scope (`demo.testfire.net`, passive-full): 8 temuan confirmed,
  risk score 26/100 — dan cek email **benar tidak menuduh** testfire.net:
  SPF/DMARC-nya memang terpasang sehat (DMARC `p=reject` terverifikasi via DoH).

## Yang jujur TIDAK dicakup (dan kenapa)
- **Blind SSRF / blind SQLi out-of-band** penuh butuh listener kolaborator (OOB) — belum ada;
  yang dilaporkan hanya yang terbukti in-band.
- **Stored XSS & IDOR antar-akun definitif** butuh dua akun uji + alur stateful per aplikasi;
  toolkit memberi indikator probable, verifikasi manual tetap wajib.
- **HTTP request smuggling** sengaja tidak diuji otomatis (risiko mengganggu backend bersama, FP tinggi).
- **Active Directory / jaringan internal Windows** di luar jangkauan tool web ini
  (itu ranah lab bugbounty ADE yang berbasis tool eksternal).
- Cek email menilai domain organisasi hasil heuristik sufiks (bukan PSL penuh).

## Addendum v3.2 — Standar Perusahaan Besar (2026-10-15)
- **Engine 41 check**: + deteksi WAF (konteks akurasi), DOM XSS (analisis statis source→sink
  di file JS), SQLi UNION-based (hitung kolom), time-based statistik (median 3 baseline +
  penjaga baseline tidak stabil anti-FP), SSRF skema file://, Web Cache Poisoning
  (urutan baseline→racun→verifikasi), Password Reset Poisoning, Session Fixation,
  enumerasi plugin WordPress (readme Stable tag → ambang CVE), source/backup disclosure
  per halaman, dan **verification pass** (temuan exposure Confirmed diminta ulang;
  yang tak tereproduksi diturunkan ke Probable) + peringatan kesehatan scan
  (rasio blokir 403/429 > 20% = hasil mungkin tertekan WAF).
- **Platform**: triage temuan (Open/Confirmed/False Positive/Fixed), Assets per target
  (risk & skor terbaru, temuan terbuka), **scan terjadwal** (scheduler server), audit log
  aktivitas, manajemen user dari UI, bulk scan multi-target, tombol Rescan, dashboard
  dengan Posture Score, donut severity, tren 14 hari, top targets & feed temuan terbaru.
- **Laporan standar pentest profesional** (DOCX & HTML selaras): cover + klasifikasi
  CONFIDENTIAL — TLP:AMBER, Report ID `RPT-<tanggal>-<id>`, Document Control, Executive
  Summary, Scope & Methodology (OWASP WSTG/ASVS, PTES, CVSS v3.1, model confidence,
  keterbatasan), Findings Summary & Detail ber-ID F-001…, Remediation Roadmap P1–P4
  ber-SLA, Appendix Risk Rating Methodology & Assessment Metadata. Nama perusahaan di
  laporan dapat diatur via env `PTK_COMPANY`.
- Verifikasi v3.2: smoke fixture **41/41 check, 76 temuan** (kategori baru: UNION SQLi,
  DOM XSS, WP File Manager 6.8, source disclosure, reset poisoning, session fixation,
  cache poisoning; WAF *tidak* FP di fixture bersih), SPA tetap 0 FP file sensitif;
  E2E dashboard penuh (triage status, assets, statistik tren/posture, audit, users,
  scheduler mengeksekusi scan berkala sungguhan, DOCX 12 elemen struktur terverifikasi);
  passive testfire.net tetap 8 temuan, skor 26, tanpa peringatan blokir.

## Hotfix v3.2.1 — False Positive Massal Command Injection (2026-10-15)
Kasus nyata yang dilaporkan ADE dari aplikasi UAT internalnya (SPA): puluhan
"Command Injection terverifikasi" CRITICAL pada lokasi/nama param berupa
fragmen JavaScript minified (`appendChild`, `createElement`, `SRC_ELEMENT_ATT_REGEX`).
Akar masalah ganda:
1. Crawler meng-crawl file `.js` sebagai halaman HTML lalu mengurai regex link
   dari kode minified -> URL & parameter sampah dari fragmen kode.
2. SPA menjawab semua path dengan shell yang sama + memantulkan request URI
   dalam bentuk URL-encoded; uji anti-refleksi CMDi yang membandingkan payload
   verbatim terkecoh (marker lolos, payload utuh tidak cocok string).
Perbaikan:
- File `.js/.css/.map` tidak pernah di-crawl sebagai halaman; respons ber-content-type
  JavaScript/CSS tidak diekstrak link/param-nya.
- Validasi kewarasan target parameter: charset path ketat (tanpa kurung/kutip/spasi/
  backslash), nama param harus identifier wajar, path aset statis ditolak.
- Gate catch-all di suite injeksi: parameter yang responsnya identik dengan shell
  soft-404 dan tidak terpengaruh nilai acak dilewati seluruhnya.
- CMDi kini mengutamakan bukti komputasi `$((a*b))` (hasil tidak ada di request —
  mustahil dipalsukan refleksi), dan anti-refleksi memeriksa bentuk ternormalisasi
  (URL-decoded + HTML-unescaped).
Regresi: fixture dilengkapi perangkap yang mereplikasi pola persis ini (bundle JS
dengan trap `src=` + catch-all /static/* yang meng-echo URI encoded); smoke test
memastikan tidak ada temuan dari fragmen JS dan semua kategori sah tetap terdeteksi
(41/41 check). Temuan lama dari scan yang terdampak harus dianggap TIDAK valid:
hapus scan tersebut atau tandai False Positive, lalu Rescan dengan v3.2.1.

## v3.2.2 — Akurasi Port Scan (insiden FP #2, 2026-10-16)

Kejadian: vulnscan enterprise-full dari VM Muse ke aplikasi UAT (SPA) melaporkan
27 temuan port CRITICAL/HIGH "confirmed" (Telnet, Redis, MongoDB, Docker API,
SMB, RDP, VNC, PostgreSQL, MySQL, ...) — SEMUA false positive. Ground truth
pemilik (nmap dari Kali + docker ps): dari internet hanya 443 & 8008 open.

Akar masalah: koneksi TCP langsung dari VM Muse dicegat gateway sandbox
runtime — connect ke port berapa pun "berhasil" dan dibalas banner teks
"muse: ... connections is turned off for this assistant ...". Koneksi tidak
pernah mencapai target. Scanner lama memperlakukan connect+banner apa pun
sebagai bukti layanan (teks gateway itu bahkan tersimpan sebagai evidence).

Perbaikan:
- Probe verifikasi protokol per layanan di scanners.py: klaim layanan WAJIB
  lolos signature asli (SSH "SSH-", VNC "RFB", Redis PING->+PONG/-NOAUTH,
  PostgreSQL SSLRequest->S/N, MySQL greeting, RDP X.224, MSSQL TDS prelogin,
  MongoDB teks identitas, LDAP bind, NFS RPC, PPTP magic cookie, TLS handshake,
  HTTP "HTTP/" termasuk fallback port non-standar).
- Connect saja -> verified=False: port berisiko tak terverifikasi hanya jadi
  SATU temuan kandidat LOW berkelompok, tidak pernah confirmed per layanan.
- Deteksi interceptor: banner gateway yang dikenal ATAU banner identik di
  >=60% port terbuka tanpa satu pun terverifikasi -> seluruh port scan
  dinyatakan TIDAK KONKLUSIF (1 temuan INFO), nol temuan port.
- Probe HTTP API tanpa autentikasi (Docker/ES/etcd/kubelet) kini hanya jalan
  untuk port yang terverifikasi HTTP.
- Scan tipe "ports" menyertakan flag intercepted + daftar terverifikasi.

Verifikasi: unit test 24/24 (signature, probe, interceptor, integrasi server
protokol lokal); smoke fixture SEMUA LULUS (41/41 check); live dari VM yang
sama ke target yang sama: portscan API -> intercepted=True, 0 terverifikasi;
vulnscan active-deep -> 0 temuan port, tepat 1 INFO tidak-konklusif; fixture
localhost port 8899 -> HTTP terverifikasi, port tertutup absen. 27 temuan FP
scan lama ditandai false_positive di instance terpasang (sisa 1 INFO TLS yang
jujur tetap open).

Aturan permanen: port scan hanya sah dari vantage point tanpa interceptor;
dari VM Muse hasilnya selalu tidak konklusif — dan kini scanner mengatakannya
sendiri, bukan mengarang temuan.

## v3.3.0 — Mobile Apps (APK) + Library Modern (2026-10-16)

Keputusan pemilik (2026-10-16): TETAP tanpa tool scanner jadi (nmap/nuclei
tidak dipanggil) — engine hasil build sendiri — tetapi library pihak ketiga
yang lazim dipakai membangun aplikasi pentest LAIN kini dipakai sebagai bahan
baku (sebelumnya murni stdlib). Venv proyek di .venv (requirements.txt):
androguard 4.1.4, requests, beautifulsoup4, lxml, cryptography, dnspython.

Baru:
- mobile.py — analyzer statis APK buatan sendiri (pemetaan OWASP MASVS):
  debuggable, allowBackup (+default target<=30), cleartext (precedence:
  network security config > atribut manifest > default target<28), permission
  dangerous (grup, severity dari yang tersensitif), komponen exported tanpa
  proteksi (aturan default per targetSdk; launcher dikecualikan), deep link
  http, secrets tertanam (AWS key, Google API key, private key, JWT — probable,
  evidence ter-masking; pola generik = candidate), URL Firebase, endpoint HTTP,
  indikasi addJavascriptInterface/ECB (candidate), sertifikat (tidak
  ditandatangani, debug cert, kedaluwarsa, hash lemah, v1-only/Janus), target/
  min SDK tertinggal. Endpoint API diekstrak dari DEX/assets (host skema/
  namespace disaring) dan dapat di-scan lanjut dari dashboard.
- Route POST /api/mobile/analyze (base64 JSON, maks 60 MB): APK dianalisis
  sebagai job, disimpan sebagai scan tipe "mobile" — temuan masuk pipeline
  Findings/triage/laporan DOCX/HTML yang sama; file APK dihapus setelah
  analisis (yang disimpan hash SHA-256 + hasil).
- Dashboard service: tab Mobile Apps (upload, log live, profil aplikasi,
  chips permission, tabel endpoint + tombol "Scan API ini", riwayat, detail
  khusus mobile di Scan Detail; ikon rescan disembunyikan untuk scan mobile).
- Crawler web: ekstraksi link/form kini memakai parser HTML asli
  (BeautifulSoup) bila tersedia — teks <script>/<style>/komentar tidak bisa
  lagi terbaca sebagai atribut (menekan kelas FP insiden #1); regex lama jadi
  fallback identik v3.2.2.

Verifikasi: tests/test_mobile.py 24/24 (fixture APK resmi repo androguard
dengan ground truth terverifikasi independen: TestActivity debuggable,
a2dp.Vol permission/receive-SMS/backup/endpoint, APK repack bermarker AWS/
Firebase, unit aturan exported sintetis; bug nyata ditemukan & diperbaiki
selama pengujian: regex URL melebur string DEX bertetangga lewat \x00 —
charset kini dibatasi printable). Smoke web SEMUA LULUS (41/41, anti-FP SPA
utuh) dengan crawler bs4 aktif; port-verify 24/24 tetap lulus. E2E live
service (venv): analisis a2dp 9 temuan HIGH score 53, TestActivity debuggable
tertangkap, detail+meta tersimpan, laporan HTML CONFIDENTIAL & DOCX valid
untuk scan mobile, log service bersih dari debug androguard.

Batas jujur: analisis mobile bersifat STATIS. Uji runtime/dinamis (Frida,
interception dari perangkat/emulator) tidak termasuk dan tidak diklaim.

### Addendum v3.3.0 — tooling build (2026-10-16)
Atas permintaan pemilik ditambahkan ke build: pytest 9.1.1, coverage 7.16.2,
hypothesis 6.170.0, defusedxml 0.7.1, psutil 7.2.2 (requirements.txt).
- defusedxml dipakai beneran: manifest & XML tak tepercaya dari APK diparse
  dengan defusedxml (anti XXE/billion-laughs terhadap analyzer itu sendiri).
- psutil dipakai beneran: /api/stats kini memuat blok "system" (uptime app,
  memori proses, CPU & memori host, jumlah job aktif) untuk dashboard.
- Suite test kini pytest: 16 test lulus (unit mobile 5, port-verify 4,
  property-based hypothesis 6 — invariant: matcher signature tidak pernah
  crash pada bytes acak, masking secret tidak membocorkan bagian tengah,
  banner interceptor selalu terdeteksi; wrapper smoke web 1). Coverage
  terukur (unit): mobile.py 79%, scanners.py 40% — smoke web berjalan sebagai
  subprocess sehingga baris vulnscan2/crawler yang ia latih tidak ikut
  terhitung di angka ini.

## v3.4.0 — Akurasi Terukur (Battery Ground-Truth) + Dashboard Enterprise Lanjutan
Permintaan pemilik: dashboard "industri besar" dan scanning "seakurat mungkin
tanpa miss maupun bug". Catatan kejujuran: tidak ada scanner di dunia yang bisa
menjamin NOL miss/NOL bug secara absolut — yang bisa dilakukan (dan dilakukan
di versi ini) adalah MENGUKUR akurasi dengan ground-truth terkontrol dan
memperbaiki setiap cacat yang pengukuran itu ungkap.

### Battery ground-truth (tests/test_battery.py, masuk suite pytest)
Fixture diperluas dua arah: kontrol POSITIF baru (/fetch SSRF oracle + file://,
/echohdr CRLF, refleksi X-Forwarded-Host, /admin/login, mode FIXTURE_MODE=waf
ala Cloudflare) dan kontrol NEGATIF endpoint patched /safe/* (search ter-escape,
item prepared-statement, redirect tervalidasi, fetch allowlist). Battery
menegaskan 43 kategori wajib tertangkap + nol temuan injeksi di /safe/* + WAF
terdeteksi hanya di mode waf. Tiga cacat nyata ditemukan & diperbaiki:
1. c_crlf_injection MATI TOTAL: payload dikirim sudah ter-encode (%0d%0a)
   padahal req_param meng-quote ulang -> double-encode, CRLF tidak pernah
   terkirim. Payload kini CRLF mentah. Check ini tidak pernah bisa menghasilkan
   temuan sebelum perbaikan ini.
2. param_targets memotong sumber secara tidak adil: limit diisi URL GET lebih
   dulu sehingga form POST (termasuk endpoint XML untuk XXE) tidak pernah
   teruji di situs ramai parameter. Kini gabungan round-robin antar sumber +
   budget suite injeksi 14 -> 30; limit CRLF & error-disclosure 6 -> 14.
3. Simulasi XXE fixture bersifat catch-all semua path (artefak fixture yang
   menyamarkan FP begitu endpoint patched ada) -> kini hanya endpoint /xml.
Hasil: battery hijau (71 temuan di fixture rentan, semua kategori tertangkap).
Coverage terukur jujur (in-process): vulnscan2 82%, crawler 73%, mobile 79%,
total suite 18 test pytest lulus.

### Dashboard enterprise lanjutan
- /api/insights: kepatuhan SLA remediasi (CRITICAL 7 hari, HIGH 30, MEDIUM 90,
  LOW 180 — overdue dihitung dari umur temuan & due date), MTTR per severity,
  tren risk score per aset (grafik di dashboard + badge overdue di Findings).
- Temuan: assignee + due date dapat diedit (POST /api/finding/update;
  status_changed_at dicatat untuk MTTR).
- Aset: kritikalitas (critical/high/medium/low) + owner per aset
  (POST /api/assets/meta, admin).
- Webhook: URL diatur admin (settings); scan selesai -> POST JSON bila ada
  temuan CRITICAL/HIGH BARU dibanding scan target sebelumnya (web, mobile,
  maupun terjadwal).
- API token: admin membuat token (ditampilkan sekali, disimpan sebagai hash
  SHA-256); akses programatik via Authorization: Bearer ptk_...; dapat dicabut.
Semua terverifikasi E2E live (token diterima/ditolak setelah cabut, webhook
menerima 11 temuan kritis baru dari scan fixture, MTTR terhitung, data uji
dibersihkan).

## v3.4.1 — Perbaikan FP WAF F5 + Laporan Standar Industri/HackerOne
Insiden FP ketiga (dilaporkan pemilik dari pemakaian nyata): scan aplikasi
GeneXus di balik nginx dituduh "WAF terdeteksi: F5 BIG-IP". Akar masalah
terbukti dari byte target asli: pola F5 lama r"f5" cocok dengan substring "f5"
di token hex acak GeneXus (gx_ajax_key "38ff6460ffff59ff..."). Perbaikan:
signature WAF ditulis ulang sebagai indikator KUAT per vendor, terpisah header
vs body (cookie BIGipServer/TS-ASM & header khas untuk F5; cf-ray untuk
Cloudflare; x-amzn-trace-id ALB BUKAN lagi bukti AWS WAF; nama vendor telanjang
di body dilarang), evidence kini mencatat indikator persisnya (header/snippet).
Regresi terkunci tiga lapis: tests/test_waf.py (8 test, termasuk korpus
GeneXus), jebakan token hex + nama vendor di fixture battery, dan verifikasi
matcher pada byte live target pemilik -> None (FP hilang), sementara mode waf
fixture tetap terdeteksi. Temuan FP di scan pemilik sudah ditandai
false_positive.
Laporan (report.py + docx_report.py + modul bersama report_common.py) naik ke
standar industri/platform: vektor CVSS v3.1 representatif per CWE di setiap
temuan, Langkah Reproduksi gaya HackerOne, kerangka PoC request, dampak
spesifik per kelas CWE, referensi (CWE/WSTG/FIRST), matriks risiko di
executive summary (kedua format), Document Control + riwayat versi +
distribusi, Appendix C berisi blok submisi HackerOne/Bugcrowd-ready per
temuan; DOCX kini punya header klasifikasi & footer nomor halaman (PAGE/
NUMPAGES) serta field Daftar Isi Word yang sesungguhnya. Terverifikasi:
tests/test_reports.py (struktur + validitas OOXML semua part) dan ekspor
laporan nyata dari scan pemilik dalam dua format.

## v3.5.0 — WAF perilaku (anti-tebakan) + Profiler Teknologi & Integrasi
Permintaan pemilik: (1) "WAF-nya jangan tebak-tebakan" — deteksi WAF ditulis
ulang menjadi uji PERILAKU: payload serangan (XSS/SQLi/LFI) dan kontrol jinak
dikirim ke path hantu yang pasti tidak ada di aplikasi; WAF dinyatakan
TERKONFIRMASI hanya bila >=2 kelas serangan diblokir DAN semua kontrol lolos
(bukti differential blocking). Nama vendor kini hanya "indikasi" terpisah
(prob probable) dari artefak khas vendor, tidak pernah menjadi dasar klaim
keberadaan WAF. Verdict adalah fungsi murni ter-unit-test. Fixture mode waf
disesuaikan: pola blokir spesifik (WAF asli tidak memblokir tanda baca tunggal).
(2) "Scan bisa lihat dari URL terinstall & terintegrasi aplikasi apa saja" —
modul techdb.py: database signature teknologi buatan sendiri (80+ entri)
memetakan artefak respons (header, nama cookie, HTML, src script) ke Web
Server, Runtime, Framework, CMS, E-commerce, Library/Framework JS, UI,
Analytics, Tag Manager, Chat/Support, Payment (termasuk Midtrans, Xendit,
DOKU), CAPTCHA, Auth/SSO (Keycloak, Auth0, Firebase, Supabase), Peta, Media —
tiap deteksi membawa evidence. Hasil mengalir ke temuan ringkasan INFO, field
tech_profile hasil scan, panel detail dashboard (chip per kategori + tooltip
bukti), tabel Profil Teknologi di laporan DOCX/HTML, dan tetap menjadi sumber
kandidat CVE. Aturan anti-FP berlaku juga di sini: petunjuk lemah bukan klaim
(GeneXus menuntut cookie GXSESSION / JSON "gx ajax_key" / teks GeneXus —
token hex acak saja tidak cukup).
Verifikasi: suite 38 test hijau (verdict perilaku 4 skenario, profiler 6
test, battery memuat assert profiler + nol tuduhan WAF di fixture bersih).
Bukti live pada aplikasi UAT pemilik sendiri: profiler membaca GeneXus
(bukti "GX_AJAX_KEY"), Java Servlet (cookie JSESSIONID), nginx — persis
stack aslinya; uji WAF perilaku: 0/3 serangan diblokir, 0 kontrol terblokir,
tanpa artefak vendor -> TIDAK ADA temuan WAF (diam, bukan menebak).

## v3.5.1 — Laporan format formal standar internasional
Atas penilaian pemilik ("dokumen laporannya jelek"), kedua generator ditulis
ulang tampilannya (isi & struktur data tidak berubah): gaya firma keamanan
profesional — halaman sampul resmi dengan pita klasifikasi atas/bawah dan
tabel meta, Document Control + tabel Version History terpisah, daftar isi
(anchor di HTML; field TOC Word dengan Heading1/Heading2 bernomor di DOCX),
heading seksi bernomor dengan garis navy, tabel header navy + zebra striping,
detail temuan sebagai sub-bab bernomor 4.N dengan sub-judul baku
(Description/Evidence/Langkah Reproduksi/Proof of Concept/Impact/
Remediation/References), blok evidence & PoC monospace ber-shading terang
(ramah cetak), header berjalan + footer nomor halaman, palet warna formal
yang diredam, dan TANPA emoji/dekorasi non-formal di dokumen (confidence &
status kini teks polos: Confirmed/Probable/Candidate, Open/Fixed/False
Positive). HTML siap cetak A4 dengan @page margin boxes (header/footer +
"Page X of Y", sampul tanpa nomor halaman).
QA visual nyata: laporan dari scan mobile pemilik dirender via LibreOffice —
sampul bersih formal, Document Control & Matriks Risiko rapi, 12 halaman;
tests/test_reports.py kini juga mengunci ketiadaan emoji & penanda formal.

## v3.5.2 — Tampilan web formal enterprise
Permintaan pemilik: tampilan web dirapikan menjadi resmi formal. Dashboard
service (templates/app.html + login.html) dirombak dari tema gelap
indigo/violet bergradien menjadi tema TERANG formal yang selaras dengan
bahasa desain laporan v3.5.1: latar #E9EDF2, panel putih, aksen navy
#16365C, severity diredam (#9B2226/#C05621/#975A16/#4A5568/#2B6CB0), border
#D8DEE7, radius kecil, tanpa gradien sama sekali, dan seluruh emoji pada
navigasi/kartu/tombol/label disapu bersih (logo menjadi monogram "PT" navy;
ikon severity pada kartu statistik menjadi titik tipografis berwarna).
Konsol log scan/mobile kini blok terang monospace. Halaman login: kartu
putih dengan garis atas navy, label uppercase, footer "CONFIDENTIAL —
AUTHORIZED ACCESS ONLY". Fungsi & alur tidak berubah — murni visual.
Terverifikasi live: login & dashboard tersaji dengan palet baru, nol
piktogram, nol gradien. Artifact tab chat diselaraskan builder dengan
bahasa desain yang sama.

## v3.6.0 — Detail tampilan, transparansi akurasi, hardening keamanan
1. Tampilan detail lebih kaya: halaman detail scan (dashboard + artifact)
   kini menampilkan Metadata Scan (profil, durasi, check dijalankan,
   total request HTTP, jumlah diblokir 403/429, distribusi kode status)
   dan tabel lipat "Cakupan Check" per modul.
2. Akurasi & transparansi: engine mencatat checks_detail (nama check,
   status ok/error/cancelled, jumlah temuan, durasi) ke hasil scan;
   endpoint detail mengeksposnya lewat objek engine. Battery mengunci
   kelengkapannya (41/41 tercatat, semua ok di fixture). Audit recon
   memastikan yang diduga lemah ternyata sudah kuat: SQLi time-based
   memakai median 3 sampel + konfirmasi ganda; mining endpoint JS sudah
   ter-wire (DOM XSS/discovery/API); analisis JWT terverifikasi menembak
   di fixture ("JWT HMAC secret lemah", "JWT tanpa klaim exp").
3. Keamanan aplikasi diperketat: batas ukuran body per route (413 —
   JSON 2 MB, analisis APK 100 MB) menutup celah memory-exhaustion;
   CSP ditambah frame-ancestors 'none', object-src 'none', base-uri,
   form-action; header Referrer-Policy: no-referrer dan Permissions-Policy;
   Cache-Control: no-store pada semua respons JSON API. Baseline yang
   sudah kuat dipertahankan: PBKDF2 200k + compare_digest + dummy-hash,
   cookie HttpOnly SameSite=Strict, throttle login 5x/300 dtk -> kunci
   60 dtk (429), audit login_failed. tests/test_security.py (server uji
   terisolasi) mengunci semua perilaku di atas; suite penuh 42 hijau.

## v3.7.0 — Expert depth + UI interaktif modern
Engine (43 check di enterprise-full):
- Verifikasi aktif teknologi: stack terdeteksi techdb dibuktikan via probe
  endpoint khas (WordPress /wp-json/, Drupal /jsonapi, Joomla manifest,
  Magento /magento_version) — entri tech_profile mendapat flag verified +
  evidence "terverifikasi aktif via ..." dan versi hasil ekstraksi.
- c_jwt_forgery (baru): baseline endpoint identitas menerima token asli &
  memantulkan klaim identitas; lalu dua pemalsuan diuji — alg=none dan
  re-sign dengan secret wordlist. Pantulan identitas palsu = CRITICAL
  confirmed; endpoint ketat diam (kontrol negatif battery: /api/profile).
- c_websocket_surface (baru): URL ws(s) dari crawler (HTML/JS) dibuktikan
  dengan handshake (101 + Sec-WebSocket-Accept valid); Origin asing yang
  tetap diterima -> indikasi CSWSH (probable).
- c_ssrf diperdalam: semua vektor dibuktikan per parameter (file://,
  metadata cloud, fetch internal) di hingga 6 parameter URL; perbaikan
  starvation nyata — limit dinaikkan 14 -> 40 karena /fetch?url= kelaparan
  di belakang parameter lain (akar "SSRF metadata tidak pernah menembak").
- Battery: 48 kategori wajib + kontrol negatif forgery + assert verified.
UI:
- Mode gelap on/off persisten (localStorage) di dashboard & login —
  palet navy gelap formal via variabel tema yang sama.
- Log live menjadi terminal CMD: jendela gelap, tiga titik jendela,
  judul root@pentest-toolkit, pewarnaan baris per severity/status,
  tombol Jeda/Salin, progress bar dari penanda [i/n].
- Chip filter severity yang bisa diklik di detail temuan (bersama filter teks).
Bug laten ditemukan & diperbaiki: baris cookie pada fungsi bulk scan
mengandung literal tak valid yang membuat blok script dashboard gugur
(node --check kini hijau untuk semua blok; bulk scan pulih).

## v3.8.0 — Full-stack detection from a single URL
ADE's requirement: scanning one URL must detect everything running behind
it — database, framework, API, everything.
- techdb grows 78 -> 94 signatures. New category **Database** (MySQL,
  MariaDB, PostgreSQL, Microsoft SQL Server, Oracle, SQLite, MongoDB) —
  detected ONLY from error artifacts: strong error-phrase patterns matched
  against the target's error page (soft-404 sample), never from bare names.
  A page that merely mentions "mysql/oracle/mongodb" in prose detects
  nothing (unit-tested anti-guessing rule).
- New category **Operating System** (indication from leaked paths in error
  pages: Linux /var/www..., Windows C:\xampp...).
- More frameworks: CodeIgniter (ci_session cookie), Spring Boot (Whitelabel
  Error Page), Flask/Werkzeug, FastAPI, Symfony (X-Debug-Token), ASP.NET
  WebForms/MVC (__VIEWSTATE).
- Active verification extended: Spring Boot via /actuator/health,
  FastAPI via /openapi.json (parse_verify unit-tested).
- Engine: _tech_fingerprint mines the cached soft-404 response body as the
  error sample (no extra requests beyond the existing ghost fetch).
- Battery locks it: the fixture's leaky 404 (mysqli warning + /var/www
  path) must yield Database: MySQL in tech_profile.
- Live proof (fixture, enterprise-full): Analytics GA, reCAPTCHA, WordPress
  5.8 [verified], Database MySQL, ASP.NET, jQuery 1.11.1, Linux (from error
  path), Midtrans + Stripe, Apache 2.4.49 — all from one URL.

## v3.9.0 — All features in English
Per ADE's instruction, every user-facing string in the product is now
English: dashboard UI + login, HTML/DOCX reports (incl. steps/impact/
references generated by report_common), engine finding titles/descriptions/
remediation, engine log lines, mobile (MASVS) findings, and API messages.
- Translation was value-audited: a string-constant multiset diff (old vs
  new) confirms no regex, payload, CWE/OWASP/CVSS value, profile name, or
  logic string changed. The one logic coupling — the verification pass's
  title check — moved consistently ("ter-expose" -> "exposed").
- Tests updated to the English titles (battery EXPECT map, smoke, mobile,
  techdb, reports). Full suite: 44 passed; battery 48 categories green.
- Live proof: enterprise-full fixture scan via the service = 81 findings,
  43/43 checks, zero Indonesian titles; tech profile as in v3.8.0.

## v3.10.0 — Package unpacking + iOS IPA analyzer (2026-10-16)
- Mobile: full package-contents inventory for APK and IPA (every file, DEX files
  with class counts, bundled package/SDK histogram, native libraries per ABI,
  frameworks, assets, largest files) in the scan metadata + explorer UI.
- New iOS static analyzer (analyze_ipa): Info.plist (ATS exceptions, URL
  schemes), embedded.mobileprovision (distribution type, get-task-allow,
  expiry), Mach-O header parsing (architectures, MH_PIE, LC_ENCRYPTION_INFO
  cryptid), secrets/endpoints from strings, Firebase config. App Store
  (FairPlay-encrypted) binaries are declared as a coverage limit, never
  silently scanned. /api/mobile/analyze accepts .apk/.ipa and dispatches by
  package structure. Suite: 48 tests incl. a synthetic IPA fixture with a
  FairPlay negative control.
- Also fixed leftover Indonesian strings in mobile findings/UI.

## v3.11.0 — Readable decompilation: DEX disassembly + decoded resources (2026-10-16)
- meta.decompile for APK: full class list (names + method counts), smali-style
  disassembly (opcode + operands rendered from androguard-parsed bytecode) for
  the app's own classes (package-prefix first, then non-library classes;
  caps: 40 classes, 40 methods/class, 120 instructions/method, ~520 KB text),
  decoded AndroidManifest.xml, decoded res/*.xml samples, resources.arsc
  string pool (best-effort). Library classes are listed, not disassembled.
- meta.decompile for IPA: decoded plist resources (Info.plist,
  embedded.mobileprovision, GoogleService-Info.plist) as readable JSON;
  Mach-O disassembly remains out of scope and is labeled as such in the UI.
- Dashboard gains a "Decompiled Code & Resources" viewer in mobile results.
  Suite: 50 tests.

## v3.12.0 — Full English default + interface language picker (2026-10-16)
- Default UI language is English everywhere (last Indonesian leftovers fixed).
- Settings (Users view > Preferences) gains an interface language picker:
  English, Bahasa Indonesia, Español, Français, Deutsch, Português, Русский,
  日本語, 한국어, 中文 (简体), العربية (RTL), हिन्दी — persisted in
  localStorage (ptk-lang), applied by a DOM translation layer with a curated
  100-key dictionary; the login page follows the saved preference.
- Honest scope: the picker localizes the interface chrome. Findings, engine
  logs and report content are security data generated in English and stay
  English in every language.

## v3.13.0 — PREREQ Phase 1: passive recon pack + governance hardening (2026-10-16)
- Libraries added (owner PREREQ list): packaging (precise PEP 440 version
  comparison in the outdated-library check), certifi (verified TLS for public
  API lookups), dnspython (precise DNS records), Pillow (EXIF extraction);
  dev-only: pip-audit + pip-tools. Baseline pip-audit of the shared venv:
  13 packages with advisories; the toolkit's own cryptography (48->50.0.2)
  and Pillow (10.2->12.3.0) were upgraded to fixed releases.
- New passive.py: passive-recon scan type — DNS enumeration (A/AAAA/CNAME/
  MX/NS/TXT/CAA), SPF/DMARC evaluation, wildcard detection, Certificate
  Transparency via crt.sh, RDAP (registrar/expiry), favicon fingerprint
  (SHA-256/MD5), robots/sitemap/security.txt parsing, HTML comment leakage,
  EXIF metadata incl. GPS detection, passive tech profiling — public lookups
  only, no attack traffic.
- Footprint: every finding now carries origin (passive/active); both report
  generators print an Origin attribute row per finding.
- Audit log hash-chaining (SHA-256 prev-hash chain in store.audit) with a
  verify_audit_chain() tamper check; pre-chain rows are skipped, not forged.
- Suite: 55 tests. Phase 2 (queued): active pack (UDP probes, TLS cipher
  enumeration, vhost enum, two-way validation), NVD sync, job queue/metrics.
  Phase 3 (queued): sandboxed APK/IPA parsing, encrypted secrets management,
  optional systemd supervision.

## v3.14.0 — stdlib adoption pass (owner's module list, 2026-10-16)
Audit first (grep-verified): most listed modules were already in use
(socket, ssl, http.client, urllib.parse/request, ipaddress, threading,
concurrent.futures, re, html, xml.etree via defusedxml, json, plistlib,
base64, struct, gzip, hashlib, hmac, secrets, uuid, sqlite3, csv, zipfile,
logging). Genuinely added where they do real work:
- urllib.robotparser -> structured robots rules in passive recon.
- defusedxml XML parsing for sitemap (count + samples + index), regex fallback.
- html.parser -> homepage comment/img signal extraction in passive.py.
- http.cookies.SimpleCookie -> precise Set-Cookie attribute parsing in
  c_cookie_security (presence = truthy morsel value; bare flags store True;
  substring fallback for unparseable headers). Fixes the trap where the word
  'httponly' inside a cookie VALUE masked a missing flag.
- unicodedata NFKC -> crawler URL dedupe canonicalization.
- zlib -> Content-Encoding: deflate decoding in netclient (gzip existed).
- selectors -> non-blocking mass-connect prefilter for port ranges > 120;
  full banner/signature verification still runs on candidates only.
- socketserver + threading -> canary.py blind-callback listener with a
  token registry (declared local/same-network only on this VM: no inbound
  path from the internet; NOT wired into blind checks until deployed on a
  reachable host).
- argparse -> cli.py headless CLI (passive/scan/ports/canary), JSON stdout,
  same authorization gate as the web UI.
- dataclasses/enum/typing -> model.py typed Finding/Severity/Confidence/
  Origin boundary for new code; legacy engine keeps the F() dict shape
  (lossless round-trip).
- CSV findings export gains the origin column.
Deliberately NOT adopted (no real gap): asyncio (selectors covers the
mass-connect need without rewriting the threaded engine), queue (no
producer/consumer gap), subprocess (engine rule: no external tools; it is
scheduled for Phase-3 parser sandboxing), signal (supervisor owns
lifecycle), email.mime (no SMTP configured; webhooks cover alerting),
binascii/codecs/copy/textwrap/string/random (covered by base64/secrets/
templates or no concrete need).
Suite: 63 tests.

## v3.15.0 — Users moved into Settings + full consistency re-check (2026-10-16)
- The standalone "Users" navigation entry is now "Settings": the view holds
  the Users panel (add user + role table), Preferences (interface language),
  and Integrations & API (webhook + API tokens). Internal route/ids are
  unchanged (no deep-link breakage); "Settings" and the new view subtitle
  were added to all 11 i18n dictionaries.
- Full re-check: pytest suite green; every script block of app.html and
  login.html passes node --check; API smoke covers login, engine info,
  users/settings/scans endpoints and the audit hash-chain verification.
- Audit-chain bug found by the re-check and fixed in this release: the
  v3.13 hash chain forked once under concurrent writers (two simultaneous
  login audits read the same prev hash; row 240). Writer now holds a lock
  and chains from the last hashed row; a one-time startup repair recomputed
  the linkage for all 249 stored rows from their stored fields (no log
  content altered) — verify_audit_chain() now passes on the real database,
  and a concurrency regression test (8 threads x 5 audits) guards it.

## v3.16.0 — Battery expansion (SPA + traps) and FP incident #4 fix (2026-10-16)
- The ground-truth battery grew teeth: new fixture surfaces /safe/slow
  (uniformly slow benign endpoint — timing-FP trap), /vuln/search_bool
  (pure boolean-blind SQLi, no error output), /trap/vendors (hex tokens +
  WAF vendor names as article prose), /trap/databases (DB names as article
  topics), /trap/echo_raw_json (escaped JSON reflection). SPA mode is now a
  full battery test (test_battery_spa): catch-all fixture, enterprise-full
  scan, ZERO injection-class findings required (permanent regression for
  the v3.2.0 mass-FP incident); the SPA fixture now also catch-alls POST.
- FP INCIDENT #4 (caught by the new trap before release): the JSON echo
  endpoint was accused of UNION-based SQLi and verified Reflected XSS,
  both "confirmed" — verbatim reflection inside an escaped JSON string
  fooled the differential tests. Engine fix in c_web_injection: UNION and
  boolean comparisons now run on bodies with the reflected payload stripped
  (anti-reflection normalization), and the XSS verifier skips parameters
  whose response Content-Type is JSON (escaped JSON string context is not
  HTML). Re-measured: /trap/* = 0 findings, real UNION at /union and the
  new boolean-blind positive still confirmed.
- Measured accuracy after expansion: recall 50/50 planted categories
  (49 previous + boolean-blind), 0 false positives across /safe/* (all
  classes), /trap/*, and the SPA fixture's injection surface. Suite: 65.

---

## v3.17.0 — PREREQ Phase 2: active pack, orchestration, data, performance

- **Active pack (own engine, `scanners.py`)**: UDP scan with per-protocol
  probes (DNS query / SNMPv1 GetRequest / NTP) and honest UDP semantics
  (valid response = open, ICMP unreachable = closed, silence =
  open|filtered — never "closed"); all-silent remote scans are flagged
  `ambiguous`. TLS cipher-suite enumeration (per-version handshakes,
  per-cipher attempts for TLS <= 1.2) with weak-cipher and deprecated
  protocol findings wired into the SSL audit. Virtual-host enumeration
  against a random-host baseline (status change, strong content
  difference, or content+length difference = candidate). Raw-socket SYN
  scan with hand-built IPv4/TCP packets and checksums — on hosts without
  raw capability (including this VM, where the sandbox returns EPERM on
  raw send) it reports itself unavailable and the scan is recorded as
  INCONCLUSIVE with an INFO finding, never as filtered ports.
- **Hybrid orchestration**: scan type `hybrid` runs passive recon, then an
  active-deep vulnscan, and merges the findings (dedupe by
  title+location+param) with per-finding origin preserved (passive/active)
  and the passive metadata embedded.
- **NVD sync (`nvd.py`)**: pulls CVEs from the NVD API 2.0 into a local
  SQLite cache (`cve_cache`), keyword-based, API-key optional
  (PTK_NVD_KEY). Sync runs in the background with a visible state; every
  per-keyword failure is reported. Verified from this VM: the NVD API is
  unreachable (HTTP 0 for all keywords) — the cache honestly stays empty
  here; the parser and pipeline are covered by stub-fetcher tests.
  techdb carries `SIGNATURE_DB_VERSION`; the store records
  `schema_meta.schema_version`.
- **Job queue (`jobgate.py`)**: priority queue with a global concurrency
  limit (3) and a per-user limit (2); jobs start as `queued`, high
  priority (`priority: "high"`) goes first; cancellation while queued is
  honoured. Scheduled scans keep the direct path (trusted, low volume).
  `/api/metrics` exposes the gate snapshot, NVD cache stats, audit-chain
  status and dashboard stats. The scan live-log poller now backs off
  adaptively (700 ms -> 4 s, reset on new log lines).
- **Finding suppressions**: persistent per-target rules (host + title
  substring) managed in Settings (and `/api/suppressions`); matching
  findings are removed at save time and counted transparently
  (`suppressed_count` + the suppressed titles in the result). Proven live:
  5 header findings suppressed on the fixture, 0 rules left behind.
- **Report integrity**: Document Control (HTML + DOCX) now carries a
  "Source Data SHA-256" fingerprint of the canonical scan data
  (`report_common.data_fingerprint`) so recipients can verify a report
  against the stored scan.
- Proven live on the local fixture: hybrid scan merged 82 findings with
  both origins; UDP scan produced the verified SNMP 'public' community
  HIGH finding and a DNS INFO; SYN scan declared itself inconclusive on
  this VM. Integration bugs caught by these proofs and fixed before
  release: risk_score argument (findings list, not summary), F() keyword
  names in the new branches (location/confidence), NVD response tuple
  order and header support in passive._fetch_bytes.

---

## v3.18.0 — PREREQ Phase 3: sandboxing, secrets vault, systemd (opt-in)

- **Sandboxed package parsing (`sandbox.py` + `sandbox_worker.py`)**:
  mobile analysis (APK/IPA) now runs in an isolated subprocess. The
  worker installs rlimits BEFORE importing the analyzer (RLIMIT_AS
  1536 MB, RLIMIT_CPU 150 s, RLIMIT_FSIZE 64 MB; env-tunable via
  PTK_SANDBOX_*), the parent enforces a hard timeout (default 180 s)
  and kills the process group member on expiry. Timeout/crash/OOM is
  reported as a SandboxError — there is NO silent in-process fallback.
  Successful results carry meta.sandbox {enabled, timeout_s, mem_mb,
  cpu_s}. Proven live through the service API on the fixture APK.
- **Encrypted secrets vault (`secretsmgr.py` + `target_secrets`)**:
  target credentials (bearer token / session cookie / basic auth) are
  stored Fernet-encrypted at rest (cryptography; authenticated
  encryption — tampered tokens fail decryption). Master key from
  PTK_SECRETS_KEY or an auto-generated `secrets.key` file (0600) in the
  app directory. The API is admin-only and write-only: list returns
  metadata only, values are never returned. Scans accept `secret_id`;
  the worker decrypts in memory, applies the credential to the scan,
  audits the use (id + target only), and redacts any reflected
  occurrences from the stored result. Proven end-to-end against a
  bearer-gated test server: the target's own request log shows the
  /private request carrying the correct Bearer token during the
  authenticated scan and none during the control scan, and the token
  appears nowhere in the stored scan result. Note the trust boundary:
  the key file lives next to the database, so this protects exported
  DBs/backups and casual reads — it is not an HSM.
- **systemd (opt-in, NOT activated on this VM)**: deploy/
  pentest-toolkit.service mirrors the bash supervisor exactly (same
  working directory, env file, venv interpreter, restart policy) with
  basic hardening (NoNewPrivileges, PrivateTmp, ProtectSystem=full with
  explicit ReadWritePaths). deploy/install-systemd.sh installs the unit
  and prints the switch-over steps; it deliberately does not stop the
  bash supervisor or enable the unit, and warns that restore-all.sh
  section 9 must be switched at the same time to avoid two supervisors
  fighting over port 5000. The VM keeps the proven bash supervisor +
  watchdog restore.
- Suite: 80 tests. The PREREQ programme (Phases 1-3) is complete.

---

## v3.18.1 — Full audit patch (UI, security, features, scan validity)

A complete re-audit of the running system (all 16 GET routes smoke-tested
live, all POST flows, reports, exports, CLI, ground-truth battery) found
and fixed three real bugs plus two authorization hardenings:

- **BUG (since v3.17.0): GET /api/findings crashed the handler**
  (UnboundLocalError). The NVD-status branch imported parse_qs locally;
  Python scoping made the name function-local for the whole handler, so
  the earlier findings branch crashed. Removed the redundant local
  import (both names are module-level). Regression test added.
- **BUG (since v3.13.0): finding origin was dropped at save time.**
  Findings carry origin (passive/active) in memory and in live job
  results, but the findings table had no origin column, so saved scans,
  the global findings view, CSV export and ALL reports lost/defaulted
  the label (passive findings in reports were labelled active). Added
  the column (schema + migration, default 'active' — correct for all
  pre-existing rows, which come from active scans), save_scan now
  persists it. Regression test covers store round-trip and the report
  render.
- **BUG (since v3.14.0): CLI passive and scan subcommands crashed**
  ('function' object has no attribute 'append') — the CLI passed a
  callable logger to engines that expect a list. The CLI now passes a
  tee list (appends + echoes to stderr), and passive's log helper
  tolerates both protocols. End-to-end CLI regression tests added.
- **Hardening**: POST /api/suppressions, /api/suppressions/delete and
  /api/nvd/sync are now admin-only (were login-only); job status/cancel
  endpoints now enforce ownership (owner or admin) — both locked by
  tests with an analyst account on an isolated server.
- **Service UI tidy**: Settings panels reordered (Users, Preferences,
  Finding Suppressions, Target Secrets, Integrations & API); small
  screens (<=760px) stack two-column grids and scroll wide tables
  inside their panel instead of stretching the page. Rendering audit:
  all data interpolations in the dashboard are escaped (91 esc() sites
  verified, including every finding field).
- Verified clean: dependency audit (pip-audit) — zero known CVEs in the
  toolkit's own dependency set (findings belong to the shared VM
  environment, as in the v3.13 baseline); ground-truth battery still
  50/50 recall with zero false positives on safe/trap/SPA surfaces;
  hybrid live run on the fixture produced 82 findings end-to-end.
  Suite: 85 tests.

## v1.0.0 — Phase 4 + version renumbering (2026-10-17)

At ADE's instruction the release numbering restarts at **1.0.0**; this
release is the Phase 4 build (internally the successor of 3.18.1).
Contents: (1) the Phase 3 canary is now wired into the engine — check
`c_blind_oob` plants unique tokens for blind SSRF (URL params) and blind
XXE (XML bodies) and reports ONLY on real callbacks; the service starts
one listener (PTK_CANARY_PORT, default 8977; PTK_CANARY_BASE for a public
base). Without a reachable callback address the check logs a declared
skip — a missing callback is "untested", never "safe". On this VM the
listener is loopback-only, so internet targets cannot call back.
(2) Adaptive backoff in netclient: Retry-After honoured on 429, 403
streaks trigger capped exponential delays, statistics exposed per scan.
(3) `c_bola_matrix`: dual-account IDOR/BOLA — object URLs replayed with
account A, account B (a second vault credential, `secret_id2`) and
anonymously; cross-account reads confirmed only on content similarity.
(4) `c_json_fuzz`: structured JSON fuzzing beyond flat NoSQL operators —
mass assignment (privileged fields reflected), per-field type confusion,
one-level nested injection with new-error-signature evidence.
(5) `headless.py`: optional Playwright rendering, feature-detected; when
unavailable the scan declares the degradation and falls back to the
static crawl. Check registry: 46 in enterprise-full. Test battery note:
the enterprise check count is asserted explicitly so a silently dropped
check fails the suite.

## v1.1.0 — Deep Integration Inventory + per-component CVE (2026-10-17)

At ADE's request ("see everything integrated into a URL — DB, API, web
server, deployment tools — with in-depth version explanations and a CVE
check for every integrated software"), the technology profiler becomes a
full integration inventory:
(1) Signature DB 94 -> 99 with a new Deployment/DevOps category (Jenkins,
GitLab), Admin Tool (phpMyAdmin, Adminer) and API (Swagger UI) entries —
all distinctive product signatures only; a unit trap test proves product
names in plain prose detect NOTHING.
(2) Every component now carries ALL its evidence (up to 4 artefacts) and
a presence confidence: >=2 independent sources = confirmed, one strong
artefact = probable, active probe = verified. DETAILS gives a 1-2
sentence deep explanation per major component, shown in the UI table and
reports.
(3) Eight active component probes (Docker Registry /v2/, Kubernetes
/version, Portainer /api/system/status, Argo CD /api/version, Jenkins
/login, GitLab /-/health, OpenAPI, GraphQL introspection-lite) confirm
deployment/API tooling from the products' own signatures — never from a
bare 200.
(4) CVE matching per component is version-RANGE aware (packaging
specifiers) on top of the exact-match table, and additionally attaches
candidates from the local NVD cache when the cached description names
the detected version or a "prior to" fix above it. All CVE output stays
CANDIDATE confidence. The range table also fixes a latent dead entry:
"IIS" never matched techdb's "Microsoft IIS" name before.
(5) Scan detail (service UI) gains an Integrations table (component,
category, version, confidence, CVE candidates, explanation + evidence);
HTML and DOCX reports gain Confidence and CVE-candidates columns.
Ground truth: the fixture now simulates Jenkins/GitLab/Registry/K8s/
Portainer/OpenAPI/GraphQL; the battery asserts each detected version +
verification and the CVE attachments (Apache CVE-2021-41773, jQuery
CVE-2015-9251/11358, WordPress CVE-2022-21661).


## v1.6.0 — Rebranding: VANTHEX (2026-10-17)
Produk berganti nama dari "Pentest Toolkit" menjadi **VANTHEX — Offensive Security Platform** (tagline: Discover. Validate. Remediate.; sub-brand: Vulnerability Intelligence & Security Assessment). Seluruh branding publik diganti: template login/app (title, brand, favicon shield crimson + meta), header Server, laporan HTML/DOCX, nama file laporan (vanthex_report_*), User-Agent scanner diseragamkan "VANTHEX/1.6.0", CLI prog "vanthex", README/INSTALL, deskripsi unit systemd, dan label modul (Security Dashboard, Assets Management, Vulnerability Findings, Mobile Application Testing, Audit Logs, Scan Schedules, System Settings). Yang SENGAJA dipertahankan demi kompatibilitas (§7.5 brief): nama event webhook "pentest_scan_completed", kunci localStorage "ptk-*", nama file DB, slug artifact, nama direktori, docstring header internal, dan catatan historis ini. Catatan i18n service: judul view yang berganti nama belum memiliki kunci terjemahan di 11 bahasa non-Inggris sehingga judul tersebut tampil dalam bahasa Inggris pada UI non-Inggris (nama produk tidak diterjemahkan). Suite penuh setelah rebrand: 97/97.

## v1.7.0 — Master Redesign: premium enterprise (2026-10-17)
Mengikuti master prompt + gambar referensi VANTHEX dari ADE: sistem token terpusat (dark bg #070B12, sidebar #090E16, card #0D1520, elevated #111B29, primer #FF4148/#D92736, teks #F4F7FB/#98A7BA, border #202D3D, sukses #22C993, warning #FFAA3D, info #43B7F5). Lapisan teatrikal HUD (scanlines, sweep, bracket, glitch, chamfer, radar, ticker) DICABUT dari service (PREMIUM PASS) dan artifact; kartu rounded 12px, glow minimal. Dashboard artifact mengikuti komposisi referensi dengan DATA ASLI saja: banner welcome memakai username sesi nyata, KPI riil, trend (rentang 7D/14D sesuai seri 14 hari yang benar-benar disediakan service — bukan 30D/90D karangan), donut severity, kartu modul ber-rute nyata, Recent Scans, Top Vulnerabilities, rail Recent Activity (event asli saja), Quick Actions, kartu Engine Health live. New Scan menjadi wizard 5 langkah dengan payload API identik dan gerbang otorisasi yang sama. Halaman Threat Intelligence/Risk Scoring TIDAK dibuat (view tidak ada — sesuai §4 master prompt); kartu Manual Exploitation diganti modul nyata. DB 0 scan saat rilis: dashboard menampilkan nol + empty state jujur.

## v1.8.0 — Scan reliability: skema dibuktikan, preflight fail-fast, budget & cache aman (2026-10-18)
Dipicu keluhan ADE: scan UAT 2067s tanpa hasil, hasil antar-scan berbeda, framework tidak terdeteksi. Akar masalah terverifikasi dari data: target disimpan TANPA skema ("uatgadaiemas.devoutsys.com/DepoEmasMaster/login") dan parser lama menebak http:// (port 80 — dari luar tertutup; terukur timeout 10.5s), sementara https 443 menjawab 200 dalam 1.16s. Perbaikan: (1) netclient.resolve_scheme_target() membuktikan skema dengan probe ringan (https dulu, fallback http); target efektif tercatat di hasil (effective_target) dan disimpan sebagai target scan. (2) Preflight fail-fast untuk profil aktif: target yang tidak merespons satu pun request dihentikan dalam hitungan detik dengan temuan INFO "Target unreachable — scan aborted early" + peringatan INCONCLUSIVE (bukan vonis bersih). (3) Budget waktu: per-check 600s (status "timeout" transparan di checks_detail) + budget total 1800s (check sisa "skipped"). (4) Cache respons GET per-scan DENGAN dua pagar yang lahir dari regresi battery: request bervariasi header tidak pernah dilayani dari cache, dan URL yang pernah diminta dengan header menjadi "tainted" (entri dibuang, tidak di-cache lagi) — tanpa pagar ini verifikasi cache-poisoning membaca snapshot sebelum-diracuni dan deteksinya mati; pagar dikunci tests/test_scan_reliability.py. (5) Budget tidur backoff kumulatif 90s/scan (sebelumnya scan fixture terukur tidur 265s — sumber durasi acak). (6) Urutan surface crawl di-sort sebelum cap: subset yang diuji deterministik. Verifikasi: battery penuh hijau (recall 50/50, FP 0), test reliability 5/5 termasuk dua scan identik -> temuan & tech persis sama, dan target mati abort <30s.

## v1.9.0 — Delete aset (2026-10-18)
Menjawab pertanyaan ADE "kenapa di aset management gada tombol hapus?": aset bukan record mandiri — daftar aset adalah agregasi tabel scans per target (store.assets_summary), dan selama ini memang tidak ada jalur hapus aset di backend maupun UI (yang ada hanya edit meta criticality/owner + hapus per-scan di Scan History). Ditambahkan store.delete_asset(host): satu transaksi menghapus semua scan target itu + findings-nya + baris asset_meta + suppression host-nya (kunci target persis dan host-nya); vault target_secrets SENGAJA tidak disentuh (entri independen yang dikelola dari Settings). Endpoint POST /api/assets/delete (admin-only, audit "asset_delete" berisi hitungan) + tombol Delete per baris di Assets Management (service UI memakai confirmDialog yang sama dengan delete lain; artifact menyusul pola yang sama). Test: tests/test_assets_delete.py (kaskade hanya target itu; aset lain + data lain utuh; host tak dikenal -> hitungan nol). Terverifikasi live end-to-end dengan aset sintetis yang dibersihkan oleh endpoint itu sendiri.

## v1.10.0 — Complex vulnerability coverage (2026-10-18)
Four new evidence-first checks (50 checks in enterprise-full), each locked
by fixture ground truth with negative /safe controls:
c_stored_xss (plants a unique marker payload in non-auth POST forms —
including direct probes of common form pages the bounded crawl may miss —
and confirms only when the payload renders unescaped on a separate fresh
GET; soft-404 gated so it cannot fire on SPA catch-alls),
c_prototype_pollution (__proto__/constructor.prototype planting; proof
only when the planted key persists into a later NEUTRAL request — a plain
echo of the same request never counts), c_jwt_kid_injection (kid path
traversal to /dev/null -> empty-key signature; kid SQL injection ->
attacker-chosen key; same proven-baseline + forged-identity standard as
the JWT forgery check), c_graphql_deep (query batching amplification +
field-suggestion schema leakage). Robustness fix: c_nosql_api now
prioritises search-like endpoints and probes up to 8 — the v1.8
alphabetical endpoint ordering plus a blind cap of 4 let a newly
discovered endpoint silently displace the search endpoint (caught by
the ground-truth battery as a missing category, fixed in the check).
Ground truth: battery recall 55/55 categories, FP 0 on /safe/*, /trap/*
and SPA mode; full suite green.

## v1.12.0 — Command Deck identity redesign (2026-10-18)
Presentation-only. The artifact dashboard was restructured from the
generic uniform card grid into a "Command Deck" bento composition:
compact command strip with a live mono clock, System & Engine Health
unchanged at the top, then varied bento cells — a hero Security Posture
cell (giant gauge, oversized display numeral, shield watermark,
gradient hairline, scans sparkline), compact stat tiles with real
sparklines, a severity spectrum bar replacing the donut, gradient Scan
Trend, a terminal-styled Live Operations cell streaming real activity,
Top Vulnerabilities with mono CVSS readouts, module feature tiles and
the Recent Scans table. A typography system (800-weight display
numerals, uppercase micro-labels, mono data readouts), brand scrollbar
and crimson selection apply app-wide. The service UI received the
matching IDENTITY PASS CSS layer. All functions, routes, API payloads
and data are unchanged; no HUD theatre was reintroduced.

## v1.13.0 — Interactive pass (2026-10-18)
Presentation/interaction only. Artifact: a Ctrl+K command palette
(fuzzy navigation + quick actions + live results from real scans,
findings and assets), clickable Severity Spectrum segments deep-linking
to filtered findings, a posture-gauge breakdown popover from real
per-asset scores, Scan Trend hover crosshair/tooltips and sparkline
tooltips, drag-to-reorder bento cells persisted in localStorage with a
reset control (desktop pointers only), keyboard shortcuts (g d/g s/
g f/g a, n, /, ?) with a help dialog, a persisted accent picker
(Crimson/Cyan/Violet/Amber via the CSS variable system), inline
Recent Scans row expansion with real findings summaries, and animated
transitions when refreshed values change. Service UI: a self-contained
interactive layer (Ctrl+K focuses the header search, stat-card tilt)
that touches no data or handlers. No backend, route, payload or data
changes.

## v1.14.0 — Depth & life pass (2026-10-18)
Presentation only. Artifact: a living canvas (deepened background with a
slow aurora mesh), a three-tier elevation system (directional shadows,
top light highlights, floating overlays with backdrop blur), an animated
conic border beam + mouse parallax shield + 3D tilt on the hero posture
cell, tilt-and-glare stat/module tiles, physical raised buttons, chart
glows, a typing effect on the newest Live Operations line, and a live
CPU/memory waveform in Engine Health drawn from the rolling buffer of
the already-polled real metrics. Service UI: the matching DEPTH PASS
layered-shadow CSS. No backend, route, payload or data changes.

## v1.15.0 — Accuracy overhaul (2026-10-19)

Dipicu audit ADE atas scan ports/subdomains miliknya sendiri yang "ngaco".
Akar masalahnya posisi jaringan VM ini, dan sekarang engine menanganinya
secara jujur di semua jalur:

- **Ports**: egress TCP terintercept gateway sandbox (banner `muse:`) —
  hasil connect mentah TIDAK lagi disimpan sebagai port terbuka. Bila
  interception terdeteksi: `open_ports` dikosongkan + 1 finding INFO
  "Port scan inconclusive". (Sebelumnya: 50 port palsu tersaji.)
- **Subdomains**: resolver sistem VM ini sintetis (IP fake 198.18.0.0/15
  untuk nama apa pun, terbukti untuk nama yang mustahil ada). Enumerasi
  sekarang memakai DNS-over-HTTPS (Cloudflare/Google) + gerbang wildcard;
  resolver sistem hanya fallback bila terbukti sehat; bila tidak ada jalur
  tepercaya -> inconclusive, bukan daftar palsu. (Sebelumnya: 51 nama palsu.)
- **Dirs/Headers**: dulu direct-socket + tebak skema http (0 hasil pada
  target https). Sekarang lewat netclient sadar-proxy, skema DIBUKTIKAN
  via probe, dan http_probe punya baseline soft-404 (shell SPA ditandai
  catch_all dan disaring dari hits). Target tak terjangkau = inconclusive.
- **SSL/TLS**: audit + cipher enum sekarang lewat tunnel HTTP CONNECT
  (bukan direct yang terintercept) dan parsing sertifikat memakai form
  DER via cryptography bila getpeercert teks kosong (bug laten: subject/
  issuer/SAN kosong). c_tls di vulnscan ikut sembuh ("TLS could not be
  audited" hilang pada target yang TLS-nya sehat).
- **UDP**: resolusi target via DoH + tolak IP sintetis (inconclusive bila
  tidak ada jalur tepercaya); validasi respons DNS diperketat (TXID cocok,
  RCODE 0, ANCOUNT >= 1) dan respons yang gagal validasi protokol turun ke
  open|filtered "unverified response", bukan "open". (Sebelumnya: respons
  error 29B dari perantara diklaim "dns open".)
- **Passive**: fallback DNS A/AAAA sekarang DoH-first + saring IP sintetis.
- **Output engine full English**: 25 string log/evidence runtime yang masih
  berbahasa Indonesia diterjemahkan (aturan ADE 2026-10-16).
- Test: +13 test kejujuran transport/DNS/port (tests/test_transport_honesty.py,
  tests/test_dns_ports_honesty.py). Bukti live ke UAT ADE: ports inconclusive
  bersih, subdomains 0 (sesuai ground truth DoH), ssl subject asli terbaca
  (CN=uatgadaiemas.devoutsys.com, TLSv1.3), headers score 67 konsisten
  dengan vulnscan, udp 53 open|filtered jujur.

## v1.16.0 — Audit akurasi menyeluruh + kerapian UI (2026-10-19)

Mandat ADE: update ulang semuanya lebih rapih (tampilan, font), fixing bug,
dan pastikan scanning seakurat mungkin di semua tipe. Baseline suite
v1.15.0: 119/119 hijau sebelum perubahan apa pun.

- BUG 1 (headers): cabang scan tipe "headers" di app2.run_tool_scan selalu
  mengembalikan "findings": [] — header keamanan yang hilang tidak pernah
  menjadi finding (berbeda dengan vulnscan c_security_headers yang menilai
  respons yang sama), dan target tak terjangkau tampak bersih. Kini cabang
  ini memancarkan finding yang PERSIS mencerminkan c_security_headers
  (judul/severity/CWE/CVSS/remediasi sama; HSTS hanya di https) + INFO
  inconclusive bila tidak ada respons. Bukti live via API: fixture tanpa
  header -> 5 finding (CSP MEDIUM 5.4 + 4 LOW), via https -> 6 (HSTS ikut).
- BUG 2 (urutan argumen F): signature vulnscan2.F adalah
  F(sev, title, desc, evidence, cwe, owasp, cvss=0.0, remed="") — posisi
  ke-7 adalah cvss. SEMUA pemanggilan F() di cabang typed app2 (ssl x2,
  udp x3, syn, vhost) mengoper string remediasi secara posisional, sehingga
  teks remediasi mendarat di field cvss dan remediation kosong di setiap
  finding scan tipe ssl/udp/syn/vhost. Diperbaiki di 9 titik pemanggilan
  (remed= keyword). mobile.py & vulnscan2 internal ternyata bersih (kwargs).
- Konsistensi: finding INFO 'TLS could not be audited' (c_tls) kini punya
  remediasi (sebelumnya satu-satunya finding engine yang kosong).
- Test regresi baru: tests/test_headers_findings.py (4) +
  tests/test_typed_scan_findings.py (5). Suite penuh: 128 test.
- Bukti live end-to-end via API service (scan bukti dihapus sesudahnya):
  headers http/https sesuai cermin vulnscan; ports loopback terukur nyata
  {18080,18443,5000} intercepted=False; dirs hanya /admin; subdomains
  example.com found=[] (DoH); syn EPERM -> INFO jujur berketerisian bersih;
  vhost 0 FP; udp loopback jujur; vulnscan passive-quick 7 finding semua
  beremediasi; ssl_audit fungsi membaca sertifikat fixture (CN=localhost,
  TLSv1.3, verify_error self-signed benar). CATATAN VANTAGE: connect
  langsung ke 127.0.0.1:443 (tidak ada listener) dijawab gateway sandbox
  dengan sertifikatnya sendiri (issuer Hatch Sandbox Egress CA) — kelas
  intercept yang sama seperti insiden port dulu; audit TLS target publik
  tetap lewat CONNECT dan membaca sertifikat asli (terbukti di UAT).
- UI (artifact, appearance-only): sapuan kerapian & tipografi menyeluruh —
  judul Scan Detail diseragamkan ke peran heading 22px, bobot label grafik
  trend ke bobot peran, tracking baris versi brand card dinormalkan, jarak
  label->field disatukan (mt-1) di 28 field form, select triage Findings
  disamakan spec kompak editor Assets; badge V1.16.0 di 4 titik. Sebelumnya
  di hari yang sama: upload APK chunked (fix 422), sweep overlay near-opaque,
  brand card terpusat, service mati pasca-restart platform dihidupkan ulang.

## Re-versioning rilis publik — v1.0.0 (2026-10-20)

Atas keputusan ADE, versi publik VANTHEX dimulai dari **v1.0.0** untuk debut
GitHub/GHCR (silsilah internal v1.6.0–v1.16.0 di atas tetap sebagai catatan
sejarah pengembangan). Semua literal versi engine, image Docker
(`vanthex:1.0.0`), workflow GHCR, badge artifact, dan nama paket diselaraskan
ke 1.0.0; tidak ada perubahan fungsional dalam langkah ini.
