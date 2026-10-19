# VANTHEX Enterprise v3 — Instalasi

> ⚠️ AUTHORIZED TESTING ONLY — hanya untuk sistem dengan izin resmi (aset kantor, lab, CTF).

## Prasyarat
- **Python 3.8+** (tidak ada dependensi lain — murni standard library)

## Instalasi & Menjalankan

```bash
unzip pentest-toolkit-v3.zip
cd pentest-toolkit-upgraded

# Jalankan server (port bebas, default 5000)
python3 app2.py 5000

# Ganti password admin default sebelum produksi:
PTK_ADMIN_PW="PasswordKuatKamu" python3 app2.py 5000
```

Buka: `http://<ip-server>:5000` — Login default: `admin` / `changeme123`
(atau password dari `PTK_ADMIN_PW` saat database pertama kali dibuat).

> Database `toolkit.db` dari v2 **kompatibel**: kolom confidence/lokasi/param
> ditambahkan otomatis saat server v3 pertama jalan. Backup dulu untuk aman.

## Akses Aman
- Akses via Tailscale / SSH tunnel saja, JANGAN expose port 5000 ke internet publik.
- SSH tunnel dari PC: `ssh -L 5000:localhost:5000 user@vps`
- Login kini punya rate-limit; tetap pakai password kuat.

## Yang baru di v3 (ringkas — detail di UPGRADE_NOTES.md)
- 🛰️⚡ Passive/Active jauh lebih akurat: baseline soft-404 + content signature,
  SQLi boolean & time-based, XSS multi-konteks, SSTI, LFI, CMDi, CRLF, SSRF,
  GraphQL introspection, Swagger/OpenAPI, JWT analysis, CSRF form, service API tanpa auth.
- 🎯 Confidence per finding (confirmed/probable/candidate) + lokasi & parameter.
- 🛑 Job bisa di-Stop; scan aktif wajib centang otorisasi (+ allowlist opsional `PTK_ALLOWED_TARGETS`).
- 🔌 Tool Port/Subdomain/Dir/SSL/Headers kembali bisa jalan dari dashboard.
- 🔀 Diff antar-scan, export JSON/CSV (selain DOCX/HTML), scan terautentikasi (cookie/header).
- 🌐 Dukungan proxy egress (env `HTTP(S)_PROXY` / `PTK_PROXY` / field di UI).

## API ringkas (semua butuh cookie session kecuali /api/login)
```
POST /api/login                    {username, password}
POST /api/scan                     {type:"vulnscan|ports|subdomains|dirs|ssl|headers",
                                    target, profile, authorized:true (wajib utk aktif),
                                    cookie?, headers?, timeout?, max_pages?, proxy?}
GET  /api/job/<id>                 live log & status (running|done|error|cancelled)
POST /api/job/<id>/cancel          hentikan scan berjalan
GET  /api/scans                    riwayat
GET  /api/scan/<id>                detail + findings + technologies
GET  /api/scan/<id>/diff           perbandingan vs scan sebelumnya
GET  /api/scan/<id>/export?fmt=json|csv
POST /api/scan/delete              {scan_id}
GET  /api/stats                    statistik dashboard (severity + confidence + target unik)
GET  /report/<id>?fmt=docx|html    unduh laporan
POST /api/users                    (admin) buat user analyst
```

## v3.3.0 — dependensi library (mobile + parser modern)

Sejak v3.3.0 engine tetap hasil build sendiri (tanpa memanggil tool scanner
jadi seperti nmap/nuclei), tetapi memakai library pihak ketiga untuk parsing:
androguard (APK), beautifulsoup4 (HTML), cryptography, requests, dnspython.
Siapkan virtualenv di folder proyek lalu jalankan app dengan Python venv itu:

    python3 -m venv --system-site-packages .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python app2.py 5000

Bila androguard belum terpasang, fitur web tetap jalan; hanya analisis APK
yang menolak dengan pesan jelas. Fitur mobile: dashboard → tab Mobile Apps →
upload .apk (maks 60 MB) → hasil tersimpan sebagai scan tipe "mobile".
