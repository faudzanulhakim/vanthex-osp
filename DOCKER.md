# VANTHEX — Instalasi Docker Compose

Alternatif dari instalasi native (lihat `INSTALL.md`). Engine, fitur, dan
perilaku scan identik; yang berbeda hanya cara menjalankan.

## Prasyarat

- Docker Engine 24+ dan Docker Compose v2 (`docker compose version`)
- ±1 GB ruang disk untuk image, port 5000 bebas

## Quick start

```bash
cp .env.example .env       # WAJIB: isi PTK_ADMIN_PW dengan password kuat
docker compose up -d --build
docker compose ps          # tunggu status "healthy"
```

Buka `http://localhost:5000` — login `admin` / password dari `.env`.

## Data & persistensi

Semua state tinggal di named volume `vanthex-data`:

- `toolkit.db` — scan, finding, user, audit log, cache CVE
- `secrets.key` — kunci vault kredensial (Fernet)

Container boleh di-rebuild/di-upgrade tanpa kehilangan data. Backup:

```bash
docker run --rm -v vanthex-data:/data -v "$PWD":/backup alpine \
    tar czf /backup/vanthex-data-backup.tgz -C /data .
```

## Upgrade

```bash
# timpa kode dengan paket baru (volume data tidak tersentuh), lalu:
docker compose up -d --build
```

## Deploy dari GitHub (GHCR)

Repo ini dilengkapi workflow `.github/workflows/docker.yml`: setiap push
ke `main` dan setiap tag versi (mis. `v1.0.0`) membangun image multi-arch
(amd64 + arm64) dan menerbitkannya ke GitHub Container Registry sebagai
`ghcr.io/<owner>/<repo>` dengan tag `latest`, versi semver, dan `sha-<short>`.
Pull request hanya membangun (cek), tidak menerbitkan.

Di server, deploy tidak butuh source code — cukup
`docker-compose.deploy.yml` + `.env`:

```bash
cp .env.example .env   # isi PTK_ADMIN_PW + GHCR_OWNER (+ VANTHEX_TAG bila mau pin versi)
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

Image privat: login sekali di server dengan Personal Access Token
(`read:packages`): `echo <PAT> | docker login ghcr.io -u <user> --password-stdin`.

Catatan keamanan repo: `.gitignore` sudah mengecualikan `toolkit.db`,
`secrets.key`, dan `.env` — jangan pernah commit ketiganya.

## Operasional

```bash
docker compose logs -f        # log aplikasi
docker compose restart        # restart
docker compose down           # berhenti (data tetap)
docker compose down -v        # berhenti + HAPUS semua data
```

## Catatan posisi jaringan (vantage) — penting untuk akurasi scan

- Scan lapisan web (vulnscan, headers, SSL, dirs, passive, mobile, dll)
  bekerja normal dari container.
- Scan lapisan jaringan (Ports, SYN, UDP) mengukur **dari posisi jaringan
  container** (NAT Docker secara default), bukan dari posisi host. Hasilnya
  menggambarkan keterlihatan target dari jaringan Docker — sah, tapi sadari
  bedanya bila targetmu ada di LAN yang sama dengan host.
- Untuk memindai target LAN dari posisi host (Linux), aktifkan opsi
  `network_mode: host` yang sudah disiapkan (berkomentar) di
  `docker-compose.yml` dan hapus blok `ports:`.
- SYN scan butuh raw socket: `cap_add: NET_RAW` sudah termasuk di compose,
  tetapi host tetap harus mengizinkannya (kebijakan kernel/LSM). Bila tidak,
  VANTHEX melaporkannya secara jujur sebagai *inconclusive* — bukan sebagai
  "port tertutup".
- Listener canary OOB (untuk uji SSRF/blind) mendengarkan di dalam
  container; agar target bisa menelepon balik, terbitkan URL publiknya dan
  set `PTK_CANARY_BASE` di `.env`.

## Troubleshooting

- **Port 5000 sudah dipakai** → ubah sisi kiri mapping di compose,
  mis. `"15000:5000"`, lalu buka `http://localhost:15000`.
- **Login ditolak** → password dibaca dari `PTK_ADMIN_PW` saat database
  pertama dibuat. Kalau DB sudah terlanjur dibuat dengan password lama,
  ubah lewat dashboard (Settings) atau hapus volume (`down -v`) untuk
  mulai bersih.
- **Container unhealthy** → `docker compose logs` untuk melihat error
  startup; penyebab tersering: `.env` belum dibuat.
