# VANTHEX — Docker Compose Deployment

**Version 1.2.1** · For native (non-Docker) installation, see
[INSTALL.md](INSTALL.md). Engine, features, and scan behavior are
identical in both installation methods; only the runtime differs.

**Dashboard URLs** (after sign-in): `/` serves the classic dashboard,
at parity with the chat artifact; `/classic` is an alias for it;
`/webui` serves the legacy webui SPA.

---

## 1. Prerequisites

| Requirement | Notes |
|---|---|
| **Docker Engine 24+** | Check with `docker version` |
| **Docker Compose v2** | The `docker compose` plugin (not the legacy `docker-compose` binary); check with `docker compose version` |
| **Disk space** | ±1 GB for the image, plus volume growth for scan history and the CVE cache |
| **Port 5000** free on the host | Remappable in the compose file if occupied |
| **Network egress** | Outbound HTTP/HTTPS to scan targets; HTTPS for DNS-over-HTTPS and the NVD API |
| **(Optional) raw-socket capability** | The compose files already add `NET_RAW`, which the SYN scan type needs; on hosts that forbid it, the SYN scan reports itself *inconclusive* |

No Python installation is required on the host — the image is based on
`python:3.12-slim` and installs the pinned dependencies from
`requirements.txt` at build time.

---

## 2. Option A — Build from source

Use this when you have the repository (development, customization, or
air-gapped builds).

```bash
git clone https://github.com/<your-user>/vanthex-osp.git
cd vanthex-osp

cp .env.example .env        # edit: set a strong PTK_ADMIN_PW
docker compose up -d --build
```

Open <http://localhost:5000> and sign in as `admin` with the
`PTK_ADMIN_PW` from your `.env`.

What this does:

- Builds the image from the `Dockerfile`
- Starts one container, publishing host port **5000** → container 5000
- Creates the named volume **`vanthex-data`** mounted at `/data`
- Adds the `NET_RAW` capability
- Registers a health check against the login page

---

## 3. Option B — Deploy the prebuilt image (GHCR)

Use this for servers: no source tree and no build step. Images are
published by GitHub Actions to the GitHub Container Registry on every
release tag (multi-arch: `linux/amd64` + `linux/arm64`).

You need only two files: `docker-compose.deploy.yml` and `.env`.

```bash
mkdir vanthex && cd vanthex
# copy docker-compose.deploy.yml and .env.example into this directory
cp .env.example .env
```

Edit `.env`:

```dotenv
PTK_ADMIN_PW=a-long-random-password
GHCR_OWNER=<your-github-user>        # image: ghcr.io/<owner>/vanthex-osp
GHCR_REPO=vanthex-osp
VANTHEX_TAG=1.2.1                    # or latest
# PTK_NVD_KEY=...                    # optional, recommended
# VANTHEX_FIRMS_MAP_KEY              # optional: NASA FIRMS key for live fire hotspots (unset = EONET fallback)
# VANTHEX_ABUSECH_AUTH_KEY           # optional: abuse.ch key for keyed threat-intel families (unset = offline)
```

Then:

```bash
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

> The `-f docker-compose.deploy.yml` flag is required for every
> command because the file is not named `docker-compose.yml`.
> The `.env` file must sit in the same directory as the compose file;
> compose refuses to start while `PTK_ADMIN_PW` is unset in it —
> there is no default password.

If the package is private, authenticate first:
`echo <PAT> | docker login ghcr.io -u <your-github-user> --password-stdin`
(a classic personal access token with `read:packages` is sufficient).

---

## 4. Configuration (.env reference)

| Variable | Purpose | Default |
|---|---|---|
| `PTK_ADMIN_PW` | Password of the seeded `admin` user (first start only; see §6) | — (required) |
| `PTK_NVD_KEY` | NVD API key for faster CVE cache synchronization | — |
| `PTK_ALLOWED_TARGETS` | Comma-separated scan-target allowlist (extra guard) | — |
| `PTK_CANARY_BASE` | Public base URL of the out-of-band canary listener | — |
| `PTK_CANARY_PORT` | Canary listener port | `8977` |
| `PTK_COOKIE_SECURE` | `1` marks session cookies `Secure` (HTTPS deployments) | — |
| `GHCR_OWNER` / `GHCR_REPO` | Image coordinates for the deploy compose file | — / `vanthex-osp` |
| `VANTHEX_TAG` | Image tag for the deploy compose file | `latest` |
| `VANTHEX_FIRMS_MAP_KEY` | NASA FIRMS MAP_KEY for live fire hotspots on the globe | — (unset = EONET fallback) |
| `VANTHEX_ABUSECH_AUTH_KEY` | abuse.ch auth key for keyed threat-intel families | — (unset = those families stay offline) |

---

## 5. Persistence model

All state lives in the **`vanthex-data`** volume, mounted at `/data`:

| File in the volume | Contents |
|---|---|
| `toolkit.db` | SQLite database: scans, findings, users, schedules, audit log, CVE cache |
| `secrets.key` | Fernet key for the encrypted credential vault |

The entrypoint (`docker-entrypoint.sh`) symlinks both files from the
application directory into `/data` at container start, so rebuilds,
image upgrades, and container recreation never lose state. Uploaded
mobile packages are processed from staging and their results are
stored in the database.

**Backup:** stop the container and archive the volume:

```bash
docker compose down
docker run --rm -v vanthex-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/vanthex-backup.tar.gz -C /data .
```

---

## 6. Operations

```bash
docker compose ps                       # status + health
docker compose logs -f                  # follow logs
docker compose restart                  # restart in place
docker compose down                     # stop (state persists in the volume)
docker compose down -v                  # stop and DELETE all state
```

**Changing the admin password:** `PTK_ADMIN_PW` seeds the account only
when the database is first created. Change it later from the dashboard
(System Settings → Users), or reset everything with
`docker compose down -v` and a fresh `.env` (history is discarded).

**Upgrading (deploy variant):**

```bash
# edit VANTHEX_TAG in .env to the new version, then:
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

**Upgrading (build variant):** `git pull`, then
`docker compose up -d --build`. Database migrations are automatic and
backward-compatible.

---

## 7. Networking notes

- **Bridge mode (default):** the container scans targets through the
  host's NAT — the same vantage point as the host itself.
- **Host network (optional):** uncomment `network_mode: host` in
  `docker-compose.yml` when the container must see the host's interfaces
  directly (e.g. LAN-local targets or raw-socket scans); the published
  `ports:` entry is then ignored and the service listens on the host's
  port 5000 directly.
- **Exposure guidance:** do not publish port 5000 directly to the
  internet. Place VANTHEX behind a VPN, an SSH tunnel, or an
  authenticated TLS reverse proxy (and set `PTK_COOKIE_SECURE=1`).

---

## 8. Troubleshooting

| Symptom | Cause / remedy |
|---|---|
| Container exits immediately | Read `docker compose logs`; the usual cause is an invalid `.env` (e.g. unescaped characters) |
| `permission denied` on the volume | The volume is managed by Docker; do not edit its files from the host while the container runs |
| Container refuses to start (`PTK_ADMIN_PW must be set`) | Create `.env` beside the compose file with a strong `PTK_ADMIN_PW` (see `.env.example`) |
| Login fails with the `.env` password | The database was seeded before the variable was set — seeding happens only at first creation; sign in with the original password, or delete the `vanthex-data` volume to re-seed |
| SYN scan *inconclusive* | The host forbids `NET_RAW` even with `cap_add`; use host networking or accept the honest inconclusive result |
| Port 5000 already allocated | Change the host side of the mapping, e.g. `"8080:5000"`, in the compose file |
| CVE sync slow / rate-limited | Set `PTK_NVD_KEY` in `.env` and recreate the container |
