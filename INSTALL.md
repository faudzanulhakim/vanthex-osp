# VANTHEX — Native Installation Guide

**Version 1.2.1** · For Docker deployment, see [DOCKER.md](DOCKER.md).

> ⚠️ **AUTHORIZED TESTING ONLY.** VANTHEX is an offensive security tool.
> Run it only against systems you own or are explicitly authorized to test.

---

## 1. Prerequisites

### Hardware

| Resource | Minimum | Recommended |
|---|---|---|
| CPU | 1 core | 2+ cores (scans are concurrent) |
| RAM | 1 GB | 2 GB+ |
| Disk | 1 GB | 5 GB+ (scan history, CVE cache, uploaded packages) |

### Software

| Requirement | Notes |
|---|---|
| **Python 3.12** (3.11 works; 3.12 is the reference runtime) | Check with `python3 --version` |
| **pip + venv** | Debian/Ubuntu: `python3-venv`, `python3-pip` |
| **git** (optional) | Only for cloning the repository; a release ZIP works too |
| **Network egress** | Outbound HTTP/HTTPS to scan targets; UDP/TCP 53 or HTTPS for DNS-over-HTTPS; access to `services.nvd.nist.gov` if you sync the CVE cache |
| **TCP port 5000** free | Configurable (see §4) |
| **CAP_NET_RAW** (optional) | Only for the SYN scan type: `sudo setcap cap_net_raw+ep $(readlink -f $(which python3))`, or run the service as root. Without it, the SYN scan reports itself *inconclusive* instead of failing |

The engine itself uses **no external scanner binaries** — nothing else to
install. All dependencies are Python packages pinned in
`requirements.txt` (including `androguard` for APK analysis,
`beautifulsoup4`, `cryptography`, `dnspython`, `lxml`, `requests`,
`python-docx`, `Pillow`, and the test tooling).

### Operating systems

Linux (reference), macOS, and Windows are supported. The systemd unit in
`deploy/` targets Linux. On Windows, use the manual run method (§4) or
Docker.

---

## 2. Obtain the source

```bash
git clone https://github.com/<your-user>/vanthex-osp.git
cd vanthex-osp
```

—or unpack a release archive and enter its directory.

---

## 3. Create the environment and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

All packages ship as wheels; no compiler is required on current
platforms. (On minimal systems where a wheel is unavailable, install
your distribution's `build-essential` / `python3-dev` equivalent first.)

---

## 4. First run

Set the administrator password **before the first start** — it seeds the
`admin` account when the database is created:

```bash
export PTK_ADMIN_PW='a-long-random-password'     # Windows: set PTK_ADMIN_PW=...
python app2.py 5000
```

Then open <http://localhost:5000> and sign in:

- **Username:** `admin`
- **Password:** the value of `PTK_ADMIN_PW` (if the variable is unset at
  first run, a strong random password is generated and printed once at
  startup — there is no default password)

**Dashboard URLs** (after sign-in): `/` serves the classic dashboard,
at parity with the chat artifact; `/classic` is an alias for it;
`/webui` serves the legacy webui SPA.

Notes on state created at first run, in the application directory:

| File | Purpose |
|---|---|
| `toolkit.db` | SQLite database: scans, findings, users, schedules, audit log, CVE cache |
| `secrets.key` | Fernet key for the encrypted credential vault (keep private, mode 0600) |
| `uploads_apk/` | Uploaded mobile packages and upload staging |

**Changing the admin password later:** `PTK_ADMIN_PW` only seeds the
account at database creation. Afterwards, change the password from the
dashboard (System Settings → Users) or delete `toolkit.db` to start
fresh (this discards all history).

### Verify the installation

```bash
curl -s http://localhost:5000/api/engine   # after login; or open the dashboard
python -m pytest tests/ -q                 # full verification suite (143 tests)
```

---

## 5. Configuration (environment variables)

| Variable | Purpose | Default |
|---|---|---|
| `PTK_ADMIN_PW` | Password of the seeded `admin` user | — (none; random-generated if unset) |
| `PTK_NVD_KEY` | NVD API key — raises CVE-sync rate limits substantially | — |
| `PTK_ALLOWED_TARGETS` | Comma-separated target allowlist (exact host, `*.domain`, or suffix) — an extra guard on top of the in-UI authorization gate | — (all hosts allowed) |
| `PTK_CANARY_BASE` | Public base URL of the out-of-band canary listener (required for blind-SSRF confirmation on internet targets) | — |
| `PTK_CANARY_PORT` | Canary listener port | `8977` |
| `PTK_COOKIE_SECURE` | `1` marks session cookies `Secure` (use behind HTTPS) | — |
| `PTK_COMPANY` | Company name printed on reports | — |
| `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY` (or `PTK_PROXY`) | Egress proxy for the web layer | — |
| `VANTHEX_FIRMS_MAP_KEY` | NASA FIRMS MAP_KEY for live fire hotspots on the globe | — (unset = EONET fallback) |
| `VANTHEX_ABUSECH_AUTH_KEY` | abuse.ch auth key for keyed threat-intel families | — (unset = those families stay offline) |

---

## 6. Run as a system service (Linux, systemd)

```bash
sudo bash deploy/install-systemd.sh
systemctl status pentest-toolkit
```

The installer registers the unit in `deploy/pentest-toolkit.service`
(adjust `WorkingDirectory` and the Python path inside it if you install
outside the default location). The service binds `0.0.0.0:5000`.

**Exposure guidance:** do not publish port 5000 directly to the
internet. Put VANTHEX behind a VPN (e.g. Tailscale/WireGuard), an SSH
tunnel (`ssh -L 5000:localhost:5000 user@server`), or an authenticated
reverse proxy with TLS (and set `PTK_COOKIE_SECURE=1`).

---

## 7. Upgrading

1. Stop the service.
2. **Back up** `toolkit.db` and `secrets.key` (together they are the
   complete state: history, users, schedules, CVE cache, vault).
3. Replace the code with the new release (keep your `.venv` or rebuild
   it with `pip install -r requirements.txt`).
4. Start the service. Database schema migrations are automatic and
   backward-compatible; the UI bundle under `webui/` is part of the
   release and needs no build step.

---

## 8. Troubleshooting

| Symptom | Cause / remedy |
|---|---|
| `Address already in use` on start | Another process holds port 5000; choose another port: `python app2.py 5001` |
| APK analysis rejected with a clear dependency message | `androguard` is not installed in the active environment; reinstall with `pip install -r requirements.txt` inside the venv |
| SYN scan reports *inconclusive (raw sockets unavailable)* | Grant `CAP_NET_RAW` (see §1) or run as root |
| Port/subdomain results *inconclusive* behind a mandatory proxy or intercepting gateway | Expected honesty behavior: direct-socket measurements cannot pass an intercepting middlebox. The web layer (which honors the proxy) is unaffected; run network-layer scans from an unintercepted vantage point |
| CVE cache sync is slow or rate-limited | Set `PTK_NVD_KEY` (free key from NVD) |
| Forgot the admin password | Stop the service, move `toolkit.db` aside, restart with a new `PTK_ADMIN_PW` (history is lost), or restore the backup |

---

## 9. Uninstall

Stop the service and remove the application directory. To erase all
state, also remove `toolkit.db`, `secrets.key`, and `uploads_apk/`.
For systemd installs: `systemctl disable --now pentest-toolkit` and
remove the unit file.
