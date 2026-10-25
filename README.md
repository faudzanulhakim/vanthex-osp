<p align="center">
  <img src="docs/assets/vanthex-logo.png" alt="VANTHEX" width="420">
</p>

<h1 align="center">VANTHEX — Offensive Security Platform</h1>

<p align="center">
  <b>Discover. Validate. Remediate.</b><br>
  Vulnerability Intelligence &amp; Security Assessment
</p>

<p align="center">
  <img alt="Version" src="https://img.shields.io/badge/version-1.9.0-crimson">
  <img alt="Python" src="https://img.shields.io/badge/python-3.12-blue">
  <img alt="Engine" src="https://img.shields.io/badge/engine-self--built-success">
  <img alt="Tests" src="https://img.shields.io/badge/tests-143%20passing-brightgreen">
</p>

---

> ⚠️ **AUTHORIZED TESTING ONLY.** VANTHEX is an offensive security tool.
> Only scan systems you own or are explicitly authorized to test. Active
> scans require ticking an authorization statement in the UI — the server
> refuses to run without it. You are responsible for how you use this tool.

## What is VANTHEX?

VANTHEX is a self-hosted web & mobile application security assessment
platform with a full management dashboard: launch scans, triage findings,
track remediation, schedule recurring assessments, and export
consultant-grade reports — all from the browser, no command line needed.

Its scanner engine is **built from scratch**. VANTHEX does **not** shell
out to ready-made scanners (no nmap, nuclei, gobuster, nikto, jadx, or
apktool — ever). Checks are implemented natively in Python on top of
widely-used libraries (`requests`, `beautifulsoup4`, `cryptography`,
`dnspython`, `lxml`, `androguard`, …), so every detection is explainable
and its evidence is inspectable.

## Highlights

- **12 scan types** — vulnerability scan, port scan, subdomain
  enumeration, directory discovery, TLS/SSL audit, security-header audit,
  passive recon, UDP scan, virtual-host enumeration, SYN scan, hybrid
  (passive + active), and mobile app analysis (APK/IPA)
- **54 vulnerability checks** in the `enterprise-full` profile, mapped to
  OWASP Top 10 2021 + API Security Top 10 — injection (SQLi, NoSQL, XXE,
  LDAP, **XPath**, SSTI, command), XSS (incl. stored, verified by re-render),
  prototype pollution, JWT attacks (incl. `kid` injection), GraphQL deep
  checks, SSRF with an out-of-band canary, BOLA/IDOR dual-account matrix,
  auth & session, TLS, CORS, sensitive files, and more
- **New in 1.3.0 (Deep OSINT + Secrets Engine v2)** — a new `osint` scan
  type (infrastructure intelligence via RDAP/DoH, Certificate
  Transparency deep parsing with shadow-subdomain candidates, Wayback
  Machine history, control-gated username OSINT across 45 platforms —
  every platform must first pass a junk-handle probe, catch-alls are
  downgraded to unverified candidates — GitHub/GitLab code-exposure
  search whose fetched files are actually scanned, and a breach-exposure
  module that is **off by default**); the secrets engine grows to **72
  provider detectors** with *local structural validation* (GitHub token
  CRC checksums, real private-key parsing, JWT structure decoding, AWS
  credential pairing) instead of provider logins — findings are never
  validated against providers; layered decoders (base64 / hex / URL /
  unicode / JS concatenation), source-map `sourcesContent` scanning,
  sensitive-file content feeding, and a pure-Python walker that scans
  **exposed `.git` history** (new check `c_git_secrets`) for secrets
  committed in old revisions
- **New in 1.2.0 (PayloadsAllTheThings Priority 1)** — XPath injection in
  the injection suite (error-based `probable`; `confirmed` only when two
  independent boolean pairs pass), exposed-secret scanning of the
  homepage and same-host JS bundles (provider patterns `probable`,
  generic assignments `candidate`; values always masked in findings and
  **never validated against their provider**), hidden-parameter
  discovery (batch + bisect with a mandatory junk control, reported as
  surface — `probable`, not a proven vulnerability), and reverse
  tabnabbing auditing of crawled pages (LOW; modern browsers apply
  `noopener` implicitly, the risk is legacy browsers and WebViews)
- **Deep integration inventory** — scanning one URL fingerprints the
  stack behind it (frameworks, servers, APIs, deployment tools, databases
  that expose a web surface) and maps versions to **CVE candidates** from
  a local NVD cache
- **Evidence-first accuracy model** (see below) — no guessed detections
- **Findings management** — confidence labels, triage workflow
  (open / confirmed / false positive / fixed, assignee, due date), risk
  score 0–100 per scan and per asset
- **Reports** — DOCX + HTML, marked `CONFIDENTIAL — TLP:AMBER`, with
  Report ID, Document Control, CVSS v3.1 vectors per CWE, reproduction
  steps, and remediation guidance
- **Mobile analysis** — self-built APK analyzer (manifest, permissions,
  exported components, cleartext, secrets patterns, network security
  config) and IPA analyzer
- **One interface everywhere** — the dashboard served by the service
  itself (native and Docker alike) is the full VANTHEX web UI: glass
  Command Deck, posture gauge, live operations, command palette; the
  previous classic UI remains available at `/classic`
- **Platform** — hash-chained (SHA-256) audit log, encrypted secrets
  vault (Fernet) for scan credentials, scan scheduling, webhooks,
  role-based users, 12-language UI with full RTL support, dark/light
  glass dashboard

## Accuracy model

VANTHEX is designed to *not cry wolf*:

- Every finding carries a **confidence label**:
  `confirmed` (hard behavioral evidence), `probable` (strong signals,
  needs manual validation), or `candidate` (version-based lead — all CVE
  matches are candidates, never claimed as confirmed vulnerabilities)
- Detections are **behavior/evidence-based** — no vendor or technology
  is ever claimed from a bare name or substring match
- When the environment cannot support a measurement (blocked egress,
  intercepted network path, missing raw-socket capability), the scan
  says **INCONCLUSIVE** instead of inventing results — an empty result
  is never presented as "target is clean"
- The engine is regression-tested against a ground-truth fixture battery
  (143 automated tests: detection recall + false-positive traps from
  real-world incidents)

## Scan types

| Type | What it does |
|---|---|
| `vulnscan` | Full web application vulnerability scan (profiles below) |
| `ports` | TCP connect port scan with service verification |
| `subdomains` | Subdomain enumeration via DNS-over-HTTPS with wildcard filtering |
| `dirs` | Directory/path discovery with soft-404 (catch-all) baseline filtering |
| `ssl` | TLS audit: certificate parsing, protocol versions, cipher enumeration |
| `headers` | Security response-header audit with score |
| `passive` | Passive recon: DNS, SPF/DMARC, Certificate Transparency, RDAP, robots/sitemap/security.txt, favicon, EXIF, tech profile — public lookups only |
| `udp` | UDP service scan with protocol-response validation |
| `vhost` | Virtual-host enumeration against a random-Host baseline |
| `syn` | Half-open SYN scan (requires raw-socket capability) |
| `hybrid` | Passive recon followed by an active scan, merged & deduplicated |
| `mobile` | Static analysis of an Android APK or iOS IPA (via the Mobile view) |

### Scan profiles (`vulnscan`)

| Profile | Use |
|---|---|
| `passive-quick` | Fast, light-touch checks |
| `passive-full` | Full passive surface mapping |
| `active-standard` | Active checks, standard depth |
| `active-deep` | Active checks, deep crawling & fuzzing |
| `enterprise-full` | All 53 checks, maximum coverage |

## Deployment

VANTHEX runs the same way everywhere — as a single Python service on
port **5000** serving the dashboard, the REST API, and the scan engine.
Choose **Docker Compose** (recommended) or a **native** installation.

### Prerequisites

**For Docker Compose:**

| Requirement | Notes |
|---|---|
| Docker Engine 24+ | `docker version` |
| Docker Compose v2 | the `docker compose` plugin; `docker compose version` |
| ±1 GB disk | image + data volume |
| Port 5000 free | remappable in the compose file |
| Network egress | HTTP/HTTPS to scan targets; HTTPS for DNS-over-HTTPS and the NVD API |

No Python is needed on the host for the Docker route — the image is
based on `python:3.12-slim`.

**For a native installation:**

| Requirement | Notes |
|---|---|
| Python **3.12** (3.11 works) | `python3 --version`; pip + venv (`python3-venv` on Debian/Ubuntu) |
| 1 GB RAM / 1 GB disk minimum | 2 GB RAM recommended; scans are concurrent |
| Port 5000 free | or choose another port at start |
| Network egress | as above |
| CAP_NET_RAW *(optional)* | only for the SYN scan type; without it that scan reports *inconclusive* |
| Linux / macOS / Windows | systemd unit provided for Linux |

All Python dependencies are pinned wheels in `requirements.txt`
(`androguard`, `beautifulsoup4`, `cryptography`, `dnspython`, `lxml`,
`requests`, `python-docx`, `Pillow`, …). **No external scanner
binaries are required or used.**

### Quick start — Docker Compose (build from source)

```bash
git clone https://github.com/<your-user>/vanthex-osp.git
cd vanthex-osp
cp .env.example .env        # set a strong PTK_ADMIN_PW
docker compose up -d --build
docker compose ps           # wait for "healthy"
```

Open <http://localhost:5000> and log in as `admin` with your
`PTK_ADMIN_PW`. All state (SQLite DB incl. the CVE cache, and the vault
key) persists in the `vanthex-data` volume across rebuilds and
upgrades.

### Deploy a prebuilt image (GHCR)

No source tree needed — the image is published by GitHub Actions
(see CI/CD):

```bash
mkdir vanthex && cd vanthex
# place docker-compose.deploy.yml and .env.example here
cp .env.example .env        # set PTK_ADMIN_PW, GHCR_OWNER, GHCR_REPO, VANTHEX_TAG=1.1
docker compose -f docker-compose.deploy.yml pull
docker compose -f docker-compose.deploy.yml up -d
```

Full Docker guide — persistence model, upgrades, networking,
troubleshooting: [DOCKER.md](DOCKER.md).

### Installation — native

```bash
git clone https://github.com/<your-user>/vanthex-osp.git
cd vanthex-osp
python3 -m venv .venv
source .venv/bin/activate           # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export PTK_ADMIN_PW='a-long-random-password'   # Windows: set PTK_ADMIN_PW=...
python app2.py 5000
```

Open <http://localhost:5000> (login `admin` / your `PTK_ADMIN_PW`.
There is no default password: if the variable is unset at first run,
a strong random password is generated and printed once at startup.
The variable only seeds the account when the database is first
created).

**Run as a service (Linux/systemd):**

```bash
sudo bash deploy/install-systemd.sh
systemctl status pentest-toolkit
```

Full native guide — state files, configuration, upgrades,
troubleshooting, uninstall: [INSTALL.md](INSTALL.md).

## Configuration

All configuration is via environment variables:

| Variable | Purpose | Default |
|---|---|---|
| `PTK_ADMIN_PW` | Password of the seeded `admin` user | — (none; random-generated if unset) |
| `PTK_NVD_KEY` | NVD API key for faster CVE cache sync | — |
| `PTK_ALLOWED_TARGETS` | Comma-separated scan-target allowlist (extra guard) | — |
| `PTK_CANARY_BASE` | Public base URL of the OOB canary listener | — |
| `PTK_CANARY_PORT` | Canary listener port | `8977` |
| `PTK_COOKIE_SECURE` | Set `1` to mark session cookies `Secure` (HTTPS deployments) | — |
| `GHCR_OWNER` / `VANTHEX_TAG` | Image owner/tag for `docker-compose.deploy.yml` | — / `latest` |

## CI/CD — GitHub Actions → GHCR

`.github/workflows/docker.yml` builds a multi-arch image
(`linux/amd64` + `linux/arm64`) and publishes it to the GitHub Container
Registry on every push to `main` and every version tag:

| Git event | Image tags |
|---|---|
| Push to `main` | `latest`, `sha-<short>` |
| Tag `v1.2.3` | `1.2.3`, `1.2`, `sha-<short>` |
| Pull request | build only (never published) |

Authentication uses the workflow's built-in `GITHUB_TOKEN`
(`packages: write`) — no extra secrets to configure.

## Architecture

| Module | Role |
|---|---|
| `app2.py` | HTTP server, REST API, job orchestration, typed-scan branches |
| `vulnscan2.py` | Vulnerability-scan engine (checks, tech/CVE inventory, risk score) |
| `scanners.py` | Port/subdomain/dir/TLS/header/UDP/vhost/SYN scanners |
| `netclient.py` | Proxy-aware HTTP client, scheme proofing, caching with taint rules |
| `passive.py` | Passive reconnaissance pack |
| `mobile.py` | APK/IPA static analyzer (sandboxed parsing) |
| `techdb.py` | Technology signature database |
| `nvd.py` | NVD API 2.0 sync into the local CVE cache |
| `store.py` | SQLite persistence, hash-chained audit log, triage |
| `report.py` / `docx_report.py` | HTML / DOCX report generators |
| `secretsmgr.py` | Fernet-encrypted credential vault |
| `canary.py` | Out-of-band (SSRF/blind) callback listener |

## Development & testing

```bash
pip install -r requirements.txt   # includes pytest, coverage, hypothesis
python -m pytest tests/ -q        # 143 tests: battery, honesty, transport, reports…
```

The test suite includes a ground-truth vulnerable-fixture server:
detections must fire where vulnerabilities exist and stay silent on the
safe control endpoints and false-positive traps.

## Documentation

- [DOCKER.md](DOCKER.md) — Docker Compose deployment, persistence, upgrades
- [INSTALL.md](INSTALL.md) — native installation
- [ENTERPRISE_NOTES.md](ENTERPRISE_NOTES.md) — coverage matrix & release history
- [UPGRADE_NOTES.md](UPGRADE_NOTES.md) · [AUDIT.md](AUDIT.md)

## Legal

Use VANTHEX only on systems you own or are explicitly authorized to
test. Unauthorized scanning may be illegal in your jurisdiction.
Provided for professional security assessment and education.

© 2026 VANTHEX. All rights reserved until a license is published.
