# UPGRADE NOTES — Pentest Toolkit v2 → v3 (2026-10-15)

Historical record of the v2 → v3 upgrade. The original files were not
modified; the upgrade was built as a working copy. The design principle
was preserved in full: **self-built engine, no ready-made scanner tools**
(nmap/nuclei/etc. are never invoked — every check is implemented
natively).

## Bugs fixed (proven — see AUDIT.md)

1. HTML report export **always crashed** (`NameError: sev` in
   `report.py`) → fixed; reports now also show confidence and location.
2. **The dashboard scan-detail page was broken** (findings were not
   passed to the renderer) → fixed.
3. XSS/SQLi markers were created **once per server process** → now
   **unique per scan**.
4. Password hash comparison `==` → `hmac.compare_digest`, plus a dummy
   pbkdf2 run for unknown users (timing equalization).
5. A limited (passive) crawl previously **locked out** the full crawl in
   the same scan → crawl caches are now separated by depth.
6. Legacy TLS detection in `ssl_audit` rewritten (dead loop removed),
   plus standard certificate verification, cipher bits, SAN, and
   `not_before` checks.

## Accuracy (false positives / false negatives)

- **Per-target soft-404 baseline**: one request to a certainly
  nonexistent random path becomes the reference; every path-discovery
  check (sensitive files, admin panels, API docs, actuator, phpMyAdmin)
  must pass this filter.
- **Sensitive files must pass a per-type content signature** (e.g.
  `.env` must match a `KEY=value`/`DB_*` pattern, `.git/HEAD` must read
  `ref: refs/`, SQL dumps must contain `CREATE TABLE`/`INSERT INTO`) —
  an HTTP 200 alone is no longer sufficient. Verified: an SPA
  catch-all-200 fixture produces **0** sensitive-file findings.
- **Three-layer SQLi**: error-based (expanded DB signatures, compared
  against baseline) → boolean-based (TRUE/FALSE body-similarity
  measurement) → time-based (delay ≥ 2.6 s, confirmed twice, max 3
  parameters). A finding on one parameter **no longer stops** testing
  of other parameters or techniques.
- **Multi-context XSS** (4 payloads: double-quote, single-quote, bare,
  img) — the payload must be reflected *intact*.
- **Anti-reflection command injection**: the marker must appear
  **without** the payload itself being reflected (verbatim reflection
  is not execution; this suppresses false positives on naturally
  reflective parameters).
- **CORS** tested on the root and on crawled API endpoints, including
  the `null` origin with credentials and wildcard-with-credentials.
- **Cookies analyzed per item** (previously one combined string):
  Secure/HttpOnly/SameSite per cookie.
- **Deduplication per (title + location + parameter)** — the same
  vulnerability on a different parameter is no longer dropped.
- **Per-finding confidence**: `confirmed` (passed automatic
  verification) / `probable` (strong indication) / `candidate`
  (version-based suspicion — CVE candidates are **always** candidate,
  never claimed as confirmed).
- **Proxy egress support** (`netclient.py`): honors the
  `HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY` environment, the Proxy field in
  the UI, or `PTK_PROXY`. On networks where egress requires a proxy,
  v2 was completely blind to internet targets; v3 is not. Port scans
  and TLS audits remain direct connections (noted in the scan log and
  README).

## New coverage

| Area | New checks |
|---|---|
| Injection | SSTI (computed result verified), Path Traversal/LFI (`/etc/passwd` & `win.ini` signatures), Command Injection (verified echo + time), CRLF/Response Splitting (injected header proven) |
| SSRF | Cloud metadata `169.254.169.254` (signature) + internal-fetch oracle via `127.0.0.1` (internal homepage title) |
| API | Swagger/OpenAPI/ReDoc exposure (signature), **GraphQL introspection** (a real `__schema` query) |
| Auth | **JWT analysis**: alg=none, weak HMAC secrets (small wordlist, cryptographically verified), missing `exp`; **CSRF**: POST forms without a token |
| Services | Expanded ports (Docker 2375, etcd 2379, ES 9200/9300, kubelet 10250, Kibana 5601, RabbitMQ 15672, …) + **unauthenticated-API verification** for Docker/ES/etcd/kubelet; banner grabbing now sends probes |
| Fingerprint | Technology + version (Apache/nginx/IIS/Jetty/Tomcat/PHP/WordPress/Joomla/Drupal) → **version-based CVE candidates** + a dedicated confirmation probe for CVE-2021-41773 (Apache 2.4.49/2.4.50) |
| TLS | CA/hostname verification, ciphers < 128-bit, SAN not covering the host, legacy TLS 1.0/1.1 (pinned handshake) |
| Headers | CSP quality (unsafe-inline/eval/wildcard) & weak HSTS max-age; HSTS is no longer reported missing on pure-HTTP targets (noise) |
| Discovery | **A real crawler**: same-host BFS, forms (action/method/input), API endpoints from JS files, `robots.txt` Disallow, `sitemap.xml`; guessed endpoints are used only when proven alive |

Profiles: `passive-quick` (3 checks), `passive-full` (6),
`active-standard` (14), `active-deep` (20 checks).

## Dashboard & server (app2.py v3)

- **The classic tools are alive again** as their own scan types, stored
  in history: Port Scan, Subdomain Enum, Dir Discovery, SSL Audit,
  Header Audit (in v2 only vulnscan could run from the UI).
- **Stop button** for running jobs (the engine stops cleanly between
  checks and between parameters); finished jobs are cleaned up
  periodically.
- **Authorization gate**: active scans are refused server-side
  (HTTP 400) without `authorized=true` from the authorization checkbox
  in the UI. Optional host allowlist via `PTK_ALLOWED_TARGETS`
  (exact host / `*.domain` / domain suffix).
- **Login rate limiting** per IP (5 failures / 5 minutes → 60-second
  lock, HTTP 429).
- **Authenticated scans**: session cookie + extra headers (e.g.
  `Authorization: Bearer`) from the UI — never stored in the database.
- Per-scan options: timeout, maximum crawl pages, proxy.
- **JSON & CSV finding export** per scan; **scan diff** (new /
  resolved / unchanged) against the previous scan with the same target
  + profile.
- Dashboard: unique-target cards, findings by confidence, finding
  filters in the detail view, search + risk filters in history,
  confidence badges and location/parameter on every finding.
- v2 databases **remain readable**: the `confidence`/`location`/`param`
  columns are added automatically (ALTER migration).

## Verification (evidence, 2026-10-15)

- `tests/test_smoke.py` — local vulnerable fixture target
  (`tests/fixture_vuln_server.py`): active-deep found **37 findings**
  including error/time SQLi, XSS, SSTI, LFI, CMDi (verified echo on
  /ping), open redirect, CORS, CSRF, weak JWT secret `'secret'`,
  GraphQL introspection, OpenAPI, signature-verified sensitive files,
  and a CVE-2021-41773 candidate. SPA fixture: **0 sensitive-file false
  positives**. All assertions PASSED.
- App E2E: wrong login 401 / correct login 200, authorization gate 400,
  passive job completed, HTML report 200 (previously crashed), valid
  DOCX (PK), CSV export 200, diff 200, Headers tool ran, **cancel →
  status cancelled**.
- Real in-scope target (`http://demo.testfire.net`, passive-full, via
  proxy): **8 confirmed findings** — missing CSP & X-Frame-Options
  (consistent with nikto findings of 2026-10-15), `Server:
  Apache-Coyote/1.1` disclosure, `JSESSIONID` cookie without SameSite,
  etc. (v2/v3 without a proxy on that network: only 1 INFO finding,
  because direct connections were refused at egress.)

## Honest limitations

- Time-based checks are parameter-capped so scan duration does not
  explode; SQLi on the 15th+ parameter can be missed.
- CVE candidates come from fingerprinted versions only — patch level
  (distribution backports) is not visible from a version string alone.
- Port scans / TLS over direct sockets: on proxy-mandatory networks
  these can return empty while web checks work normally — the scan log
  states this explicitly.
- SSRF without an OOB server: only proven cases are reported (metadata
  signature / internal-fetch oracle); blind SSRF cannot be confirmed
  without a collaborator listener.

## Addendum v3.1 — Enterprise (2026-10-15)

An enterprise layer was added on top of v3 without changing its
accuracy principles: the `enterprise-full` profile (34 checks), XXE/
LDAP/NoSQL coverage, IDOR/BOLA, confirmed unauthenticated upload,
default Basic Auth credentials, login rate-limit testing, PII-leaking
APIs, outdated JS libraries + source maps, SRI/session-in-URL, verbose
errors, deserialization surface, SPF/DMARC via DNS-over-HTTPS,
subdomain takeover, a 0–100 Risk Score per scan, and an OWASP Coverage
panel on the dashboard. The full matrix and the honestly-not-covered
list: see `ENTERPRISE_NOTES.md`. Verification: local fixture
enterprise-full = 64 findings (34/34 checks), SPA still 0 sensitive-file
false positives; dashboard E2E passed; passive testfire.net 8 findings,
risk score 26, and the email checks did not falsely accuse
(SPF/DMARC on testfire.net is healthy).

## Addendum v3.2 — Company Standard (2026-10-15)

The dashboard was expanded into a vulnerability-management platform
(Findings + triage, Assets, Schedules with a server-side scheduler,
Audit Log, Users, bulk scans, rescan, posture score, SVG donut &
trend). Engine at 41 checks (WAF, DOM XSS, UNION SQLi, statistical
anti-FP time-based checks, cache/reset poisoning, session fixation,
WordPress plugin enumeration, source disclosure, a verification pass,
WAF/rate-limit warnings). DOCX/HTML reports standardized to a
professional pentest format (Document Control, Methodology, F-IDs,
Roadmap, Appendices; `PTK_COMPANY` environment variable for the company
name). Details: `ENTERPRISE_NOTES.md`.
