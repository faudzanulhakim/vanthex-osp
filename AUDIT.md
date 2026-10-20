# Initial Source Audit — 2026-10-15

Audit of the original `pentest-toolkit.zip` source, performed before the
v3 upgrade. The original files were **not modified**; all fixes were
built in a working copy. This document is kept as the historical record
of what was found and why the upgrade took the shape it did.

## Strengths (retained)

- 100% Python standard library, no external tool dependencies
  (no nmap/nuclei/etc.) — by design.
- Clean separation of passive (observation) vs. active (intrusive)
  checks, with tiered scan profiles.
- Findings already carried severity, CWE, OWASP, CVSS, and remediation.
- The legacy error-based SQLi check already used a verify pattern
  (`'` breaks / `''` recovers), and XSS used a unique marker.
- Login + SQLite history + DOCX/HTML export + live process log.

## Confirmed bugs (reproduced, not conjectured)

1. `report.py:42` used a variable `sev` that was never defined → HTML
   export **always crashed** with `NameError: name 'sev' is not defined`
   (reproduced 2026-10-15).
2. The dashboard scan-detail view was broken: `viewScanDetail()` in
   `templates/app.html` called `renderFindings()` without passing
   `d.findings` from the API → `j.findings` undefined → the detail page
   errored.
3. `MARKER` in `vulnscan2.py` was created once at module import, not per
   scan — every scan in one server process shared the same marker.
4. `store.verify_user` compared password hashes with `==` (not
   `hmac.compare_digest`) and login had no rate limiting → unrestricted
   password brute force.
5. No stop button for running jobs; `JOBS` was never cleaned up; no job
   timeout.

## Accuracy weaknesses (false positives / false negatives)

- **Sensitive files**: checked only `status == 200` plus the absence of
  the words "not found" in the first 60 bytes. SPA/catch-all targets
  that always return 200 produced mass false positives; real files
  whose pages begin with "not found" were missed (false negatives). No
  per-file *content signature* and no soft-404 baseline existed.
- **SQLi**: error-based only, with rigid conditions (must be HTTP 500
  and `''` must return exactly 200). Boolean- and time-based techniques
  were not tested at all → most real SQLi went undetected. After the
  first SQLi hit the function returned immediately → other parameters
  and XSS were never tested.
- **XSS**: a single payload, no context variants (attribute/JS/single
  quote).
- **Discovery**: `discover_paths()` read only `href/action/src="..."`
  (double quotes), at most 14 paths, the rest hardcoded guesses never
  verified to exist — injection was tested against endpoints that often
  did not exist.
- **CORS**: tested only against a `/api` path that might not exist.
- **Cookies**: `Set-Cookie` was read as one combined string; the second
  and later cookies were never analyzed per cookie, and the `SameSite`
  flag was not checked.
- **TLS**: the legacy-protocol detection loop in `scanners.ssl_audit`
  was defective (a dead loop), with no cipher-bit, hostname-mismatch,
  self-signed, or `not_before` checks.
- **Port scan**: banner grabbing was a passive `recv()` only, sending
  no probe — services that wait for a request first (HTTP etc.) always
  showed an empty banner.
- **CVE probes**: a very small list, based on `status == 200` alone →
  false-positive prone, with no product/version matching at all.
- **Finding deduplication by title only** → the same vulnerability on a
  different parameter was silently dropped.

## Coverage that was entirely missing (added in the upgrade)

SSTI, path traversal/LFI, command injection (echo + time), CRLF
injection, SSRF (cloud metadata + internal-fetch oracle), GraphQL
introspection, Swagger/OpenAPI exposure, CSRF (POST forms without a
token), JWT analysis (alg=none, weak secrets via a small wordlist,
missing `exp`), weak CSP/HSTS quality, technology fingerprinting +
version-based CVE candidates (labeled *candidate*, never claimed as
confirmed), unauthenticated service APIs (Docker 2375, Elasticsearch
9200, kubelet 10250), additional ports/services, soft-404 baseline,
per-finding confidence levels, per-finding location + parameter, a real
crawler (forms, JS endpoints, robots/sitemap), authenticated scans
(custom header/cookie), stop/cancel for scans, an authorization gate +
optional allowlist, scan-to-scan diff, and JSON/CSV export.
