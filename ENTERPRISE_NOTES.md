# ENTERPRISE NOTES — VANTHEX (coverage matrix & release history)

The enterprise layer on top of v3: coverage extended across the full severity
spectrum **LOW → CRITICAL** and mapped to **OWASP Top 10 2021 + API Security Top 10**,
with a new profile **`enterprise-full`** (34 checks) and a **Risk Score 0–100** on the dashboard.
The v3 accuracy principle is unchanged: layered verification first, claims afterwards —
confidence `confirmed / probable / candidate` on every finding.

## Coverage matrix (check → OWASP → severity range)

| Area | Check | OWASP | Severity |
|---|---|---|---|
| SQL Injection (error/boolean/time) | `c_web_injection` | A03 Injection | CRITICAL |
| XSS reflected multi-context | `c_web_injection` | A03 | HIGH |
| SSTI | `c_web_injection` | A03 | CRITICAL |
| Command Injection (echo/time) | `c_web_injection` | A03 | CRITICAL |
| Path Traversal / LFI | `c_web_injection` | A01 | CRITICAL |
| **XXE** (expanded entities, passwd signature) | `c_web_injection` | A05 | CRITICAL |
| **LDAP Injection** (LDAP error signature) | `c_web_injection` | A03 | HIGH (probable) |
| **NoSQL Injection** ($gt/$ne operators, param + JSON API) | `c_web_injection`, `c_nosql_api` | A03 / API8 | HIGH |
| CRLF / Response Splitting | `c_crlf_injection` | A03 | HIGH |
| SSRF (cloud metadata + internal oracle) | `c_ssrf` | A10 | CRITICAL–HIGH |
| **IDOR / BOLA** (neighboring objects without auth) | `c_broken_access_idor` | A01 / API1 | HIGH (probable) |
| **Upload without authentication** (benign probe served back) | `c_upload_surface` | A01 | HIGH confirmed / MEDIUM form |
| **Default Basic Auth credentials** (8 common pairs) | `c_default_credentials` | A07 | CRITICAL |
| **Login without rate-limit** (6 failed attempts, unregistered user) | `c_rate_limit_login` | A07 | MEDIUM (probable) |
| JWT (alg=none, cryptographically weak secret, no exp) | `c_jwt_analysis` | A07 | CRITICAL–MEDIUM |
| Login over plain HTTP, session in URL, autocomplete | `c_auth_surface`, `c_sri_and_session` | A02/A07 | HIGH–LOW |
| Sensitive files & backup archives (signature mandatory) | `c_sensitive_files` | A05 | CRITICAL–LOW |
| Directory listing, admin panel, actuator | `c_directory_listing`, `c_admin_panels`, `c_cve_candidates` | A05 | HIGH–MEDIUM |
| Verbose error / stack trace | `c_error_disclosure` | A05 | MEDIUM (probable) |
| Security headers + CSP/HSTS quality | `c_security_headers` | A05/A02 | MEDIUM–LOW |
| Per-item cookies (Secure/HttpOnly/SameSite) | `c_cookie_security` | A05 | MEDIUM–LOW |
| CORS (origin echo, null+credentials, wildcard+credentials) | `c_cors` | A05 | HIGH–MEDIUM |
| HTTP methods, TRACE/XST, **WebDAV PROPFIND** | `c_http_methods` | A05 | MEDIUM |
| Open Redirect | `c_open_redirect` | A01 | HIGH |
| CSRF (POST form without token) | `c_csrf_forms` | A01 | MEDIUM (probable) |
| GraphQL introspection, Swagger/OpenAPI exposure | `c_api_exposure` | A05 | HIGH–MEDIUM |
| **API leaking sensitive fields/PII without auth** | `c_api_sensitive_data` | API3 | HIGH–MEDIUM |
| TLS (verify, legacy 1.0/1.1, cipher <128, SAN, expiry) | `c_tls` | A02 | CRITICAL–MEDIUM |
| Risky ports & services + unauthenticated API services | `c_services` | A05 | CRITICAL–LOW |
| Technology fingerprint + version CVE candidates | `c_tech_fingerprint`, `c_cve_candidates` | A06 | CRITICAL–INFO (candidate) |
| **Outdated JS libraries** (jQuery/Bootstrap/AngularJS/Lodash) | `c_js_libraries` | A06 | MEDIUM (candidate) |
| **Exposed source maps** (sourcesContent) | `c_js_libraries` | A05 | HIGH |
| **Missing SRI / mixed content** | `c_sri_and_session` | A08/A02 | MEDIUM–LOW |
| **Serialized data** (Java/PHP/ViewState) | `c_deserialization_surface` | A08 | LOW (candidate) |
| **Domain SPF/DMARC** (via DNS-over-HTTPS) | `c_email_security` | A07 | MEDIUM–LOW |
| **Subdomain takeover** (orphaned CNAME + service signature) | `c_subdomain_takeover` | A05 | HIGH (probable) |
| security.txt absent, robots.txt leaking paths | `c_security_txt_robots` | A05 | INFO–LOW |
| Host-header injection | `c_host_header` | A05 | MEDIUM |

## Profiles
- `passive-quick` 3 checks · `passive-full` 7 checks (including domain email posture)
- `active-standard` 22 checks · `active-deep` 27 checks
- **`enterprise-full` 34 checks** — all of the above + default credentials, login rate-limit
  tests, subdomain takeover. Most intrusive: use only with written scope.

## Risk Score
Score 0–100 per scan = Σ(severity weight × confidence factor), shown as a
badge in scan results & detail, and stored with the scan. The dashboard now also
shows an **OWASP Coverage** panel (aggregation of all findings per OWASP category).

## v3.1 verification (2026-10-15)
- Local fixture smoke test: **enterprise-full found 64 findings, 34/34 checks ran,
  risk score 100/100** — all new categories caught (XXE, IDOR, NoSQL API,
  default credentials `tomcat:tomcat`, confirmed unauthenticated upload, absent rate-limit,
  error disclosure, jQuery 1.11.1, source map, session-in-URL, login-over-HTTP,
  API leaking `password_hash`, deserialization surface, SRI, robots, security.txt).
  The SPA catch-all fixture still produced **0 false positives** for sensitive files.
- Dashboard E2E: the enterprise authorization gate returns 400 without the checkbox; the enterprise job
  finished in 28.6 s; risk score stored & shown in detail; OWASP statistics aggregated (13 categories).
- Real in-scope target (`demo.testfire.net`, passive-full): 8 confirmed findings,
  risk score 26/100 — and the email check **correctly did not accuse** testfire.net:
  its SPF/DMARC are genuinely healthy (DMARC `p=reject` verified via DoH).

## What is honestly NOT covered (and why)
- **Full blind SSRF / blind out-of-band SQLi** needs a collaborator listener (OOB) — not yet present;
  only in-band proven results are reported.
- **Definitive stored XSS & cross-account IDOR** need two test accounts + per-application stateful flows;
  the toolkit provides probable indicators, manual verification remains mandatory.
- **HTTP request smuggling** is deliberately not auto-tested (risk of disturbing shared backends, high FP).
- **Active Directory / internal Windows networks** are outside this web tool's reach
  (that is the domain of the external-tool-based bug bounty lab).
- The email check assesses the organization domain from a suffix heuristic (not a full PSL).

## Addendum v3.2 — Large-enterprise standard (2026-10-15)
- **Engine 41 checks**: + WAF detection (accuracy context), DOM XSS (static source→sink
  analysis in JS files), UNION-based SQLi (column counting), statistical time-based (median of 3 baselines +
  unstable-baseline guard against FP), file:// scheme SSRF, Web Cache Poisoning
  (baseline→poison→verify sequence), Password Reset Poisoning, Session Fixation,
  WordPress plugin enumeration (readme Stable tag → CVE threshold), per-page source/backup disclosure,
  and a **verification pass** (Confirmed exposure findings are re-requested;
  ones that do not reproduce are downgraded to Probable) + scan health warnings
  (403/429 block ratio > 20% = results may be suppressed by a WAF).
- **Platform**: finding triage (Open/Confirmed/False Positive/Fixed), Assets per target
  (latest risk & score, open findings), **scheduled scans** (server scheduler), activity audit log,
  user management from the UI, multi-target bulk scan, Rescan button, dashboard
  with Posture Score, severity donut, 14-day trend, top targets & latest findings feed.
- **Professional pentest-standard reports** (DOCX & HTML aligned): cover + classification
  CONFIDENTIAL — TLP:AMBER, Report ID `RPT-<date>-<id>`, Document Control, Executive
  Summary, Scope & Methodology (OWASP WSTG/ASVS, PTES, CVSS v3.1, confidence model,
  limitations), Findings Summary & Detail with F-001… IDs, Remediation Roadmap P1–P4
  with SLAs, Appendix Risk Rating Methodology & Assessment Metadata. The company name on
  reports can be set via the `PTK_COMPANY` env var.
- v3.2 verification: smoke fixture **41/41 checks, 76 findings** (new categories: UNION SQLi,
  DOM XSS, WP File Manager 6.8, source disclosure, reset poisoning, session fixation,
  cache poisoning; WAF *not* FP on the clean fixture), SPA still 0 sensitive-file FP;
  full dashboard E2E (triage status, assets, trend/posture statistics, audit, users,
  scheduler executing real periodic scans, DOCX 12 structural elements verified);
  passive testfire.net still 8 findings, score 26, no block warnings.

## Hotfix v3.2.1 — Mass Command Injection false positives (2026-10-15)
A real case reported from a real internal UAT application (SPA): dozens of
"verified Command Injection" CRITICAL findings at locations/parameter names that were
minified JavaScript fragments (`appendChild`, `createElement`, `SRC_ELEMENT_ATT_REGEX`).
Dual root cause:
1. The crawler crawled `.js` files as HTML pages and then parsed link regexes
   from minified code -> garbage URLs & parameters from code fragments.
2. The SPA answers every path with the same shell + reflects the request URI
   in URL-encoded form; the CMDi anti-reflection test that compared the payload
   verbatim was fooled (the marker passed, the full payload did not string-match).
Fixes:
- `.js/.css/.map` files are never crawled as pages; responses with JavaScript/CSS
  content types have no links/params extracted from them.
- Parameter target sanity validation: strict path charset (no parentheses/quotes/spaces/
  backslashes), parameter names must be reasonable identifiers, static asset paths rejected.
- Catch-all gate in the injection suite: parameters whose response is identical to the
  soft-404 shell and unaffected by random values are skipped entirely.
- CMDi now prioritizes computation evidence `$((a*b))` (the result is not in the request —
  impossible to fake via reflection), and the anti-reflection check examines the normalized
  form (URL-decoded + HTML-unescaped).
Regression: the fixture was equipped with a trap replicating this exact pattern (a JS bundle
with a `src=` trap + a catch-all /static/* echoing the encoded URI); the smoke test
ensures no findings come from JS fragments and all legitimate categories are still detected
(41/41 checks). Old findings from affected scans must be considered NOT valid:
delete those scans or mark them False Positive, then Rescan with v3.2.1.

## v3.2.2 — Port scan accuracy (FP incident #2, 2026-10-16)

Incident: an enterprise-full vulnscan from the Muse VM to a UAT application (SPA) reported
27 "confirmed" CRITICAL/HIGH port findings (Telnet, Redis, MongoDB, Docker API,
SMB, RDP, VNC, PostgreSQL, MySQL, ...) — ALL false positives. Ground truth
from the operator (nmap from Kali + docker ps): from the internet only 443 & 8008 are open.

Root cause: direct TCP connections from the Muse VM are intercepted by the runtime sandbox
gateway — connecting to any port "succeeds" and is answered with the text banner
"muse: ... connections is turned off for this assistant ...". The connection
never reaches the target. The old scanner treated any connect+banner
as service evidence (that gateway text was even stored as evidence).

Fixes:
- Per-service protocol verification probes in scanners.py: a service claim MUST
  pass the genuine signature (SSH "SSH-", VNC "RFB", Redis PING->+PONG/-NOAUTH,
  PostgreSQL SSLRequest->S/N, MySQL greeting, RDP X.224, MSSQL TDS prelogin,
  MongoDB identity text, LDAP bind, NFS RPC, PPTP magic cookie, TLS handshake,
  HTTP "HTTP/" including the non-standard-port fallback).
- Connect alone -> verified=False: unverified risky ports become only
  ONE grouped LOW candidate finding, never confirmed per service.
- Interceptor detection: a known gateway banner OR an identical banner on
  >=60% of open ports with none verified -> the entire port scan is
  declared INCONCLUSIVE (1 INFO finding), zero port findings.
- Unauthenticated HTTP API probes (Docker/ES/etcd/kubelet) now run only
  for ports verified as HTTP.
- The "ports" scan type includes the intercepted flag + the verified list.

Verification: unit tests 24/24 (signatures, probes, interceptor, local protocol server
integration); smoke fixture ALL PASS (41/41 checks); live from the same VM
to the same target: portscan API -> intercepted=True, 0 verified;
active-deep vulnscan -> 0 port findings, exactly 1 inconclusive INFO; localhost fixture
port 8899 -> HTTP verified, closed ports absent. The 27 FP findings from
the old scan were marked false_positive on the installed instance (1 honest TLS INFO
remains open).

Permanent rule: port scans are only valid from a vantage point without an interceptor;
from the Muse VM the results are always inconclusive — and now the scanner says so
itself, instead of fabricating findings.

## v3.3.0 — Mobile Apps (APK) + Modern Libraries (2026-10-16)

Decision (2026-10-16): STILL no ready-made scanner tools (nmap/nuclei
are not invoked) — a self-built engine — but third-party libraries
commonly used to build OTHER pentest applications are now used as raw
material (previously pure stdlib). Project venv in .venv (requirements.txt):
androguard 4.1.4, requests, beautifulsoup4, lxml, cryptography, dnspython.

New:
- mobile.py — a self-built static APK analyzer (OWASP MASVS mapping):
  debuggable, allowBackup (+default target<=30), cleartext (precedence:
  network security config > manifest attribute > default target<28), dangerous
  permissions (grouped, severity from the most sensitive), exported components without
  protection (default rules per targetSdk; launcher excepted), http deep links,
  embedded secrets (AWS key, Google API key, private key, JWT — probable,
  masked evidence; generic patterns = candidate), Firebase URLs, HTTP endpoints,
  addJavascriptInterface/ECB indications (candidate), certificates (not
  signed, debug cert, expired, weak hash, v1-only/Janus), lagging target/
  min SDK. API endpoints are extracted from DEX/assets (schema/namespace
  hosts filtered) and can be scanned further from the dashboard.
- Route POST /api/mobile/analyze (base64 JSON, max 60 MB): the APK is analyzed
  as a job, stored as a "mobile" scan type — findings enter the same
  Findings/triage/DOCX/HTML report pipeline; the APK file is deleted after
  analysis (what is stored is the SHA-256 hash + results).
- Service dashboard: Mobile Apps tab (upload, live log, app profile,
  permission chips, endpoint table + "Scan this API" button, history, mobile-specific
  detail in Scan Detail; the rescan icon is hidden for mobile scans).
- Web crawler: link/form extraction now uses a real HTML parser
  (BeautifulSoup) when available — <script>/<style>/comment text can no
  longer be read as attributes (suppressing the FP class of incident #1); the old regex becomes
  a fallback identical to v3.2.2.

Verification: tests/test_mobile.py 24/24 (official androguard repo fixture APK
with independently verified ground truth: TestActivity debuggable,
a2dp.Vol permission/receive-SMS/backup/endpoint, repacked APK with AWS/
Firebase markers, synthetic exported-rule units; a real bug found & fixed
during testing: the URL regex melted neighboring DEX strings across \x00 —
the charset is now limited to printable). Web smoke ALL PASS (41/41, SPA anti-FP
intact) with the bs4 crawler active; port-verify 24/24 still passing. Live service E2E
(venv): a2dp analysis 9 HIGH findings score 53, TestActivity debuggable
caught, detail+meta stored, valid CONFIDENTIAL HTML report & DOCX
for a mobile scan, service log clean of androguard debug output.

Honest limit: mobile analysis is STATIC. Runtime/dynamic testing (Frida,
interception from a device/emulator) is not included and not claimed.

### Addendum v3.3.0 — build tooling (2026-10-16)
At the operator's request, added to the build: pytest 9.1.1, coverage 7.16.2,
hypothesis 6.170.0, defusedxml 0.7.1, psutil 7.2.2 (requirements.txt).
- defusedxml is genuinely used: untrusted manifests & XML from APKs are parsed
  with defusedxml (anti XXE/billion-laughs against the analyzer itself).
- psutil is genuinely used: /api/stats now carries a "system" block (app uptime,
  process memory, host CPU & memory, active job count) for the dashboard.
- The test suite is now pytest: 16 tests passing (mobile units 5, port-verify 4,
  hypothesis property-based 6 — invariants: the signature matcher never
  crashes on random bytes, secret masking never leaks the middle portion,
  the interceptor banner is always detected; web smoke wrapper 1). Measured
  coverage (unit): mobile.py 79%, scanners.py 40% — the web smoke runs as a
  subprocess so the vulnscan2/crawler lines it exercises do not count
  in this figure.

## v3.4.0 — Measured accuracy (ground-truth battery) + advanced enterprise dashboard
Operator request: an "industry-scale" dashboard and scanning "as accurate as possible
with no misses and no bugs". Honesty note: no scanner in the world can
guarantee ZERO misses/ZERO bugs absolutely — what can be done (and is done
in this version) is to MEASURE accuracy with controlled ground truth and
fix every defect that measurement reveals.

### Ground-truth battery (tests/test_battery.py, part of the pytest suite)
The fixture was extended in both directions: new POSITIVE controls (/fetch SSRF oracle + file://,
/echohdr CRLF, X-Forwarded-Host reflection, /admin/login, FIXTURE_MODE=waf
in the style of Cloudflare) and NEGATIVE controls, patched /safe/* endpoints (escaped search,
prepared-statement item, validated redirect, allowlist fetch). The battery
asserts 43 mandatory categories caught + zero injection findings on /safe/* + WAF
detected only in waf mode. Three real defects found & fixed:
1. c_crlf_injection TOTALLY DEAD: the payload was sent already encoded (%0d%0a)
   while req_param re-quotes -> double-encode, the CRLF was never
   sent. The payload is now raw CRLF. This check could never produce a
   finding before this fix.
2. param_targets cut sources unfairly: the limit was filled by GET URLs
   first so POST forms (including the XML endpoint for XXE) were never
   tested on parameter-rich sites. Now a round-robin combination across sources +
   the injection suite budget 14 -> 30; CRLF & error-disclosure limits 6 -> 14.
3. The fixture XXE simulation was catch-all on every path (a fixture artifact
   that masked FPs once patched endpoints existed) -> now only the /xml endpoint.
Result: battery green (71 findings on the vulnerable fixture, all categories caught).
Honestly measured coverage (in-process): vulnscan2 82%, crawler 73%, mobile 79%,
total suite 18 pytest tests passing.

### Advanced enterprise dashboard
- /api/insights: remediation SLA compliance (CRITICAL 7 days, HIGH 30, MEDIUM 90,
  LOW 180 — overdue computed from finding age & due date), MTTR per severity,
  risk score trend per asset (chart on the dashboard + overdue badge in Findings).
- Findings: assignee + due date editable (POST /api/finding/update;
  status_changed_at recorded for MTTR).
- Assets: criticality (critical/high/medium/low) + owner per asset
  (POST /api/assets/meta, admin).
- Webhook: URL set by admin (settings); scan completion -> POST JSON when there are
  NEW CRITICAL/HIGH findings compared to the target's previous scan (web, mobile,
  or scheduled).
- API tokens: admin creates tokens (shown once, stored as a SHA-256
  hash); programmatic access via Authorization: Bearer ptk_...; revocable.
All verified live E2E (token accepted/rejected after revocation, webhook
received 11 new critical findings from a fixture scan, MTTR computed, test data
cleaned up).

## v3.4.1 — F5 WAF FP fix + industry/HackerOne-standard reports
Third FP incident (reported from real use): a GeneXus application
behind nginx was accused of "WAF detected: F5 BIG-IP". Root cause
proven from the target's actual bytes: the old F5 pattern r"f5" matched the substring "f5"
in a random GeneXus hex token (gx ajax_key "38ff6460ffff59ff..."). Fix:
WAF signatures rewritten as STRONG per-vendor indicators, separated header
vs body (BIGipServer/TS-ASM cookies & distinctive headers for F5; cf-ray for
Cloudflare; x-amzn-trace-id ALB is NO LONGER evidence of AWS WAF; bare vendor
names in the body are forbidden), evidence now records the exact indicator (header/snippet).
Regression locked in three layers: tests/test_waf.py (8 tests, including the
GeneXus corpus), hex-token + vendor-name traps in the battery fixture, and matcher
verification on the live target's bytes -> None (FP gone), while the fixture waf
mode is still detected. The FP finding in the affected scan has been marked
false_positive.
Reports (report.py + docx_report.py + shared module report_common.py) raised to
industry/platform standard: representative CVSS v3.1 vector per CWE on every
finding, HackerOne-style Reproduction Steps, PoC request skeleton, per-CWE-class
specific impact, references (CWE/WSTG/FIRST), risk matrix in the
executive summary (both formats), Document Control + version history +
distribution, Appendix C containing a HackerOne/Bugcrowd-ready submission block per
finding; the DOCX now has a classification header & page-number footer (PAGE/
NUMPAGES) and a real Word Table of Contents field. Verified:
tests/test_reports.py (structure + OOXML validity of all parts) and real report
exports from a production scan in both formats.

## v3.5.0 — Behavioral WAF (anti-guessing) + Technology & Integration Profiler
Operator requirements: (1) "the WAF must not be guessed" — WAF detection
rewritten as a BEHAVIOR test: attack payloads (XSS/SQLi/LFI) and benign controls
are sent to a ghost path that certainly does not exist in the application; a WAF is declared
CONFIRMED only when >=2 attack classes are blocked AND all controls pass
(differential blocking evidence). Vendor names are now only a separate "indication"
(prob probable) from distinctive vendor artifacts, never the basis for claiming
the existence of a WAF. The verdict is a pure unit-tested function. The fixture waf mode
was adjusted: specific blocking patterns (a real WAF does not block single punctuation marks).
(2) "A scan can see from a URL what applications are installed & integrated" —
module techdb.py: a self-built technology signature database (80+ entries)
mapping response artifacts (headers, cookie names, HTML, script src) to Web
Server, Runtime, Framework, CMS, E-commerce, JS Library/Framework, UI,
Analytics, Tag Manager, Chat/Support, Payment (including Midtrans, Xendit,
DOKU), CAPTCHA, Auth/SSO (Keycloak, Auth0, Firebase, Supabase), Maps, Media —
each detection carries evidence. Results flow into an INFO summary finding, the
tech_profile field of the scan result, the dashboard detail panel (chips per category + evidence
tooltips), the Technology Profile table in DOCX/HTML reports, and remain the source
of CVE candidates. The anti-FP rule applies here too: weak hints are not claims
(GeneXus requires the GXSESSION cookie / "gx ajax_key" JSON / GeneXus text —
a random hex token alone is not enough).
Verification: suite 38 tests green (behavior verdict 4 scenarios, profiler 6
tests, battery carries profiler assertions + zero WAF accusations on the clean fixture).
Live proof on the internal UAT application itself: the profiler read GeneXus
(evidence "GX_AJAX_KEY"), Java Servlet (JSESSIONID cookie), nginx — exactly
its real stack; behavioral WAF test: 0/3 attacks blocked, 0 controls blocked,
no vendor artifacts -> NO WAF finding (silence, not guessing).

## v3.5.1 — Formal report format to international standard
Per the operator's assessment ("the report document looks poor"), both generators were
rewritten in appearance (content & data structure unchanged): professional security-firm
style — an official cover page with top/bottom classification bands and
a meta table, Document Control + a separate Version History table, a table of
contents (anchors in HTML; a Word TOC field with numbered Heading1/Heading2 in DOCX),
numbered section headings with navy rules, navy table headers + zebra striping,
finding details as numbered sub-chapters 4.N with standard sub-headings
(Description/Evidence/Reproduction Steps/Proof of Concept/Impact/
Remediation/References), lightly shaded monospace evidence & PoC blocks
(print-friendly), a running header + page-number footer, a muted formal color
palette, and NO emoji/non-formal decoration in the document (confidence &
status are now plain text: Confirmed/Probable/Candidate, Open/Fixed/False
Positive). Print-ready A4 HTML with @page margin boxes (header/footer +
"Page X of Y", cover without page number).
Real visual QA: a report from a production mobile scan was rendered via LibreOffice —
clean formal cover, tidy Document Control & Risk Matrix, 12 pages;
tests/test_reports.py now also locks the absence of emoji & the formal markers.

## v3.5.2 — Formal enterprise web appearance
Operator request: the web appearance tidied into a formal official style. The service
dashboard (templates/app.html + login.html) was overhauled from a gradient indigo/violet dark
theme into a formal LIGHT theme aligned with the v3.5.1 report design language:
background #E9EDF2, white panels, navy accent
#16365C, muted severities (#9B2226/#C05621/#975A16/#4A5568/#2B6CB0), border
#D8DEE7, small radii, no gradients at all, and every emoji across
navigation/cards/buttons/labels swept clean (the logo became a navy "PT" monogram;
severity icons on statistic cards became colored typographic dots).
The scan/mobile log console is now a light monospace block. Login page: a white
card with a navy top rule, uppercase labels, footer "CONFIDENTIAL —
AUTHORIZED ACCESS ONLY". Functions & flows unchanged — purely visual.
Verified live: login & dashboard served with the new palette, zero
pictograms, zero gradients. The chat artifact tab was aligned by the builder with
the same design language.

## v3.6.0 — Detail appearance, accuracy transparency, security hardening
1. Richer detail appearance: the scan detail page (dashboard + artifact)
   now shows Scan Metadata (profile, duration, checks run,
   total HTTP requests, number blocked 403/429, status code distribution)
   and a collapsible "Check Coverage" table per module.
2. Accuracy & transparency: the engine records checks_detail (check name,
   ok/error/cancelled status, finding count, duration) into the scan result;
   the detail endpoint exposes it via the engine object. The battery locks
   its completeness (41/41 recorded, all ok on the fixture). A recon audit
   confirmed what was suspected weak was already strong: time-based
   SQLi uses a median of 3 samples + double confirmation; JS endpoint mining is already
   wired (DOM XSS/discovery/API); JWT analysis verified firing
   on the fixture ("weak JWT HMAC secret", "JWT without exp claim").
3. Application security tightened: per-route body size limits (413 —
   JSON 2 MB, APK analysis 100 MB) close the memory-exhaustion gap;
   CSP gained frame-ancestors 'none', object-src 'none', base-uri,
   form-action; Referrer-Policy: no-referrer and Permissions-Policy headers;
   Cache-Control: no-store on all API JSON responses. The baseline that
   was already strong is retained: PBKDF2 200k + compare_digest + dummy-hash,
   HttpOnly SameSite=Strict cookies, login throttle 5x/300 s -> 60 s lock
   (429), login_failed audit. tests/test_security.py (isolated test
   server) locks all of the above behavior; full suite 42 green.

## v3.7.0 — Expert depth + modern interactive UI
Engine (43 checks in enterprise-full):
- Active technology verification: stacks detected by techdb are proven via distinctive
  endpoint probes (WordPress /wp-json/, Drupal /jsonapi, Joomla manifest,
  Magento /magento_version) — tech_profile entries gain a verified flag +
  "actively verified via ..." evidence and an extracted version.
- c_jwt_forgery (new): an identity endpoint baseline accepts the genuine token &
  reflects identity claims; then two forgeries are tested — alg=none and
  re-signing with a wordlist secret. Reflected forged identity = confirmed CRITICAL;
  strict endpoints stay silent (battery negative control: /api/profile).
- c_websocket_surface (new): ws(s) URLs from the crawler (HTML/JS) are proven
  with a handshake (101 + valid Sec-WebSocket-Accept); a foreign Origin still
  accepted -> CSWSH indication (probable).
- c_ssrf deepened: all vectors proven per parameter (file://,
  cloud metadata, internal fetch) on up to 6 URL parameters; a real starvation
  fix — the limit raised 14 -> 40 because /fetch?url= starved
  behind other parameters (the root of "SSRF metadata never fired").
- Battery: 48 mandatory categories + forgery negative control + verified assertions.
UI:
- Persistent dark mode on/off (localStorage) on dashboard & login —
  a formal dark navy palette via the same theme variables.
- The live log becomes a CMD terminal: dark window, three window dots,
  title root@pentest-toolkit, per-severity/status line coloring,
  Pause/Copy buttons, a progress bar from [i/n] markers.
- Clickable severity filter chips in finding detail (together with the text filter).
Latent bug found & fixed: the cookie row in the bulk scan function
contained an invalid literal that made the dashboard script block collapse
(node --check is now green for all blocks; bulk scan recovered).

## v3.8.0 — Full-stack detection from a single URL
Design requirement: scanning one URL must detect everything running behind
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
By decision, every user-facing string in the product is now
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
- Libraries added (the PREREQ list): packaging (precise PEP 440 version
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

## v3.14.0 — stdlib adoption pass (module list, 2026-10-16)
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

By decision the release numbering restarts at **1.0.0**; this
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

On request ("see everything integrated into a URL — DB, API, web
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
The product was renamed from "Pentest Toolkit" to **VANTHEX — Offensive Security Platform** (tagline: Discover. Validate. Remediate.; sub-brand: Vulnerability Intelligence & Security Assessment). All public branding was changed: login/app templates (title, brand, crimson shield favicon + meta), the Server header, HTML/DOCX reports, report file names (vanthex_report_*), the scanner User-Agent standardized to "VANTHEX/1.6.0", the CLI prog "vanthex", README/INSTALL, the systemd unit description, and module labels (Security Dashboard, Assets Management, Vulnerability Findings, Mobile Application Testing, Audit Logs, Scan Schedules, System Settings). Deliberately retained for compatibility (per §7.5 of the brief): the webhook event name "pentest_scan_completed", the "ptk-*" localStorage keys, the DB file name, the artifact slug, the directory name, internal header docstrings, and these historical notes. Service i18n note: the renamed view titles do not yet have translation keys in the 11 non-English languages, so those titles appear in English on non-English UIs (product names are not translated). Full suite after the rebrand: 97/97.

## v1.7.0 — Master Redesign: premium enterprise (2026-10-17)
Following the master prompt + the provided VANTHEX reference images: a centralized token system (dark bg #070B12, sidebar #090E16, card #0D1520, elevated #111B29, primary #FF4148/#D92736, text #F4F7FB/#98A7BA, border #202D3D, success #22C993, warning #FFAA3D, info #43B7F5). The theatrical HUD layers (scanlines, sweep, brackets, glitch, chamfer, radar, ticker) were REMOVED from the service (PREMIUM PASS) and the artifact; cards rounded 12px, minimal glow. The artifact dashboard follows the reference composition with REAL DATA only: the welcome banner uses the actual session username, real KPIs, trend (7D/14D ranges matching the 14-day series the service genuinely provides — not fabricated 30D/90D), severity donut, module cards with real routes, Recent Scans, Top Vulnerabilities, a Recent Activity rail (real events only), Quick Actions, a live Engine Health card. New Scan became a 5-step wizard with an identical API payload and the same authorization gate. The Threat Intelligence/Risk Scoring pages were NOT created (the views do not exist — per §4 of the master prompt); the Manual Exploitation card was replaced with a real module. DB had 0 scans at release: the dashboard shows zero + an honest empty state.

## v1.8.0 — Scan reliability: proven scheme, preflight fail-fast, safe budget & cache (2026-10-18)
Triggered by a field complaint: a UAT scan ran 2067s without results, results differed between scans, and the framework was not detected. Root cause verified from the data: the target was stored WITHOUT a scheme ("uatgadaiemas.devoutsys.com/DepoEmasMaster/login") and the old parser guessed http:// (port 80 — closed externally; measured timeout 10.5s), while https 443 answered 200 in 1.16s. Fixes: (1) netclient.resolve_scheme_target() proves the scheme with a light probe (https first, http fallback); the effective target is recorded in the result (effective_target) and stored as the scan target. (2) Preflight fail-fast for active profiles: a target that responds to no request at all is stopped within seconds with an INFO finding "Target unreachable — scan aborted early" + an INCONCLUSIVE warning (not a clean verdict). (3) Time budget: per-check 600s ("timeout" status transparent in checks_detail) + total budget 1800s (remaining checks "skipped"). (4) Per-scan GET response cache WITH two guards born from a battery regression: header-varying requests are never served from cache, and a URL ever requested with headers becomes "tainted" (its entries are dropped, never cached again) — without these guards the cache-poisoning verification read the pre-poison snapshot and the detection died; the guards are locked by tests/test_scan_reliability.py. (5) Cumulative backoff sleep budget 90s/scan (previously a fixture scan measurably slept 265s — a source of random durations). (6) The crawl surface order is sorted before the cap: the tested subset is deterministic. Verification: full battery green (recall 50/50, FP 0), reliability tests 5/5 including two identical scans -> exactly the same findings & tech, and a dead target aborting <30s.

## v1.9.0 — Asset deletion (2026-10-18)
Answering the question "why is there no delete button in Asset Management?": an asset is not an independent record — the asset list is an aggregation of the scans table per target (store.assets_summary), and until now there was simply no asset deletion path in the backend or the UI (only criticality/owner meta editing + per-scan deletion in Scan History). Added store.delete_asset(host): one transaction deletes all of that target's scans + their findings + the asset_meta row + its host suppressions (exact target key and its host); the vault target_secrets are DELIBERATELY untouched (independent entries managed from Settings). Endpoint POST /api/assets/delete (admin-only, "asset_delete" audit with counts) + a Delete button per row in Assets Management (the service UI uses the same confirmDialog as other deletes; the artifact follows the same pattern). Tests: tests/test_assets_delete.py (cascade only for that target; other assets + other data intact; unknown host -> zero counts). Verified live end-to-end with a synthetic asset cleaned up by the endpoint itself.

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

Triggered by an audit of the operator's own ports/subdomains scans, which were "wrong".
The root cause is this VM's network position, and the engine now handles it
honestly on every path:

- **Ports**: TCP egress is intercepted by the sandbox gateway (the `muse:` banner) —
  raw connect results are NO LONGER stored as open ports. When
  interception is detected: `open_ports` is emptied + 1 INFO finding
  "Port scan inconclusive". (Previously: 50 fake ports were presented.)
- **Subdomains**: this VM's system resolver is synthetic (fake IPs in 198.18.0.0/15
  for any name whatsoever, proven for names that cannot exist). Enumeration
  now uses DNS-over-HTTPS (Cloudflare/Google) + a wildcard gate;
  the system resolver is only a fallback when proven healthy; when no trusted
  path exists -> inconclusive, not a fake list. (Previously: 51 fake names.)
- **Dirs/Headers**: previously direct-socket + a guessed http scheme (0 results on
  https targets). Now via the proxy-aware netclient, the scheme is PROVEN
  by probe, and http_probe has a soft-404 baseline (SPA shells are marked
  catch_all and filtered from hits). Unreachable targets = inconclusive.
- **SSL/TLS**: the audit + cipher enumeration now go through an HTTP CONNECT tunnel
  (not the intercepted direct path) and certificate parsing uses the DER
  form via cryptography when the text getpeercert is empty (a latent bug: subject/
  issuer/SAN empty). c_tls in vulnscan healed along with it ("TLS could not be
  audited" gone on targets with healthy TLS).
- **UDP**: target resolution via DoH + synthetic-IP rejection (inconclusive when
  no trusted path exists); DNS response validation tightened (TXID match,
  RCODE 0, ANCOUNT >= 1) and responses failing protocol validation drop to
  open|filtered "unverified response", not "open". (Previously: a 29B error
  response from an intermediary was claimed as "dns open".)
- **Passive**: the DNS A/AAAA fallback is now DoH-first + synthetic-IP filtering.
- **Fully English engine output**: 25 runtime log/evidence strings that were still
  in Indonesian were translated (per the 2026-10-16 language rule).
- Tests: +13 transport/DNS/port honesty tests (tests/test_transport_honesty.py,
  tests/test_dns_ports_honesty.py). Live proof against the UAT target: ports inconclusive
  and clean, subdomains 0 (matching the DoH ground truth), the real SSL subject read
  (CN=uatgadaiemas.devoutsys.com, TLSv1.3), headers score 67 consistent
  with vulnscan, udp 53 honestly open|filtered.

## v1.16.0 — Full accuracy audit + UI tidiness (2026-10-19)

Mandate: rework everything to be tidier (appearance, fonts), fix bugs,
and ensure scanning is as accurate as possible across all types. v1.15.0 suite
baseline: 119/119 green before any change.

- BUG 1 (headers): the "headers" scan-type branch in app2.run_tool_scan always
  returned "findings": [] — missing security headers never
  became findings (unlike vulnscan c_security_headers, which assesses
  the same response), and unreachable targets looked clean. The branch
  now emits findings that EXACTLY mirror c_security_headers
  (same title/severity/CWE/CVSS/remediation; HSTS only on https) + an inconclusive INFO
  when there is no response. Live proof via the API: a fixture without
  headers -> 5 findings (CSP MEDIUM 5.4 + 4 LOW), via https -> 6 (HSTS included).
- BUG 2 (F() argument order): the vulnscan2.F signature is
  F(sev, title, desc, evidence, cwe, owasp, cvss=0.0, remed="") — position
  7 is cvss. ALL F() calls in the app2 typed branches (ssl x2,
  udp x3, syn, vhost) passed the remediation string positionally, so
  the remediation text landed in the cvss field and remediation was empty on every
  finding of the ssl/udp/syn/vhost scan types. Fixed at 9 call sites
  (remed= keyword). mobile.py & the vulnscan2 internals turned out clean (kwargs).
- Consistency: the INFO finding 'TLS could not be audited' (c_tls) now has
  remediation (previously the only engine finding with none).
- New regression tests: tests/test_headers_findings.py (4) +
  tests/test_typed_scan_findings.py (5). Full suite: 128 tests.
- Live end-to-end proof via the service API (proof scans deleted afterwards):
  headers http/https matching the vulnscan mirror; loopback ports genuinely measured
  {18080,18443,5000} intercepted=False; dirs only /admin; subdomains
  example.com found=[] (DoH); syn EPERM -> honest INFO with clean severity;
  vhost 0 FP; loopback udp honest; passive-quick vulnscan 7 findings all
  with remediation; the ssl_audit function reading the fixture certificate (CN=localhost,
  TLSv1.3, self-signed verify_error correct). VANTAGE NOTE: a direct connect
  to 127.0.0.1:443 (no listener) is answered by the sandbox gateway
  with its own certificate (issuer Hatch Sandbox Egress CA) — the same intercept
  class as the old port incident; public-target TLS audits still go
  via CONNECT and read the genuine certificate (proven on the UAT).
- UI (artifact, appearance-only): a comprehensive tidiness & typography sweep —
  the Scan Detail title standardized to the 22px heading role, trend chart label weights
  to role weights, brand card version line tracking normalized, label->field
  spacing unified (mt-1) on 28 form fields, the Findings triage select
  matched to the compact Assets editor spec; the V1.16.0 badge at 4 points. Earlier
  the same day: chunked APK upload (422 fix), near-opaque overlay sweep,
  centered brand card, service revived after a platform restart.

## Public release re-versioning — v1.0.0 (2026-10-20)

By decision, the public VANTHEX versioning starts from **v1.0.0** for the
GitHub/GHCR debut (the internal lineage v1.6.0–v1.16.0 above remains as
development history). All engine version literals, the Docker image
(`vanthex:1.0.0`), the GHCR workflow, artifact badges, and the package name were aligned
to 1.0.0; there is no functional change in this step.

## v1.1.0 — The artifact UI becomes the service's built-in UI (2026-10-20)

On request ("the artifact display, when deployed locally, natively
or via Docker, must be 1:1"), the UI that until now lived only as a
Muse artifact is now served directly by the service:

- The artifact production bundle (React, byte-identical) is copied into `webui/`
  and served by app2 at `/` for admin sessions; a new endpoint
  `POST /actions` implements all 46 artifact actions in Python
  (`actions.py`, a faithful port of the artifact's server/src/actions.ts — data mapping,
  result shapes, and error messages identical), running with an internal admin
  session exactly like the artifact model. Not logged in → redirect to the
  service login page; the classic UI remains available at `/classic`.
- Service login: fixed the icon/text overlap on the username/password
  fields (an old CSS layer overrode the input padding) + a glass
  layer. Full suite 128/128 green after the template changes.
- Verification: 24 integration checks + 22 flow checks through /actions against
  the live service — all passing (full scan cycle, chunked APK upload,
  schedule/suppression/token/secret CRUD, DOCX base64 reports).
- Subsequent bundle synchronization: `sync-webui.sh` (copies the latest artifact
  client/dist into webui/).
