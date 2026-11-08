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

## Addendum v1.2.2 — ExploitKit (2026-11-02)

Engine v1.2.2 menambahkan dua modul baru yang memperluas VANTHEX dari
scanner/verifier menjadi platform yang memproduksi **dan** memverifikasi
eksploit non-destruktif:

- **`payloadforge.py`** — pustaka generator payload murni (stdlib, tanpa
  jaringan): XSS multi-konteks + encoder + mutator evasion, SQLi (boolean/
  error/time/UNION), command injection (aritmetika + delay), SSTI, path
  traversal (+fingerprint file), SSRF (metadata cloud + loopback), CRLF,
  JWT (alg none / kid / HMAC forge), dan generator shell reverse/bind
  (teks saja, tidak dijalankan engine). Punya CLI `python3 payloadforge.py
  <kategori> --marker ...` plus test unit 29 kasus.
- **`exploitkit.py`** — check poC berlakon `c_*(ctx, add)` yang terdaftar di
  registry runner: `c_sqli_confirm`, `c_cmdi_confirm`,
  `c_traversal_confirm`, `c_ssrf_probe`, `c_payload_replay`. Semua PoC
  read-only/differential; `origin="exploitkit"`. Prinsip kejujuran
  dipertahankan: `confirmed` hanya dari diferensial yang lolos 2 pasangan
  independent + reproduksi; SSRF loopback tanpa port-oracle diturunkan ke
  `probable`.
- Profil baru **`active-exploit`** (standar penuh + 5 check exploitkit);
  `enterprise-full` menambah `_EXPLOIT` juga.
- Test integrasi `tests/test_exploitkit.py` (3 kasus, termasuk scan penuh
  via runner) memverifikasi confirmed pada fixture yang sengaja rentan.

## Addendum v1.2.3 — Shell handler & post-exploitation (2026-11-02)

Eksekusi nyata: VANTHEX kini punya shell handler + post-exploitation CLI
di samping engine. Dikode dalam Bahasa Indonesia, stdlib-only, tanpa
saling-import ke vulnscan2.

- **`shellhandler.py`** — handler reverse/bind:
  - transport dibikin **tahan echo `bash -i`**: completion pakai marker
  digit (`__VHX_DONE__\d+`) yang tak pernah ter-echo, sehingga `command()`
  tidak berhenti prematur (perbaikan roundtrip download terbukti exact).
  - `command()`, `send_file()`, `recv_file()` (delimiter B64S/B64E + rfind
    untuk mengabaikan echo), `enum()`, plus **`grab()`** (ssh_keys,
    shell_history, sudoers, crontab, uid0, env rahasia, cfg dirs) dan
    **`exfil()`** (tar + base64 unduh path).
  - mode `reverse` (listener) & `bind` (connector).
- **`postex.py`** — CLI: `listen`, `connect`, `enum`, `exec`, `upload`,
  `download`, `grab`, `exfil`, plus REPL dan mode PTY interaktif.
- **`payloadforge.py`** — kategori baru: `xxe`, `lfi` (php wrappers),
  `webshell` (php/jsp/aspx/node).
- Terbukti live terhadap reverse-shell bash nyata di localhost: `whoami`
  -> root, `id`, enum OS, upload 29 byte, download roundtrip 29 byte **exact**
  (isi `VANTHEX transfer proof 12345\n`), grab menemukan ssh/history/sudoers/
  env secret, exfil mengunduh tar 10240 byte.
- Test: 44 lulus (payloadforge 33 + exploitkit 3 incl. scan penuh +
  shellhandler 8).

## Addendum v1.2.4 — Injection breadth & lateral recon (2026-11-02)

Perluasan cakupan injeksi + kemampuan recon pasca-kompromi.

Engine (`exploitkit.py`) dua check baru, terdaftar di `_EXPLOIT`:
- `c_ldap_confirm` — LDAP injection: error-based (NamingException/bad filter)
  = probable; boolean wildcard 2 varian = confirmed. Wired & teruji terhadap
  fixture `/ldap/search`.
- `c_xxe_confirm` — XXE read-only: kirim XML ber-entity `file:///etc/passwd`
  ke endpoint XML (crawl + tebakan /xml /soap /wsdl ...), fingerprint passwd
  = confirmed. Teruji custom XML handler.

`payloadforge.py` kategori baru (+5): `nosql` (Mongo $gt/$ne/$regex/$where),
`ldap`, `xpath`, `smtp` (header injection), `deser` (PHP/Java/JS proto-poll/
  pickle probing). Total 22 kategori.

`postex.py` + `shellhandler.py`: subcommand `sweep` — sapuan port internal
lewat shell target (`/dev/tcp` probe pada list port default), untuk recon
lateral movement; hasil {port: open}. Teruji via fake shell + CLI help.

Versi 1.2.4. Test lulus: payloadforge 33 + shellhandler 9 + exploitkit
(LDAP+XXE ditambah test runner penuh).

## Addendum v1.3.3 — ExploitKit confirm (Deser + SMTP Header Injection) (2026-11-02)

### Engine

- **3 check & 1 helper baru di `exploitkit.py`** (bukan di `vulnscan2.py`; engine check
  registry sekarang 69 check):
  - `c_nosql_confirm` — konfirmasi NoSQL injection (Mongo) di endpoint JSON API:
    differential 2/2 operator `$gt`/`$ne` → data leak = `confirmed`; time- based
    `$where` sleep JS 2× = `confirmed`; 1 signal = `probable`. Target: surface
    `js_endpoints` + heuristik `/api/search` fallback.
  - `c_xpath_confirm` — konfirmasi XPath injection di `/xpath/search` (error verbose)
    dan `/xpath/blind` (generalised error, boolean only): error XPathExpressionException
    verbatim = `probable`; boolean 2/2 + reproduksi = `confirmed`; 1 boolean =
    `probable`.

### Bug fix eksploratori (pivot, bukan regresi)

- **netclient URL-encoding**: `ctx. client.get("/path?p=x or y")` dengan payload mentah
  (spasi/kutip) melempar exception → `Resp.status=0`. Fix: URL-encode nilai sebelum
  kirim. Check baru sekarang pakai `quote(str(value))` secara internal.
- **`_unrefl` + URL-encoded payload**: jika payload yang URL-encoded yang ada di
  body (bukan versi mentah), `_unrefl` null seluruh body. Untuk boolean differential,
  `len(tb)==0` vs `len(fb)>0` adalah sinyal positif kuat — kondisi sekarang
  menerima `(len(tb) > len(fb)*1.15 or (len(tb)==0 and len(fb)>0))`.
- **netclient absolute URL**: `ctx. client.get("http://...")` di- mangled → 404.
  Semua check langsung pakai path relatif (`"/api/..."`, `"/xpath/search"`).

### Test

- `tests/ test_exploitkit.py`: `test_nosql_confirm_finds_on_fixture` (differential
  `$gt` → user data, negatif `/safe/json/*` tidak boleh confirmed) dan
  `test_xpath_confirm_finds_on_fixture` (boolean 2/2 pada /xpath/ blind+search,
  negatif `/safe/xpath/*` clean).
- `tests/ test_battery.py`: ekspektasi count 69 (tripwire hardcode), fragment
  pencarian `NoSQL Injection` + `XPath Injection` + `JWT can be forged` di EXPECT.
- **Hasil: 11/11 passed** (`test_exploitkit`: 9 including 4 baru (NoSQL/XPath/JWT/webshell);
  `test_battery`: 2) dalam ~700 s.

### Engine: JWT forgery (v1.3.2)

- **`c_jwt_forge`** — konfirmasi JWT forgery di `/api/me` (endpoint ber-JWT):
  - `alg=none` variants (3 bentuk) → token tanpa signature → confirmed
    bila server 200 dengan klaim `admin:true` bikinan kita. Bukti: forged
    token diterima tanpa verifikasi signature — siapa pun dapat membuat token
    tanpa tahu secret.
  - Weak-secret HS256 re-sign (4 secret umum) → confirmed pada `/api/me`
    (secret="secret"). Bukti deterministik: re-sign dengan weak key menghasilkan
    token valid.
  - Bounded: alg=none pada non-strict endpoints saja; weak-secret pada `/api/me`
    saja; /api/profile tidak disentuh (secret kuat, kontrol negatif).
  - Non-destructive: hanya kirim token tiruan; tidak ada write.

- **`deliver_webshell(client, upload_path, name, lang, marker)`** — helper
  operator-gated: upload webshell (PHP/JSP/ASPX/Node) via multipart POST ke
  `/upload`, verifikasi `/uploads/<name>` menyajikan kembali. AUTHORIZED TESTING
  ONLY — menulis file ke target; TIDAK masuk profil scan default. Teruji di
  fixture: upload PHP marker → serve 200 dengan marker.

### Engine: Deserialization confirm (v1.3.3)

- **`c_deser_confirm`** — konfirmasi unsafe Python pickle deserialization:
  kirim pickle byte dengan `__reduce__ -> eval('7*6') = 42` (non-destruktif,
  tanpa efek samping). Fingerprint: `{"deser": "pickle", "result": 42}` di
  respons = confirmed (2 reproduksi). Target: `/deser` (vulnerable) + surface
  heuristics. `/safe/deser` menolak pickle (kontrol negatif).
  CWE-502, CVSS 9.8. Non-destructive: eval arithmetik bukan shell.

### Engine: SMTP header injection confirm (v1.3.3)

- **`c_smtp_confirm`** — konfirmasi SMTP header injection (email field):
  kirim CRLF dalam email (`victim@x.com\r\nBcc: VHXMK@x.com`). Fingerprint:
  `Bcc: VHXMK@x.com` muncul di `smtp_trace` / respons server = confirmed
  (2 reproduksi). Target: `/contact` (vulnerable) + surface heuristics.
  `/safe/contact` men-strip CRLF (kontrol negatif).
  CWE-93, CVSS 7.5. Non-destructive: hanya baca respons server.

### Fixture baru (v1.3.3)

- `/deser` — Python pickle deserialization (vulnerable: `pickle.loads()`
  -> `__reduce__` -> `eval('7*6') = 42`). JSON fingerprint.
- `/safe/deser` — reject pickle (Content-Type bukan `application/octet-stream`
  atau magic bytes `\x80\x03`/`\x80\x04`).
- `/contact` — SMTP header injection (vulnerable: email field di-reflect
  mentah ke raw RFC header, CRLF tidak distrip).
- `/safe/contact` — patched: `re.sub(r'[\r\n]', '', email)` sebelum dipakai.

### Test (v1.3.3)

- `tests/test_exploitkit.py`: `test_deser_confirm_on_fixture` (pickle gadget
  eval 42 → confirmed; /safe/deser clean) + `test_smtp_confirm_on_fixture`
  (CRLF Bcc leak → confirmed; /safe/contact clean).
- `tests/test_battery.py`: EXPECT fragments untuk deserialization RCE +
  SMTP header injection; tripwire count 71.
- **Hasil: 13/13 passed** (test_exploitkit: 11; test_battery: 2) dalam ~700 s.

## Addendum v1.4.0 — Offensive Pack: 13 check + 3 engine (2026-11-03)

Paket offensive scan terbesar dalam satu rilis: 13 check `c_*` baru,
semua non-destruktif dan mengikuti model kejujuran hasil (confirmed =
terproduksi 2x, diferensial dgn kontrol negatif `/safe/*`).

### Modul baru

- `credkit.py` — suite kredensial (enterprise-full saja, intrusif):
  - `c_password_spray` — password spraying adaptif (1 password × banyak
    user), lockout-evasion (jeda, stop saat rate-limit terdeteksi).
  - `c_otp_bypass` — bypass OTP/2FA: kode null/kosong, kode lemah umum,
    tanpa rate-limit; verifikasi 2x; /safe menolak = negatif.
  - `c_user_enum` — enumerasi username via diferensial pesan/panjang/timing
    (timing saja = probable LOW; pesan/panjang = confirmed MEDIUM).
- `dirbrute.py` — brute force direktori/file adaptif: baseline soft-404
  per-scan + similarity body + reproduksi 2x; wordlist kandidat bernilai
  (backup, vault, panel, dll) + ekstensi (.bak/.sql/.zip/.txt/...).
  `c_dir_bruteforce` di _ADVANCED (active-deep & enterprise-full).
- `sesskit.py` — pipeline eksploit→sesi (OPERATOR-GATED, bukan check scan):
  `deliver_webshell` → verifikasi serve → probe eksekusi read-only
  (id/uname) → laporan. CLI: `python3 sesskit.py --target ... --upload ...
  --name ... --lang php`. Tidak pernah masuk PROFILES.

### Check exploitkit baru (masuk _EXPLOIT: active-exploit + enterprise-full)

- `c_ssti_rce` — fingerprint mesin template ({{7*7}}, {{7*'7'}} → jinja2)
  + bukti akses objek config = CRITICAL (potensi RCE); aritmetika saja = HIGH.
- `c_sqli_second_order` — payload quote tersimpan via endpoint tulis yang
  senyap, error SQL muncul di endpoint baca lain (diferensial bersih vs quote).
- `c_sqli_extract` — UNION SELECT: deteksi jumlah kolom otomatis, lalu
  enumerasi information_schema (read-only metadata saja).
- `c_deser_gadget` — gadget chain Java (pola ysoserial/CommonsCollections)
  & PHP (pola phpggc); bukti via pingback marker, tanpa command.
- `c_cve_exploit` — konfirmasi aktif Log4Shell (JNDI), Shellshock (bash CGI),
  PHP-CGI arg injection (CVE-2012-1823), Spring SpEL; semua echo/marker.
- `c_prototype_rce` — prototype pollution → gadget (child_process) aktif;
  bukti header X-Polluted + gadget diecho; /safe tak terpengaruh.
- `c_h2c_smuggling` — upgrade h2c cleartext diterima frontend; request
  diselundupkan di body dieksekusi backend (endpoint internal tercapai).
- `c_cache_deception` — path ACL 403 + ekstensi statis → isi privat
  cacheable (Cache-Control public/max-age); /safe tetap 403 = negatif.
- `c_waf_bypass` — deteksi blokir WAF lalu mutasi adaptif via
  `payloadforge.waf_variants` (filter pola terblokir, urut encoding ganda →
  komentar → case) sampai lolos DAN fungsional; 2x = confirmed.

### Fixture (tests/fixture_vuln_server.py)

Endpoint kontrol baru: /spray/login(+safe), /otp/verify(+safe), /deser/java
+ /deser/php(+safe), /profile/save|view(+safe), /template/render(+safe),
/extract, /cgi-bin/status|php-cgi(+safe), /spel/eval(+safe), /pollute(+safe),
/h2c(+safe, GET & POST), /admin/profile(.css)(+safe), /vault/, /wafgate/echo,
/api/log(+safe, GET & POST). Perbaikan: do_POST kini mem-parse `q` (sebelumnya
dibuang) — handler form-post tidak lagi crash.

### Test (v1.4.0)

- `tests/test_offensive_v2.py`: 17 test (13 check di fixture + unit
  payloadforge.waf_variants + 2 unit sesskit stub-client + wiring).
- `tests/test_battery.py`: tripwire 71 → 89 (sinkron len enterprise-full).

## Addendum v1.5.0 — Offense Brain Pack: 6 check + 6 engine (2026-11-03)

### Check baru (semua diferensial, kontrol /safe, confidence model ketat)
1. `c_oob_sweep` (exploitkit) — Universal OOB Sweeper: satu pass menanam token canary ke SEMUA kelas permukaan (param URL kelas fetch, User-Agent JNDI, Referer, X-Forwarded-For, body JSON) dengan atribusi per-kelas; temuan HANYA dari callback nyata; token yang belum callback diserahkan ke grace-window runner. Tanpa canary → declared skip.
2. `c_js_bundle_mine` (exploitkit) — SPA Bundle Miner: bandingkan endpoint yang dirujuk JS surface vs yang ter-link di HTML; endpoint legacy hidden yang hidup & mengembalikan JSON stabil 2x → temuan. Referensi mati (404) & catch-all tidak dilaporkan.
3. `c_session_entropy` (exploitkit) — Session Entropy Analyzer: N token sesi (anti-cache via header variasi), deteksi statis / counter berurutan / entropi rendah; kontrol negatif /safe/api/session/new (acak kripto).
4. `c_authz_matrix` (exploitkit, profil enterprise-full — intrusif) — Multi-Role Authz Matrix: endpoint admin dengan cookie role user/admin; temuan = eskalasi vertikal (bukan-sesi juga ditolak, role=user diterima 2x, /safe tetap 403).
5. `c_openapi_stateful` (exploitkit) — OpenAPI Stateful Fuzzer: baca spec, panen ID nyata dari endpoint koleksi, probe endpoint ber-param path; temuan bila ID panen 200 JSON 2x + ID bogus ditolak + /safe 403 (IDOR by spec). Read-only (GET).
6. `c_custom_templates` (exploitkit) — Custom Template Engine: jalankan template JSON operator (templates/*.json, format vulntpl — match DSL status/body/header/regex, && / ||). Tanpa template → declared skip.

### Engine baru (modul terpisah, semua bounded)
- `chainplanner.py` — Exploit Chain Planner (read-only): graf rantai dari temuan (SSTI+config → RCE → sesskit; SSRF → cloud metadata; traversal → kredensial; deser → RCE; spray → takeover; SQLi → dump). Output rencana, operator-gated.
- `wordmint.py` — Targeted Wordlist Generator: password perusahaan+tahun+leetspeak (MAX 400), subdomain (MAX 60). Bug fixed: titik domain dipertahankan.
- `harkit.py` — HAR Replay Diff: replay GET dari HAR dengan 2 identitas sesi → verdict same-private / differential (authz horizontal).
- `monitor.py` — Continuous Monitor (operator-gated): scan ulang + diff state JSON → hanya temuan BARU (exit 2 bila ada). Tidak menjadwalkan diri sendiri.
- `proxykit.py` — Proxy Mode Pasif (operator-gated): forward proxy HTTP + passive scan live (header keamanan, cookie flags, secret pattern) → findings.jsonl. CONNECT TLS ditolak (lab HTTP).
- `vulntpl.py` — engine template custom (loader/validator/match DSL, read-only, tanpa eval() bebas).

### Wiring & test
- `vulnscan2.py`: alias 6 check; c_oob_sweep & c_openapi_stateful di _EXPLOIT; c_js_bundle_mine, c_session_entropy, c_custom_templates di _ADVANCED; c_authz_matrix di enterprise-full. Tripwire: enterprise-full 89 → **95**.
- `tests/test_offensive_v3.py`: **14 test** (6 check di fixture port unik + unit harkit/monitor/chainplanner/wordmint/vulntpl/proxykit + negative safe-session) — 14/14 PASSED.
- Perbaikan akurasi saat pengembangan: anti-cache `_collect_sessions` (respons GET di-cache client → token 'identik' palsu); miner pakai body HTML halaman (surf.pages = path, bukan HTML).

## Addendum v1.6.0 — Credential Takeover Pack: 7 check (2026-11-03)

### Check baru (modul takeover.py — semua berusaha membuktikan AKSES NYATA)
1. `c_jwt_weak_secret_takeover` (_EXPLOIT) — brute secret HS256 (wordlist 15 kandidat, bounded) → token role=admin DITEMPA → endpoint admin menerima 2x. /safe menolak (secret kuat).
2. `c_reset_token_takeover` (_EXPLOIT) — reset token bocor di respons / prediktabel md5(email) → password akun diganti 2x. /safe menolak token prediktabel.
3. `c_oauth_token_theft` (_EXPLOIT) — redirect_uri tak divalidasi → code OAuth terlampir ke domain penyerang; state tidak diwajibkan (login CSRF). /safe menolak redirect asing.
4. `c_email_change_takeover` (_EXPLOIT) — ganti email akun tanpa re-auth (pre-hijack), bukti /profile. /safe menuntut reauth.
5. `c_api_key_reuse` (_EXPLOIT) — API key bocor di bundle JS DIVALIDASI AKTIF (read-only, scope terekam). /safe menolak semua key.
6. `c_otp_brute` (enterprise-full, intrusif) — brute OTP bounded 30 kode tanpa lockout efektif → 2FA dilewati. /safe menolak kode salah.
7. `c_ratelimit_bypass` (enterprise-full, intrusif) — lockout login dihitung dari XFF client-controlled → rotasi XFF lolos & login sukses. /safe menghitung global → 429.

### Fixture controls v1.6.0
/api/session/jwt + /admin/me (secret 'supersecret'), /reset/request+confirm (token md5(email) di respons), /login/limited (rate limit per-XFF, kredensial admin@fixture.local/Summer2025!), /profile/email (tanpa re-auth), /api/key/check + /static/config.js (vk_live_ key aktif, scope payments:write), /safe/oauth/authorize (allowlist). HOME + <script src=/static/config.js>.

### Pelajaran debugging (penting)
- Fixture sudah punya handler /oauth/authorize (v1.8.0, lax) — menambah duplikat elif SHADOW handler lama dan crash (`q` adalah DICT ter-decode, bukan query string). Selalu grep path dulu sebelum menambah handler.
- netclient: 302 normal ok; crash fix: jangan parse `q` sebagai string.
- Battery matrix sempat MISS 'API sensitive data detected' karena endpoint legacy JS menggeser window [:6] c_api_sensitive_data → widened [:10].

### Test
- `tests/test_offensive_v4.py`: **8 test** (7 check + wiring) — 8/8 PASSED; enterprise-full tripwire 95 → **102**.

## Addendum v1.7.0 — Total Domination Pack: 5 check + 5 engine (2026-11-03)

### Check baru (modul dominion.py)
1. `c_session_replay` (_EXPLOIT) — token sesi diterbitkan tanpa auth → replay sebagai cookie → akses halaman terproteksi 2x (hijack valid). /safe menolak.
2. `c_shadow_admin_hunter` (_EXPLOIT) — endpoint admin tersembunyi + bypass ACL (X-Original-URL, X-Rewrite-URL, method-override, trailing slash, %2f, double slash, case). /safe 403.
3. `c_cred_reuse` (enterprise-full, intrusif) — spray mini bounded (6 kombinasi, FORM-encoded) → kredensial pemenang di-reuse ke /svc/{smtp-login,dbadmin,panel}. /safe menolak.
4. `c_ws_cswsh` (_EXPLOIT) — handshake WebSocket dgn Origin asing/tanpa Origin → 101 = CSWSH. /safe/ws menolak. Pakai http.client langsung (netclient tidak bicara WS).
5. `c_blind_orchestrate` (_EXPLOIT) — korelasi timing nyata (.elapsed): payload ;sleep 0.3; lambat 2x (>=0.28s), baseline <0.15s, /safe cepat → blind injection confirmed.

### Engine baru (modul pure, operator-gated)
- `chainrun.py` — eksekusi rantai PER-APPROVAL (approver+executor disuntikkan; fail-closed).
- `impact.py` — simulator dampak READ-ONLY: blast radius 0-10, data at risk, layanan terjangkau.
- `evolver.py` — payload evolver genetik (mutasi payloadforge.waf_variants + crossover; stop saat skor 1.0 = lolos & ter-echo).
- `subtakeover.py` — fingerprint CNAME mendangling 8 layanan (github/azure/s3/heroku/...) + verify end-to-end (dns+fetcher disuntikkan).
- `campaign.py` — mode kampanye: scan → chain → report dengan callback progress per fase (siap dihubungkan Telegram).

### Fixture v1.7.0
/admin/vault (token SESS-* diterima), /admin/panel (X-Original-URL dipercaya), /blind/sleep (timing), /svc/* POST (reuse admin/Password1!), /safe/ws. PERHATIAN: blok elif yang salah tempat (svc di do_GET) = 404 diam-diam — cek method handler dulu.

### Test
- `tests/test_offensive_v5.py`: **10 test** (5 check + 5 engine) — 10/10 PASSED; enterprise-full tripwire 102 → **107**. Wajib run pakai `.venv/bin/python`.

## v1.8.0 — Fleet & Pivot Pack (round 4)
Tambahan check (enterprise-full 107 → 110):
- c_pivot_internal_map (pivot.py): peta jaringan internal bocor (host/port/kredensial) → graf pivot; kontrol /safe/internal/netmap.
- c_cloud_container_recon (cloudrecon.py): IMDSv1 terbuka + kredensial TERVERIFIKASI aktif (read-only), Docker API tanpa auth, Kubernetes API unauth.
- c_grammar_fuzz (fuzzkit.py): grammar-based fuzz mutasi STRUKTUR (type-flip, depth-nest, proto-pollution) vs parser JSON; kontrol /safe/api/fuzz.

Engine baru:
- selftune.py — self-tuning: probe latensi/WAF/tech → rekomendasi timeout/concurrency/evasion.
- fleet.py — multi-target paralel (ThreadPoolExecutor, cap global) + ranking risiko lintas-target + temuan shared; CLI: --targets,--profile,--parallel.
- reportgen.py — laporan DOCX gaya kampanye (exec summary, timeline, chain-of-exploits, temuan, rekomendasi).
- beacon.py — C2 beacon simulator (engagement-only): jitter, UA rotasi, exfil chunked → laporan dwell-time untuk uji deteksi SOC/NDR. Beacon dikirim dari host operator ke LISTENER OPERATOR; tidak menyentuh target.
- phishclone.py — phishing page cloner (engagement-only): clone + watermark WAJIB "AUTHORIZED PHISHING SIMULATION" + meta x-vanthex-engagement; form diarahkan ke /capture lokal.
- sentinel.py — persistence detector: snapshot permukaan → diff antar re-scan (endpoint baru/hilang/berubah → verdict backdoor/deploy). Cron eksternal opsional.

Test: tests/test_offensive_v6.py 11/11 (PORT 18212). Tripwire battery: 110.

## v1.9.0 — AI Warfare Pack (round 5)
Tambahan check (enterprise-full 110 → 115):
- c_llm_prompt_injection (llmattack.py): prompt injection + system-prompt extraction + tool-call induksi terhadap chatbot LLM target; diferensial vs /safe.
- c_mcp_audit (mcpaudit.py): server MCP/agent tanpa auth yang expose tool destruktif (exec/write/db) + token di metadata.
- c_ai_supply_recon (aisupply.py): endpoint model terbuka (Ollama-style) + API key LLM (sk-/AIza/sk-ant/gsk_) bocor di JS + validasi aktif read-only.
- c_identity_graph (identgraph.py): peta identitas (email, admin, IdP/SSO, pola email korporat) dari permukaan publik.
- c_cache_poisoning_v2 (cacheadv.py): poisoning via X-Forwarded-Host duplikat (server ambil yang terakhir) + verifikasi persistensi cache; semua probe pakai cache-buster.

Engine baru:
- tripwire.py — zero-day tripwire: feed CVE (lokal/builtin) vs tech fingerprint → alert prioritas; CLI --target/--feed.
- browserkit.py — browser-in-the-middle: render Chromium headless (Playwright) → runtime_requests, DOM injection, divergence HTTP-vs-DOM. Chromium 1248 ter-install di ~/.cache/ms-playwright. Degrade anggun via BrowserUnavailable.
- insomnia.py — generator payload fileless one-liner (powershell/python) uji EDR; GATING WAJIB authorized=True (raise ValueError); tidak pernah dieksekusi oleh engine; + checklist indikator SOC.

Test: tests/test_offensive_v7.py 9/9 (PORT 18216; autostart module-level per lesson v6). Tripwire battery: 115.
Pelajaran: anchor "trap/vendors" dobel (do_GET & do_POST) → handler POST /api/llm/chat sempat nyasar do_GET (404 diam) → dipindah do_POST.

## v2.0.0 — OSINT Lifetime Watch + v2.1.0 — Apex Intelligence Pack (round 6)
### v2.0.0 OSINT Lifetime Watch
- osintwatch.py: subjek universal (domain/email/handle/nama/IP) dipantau SEUMUR HIDUP — snapshot berkala via run_osint_recon → diff bagian-per-bagian (profil/subdomain/breach/kode/infra/mention) → alert ber-rank severity. Snapshot pertama = baseline (tanpa alarm). State: osint_watches.json (env PTK_OSINT_WATCH_PATH). CLI --add/--run/--list/--remove. API: GET+POST /api/osint/watch (add/remove/run/clear).
- tests/test_osintwatch.py 7/7.
### v2.1.0 Apex Intelligence Pack (7 modul; tripwire tetap 115 — bukan check scan)
1. predator.py — Predator Graph: korelasi lintas-watch; entitas dibagi ≥2 subjek → link + alert (strong section = HIGH). API POST /api/osint/predator.
2. avatardeanon.py — deanonimisasi avatar: kluster aHash strict (K4, metode WS-E) → akun "anonim" terpaut identik; label probable, TIDAK terverifikasi.
3. breachoracle.py — Breach Oracle: watch email seumur hidup (HudsonRock + XposedOrNot, 2 sumber independen) → alert hanya kebocoran BARU/naik; password-pattern analysis OPT-IN (analyze_dump_patterns optin=True). API POST /api/osint/breachoracle.
4. attackpath.py — Attack Path planner heuristik: capability map dari temuan → enumerasi jalur DAG → skor Πp_success × dampak; rantai aturan chainplanner digabung; SEMUA output operator=True (tidak pernah dieksekusi). API POST /api/osint/attackpath.
5. asnorbit.py — ASN Orbit Tracker: domain → IP (DoH) → RDAP ASN → prefix → kandidat aset organisasi (RDAP cocok owner); bounded, deterministik (seed 42); kegagalan sumber = warning jujur.
6. ctstream.py — CT Live Stream: poll crt.sh per domain watch → sertifikat BARU = alert (phishing domain terdeteksi sebelum dipakai). State ct_stream.json. API POST /api/osint/ctstream (add/run/list).
7. mobilemirror.py — Mobile App Mirror: URL .apk/.ipa → download bounded 150 MB → mobile.analyze_* → ringkas endpoint+secrets; GATING optin=True.
- tests/test_apex.py 9/9 (offline, fake fetch; PIL untuk aHash).
### Pelajaran
- Env-path state HARUS dibaca saat call-time (fungsi _state_file), bukan saat import — monkeypatch env test tidak berefek kalau konstanta dihitung di module level.
- diff baseline kosong TIDAK menghasilkan alert (by design — snapshot pertama = baseline); uji severity harus pakai baseline non-kosong.
- API app2: routes POST baru WAJIB diletakkan SETELAH gerbang sesi _do_POST (if not sess → 401); GET baru setelah gerbang sesi do_GET (else 302).
- crt.sh rows: kolom name bisa common_name/name_value/name.

## Addendum — Auth Annihilation Pack + platform upgrades (2026-11-06, masih versi produk 1.2.2)

### Engine baru (semua operator-gated, no-op tanpa gate)
- `authattack.py` (`c_auth_attack`; gate `PTK_AUTHATTACK=1` atau opts `auth_attack`): login brute/stuffing (wordlist 983 entri + mutasi deterministik, maks 60 attempt), rate-limit evasion (rotasi X-Forwarded-For/X-Real-IP + varian path), deteksi "No Rate Limit on Login", mass assignment di login/registrasi, SQLi/noSQLi bypass login (CONFIRMED hanya bila marker authenticated terbukti), OTP/MFA brute + tampering (maks 40 attempt).
- `jwtred.py` (`c_jwt_attack`; gate `PTK_JWTRED=1` / `VANTHEX_JWTRED=1`): JWT toolkit stdlib + cracker 3k secret; attack alg:none, weak HMAC secret + eskalasi klaim, kid injection (traversal/SQLi), jwk/jku header injection, RS256→HS256 key confusion, claim tampering; password reset poisoning (Host header, token prediktabel, kebocoran Referer); OAuth: redirect_uri code leak, code replay, implicit fragment.
- `authzmatrix.py` (`c_authz_matrix` gate `PTK_AUTHZ=1`; `c_spa_mine` default-on): matriks authz dua sesi → IDOR/BOLA CONFIRMED (maks 30 objek × 2 request), privilege escalation via mass assignment (CONFIRMED hanya bila refleksi terverifikasi setelah update), SPA endpoint miner (regex JS bundle → merge ke surface, INFO ringkas).

### Integrasi profil
- `c_auth_attack`, `c_jwt_attack`, `c_bola_matrix` masuk `enterprise-full` + profil baru **`auth-assault` (64 checks)**; `c_spa_mine` masuk `active-deep`, `enterprise-full`, `auth-assault`.
- **`enterprise-full` 115 → 118**, `active-deep` 60 → **61**. Battery tripwire + semua test-lock pin di-update (test_battery, test_v13, test_v1100, test_offensive_v6/v7).

### Platform (gelombang sebelumnya, hari yang sama)
- `threatprior.py` (EPSS api.first.org tanpa key + CISA KEV cache TTL 24h → priority P1–P3), `attackgraph.py` (attack paths + impact score, seksi report HTML/DOCX), `notify.py` (Telegram/Slack/webhook, P1-gated), `sarif_export.py` (action `sarifExport`), `pocbox.py` (validasi PoC → confirmed + poc_proof), `lateralmap.py`, `sessionreplay.py` (actions `importHar`/`replayCapture`), `wafbank.py` (bypass per-WAF), `secondorder.py`, `wordsmith.py` (wordlist kontekstual), self-healing `heal_path` (varian path saat 404/410), scheduler window + catchup + auto-diff, `rbac.py` (viewer/operator/admin + audit, `PTK_DISABLE_RBAC=1` escape hatch).
- CVSS audit AST seluruh modul: 24 pelanggaran band severity/CVSS difix; invariant permanen `test_cvss_consistency.py`.
- **Actions 50 → 54** (`sarifExport`, `importHar`, `replayCapture`, `pocboxRun`); test lock di-update.
- Fix lingkungan: request internal loopback (127.0.0.1:5000) di actions.py di-bypass dari egress proxy — gejala "service unreachable" palsu di dashboard.
- Scan uji: crowllm.com (active-deep) → MEDIUM 23/100, 9 temuan (CSP + 4 security header), Cloudflare terdeteksi.
