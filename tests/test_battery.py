"""Battery ground-truth v3.4: matriks deteksi engine vs fixture terkontrol.

Both directions are tested at once:
- POSITIVE: every vulnerability PLANTED in the fixture MUST be caught (anti-miss).
- NEGATIVE: patched /safe/* endpoints MUST NOT produce injection-class
  findings (anti false-positive), and the clean fixture must not be accused of WAF.
- WAF mode: WAF MUST be detected (positive control c_waf_detection).

Run: .venv/bin/python -m pytest tests/test_battery.py -q (or this file directly).
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT_VULN, PORT_WAF = 18083, 18084

# Categories that must be caught (title fragment -> label), carried over from smoke + v3.4 additions.
EXPECT = {
    "SQLi detected": "SQL Injection",
    "XSS detected": "Reflected XSS",
    "SSTI detected": "Template Injection",
    "LFI/traversal detected": "Path Traversal",
    "CMDi detected": "Command Injection",
    "open redirect detected": "Open Redirect",
    "CORS detected": "CORS",
    ".env signature-verified": "Sensitive file exposed: /.env",
    "directory listing detected": "Directory listing",
    "CSRF form detected": "without anti-CSRF token",
    "JWT analysis (weak secret / no exp)": "JWT",
    "OpenAPI exposure detected": "API documentation exposed",
    "GraphQL introspection detected": "GraphQL introspection",
    "cookie flags detected": "Cookie 'session'",
    "TRACE/XST detected": "TRACE enabled",
    "fingerprint/kandidat CVE Apache": "Apache 2.4.49",
    "XXE detected": "XML External Entity",
    "IDOR/BOLA detected": "IDOR/BOLA indication",
    "NoSQL API detected": "NoSQL Injection in API",
    "default credentials detected": "Default credentials work",
    "rate-limit login detected absent": "No rate limiting",
    "upload unauth confirmed": "File upload WITHOUT authentication confirmed",
    "form upload detected": "File upload form found",
    "error disclosure detected": "Verbose error",
    "JS library usang detected": "Outdated JS library: jQuery 1.11.1",
    "source map detected": "JavaScript source map exposed",
    "session-in-URL detected": "Session token in URL",
    "login via HTTP detected": "Login form/credentials sent over plain HTTP",
    "security.txt detected absent": "security.txt not found",
    "robots disclosure detected": "robots.txt discloses sensitive paths",
    "API sensitive data detected": "Unauthenticated API leaks sensitive fields",
    "deserialization surface detected": "Serialized data detected",
    "SRI absen detected": "without Subresource Integrity",
    "UNION SQLi detected": "SQL Injection (UNION-based",
    "DOM XSS detected": "DOM-based XSS",
    "WP plugin enum detected": "WordPress plugin detected: wp-file-manager 6.8",
    "source disclosure detected": "Page backup/source exposed: /report.php.bak",
    "reset poisoning detected": "Password Reset Poisoning",
    "session fixation detected": "Session fixation",
    "cache poisoning detected": "Web Cache Poisoning confirmed",
    # --- tambahan battery v3.4 ---
    "SSRF detected": "SSRF",
    "CRLF detected": "CRLF / Response Splitting",
    "host-header reflection detected": "X-Forwarded-Host reflected",
    "admin panel detected": "Admin/login panel exposed: /admin/login",
    # --- tambahan battery v3.7 (expert) ---
    "JWT forgery alg=none": "JWT can be forged (alg=none accepted)",
    "JWT forgery re-sign": "JWT can be forged (weak secret, token re-signed)",
    "WebSocket aktif": "Active WebSocket endpoint",
    "CSWSH detected": "cross-origin connections (CSWSH indication)",
    "SSRF metadata cloud": "SSRF to cloud metadata",
    # --- battery v3.16 additions (trap extensions) ---
    "pure boolean-blind SQLi": "SQL Injection (boolean-based): /vuln/search_bool",
    # --- tambahan battery v1.10 (check kompleks) ---
    "Stored XSS v1.10": "Stored XSS verified (persistent)",
    "Prototype pollution v1.10": "Prototype pollution confirmed",
    "JWT kid injection v1.10": "kid injection",
    "GraphQL batching v1.10": "GraphQL query batching enabled",
    "GraphQL suggestion v1.10": "GraphQL field suggestion leakage",
    # --- tambahan battery v1.2 (Priority 1: PayloadsAllTheThings) ---
    "XPath error v1.2": "XPath Injection (error indication)",
    "XPath boolean v1.2": "XPath Injection (boolean-based)",
    "secret Tier A v1.2": "AWS Access Key ID exposed in web content",
    "secret Tier B v1.2": "Hardcoded credential indication in web content",
    "hidden params v1.2": "Hidden parameters accepted: /hidden",
    "tabnabbing v1.2": "Reverse tabnabbing:",
    # --- tambahan battery v1.3 (OSINT + Secrets Engine v2) ---
    "secret source-map v1.3": "SendGrid API key exposed in web content",
    # --- tambahan battery v1.8.0 (Coverage Expansion; fixture memang
    # planted vulnerable: LDAP simulator, GraphQL alias resolver, OIDC
    # loose config, upload that re-serves HTML files) ---
    "LDAP boolean v1.8": "LDAP Injection (boolean-based)",
    "GraphQL alias v1.8": "GraphQL alias amplification accepted",
    "OAuth ROPC v1.8": "OAuth password grant (ROPC) enabled",
    "upload bypass v1.8": "Upload validation bypass",
    # --- tambahan battery v1.3.x (ExploitKit confirm check NoSQL & XPath) ---
    "NoSQL confirm v1.3": "NoSQL Injection",
    "XPath confirm v1.3": "XPath Injection",
    "JWT forgery v1.3": "JWT can be forged",
    "Deser RCE v1.3": "Insecure Deserialization (RCE, confirmed)",
    "SMTP header inject v1.3": "SMTP Header Injection (email field)",
    }

INJECTION_CLASSES = ("XSS", "SQL", "SSRF", "CRLF", "redirect", "LFI", "CMDi",
                     "SSTI", "XXE", "NoSQL", "Command Injection", "Traversal",
                     "XPath")


def _wait(port, tries=40):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return True
        except Exception:
            time.sleep(0.25)
    return False


def _boot():
    procs = []
    p1 = subprocess.Popen([sys.executable, "tests/fixture_vuln_server.py", str(PORT_VULN)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    env = dict(os.environ, FIXTURE_MODE="waf")
    p2 = subprocess.Popen([sys.executable, "tests/fixture_vuln_server.py", str(PORT_WAF)],
                          env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs = [p1, p2]
    assert _wait(PORT_VULN) and _wait(PORT_WAF), "battery fixture did not start"
    return procs


def test_battery_matrix():
    procs = _boot()
    try:
        import vulnscan2
        res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT_VULN}", "enterprise-full",
                                     log=[], opts={"timeout": 5, "max_pages": 25})
        titles = [f["title"] for f in res["findings"]]
        blob = " | ".join(titles)
        print(f"\n[battery] {len(titles)} enterprise-full findings on the vuln fixture")
        missing = [k for k, frag in EXPECT.items() if frag not in blob]
        assert not missing, f"CATEGORY MISSED (MISS): {missing}"
        # Coverage transparency (v3.6): per-check status must be fully recorded.
        # The explicit count is intentional: checks silently missing from
        # the registry must fail this battery. Counted from
        # PROFILES['enterprise-full'], all of which resolve to real functions
        #  (95 = 66 baseline + c_nosql_confirm + c_xpath_confirm + c_jwt_forge
        #  + c_deser_confirm + c_smtp_confirm + 5 v1.3.4 + 13 v1.4.0
        #  + 6 v1.5.0 (oob-sweep, bundle-miner, entropy, authz-matrix,
        #  openapi-stateful, custom-templates)). Always keep in sync with
        #  len(PROFILES['enterprise-full']).
        det = res.get("checks_detail") or []
        assert len(det) == res["checks_total"] == 141, \
            f"checks_detail {len(det)} != total {res['checks_total']}"
        # Kontrol v1.3 (Secrets Engine v2): pasangan kredensial AWS dari
        # the .git history has its exposure confirmed; the source-map secret
        # and the base64 layer are caught with labeled evidence.
        gitsec = [f for f in res["findings"]
                  if str(f.get("location", "")).startswith("/.git@")]
        assert any(f["confidence"] == "confirmed"
                   and "complete credential pair" in f["evidence"]
                   for f in gitsec), gitsec
        assert any("app.js.map#" in str(f.get("location", ""))
                   for f in res["findings"]), \
            [f.get("location") for f in res["findings"]]
        assert any("base64-decoded" in f.get("evidence", "")
                   for f in res["findings"]), \
            [f.get("evidence") for f in res["findings"]]
        # Priority 1 control (v1.2): the secret traps in clean.js must not
        # produce findings; tabnabbing aggregates to exactly 1;
        # hidden params mention exactly debug & preview.
        assert not [f for f in res["findings"]
                    if f.get("location") == "/static/clean.js"], \
            [f["title"] for f in res["findings"]
             if f.get("location") == "/static/clean.js"]
        # v1.4.0 control: the canary meta is always present and honest (battery
        # runs WITHOUT a canary -> configured False, base_kind none,
        # no callback claim), and every technology carries a WS3/K4
        # fingerprint score with its signals in the finding evidence.
        assert res["canary"]["configured"] is False, res["canary"]
        assert res["canary"]["base_kind"] == "none", res["canary"]
        assert res["canary"]["callbacks_received"] == 0, res["canary"]
        assert all("score" in t for t in res["tech_profile"]), \
            "technology without a fingerprint score (WS3/K4)"
        _tech_finds = [f for f in res["findings"]
                       if f["title"].startswith("Technology detected:")]
        assert _tech_finds and all("fingerprint score" in f["evidence"]
                                   for f in _tech_finds), _tech_finds[:2]
        tab = [f for f in res["findings"]
               if f["title"].startswith("Reverse tabnabbing:")]
        assert len(tab) == 1 and " 1 external" in tab[0]["title"], tab
        hid = [f for f in res["findings"]
               if f["title"].startswith("Hidden parameters accepted: /hidden")]
        assert len(hid) == 1, hid
        assert set(x.strip() for x in hid[0]["param"].split(",")) == \
            {"debug", "preview"}, hid[0]["param"]
        # Negative JWT forgery control: the strict /api/profile endpoint must not
        # appear as forgeable.
        forgery = [t for t in titles if "can be forged" in t]
        assert forgery and all("/api/profile" not in t for t in forgery), forgery
        # Active technology verification (v3.7): WordPress is proven to be running.
        wp = [t for t in (res.get("tech_profile") or []) if t["name"] == "WordPress"]
        assert wp and wp[0].get("verified") is True, res.get("tech_profile")
        # Database detection from error artifacts (v3.8): the fixture 404 page
        # leaks traces of mysqli/MySQL + Linux paths.
        # v1.1 integration inventory: deployment/API components probed
        # active must verify with the correct version.
        techmap = {t["name"]: t for t in (res.get("tech_profile") or [])}
        for nama, ver in (("Jenkins", "2.319.1"), ("Docker Registry", "2.8.3"),
                          ("Kubernetes API", "1.28.2"),
                          ("Portainer", "2.19.4"),
                          ("OpenAPI (REST API)", "1.4.0")):
            t = techmap.get(nama)
            assert t and t.get("version") == ver and t.get("verified"), \
                (nama, t)
        assert "GitLab" in techmap and "GraphQL API" in techmap, \
            [t["name"] for t in techmap.values()]
        # CVEs per component (candidates) from the internal range-based table.
        cve_of = {t["name"]: [c["id"] for c in (t.get("cves") or [])]
                  for t in techmap.values()}
        assert "CVE-2021-41773" in cve_of.get("Apache", []), cve_of
        assert "CVE-2015-9251" in cve_of.get("jQuery", []), cve_of
        assert "CVE-2022-21661" in cve_of.get("WordPress", []), cve_of
        assert "Candidate CVE-2022-21661" in blob
        db = [t for t in (res.get("tech_profile") or []) if t.get("category") == "Database"]
        assert any(t["name"] == "MySQL" for t in db), res.get("tech_profile")
        assert all(d["status"] == "ok" for d in det), \
            [d for d in det if d["status"] != "ok"]
        # regresi FP lama
        assert "appendChild" not in blob and "t.head" not in blob
        assert "WAF detected" not in blob, "clean fixture accused of WAF (FP)"
        # NEGATIVE: patched endpoints must not be hit by injection-class findings
        bad = [f for f in res["findings"]
               if (f.get("location") or "").startswith("/safe/")
               and any(c.lower() in f["title"].lower() for c in INJECTION_CLASSES)]
        assert not bad, f"FP di endpoint patched: {[f['title'] for f in bad]}"
        # NEGATIVE WAF: the clean fixture (with the GeneXus hex token trap &
        # vendor names in text) MUST NOT be accused of WAF at all (v3.5:
        # deteksi perilaku — serangan & kontrol sama-sama 404 di path hantu).
        assert not any(t.startswith("WAF") or t.startswith("WAF indication")
                       for t in titles), "clean fixture accused of WAF (FP)"
        # PROFILER teknologi & integrasi (v3.5): stack fixture wajib terbaca,
        # GeneXus MUST NOT be claimed from the hex token alone.
        tech = {t["name"]: t for t in res.get("tech_profile") or []}
        for nama, ver in [("Apache", "2.4.49"), ("WordPress", "5.8"),
                          ("jQuery", "1.11.1"), ("Google Analytics", ""),
                          ("Google reCAPTCHA", ""), ("Stripe", ""), ("Midtrans", "")]:
            assert nama in tech, f"profiler melewatkan {nama}: {sorted(tech)}"
            if ver:
                assert tech[nama]["version"] == ver, f"{nama} versi {tech[nama]['version']} != {ver}"
        assert "GeneXus" not in tech, "GeneXus claimed from the hex token (profiler FP)"
        # v3.16 trap: /trap/* pages must not produce any findings — vendors
        # are only article text + hex tokens, DB names are only article
        # topics, escaped JSON reflection is not XSS/SQLi.
        traps = [f for f in res["findings"]
                 if (f.get("location") or "").startswith("/trap/")]
        assert not traps, f"FP on trap pages: {[f['title'] for f in traps]}"
        assert not any("F5" in n for n in tech), "F5 claimed from text/hex (FP)"
        import urllib.request as _u
        import techdb as _td
        body = _u.urlopen(f"http://127.0.0.1:{PORT_VULN}/trap/databases",
                          timeout=5).read().decode("utf-8", "replace")
        prof = _td.profile({}, body)
        assert not any(t["category"] == "Database" for t in prof), \
            f"nama DB di artikel jadi deteksi Database: {prof}"
        # WAF positive: waf mode must be behavior-CONFIRMED + vendor Cloudflare
        res2 = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT_WAF}", "active-standard",
                                      log=[], opts={"timeout": 5, "max_pages": 10})
        blob2 = " | ".join(f["title"] for f in res2["findings"])
        print(f"[battery] waf fixture: {len(res2['findings'])} findings (suppressed context)")
        assert "WAF confirmed" in blob2 and "Cloudflare" in blob2, \
            "WAF mode not behavior-confirmed"
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    test_battery_matrix()
    print("BATTERY LULUS")


PORT_SPA = 18085


def test_battery_spa():
    """SPA mode (catch-all soft-404): injection classes MUST be zero — a
    permanent regression guard for the v3.2.0 mass-FP incident. Shell
    property findings (header, cookie, page JWT) remain valid and are
    counted loosely."""
    import vulnscan2
    env = dict(os.environ, FIXTURE_MODE="spa")
    proc = subprocess.Popen([sys.executable, "tests/fixture_vuln_server.py",
                             str(PORT_SPA)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert _wait(PORT_SPA), "spa fixture did not start"
        res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT_SPA}",
                                     "enterprise-full", log=[],
                                     opts={"timeout": 5, "max_pages": 20})
        finds = res["findings"]
        print(f"\n[battery-spa] {len(finds)} findings on the SPA fixture")
        inj = [f for f in finds
               if any(c.lower() in f["title"].lower()
                      for c in INJECTION_CLASSES + ("injection",))]
        assert not inj, f"FP injeksi di SPA: {[f['title'] for f in inj]}"
        assert len(finds) <= 40, f"SPA findings ballooned: {len(finds)}"
    finally:
        proc.terminate()
