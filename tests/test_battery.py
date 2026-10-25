"""Battery ground-truth v3.4: matriks deteksi engine vs fixture terkontrol.

Dua arah diuji sekaligus:
- POSITIF: setiap kerentanan yang DITANAM di fixture WAJIB tertangkap (anti-miss).
- NEGATIF: endpoint /safe/* yang sudah dipatch TIDAK BOLEH menghasilkan temuan
  kelas injeksi (anti false-positive), dan fixture bersih tidak boleh dituduh WAF.
- Mode waf: WAF HARUS detected (kontrol positif c_waf_detection).

Jalankan: .venv/bin/python -m pytest tests/test_battery.py -q (atau file ini langsung).
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

# Kategori wajib tertangkap (fragmen judul -> label), warisan smoke + tambahan v3.4.
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
    "analisis JWT (secret lemah / tanpa exp)": "JWT",
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
    # --- tambahan battery v3.16 (perluasan jebakan) ---
    "SQLi boolean-blind murni": "SQL Injection (boolean-based): /vuln/search_bool",
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
    # ditanam rentan: LDAP simulator, GraphQL alias resolver, OIDC
    # config longgar, upload yang menyajikan ulang file HTML) ---
    "LDAP boolean v1.8": "LDAP Injection (boolean-based)",
    "GraphQL alias v1.8": "GraphQL alias amplification accepted",
    "OAuth ROPC v1.8": "OAuth password grant (ROPC) enabled",
    "upload bypass v1.8": "Upload validation bypass",
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
    assert _wait(PORT_VULN) and _wait(PORT_WAF), "fixture battery tidak start"
    return procs


def test_battery_matrix():
    procs = _boot()
    try:
        import vulnscan2
        res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT_VULN}", "enterprise-full",
                                     log=[], opts={"timeout": 5, "max_pages": 25})
        titles = [f["title"] for f in res["findings"]]
        blob = " | ".join(titles)
        print(f"\n[battery] {len(titles)} temuan enterprise-full di fixture vuln")
        missing = [k for k, frag in EXPECT.items() if frag not in blob]
        assert not missing, f"KATEGORI LOLOS (MISS): {missing}"
        # Transparansi cakupan (v3.6): status per check harus tercatat lengkap.
        # 59 = 54 sampai v1.7.0 + 4 check v1.8.0 (c_bfla_matrix,
        # c_oauth_sso, c_dns_axfr, c_cloud_buckets; LDAP differential di
        # dalam c_web_injection, GraphQL authz/depth di dalam
        # c_graphql_deep, upload bypass di dalam c_upload_surface)
        # + 1 check v1.10.0 (c_dependency_versions, WS2).
        # Angka eksplisit disengaja: check yang hilang diam-diam dari
        # registry harus menggagalkan battery ini.
        det = res.get("checks_detail") or []
        assert len(det) == res["checks_total"] == 59, \
            f"checks_detail {len(det)} != total {res['checks_total']}"
        # Kontrol v1.3 (Secrets Engine v2): pasangan kredensial AWS dari
        # riwayat .git terkonfirmasi paparannya; secret source-map dan
        # lapisan base64 tertangkap dengan evidence berlabel.
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
        # Kontrol Priority 1 (v1.2): jebakan secrets di clean.js tidak
        # boleh menghasilkan temuan; tabnabbing tepat 1 teragregasi;
        # hidden params tepat menyebut debug & preview.
        assert not [f for f in res["findings"]
                    if f.get("location") == "/static/clean.js"], \
            [f["title"] for f in res["findings"]
             if f.get("location") == "/static/clean.js"]
        # Kontrol v1.4.0: meta canary selalu hadir dan jujur (battery
        # berjalan TANPA canary -> configured False, base_kind none,
        # tidak ada klaim callback), dan setiap teknologi membawa skor
        # fingerprint WS3/K4 beserta sinyalnya di evidence temuan.
        assert res["canary"]["configured"] is False, res["canary"]
        assert res["canary"]["base_kind"] == "none", res["canary"]
        assert res["canary"]["callbacks_received"] == 0, res["canary"]
        assert all("score" in t for t in res["tech_profile"]), \
            "teknologi tanpa skor fingerprint (WS3/K4)"
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
        # Kontrol negatif JWT forgery: endpoint ketat /api/profile tidak boleh
        # muncul sebagai dapat dipalsukan.
        forgery = [t for t in titles if "can be forged" in t]
        assert forgery and all("/api/profile" not in t for t in forgery), forgery
        # Verifikasi aktif teknologi (v3.7): WordPress terbukti berjalan.
        wp = [t for t in (res.get("tech_profile") or []) if t["name"] == "WordPress"]
        assert wp and wp[0].get("verified") is True, res.get("tech_profile")
        # Deteksi database dari artefak error (v3.8): halaman 404 fixture
        # membocorkan jejak mysqli/MySQL + jalur Linux.
        # Inventory integrasi v1.1: komponen deployment/API hasil probe
        # aktif harus terverifikasi dengan versi yang benar.
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
        # CVE per komponen (kandidat) dari tabel internal berbasis rentang.
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
        assert "WAF detected" not in blob, "fixture bersih dituduh WAF (FP)"
        # NEGATIF: endpoint patched tidak boleh kena temuan kelas injeksi
        bad = [f for f in res["findings"]
               if (f.get("location") or "").startswith("/safe/")
               and any(c.lower() in f["title"].lower() for c in INJECTION_CLASSES)]
        assert not bad, f"FP di endpoint patched: {[f['title'] for f in bad]}"
        # NEGATIF WAF: fixture bersih (dengan jebakan token hex GeneXus &
        # nama vendor di teks) TIDAK BOLEH dituduh WAF sama sekali (v3.5:
        # deteksi perilaku — serangan & kontrol sama-sama 404 di path hantu).
        assert not any(t.startswith("WAF") or t.startswith("WAF indication")
                       for t in titles), "fixture bersih dituduh WAF (FP)"
        # PROFILER teknologi & integrasi (v3.5): stack fixture wajib terbaca,
        # GeneXus TIDAK boleh diklaim dari token hex saja.
        tech = {t["name"]: t for t in res.get("tech_profile") or []}
        for nama, ver in [("Apache", "2.4.49"), ("WordPress", "5.8"),
                          ("jQuery", "1.11.1"), ("Google Analytics", ""),
                          ("Google reCAPTCHA", ""), ("Stripe", ""), ("Midtrans", "")]:
            assert nama in tech, f"profiler melewatkan {nama}: {sorted(tech)}"
            if ver:
                assert tech[nama]["version"] == ver, f"{nama} versi {tech[nama]['version']} != {ver}"
        assert "GeneXus" not in tech, "GeneXus diklaim dari token hex (FP profiler)"
        # Jebakan v3.16: halaman /trap/* tidak boleh menghasilkan temuan apa
        # pun — vendor cuma teks artikel + token hex, nama DB cuma topik
        # artikel, refleksi JSON ter-escape bukan XSS/SQLi.
        traps = [f for f in res["findings"]
                 if (f.get("location") or "").startswith("/trap/")]
        assert not traps, f"FP di halaman jebakan: {[f['title'] for f in traps]}"
        assert not any("F5" in n for n in tech), "F5 diklaim dari teks/hex (FP)"
        import urllib.request as _u
        import techdb as _td
        body = _u.urlopen(f"http://127.0.0.1:{PORT_VULN}/trap/databases",
                          timeout=5).read().decode("utf-8", "replace")
        prof = _td.profile({}, body)
        assert not any(t["category"] == "Database" for t in prof), \
            f"nama DB di artikel jadi deteksi Database: {prof}"
        # WAF positif: mode waf harus TERKONFIRMASI perilaku + vendor Cloudflare
        res2 = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT_WAF}", "active-standard",
                                      log=[], opts={"timeout": 5, "max_pages": 10})
        blob2 = " | ".join(f["title"] for f in res2["findings"])
        print(f"[battery] fixture waf: {len(res2['findings'])} temuan (suppressed context)")
        assert "WAF confirmed" in blob2 and "Cloudflare" in blob2, \
            "WAF mode tidak terkonfirmasi perilaku"
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    test_battery_matrix()
    print("BATTERY LULUS")


PORT_SPA = 18085


def test_battery_spa():
    """Mode SPA (catch-all soft-404): kelas injeksi WAJIB nol — regresi
    permanen insiden FP massal v3.2.0. Temuan properti shell (header,
    cookie, JWT di halaman) tetap sah dan dihitung longgar."""
    import vulnscan2
    env = dict(os.environ, FIXTURE_MODE="spa")
    proc = subprocess.Popen([sys.executable, "tests/fixture_vuln_server.py",
                             str(PORT_SPA)], env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert _wait(PORT_SPA), "fixture spa tidak start"
        res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT_SPA}",
                                     "enterprise-full", log=[],
                                     opts={"timeout": 5, "max_pages": 20})
        finds = res["findings"]
        print(f"\n[battery-spa] {len(finds)} temuan di fixture SPA")
        inj = [f for f in finds
               if any(c.lower() in f["title"].lower()
                      for c in INJECTION_CLASSES + ("injection",))]
        assert not inj, f"FP injeksi di SPA: {[f['title'] for f in inj]}"
        assert len(finds) <= 40, f"temuan SPA membengkak: {len(finds)}"
    finally:
        proc.terminate()
