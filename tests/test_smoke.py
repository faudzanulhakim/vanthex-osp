#!/usr/bin/env python3
"""
Smoke/integration test engine v3 melawan fixture rentan lokal.
Jalankan: python3 tests/test_smoke.py   (dari root toolkit)
Syarat lulus:
- active-deep di fixture menemukan kategori injeksi & exposure utama dengan confidence.
- active-standard di fixture mode SPA (catch-all 200) TIDAK melaporkan file sensitif (anti-FP).
- report HTML tidak crash (regresi bug `sev` v2) & store round-trip confidence/location.
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)


def wait_port(port, proc, tries=40):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return True
        except urllib.error.HTTPError:
            return True
        except Exception:
            if proc.poll() is not None:
                return False
            time.sleep(0.25)
    return False


def main():
    procs = []
    try:
        env1 = dict(os.environ)
        p1 = subprocess.Popen([sys.executable, "tests/fixture_vuln_server.py", "18080"],
                              env=env1, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        env2 = dict(os.environ, FIXTURE_MODE="spa")
        p2 = subprocess.Popen([sys.executable, "tests/fixture_vuln_server.py", "18081"],
                              env=env2, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs = [p1, p2]
        assert wait_port(18080, p1) and wait_port(18081, p2), "fixture tidak start"

        import vulnscan2
        log = []
        t0 = time.time()
        res = vulnscan2.run_vulnscan("http://127.0.0.1:18080", "enterprise-full",
                                     log=log, opts={"timeout": 5, "max_pages": 20})
        dur = time.time() - t0
        titles = [f["title"] for f in res["findings"]]
        blob = " | ".join(titles)
        print(f"[engine] {len(titles)} findings dalam {dur:.0f} dtk; risk={res['overall_risk']}")
        for t in titles:
            print("   -", t)
        expect = {
            "SQL Injection": "SQLi detected",
            "Reflected XSS": "XSS detected",
            "Template Injection": "SSTI detected",
            "Path Traversal": "LFI/traversal detected",
            "Command Injection": "CMDi detected",
            "Open Redirect": "open redirect detected",
            "CORS": "CORS detected",
            "Sensitive file exposed: /.env": ".env signature-verified",
            "Directory listing": "directory listing detected",
            "without anti-CSRF token": "CSRF form detected",
            "JWT": "analisis JWT (secret lemah / tanpa exp)",
            "API documentation exposed": "OpenAPI exposure detected",
            "GraphQL introspection": "GraphQL introspection detected",
            "Cookie 'session'": "cookie flags detected",
            "TRACE enabled": "TRACE/XST detected",
            "Apache 2.4.49": "fingerprint/kandidat CVE Apache",
            # --- kategori enterprise v3.1 ---
            "XML External Entity": "XXE detected",
            "IDOR/BOLA indication": "IDOR/BOLA detected",
            "NoSQL Injection in API": "NoSQL API detected",
            "Default credentials work": "default credentials detected",
            "No rate limiting": "rate-limit login detected absent",
            "File upload WITHOUT authentication confirmed": "upload unauth confirmed",
            "File upload form found": "form upload detected",
            "Verbose error": "error disclosure detected",
            "Outdated JS library: jQuery 1.11.1": "JS library usang detected",
            "JavaScript source map exposed": "source map detected",
            "Session token in URL": "session-in-URL detected",
            "Login form/credentials sent over plain HTTP": "login via HTTP detected",
            "security.txt not found": "security.txt detected absent",
            "robots.txt discloses sensitive paths": "robots disclosure detected",
            "Unauthenticated API leaks sensitive fields": "API sensitive data detected",
            "Serialized data detected": "deserialization surface detected",
            "without Subresource Integrity": "SRI absen detected",
            # --- kategori advanced v3.2 ---
            "SQL Injection (UNION-based": "UNION SQLi detected",
            "DOM-based XSS": "DOM XSS detected",
            "WordPress plugin detected: wp-file-manager 6.8": "WP plugin enum detected",
            "Page backup/source exposed: /report.php.bak": "source disclosure detected",
            "Password Reset Poisoning": "reset poisoning detected",
            "Session fixation": "session fixation detected",
            "Web Cache Poisoning confirmed": "cache poisoning detected",
        }
        assert "WAF detected" not in blob, "WAF FP di fixture bersih"
        # Regresi FP v3.2.0 (kasus nyata ADE): fragmen JS minified TIDAK boleh
        # menjadi target parameter / temuan Command Injection sampah.
        assert "appendChild" not in blob, "fragmen JS bocor menjadi temuan (FP v3.2.0)"
        assert "t.head" not in blob, "param sampah JS bocor (FP v3.2.0)"
        missing = [v for k, v in expect.items() if k not in blob]
        assert not missing, f"KATEGORI HILANG: {missing}"
        assert any(f["confidence"] == "confirmed" for f in res["findings"]), "tidak ada confirmed"
        assert any(f["confidence"] == "candidate" for f in res["findings"]), "tidak ada candidate (CVE)"
        assert res["scan_id_ref"], "marker per-scan kosong"
        assert res["risk_score"] >= 50, f"risk score terlalu rendah: {res['risk_score']}"
        assert res["checks_total"] >= 40, f"check enterprise kurang: {res['checks_total']}"
        print(f"[enterprise] risk_score={res['risk_score']}/100, checks={res['checks_run']}/{res['checks_total']}")

        # --- anti-FP: SPA catch-all tidak boleh menghasilkan file sensitif
        log2 = []
        res2 = vulnscan2.run_vulnscan("http://127.0.0.1:18081", "active-standard",
                                      log=log2, opts={"timeout": 5, "max_pages": 10})
        sens = [f["title"] for f in res2["findings"] if "Sensitive file" in f["title"]]
        print(f"[spa] findings={len(res2['findings'])}, file sensitif={sens}")
        assert not sens, f"FALSE POSITIVE di SPA: {sens}"

        # --- regresi report HTML (bug sev v2)
        from report import render_report
        scan = {"target": "http://x", "profile": "active-deep", "overall_risk": "HIGH",
                "summary": {"HIGH": 1}, "id": "test123"}
        html = render_report(scan, res["findings"][:2])
        assert "HIGH" in html and "Penetration Test Report" in html and "CONFIDENTIAL" in html
        print("[report] HTML OK (bug sev v2 tidak kambuh)")

        # --- store round-trip confidence/location + diff
        import store, tempfile
        store.DB_PATH = os.path.join(tempfile.mkdtemp(), "t.db")
        store.init_db()
        sid = store.save_scan("http://127.0.0.1:18080", "vulnscan", "active-deep", res)
        got = store.get_findings(sid)
        assert got and "confidence" in got[0] and "location" in got[0]
        d = store.diff_scans(sid)
        assert d is not None and d["previous_scan_id"] is None
        print("[store] round-trip OK, diff OK")
        print("\nSEMUA TEST LULUS ✅")
        return 0
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
