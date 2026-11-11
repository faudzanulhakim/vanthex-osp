#!/usr/bin/env python3
"""
Smoke/integration test of engine v3 against a local vulnerable fixture.
Run: python3 tests/test_smoke.py   (from the toolkit root)
Pass criteria:
- active-deep on the fixture finds the main injection & exposure categories with confidence.
- active-standard on the SPA fixture (catch-all 200) does NOT report sensitive files (anti-FP).
- HTML report does not crash (regression for the v2 `sev` bug) & store round-trip confidence/location.
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
for _sub in ("webapp", "engine", "tools", "offensive", "scripts"):
    sys.path.insert(0, os.path.join(ROOT, _sub))
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
        assert wait_port(18080, p1) and wait_port(18081, p2), "fixture did not start"

        import vulnscan2
        log = []
        t0 = time.time()
        res = vulnscan2.run_vulnscan("http://127.0.0.1:18080", "enterprise-full",
                                     log=log, opts={"timeout": 5, "max_pages": 20})
        dur = time.time() - t0
        titles = [f["title"] for f in res["findings"]]
        blob = " | ".join(titles)
        print(f"[engine] {len(titles)} findings in {dur:.0f}s; risk={res['overall_risk']}")
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
            # --- enterprise v3.1 categories ---
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
            # --- advanced v3.2 categories ---
            "SQL Injection (UNION-based": "UNION SQLi detected",
            "DOM-based XSS": "DOM XSS detected",
            "WordPress plugin detected: wp-file-manager 6.8": "WP plugin enum detected",
            "Page backup/source exposed: /report.php.bak": "source disclosure detected",
            "Password Reset Poisoning": "reset poisoning detected",
            "Session fixation": "session fixation detected",
            "Web Cache Poisoning confirmed": "cache poisoning detected",
        }
        assert "WAF detected" not in blob, "WAF FP on clean fixture"
        # FP regression v3.2.0 (real ADE case): minified JS fragments must NOT
        # become parameter targets / junk Command Injection findings.
        assert "appendChild" not in blob, "leaked JS fragment became a finding (FP v3.2.0)"
        assert "t.head" not in blob, "junk leaked JS param (FP v3.2.0)"
        missing = [v for k, v in expect.items() if k not in blob]
        assert not missing, f"MISSING CATEGORIES: {missing}"
        assert any(f["confidence"] == "confirmed" for f in res["findings"]), "no confirmed findings"
        assert any(f["confidence"] == "candidate" for f in res["findings"]), "no candidate findings (CVE)"
        assert res["scan_id_ref"], "per-scan marker is empty"
        assert res["risk_score"] >= 50, f"risk score too low: {res['risk_score']}"
        assert res["checks_total"] >= 40, f"too few enterprise checks: {res['checks_total']}"
        print(f"[enterprise] risk_score={res['risk_score']}/100, checks={res['checks_run']}/{res['checks_total']}")

        # --- anti-FP: SPA catch-all must not yield sensitive-file findings
        log2 = []
        res2 = vulnscan2.run_vulnscan("http://127.0.0.1:18081", "active-standard",
                                      log=log2, opts={"timeout": 5, "max_pages": 10})
        sens = [f["title"] for f in res2["findings"] if "Sensitive file" in f["title"]]
        print(f"[spa] findings={len(res2['findings'])}, sensitive files={sens}")
        assert not sens, f"FALSE POSITIVE on SPA: {sens}"

        # --- HTML report regression (sev v2 bug)
        from report import render_report
        scan = {"target": "http://x", "profile": "active-deep", "overall_risk": "HIGH",
                "summary": {"HIGH": 1}, "id": "test123"}
        html = render_report(scan, res["findings"][:2])
        assert "HIGH" in html and "Penetration Test Report" in html and "CONFIDENTIAL" in html
        print("[report] HTML OK (sev v2 bug did not recur)")

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
        print("\nALL TESTS PASSED ✅")
        return 0
    finally:
        for p in procs:
            p.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
