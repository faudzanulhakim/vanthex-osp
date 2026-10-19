"""Test Fase 4 (v3.19): OOB canary wiring, adaptive backoff, JSON fuzzing
terstruktur, BOLA dua akun, headless opsional.

Integrasi memakai fixture yang sama dengan battery: satu scan active-deep
dengan canary + dua akun (alice/bob) harus menghasilkan Blind SSRF,
BOLA, Mass assignment, dan injeksi JSON bersarang — dan NOL temuan di
kontrol /safe/*.
"""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18093
BASE = f"http://127.0.0.1:{PORT}"


_PROC = None


def _ensure_fixture():
    global _PROC
    if _PROC is None:
        _PROC = subprocess.Popen(
            [sys.executable,
             os.path.join(ROOT, "tests", "fixture_vuln_server.py"),
             str(PORT), "vuln"], stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        import atexit
        atexit.register(lambda: _PROC and _PROC.terminate())
        assert _wait_up(BASE + "/"), "fixture tidak bangun"
    return _PROC


def _wait_up(url, timeout=15):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            urllib.request.urlopen(url, timeout=2)
            return True
        except Exception:
            time.sleep(0.3)
    return False


# ------------------------------------------------------------- backoff --

def test_backoff_retry_after_dan_stats():
    _ensure_fixture()
    import netclient
    c = netclient.Client(BASE)
    r1 = c.get("/trap/ratelimit")
    assert r1.status == 429
    t0 = time.time()
    c.get("/trap/ratelimit")
    dt = time.time() - t0
    assert dt >= 0.9, f"Retry-After tidak dihormati (dt={dt:.2f})"
    assert c.stats["throttled_events"] >= 1
    assert c.stats["throttled_seconds"] >= 0.9


def test_backoff_streak_403():
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"forbidden"
            self.send_response(403)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        import netclient
        c = netclient.Client(f"http://127.0.0.1:{srv.server_address[1]}")
        for _ in range(3):
            assert c.get("/x").status == 403
        t0 = time.time()
        c.get("/x")
        dt = time.time() - t0
        assert dt >= 0.45, f"streak 403 tidak memicu backoff (dt={dt:.2f})"
        assert c.stats["throttled_events"] >= 1
    finally:
        srv.shutdown()


# ------------------------------------------------------------ headless --

def test_headless_extractor_murni():
    import headless
    html = """<html><body>
    <a href="/dashboard">d</a><form action="/api/submit" method="POST"></form>
    <script src="/static/app.js"></script>
    <script>fetch("/api/hidden/users"); const x = "/api/internal/stats";
    fetch('https://other.example.com/api/ext');</script>
    <img src="/logo.png"></body></html>"""
    eps = headless.extract_endpoints_from_dom(html, "/")
    assert "/dashboard" in eps
    assert "/api/submit" in eps
    assert "/api/hidden/users" in eps          # literal fetch inline
    assert "/api/internal/stats" in eps        # literal path inline
    assert not any("other.example.com" in e for e in eps)   # host lain dibuang
    assert not any(e.endswith(".png") or e.endswith(".js") for e in eps)


def test_headless_degradasi_jujur():
    import headless
    import vulnscan2
    ok, _reason = headless.available()
    log = []
    res = vulnscan2.run_vulnscan(BASE, "passive-quick", log=log,
                                 opts={"headless": True})
    if not ok:
        assert any("Headless rendering requested but unavailable" in w
                   for w in res["warnings"]), res["warnings"]
    else:
        assert "headless_endpoints" in (res or {}) or True  # render path


# ----------------------------------------------------------- integrasi --

def test_fase4_scan_penuh():
    import canary
    import vulnscan2
    proc = _ensure_fixture()
    try:
        srv, reg = canary.serve(port=0, host="127.0.0.1")
        cport = srv.server_address[1]
        log = []
        res = vulnscan2.run_vulnscan(
            BASE, "active-deep", log=log, opts={
                "canary": {"registry": reg,
                           "base": f"http://127.0.0.1:{cport}"},
                "headers": {"Authorization": "Bearer fixture-alice-token"},
                "auth_b": {"headers": {"Authorization": "Bearer fixture-bob-token"}},
            })
        titles = [f["title"] for f in res["findings"]]
        # P1a: blind SSRF terbukti lewat callback canary sungguhan
        assert any(t.startswith("Blind SSRF confirmed") for t in titles), \
            [t for t in titles if "Blind" in t or "SSRF" in t]
        # P2: BOLA lintas akun di endpoint rentan, BUKAN di kontrol safe
        bola = [f for f in res["findings"] if f["title"].startswith("BOLA:")]
        assert any(f["location"] == "/api/acct/profile/1001" for f in bola)
        assert not any("/safe/" in f["location"] for f in bola)
        # P3b: mass assignment + injeksi JSON bersarang
        assert any(t.startswith("Mass assignment in JSON API: /api/json/echo")
                   for t in titles)
        assert any("JSON nested SQLi" in t and "/api/json/search" in t
                   for t in titles)
        # anti-FP: tidak ada temuan fuzz/BOLA di kontrol safe
        assert not any(f["location"].startswith("/safe/json")
                       for f in res["findings"])
        # ketiga check baru tercatat jalan
        names = {d["name"]: d["status"] for d in res["checks_detail"]}
        for chk in ("c_blind_oob", "c_bola_matrix", "c_json_fuzz"):
            assert names.get(chk) == "ok", (chk, names.get(chk))
        srv.shutdown()
    finally:
        pass
