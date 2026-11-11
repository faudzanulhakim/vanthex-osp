"""Accuracy v3 regression tests (round 2).

Covers:
- /fp/blind-cmdi: true blind command execution — the time-based confirm
  path uses the round-2 timing rules (timingoracle.blind_time_confirm:
  3 consistent attempts at >= 2.5x baseline and >= baseline + 0.8 s plus
  a scaling pair sleep-2 >= 1.4x sleep-1) and credits CONFIRMED with
  verification 'differential' and scaling evidence;
- /fp/blind-noisy: network-noise control (0.2-0.4 s jitter regardless of
  q) — the merely elevated response is downgraded to candidate with
  verification 'manual-required' and the scaling-failure note;
- candidate CVSS scaling: a candidate finding shows the scaled/capped
  score (9.8 -> 3.9) with impact_cvss 9.8 preserved, and the report HTML
  renders 'Impact potential' for it (graceful when impact_cvss missing);
- XSS canary upgrade: a near-miss reflection with a UNIQUE canary token
  (PTKXSS + 8 hex) coming back DECODED outside echo contexts is
  probable/'differential'; an echo-only canary (next= query echo) stays
  candidate/'reflection-only'.

All hermetic: the fixture server is booted locally on a free-ish port
and the XSS cases use a tiny in-process HTTP server.
Run: .venv/bin/python -m pytest tests/test_accuracy_v3.py -q
"""
import http.server
import html as _html
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.request
from types import SimpleNamespace
from urllib.parse import quote, urlparse, parse_qs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18380


def _boot(port=PORT):
    p = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return p
        except Exception:
            time.sleep(0.25)
    raise AssertionError("fixture did not start")


class _LogCtx:
    """Minimal Ctx stand-in for exploitkit.c_cmdi_confirm."""

    def __init__(self, client, num_a=7, num_b=3):
        self.client = client
        self.num_a, self.num_b = num_a, num_b
        self.target = f"http://127.0.0.1:{PORT}"
        self.logs = []

    def L(self, msg):
        self.logs.append(str(msg))

    def cancelled(self):
        return False

    def is_missing(self, r):
        return getattr(r, "status", 0) in (0, 404, 410)

    def req_param(self, base, pname, value, method="GET", orig_qs=None):
        sep = "&" if "?" in base else "?"
        return self.client.get(f"{base}{sep}{pname}={quote(value, safe='')}")


def _cmdi_on(path, port):
    import exploitkit
    from netclient import Client
    ctx = _LogCtx(Client(f"http://127.0.0.1:{port}"))
    orig = exploitkit._targets
    exploitkit._targets = lambda c, limit=36: [(path, "q", "GET", "")]
    found = []
    try:
        exploitkit.c_cmdi_confirm(ctx, found.append)
    finally:
        exploitkit._targets = orig
    return found


def test_blind_cmdi_confirmed_with_scaling_evidence():
    p = _boot(PORT + 1)
    try:
        found = _cmdi_on("/fp/blind-cmdi", PORT + 1)
        conf = [f for f in found if f["confidence"] == "confirmed"]
        assert conf, found
        f = conf[0]
        assert "time-based" in f["title"]
        assert f["verification"] == "differential"
        # round-2 evidence: baseline, per-attempt timings, scaling pair
        ev = f["evidence"]
        assert "baseline" in ev, ev
        assert "sleep-2 attempts" in ev, ev
        assert "scaling pair" in ev, ev
    finally:
        p.terminate()


def test_blind_noisy_downgraded_candidate_manual_required():
    p = _boot(PORT + 2)
    try:
        found = _cmdi_on("/fp/blind-noisy", PORT + 2)
        conf = [f for f in found if f["confidence"] == "confirmed"]
        assert not conf, f"noisy endpoint must never confirm: {conf}"
        cand = [f for f in found if f["confidence"] == "candidate"]
        assert cand, found
        f = cand[0]
        assert f["verification"] == "manual-required"
        assert "scaling test failed" in f["verification_note"], \
            f["verification_note"]
        assert "network noise" in f["verification_note"]
    finally:
        p.terminate()


def test_candidate_cvss_scaled_and_impact_potential_rendered():
    import vulnscan2
    import report
    f = vulnscan2.F("CRITICAL", "Blind OS Command Injection (time-based)",
                    "d", evidence="e", cwe="CWE-78", cvss=9.8,
                    confidence="candidate", location="/fp/blind-noisy",
                    verification="manual-required",
                    verification_note="note")
    assert f["cvss"] == 3.9, f["cvss"]
    assert f["impact_cvss"] == 9.8, f["impact_cvss"]
    scan = {"id": "V3", "target": "http://x", "profile": "p",
            "scan_type": "vulnscan"}
    html_out = report.render_report(scan, [f])
    assert "Impact potential:" in html_out
    assert "9.8" in html_out
    # confirmed findings keep their score and mirror impact_cvss
    f2 = vulnscan2.F("CRITICAL", "t", "d", cvss=9.8, confidence="confirmed")
    assert f2["cvss"] == 9.8 and f2["impact_cvss"] == 9.8


def test_report_impact_potential_graceful_when_missing():
    import report
    old_f = {"severity": "HIGH", "title": "Old finding", "description": "d",
             "evidence": "", "cwe": "", "owasp": "", "cvss": 5.0,
             "remediation": "", "confidence": "candidate",
             "location": "/", "param": "", "origin": "active"}
    scan = {"id": "V4", "target": "http://x", "profile": "p",
            "scan_type": "vulnscan"}
    html_out = report.render_report(scan, [old_f])
    assert "Old finding" in html_out  # renders without error
    assert "Impact potential:" not in html_out


# ------------------------------------------------------------ XSS canary

def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _serve(handler_cls):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


class _XssHandler(http.server.BaseHTTPRequestHandler):
    """Two near-miss reflection endpoints (quotes/angle brackets are
    stripped, so no payload can break out of the href attribute — the
    marker lands inside an attribute value = near_miss, never a proven
    executable position):

    /xssdiff  reflects q into a plain id= URL attribute — the canary
              comes back DECODED outside any echoed query value ->
              probable / differential.
    /xssecho  reflects q into a next= query echo (the v1.2.4 FP
              pattern) — the canary only survives inside the echoed
              query value -> candidate / reflection-only.
    """

    def _strip(self, v):
        # strips the special characters so families are limited to the
        # script family and breakouts are impossible
        return str(v).replace('"', "").replace("'", "") \
            .replace("<", "").replace(">", "")

    def do_GET(self):
        p = urlparse(self.path).path
        q = self._strip(parse_qs(urlparse(self.path).query)
                        .get("q", [""])[0])
        if p == "/":
            body = ("<html><head><title>xss lab</title></head><body>"
                    "<a href='/xssdiff?q=hello'>diff lab</a>"
                    "<a href='/xssecho?q=hello'>echo lab</a>"
                    "</body></html>")
        elif p == "/xssdiff":
            body = (f"<html><head><title>diff</title></head><body>"
                    f"<a href=\"/item?id={q}\">go</a></body></html>")
        elif p == "/xssecho":
            body = (f"<html><head><title>echo</title></head><body>"
                    f"<a href=\"/login?next={q}\">next</a></body></html>")
        else:
            body = "<html><body>404 page</body></html>"
        data = body.encode()
        self.send_response(404 if p == "/nope" else 200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.do_GET()

    def log_message(self, *a):
        pass


def _scan_xss(path):
    import vulnscan2
    srv, port = _serve(_XssHandler)
    try:
        res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{port}",
                                     "active-deep", log=[])
    finally:
        srv.shutdown()
    return [f for f in res["findings"]
            if "position not confirmed" in f["title"] and path in
            f.get("location", "")]


def test_xss_canary_differential_on_decoded_reflection():
    fs = _scan_xss("/xssdiff")
    assert fs, "no near-miss XSS finding for /xssdiff"
    f = fs[0]
    assert f["confidence"] == "probable", f
    assert f["verification"] == "differential", f
    assert "canary PTKXSS" in f["evidence"], f["evidence"]
    assert "decoded outside echo contexts" in f["evidence"]


def test_xss_canary_echo_only_stays_reflection_only():
    fs = _scan_xss("/xssecho")
    assert fs, "no near-miss XSS finding for /xssecho"
    f = fs[0]
    assert f["confidence"] == "candidate", f
    assert f["verification"] == "reflection-only", f
    assert "Generic family reflection only" in f["verification_note"], \
        f["verification_note"]
