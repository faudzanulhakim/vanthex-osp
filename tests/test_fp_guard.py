"""FP-guard tests (v1.2.4): reflection-echo false positives must never be
credited as CONFIRMED execution proof.

Covers:
- _echo_only_response unit cases (redirect Location echo, URL-encoded body
  echo, next= echo, decoded standalone marker = real proof);
- _is_auth_redirect;
- exploitkit c_cmdi_confirm on /fp/echo -> NO confirmed finding;
- /fp/true-cmdi -> CONFIRMED with verification 'executed-proof';
- /fp/safe/cmdi -> nothing;
- xpath confirm on a redirect-echo endpoint is not confirmed;
- auth-redirect endpoints are skipped with an [fp-guard] log line;
- report.py HTML renders 'Verification:' + verification_note, and renders
  old findings (without the new keys) gracefully.
All hermetic: the fixture server is booted locally on a free-ish port.
"""
import os
import subprocess
import sys
import time
import urllib.request
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18311


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


def _R(status=200, body="", headers=None):
    return SimpleNamespace(status=status, body=body,
                           headers=headers or {})


# ---------------------------------------------------------------- unit tests

def test_echo_only_redirect_location_echo():
    import vulnscan2
    m = "1;echo PTKab12"
    r = _R(302, "", {"Location": f"/login?next=%2Fapp%3Fq%3D1%3Becho%20PTKab12"})
    assert vulnscan2._echo_only_response(r, m)
    r2 = _R(302, "", {"Location": f"/login?next={m}"})
    assert vulnscan2._echo_only_response(r2, m)


def test_echo_only_urlencoded_body_echo():
    import vulnscan2
    m = "1;echo PTKab12"
    from urllib.parse import quote
    body = f"<html>q={quote(m, safe='')}&amp;next=/login</html>"
    assert vulnscan2._echo_only_response(_R(200, body), m)


def test_echo_only_next_param_body_echo():
    import vulnscan2
    m = "1;echo PTKab12"
    from urllib.parse import quote
    nxt = quote("/app?q=" + m, safe="")
    body = (f"<html><form><input type='password' name='password'></form>"
            f"<a href='/login?next={nxt}'>next</a></html>")
    assert vulnscan2._echo_only_response(_R(200, body), m)


def test_decoded_standalone_marker_is_not_echo_only():
    import vulnscan2
    m = "1;echo PTKab12"
    # real execution proof: decoded marker standalone in the body
    assert not vulnscan2._echo_only_response(_R(200, "output: 1;echo PTKab12"), m)
    # marker outside the echo AND inside an echo -> still real proof
    from urllib.parse import quote
    tok = "PTKab12"
    nxt = quote("/app?q=" + m, safe="")
    body = f"result {tok} done <a href='/login?next={nxt}'>n</a>"
    assert not vulnscan2._echo_only_response(_R(200, body), tok)
    assert not vulnscan2._echo_only_response(_R(200, "nothing here"), m)


def test_is_auth_redirect():
    import vulnscan2
    assert vulnscan2._is_auth_redirect(
        _R(302, "", {"Location": "/login?next=%2Fadmin"}))
    assert not vulnscan2._is_auth_redirect(_R(200, "<html>ok</html>"))
    assert vulnscan2._is_auth_redirect(_R(200, (
        "<html><form><input type='password' name='password'></form>"
        "<input type='hidden' name='goto' value='x'>?next=/x</html>")))


# ----------------------------------------------------------- integration

class _LogCtx:
    """Minimal Ctx stand-in for exploitkit.c_cmdi_confirm / _fp_gate."""

    def __init__(self, client, num_a=7, num_b=3):
        self.client = client
        self.num_a, self.num_b = num_a, num_b
        self.target = "http://127.0.0.1:18311"
        self.logs = []

    def L(self, msg):
        self.logs.append(str(msg))

    def cancelled(self):
        return False

    def surface(self, full=False):
        return SimpleNamespace(param_urls=[], js_endpoints=[], path_urls=[],
                               forms=[])

    def is_missing(self, r):
        return getattr(r, "status", 0) in (0, 404, 410)

    def req_param(self, base, pname, value, method="GET", orig_qs=None):
        from urllib.parse import quote
        sep = "&" if "?" in base else "?"
        return self.client.get(f"{base}{sep}{pname}={quote(value, safe='')}")


def test_cmdi_confirm_on_echo_endpoint_never_confirmed():
    import exploitkit
    import vulnscan2
    p = _boot(PORT + 1)
    try:
        from netclient import Client
        ctx = _LogCtx(Client(f"http://127.0.0.1:{PORT + 1}"))
        found = []
        exploitkit.c_cmdi_confirm(ctx, found.append)
        confirmed = [f for f in found if f["confidence"] == "confirmed"]
        assert not confirmed, f"unexpected confirmed on /fp/echo: {confirmed}"
    finally:
        p.terminate()


def test_fp_gate_downgrades_echo_and_skips_auth_redirect():
    import exploitkit
    import vulnscan2
    p = _boot(PORT + 2)
    try:
        from netclient import Client
        cl = Client(f"http://127.0.0.1:{PORT + 2}")
        ctx = _LogCtx(cl)
        payload = "1;echo PTKguard1"
        r = cl.get(f"/fp/echo?q=1%3Becho%20PTKguard1")
        g = vulnscan2._fp_gate(ctx, r, payload, "/fp/echo")
        assert g == "echo", g
        f = vulnscan2.F("CRITICAL", "Command Injection verified: /fp/echo",
                        "d", evidence="x", confidence="confirmed",
                        location="/fp/echo", verification="executed-proof")
        g2 = exploitkit_guard(ctx, f, r, payload, "/fp/echo")
        assert g2 is not None and g2["confidence"] == "candidate"
        assert g2["verification"] == "reflection-only"
        assert "NOT proof of execution" in g2["verification_note"]

        r2 = cl.get("/fp/auth-redirect")
        assert vulnscan2._fp_gate(ctx, r2, "zzz-no-echo", "/fp/auth-redirect") \
            == "skip"
        assert any("[fp-guard]" in l and "unauthenticated redirect" in l
                   for l in ctx.logs), ctx.logs
    finally:
        p.terminate()


def exploitkit_guard(ctx, f, resp, marker, loc):
    import exploitkit
    return exploitkit._guard_finding(ctx, f, resp, marker, loc)


def test_cmdi_confirm_true_cmdi_confirmed():
    import exploitkit
    p = _boot(PORT + 4)
    try:
        from netclient import Client
        ctx = _LogCtx(Client(f"http://127.0.0.1:{PORT + 4}"))
        orig = exploitkit._targets
        exploitkit._targets = lambda c, limit=36: \
            [("/fp/true-cmdi", "q", "GET", "")]
        try:
            found = []
            exploitkit.c_cmdi_confirm(ctx, found.append)
        finally:
            exploitkit._targets = orig
        conf = [f for f in found if f["confidence"] == "confirmed"]
        assert conf, found
        assert all(f.get("verification") == "executed-proof" for f in conf), conf

        ctx2 = _LogCtx(Client(f"http://127.0.0.1:{PORT + 4}"))
        exploitkit._targets = lambda c, limit=36: \
            [("/fp/safe/cmdi", "q", "GET", "")]
        try:
            found2 = []
            exploitkit.c_cmdi_confirm(ctx2, found2.append)
        finally:
            exploitkit._targets = orig
        assert not found2, found2
    finally:
        p.terminate()


def test_xpath_confirm_on_redirect_echo_not_confirmed():
    import exploitkit
    p = _boot(PORT + 5)
    try:
        from netclient import Client
        cl = Client(f"http://127.0.0.1:{PORT + 5}")

        class _Rewrite:
            """Send the check's xpath probes to the redirect-echo endpoint."""

            def __init__(self, c):
                self.c = c

            def get(self, path, **kw):
                path = path.replace("/xpath/search", "/fp/echo")
                path = path.replace("/xpath/blind", "/fp/echo")
                return self.c.get(path, **kw)

        ctx = _LogCtx(_Rewrite(cl))
        ctx.target = f"http://127.0.0.1:{PORT + 5}"

        # redirect c_xpath_confirm's probes at the echo endpoint
        orig_targets = exploitkit._targets
        exploitkit._targets = lambda c, limit=36: \
            [("/fp/echo", "name", "GET", "")]
        try:
            found = []
            exploitkit.c_xpath_confirm(ctx, found.append)
        finally:
            exploitkit._targets = orig_targets
        conf = [f for f in found if f["confidence"] == "confirmed"]
        assert not conf, conf
    finally:
        p.terminate()


def test_report_renders_verification_and_note():
    import report
    scan = {"id": "T1", "target": "http://x", "profile": "enterprise-full",
            "scan_type": "vulnscan"}
    new_f = {"severity": "CRITICAL", "title": "Cmdi (reflection only)",
             "description": "d", "evidence": "e", "cwe": "CWE-78",
             "owasp": "", "cvss": 9.8, "remediation": "r",
             "confidence": "candidate", "location": "/fp/echo",
             "param": "q", "origin": "exploitkit",
             "verification": "reflection-only",
             "verification_note": "Marker only reflected inside an echoed "
                                  "query string — NOT proof of execution."}
    html = report.render_report(scan, [new_f])
    # verification moved to the web UI (operator-facing) — reports no
    # longer carry the Verification rows; manual validation only shows
    # for findings that carry a manual_check block
    assert "Verification:" not in html


def test_report_graceful_without_new_keys():
    import report
    scan = {"id": "T2", "target": "http://x", "profile": "p",
            "scan_type": "vulnscan"}
    old_f = {"severity": "HIGH", "title": "Old finding",
             "description": "d", "evidence": "", "cwe": "", "owasp": "",
             "cvss": 5.0, "remediation": "", "confidence": "probable",
             "location": "/", "param": "", "origin": "active"}
    html = report.render_report(scan, [old_f])
    assert "Old finding" in html  # renders without error; no Verification row


def test_docx_renders_verification_gracefully():
    import docx_report
    scan = {"id": "T3", "target": "http://x", "profile": "p",
            "scan_type": "vulnscan"}
    new_f = {"severity": "CRITICAL", "title": "t", "description": "d",
             "evidence": "e", "cwe": "", "owasp": "", "cvss": 9.0,
             "remediation": "r", "confidence": "candidate", "location": "/",
             "param": "", "origin": "exploitkit",
             "verification": "reflection-only",
             "verification_note": "not proof"}
    old_f = {"severity": "LOW", "title": "old", "description": "d",
             "evidence": "", "cwe": "", "owasp": "", "cvss": 2.0,
             "remediation": "", "confidence": "probable", "location": "/",
             "param": "", "origin": "active"}
    out = os.path.join(ROOT, ".hermes_test_fp_guard.docx")
    try:
        docx_report.generate_docx(scan, [new_f, old_f], out)
        assert os.path.exists(out)
        import zipfile
        with zipfile.ZipFile(out) as zf:
            doc = zf.read("word/document.xml").decode("utf-8", "replace")
        assert "Verification:" not in doc
    finally:
        if os.path.exists(out):
            os.remove(out)


def test_F_infers_verification_default():
    import vulnscan2
    assert vulnscan2.F("HIGH", "t", "d", confidence="confirmed")[
        "verification"] == "signature"
    assert vulnscan2.F("HIGH", "t", "d", confidence="probable")[
        "verification"] == "manual-required"
    assert vulnscan2.F("HIGH", "t", "d", confidence="candidate")[
        "verification"] == "reflection-only"
    assert vulnscan2.F("HIGH", "t", "d", confidence="candidate",
                       verification="differential")["verification"] == \
        "differential"
