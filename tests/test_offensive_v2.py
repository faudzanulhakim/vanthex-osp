"""Tes offensive pack v1.4.0 — 13 check baru (credkit/dirbrute/exploitkit),
engine payloadforge.waf_variants, dan pipeline sesskit (stub client).
Each test boots the fixture on port 18150+N so it does not clash with test_exploitkit.
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18150


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


def _run(check, port):
    """Boot the fixture, run one check, return the findings."""
    import vulnscan2
    p = _boot(port)
    try:
        ctx = vulnscan2.Ctx(f"http://127.0.0.1:{port}/", {}, [])
        found = []
        check(ctx, found.append)
        return found
    finally:
        p.terminate()


# ---------------- credkit ----------------

def test_password_spray_on_fixture():
    import credkit
    found = _run(credkit.c_password_spray, PORT)
    assert any("Password Spray" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf and all(str(f["location"]) == "/spray/login" for f in conf), conf


def test_otp_bypass_on_fixture():
    import credkit
    found = _run(credkit.c_otp_bypass, PORT + 1)
    assert any("OTP/2FA Bypass" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf and all(str(f["location"]) == "/otp/verify" for f in conf), conf


def test_user_enum_on_fixture():
    import credkit
    found = _run(credkit.c_user_enum, PORT + 2)
    assert any("Username Enumeration" in f["title"] for f in found), found


# ---------------- exploitkit v1.4.0 ----------------

def test_ssti_rce_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_ssti_rce, PORT + 3)
    assert any("SSTI" in f["title"] and "config" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf and all(str(f["location"]) == "/template/render" for f in conf), conf


def test_sqli_second_order_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_sqli_second_order, PORT + 4)
    assert any("Second-Order SQL" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, conf


def test_sqli_extract_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_sqli_extract, PORT + 5)
    assert any("Database Schema Enumeration" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, conf


def test_deser_gadget_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_deser_gadget, PORT + 6)
    langs = {f["title"] for f in found}
    assert any("JAVA" in t for t in langs) and any("PHP" in t for t in langs), found


def test_cve_exploit_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_cve_exploit, PORT + 7)
    titles = " | ".join(f["title"] for f in found)
    for needle in ("Log4Shell", "Shellshock", "PHP-CGI", "SpEL"):
        assert needle in titles, (needle, titles)
    assert all(f["confidence"] == "confirmed" for f in found), found


def test_prototype_rce_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_prototype_rce, PORT + 8)
    assert any("Prototype Pollution" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf and all(str(f["location"]) == "/pollute" for f in conf), conf


def test_h2c_smuggling_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_h2c_smuggling, PORT + 9)
    assert any("h2c Smuggling" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, conf


def test_cache_deception_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_cache_deception, PORT + 10)
    assert any("Cache Deception" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, conf


def test_waf_bypass_on_fixture():
    import exploitkit
    found = _run(exploitkit.c_waf_bypass, PORT + 11)
    # the title deliberately does NOT start with "WAF" — the battery anti-FP
    # tripwire flags the clean fixture if any WAF-* finding appears.
    assert any("Signature-Based Filter Evasion" in f["title"] for f in found), found
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, conf


# ---------------- dirbrute ----------------

def test_dir_bruteforce_on_fixture():
    import dirbrute
    found = _run(dirbrute.c_dir_bruteforce, PORT + 12)
    locs = {str(f["location"]) for f in found}
    assert any("vault" in l for l in locs), locs
    assert all(f["confidence"] == "confirmed" for f in found), found


# ---------------- payloadforge.waf_variants (unit) ----------------

def test_waf_variants_filters_blocked():
    import payloadforge as pf
    payload = "<script>alert('x')</script>"
    vs = pf.waf_variants(payload, blocked=("<script>alert(",))
    assert vs, "there must be a variant that passes the filter"
    for v in vs:
        assert "<script>alert(" not in v.lower(), v
    # no blocked pattern: the canonical payload stays first
    vs2 = pf.waf_variants(payload, blocked=())
    assert vs2[0] == payload


# ---------------- sesskit (pipeline, stub client) ----------------

class _StubClient:
    """Client stub: upload accepts multipart; GET on the exact serve_url (no
    query) returns the uploaded file contents; GET with ?c= returns
    simulated execution output (or the raw payload when echo=True)."""

    def __init__(self, echo=False):
        self.uploaded = {}
        self.echo = echo

    def post(self, path, data=None, headers=None):
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        self.uploaded[path] = data or ""
        from types import SimpleNamespace
        return SimpleNamespace(status=200, body="upload ok", headers=[])

    def get(self, path, headers=None, params=None):
        from types import SimpleNamespace
        if "?" not in path and path.startswith("/uploads/"):
            body = self.uploaded.get("/upload", "")
        elif self.echo:
            body = self.uploaded.get("/upload", "")
        else:
            body = "uid=1000(vhx) gid=1000(vhx) groups=1000(vhx)" \
                   " | Linux fixture 6.8.0-generic GNU/Linux"
        return SimpleNamespace(status=200, body=body, headers=[])


def test_sesskit_pipeline_with_stub():
    import sesskit
    rep = sesskit.run_pipeline(_StubClient(), "/upload", "sh.php", "php",
                               marker="VHXTEST")
    assert rep["status"] == "ok", rep
    assert rep["exec"] == "verified", rep
    assert "uid" in rep["enum"].get("uid", ""), rep
    assert rep["serve_url"].endswith("sh.php"), rep


def test_sesskit_pipeline_reports_not_executed():
    """A client that echoes the raw payload -> honest 'not-executed'."""
    import sesskit
    rep = sesskit.run_pipeline(_StubClient(echo=True), "/upload", "sh.php", "php")
    assert rep["status"] == "ok", rep
    assert rep["exec"] == "not-executed", rep


# ---------------- wiring ----------------

def test_new_checks_resolve_in_profiles():
    import vulnscan2
    for prof in ("active-exploit", "enterprise-full"):
        for name in ("c_ssti_rce", "c_deser_gadget", "c_cve_exploit",
                     "c_h2c_smuggling", "c_waf_bypass"):
            assert name in vulnscan2.PROFILES[prof], (prof, name)
    for name in ("c_password_spray", "c_otp_bypass", "c_user_enum"):
        assert name in vulnscan2.PROFILES["enterprise-full"], name
        assert name not in vulnscan2.PROFILES["active-exploit"], name
    # every name in every profile resolves to a callable
    for prof, checks in vulnscan2.PROFILES.items():
        for name in checks:
            assert callable(getattr(vulnscan2, name, None)), (prof, name)
