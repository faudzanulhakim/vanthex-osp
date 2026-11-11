"""Tes paket v1.5.0 (offense brain) — 6 check baru + 5 engine baru.
Each test boots the fixture on a unique port (18160+N) and runs one check via Ctx.
Engine pure (harkit/monitor/chainplanner/wordmint/vulntpl) unit-test.
"""
import json
import os
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18160


def _boot(port):
    import subprocess
    p = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return p
        except Exception:
            time.sleep(0.25)
    p.terminate()
    raise AssertionError("fixture did not start")


def _run(check, port, opts=None):
    p = _boot(port)
    try:
        import vulnscan2
        ctx = vulnscan2.Ctx(f"http://127.0.0.1:{port}/", opts or {}, [])
        found = []
        check(ctx, found.append)
        return found, ctx
    finally:
        p.terminate()


class _Res:
    def __init__(self, status, body, headers=None):
        self.status, self.body, self.headers = status, body, headers or []


class _StubClient:
    def __init__(self, routes):
        self.routes = routes

    def get(self, path, headers=None):
        return self.routes.get(("GET", path.split("?")[0]), _Res(404, ""))

    def post(self, path, data="", headers=None):
        return self.routes.get(("POST", path.split("?")[0]), _Res(404, ""))


# ---------------- c_js_bundle_mine ----------------

def test_bundle_miner_finds_legacy():
    import exploitkit
    found, _ = _run(exploitkit.c_js_bundle_mine, PORT)
    assert any("Hidden API Endpoint in JS Bundle" in f["title"] and
               "/api/legacy/admin-export" in str(f["location"])
               for f in found), [f["title"] for f in found]
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, "no confirmed findings"


# ---------------- c_session_entropy ----------------

def test_session_entropy_predictable():
    import exploitkit
    found, _ = _run(exploitkit.c_session_entropy, PORT + 1)
    assert any("Session Token" in f["title"] and
               "/api/session/new" in str(f["location"]) for f in found), \
        [f["title"] for f in found]


def test_session_entropy_safe_endpoint_not_flagged():
    """Negative: /safe/api/session/new (crypto-random) must NOT be reported."""
    import exploitkit, vulnscan2, subprocess, urllib.request
    port = PORT + 2
    p = _boot(port)
    try:
        ctx = vulnscan2.Ctx(f"http://127.0.0.1:{port}/", {}, [])
        toks = exploitkit._collect_sessions(ctx, "/safe/api/session/new", 5)
        assert len(toks) >= 4
        assert len(set(toks)) == len(toks), "safe endpoint token duplikat"
        # the delta must not be constant
        import re
        nums = [re.findall(r"\d+", t) for t in toks]
        if all(len(n) == len(nums[0]) and n for n in nums):
            for i in range(len(nums[0])):
                deltas = [int(nums[k + 1][i]) - int(nums[k][i])
                          for k in range(len(nums) - 1)]
                assert len(set(deltas)) > 1, "safe endpoint is still predictable"
    finally:
        p.terminate()


# ---------------- c_authz_matrix ----------------

def test_authz_matrix_bypass():
    import exploitkit
    found, _ = _run(exploitkit.c_authz_matrix, PORT + 3)
    assert any("Vertical Authz Bypass" in f["title"] and
               "/admin/" in str(f["location"]) for f in found), \
        [f["title"] for f in found]
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, "no confirmed findings"


# ---------------- c_openapi_stateful ----------------

def test_openapi_stateful_idor():
    import exploitkit
    found, _ = _run(exploitkit.c_openapi_stateful, PORT + 4)
    assert any("IDOR by spec" in f["title"] for f in found), \
        [f["title"] for f in found]
    conf = [f for f in found if f["confidence"] == "confirmed"]
    assert conf, "no confirmed findings"


# ---------------- c_oob_sweep ----------------

class _CtxMin:
    def __init__(self, client, opts):
        self.client, self.opts = client, opts
        self.scan_id = "t-v150"
        self.logs = []
        self.L = self.logs.append
        self.cancelled = lambda: False
        self._oob_planted = []
        self._oob_reported = set()
        self._oob_last_plant_ts = 0.0

    class _S:
        js_endpoints = ["/api/session/new"]
        param_urls = []
        pages = []

    def surface(self, full=False):
        return self._S()

    def param_targets(self, limit=20):
        return []

    def req_param(self, *a):
        return None


class _StubRegistry:
    def __init__(self):
        self.toks, self.n = [], 0

    def issue(self, label, meta=None):
        self.n += 1
        t = f"vhx{self.n:08x}"
        self.toks.append((t, label))
        return t

    def url(self, base, tok):
        return f"{base}/{tok}"

    def hits(self, tok):
        return [{"ip": "10.0.0.9", "method": "GET"}]


def test_oob_sweep_callback_attribution():
    """A token with a real callback -> confirmed findings with per-class attribution."""
    import exploitkit
    reg = _StubRegistry()
    client = _StubClient({("GET", "/"): _Res(200, "home")})
    ctx = _CtxMin(client, {"canary": {"registry": reg, "base": "http://oob.test"}})
    found = []
    exploitkit.c_oob_sweep(ctx, found.append)
    assert any("real callback" in f["title"] and
               f["confidence"] == "confirmed" for f in found), \
        ([f["title"] for f in found], ctx.logs)
    planted = ctx._oob_planted
    assert len(planted) >= 9, len(planted)  # 3 headers x3 classes + json + pre


def test_oob_sweep_skip_tanpa_canary():
    """Without a canary: the check is skipped (declared), NO findings."""
    import exploitkit
    client = _StubClient({("GET", "/"): _Res(200, "home")})
    ctx = _CtxMin(client, {})
    found = []
    exploitkit.c_oob_sweep(ctx, found.append)
    assert found == []
    assert any("canary" in m for m in ctx.logs)


# ---------------- vulntpl (custom template engine) ----------------

def test_custom_template_engine():
    import vulntpl
    tdir = os.path.join(ROOT, "templates")
    os.makedirs(tdir, exist_ok=True)
    tf = os.path.join(tdir, "_test_keys.json")
    with open(tf, "w") as fh:
        json.dump({"name": "Kunci vault terekspos", "severity": "HIGH",
                   "cwe": "CWE-538",
                   "requests": [{"path": "/vault/keys.txt"}],
                   "match": "status=200 && body~api_key"}, fh)
    try:
        import exploitkit
        found, ctx = _run(exploitkit.c_custom_templates, PORT + 5)
        assert any("Custom Template" in f["title"] and
                   "Kunci vault" in f["title"] for f in found), \
            ([f["title"] for f in found], ctx.logs)
    finally:
        os.remove(tf)


def test_vulntpl_match_logic():
    import vulntpl
    r = _Res(200, "Config {api_key: X}", [("Server", "nginx")])
    assert vulntpl.match(r, 'status=200 && body~API_KEY')
    assert vulntpl.match(r, 'status~2 && header~server:nginx')
    assert vulntpl.match(r, 'status=404 || body~api_key')
    assert not vulntpl.match(r, 'body!~api_key')
    assert not vulntpl.match(r, 'status=500')
    assert vulntpl.match(_Res(200, "abc", []), 'bodyre~^a.c$')
    # invalid template rejected
    try:
        vulntpl._validate({"requests": [{"path": "/x", "method": "DELETE"}],
                           "match": "status=200"})
        assert False, "DELETE must be rejected"
    except ValueError:
        pass


# ---------------- harkit ----------------

def test_harkit_diff():
    import harkit
    har = {"log": {"entries": [
        {"request": {"method": "GET", "url": "http://t.local/api/profile",
                     "cookies": []}}]}}

    class _ACL(_StubClient):
        def get(self, path, headers=None):
            if "session=B" in (headers or {}).get("Cookie", ""):
                return _Res(403, "")
            return _Res(200, "y" * 40)

    rows = harkit.replay_and_diff(har, _ACL({}), "session=A", "session=B")
    assert rows[0]["verdict"] == "differential", rows

    class _NOACL(_StubClient):
        def get(self, path, headers=None):
            return _Res(200, "x" * 40)

    rows2 = harkit.replay_and_diff(har, _NOACL({}), "session=A", "session=B")
    assert rows2[0]["verdict"] == "same-private", rows2
    assert "Weak authz" in harkit.report(rows2)
    assert "Empty HAR" in harkit.report([])


# ---------------- monitor ----------------

def test_monitor_diff_only_new():
    from monitor import diff_findings, _fkey, load_state, save_state
    old = [{"title": "A", "location": "/x", "param": ""}]
    new = [{"title": "A", "location": "/x", "param": ""},
           {"title": "B", "location": "/y", "param": ""}]
    nf = diff_findings(old, new)
    assert len(nf) == 1 and nf[0]["title"] == "B"
    assert len(diff_findings([], new)) == 2
    assert diff_findings(old, old) == []
    # state round-trip
    sp = os.path.join(ROOT, "tests", "_state_test.json")
    save_state(sp, old, meta={"t": 1})
    got, meta = load_state(sp)
    os.remove(sp)
    assert got == old and meta.get("t") == 1
    assert _fkey({"title": "A", "location": "/x", "param": ""}) == \
        _fkey({"title": "A", "location": "/x", "param": "", "evidence": "zz"})


# ---------------- chainplanner ----------------

def test_chainplanner_plans():
    import chainplanner
    plans = chainplanner.plan([
        {"title": "SSTI RCE", "severity": "CRITICAL"},
        {"title": "Akses config ter-ekspose", "severity": "HIGH"},
        {"title": "SSRF", "severity": "HIGH"},
    ])
    names = [p["name"] for p in plans]
    assert any("SSTI" in n for n in names), names
    assert any("metadata" in n.lower() for n in names), names
    assert all(p["steps"] for p in plans)
    assert all(p.get("operator") is True for p in plans)
    assert chainplanner.plan([]) == []
    # SSTI without config access -> chain cannot be built yet (honest)
    assert chainplanner.plan([{"title": "SSTI RCE"}]) == []


# ---------------- wordmint ----------------

def test_wordmint_bounded():
    import wordmint
    pw = wordmint.mint_passwords("Acme", extra_seeds=("dev",))
    assert 50 < len(pw) <= wordmint.MAX_PASSWORDS, len(pw)
    assert any("acme2025" in p for p in pw), pw[:10]
    subs = wordmint.mint_subdomains("acme.com")
    assert 0 < len(subs) <= wordmint.MAX_SUBDOMAINS
    assert all(s.endswith("acme.com") for s in subs)


# ---------------- proxykit passive scanner ----------------

def test_proxykit_passive_scan():
    from proxykit import PassiveScanner
    ps = PassiveScanner()
    f = ps.scan(_Res(200, "<html>ok</html>", [("Content-Type", "text/html")]),
                "http://t/")
    assert any("Missing security headers" in x["title"] for x in f), f
    f2 = ps.scan(_Res(200, "AKIAIOSFODNN7EXAMPLE",
                      [("Content-Type", "text/plain")]), "http://t/k")
    assert any("AWS Access Key" in x["title"] for x in f2)
    f3 = ps.scan(_Res(200, "ok", [("Set-Cookie", "sid=1; Path=/")]), "http://t/c")
    assert any("Set-Cookie" in x["title"] for x in f3)
    f4 = ps.scan(_Res(200, "clean", [("Content-Type", "text/plain")]), "http://t/z")
    assert f4 == []
