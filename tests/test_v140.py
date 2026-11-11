"""VANTHEX v1.4.0 — Accuracy & OSINT Depth acceptance tests.

WS1 OAST: formal per-scan canary registry, grace-window re-poll,
        blind CMDi/XSS through the same canary path, honest meta.
WS2 XSS:  marker sandwich + parsed-DOM position evidence (5 kinds),
        inert guards, stored baseline diff.
WS3:      scored fingerprinting (data rules, max-merge, floor 0.3,
        provocation exceptions) + F5-incident dataset regression.
WS4:      A3 gen-2 — structured dataset, offline self-check with
        persistent disabling (UNKNOWN never disables), profile
        extraction, recursive typed-identifier pivots, permutation.

Run: .venv/bin/python -m pytest tests/test_v140.py -q
"""
import json
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT_LAB = 18097


# ------------------------------------------------------------ WS1 units

def test_canary_registry_formal_records():
    import canary
    reg = canary.CanaryRegistry()
    tok = reg.issue("cmdi /ping host", meta={
        "scan_id": "scan-A", "check": "c_blind_oob", "target": "/ping",
        "parameter": "host", "payload_class": "shell separator ';' + curl"})
    rec = reg.record_of(tok)
    assert rec["scan_id"] == "scan-A" and rec["check"] == "c_blind_oob"
    assert rec["parameter"] == "host" and "curl" in rec["payload_class"]
    assert rec["issued_at"] > 0
    reg.issue("other", meta={"scan_id": "scan-B"})
    assert len(reg.issued("scan-A")) == 1 and len(reg.issued()) == 2
    reg.record(canary.Hit(token=tok, ts=time.time(), ip="10.0.0.9",
                          method="GET", path="/" + tok, user_agent="curl/8"))
    st = reg.stats("scan-A")
    assert st == {"tokens_planted": 1, "tokens_hit": 1,
                  "callbacks_received": 1}, st
    assert reg.stats("scan-B")["callbacks_received"] == 0


def test_oob_sweep_attributes_to_owning_scan():
    import canary
    import vulnscan2
    reg = canary.CanaryRegistry()
    opts = {"canary": {"registry": reg, "base": "http://127.0.0.1:9",
                       "base_kind": "builtin"}}
    ctx_a = vulnscan2.Ctx("http://127.0.0.1:9/", dict(opts), [])
    ctx_b = vulnscan2.Ctx("http://127.0.0.1:9/", dict(opts), [])
    _u, eb = vulnscan2._oob_issue(ctx_b, reg, "http://127.0.0.1:9",
                                  "SSRF", "/fetch", "url", "url fetch")
    reg.record(canary.Hit(token=eb["token"], ts=time.time(), ip="1.2.3.4",
                          method="GET", path="/x", user_agent="ua"))
    fa, fb = [], []
    assert vulnscan2._oob_sweep(ctx_a, fa.append) == 0 and not fa
    assert vulnscan2._oob_sweep(ctx_b, fb.append) == 1
    assert fb[0]["confidence"] == "confirmed"
    assert ctx_b.canary_status()["callbacks_received"] == 1
    assert ctx_a.canary_status()["callbacks_received"] == 0


def test_canary_meta_when_not_configured():
    import vulnscan2
    res = vulnscan2.run_vulnscan("http://127.0.0.1:9", "passive-quick",
                                 log=[], opts={"timeout": 2})
    can = res["canary"]
    assert can["configured"] is False and can["base_kind"] == "none"
    assert can["tokens_planted"] == 0 and can["callbacks_received"] == 0
    assert "not configured" in can["note"]


# ------------------------------------------------------------ WS2 units

def _marks():
    import xssverify
    return xssverify.make_sandwich("c0ffee1234")


def test_xss_position_evidence_five_kinds():
    import xssverify as X
    m = _marks()
    base = "<html><body>hello</body></html>"
    cases = {
        "event_handler": f"<html><body><svg/onload={m['inner']}></body></html>",
        "url_scheme": f"<html><body><a href=\"javascript:{m['inner']}\">x</a></body></html>",
        "script_element": f"<html><body><script>{m['inner']}</script></body></html>",
        "marker_element_sink":
            f"<html><body><b class=\"{m['open']}\"><svg/onload={m['inner']}></b></body></html>",
    }
    for kind, body in cases.items():
        r = X.analyze(200, "text/html", body, base, m)
        assert r["verdict"] == "confirmed" and kind in r["kinds"], (kind, r)
    # K4: reflection into a PRE-EXISTING script block, string broken out
    bscript = '<html><body><script>var q="hello";</script></body></html>'
    r = X.analyze(200, "text/html",
                  '<html><body><script>var q="";' + m["inner"] + ';//";</script></body></html>',
                  bscript, m)
    assert r["verdict"] == "confirmed" and "script_context" in r["kinds"], r


def test_xss_inert_guards_never_confirm():
    import xssverify as X
    m = _marks()
    base = "<html><body>hello</body></html>"
    traps = [
        # entity-encoded reflection (output encoding worked)
        "<html><body>&lt;svg/onload=" + m["inner"] + "&gt;</body></html>",
        # comment
        "<html><body><!-- <svg/onload=" + m["inner"] + "> --></body></html>",
        # textarea content
        f"<html><body><textarea>{m['inner']}</textarea></body></html>",
        # hidden input value
        f"<html><body><input type='hidden' value='{m['inner']}'></body></html>",
        # http(s) URL attribute value
        f"<html><body><a href='https://example.com/?q={m['inner']}'>x</a></body></html>",
        # marker element present, sink stripped by a sanitizer
        f"<html><body><b class='{m['open']}'>plain</b></body></html>",
        # plain text reflection
        f"<html><body>you searched for {m['inner']}</body></html>",
    ]
    for body in traps:
        r = X.analyze(200, "text/html", body, base, m)
        assert r["verdict"] != "confirmed", (body[:60], r)
        assert r["verdict"] == "reflected" and r["inert"], (body[:60], r)
    # JSON body and 3xx are not HTML evidence at all
    r = X.analyze(200, "application/json", '{"x":"' + m["inner"] + '"}', base, m)
    assert r["verdict"] == "reflected" and not r["near_miss"]
    r = X.analyze(302, "text/html", f"<html>{m['inner']}</html>", base, m)
    assert r["verdict"] == "reflected" and not r["near_miss"]
    # marker inside a JS string literal (no breakout) is a trap
    bscript = '<html><body><script>var q="hello";</script></body></html>'
    r = X.analyze(200, "text/html",
                  '<html><body><script>var q="' + m["inner"] + '";</script></body></html>',
                  bscript, m)
    assert r["verdict"] == "reflected" and r["near_miss"], r


def test_stored_xss_baseline_diff():
    """A retrieval page whose BASELINE already contains the payload
    must not be credited; a genuine new store must be."""
    import vulnscan2

    class _Resp:
        def __init__(self, body, status=200):
            self.body, self.status = body, status

    class _Client:
        def __init__(self, seeded, store_works):
            self.seeded, self.store_works = seeded, store_works
            self.stored = []
            self.host, self.port = "fixture", 80

        def get(self, path, headers=None):
            if path == "/board":
                entries = "".join(f"<div>{e}</div>"
                                  for e in [self.seeded] + self.stored
                                  if e)
                return _Resp(f"<html><title>Board</title>{entries}</html>")
            return _Resp("", status=404)

        def post(self, action, data=None, headers=None):
            if self.store_works and data:
                from urllib.parse import parse_qs
                form = {k: v[0] for k, v in parse_qs(data).items()}
                self.stored.append(form.get("comment", ""))
            return _Resp("<html>signed</html>")

    class _Surf:
        forms = [{"action": "/board", "page": "/board", "method": "POST",
                  "inputs": ["comment"]}]
        pages = ["/board"]

    def _run(seeded, store_works):
        ctx = vulnscan2.Ctx.__new__(vulnscan2.Ctx)
        ctx.opts, ctx.log, ctx.marker = {}, [], "c0ffee1234"
        ctx._xss_marks = None
        ctx.client = _Client(seeded, store_works)
        ctx.surface = lambda full=True: _Surf()
        ctx.is_missing = lambda resp: False
        ctx.L = lambda msg: None
        finds = []
        vulnscan2.c_stored_xss(ctx, finds.append)
        return ctx, finds

    # genuine store: payload appears only AFTER planting -> confirmed
    _ctx, finds = _run("", True)
    assert any(f["title"].startswith("Stored XSS verified")
               and f["confidence"] == "confirmed" for f in finds), finds
    # trap: baseline already renders the exact payload and the store
    # adds no new copy -> NOT credited
    import xssverify
    marks = xssverify.make_sandwich("c0ffee1234")
    seeded = f"<svg/onload={marks['inner']}0>"
    _ctx, finds = _run(seeded, False)
    assert not [f for f in finds if "Stored XSS" in f["title"]], finds


# ------------------------------------------------------------ WS3 units

def test_waf_dataset_benign_content_names_no_vendor():
    """F5-incident regression (design WS3 test): vendor substrings in
    random tokens and vendor names in benign article text must NOT
    name a vendor."""
    import vulnscan2
    import wafscore
    genexus = ('<script>var GX={"gx_ajax_key":"38ff6460ffff59ffff06ff6b'
               'ffff3644f5f5f5aabbcc"};</script><footer>Powered by nginx'
               ' — blog membahas akamai, barracuda, dan f5.</footer>')
    assert vulnscan2._waf_match([("Server", "nginx")], genexus) is None
    article = ("Perbandingan WAF populer: cloudflare, akamai, imperva, "
               "sucuri, barracuda, and f5 big-ip are discussed as products. "
               "Token sesi: 38ff6460ffff59ffff06ff6bffff3644f5f5f5aabbcc. "
               "Checksum f5f5f5f5ffff.")
    assert vulnscan2._waf_match([("Server", "nginx")], article) is None
    scored = wafscore.score_waf([("Server", "nginx")], article)
    assert all(v["score"] < wafscore.DISPLAY_FLOOR
               for v in scored["vendors"]), scored


def test_waf_scored_merge_boost_and_evidence():
    import wafscore
    s = wafscore.score_waf([("CF-RAY", "8f00abcd-SIN")], "", status=403)
    v = wafscore.best_vendor(s)
    assert v["vendor"] == "Cloudflare" and v["score"] >= 0.95, s
    ev = wafscore.evidence_str(v)
    assert "score" in ev and "CF-RAY" in ev and "blocking status 403" in ev
    # max-merge: two weak-ish views never sum past the max signal
    s2 = wafscore.merge_scored(
        wafscore.score_waf([], "our blog mentions akamai for the image cdn"),
        wafscore.score_waf([("X-Akamai-Transformed", "9 - 0")], ""))
    v2 = wafscore.best_vendor(s2)
    assert v2["vendor"] == "Akamai" and v2["score"] == 0.90, s2


class _FakeResp:
    def __init__(self, status, body="", headers=None):
        self.status, self.body = status, body
        self.headers = headers or []

    def hdr(self, name):
        for k, v in self.headers:
            if k.lower() == name.lower():
                return v
        return ""


def _waf_ctx(probe_map, home=None):
    import vulnscan2

    class _Client:
        def get(self, path):
            if path == "/":
                return home or _FakeResp(200, "<html>app</html>",
                                         [("Server", "nginx")])
            for frag, resp in probe_map:
                if frag in path:
                    return resp
            return _FakeResp(404, "not found")
    ctx = vulnscan2.Ctx.__new__(vulnscan2.Ctx)
    ctx.client, ctx.marker, ctx.log = _Client(), "c0ffee1234", []
    ctx.L = lambda msg: ctx.log.append(msg)
    return ctx


def test_unknown_waf_provocation_and_exceptions():
    import vulnscan2
    # ONE attack class blocked with a generic page, the rest pass and
    # controls pass: behavior verdict does NOT reach 'confirmed'
    # (needs >=2), no vendor signal -> Unknown WAF via provocation.
    ctx = _waf_ctx([("%3Cscript%3E", _FakeResp(403, "blocked by security")),
                    ("OR%20%271%27", _FakeResp(404, "no")),
                    ("..%2f", _FakeResp(404, "no"))])
    finds = []
    vulnscan2.c_waf_detection(ctx, finds.append)
    assert any(t.startswith("Unknown WAF") for t in
               [f["title"] for f in finds]), finds
    # 429 + Retry-After only -> rate limiting, NOT a WAF claim
    ctx = _waf_ctx([("%3Cscript%3E", _FakeResp(429, "slow down",
                                               [("Retry-After", "5")])),
                    ("OR%20%271%27", _FakeResp(429, "slow down",
                                               [("Retry-After", "5")])),
                    ("..%2f", _FakeResp(429, "slow down",
                                        [("Retry-After", "5")]))])
    finds = []
    vulnscan2.c_waf_detection(ctx, finds.append)
    assert not [f for f in finds if "WAF" in f["title"]], finds
    # attacks and controls share the same status -> baseline, no claim
    ctx = _waf_ctx([("%3Cscript%3E", _FakeResp(403, "blocked")),
                    ("OR%20%271%27", _FakeResp(403, "blocked")),
                    ("..%2f", _FakeResp(403, "blocked")),
                    ("q=aaaa", _FakeResp(403, "blocked"))])
    # controls also 403 via catch-all fallback in _Client? no — control
    # paths don't match probe fragments and return 404 except 'q=aaaa'
    finds = []
    vulnscan2.c_waf_detection(ctx, finds.append)
    assert not [f for f in finds if f["title"].startswith("Unknown")], finds


# ------------------------------------------------------------ WS4 units

GOODHUB = [("GoodHub", "http://127.0.0.1:1/sim/{h}", "profile:{h}")]




def _selfcheck_fetch(url, **kw):
    if "lichess" in url:
        return 0, [], b""
    if "keybase.io" in url:  # catch-all: claims every handle incl. junk
        h = url.rsplit("/", 1)[-1]
        return 200, [], f"profile page of {h}".encode()
    if "api.github.com" in url:
        if url.endswith("/users/github"):
            return 200, [], b'{"login": "github"}'
        return 404, [], b"{}"
    if "medium.com" in url:  # claimed fixture handle does not resolve
        return 404, [], b"not found"
    return 404, [], b""






# ------------------------------------------- WS1+WS2 integration (lab)

_LAB = {}


def _lab_scan():
    if _LAB:
        return _LAB["res"]
    import canary
    import socket
    import vulnscan2
    _s = socket.socket()
    _s.bind(("127.0.0.1", 0))
    port = _s.getsockname()[1]
    _s.close()
    env = dict(os.environ, FIXTURE_MODE="lab14")
    proc = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _LAB["proc"] = proc
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            break
        except Exception:
            time.sleep(0.25)
    srv, reg = canary.serve(port=0, host="127.0.0.1")
    _LAB["srv"] = srv
    cport = srv.server_address[1]
    log = []
    res = vulnscan2.run_vulnscan(
        f"http://127.0.0.1:{port}", "active-deep", log=log, opts={
            "timeout": 5, "max_pages": 30, "canary_grace_s": 15,
            "canary": {"registry": reg,
                       "base": f"http://127.0.0.1:{cport}",
                       "base_kind": "builtin"}})
    _LAB["res"], _LAB["log"] = res, log
    return res


def test_lab_oob_grace_window_and_meta():
    res = _lab_scan()
    titles = [f["title"] for f in res["findings"]]
    # immediate SSRF (fixture /fetch) AND the slow queued fetch that
    # only the grace-window re-poll can catch (/blind/fetch, 9s delay)
    assert any(t.startswith("Blind SSRF confirmed") and "/fetch" in t
               for t in titles), [t for t in titles if "Blind" in t]
    assert any(t.startswith("Blind SSRF confirmed") and "/blind/fetch" in t
               for t in titles), [t for t in titles if "Blind" in t]
    # blind CMDi via the simulated executing /blind/ping
    assert any(t.startswith("Blind command injection confirmed")
               and "/blind/ping" in t for t in titles), \
        [t for t in titles if "Blind" in t]
    # blind XSS via the victim-simulated board
    assert any(t.startswith("Blind XSS confirmed") and "/blind/xss" in t
               for t in titles), [t for t in titles if "Blind" in t]
    can = res["canary"]
    assert can["configured"] is True and can["base_kind"] == "builtin"
    assert can["tokens_planted"] >= 6, can
    assert can["callbacks_received"] >= 3, can
    assert "grace window" in can["note"] and "arrived during" in can["note"], can


def test_lab_xss_position_evidence():
    res = _lab_scan()
    finds = res["findings"]
    titles = [f["title"] for f in finds]

    def conf_at(loc):
        return [f for f in finds if loc in f["title"]
                and "XSS" in f["title"] and f["confidence"] == "confirmed"]
    # K1/K2/K3/K5 on the raw text lab, K1 on attribute breakout, K4 on
    # the script-string lab — all confirmed via parsed-DOM position.
    assert conf_at("/xsslab/text"), titles
    assert conf_at("/xsslab/attr"), titles
    assert conf_at("/xsslab/script"), titles
    assert any("script_context" in f["evidence"]
               for f in conf_at("/xsslab/script")), conf_at("/xsslab/script")
    # encoded lab: output encoding works — no XSS finding of any tier
    assert not [f for f in finds if "/xsslab/encoded" in f["title"]
                and "XSS" in f["title"]], titles
    # hidden-input lab: marker trapped in a value — never confirmed
    assert not conf_at("/xsslab/hidden"), titles


def teardown_module():
    if _LAB.get("proc"):
        _LAB["proc"].terminate()
    if _LAB.get("srv"):
        _LAB["srv"].shutdown()
