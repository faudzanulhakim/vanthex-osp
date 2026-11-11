"""
tests/test_ghostcrawl.py — hermetic tests for ghostcrawl.py.

Everything runs against a local http.server (no external network):
  * robots.txt with Disallow entries (one wildcard),
  * sitemap.xml with same-host and foreign <loc> URLs,
  * a cache emulator: warm hits are served fast + X-Cache: HIT, cold
    (cache-busted) requests sleep and return X-Cache: MISS,
  * an HTML page embedding a JS file with route strings,
  * a /api/ prefix that returns 429 to exercise adaptive backoff.
"""
import http.server
import json
import threading
import time

import pytest

from offensive import ghostcrawl

# ------------------------------------------------------------ fake server

_HTML = """<html><body>
<script src="/app.js"></script>
<a href="/visible">v</a>
</body></html>"""

_APP_JS = """
const routes = ["/admin/panel", "/api/internal", "/reports/daily"];
"""

_ROBOTS = """
User-agent: *
Disallow: /secret/
Disallow: /wild*
"""

_SITEMAP = """<?xml version="1.0"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>http://127.0.0.1:0/en/hidden</loc></url>
  <url><loc>http://other.example.net/foreign/path</loc></url>
</urlset>"""

WARM_SLEEP = 0.01
COLD_SLEEP = 0.12


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "TestServ/1.0"

    def do_GET(self):
        path = self.path
        # rate-limited prefix: 429 on /api/limited
        if path.startswith("/api/limited"):
            self._send(429, "slow down", extra=[("Retry-After", "1")])
            return
        if path == "/robots.txt":
            self._send(200, _ROBOTS, ctype="text/plain")
            return
        if path == "/sitemap.xml":
            self._send(200, _SITEMAP, ctype="application/xml")
            return
        if path == "/app.js":
            self._send(200, _APP_JS, ctype="application/javascript")
            return
        if path == "/":
            self._send(200, _HTML,
                       extra=[("Set-Cookie", "sid=abc123; Path=/")])
            return
        # cache emulator: cache-busted (has __gc=) is always cold; the plain
        # path is warm (fast) and carries X-Cache: HIT
        cold = "__gc=" in path
        clean = path.split("?", 1)[0]
        if clean == "/en/hidden":
            if cold:
                time.sleep(COLD_SLEEP)
                self._send(200, "hidden content", extra=[("X-Cache", "MISS")])
            else:
                time.sleep(WARM_SLEEP)
                self._send(200, "hidden content", extra=[("X-Cache", "HIT"),
                                                         ("Age", "120")])
            return
        if clean == "/secret/probe":
            self._send(200, "secret area")
            return
        if clean == "/admin/panel":
            self._send(200, "admin panel")
            return
        self._send(404, "not found")

    def _send(self, code, body, ctype="text/html", extra=None):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # silence
        pass


class Resp:
    """Minimal netclient.Resp-shaped object for fetcher stubs."""

    def __init__(self, status, body="", elapsed=0.0, headers=None):
        self.status = status
        self.body = body
        self.elapsed = elapsed
        self.headers = headers or []
        self.error = ""

    def hdr(self, name, default=""):
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default


@pytest.fixture(scope="module")
def server():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{port}", port
    srv.shutdown()


def _http_fetcher(base):
    """Real fetcher over the local server (urllib, gzip-free, tiny)."""
    import urllib.request

    def fetch(path, headers=None, timeout=5):
        url = base.rstrip("/") + path
        req = urllib.request.Request(url, headers=dict(headers or {}))
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", "replace")
                status = r.status
                hdrs = [(k, v) for k, v in r.getheaders()]
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            status = e.code
            hdrs = [(k, v) for k, v in e.headers.items()]
        return Resp(status, body, elapsed=time.perf_counter() - t0,
                    headers=hdrs)
    return fetch


# ------------------------------------------------------------ jitter tests


def test_jitter_bounded_bell_curve():
    import random as _r
    j = ghostcrawl.HumanJitter(min_delay=0.2, max_delay=2.0, base=0.8,
                               seed=7, sleeper=lambda s: None)
    for _ in range(400):
        d = j.delay("/some/path", apply=False)
        assert 0.2 <= d <= 2.0
    # a clamped gaussian is not uniform: values cluster near the base
    samples = [j.delay("/p", apply=False) for _ in range(400)]
    mean = sum(samples) / len(samples)
    assert 0.5 < mean < 1.2


def test_adaptive_backoff_on_429():
    slept = []
    j = ghostcrawl.HumanJitter(seed=1, sleeper=slept.append)
    p = "/api/limited/item"
    assert j.penalty(p) == 1.0
    j.record(429, p)
    assert j.penalty(p) > 1.0
    assert j.hit_prefixes == ["/api/"]
    before = len(slept)
    j.delay(p)                      # applies the inflated delay
    j.throttle(p)
    assert len(slept) > before
    j.record(429, p)
    p2 = j.penalty(p)
    assert p2 > j.penalty("/other")  # remembered per prefix
    # success decays but never forgets the throttle entirely
    j.record(200, p)
    assert j.penalty(p) < p2
    assert j.penalty(p) >= 1.0
    assert j.hit_prefixes == ["/api/"]  # threshold remembered


# ------------------------------------------------------------ header pool


def test_header_rotation_and_cookie_passthrough():
    pool = ghostcrawl.HeaderPool(seed=3)
    uas = {pool.rotate()["User-Agent"] for _ in range(40)}
    assert len(uas) > 1
    resp = Resp(200, "", headers=[("Set-Cookie", "sid=abc123; Path=/"),
                                  ("Set-Cookie", "theme=dark")])
    assert pool.add_cookies(resp) == 2
    h = pool.rotate()
    assert "Cookie" in h and "sid=abc123" in h["Cookie"]


def test_header_fingerprint_differential():
    calls = []

    def fetch(path, headers=None):
        calls.append(headers)
        if headers and "Firefox" in headers.get("User-Agent", ""):
            return Resp(403, "blocked", headers=[])
        return Resp(200, "ok" * 50, headers=[])

    pool = ghostcrawl.HeaderPool(seed=5)
    fp = pool.fingerprint(fetch, "/x")
    assert fp is not None and fp["differs"]
    assert len(calls) == 2                      # differential on 2 requests
    assert any("status" in r for r in fp["reactions"])

    flat = lambda path, headers=None: Resp(200, "same", headers=[])
    fp2 = ghostcrawl.HeaderPool(seed=5).fingerprint(flat, "/x")
    assert fp2 is not None and not fp2["differs"]


# ------------------------------------------------------------ cache timing


def test_cache_timing_finds_hidden_path(server):
    base, _ = server
    fetch = _http_fetcher(base)
    hits = ghostcrawl.cache_timing_enumeration(
        ["/en/hidden", "/definitely/missing"],
        fetch,
        jitter=ghostcrawl.HumanJitter(seed=11, sleeper=lambda s: None),
        log=lambda m: None)
    found = {h["path"] for h in hits}
    assert "/en/hidden" in found
    assert "/definitely/missing" not in found
    h = next(x for x in hits if x["path"] == "/en/hidden")
    assert h["confirmed"] and "X-Cache" in h["cache_header"]
    assert h["warm_ms"] < h["cold_ms"]


# ------------------------------------------------------------ alt map


def test_alt_map_harvest(server):
    base, port = server
    fetch = _http_fetcher(base)
    out = ghostcrawl.alt_map_discovery(fetch, base=base)
    # robots.txt Disallow entries harvested (wildcard expanded)
    assert "/secret/" in out["robots"]
    assert any(p.startswith("/wild") for p in out["robots"])
    # sitemap: same-host kept, foreign dropped
    assert "/en/hidden" in out["sitemap"]
    assert not any("foreign" in p for p in out["sitemap"])
    # JS-embedded routes from /app.js
    assert "/admin/panel" in out["js_routes"]
    assert "/api/internal" in out["js_routes"]


# ------------------------------------------------------------ run_ghost


class FakeCtx:
    def __init__(self, fetcher, cancelled_flag=False):
        self._fetch = fetcher
        self._cancelled = cancelled_flag
        self.logs = []

    def L(self, m):
        self.logs.append(m)

    def cancelled(self):
        return self._cancelled


def _patched_ctx(server, cancelled_flag=False):
    base, _ = server
    fetch = _http_fetcher(base)
    ctx = FakeCtx(None, cancelled_flag)
    ctx.client = type("C", (), {})()
    ctx.client.base_path = "/"
    ctx.client.get = lambda path, headers=None: fetch(path, headers)
    ctx.target = base
    return ctx


def test_gate_noop_without_env(server, monkeypatch):
    monkeypatch.delenv("PTK_GHOST", raising=False)
    monkeypatch.delenv("VANTHEX_GHOST", raising=False)
    ctx = _patched_ctx(server)
    added = []
    ghostcrawl.run_ghost(ctx, added.append)
    assert added == []
    assert any("gate" in m for m in ctx.logs)


def test_run_ghost_finds_and_caps(server, monkeypatch):
    monkeypatch.setenv("PTK_GHOST", "1")
    ctx = _patched_ctx(server)
    added = []
    ghostcrawl.run_ghost(ctx, added.append)
    assert added, "expected findings under the gate"
    assert len(added) <= 8                      # cap enforced
    titles = [f["title"] for f in added]
    assert any("robots.txt" in t for t in titles)
    for f in added:
        assert f["origin"] == "ghostcrawl"
        assert f["verification"] in ("signature", "manual-required",
                                     "reflection-only")
        # English, human-readable
        assert f["description"].strip()[0].isupper()


def test_run_ghost_respects_cancellation(server, monkeypatch):
    monkeypatch.setenv("PTK_GHOST", "1")
    ctx = _patched_ctx(server)
    ctx._cancelled = True
    added = []
    ghostcrawl.run_ghost(ctx, added.append)
    assert added == []
