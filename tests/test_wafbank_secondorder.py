#!/usr/bin/env python3
"""Hermetic tests for the VANTHEX v1.2.3 engine upgrades:
(A) wafbank — WAF-aware payload bank v2 (+ exploitkit/c_web_injection retry)
(B) secondorder — second-order injection detector (+ vulnscan2 wiring)

AUTHORIZED TESTING ONLY — all HTTP traffic targets a local fixture server.
"""
import html
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
from urllib.parse import parse_qs, quote, unquote, urlparse

import pytest

import wafbank
import secondorder
import exploitkit
import vulnscan2

AUTHORIZED_HEADER = "AUTHORIZED TESTING ONLY"

# ============================================================ fixture server

STORE = []          # second-order store: values POSTed to /so/store
SQLI_LAST = []      # audit of /sqli values received


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # silence
        pass

    def _send(self, code, body, ctype="text/html"):
        b = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        p = urlparse(self.path).path
        if p == "/":
            self._send(200, "<html><body><h1>Fixture</h1>"
                            "<a href='/so/render'>Feed</a>"
                            "<a href='/so/render-escaped'>Escaped</a></body></html>")
        elif p == "/so/render":
            self._send(200, "<html><body><div id='feed'>"
                            + "".join(STORE) + "</div></body></html>")
        elif p == "/so/render-escaped":
            self._send(200, "<html><body><div id='feed'>"
                            + html.escape("".join(STORE)) + "</div></body></html>")
        elif p == "/sqli":
            v = unquote(parse_qs(urlparse(self.path).query).get("q", [""])[0])
            SQLI_LAST.append(v)
            if "/*" in v:
                self._send(200, "you have an error in your sql syntax near x")
            elif "'" in v.lower() or "or" in v.lower():
                self._send(403, "Request blocked by Web Application Firewall")
            else:
                self._send(200, "OK page")
        else:
            self._send(404, "not found")

    def do_POST(self):
        p = urlparse(self.path).path
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode()
        if p == "/so/store":
            STORE.append(parse_qs(body).get("msg", [""])[0])
            self._send(200, "stored")
        else:
            self._send(404, "not found")


@pytest.fixture(scope="module")
def server():
    STORE.clear()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


class Resp(SimpleNamespace):
    def hdr(self, name, default=None):
        return default


class FakeClient:
    """Minimal HTTP client over urllib for the fixture server."""
    def __init__(self, base):
        import urllib.request
        self._ur = urllib.request
        self.base = base
        self.gets = []

    def get(self, url, params=None, headers=None):
        full = self.base + url
        if params:
            full += ("&" if "?" in full else "?") + params
        self.gets.append(full)
        try:
            with self._ur.urlopen(full) as r:
                return Resp(status=r.status, body=r.read().decode(),
                            headers=dict(r.headers), elapsed=None)
        except self._ur.HTTPError as e:
            return Resp(status=e.code, body=e.read().decode(),
                        headers=dict(e.headers or {}), elapsed=None)

    def post(self, url, data=None, headers=None):
        req = self._ur.Request(self.base + url,
                               data=(data or "").encode(), method="POST")
        try:
            with self._ur.urlopen(req) as r:
                return Resp(status=r.status, body=r.read().decode(),
                            headers=dict(r.headers), elapsed=None)
        except self._ur.HTTPError as e:
            return Resp(status=e.code, body=e.read().decode(),
                        headers=dict(e.headers or {}), elapsed=None)


class FakeCtx:
    def __init__(self, base, waf_vendor="modsecurity"):
        self.client = FakeClient(base)
        self.marker = "mk123"
        self._waf_vendor = waf_vendor
        self.logs = []
        self._cancelled = False

    def L(self, m):
        self.logs.append(m)

    def cancelled(self):
        return self._cancelled

    def is_missing(self, r):
        return r.status in (404, 410)

    def soft404(self):
        return Resp(status=404, body="not found", headers={}, elapsed=None)

    def xss_marks(self):
        import xssverify
        return xssverify.make_sandwich(self.marker)

    def param_targets(self, limit=40):
        return [("/sqli", "q", "GET", None)]

    def req_param(self, base, pname, value, method="GET", orig_qs=None):
        return self.client.get(base, params=f"{pname}={quote(value, safe='')}")


# ============================================================ (A) wafbank

def test_transforms_deterministic():
    for name, fn in wafbank.TRANSFORMS.items():
        p = "1 OR 1=1 SELECT 'x'"
        assert fn(p) == fn(p), name
    # a representative transform actually changes form
    assert "/*!*/" in wafbank.TRANSFORMS["sql-comment"]("1 OR 1=1")
    assert "%09" in wafbank.TRANSFORMS["whitespace-tab"]("a b")
    assert "%0a" in wafbank.TRANSFORMS["whitespace-newline"]("a b")
    assert "%2527" in wafbank.TRANSFORMS["double-urlencode"]("1'")
    assert wafbank.TRANSFORMS["json-wrap"]("x") == '{"value": "x"}'


def test_payloads_for_cap_and_dedupe_and_order():
    bases = ["1 OR 1=1", "' UNION SELECT NULL"]
    out = wafbank.payloads_for("cloudflare", bases, max_per=6)
    assert all(isinstance(t, str) and isinstance(p, str) for t, p in out)
    payloads = [p for _, p in out]
    assert len(payloads) == len(set(payloads)), "must be deduped"
    assert all(p != b for _, p in out for b in bases), "no identity variants"
    assert out == wafbank.payloads_for("cloudflare", bases, max_per=6)
    # per-base cap
    out2 = wafbank.payloads_for("cloudflare", bases, max_per=2)
    assert len(out2) <= 4
    # bank covers the required fingerprints
    for fp in ("cloudflare", "aws-waf", "modsecurity", "imperva", "generic"):
        assert fp in wafbank.BANK and wafbank.BANK[fp]
        res = wafbank.payloads_for(fp, ["1 OR 1=1"], max_per=6)
        assert res, fp


def test_payloads_for_log_line():
    logs = []
    wafbank.payloads_for("Cloudflare", ["1 OR 1=1"], max_per=6, log=logs.append)
    assert any(m.startswith("[wafbank] ") and "bypass payloads for cloudflare"
               in m for m in logs)


def test_normalize_vendor():
    assert wafbank.normalize_vendor("Cloudflare") == "cloudflare"
    assert wafbank.normalize_vendor("AWS WAF") == "aws-waf"
    assert wafbank.normalize_vendor("ModSecurity") == "modsecurity"
    assert wafbank.normalize_vendor("Imperva/Incapsula") == "imperva"
    assert wafbank.normalize_vendor("Totally Unknown") == "generic"


def test_is_blocked():
    assert wafbank.is_blocked(403, "")
    assert wafbank.is_blocked(406, "")
    assert not wafbank.is_blocked(200, "normal page")
    assert wafbank.is_blocked(200, "Request blocked by security policy")


def test_bypass_retry_blocked_first_attempt(server):
    ctx = FakeCtx(server, waf_vendor="modsecurity")
    budget = 12
    seen = []

    def send(v):
        seen.append(v)
        return ctx.req_param("/sqli", "q", v)

    name, r, remaining = wafbank.bypass_retry(
        ctx, send, "1 OR 1=1", budget,
        err_check=lambda b: "error in your sql syntax" in (b or ""),
        log=ctx.L)
    assert name is not None and r is not None
    assert "/*" in r.body or name == "sql-comment"
    assert remaining < 12
    assert any("[wafbank]" in m for m in ctx.logs)
    assert len(seen) <= 12


def test_bypass_retry_no_waf_or_no_budget(server):
    ctx = FakeCtx(server, waf_vendor=None)
    name, r, rem = wafbank.bypass_retry(
        ctx, lambda v: ctx.req_param("/sqli", "q", v), "1 OR 1=1", 12)
    assert name is None and r is None and rem == 12
    ctx2 = FakeCtx(server)
    name, r, rem = wafbank.bypass_retry(
        ctx2, lambda v: ctx2.req_param("/sqli", "q", v), "1 OR 1=1", 0)
    assert name is None and rem == 0


def test_exploitkit_sqli_confirm_waf_retry(server):
    """Blocked first attempt -> wafbank retry -> finding with transform name."""
    STORE.clear()
    SQLI_LAST.clear()
    ctx = FakeCtx(server, waf_vendor="modsecurity")
    findings = []
    exploitkit.c_sqli_confirm(ctx, findings.append)
    hits = [f for f in findings if "error-based" in f["title"]]
    assert hits, "wafbank retry should recover the error-based SQLi finding"
    assert any("wafbank bypass transform" in f["evidence"] for f in hits)
    # the canonical forms really were blocked by the fixture
    assert any(v == "1 OR 1=1" for v in SQLI_LAST)


def test_exploitkit_sqli_confirm_no_waf_no_false_hit(server):
    """Without a WAF fingerprint there is no retry; blocked payloads stay
    blocked and no error-based finding is invented."""
    STORE.clear()
    SQLI_LAST.clear()
    ctx = FakeCtx(server, waf_vendor=None)
    findings = []
    exploitkit.c_sqli_confirm(ctx, findings.append)
    assert not [f for f in findings if "error-based" in f["title"]]


# ============================================================ (B) secondorder

def test_second_order_detects_unescaped_sink(server):
    STORE.clear()
    ctx = FakeCtx(server)
    findings = secondorder.second_order_probe(
        ctx, "/so/store", "msg", ["/so/render"], log=ctx.L)
    assert len(findings) == 1
    f = findings[0]
    assert f["title"] == "Second-Order Injection Sink"
    assert f["severity"] == "HIGH" and f["cvss"] == 7.1
    assert f["confidence"] == "confirmed"
    assert "/so/store" in f["evidence"] and "/so/render" in f["evidence"]
    assert f["remediation"] and f["remediation"][0].isupper()


def test_second_order_escaped_is_negative(server):
    STORE.clear()
    ctx = FakeCtx(server)
    findings = secondorder.second_order_probe(
        ctx, "/so/store", "msg", ["/so/render-escaped"], log=ctx.L)
    assert findings == []


def test_second_order_echo_bound(server):
    STORE.clear()
    ctx = FakeCtx(server)
    echo = ["/so/render-escaped"] * 8   # 8 candidates, bounded to 5
    secondorder.second_order_probe(ctx, "/so/store", "msg", echo)
    assert len(ctx.client.gets) <= 5, "echo GETs must be capped at 5"


def test_second_order_cancelled(server):
    ctx = FakeCtx(server)
    ctx._cancelled = True
    assert secondorder.second_order_probe(
        ctx, "/so/store", "msg", ["/so/render"]) == []


def test_vulnscan2_second_order_check(server):
    """c_stored_xss wiring: the second-order echo re-check runs as part of
    the stored-XSS check and credits the unescaped sink finding."""
    STORE.clear()
    ctx = FakeCtx(server)
    surf = SimpleNamespace(
        forms=[{"method": "POST", "action": "/so/store", "page": "/so/store",
                "inputs": ["msg"]}],
        pages=["/so/render"], param_urls=[], js_endpoints=[])
    ctx.surface = lambda full=True: surf
    findings = []
    vulnscan2.c_stored_xss(ctx, findings.append)
    assert any(f["title"] == "Second-Order Injection Sink" for f in findings)


def test_vulnscan2_c_waf_detection_stores_fingerprint(server):
    ctx = FakeCtx(server, waf_vendor=None)
    # the fixture is NOT a WAF: behavior verdict unconfirmed, no vendor —
    # fingerprint stays None and no retry budget is ever spent later.
    findings = []
    vulnscan2.c_waf_detection(ctx, findings.append)
    assert ctx._waf_vendor is None


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
