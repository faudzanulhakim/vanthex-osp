"""Accuracy v2 regression tests (scan-accuracy upgrade).

Covers:
- preflight WAF/challenge classification (blocked -> INCONCLUSIVE INFO
  finding, verification manual-required, never confirmed);
- unreachable preflight evidence detail (per-attempt scheme/error/elapsed);
- scheme fallback (https-only primary falls back to a responding http
  target, effective scheme recorded in the result dict);
- DOM XSS reflection probe: differential path (marker reflected),
  static-analysis downgrade path (note appended), and the 3-finding cap;
- header precision: CSP frame-ancestors suppresses the x-frame-options
  finding, plain-HTTP suppresses HSTS, evidence quotes observed headers,
  verification labels (signature / version-fingerprint).

All hermetic: tiny in-process HTTP servers plus fixture-server endpoints
under /fp/. Run: .venv/bin/python -m pytest tests/test_accuracy_v2.py -q
"""
import http.server
import os
import socket
import sys
import threading
from types import SimpleNamespace

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import vulnscan2


# ----------------------------------------------------------------- helpers

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


def _resp(status=200, body="", headers=None, elapsed=0.01, error=""):
    hdrs = headers or []
    low = {str(k).lower(): str(v) for k, v in hdrs}

    def hdr(name):
        return low.get(str(name).lower(), "")

    return SimpleNamespace(status=status, body=body,
                           headers=hdrs, elapsed=elapsed,
                           error=error, ok=200 <= status < 400,
                           hdr=hdr, hdr_all=lambda n: [v for k, v in hdrs
                                                       if str(k).lower() == str(n).lower()])


class _WafHandler(http.server.BaseHTTPRequestHandler):
    """Everything answers 403 with a Cloudflare-style challenge body."""

    def do_GET(self):
        body = (b"<html><head><title>Just a moment...</title></head>"
                b"<body>Attention Required! Checking your browser "
                b"before accessing. cf-chl: 8f00abcd</body></html>")
        self.send_response(403)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _OkHandler(http.server.BaseHTTPRequestHandler):
    """Plain HTTP 200 for everything (scheme-fallback target)."""

    def do_GET(self):
        body = b"<html><title>ok</title><body>ok</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


# ------------------------------------------------- 1. WAF-block classification

def test_waf_block_reason_classifier():
    blocked = _waf = None
    r403 = _resp(403, "no thanks")
    blocked = vulnscan2._waf_block_reason(r403)
    assert blocked == "HTTP 403"
    rcf = _resp(200, "<html>Just a moment... cf-chl</html>")
    assert vulnscan2._waf_block_reason(rcf) == "body marker 'just a moment'"
    rakamai = _resp(503, "server busy")
    assert vulnscan2._waf_block_reason(rakamai) == "HTTP 503"
    rok = _resp(200, "<html>hello world</html>")
    assert vulnscan2._waf_block_reason(rok) is None
    assert _waf is None


def test_scan_aborts_with_waf_block_finding():
    srv, port = _serve(_WafHandler)
    try:
        res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{port}",
                                     "active-standard", log=[])
    finally:
        srv.shutdown()
    blocked = [f for f in res["findings"]
               if f["title"].startswith("Target blocked the scanner")]
    assert blocked, "WAF-block finding missing"
    f = blocked[0]
    assert "INCONCLUSIVE" in f["title"]
    assert f["severity"] == "INFO"
    assert f["verification"] == "manual-required"
    assert f["confidence"] != "confirmed"
    assert f.get("verification_note")
    assert "403" in f["evidence"]
    assert any("blocked the scanner" in w for w in res["warnings"])


# ------------------------------------------- 2. unreachable evidence detail

def test_unreachable_evidence_lists_attempts():
    port = _free_port()  # nothing listens there -> instant refusal
    res = vulnscan2.run_vulnscan(f"http://127.0.0.1:{port}",
                                 "active-standard", log=[])
    unreach = [f for f in res["findings"]
               if f["title"] == "Target unreachable — scan aborted early"]
    assert unreach, "unreachable finding missing"
    f = unreach[0]
    assert f["severity"] == "INFO"
    assert f["verification"] == "manual-required"
    assert f["confidence"] != "confirmed"
    # evidence must list per-attempt scheme / error / elapsed
    ev = f["evidence"]
    assert "https" in ev and "http" in ev, ev
    assert "after" in ev and "s" in ev, ev
    assert any("unreachable" in w for w in res["warnings"])
    assert res["effective_scheme"] in ("http", "https")


# ------------------------------------------------------- 3. scheme fallback

def test_scheme_fallback_to_responding_scheme():
    srv, port = _serve(_OkHandler)
    try:
        # explicit https against a plain-HTTP server: preflight must fall
        # back to http and continue against it.
        res = vulnscan2.run_vulnscan(f"https://127.0.0.1:{port}",
                                     "active-standard", log=[])
        assert res["effective_scheme"] == "http"
        assert res["effective_target"].startswith("http://")
        blocked = [f for f in res["findings"]
                   if f["title"].startswith(("Target blocked", "Target unreachable"))]
        assert not blocked, blocked
    finally:
        srv.shutdown()


# --------------------------------------------- 4. DOM XSS reflection probe

DOM_JS = ("<script>var p=new URLSearchParams(location.search);"
          "document.getElementById('o').innerHTML=p.get('q');</script>")


class _FakeDomClient:
    """Serves /fp/domxss (reflects q) and /fp/domxss-static (does not)."""

    scheme = "http"

    def get(self, path, params=None, **kw):
        base = path.split("?")[0]
        if base in ("/fp/domxss", "/fp/domxss-static"):
            val = ""
            if params and base == "/fp/domxss" and "=" in params:
                val = params.split("=", 1)[1]
            body = (f"<html><body><p id='reflected'>{val}</p>"
                    f"<div id='o'></div>{DOM_JS}</body></html>")
            return _resp(200, body)
        return _resp(404, "nope")


def _dom_ctx(pages, param_urls=None):
    surf = SimpleNamespace(
        homepage=_resp(200, "<html><body>home</body></html>"),
        pages=list(pages), param_urls=list(param_urls or []),
        js_endpoints=[], forms=[])
    return SimpleNamespace(client=_FakeDomClient(),
                           surface=lambda full=True: surf,
                           opts={}, L=lambda m: None)


def _run_dom(ctx):
    findings = []
    vulnscan2.c_dom_xss(ctx, findings.append)
    return findings


def test_dom_xss_differential_path():
    ctx = _dom_ctx(["/fp/domxss"], ["/fp/domxss?q=1"])
    fs = _run_dom(ctx)
    assert len(fs) == 1
    f = fs[0]
    assert f["verification"] == "differential"
    assert f["confidence"] == "probable"
    assert f["confidence"] != "confirmed"
    assert "PTKDOM" in f["evidence"] and "reflected" in f["evidence"]


def test_dom_xss_static_downgrade_path():
    ctx = _dom_ctx(["/fp/domxss-static"], ["/fp/domxss-static?q=1"])
    fs = _run_dom(ctx)
    assert len(fs) == 1
    f = fs[0]
    assert f["verification"] == "static-analysis"
    assert f["confidence"] == "probable"
    assert f.get("verification_note") == (
        'Static source-to-sink pattern only — value reflection unconfirmed '
        'at runtime. Manual verification required.')


def test_dom_xss_cap_three():
    pages = ["/fp/domxss"] * 8  # repeated inline hits (JS files absent)
    ctx = _dom_ctx(pages, ["/fp/domxss?q=1"])
    fs = _run_dom(ctx)
    assert len(fs) <= vulnscan2.DOM_XSS_CAP == 3


def test_dom_probe_ignores_url_echo():
    marker, reflected = vulnscan2._dom_reflection_probe(
        _dom_ctx(["/fp/url-echo"], ["/fp/url-echo?q=1"]), "/fp/url-echo")
    assert marker.startswith("PTKDOM") and len(marker) == 14


# ----------------------------------------------- 5. header findings precision

def _hdr_ctx(headers, scheme="http"):
    r = _resp(200, "<html>ok</html>", headers=headers)
    return SimpleNamespace(client=SimpleNamespace(scheme=scheme),
                           surface=lambda full=False: SimpleNamespace(homepage=r),
                           opts={}, L=lambda m: None)


def _run_headers(ctx):
    findings = []
    vulnscan2.c_security_headers(ctx, findings.append)
    return findings


def test_frame_ancestors_suppresses_xfo():
    headers = [("Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'self'"),
               ("Referrer-Policy", "strict-origin-when-cross-origin")]
    fs = _run_headers(_hdr_ctx(headers, scheme="https"))
    titles = [f["title"] for f in fs]
    assert not any("x-frame-options" in t for t in titles), titles
    assert any("x-content-type-options" in t for t in titles)
    # strict HSTS present + good max-age -> no weak-HSTS finding either
    assert not any("Weak HSTS" in t for t in titles)


def test_plain_http_suppresses_hsts():
    fs = _run_headers(_hdr_ctx([]))
    assert not any("strict-transport-security" in f["title"] for f in fs)
    assert any("x-frame-options" in f["title"] for f in fs)


def test_header_evidence_quotes_observed_headers():
    headers = [("Server", "fixture/1.0"), ("Content-Type", "text/html")]
    fs = _run_headers(_hdr_ctx(headers, scheme="https"))
    xfo = [f for f in fs if "x-frame-options" in f["title"]]
    assert xfo
    ev = xfo[0]["evidence"]
    assert "'x-frame-options' absent" in ev
    assert "Server: fixture/1.0" in ev
    assert xfo[0]["verification"] == "signature"


def test_x_powered_by_verification_label():
    r = _resp(200, "<html>ok</html>",
              headers=[("X-Powered-By", "PHP/7.4.3")])
    ctx = SimpleNamespace(client=SimpleNamespace(scheme="http"),
                          surface=lambda full=False: SimpleNamespace(homepage=r),
                          opts={}, L=lambda m: None)
    findings = []
    vulnscan2.c_version_disclosure(ctx, findings.append)
    pb = [f for f in findings if f["title"].startswith("X-Powered-By")]
    assert pb and pb[0]["verification"] == "version-fingerprint"
