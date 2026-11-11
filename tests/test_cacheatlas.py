"""
tests/test_cacheatlas.py — hermetic tests for the web-cache deception &
poisoning atlas (cacheatlas.py).

Own HTTP fixture (module-level autostart, ThreadingHTTPServer) — a cache
EMULATOR in front of an origin:
  * cache is keyed per FULL raw path (query included); a response is stored
    only when it was served with a public Cache-Control;
  * /account        — cookie-carrying: authenticated dashboard body (cached);
                      session-less: public login body. The origin normalises
                      the deception tricks (.css / ;.js / %2e%2e.css) to the
                      same resource — classic cache-deception setup;
  * /candidate.css  — cookie bodies differ per session, Cache-Control:
                      private + no-store — cache evidence but no shared
                      cache-served body => deception candidate only;
  * /admin          — plain: public index; '/admin;.js': admin content
                      (path-normalization bug) => normalization differential;
  * /clean          — static, no anomalies => no findings.

Run: .venv/bin/python -m pytest tests/test_cacheatlas.py -q
"""
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# loopback must bypass any egress proxy
os.environ["no_proxy"] = "127.0.0.1,localhost"
for _k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
    os.environ.pop(_k, None)

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from offensive import cacheatlas as _ca            # noqa: E402

PORT = 18520
BASE = "http://127.0.0.1:%d" % PORT

AUTH_BODY = "ACCOUNT-DASHBOARD session=active user=vt1 settings=private"
UNAUTH_BODY = "PUBLIC-ACCOUNT-PAGE login-form"
ADMIN_BODY = "ADMIN-CONTENT secret-settings internal=1"
ADMIN_PLAIN_BODY = "PUBLIC-ADMIN-INDEX"
CAND_AUTH_BODY = "ACCOUNT-PRIVATE-DATA token=zt1"
CAND_PUB_BODY = "PUBLIC-PLACEHOLDER"

# request counter the budget test reads
REQ_LOG = []
_LOCK = threading.Lock()

_CACHE = {}   # raw full path -> (status, headers list, body)


def _account_body(cookie):
    return AUTH_BODY if cookie else UNAUTH_BODY


class _H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def log_message(self, *a):
        pass

    def do_GET(self):
        with _LOCK:
            REQ_LOG.append(self.path)
        if self.path in _CACHE:
            status, hdrs, body = _CACHE[self.path]
            hdrs = [(k, v) for k, v in hdrs if k != "X-Cache"]
            hdrs.append(("X-Cache", "hit"))
            self._send(status, body, hdrs)
            return
        path = self.path
        cookie = self.headers.get("Cookie") or ""
        hdrs = [("X-Cache", "miss")]
        if path.startswith("/account") or path.startswith("/account%2e%2e"):
            body = _account_body(cookie)
            hdrs.append(("Cache-Control", "public, max-age=60"))
            cacheable = True
        elif path.startswith("/candidate"):
            # auth body only with a cookie; NOT shared-cacheable at all
            body = CAND_AUTH_BODY if cookie else CAND_PUB_BODY
            hdrs.append(("Cache-Control", "private, no-store"))
            cacheable = False
        elif path.startswith("/admin"):
            if ";.js" in path:
                body = ADMIN_BODY       # normalization bug
            else:
                body = ADMIN_PLAIN_BODY
            hdrs.append(("Cache-Control", "public, max-age=60"))
            cacheable = True
        elif path.startswith("/clean"):
            body = "CLEAN-STATIC-CONTENT"
            hdrs.append(("Cache-Control", "public, max-age=60"))
            cacheable = True
        else:
            self._send(404, "not found", [])
            return
        if cacheable:
            _CACHE[path] = (200, list(hdrs), body)
        self._send(200, body, hdrs)

    def _send(self, code, body, hdrs):
        b = body.encode()
        self.send_response(code)
        for k, v in hdrs:
            self.send_header(k, v)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)


_srv = ThreadingHTTPServer(("127.0.0.1", PORT), _H)
threading.Thread(target=_srv.serve_forever, daemon=True).start()


def _fetcher(path, headers=None):
    """Direct fetcher over a fresh socket per request (no shared state)."""
    import socket
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    lines = [f"GET {path} HTTP/1.0", "Host: 127.0.0.1"]
    for k, v in (headers or {}).items():
        if v:
            lines.append(f"{k}: {v}")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    data = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        data += chunk
    s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines_ = head.split(b"\r\n")
    status = 0
    hdrs = []
    try:
        status = int(lines_[0].split()[1])
    except Exception:
        pass
    for ln in lines_[1:]:
        if b":" in ln:
            k, _, v = ln.partition(b":")
            hdrs.append((k.decode("latin-1").strip(),
                         v.decode("latin-1").strip()))
    return {"status": status, "headers": hdrs,
            "body": body.decode("utf-8", "replace")}


class _Ctx:
    def __init__(self, opts=None):
        self.client = type("C", (), {})()
        self.client.host = "127.0.0.1"
        self.client.port = PORT
        self.client.extra_headers = {}
        self.opts = opts or {}
        self.logs = []

    def cancelled(self):
        return False

    def L(self, msg):
        self.logs.append(msg)

    def surface(self, full=False):
        class S:
            param_urls = ["/clean"]
        return S()


def _reset():
    _CACHE.clear()
    REQ_LOG.clear()


def test_quirks_db_has_seven_cdns_with_required_fields():
    assert len(_ca.CDN_QUIRKS_DB) == 7
    for cdn in ("varnish", "akamai", "cloudfront", "fastly", "cloudflare",
                "nginx proxy_cache", "squid"):
        e = _ca.CDN_QUIRKS_DB[cdn]
        assert e["cached_header_names"], cdn
        assert e["path_normalization_bugs"], cdn
        assert e["cache_key_elements"], cdn
        assert e["purge_mechanisms"], cdn


def test_deception_confirmed_on_cache_emulator():
    _reset()
    rs = _ca.deception_probe(_fetcher, "/account")
    assert rs, "expected per-trick results"
    conf = [r for r in rs if r["confidence"] == "confirmed"]
    assert conf, rs
    r = conf[0]
    assert r["verification"] == "cache-served-authenticated-body"
    assert r["same_shape_as_authenticated"] is True
    assert r["differs_from_unauthenticated"] is True
    assert r["sessionless_status"] == 200
    # the confirming session-less replay must actually be a cache HIT
    assert "x-cache: hit" in r["cache_evidence"].lower()
    assert "differential" in r["verification_note"].lower()


def test_deception_candidate_when_cache_present_but_body_not_shared():
    _reset()
    rs = _ca.deception_probe(_fetcher, "/candidate.css")
    assert rs
    assert all(r["confidence"] in ("candidate", "none") for r in rs), rs
    cand = [r for r in rs if r["confidence"] == "candidate"]
    assert cand
    assert cand[0]["verification"] == "cache-evidence-only"
    assert "not" in cand[0]["verification_note"].lower()
    assert not any(r["confidence"] == "confirmed" for r in rs)


def test_normalization_probe_differential_probable_on_admin():
    _reset()
    n = _ca.normalization_probe(_fetcher, "/admin")
    assert n["plain_stable"] is True
    assert n["confidence"] == "probable"
    assert n["verification"] == "differential-reproduced-2x"
    hit = [r for r in n["results"] if r["variant"] == "semicolon-ext"]
    assert hit and hit[0]["reproduced"] is True


def test_clean_endpoint_no_findings():
    _reset()
    d = _ca.deception_probe(_fetcher, "/clean")
    assert not any(r["confidence"] in ("confirmed", "candidate")
                   for r in d) or all(
        r["confidence"] == "candidate" and "cache-evidence-only" ==
        r["verification"] for r in d)
    n = _ca.normalization_probe(_fetcher, "/clean")
    assert n["confidence"] == "none"
    kp = _ca.key_element_fingerprint(_fetcher, "/clean")
    assert set(kp["elements"]) == {"Accept-Encoding", "User-Agent",
                                   "X-Forwarded-Proto", "Cookie"}
    assert kp["requests"] == 8 and kp["cache_busted"] is True


def test_gate_noop_without_env():
    _reset()
    old = os.environ.pop("PTK_CACHEATLAS", None)
    try:
        ctx = _Ctx({"cacheatlas_endpoints": ["/clean"]})
        findings = []
        _ca.c_cache_atlas(ctx, findings.append)
        assert findings == []
        assert any("gated off" in m for m in ctx.logs)
    finally:
        if old is not None:
            os.environ["PTK_CACHEATLAS"] = old


def test_caps_five_endpoints_and_forty_requests():
    _reset()
    os.environ["PTK_CACHEATLAS"] = "1"
    try:
        eps = ["/clean", "/clean2", "/clean3", "/clean4", "/clean5",
               "/clean6"]
        ctx = _Ctx({"cacheatlas_endpoints": eps})
        findings = []
        _ca.c_cache_atlas(ctx, findings.append)
        # endpoint cap: only the first MAX_ATLAS_ENDPOINTS paths may appear
        probed = {p for p in REQ_LOG if p.split("?")[0].rstrip(";.js2e%")
                  .startswith("/clean")}
        distinct_paths = {p for p in REQ_LOG}
        assert len(REQ_LOG) <= _ca.ATLAS_REQUEST_BUDGET, len(REQ_LOG)
        # no request may target the 6th endpoint
        assert not any(p.startswith("/clean6") for p in distinct_paths)
        assert ctx.cancelled() is False
        assert any("done" in m or "budget" in m for m in ctx.logs)
    finally:
        os.environ.pop("PTK_CACHEATLAS", None)


def test_respects_cancellation():
    _reset()
    os.environ["PTK_CACHEATLAS"] = "1"
    try:
        ctx = _Ctx({"cacheatlas_endpoints": ["/account"]})
        ctx.cancelled = lambda: True
        findings = []
        _ca.c_cache_atlas(ctx, findings.append)
        assert findings == []
        assert REQ_LOG == []
    finally:
        os.environ.pop("PTK_CACHEATLAS", None)


def test_deception_and_normalization_via_gated_check_produce_findings():
    _reset()
    os.environ["PTK_CACHEATLAS"] = "1"
    try:
        ctx = _Ctx({"cacheatlas_endpoints": ["/account", "/admin"],
                    "cacheatlas_cookie": "session=real"})
        findings = []
        _ca.c_cache_atlas(ctx, findings.append)
        kinds = [f["title"] for f in findings]
        assert any("Web Cache Deception" in t for t in kinds), kinds
        assert any("Path Normalization" in t for t in kinds), kinds
        for f in findings:
            assert f["verification"], "verification label required"
            assert f["verification_note"]
            assert f["origin"] == "cacheatlas"
        conf = [f for f in findings if f["confidence"] == "confirmed"]
        assert conf and conf[0]["severity"] == "HIGH"
    finally:
        os.environ.pop("PTK_CACHEATLAS", None)
