"""Security test of the toolkit's own web app (v3.6): isolated test server
(temporary DB, ephemeral port) — security headers, body size cap,
authentication, and login throttle logic."""
import http.client
import json
import os
import sys
import threading
import time
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import store


def _boot(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("PTK_ADMIN_PW", "test-admin-pw-123")
    store.init_db()  # seed the admin from env
    import app2
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app2.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _req(port, method, path, body=None, headers=None, raw_headers=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, (bytes, str)) else json.dumps(body)
        h.setdefault("Content-Type", "application/json")
    if raw_headers:
        h.update(raw_headers)
    c.request(method, path, data, h)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out


def test_security_headers_dan_no_store(tmp_path, monkeypatch):
    srv, port = _boot(tmp_path, monkeypatch)
    try:
        st, hd, _ = _req(port, "GET", "/login")
        assert st == 200
        assert hd.get("X-Content-Type-Options") == "nosniff"
        assert hd.get("X-Frame-Options") == "DENY"
        assert "frame-ancestors 'none'" in hd.get("Content-Security-Policy", "")
        assert hd.get("Referrer-Policy") == "no-referrer"
        # Unauthenticated GET of the API is redirected to login (an intentional
        # browser-flow behavior); no-store must be present on JSON API responses.
        st, hd, _ = _req(port, "GET", "/api/scans")
        assert st in (302, 401)
        st, hd, _ = _req(port, "POST", "/api/login",
                         {"username": "admin", "password": "salah"})
        assert st == 401 and hd.get("Cache-Control") == "no-store"
    finally:
        srv.shutdown()


def test_body_cap_dan_bad_json(tmp_path, monkeypatch):
    srv, port = _boot(tmp_path, monkeypatch)
    try:
        # A declared 3 MB body on a plain JSON endpoint -> 413 before reading.
        st, _, body = _req(port, "POST", "/api/login", body=b"",
                           raw_headers={"Content-Length": str(3 * 1024 * 1024)})
        assert st == 413, (st, body[:100])
        # Broken JSON -> 400, not 500.
        st, _, _ = _req(port, "POST", "/api/login", body=b"{bukan json")
        assert st == 400
    finally:
        srv.shutdown()


def test_login_throttle_progressive_no_lockout(tmp_path, monkeypatch):
    srv, port = _boot(tmp_path, monkeypatch)
    import app2
    app2.LOGIN_FAILS.clear()  # per-IP throttle bucket is shared across tests
    try:
        for i in range(5):
            st, _, _ = _req(port, "POST", "/api/login",
                            {"username": "admin", "password": "salah"})
            assert st == 401, (i, st)
        # NO lockout (v1.9.1): the correct password is still
        # accepted after consecutive failures — only the response is
        # slowed down by the progressive delay.
        st, _, _ = _req(port, "POST", "/api/login",
                        {"username": "admin", "password": "test-admin-pw-123"})
        assert st == 200, f"valid login must not be locked out, got {st}"
    finally:
        srv.shutdown()


def test_login_delay_logic():
    import app2
    ip = "10.9.9.9"
    now = time.time()
    app2.LOGIN_FAILS[ip] = [now - 10] * 2
    assert app2.login_delay(ip, now=now) == 0.0
    app2.LOGIN_FAILS[ip] = [now - 10] * 3
    assert app2.login_delay(ip, now=now) == 1.0
    app2.LOGIN_FAILS[ip] = [now - 10] * 5
    assert app2.login_delay(ip, now=now) == 4.0
    app2.LOGIN_FAILS[ip] = [now - 10] * 20
    assert app2.login_delay(ip, now=now) == app2.LOGIN_DELAY_CAP
    app2.LOGIN_FAILS[ip] = [now - 400] * 6  # outside the 300s window
    assert app2.login_delay(ip, now=now) == 0.0
    app2.LOGIN_FAILS.pop(ip, None)
