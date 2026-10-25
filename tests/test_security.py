"""Test keamanan aplikasi web toolkit sendiri (v3.6): server uji terisolasi
(DB temporer, port ephemeral) — header keamanan, batas ukuran body,
autentikasi, dan logika throttle login."""
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
    store.init_db()  # seed admin dari env
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
        # GET API tanpa sesi diarahkan ke login (perilaku browser-flow yang
        # disengaja); no-store wajib ada pada respons JSON API.
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
        # Deklarasi body 3 MB ke endpoint JSON biasa -> 413 sebelum dibaca.
        st, _, body = _req(port, "POST", "/api/login", body=b"",
                           raw_headers={"Content-Length": str(3 * 1024 * 1024)})
        assert st == 413, (st, body[:100])
        # JSON rusak -> 400, bukan 500.
        st, _, _ = _req(port, "POST", "/api/login", body=b"{bukan json")
        assert st == 400
    finally:
        srv.shutdown()


def test_login_throttle_progressive_no_lockout(tmp_path, monkeypatch):
    srv, port = _boot(tmp_path, monkeypatch)
    import app2
    app2.LOGIN_FAILS.clear()  # bucket throttle per-IP dipakai bersama antar test
    try:
        for i in range(5):
            st, _, _ = _req(port, "POST", "/api/login",
                            {"username": "admin", "password": "salah"})
            assert st == 401, (i, st)
        # TIDAK ada lockout (v1.9.1): password yang benar tetap
        # diterima setelah kegagalan beruntun — responsnya saja yang
        # diperlambat oleh penundaan progresif.
        st, _, _ = _req(port, "POST", "/api/login",
                        {"username": "admin", "password": "test-admin-pw-123"})
        assert st == 200, f"login sah tidak boleh terkunci, dapat {st}"
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
    app2.LOGIN_FAILS[ip] = [now - 400] * 6  # di luar jendela 300 dtk
    assert app2.login_delay(ip, now=now) == 0.0
    app2.LOGIN_FAILS.pop(ip, None)
