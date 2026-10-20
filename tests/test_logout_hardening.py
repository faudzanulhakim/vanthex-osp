"""v1.1.1: tombol logout yang benar-benar mengakhiri sesi + hardening
password admin awal. Server uji terisolasi (pola test_security.py)."""
import http.client
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import store


def _req(port, method, path, body=None, cookie=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    h = {}
    data = None
    if body is not None:
        data = json.dumps(body)
        h["Content-Type"] = "application/json"
    if cookie:
        h["Cookie"] = cookie
    c.request(method, path, data, h)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out


def _boot(tmp_path, monkeypatch, with_pw=True):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setattr(store, "GENERATED_ADMIN_PW", None)
    if with_pw:
        monkeypatch.setenv("PTK_ADMIN_PW", "test-admin-pw-123")
    else:
        monkeypatch.delenv("PTK_ADMIN_PW", raising=False)
    store.init_db()
    import app2
    srv = app2.ThreadingHTTPServer(("127.0.0.1", 0), app2.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def test_seed_without_env_generates_random_password(tmp_path, monkeypatch):
    _boot(tmp_path, monkeypatch, with_pw=False)
    gen = store.GENERATED_ADMIN_PW
    assert gen and gen != "changeme123" and len(gen) >= 16
    assert store.verify_user("admin", gen)
    assert not store.verify_user("admin", "changeme123")


def test_seed_with_env_keeps_env_password(tmp_path, monkeypatch):
    _boot(tmp_path, monkeypatch, with_pw=True)
    assert store.GENERATED_ADMIN_PW is None
    assert store.verify_user("admin", "test-admin-pw-123")


def test_actions_logout_kills_browser_session(tmp_path, monkeypatch):
    import actions
    monkeypatch.setattr(actions, "_session_cookie", "")
    monkeypatch.setattr(actions, "_session_exp", 0.0)
    _, port = _boot(tmp_path, monkeypatch, with_pw=True)

    status, headers, _ = _req(port, "POST", "/api/login",
                              {"username": "admin",
                               "password": "test-admin-pw-123"})
    assert status == 200
    cookie = headers["Set-Cookie"].split(";")[0]
    assert cookie.startswith("ptk_session=")

    status, _, body = _req(port, "POST", "/actions",
                           {"action": "getMe", "args": {}}, cookie)
    assert status == 200
    assert json.loads(body)["data"]["user"] == "admin"

    status, headers, body = _req(port, "POST", "/actions",
                                 {"action": "logout", "args": {}}, cookie)
    assert status == 200
    assert json.loads(body)["data"]["loggedOut"] is True
    assert "Max-Age=0" in headers.get("Set-Cookie", "")

    # Sesi browser lama harus sudah mati: GET tanpa sesi sah di-redirect
    # app2 ke halaman login (302), bukan data pengguna.
    status, headers, _ = _req(port, "GET", "/api/me", cookie=cookie)
    assert status == 302 and "/login" in headers.get("Location", "")
    # Dan sesi internal actions ikut dibersihkan.
    assert actions._session_cookie == ""
