"""Audit regression test v3.18.1: admin gate for suppressions &
NVD sync, and job ownership (other users cannot read/cancel
a job that is not theirs). Isolated test server, same pattern as test_security.
"""
import http.client
import json
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import store


def _boot(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("PTK_ADMIN_PW", "test-admin-pw-123")
    store.init_db()
    import app2
    app2.LOGIN_FAILS.clear()  # global per-IP throttle bucket: reset across
    # test files so subset ordering does not lock out logins (429)
    from http.server import ThreadingHTTPServer
    srv = ThreadingHTTPServer(("127.0.0.1", 0), app2.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _req(port, method, path, body=None, cookie=None):
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
    h = {"Content-Type": "application/json"}
    if cookie:
        h["Cookie"] = cookie
    data = json.dumps(body) if body is not None else None
    c.request(method, path, data, h)
    r = c.getresponse()
    out = (r.status, dict(r.getheaders()), r.read())
    c.close()
    return out


def _login(port, user, pw):
    st, hd, _ = _req(port, "POST", "/api/login",
                     {"username": user, "password": pw})
    assert st == 200, (user, st)
    return hd["Set-Cookie"].split(";")[0]


def _setup_users(port, admin_cookie):
    st, _, _ = _req(port, "POST", "/api/users",
                    {"username": "analyst1", "password": "analyst-pw-123",
                     "role": "analyst"}, cookie=admin_cookie)
    assert st == 200, st
    return _login(port, "analyst1", "analyst-pw-123")


def test_suppressions_dan_nvd_hanya_admin(tmp_path, monkeypatch):
    srv, port = _boot(tmp_path, monkeypatch)
    try:
        admin = _login(port, "admin", "test-admin-pw-123")
        analyst = _setup_users(port, admin)
        # pre-existing gate (control): secrets are indeed admin-only
        st, _, _ = _req(port, "GET", "/api/secrets", cookie=analyst)
        assert st == 403
        # NEW v3.18.1 gate: suppressions POST/delete + nvd sync
        st, _, _ = _req(port, "POST", "/api/suppressions",
                        {"host": "x.test", "title": "Header"}, cookie=analyst)
        assert st == 403, st
        st, _, body = _req(port, "POST", "/api/suppressions",
                           {"host": "x.test", "title": "Header"}, cookie=admin)
        assert st == 200, (st, body)
        sid = json.loads(body)["id"]
        st, _, _ = _req(port, "POST", "/api/suppressions/delete",
                        {"id": sid}, cookie=analyst)
        assert st == 403
        st, _, _ = _req(port, "POST", "/api/suppressions/delete",
                        {"id": sid}, cookie=admin)
        assert st == 200
        st, _, _ = _req(port, "POST", "/api/nvd/sync", {}, cookie=analyst)
        assert st == 403
    finally:
        srv.shutdown()


def test_job_hanya_pemilik_atau_admin(tmp_path, monkeypatch):
    srv, port = _boot(tmp_path, monkeypatch)
    try:
        admin = _login(port, "admin", "test-admin-pw-123")
        analyst = _setup_users(port, admin)
        st, _, body = _req(port, "POST", "/api/scan",
                           {"target": "http://127.0.0.1:9", "type": "headers",
                            "authorized": True}, cookie=admin)
        assert st == 200, (st, body)
        jid = json.loads(body)["job_id"]
        # the analyst must not read / cancel the admin's job
        st, _, _ = _req(port, "GET", f"/api/job/{jid}", cookie=analyst)
        assert st == 403, st
        st, _, _ = _req(port, "POST", f"/api/job/{jid}/cancel", {},
                        cookie=analyst)
        assert st == 403, st
        # the owner (admin) still can
        st, _, _ = _req(port, "GET", f"/api/job/{jid}", cookie=admin)
        assert st == 200
        # with no session at all: rejected by the session handler (401/302)
        st, _, _ = _req(port, "GET", f"/api/job/{jid}")
        assert st in (401, 302)
    finally:
        srv.shutdown()


def test_findings_and_nvd_status_no_crash(tmp_path, monkeypatch):
    """Regression v3.18.1: a local parse_qs import in the nvd/status branch once
    made /api/findings crash (UnboundLocalError) — both routes must
    answer 200."""
    srv, port = _boot(tmp_path, monkeypatch)
    try:
        admin = _login(port, "admin", "test-admin-pw-123")
        st, _, _ = _req(port, "GET", "/api/findings", cookie=admin)
        assert st == 200, st
        st, _, _ = _req(port, "GET", "/api/nvd/status?q=wordpress",
                        cookie=admin)
        assert st == 200, st
    finally:
        srv.shutdown()


def test_origin_tersimpan_dan_masuk_laporan(tmp_path, monkeypatch):
    """Regression v3.18.1: the origin column in the findings table — previously
    the origin from F() was lost during save_scan so reports & exports for
    passive/hybrid scans were mislabeled. It must now round-trip intact."""
    srv, port = _boot(tmp_path, monkeypatch)
    try:
        result = {"type": "passive", "target": "example.test",
                  "profile": "passive-full", "overall_risk": "LOW",
                  "summary": {"INFO": 1, "LOW": 1},
                  "findings": [
                      {"severity": "INFO", "title": "Passive thing",
                       "description": "d", "evidence": "e", "confidence": "probable",
                       "location": "example.test", "param": "", "origin": "passive"},
                      {"severity": "LOW", "title": "Active thing",
                       "description": "d", "evidence": "e", "confidence": "probable",
                       "location": "example.test", "param": "", "origin": "active"}]}
        sid = store.save_scan("example.test", "passive", "passive-full", result)
        rows = store.get_findings(sid)
        assert {r["title"]: r["origin"] for r in rows} == {
            "Passive thing": "passive", "Active thing": "active"}
        glob = store.list_findings_global()
        assert {r["title"]: r["origin"] for r in glob}["Passive thing"] == "passive"
        # the HTML report from the test server must show the passive origin
        admin = _login(port, "admin", "test-admin-pw-123")
        st, _, body = _req(port, "GET", f"/report/{sid}?fmt=html", cookie=admin)
        assert st == 200
        assert b"passive" in body.lower()
    finally:
        srv.shutdown()


def test_cli_passive_dan_scan_jalan(tmp_path):
    """Regression v3.18.1: the CLI once crashed with 'function object has no attribute
    append' because the callable vs list log protocol did not match. Both
    subcommands must emit valid JSON with exit 0."""
    import subprocess
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"<html><body>hello</body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        for argv in (["passive", url],
                     ["scan", url, "--profile", "passive-quick"]):
            r = subprocess.run([sys.executable, os.path.join(root, "cli.py"),
                                *argv], capture_output=True, text=True,
                               timeout=240, cwd=root)
            assert r.returncode == 0, (argv, r.stderr[-400:])
            out = json.loads(r.stdout)
            assert out["type"] in ("passive", "vulnscan"), out.get("type")
    finally:
        srv.shutdown()
