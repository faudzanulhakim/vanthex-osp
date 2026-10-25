"""v1.13.1 — globe fetch path survives proxy-credential rotation.

Measured diagnosis behind the design: the systemd service process
holds NO proxy credential (its unit env carries only PTK_* vars),
and a runtime egress credential copied out of a dead agent session
is rejected by the proxy (407) — so fetches are delegated:
  tier 1: a detached fetch daemon (launched by the watchdog from a
          live session; holds the credential in memory; unix socket)
  tier 2: a short-lived helper subprocess inheriting a proxy
          resolved from this process's own env
  tier 3: direct in-process fetch (pre-v1.13.1 behaviour)

Hermetic tests: delegation/routing with stubbed tiers, the real
helper + daemon against a local 127.0.0.1 server. No external
network is used.
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ---------------------------------------------------------- proxy resolve
def test_resolve_ptk_env_wins(monkeypatch):
    monkeypatch.setenv("PTK_PROXY", "http://op:op@proxy:9999")
    assert gf._resolve_proxy() == ("http://op:op@proxy:9999", "ptk-env")


def test_resolve_env(monkeypatch):
    monkeypatch.delenv("PTK_PROXY", raising=False)
    monkeypatch.setattr(gf.urllib.request, "getproxies",
                        lambda: {"https": "http://env:env@proxy:3128"})
    assert gf._resolve_proxy() == ("http://env:env@proxy:3128", "env")


def test_resolve_none(monkeypatch):
    monkeypatch.delenv("PTK_PROXY", raising=False)
    monkeypatch.setattr(gf.urllib.request, "getproxies", lambda: {})
    assert gf._resolve_proxy() == (None, "")


# ------------------------------------------------------- delegation routing
def test_fetch_routes_through_helper(monkeypatch):
    seen = {}

    def fake_helper(op, payload, http_timeout):
        seen.update(op=op, payload=payload)
        return {"status": 200, "body": b"{}", "error": ""}
    monkeypatch.setattr(gf, "_helper_fetch", fake_helper)
    st, raw = gf._fetch("example.org", "/feed")
    assert (st, raw) == (200, b"{}")
    assert seen["op"] == "client_get"
    assert seen["payload"]["host"] == "example.org"


def test_fetch_helper_error_raises_ioerror(monkeypatch):
    monkeypatch.setattr(
        gf, "_helper_fetch",
        lambda op, payload, t: {"status": 0, "body": b"",
                                "error": "Tunnel connection failed: 407"})
    with pytest.raises(IOError, match="407"):
        gf._fetch("example.org", "/feed")


class _Resp:
    status = 200
    raw = b"direct-bytes"
    body = "direct-bytes"
    error = ""


def test_fetch_direct_when_no_delegation(monkeypatch):
    monkeypatch.setattr(gf, "_helper_fetch",
                        lambda op, payload, t: None)
    monkeypatch.setattr(gf, "_client",
                        # v1.23.0: _client gained an optional headers kwarg
                        # (DoH Accept header); the mock must accept it.
                        lambda host, timeout=30.0, headers=None: type(
                            "C", (), {"get": lambda s, p: _Resp()})())
    st, raw = gf._fetch("example.org", "/feed")
    assert (st, raw) == (200, b"direct-bytes")


def test_fetch_binary_routes_and_cut_flag(monkeypatch):
    monkeypatch.setattr(
        gf, "_helper_fetch",
        lambda op, payload, t: {"status": 200, "headers":
                                {"content-type": "image/jpeg"},
                                "body": b"\xff\xd8img", "cut": True,
                                "error": ""})
    st, hdrs, body, cut = gf._fetch_binary("https://cam.example/x.jpg")
    assert st == 200 and body == b"\xff\xd8img" and cut is True
    assert hdrs["content-type"] == "image/jpeg"


def test_fetch_binary_error_type_fidelity(monkeypatch):
    monkeypatch.setattr(
        gf, "_helper_fetch",
        lambda op, payload, t: {"status": 0, "headers": {}, "body": b"",
                                "cut": False, "error": "ssl boom",
                                "error_type": "SSLError"})
    with pytest.raises(ssl.SSLError):
        gf._fetch_binary("https://cam.example/x.jpg")


def test_raise_helper_error_mapping():
    for et, exc in (("SSLError", ssl.SSLError),
                    ("TimeoutError", TimeoutError),
                    ("ConnectionError", ConnectionError),
                    ("URLError", urllib.error.URLError),
                    ("ValueError", ValueError),
                    ("AnythingElse", IOError)):
        with pytest.raises(exc):
            gf._raise_helper_error({"error_type": et, "error": "x"})


# ------------------------------------------------------------ tier ordering
def test_helper_fetch_prefers_daemon(monkeypatch):
    monkeypatch.setattr(gf, "_daemon_fetch",
                        lambda op, p, t: {"status": 200, "body": b"D",
                                          "error": ""})
    monkeypatch.setattr(gf, "_spawn_helper_fetch",
                        lambda op, p, t: pytest.fail("tier 2 used"))
    meta = gf._helper_fetch("client_get", {"host": "h", "path": "/"}, 5.0)
    assert meta["body"] == b"D"


def test_helper_fetch_falls_to_spawn(monkeypatch):
    monkeypatch.setattr(gf, "_daemon_fetch", lambda op, p, t: None)
    monkeypatch.setattr(gf, "_spawn_helper_fetch",
                        lambda op, p, t: {"status": 200, "body": b"S",
                                          "error": ""})
    meta = gf._helper_fetch("client_get", {"host": "h", "path": "/"}, 5.0)
    assert meta["body"] == b"S"


def test_daemon_fetch_none_without_socket(monkeypatch, tmp_path):
    monkeypatch.setattr(gf, "_FETCH_SOCK_PATH",
                        str(tmp_path / "absent.sock"))
    assert gf._daemon_fetch("binary", {"url": "http://x/"}, 5.0) is None


# ------------------------------------------------- direct binary (hermetic)
class _Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — stdlib naming
        body = b"\x89PNG\r\n\x1a\nfake-image-bytes"
        self.send_response(200)
        self.send_header("Content-Type", "image/png")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


@pytest.fixture()
def local_server():
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv.server_address[1]
    srv.shutdown()


def _scrubbed_env(**extra):
    env = {k: v for k, v in os.environ.items()
           if "proxy" not in k.lower()}
    env.update(extra)
    return env


def test_fetch_binary_direct_local(local_server, monkeypatch):
    for var in ("PTK_PROXY", "HTTPS_PROXY", "HTTP_PROXY",
                "https_proxy", "http_proxy"):
        monkeypatch.delenv(var, raising=False)
    st, hdrs, body, cut = gf._fetch_binary_direct(
        f"http://127.0.0.1:{local_server}/cam.jpg", cap=4096)
    assert st == 200 and body.startswith(b"\x89PNG") and cut is False
    assert hdrs.get("content-type") == "image/png"


def test_helper_script_binary_e2e(local_server, tmp_path):
    """The real helper subprocess: one JSON request on stdin, body to
    file, one JSON result on stdout (tier-2 execution path)."""
    req = {"op": "binary", "out": str(tmp_path / "body.bin"),
           "url": f"http://127.0.0.1:{local_server}/cam.jpg",
           "timeout": 10.0, "cap": 4096, "headers": None,
           "method": "GET", "data_b64": None}
    proc = subprocess.run(
        [sys.executable,
         os.path.join(TREE, "globe_fetch_helper.py")],
        input=json.dumps(req).encode(), stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=_scrubbed_env(), timeout=30)
    assert proc.returncode == 0, proc.stderr.decode()[-300:]
    meta = json.loads(proc.stdout.decode())
    assert meta["status"] == 200 and meta["error"] == ""
    with open(tmp_path / "body.bin", "rb") as f:
        assert f.read().startswith(b"\x89PNG")


def test_daemon_binary_e2e(local_server, tmp_path, monkeypatch):
    """The real daemon on a tmp socket serves a binary op for a
    local URL (tier-1 execution path), reached via gf._daemon_fetch."""
    sock = str(tmp_path / "fetch.sock")
    proc = subprocess.Popen(
        [sys.executable, os.path.join(TREE, "globe_fetch_daemon.py")],
        env=_scrubbed_env(VANTHEX_GLOBE_FETCH_SOCK=sock),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if os.path.exists(sock):
                break
            time.sleep(0.1)
        assert os.path.exists(sock)
        assert oct(os.stat(sock).st_mode)[-3:] == "600"
        monkeypatch.setattr(gf, "_FETCH_SOCK_PATH", sock)
        meta = gf._daemon_fetch(
            "binary",
            {"url": f"http://127.0.0.1:{local_server}/cam.jpg",
             "timeout": 10.0, "cap": 4096, "headers": None,
             "method": "GET", "data_b64": None}, 10.0)
        assert meta is not None and meta["status"] == 200
        assert meta["body"].startswith(b"\x89PNG")
        assert meta["headers"].get("content-type") == "image/png"
    finally:
        proc.terminate()
        proc.wait(timeout=10)
