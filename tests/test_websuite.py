"""
Hermetic tests for websuite.py (WebSocket & SSE attack suite).

Self-contained http.server fixtures at module level (autostart + atexit
shutdown, so both pytest and plain import have live servers):
- /ws/vuln   : WS handshake accepting ANY origin (vulnerable) + token-shaped
               echo; coerces binary->text echoes; echoes oversized length
               claims back as-is.
- /ws/safe   : WS handshake rejecting foreign/missing origins (safe control).
- /sse/vuln  : SSE stream without auth (vulnerable).
- /sse/safe  : SSE stream requiring a session cookie (safe control).
- /sub/vuln  : subscribe endpoint serving data without Authorization.
- /sub/safe  : subscribe endpoint requiring Authorization.
No external network.
"""
import atexit
import base64
import hashlib
import json
import os
import struct
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from offensive import websuite

_PORT = None
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# --------------------------------------------------------- frame helpers

def _server_read_frame(conn):
    """Read one masked client frame. Returns (opcode, payload, claimed_len)
    or (None, b'', 0) on EOF/timeout."""
    try:
        conn.settimeout(3)
        hdr = b""
        while len(hdr) < 2:
            chunk = conn.recv(2 - len(hdr))
            if not chunk:
                return None, b"", 0
            hdr += chunk
        op = hdr[0] & 0x0F
        masked = bool(hdr[1] & 0x80)
        ln = hdr[1] & 0x7F
        claimed = ln
        if ln == 126:
            ext = b""
            while len(ext) < 2:
                ext += conn.recv(2 - len(ext))
            ln = struct.unpack(">H", ext)[0]
            claimed = ln
        elif ln == 127:
            ext = b""
            while len(ext) < 8:
                ext += conn.recv(8 - len(ext))
            claimed = struct.unpack(">Q", ext)[0]
            ln = min(claimed, 4096)
        if claimed > 1 << 32:
            return op, b"OVERSIZED", claimed
        if masked:
            conn.recv(4)
        data = b""
        while len(data) < ln:
            chunk = conn.recv(ln - len(data))
            if not chunk:
                break
            data += chunk
        if masked and data:
            mask = b"\x11\x22\x33\x44"   # probe client's fixed mask
            data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        return op, data, claimed
    except Exception:
        return None, b"", 0


def _server_send_frame(conn, opcode, payload=b""):
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    n = len(payload)
    if n < 126:
        hdr.append(n)
    elif n < 65536:
        hdr.append(126)
        hdr += struct.pack(">H", n)
    else:
        hdr.append(127)
        hdr += struct.pack(">Q", n)
    try:
        conn.sendall(bytes(hdr) + payload)
    except Exception:
        pass


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):     # silence test output
        pass

    # ---- WebSocket upgrade ------------------------------------------------
    def _ws_upgrade(self, path):
        if path == "/ws/safe":
            origin = self.headers.get("Origin")
            # allow a same-party/no-origin request, reject foreign origins
            if origin and origin != "http://localhost":
                self._simple(403, "origin rejected")
                return None
        key = self.headers.get("Sec-WebSocket-Key") or ""
        if self.headers.get("Upgrade", "").lower() != "websocket" or not key:
            self._simple(400, "bad upgrade")
            return None
        acc = base64.b64encode(hashlib.sha1(
            (key + _WS_GUID).encode("latin-1")).digest()).decode()
        resp = ("HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\nConnection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {acc}\r\n\r\n")
        self.connection.sendall(resp.encode("latin-1"))
        self.close_connection = True
        return self.connection

    def do_GET(self):
        path, _, _q = self.path.partition("?")
        if path in ("/ws/vuln", "/ws/safe"):
            conn = self._ws_upgrade(path)
            if conn is None:
                return
            self._ws_echo_loop(path, conn)
        elif path == "/sse/vuln":
            self._sse(body='event: tick\ndata: {"n":1}\n\n'
                           'data: session=abc-token\n\n')
        elif path == "/sse/safe":
            if "ptk-session=1" in (self.headers.get("Cookie") or ""):
                self._sse(body="data: ok\n\n")
            else:
                self._simple(401, "unauthorized")
        elif path == "/sub/vuln":
            self._json({"channel": "orders", "items": [1, 2, 3]})
        elif path == "/sub/safe":
            if self.headers.get("Authorization"):
                self._json({"channel": "orders", "items": [1, 2, 3]})
            else:
                self._simple(401, "unauthorized")
        else:
            self._simple(404, "nope")

    def _ws_echo_loop(self, path, conn):
        vuln = path == "/ws/vuln"
        while True:
            op, data, claimed = _server_read_frame(conn)
            if op is None:
                return
            if op == 0x9:                                    # ping -> pong
                _server_send_frame(conn, 0xA, data)
                continue
            if claimed > 1 << 32:
                if vuln:
                    # vulnerable: echoes the oversized length claim back
                    conn.sendall(bytes([0x81, 0x80 | 127])
                                 + struct.pack(">Q", claimed))
                else:
                    # safe: proper close frame, no giant length accepted
                    _server_send_frame(conn, 0x8, struct.pack(">H", 1009))
                return
            if vuln:
                if op == 0x2:
                    # anomaly: binary payload echoed as a TEXT frame
                    _server_send_frame(conn, 0x1, data)
                else:
                    _server_send_frame(conn, 0x1, json.dumps({
                        "jwt": "eyJhbGciOiJIUzI1NiJ9.e30.sig",
                        "session": "sess-abc123", "secret": "shh",
                        "echo": data.decode("utf-8", "replace"),
                    }).encode())
            else:
                _server_send_frame(conn, op, data)

    def _sse(self, body):
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except Exception:
            pass

    def _json(self, obj):
        payload = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _simple(self, code, text):
        payload = text.encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def _start():
    global _PORT
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    _PORT = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    atexit.register(srv.shutdown)
    return srv


_SRV = _start()
BASE = f"http://127.0.0.1:{_PORT}"
WS_VULN = f"ws://127.0.0.1:{_PORT}/ws/vuln"
WS_SAFE = f"ws://127.0.0.1:{_PORT}/ws/safe"


# ============================================================ 1. origin bypass

def test_ws_origin_bypass_vulnerable_probable():
    out = websuite.ws_origin_bypass(WS_VULN, "ptk-probe")
    assert "evil" in out["accepted"]
    assert out["token_echo"] is True
    f = out["findings"][0]
    assert f["severity"] == "HIGH"
    assert f["confidence"] == "probable"
    assert f["verification"] == "differential"
    assert "Hijacking" in f["title"]
    assert f["cvss"] == 8.2


def test_ws_origin_bypass_suffix_trust_variant_present():
    out = websuite.ws_origin_bypass(WS_VULN)
    # suffix-trust origin (ends with the target host) must also be accepted
    assert "suffix-trust" in out["accepted"]
    assert out["results"]["null"]["status"] == 101


def test_ws_origin_bypass_safe_control_info():
    out = websuite.ws_origin_bypass(
        WS_SAFE, fetcher=lambda u: "no nonce here")
    f = out["findings"][0]
    assert out["hijackable"] is False
    assert f["severity"] == "INFO"


def test_ws_origin_bypass_nonce_hint_noted():
    out = websuite.ws_origin_bypass(
        WS_VULN, fetcher=lambda u: "handshake needs ws_token nonce")
    f = out["findings"][0]
    assert "nonce" in (f.get("verification_note") or "").lower()


# ======================================================= 2. CSWSH message probe

def test_cswsh_message_probe_foreign_origin():
    out = websuite.cswsh_message_probe(WS_VULN, "ptk-cswsh-probe")
    assert out["foreign_accepted"] is True
    assert out["echoed"] is True
    assert out["token_echo"] is True
    assert "session" in out["echo"].lower()


def test_cswsh_message_probe_safe_rejects():
    out = websuite.cswsh_message_probe(WS_SAFE, "ptk-probe")
    assert out["foreign_accepted"] is False
    assert out["echoed"] is False


# ======================================================== 3. message injection

def test_ws_message_injection_anomalies_on_vulnerable():
    out = websuite.ws_message_injection(WS_VULN)
    assert out["baseline"] and out["baseline"].get("op") == 0xA  # pong
    assert out["anomalies"], "vulnerable fixture must produce anomalies"
    joined = " ".join(out["anomalies"]).lower()
    assert "binary" in joined or "4gib" in joined
    f = out["findings"][0]
    assert f["confidence"] == "candidate"
    assert f["verification"] == "manual-required"
    assert f["severity"] == "MEDIUM"


def test_ws_message_injection_clean_on_safe():
    out = websuite.ws_message_injection(WS_SAFE)
    assert out["baseline"] and out["baseline"].get("op") == 0xA
    assert out["anomalies"] == []
    assert out["findings"] == []


# =========================================================== 4. SSE auth probe

def test_sse_auth_probe_vulnerable():
    out = websuite.sse_auth_probe(BASE + "/sse/vuln", "ptk-session=1")
    f = out["findings"][0]
    assert f["severity"] == "MEDIUM"
    assert f["confidence"] == "probable"
    assert f["verification"] == "differential"
    assert "event-stream" in out["without_auth"]["ctype"]


def test_sse_auth_probe_safe():
    out = websuite.sse_auth_probe(BASE + "/sse/safe", "ptk-session=1")
    f = out["findings"][0]
    assert f["severity"] == "INFO"
    assert out["without_auth"]["status"] == 401


def test_sse_probe_socket_closed_in_finally():
    # repeated probes must not leak sockets / hang
    for _ in range(3):
        websuite.sse_auth_probe(BASE + "/sse/vuln")


# ========================================================== 5. subscribe bypass

def test_subscribe_bypass_vulnerable():
    out = websuite.subscribe_bypass(
        BASE + "/sub/vuln", "Authorization: Bearer ptk-canary")
    f = out["findings"][0]
    assert f["severity"] == "HIGH"
    assert f["confidence"] == "probable"
    assert f["verification"] == "differential"
    assert out["without_auth"]["status"] == 200


def test_subscribe_bypass_safe_no_finding():
    out = websuite.subscribe_bypass(
        BASE + "/sub/safe", "Authorization: Bearer ptk-canary")
    assert out["findings"] == []
    assert out["without_auth"]["status"] == 401


# ============================================================== 6. scan check

class _Resp:
    def __init__(self, body):
        self.body = body


class _Client:
    target = BASE + "/"

    def __init__(self, body=""):
        self.body = body
        self.cookie = "ptk-session=1"

    def get(self, path):
        return _Resp(self.body)


class _Surf:
    pages = ["/"]


class _Ctx:
    def __init__(self, body, opts):
        self.client = _Client(body)
        self.opts = opts
        self.log = []
        self._cancel = False

    def surface(self, full=True):
        return _Surf()

    def L(self, msg):
        self.log.append(msg)

    def cancelled(self):
        return self._cancel


WS_BODY = (f'<script>var s = new WebSocket("ws://127.0.0.1:{_PORT}/ws/vuln");'
           f'</script> socket.io io.connect()')


def test_c_ws_suite_gated_off_noop(monkeypatch):
    monkeypatch.delenv("PTK_WS", raising=False)
    monkeypatch.delenv("PTK_WEBSOCKET", raising=False)
    ctx = _Ctx(WS_BODY, {})
    added = []
    websuite.c_ws_suite(ctx, added.append)
    assert added == []
    assert any("gate" in m for m in ctx.log)


def test_c_ws_suite_gated_on_finds_cswsh(monkeypatch):
    monkeypatch.setenv("PTK_WS", "1")
    ctx = _Ctx(WS_BODY, {})
    added = []
    websuite.c_ws_suite(ctx, added.append)
    titles = " | ".join(f["title"] for f in added)
    assert "Hijacking" in titles
    probs = [f for f in added if f["confidence"] == "probable"]
    assert probs, "CSWSH probable finding expected"
    # SSE probes on nonexistent paths of the fixture must NOT add INFO noise
    assert all(f["severity"] != "INFO" for f in added)


def test_c_ws_suite_cancel_respected(monkeypatch):
    monkeypatch.setenv("PTK_WS", "1")
    ctx = _Ctx(WS_BODY, {})
    ctx._cancel = True
    added = []
    websuite.c_ws_suite(ctx, added.append)
    assert added == []


def test_c_ws_suite_endpoint_cap(monkeypatch):
    monkeypatch.setenv("PTK_WS", "1")
    urls = " ".join(f'ws://127.0.0.1:{_PORT}/ws/x{i}' for i in range(8))
    eps = websuite._extract_ws_paths(urls)
    assert len(eps) == 8                       # discovery itself is uncapped
    ctx = _Ctx(f"var w=new WebSocket('{urls.split()[0]}');", {})
    assert len(websuite._extract_ws_paths(ctx.client.body)) == 1


def test_extract_ws_paths_socketio():
    eps = websuite._extract_ws_paths('io.connect("/socket.io/") socket.io')
    assert "SOCKETIO:/socket.io/" in eps


def test_absolute_ws_url_normalisation():
    assert websuite._absolute_ws_url("SOCKETIO:/socket.io/", BASE + "/a") \
        == f"ws://127.0.0.1:{_PORT}/socket.io/"
    assert websuite._absolute_ws_url("/ws/x", BASE) \
        == f"ws://127.0.0.1:{_PORT}/ws/x"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
