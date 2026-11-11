"""
WebSuite — WebSocket & Server-Sent Events attack pack for VANTHEX.
AUTHORIZED TESTING ONLY.

Checks and probes:
- ws_origin_bypass(url, payload, fetcher)
      Raw-socket ws:// handshake (stdlib: Sec-WebSocket-Accept = base64 of
      sha1(key + magic GUID), plain TCP HTTP Upgrade). Four Origin variants
      are tried: (a) no Origin header at all, (b) evil foreign origin,
      (c) subdomain-suffix trust bypass (origin ending in the target host,
      the classic `endswith(host)` allowlist mistake), (d) literal "null".
      wss:// targets are documented as requiring an ssl-wrapped socket and
      are probed with TLS if available; plain ws:// is the default path.
      Verdict: evil/suffix origin accepted at 101 AND the server echoes
      token-shaped data (jwt/session/secret/token keys) -> PROBABLE
      cross-site websocket hijacking; otherwise CANDIDATE manual-required.
- cswsh_message_probe(url, payload)
      Full CSWSH message probe: handshake with a FOREIGN origin, send one
      message, read the echo. Evidence-only helper feeding ws_origin_bypass.
- ws_message_injection(url)
      Malformed-frame handling probe vs a baseline ping: a BINARY frame
      where text is expected, a frame claiming an oversized (64-bit)
      payload length while sending only a few bytes, and an empty frame.
      Any server-side misbehaviour (accepts the oversized claim, echoes
      binary as text, closes without a proper close frame) is reported as
      CANDIDATE manual-required — never confirmed.
- sse_auth_probe(url, session_cookie=None)
      GET with Accept: text/event-stream, once WITH a session cookie and
      once WITHOUT. Unauthenticated stream (200 + text/event-stream with
      real event data) -> PROBABLE unauthorized SSE access; otherwise the
      differential is the proof that auth is enforced.
- subscribe_bypass(url, auth_header)
      Subscribe endpoint differential: identical request with vs without
      the Authorization header. Substantive content without auth while the
      with-auth request succeeds -> PROBABLE subscribe bypass.
- c_ws_suite(ctx, add)
      Scan check, operator-gated (PTK_WS=1, PTK_WEBSOCKET also accepted).
      Discovers ws:// / socket.io mentions in ctx page bodies, probes at
      most MAX_WS_ENDPOINTS endpoints, honours ctx.cancelled().

Honesty rules: no finding is CONFIRMED from a single probe; differentials
are against explicit baselines (ping frame, with-auth stream, with-auth
subscribe). Sockets use short timeouts and are always closed in finally.
"""
import base64 as _b64
import hashlib as _hashlib
import json as _json
import os as _os
import re as _re
import socket as _socket
import struct as _struct
import time as _time
from urllib.parse import urlsplit

AUTHORIZED_TESTING_ONLY = "AUTHORIZED TESTING ONLY"

GATE_ENV = "PTK_WS"
GATE_ENV_ALT = "PTK_WEBSOCKET"

MAX_WS_ENDPOINTS = 3
_RAW_TIMEOUT = 4.0
_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_KEY = "dGhlIHNhbXBsZSBub25jZQ=="

_TOKEN_KEYS = ("jwt", "session", "secret", "token", "authorization",
               "auth", "password", "credential", "cookie", "api_key",
               "apikey", "access_token", "refresh_token")

_EVIL_ORIGIN = "https://evil.attacker.example"
_NULL_ORIGIN = "null"

_VERIFY_MH = ("Manual check: open the WebSocket from a page on an attacker-"
              "controlled origin with the victim session cookies and observe "
              "whether server messages (tokens, session data) are readable.")


def _F():
    """Lazily import the shared finding factory (circular-import guard)."""
    from vulnscan2 import F
    return F


def _gate(opts=None):
    env = _os.environ.get(GATE_ENV) or _os.environ.get(GATE_ENV_ALT)
    if env == "1":
        return True
    if opts:
        return bool(opts.get("ws_suite") or opts.get("ws"))
    return False


# ------------------------------------------------------------ frame helpers

def _expected_accept(key):
    return _b64.b64encode(
        _hashlib.sha1((key + _MAGIC).encode("latin-1")).digest()).decode()


def _mask_frame(opcode, data=b"", mask=b"\x11\x22\x33\x44"):
    """Build one masked client frame (RFC 6455 requires client masking)."""
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    n = len(data)
    if n < 126:
        hdr.append(0x80 | n)
    elif n < 65536:
        hdr.append(0x80 | 126)
        hdr += _struct.pack(">H", n)
    else:
        hdr.append(0x80 | 127)
        hdr += _struct.pack(">Q", n)
    hdr += mask
    hdr += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return bytes(hdr)


def _read_frame(sock, timeout=_RAW_TIMEOUT):
    """Read one WS frame; returns dict(op, payload, err, claimed_len)."""
    out = {"op": None, "payload": b"", "err": "", "claimed_len": 0}
    try:
        sock.settimeout(timeout)
        h = _recv_exact(sock, 2)
        if h is None:
            out["err"] = "closed/timeout waiting for frame header"
            return out
        b0, b1 = h[0], h[1]
        out["op"] = b0 & 0x0F
        ln = b1 & 0x7F
        masked = bool(b1 & 0x80)
        if ln == 126:
            ext = _recv_exact(sock, 2)
            ln = _struct.unpack(">H", ext)[0]
        elif ln == 127:
            ext = _recv_exact(sock, 8)
            ln = _struct.unpack(">Q", ext)[0]
        out["claimed_len"] = ln
        if ln > 1 << 20:            # refuse to actually buffer absurd sizes
            out["payload"] = b""
            return out
        if masked:
            _recv_exact(sock, 4)     # server frames are unmasked; skip if set
        if ln:
            data = _recv_exact(sock, ln)
            out["payload"] = data or b""
        return out
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
        return out


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        try:
            chunk = sock.recv(n - len(buf))
        except _socket.timeout:
            return buf if buf else None
        if not chunk:
            return buf if buf else None
        buf += chunk
    return buf


def _recv_some(sock, timeout=_RAW_TIMEOUT):
    """Best-effort read of whatever arrives within timeout."""
    sock.settimeout(timeout)
    data = b""
    t0 = _time.time()
    while _time.time() - t0 < timeout:
        try:
            chunk = sock.recv(65536)
        except _socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if len(data) > 4096:
            break
    return data


# ------------------------------------------------------- raw WS handshake

def _ws_connect(url, origin=None, timeout=_RAW_TIMEOUT):
    """Raw-socket ws:// handshake. Returns dict with status, headers,
    accepted (101 + correct Sec-WebSocket-Accept), sock (open socket on
    success — CALLER MUST CLOSE) and err. wss:// uses an ssl wrapper
    (documented requirement); falls back to a handshake failure note when
    the ssl handshake is refused."""
    out = {"status": 0, "headers": [], "accepted": False, "sock": None,
           "err": "", "transport": "plain"}
    try:
        parts = urlsplit(url)
        host = parts.hostname
        scheme = (parts.scheme or "ws").lower()
        if not host:
            out["err"] = "cannot parse host from URL"
            return out
        if scheme == "wss":
            port = parts.port or 443
            try:
                import ssl as _ssl
                raw = _socket.create_connection((host, port), timeout=timeout)
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=host)
                out["transport"] = "ssl"
            except Exception as e:
                out["err"] = ("wss:// handshake failed (ssl wrapper needed): "
                              f"{type(e).__name__}: {e}")
                return out
        else:
            port = parts.port or 80
            sock = _socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        lines = [f"GET {path} HTTP/1.1", f"Host: {host}:{port}",
                 "Upgrade: websocket", "Connection: Upgrade",
                 f"Sec-WebSocket-Key: {_KEY}", "Sec-WebSocket-Version: 13"]
        if origin is not None:
            lines.append(f"Origin: {origin}")
        raw = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        sock.sendall(raw)
        data = b""
        t0 = _time.time()
        while b"\r\n\r\n" not in data and _time.time() - t0 < timeout:
            try:
                chunk = sock.recv(4096)
            except _socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        lines_r = head.split(b"\r\n")
        try:
            out["status"] = int(lines_r[0].split()[1])
        except Exception:
            out["err"] = "unparseable handshake response"
        for ln in lines_r[1:]:
            if b":" in ln:
                k, _, v = ln.partition(b":")
                out["headers"].append((k.decode("latin-1").strip(),
                                       v.decode("latin-1").strip()))
        if out["status"] == 101:
            got = ""
            for k, v in out["headers"]:
                if k.lower() == "sec-websocket-accept":
                    got = v.strip()
            out["accepted"] = got == _expected_accept(_KEY)
            out["sock"] = sock        # ownership passes to caller
            out["_leftover"] = rest
        else:
            try:
                sock.close()
            except Exception:
                pass
        return out
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
        return out


def _ws_send_text(sock, text):
    sock.sendall(_mask_frame(0x1, text.encode("utf-8")))


def _ws_send_ping(sock):
    sock.sendall(_mask_frame(0x9, b"ptk-ping"))


def _ws_close(sock):
    try:
        sock.close()
    except Exception:
        pass


def _token_shape(text):
    """True when the echoed text carries token-shaped keys."""
    low = str(text).lower()
    return any(k in low for k in _TOKEN_KEYS)


def _extract_ws_paths(blob):
    """Discover ws:// endpoints and socket.io mentions from page bodies."""
    found = []
    for m in _re.finditer(r'ws://[^"\'<>\s\\]+', blob or "", _re.I):
        found.append(m.group(0).rstrip(".,;)"))
    # socket.io mentions without an explicit ws:// URL -> implied /socket.io/
    if _re.search(r'io\.connect|socket\.io', blob or "", _re.I):
        found.append("SOCKETIO:/socket.io/")
    # relative paths shown in new WebSocket("...") literals
    for m in _re.finditer(r'new\s+WebSocket\(\s*["\']([^"\']+)["\']',
                          blob or "", _re.I):
        p = m.group(1)
        if p.startswith("ws"):
            found.append(p)
    seen, out = set(), []
    for f in found:
        k = f.split("?")[0]
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out


def _absolute_ws_url(ws_url, target):
    """Turn a discovered endpoint into an absolute ws:// URL on the target
    host (socket.io mentions and relative paths are normalised)."""
    if ws_url.startswith("SOCKETIO:"):
        ws_url = ws_url[len("SOCKETIO:"):]
    if ws_url.startswith("ws://") or ws_url.startswith("wss://"):
        return ws_url
    parts = urlsplit(target)
    scheme = "wss" if (parts.scheme or "http").lower() == "https" else "ws"
    host = parts.hostname or "127.0.0.1"
    port_part = f":{parts.port}" if parts.port else ""
    path = ws_url if ws_url.startswith("/") else "/" + ws_url
    return f"{scheme}://{host}{port_part}{path}"


# =========================================================== 1. origin bypass

def ws_origin_bypass(url, payload="ping", fetcher=None):
    """Probe one ws:// endpoint with four Origin variants.

    fetcher(url) -> str (page body) is injected so unit tests can run this
    offline; when provided it is used to fetch the page hosting the
    WebSocket and look for a one-time nonce/token requirement (which would
    mitigate hijacking even if the Origin check is missing).

    Returns a findings-style dict list (usually one entry) plus a details
    dict on every variant for the caller/log."""
    variants = [
        ("no-origin", None),
        ("evil", _EVIL_ORIGIN),
        ("suffix-trust", f"https://{urlsplit(url).hostname}.evil.attacker.example"),
        ("null", _NULL_ORIGIN),
    ]
    results = {}
    probe_msg = payload or "ping"
    nonce_hint = False
    if fetcher is not None:
        try:
            body = fetcher(url)
            low = (body or "").lower()
            nonce_hint = bool(_re.search(
                r'(nonce|csrf|one.?time|ws[_-]?token)', low))
        except Exception:
            nonce_hint = False
    for name, origin in variants:
        res = _ws_connect(url, origin=origin)
        entry = {"origin": name, "status": res["status"],
                 "accepted": res["accepted"], "err": res["err"], "echo": "",
                 "token_echo": False}
        sock = res["sock"]
        if sock:
            try:
                _ws_send_text(sock, probe_msg)
                fr = _read_frame(sock)
                txt = fr["payload"].decode("utf-8", "replace")
                entry["echo"] = txt[:300]
                entry["token_echo"] = _token_shape(txt)
            except Exception as e:
                entry["err"] = f"{type(e).__name__}: {e}"
            finally:
                _ws_close(sock)
        results[name] = entry
    hijackable = (results["evil"]["accepted"]
                  or results["suffix-trust"]["accepted"])
    token_echo = (results["evil"]["token_echo"]
                  or results["suffix-trust"]["token_echo"])
    accepted_names = [n for n, e in results.items() if e["accepted"]]
    out = {"url": url, "results": results, "accepted": accepted_names,
           "hijackable": hijackable, "token_echo": token_echo,
           "nonce_hint": nonce_hint, "findings": []}
    if hijackable:
        if token_echo:
            conf, ver, note = "probable", "differential", (
                "Foreign Origin handshake accepted AND the first server "
                "message carries token-shaped keys (jwt/session/secret) — "
                "a malicious page could read session data with the victim's "
                "cookies. Reproduce manually to confirm.")
            cvss, sev = 8.2, "HIGH"
        else:
            conf, ver, note = "candidate", "manual-required", (
                "Foreign Origin handshake accepted, but no token-shaped "
                "data was observed in the first echo — the channel may only "
                "carry non-sensitive traffic. Manual verification required.")
            cvss, sev = 5.3, "MEDIUM"
        if nonce_hint:
            note += (" NOTE: the hosting page references a nonce/token — "
                     "the server may still require a one-time handshake "
                     "token not visible to this probe.")
        ev = ("handshakes accepted from origins: "
              + ",".join(accepted_names)
              + "; evil=" + _json.dumps(results["evil"], default=str)
              + "; suffix-trust=" + _json.dumps(results["suffix-trust"],
                                                default=str))
        F = _F()
        out["findings"].append(F(
            sev,
            f"Cross-Site WebSocket Hijacking suspected: {url}",
            "The WebSocket handshake is accepted from an attacker-controlled "
            "Origin (or with no Origin at all), so any web page the victim "
            "visits can open the socket with their cookies and read/write "
            "the channel." if token_echo else
            "The WebSocket handshake is accepted from an attacker-controlled "
            "Origin; the channel content looked non-sensitive in this probe.",
            evidence=ev, cwe="CWE-346",
            owasp="A01:2021 Broken Access Control", cvss=cvss,
            location=url, remed="Validate the Origin header against a strict "
            "allowlist of exact hosts (never a suffix match); require a "
            "one-time token in the handshake; never rely on cookies alone.",
            confidence=conf, verification=ver, verification_note=note
            + " " + _VERIFY_MH))
    else:
        F = _F()
        out["findings"].append(F(
            "INFO", f"WebSocket Origin checks look enforced: {url}",
            "Handshakes from a foreign Origin, a suffix-matching Origin, "
            "the null Origin and a no-Origin request were all rejected, or "
            "the endpoint was unreachable. Informational.",
            evidence=_json.dumps(out["results"], default=str),
            cwe="CWE-346", owasp="A01:2021 Broken Access Control",
            cvss=0.0, location=url,
            confidence="candidate", verification="manual-required",
            verification_note=("Controls rejected every foreign-origin "
                               "variant; no finding raised.")))
    return out


# ====================================================== 2. CSWSH message probe

def cswsh_message_probe(url, payload="ptk-cswsh-probe"):
    """Handshake with a FOREIGN origin, send one message, read the echo.

    Returns dict(foreign_accepted, echoed, token_echo, echo, err). This is
    the message-level proof backing ws_origin_bypass (origin acceptance
    alone is only handshake-level evidence)."""
    res = _ws_connect(url, origin=_EVIL_ORIGIN)
    out = {"foreign_accepted": res["accepted"], "echoed": False,
           "token_echo": False, "echo": "", "err": res["err"], "status":
           res["status"]}
    sock = res["sock"]
    if sock:
        try:
            _ws_send_text(sock, payload)
            fr = _read_frame(sock)
            txt = fr["payload"].decode("utf-8", "replace")
            out["echo"] = txt[:300]
            out["echoed"] = payload in txt or bool(txt)
            out["token_echo"] = _token_shape(txt)
        except Exception as e:
            out["err"] = f"{type(e).__name__}: {e}"
        finally:
            _ws_close(sock)
    return out


# ======================================================== 3. message injection

def ws_message_injection(url):
    """Send malformed frames vs a baseline ping and diff server behaviour.

    Frames: (a) BINARY opcode where a text message is expected, (b) a frame
    CLAIMING an oversized 64-bit length while only 4 bytes are sent,
    (c) an empty text frame. Baseline: a normal ping -> pong.
    Any anomaly is CANDIDATE / manual-required — never confirmed."""
    out = {"baseline": None, "anomalies": [], "findings": []}
    # baseline: ping/pong on a clean connection
    res = _ws_connect(url, origin=None)
    if res["sock"]:
        try:
            _ws_send_ping(res["sock"])
            fr = _read_frame(res["sock"])
            out["baseline"] = {"op": fr["op"], "payload_len":
                               len(fr["payload"]), "err": fr["err"]}
        finally:
            _ws_close(res["sock"])
    else:
        out["baseline"] = {"err": res["err"] or "handshake failed"}
        return out

    def _probe(tag, opcode, data, claim_len=None):
        entry = {"frame": tag, "err": "", "op": None, "closed": False,
                 "payload_len": 0}
        r = _ws_connect(url, origin=None)
        sock = r["sock"]
        if not sock:
            entry["err"] = r["err"] or "handshake failed"
            return entry
        try:
            if claim_len is not None:
                # oversized frame-length claim: build a frame whose 64-bit
                # length field claims claim_len bytes but send only len(data)
                mask = b"\x11\x22\x33\x44"
                hdr = bytearray([0x80 | (opcode & 0x0F), 0x80 | 127])
                hdr += _struct.pack(">Q", claim_len)
                hdr += mask
                hdr += bytes(b ^ mask[i % 4] for i, b in enumerate(data))
                sock.sendall(bytes(hdr))
            else:
                sock.sendall(_mask_frame(opcode, data))
            fr = _read_frame(sock, timeout=2.0)
            entry["op"] = fr["op"]
            entry["payload_len"] = len(fr["payload"])
            entry["claimed_len"] = fr["claimed_len"]
            entry["err"] = fr["err"]
            entry["closed"] = bool(fr["err"]) and not fr["payload"]
        except Exception as e:
            entry["err"] = f"{type(e).__name__}: {e}"
            entry["closed"] = True
        finally:
            _ws_close(sock)
        return entry

    bin_res = _probe("binary-where-text-expected", 0x2, b"ptk-bin")
    big_res = _probe("oversized-length-claim", 0x1, b"PTK!",
                     claim_len=1 << 40)
    empty_res = _probe("empty-frame", 0x1, b"")
    out["probes"] = {"binary": bin_res, "oversized": big_res,
                     "empty": empty_res}
    base = out["baseline"] or {}
    # anomaly heuristics (conservative; everything stays candidate)
    if bin_res.get("op") == 0x1 and bin_res.get("payload_len", 0) > 0:
        out["anomalies"].append("binary frame echoed back as a TEXT frame "
                                "(opcode coerced 2->1)")
    if big_res.get("claimed_len", 0) >= (1 << 32):
        out["anomalies"].append("server accepted a frame claiming a >4GiB "
                                "payload length without closing/limiting")
    if empty_res.get("err") and "timeout" not in empty_res["err"].lower():
        out["anomalies"].append("empty frame caused an error/close: "
                                + empty_res["err"])
    if out["anomalies"]:
        F = _F()
        out["findings"].append(F(
            "MEDIUM",
            f"WebSocket malformed-frame handling anomalies: {url}",
            "The server reacted abnormally to malformed frames (binary "
            "opcode coercion, oversized length claim accepted, or unclean "
            "close on an empty frame). Depending on the implementation this "
            "can enable frame-smuggling or parser desync downstream.",
            evidence=_json.dumps(out["probes"], default=str),
            cwe="CWE-20", owasp="A03:2021 Injection", cvss=5.3,
            location=url, remed="Enforce RFC 6455 frame validation: reject "
            "unexpected opcodes, cap frame lengths server-side, always send "
            "a proper close frame on protocol violations.",
            confidence="candidate", verification="manual-required",
            verification_note="Anomaly observed on one probe pair vs the "
            "ping baseline; implementation-level impact requires manual "
            "verification. " + _VERIFY_MH))
    return out


# ========================================================== 4. SSE auth probe

def _sse_request(url, headers):
    """One SSE probe request via raw HTTP (keeps the check self-contained
    and hermetic; short timeout, socket closed in finally)."""
    out = {"status": 0, "ctype": "", "body": "", "err": ""}
    try:
        parts = urlsplit(url)
        host = parts.hostname or "127.0.0.1"
        port = parts.port or (443 if (parts.scheme or "http") == "https"
                              else 80)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        s = _socket.create_connection((host, port), timeout=_RAW_TIMEOUT)
        try:
            s.settimeout(_RAW_TIMEOUT)
            lines = [f"GET {path} HTTP/1.1", f"Host: {host}:{port}",
                     "Accept: text/event-stream", "Connection: close"]
            for k, v in (headers or {}).items():
                lines.append(f"{k}: {v}")
            s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
            data = b""
            t0 = _time.time()
            while _time.time() - t0 < _RAW_TIMEOUT:
                try:
                    chunk = s.recv(65536)
                except _socket.timeout:
                    break
                if not chunk:
                    break
                data += chunk
                if b"\n\n" in data.partition(b"\r\n\r\n")[2]:
                    break
            head, _, body = data.partition(b"\r\n\r\n")
            for ln in head.split(b"\r\n"):
                low = ln.lower()
                if low.startswith(b"content-type:"):
                    out["ctype"] = ln.split(b":", 1)[1].decode(
                        "latin-1").strip()
                elif low.startswith(b"http/"):
                    try:
                        out["status"] = int(ln.split()[1])
                    except Exception:
                        pass
            out["body"] = body.decode("utf-8", "replace")[:2000]
        finally:
            try:
                s.close()
            except Exception:
                pass
        return out
    except Exception as e:
        out["err"] = f"{type(e).__name__}: {e}"
        return out


def sse_auth_probe(url, session_cookie=None):
    """SSE stream with vs without a session cookie.

    Unauthenticated stream (200 + text/event-stream + real 'data:' events)
    -> PROBABLE unauthorized SSE access; otherwise CANDIDATE/INFO."""
    hdr_with = {"Accept": "text/event-stream"}
    if session_cookie:
        hdr_with["Cookie"] = session_cookie
    with_auth = _sse_request(url, hdr_with)
    without = _sse_request(url, {"Accept": "text/event-stream"})
    out = {"with_auth": with_auth, "without_auth": without, "findings": []}
    is_stream = (lambda r: r["status"] == 200
                 and "text/event-stream" in r["ctype"].lower()
                 and ("data:" in r["body"] or "event:" in r["body"]))
    if is_stream(without):
        F = _F()
        out["findings"].append(F(
            "MEDIUM",
            f"Unauthenticated Server-Sent Events stream: {url}",
            "The SSE endpoint streams live events without any session "
            "cookie — anyone who can reach the URL receives the same event "
            "firehose an authenticated user would (data exposure or "
            "notification spoofing depending on channel content).",
            evidence=(f"no-auth: {without['status']} {without['ctype']} "
                      f"body={without['body'][:200]!r}; with-auth: "
                      f"{with_auth['status']}"),
            cwe="CWE-306", owasp="A01:2021 Broken Access Control",
            cvss=5.3, location=url,
            remed="Require authentication on the SSE route (cookie/session "
            "check before registering the stream) and scope events per "
            "user; do not serve a shared global channel unauthenticated.",
            confidence="probable", verification="differential",
            verification_note="Unauthenticated request returned a live "
            "text/event-stream with event data; the with-auth request is "
            "the comparison point. " + _VERIFY_MH))
    elif not without["status"] and not without["err"]:
        F = _F()
        out["findings"].append(F(
            "INFO", f"SSE endpoint unreachable: {url}",
            "The SSE probe received no HTTP response; the endpoint may not "
            "exist. Informational only.", evidence=_json.dumps(out),
            cwe="", owasp="", cvss=0.0, location=url,
            confidence="candidate", verification="manual-required",
            verification_note="No response — nothing concluded."))
    else:
        F = _F()
        out["findings"].append(F(
            "INFO", f"SSE auth appears enforced: {url}",
            "The unauthenticated stream request did not return live event "
            "data (rejected, empty, or non-event-stream content type). "
            "Informational.", evidence=_json.dumps(out),
            cwe="CWE-306", owasp="A01:2021 Broken Access Control",
            cvss=0.0, location=url, confidence="candidate",
            verification="manual-required",
            verification_note="Auth differential held; no finding raised."))
    return out


# ========================================================= 5. subscribe bypass

def subscribe_bypass(url, auth_header="Authorization: Bearer ptk-canary"):
    """Subscribe differential: identical request with vs without the
    Authorization header. Substantive (non-error) content without auth
    while the with-auth request succeeds -> PROBABLE."""
    key, _, val = auth_header.partition(":")
    with_auth = _sse_request(url, {key.strip(): val.strip(),
                                   "Accept": "application/json"})
    without = _sse_request(url, {"Accept": "application/json"})
    out = {"with_auth": with_auth, "without_auth": without, "findings": []}
    ok_with = with_auth["status"] == 200 and len(with_auth["body"]) > 0
    leak = (without["status"] == 200 and len(without["body"]) > 40
            and not _re.search(r'(?i)(unauthorized|forbidden|error|denied)',
                               without["body"]))
    if ok_with and leak:
        F = _F()
        out["findings"].append(F(
            "HIGH",
            f"Subscribe endpoint serves data without authorization: {url}",
            "The subscribe endpoint returns substantive data with no "
            "Authorization header, while the same request with credentials "
            "succeeds — unauthenticated clients can subscribe to the "
            "resource stream.",
            evidence=(f"without-auth: {without['status']} "
                      f"len={len(without['body'])} "
                      f"body={without['body'][:200]!r}; with-auth: "
                      f"{with_auth['status']} len={len(with_auth['body'])}"),
            cwe="CWE-306", owasp="A01:2021 Broken Access Control",
            cvss=7.5, location=url,
            remed="Enforce authorization on the subscribe route before "
            "opening the stream; reject requests without a valid token "
            "with 401/403 instead of serving public content.",
            confidence="probable", verification="differential",
            verification_note="Differential with/without Authorization "
            "header on the same request. " + _VERIFY_MH))
    return out


# ================================================================ 6. scan check

def c_ws_suite(ctx, add):
    """WebSocket/SSE suite check (operator-gated: PTK_WS=1 or opts['ws_suite']).

    Discovers ws:// and socket.io mentions from the ctx page bodies, probes
    at most MAX_WS_ENDPOINTS endpoints, honours ctx.cancelled(). SSE probes
    run against discovered /socket.io|/events-ish paths on the same host."""
    if not _gate(getattr(ctx, "opts", None)):
        ctx.L("  [websuite] operator gate PTK_WS not set — skipped")
        return
    blob = ""
    try:
        surf = ctx.surface(full=True)
        pages = list(surf.pages)[:8]
        for pg in pages:
            if ctx.cancelled():
                return
            try:
                r = ctx.client.get(str(pg).split("?")[0])
                blob += (r.body or "")
            except Exception:
                continue
    except Exception as e:
        ctx.L(f"  [websuite] surface fetch failed: {type(e).__name__}: {e}")
    endpoints = _extract_ws_paths(blob)[:MAX_WS_ENDPOINTS]
    ctx.L(f"  [websuite] {len(endpoints)} WS endpoint(s) discovered")
    target = getattr(getattr(ctx, "client", None), "target", "") or \
        str(getattr(ctx, "target", ""))
    for ep in endpoints:
        if ctx.cancelled():
            return
        url = _absolute_ws_url(ep, target)
        try:
            res = ws_origin_bypass(url, "ptk-probe")
            for f in res["findings"]:
                if f.get("severity") != "INFO" or f.get("cvss"):
                    add(f)
        except Exception as e:
            ctx.L(f"  [websuite] origin bypass probe failed for {url}: "
                  f"{type(e).__name__}: {e}")
    if ctx.cancelled():
        return
    # SSE/subscribe probes on plausible stream paths of the same host
    parts = urlsplit(target)
    base = f"{parts.scheme or 'http'}://{parts.hostname or '127.0.0.1'}"
    if parts.port:
        base += f":{parts.port}"
    for path in ("/events", "/stream", "/sse"):
        if ctx.cancelled():
            return
        try:
            res = sse_auth_probe(base + path,
                                 session_cookie=getattr(
                                     getattr(ctx, "client", None),
                                     "cookie", None))
            for f in res["findings"]:
                if f.get("severity") != "INFO" or f.get("cvss"):
                    add(f)
        except Exception as e:
            ctx.L(f"  [websuite] SSE probe failed for {path}: "
                  f"{type(e).__name__}: {e}")
