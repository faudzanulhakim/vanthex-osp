#!/usr/bin/env python3
"""VANTHEX — fetch execution shared by the globe fetch helper and
the globe fetch daemon (v1.13.1).

As a script: spawned by globe_feeds for ONE HTTP fetch, then exits.
Reads one JSON request from stdin:
    {"op": "client_get"|"binary", "out": <body file path>, ...}
performs the fetch with the SAME transport code the service uses
(netclient for "client_get"; globe_feeds._fetch_binary_direct for
"binary"), writes the raw body to "out", and prints ONE JSON result
object on stdout:
    {"status", "headers", "cut", "error", "error_type", "body_file"}

The daemon (globe_fetch_daemon.py) imports execute() from here and
returns the same result shape over its unix socket.

Proxy configuration arrives via the environment (PTK_PROXY /
HTTPS_PROXY / ...) prepared by whoever launched the process: the
credential is used, never printed, logged, or returned.
"""
import base64
import json
import os
import sys
import urllib.parse
import urllib.request

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)


def execute(req):
    """Perform one fetch op. Returns (meta, body_bytes); transport
    failures are reported inside meta (error/error_type), never
    raised, so callers keep one uniform result shape."""
    meta = {"status": 0, "headers": {}, "cut": False,
            "error": "", "error_type": ""}
    body = b""
    try:
        if req["op"] == "client_get":
            import netclient
            client = netclient.Client(
                "https://" + req["host"],
                timeout=req.get("timeout") or 30.0,
                extra_headers=req.get("headers"))
            resp = client.get(req["path"])
            if resp.error:
                meta["error"] = resp.error
                meta["error_type"] = "OSError"
            else:
                meta["status"] = resp.status
                body = resp.raw or (resp.body or "").encode(
                    "utf-8", "replace")
        elif req["op"] == "binary":
            import globe_feeds as gf
            data = req.get("data_b64")
            data = base64.b64decode(data) if data else None
            status, hdrs, raw, cut = gf._fetch_binary_direct(
                req["url"], timeout=req.get("timeout") or 10.0,
                cap=req.get("cap") or 1024 * 1024,
                headers=req.get("headers"),
                method=req.get("method") or "GET",
                data=data)
            meta["status"] = status
            meta["headers"] = hdrs
            meta["cut"] = cut
            body = raw
        elif req["op"] == "tls":
            # v1.23.0 SSL tool: TLS handshake through the launch-time
            # proxy ONLY. When no proxy is configured (e.g. the
            # subprocess helper spawned by the proxy-less service),
            # the op ERRORS instead of handshaking direct: a direct
            # handshake from the service network would meet the
            # sandbox gateway, and its certificate must never be
            # reported as the target's. SNI is always set; the cert
            # is captured with an unverified context (DER), while
            # verify_ok comes from a separate default-context
            # handshake. No cert content is logged.
            import socket as _socket
            import ssl as _ssl
            host = req.get("host", "")
            port = int(req.get("port") or 443)
            timeout = req.get("timeout") or 15.0
            proxies = urllib.request.getproxies()
            proxy = proxies.get("https", "")
            try:
                if not proxy:
                    raise IOError("no proxy configured for TLS audit")
                pp = urllib.parse.urlparse(
                    proxy if "//" in proxy else "http://" + proxy)
                conn = _socket.create_connection(
                    (pp.hostname, pp.port or 8080), timeout=timeout)
                th = None
                if pp.username:
                    cred = base64.b64encode(
                        ("%s:%s" % (pp.username,
                                    pp.password or "")).encode()).decode()
                    th = {"Proxy-Authorization": "Basic " + cred}
                conn.sendall(
                    ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
                     % (host, port, host, port)).encode()
                    + (("Proxy-Authorization: %s\r\n" % th[
                        "Proxy-Authorization"]).encode() if th else b"")
                    + b"\r\n")
                resp = b""
                while b"\r\n\r\n" not in resp:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    resp += chunk
                if b" 200 " not in resp.split(b"\r\n", 1)[0]:
                    raise IOError("proxy CONNECT refused: %s"
                                  % resp.split(b"\r\n", 1)[0][:80])
                uctx = _ssl._create_unverified_context()
                with uctx.wrap_socket(conn,
                                      server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
                    meta["version"] = ss.version() or ""
                    cipher = ss.cipher()
                    meta["cipher"] = (
                        cipher[0] if cipher else "")
                # Second handshake: default verification (hostname +
                # CA) for verify_ok only; its cert is discarded.
                try:
                    try:
                        import certifi as _certifi
                        vctx = _ssl.create_default_context(
                            cafile=_certifi.where())
                    except Exception:
                        vctx = _ssl.create_default_context()
                    conn2 = _socket.create_connection(
                        (pp.hostname, pp.port or 8080), timeout=timeout)
                    conn2.sendall(
                        ("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n"
                         % (host, port, host, port)).encode()
                        + (("Proxy-Authorization: %s\r\n" % th[
                            "Proxy-Authorization"]).encode()
                           if th else b"") + b"\r\n")
                    resp2 = b""
                    while b"\r\n\r\n" not in resp2:
                        chunk = conn2.recv(4096)
                        if not chunk:
                            break
                        resp2 += chunk
                    if b" 200 " not in resp2.split(b"\r\n", 1)[0]:
                        raise IOError("proxy CONNECT refused")
                    with vctx.wrap_socket(conn2,
                                          server_hostname=host):
                        pass
                    meta["verify_ok"] = True
                    meta["verify_error"] = ""
                except Exception as e2:  # noqa: BLE001
                    meta["verify_ok"] = False
                    meta["verify_error"] = str(e2)[:200]
                meta["status"] = "ok"
                meta["der_b64"] = base64.b64encode(der).decode() \
                    if der else ""
            except Exception as e:  # noqa: BLE001
                meta["error"] = str(e)[:400]
                meta["error_type"] = type(e).__name__
        else:
            meta["error"] = "unknown op: %s" % (req.get("op"),)
            meta["error_type"] = "ValueError"
    except Exception as e:  # noqa: BLE001 — reported to caller verbatim
        meta["error"] = str(e)[:400]
        meta["error_type"] = type(e).__name__
    return meta, body


def main():
    req = json.loads(sys.stdin.read())
    meta, body = execute(req)
    meta["body_file"] = ""
    if not meta["error"]:
        with open(req["out"], "wb") as f:
            f.write(body)
        meta["body_file"] = req["out"]
    sys.stdout.write(json.dumps(meta))


if __name__ == "__main__":
    main()
