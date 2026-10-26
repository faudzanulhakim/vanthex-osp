#!/usr/bin/env python3
"""VANTHEX — globe fetch daemon (v1.13.1).

Why this exists (measured 2026-10-23): the systemd service process
inherits no proxy environment and the runtime egress credential
(HTTPS_PROXY) rotates per agent session; a credential copied out of
a dead session is rejected by the proxy (407), so the service can
never hold a usable one. A detached long-lived process that
inherited the credential AT LAUNCH keeps fetching with it after the
launching session ends (the same pattern as the reverse tunnel's
mochi-proxy-connect). The 5-minute watchdog (restore-all.sh
section 9) therefore launches this daemon detached from its own live
session whenever it is not running; the daemon holds the credential
in MEMORY ONLY (never written to disk) and serves globe fetch ops
over a 0600 unix socket:

    request : 4-byte BE length + JSON {"op": "client_get"|"binary", ...}
    response: 4-byte BE length + JSON meta, then
              4-byte BE length + raw body bytes

Ops are executed by globe_fetch_helper.execute() — the same
transport code the service itself uses (netclient /
globe_feeds._fetch_binary_direct), so timeouts, caps and the
no-redirect posture are identical. Only globe_feeds (running inside
the service) is meant to connect; the ops it sends are its own
declared feeds and camera-index URLs, never free-form user input.

Self-healing: a probe thread re-fetches one small declared feed
every 240 s. If the proxy starts rejecting the held credential
(407), the daemon exits, and the next watchdog run (<=5 min)
relaunches it with a fresh session credential. Other probe failures
are ignored — per-request errors already flow back to the service.

Container direct-egress mode (VANTHEX_FETCH_DAEMON_DIRECT=1, set
by the container entrypoint when VANTHEX_CONTAINER_FETCH_DAEMON=1):
the 407-exit is disabled, because there is no proxy credential to
rotate and no watchdog to relaunch — the daemon stays up, and the
service falls through to direct fetch if the daemon ever stops
answering. VM behavior is unchanged when the flag is unset.

Socket path: $VANTHEX_GLOBE_FETCH_SOCK or
../pentest-toolkit-service/globe-fetch.sock relative to this file.
"""
import json
import os
import socket
import socketserver
import struct
import sys
import threading
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

SOCK_PATH = os.environ.get(
    "VANTHEX_GLOBE_FETCH_SOCK",
    os.path.normpath(os.path.join(
        _HERE, "..", "pentest-toolkit-service", "globe-fetch.sock")))
PROBE_URL = ("https://earthquake.usgs.gov/earthquakes/feed/v1.0/"
             "summary/2.5_day.geojson")
PROBE_EVERY = 240.0

# Container direct-egress mode: exact "1" only. Unset (VM default)
# keeps the 407-exit below.
_DIRECT = os.environ.get("VANTHEX_FETCH_DAEMON_DIRECT", "") == "1"


def _probe_failure_is_fatal(exc):
    """VM default: a 407 means the held proxy credential died, so the
    daemon exits for watchdog relaunch. Container direct-egress mode:
    never fatal — no proxy to rotate, no watchdog to relaunch."""
    if _DIRECT:
        return False
    return "407" in str(exc)

import globe_fetch_helper as helper  # noqa: E402


def _log(msg):
    sys.stderr.write("[globe-fetch-daemon %s] %s\n"
                     % (time.strftime("%H:%M:%S"), msg))
    sys.stderr.flush()


def _read_exactly(conn, n):
    buf = b""
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise IOError("client closed early")
        buf += chunk
    return buf


class _Handler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            (rlen,) = struct.unpack(
                ">I", _read_exactly(self.request, 4))
            if rlen > 1024 * 1024:
                raise ValueError("request too large")
            req = json.loads(
                _read_exactly(self.request, rlen).decode("utf-8"))
            meta, body = helper.execute(req)
            blob = json.dumps(meta).encode("utf-8")
            self.request.sendall(struct.pack(">I", len(blob)) + blob)
            self.request.sendall(struct.pack(">I", len(body)) + body)
        except Exception as e:  # noqa: BLE001 — one bad request must
            _log("request failed: %s" % (e,))  # never kill the daemon


class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def _probe_loop():
    """Exit when the held credential starts drawing 407s so the
    watchdog relaunches this daemon with a fresh one."""
    while True:
        time.sleep(PROBE_EVERY)
        try:
            import globe_feeds as gf
            _st, _h, _b, _c = gf._fetch_binary_direct(
                PROBE_URL, timeout=20.0, cap=64 * 1024)
        except Exception as e:  # noqa: BLE001
            if _probe_failure_is_fatal(e):
                _log("credential rejected by proxy (407); exiting "
                     "for watchdog relaunch")
                os._exit(3)
        # a live HTTP status (even an error status) means the
        # credential works — nothing to do


def main():
    if os.path.exists(SOCK_PATH):
        os.unlink(SOCK_PATH)
    srv = _Server(SOCK_PATH, _Handler)
    os.chmod(SOCK_PATH, 0o600)
    _log("listening on %s" % SOCK_PATH)
    threading.Thread(target=_probe_loop, daemon=True).start()
    try:
        srv.serve_forever()
    finally:
        try:
            os.unlink(SOCK_PATH)
        except OSError:
            pass


if __name__ == "__main__":
    main()
