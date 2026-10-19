"""
Pentest Toolkit — blind callback (canary) listener (canary.py, v3.14).

socketserver-based HTTP listener that issues unique canary tokens and
records callbacks — the out-of-band (OOB) infrastructure for blind
SSRF/XXE/RCE confirmation.

DEPLOYMENT REALITY (declared, not hidden): a canary only works when the
target can reach this listener. This VM sits behind NAT/proxy with no
inbound path from the internet, so on THIS host the listener serves local
and same-network use only. Run the toolkit on a reachable host (the
operator's own VPS/Kali) for real OOB work. The module is deliberately NOT
wired into vulnscan2's blind checks until such a deployment exists —
findings must never depend on callbacks that cannot arrive.
"""
import http.server
import json
import secrets
import socketserver
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional


@dataclass
class Hit:
    token: str
    ts: float
    ip: str
    method: str
    path: str
    user_agent: str = ""


@dataclass
class CanaryRegistry:
    """Token -> label + hits. Thread-safe via a single lock."""
    _tokens: Dict[str, str] = field(default_factory=dict)
    _hits: List[Hit] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def issue(self, label: str = "") -> str:
        tok = secrets.token_hex(8)
        with self._lock:
            self._tokens[tok] = label or tok
        return tok

    def label_of(self, token: str) -> Optional[str]:
        with self._lock:
            return self._tokens.get(token)

    def record(self, hit: Hit) -> None:
        with self._lock:
            self._hits.append(hit)

    def hits(self, token: Optional[str] = None) -> List[dict]:
        with self._lock:
            rows = [h for h in self._hits
                    if token is None or h.token == token]
        return [asdict(h) for h in rows]

    def url(self, base: str, token: str) -> str:
        return base.rstrip("/") + "/" + token


class _Handler(http.server.BaseHTTPRequestHandler):
    registry: CanaryRegistry = None          # disuntik serve()
    server_version = "canary"

    def _handle(self):
        token = self.path.strip("/").split("/")[0].split("?")[0]
        if self.registry is not None and token:
            self.registry.record(Hit(
                token=token, ts=time.time(),
                ip=self.client_address[0] if self.client_address else "",
                method=self.command, path=self.path[:200],
                user_agent=self.headers.get("User-Agent", "")[:120]))
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = _handle
    do_POST = _handle
    do_PUT = _handle
    do_DELETE = _handle
    do_HEAD = _handle

    def log_message(self, *a):                # senyap: log kita sendiri
        pass


class _Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(port: int = 8899, host: str = "0.0.0.0",
          registry: Optional[CanaryRegistry] = None):
    """Start the listener in a background thread -> (server, registry)."""
    reg = registry or CanaryRegistry()
    handler = type("BoundCanaryHandler", (_Handler,), {"registry": reg})
    srv = _Server((host, port), handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True,
                          name="ptk-canary")
    th.start()
    return srv, reg


if __name__ == "__main__":                    # pragma: no cover
    srv, reg = serve()
    tok = reg.issue("selftest")
    print(json.dumps({"listening": srv.server_address, "sample_token": tok}))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
