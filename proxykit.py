"""
ProxyKit v1 — forward proxy HTTP dengan passive-scan live untuk VANTHEX.
OPERATOR-GATED (meneruskan traffic operator).

Proxy HTTP sederhana (bukan MITM TLS): menerima request ber-URI absolut
(GET http://host/path), meneruskannya ke origin, menjalankan check pasif
pada respons (header keamanan, cookie flags, pola secret), dan mencatat
temuan ke findings.jsonl. CONNECT ditolak dengan penjelasan (tanpa
interception TLS — proxy ini untuk lab HTTP dan diagnosa).

    python3 proxykit.py --port 8077 --out ~/proxy-findings.jsonl

Modul: PassiveScanner reusable + unit-testable (scan(resp, url) -> list).
"""
import argparse
import json as _json
import re as _re
import sys
import urllib.request as _u
import urllib.error as _ue
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SECRET_PATTERNS = [
    ("AWS Access Key", _re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Stripe live key", _re.compile(r"sk_live_[0-9a-zA-Z]{16,}")),
    ("GitHub token", _re.compile(r"ghp_[0-9A-Za-z]{30,}")),
    ("Private key block", _re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("Bearer token inline", _re.compile(r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}")),
]


class PassiveScanner:
    """Check pasif pada respons HTTP. scan(resp, url) -> list temuan dict."""

    def scan(self, resp, url):
        out = []
        headers = dict((k.lower(), v) for k, v in (getattr(resp, "headers", None) or []))
        body = getattr(resp, "body", "") or ""
        # 1) header keamanan hilang (untuk HTML)
        ctype = headers.get("content-type", "")
        if "text/html" in ctype:
            missing = [h for h in ("content-security-policy",
                                   "x-content-type-options", "x-frame-options")
                       if h not in headers]
            if missing:
                out.append({"kind": "headers", "severity": "LOW",
                            "title": "Header keamanan hilang: " + ", ".join(missing),
                            "url": url})
        # 2) cookie flags lemah
        for sc in [v for k, v in (getattr(resp, "headers", None) or [])
                   if k.lower() == "set-cookie"]:
            low = sc.lower()
            if "httponly" not in low or "secure" not in low:
                out.append({"kind": "cookie", "severity": "MEDIUM",
                            "title": "Set-Cookie tanpa flag Secure/HttpOnly",
                            "evidence": sc[:100], "url": url})
        # 3) secret di body/header
        blob = body + "\n" + "\n".join(f"{k}: {v}" for k, v in headers.items())
        for name, rx in SECRET_PATTERNS:
            m = rx.search(blob)
            if m:
                out.append({"kind": "secret", "severity": "HIGH",
                            "title": f"Secret terdeteksi di traffic: {name}",
                            "evidence": blob[max(0, m.start() - 10):m.end()][:120],
                            "url": url})
        return out


class _H(BaseHTTPRequestHandler):
    scanner = PassiveScanner()
    out_path = "proxy-findings.jsonl"
    findings = []

    def log_message(self, *a):
        pass

    def _record(self, finds):
        if not finds:
            return
        with open(self.out_path, "a", encoding="utf-8") as fh:
            for f in finds:
                fh.write(_json.dumps(f, ensure_ascii=False) + "\n")
        self.findings.extend(finds)

    def do_GET(self):
        # URI absolut: http://host/path ; relatif tidak didukung (proxy form)
        if not self.path.lower().startswith("http"):
            self.send_error(400, "Proxy ini hanya menerima URI absolut "
                                 "(set browser/curl -x).")
            return
        req = _u.Request(self.path, headers={
            k: v for k, v in self.headers.items()
            if k.lower() not in ("proxy-connection", "connection", "host")})
        try:
            resp = _u.urlopen(req, timeout=10)
            status, body, hdrs = resp.status, resp.read(), resp.headers.items()
        except _ue.HTTPError as e:
            status, body, hdrs = e.code, e.read(), e.headers.items()
        except Exception as e:
            self.send_error(502, f"origin error: {e}")
            return
        self.send_response(status)
        for k, v in hdrs:
            if k.lower() not in ("transfer-encoding", "connection",
                                 "content-length"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        # passive scan on live traffic
        class _R:
            pass
        r = _R()
        r.status, r.body, r.headers = status, body.decode("utf-8", "replace"), list(hdrs)
        self._record(self.scanner.scan(r, self.path))

    def do_CONNECT(self):
        self.send_error(501, "CONNECT (TLS) tidak didukung: proxy ini untuk "
                             "traffic HTTP plaintext. Gunakan untuk lab/diagnosa.")


def main(argv=None):
    ap = argparse.ArgumentParser(description="ProxyKit — forward proxy + passive scan")
    ap.add_argument("--port", type=int, default=8077)
    ap.add_argument("--out", default="proxy-findings.jsonl")
    ns = ap.parse_args(argv)
    _H.out_path = ns.out
    srv = ThreadingHTTPServer(("127.0.0.1", ns.port), _H)
    print(f"[proxykit] listening 127.0.0.1:{ns.port} -> {ns.out}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
