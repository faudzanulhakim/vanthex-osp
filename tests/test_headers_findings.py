"""Regression tests for the v1.16.0 headers-branch fix.

Before the fix, run_tool_scan's "headers" branch returned "findings": []
unconditionally: missing security headers never became findings (unlike
vulnscan2.c_security_headers, which rates the same response), and an
unreachable target silently looked clean. These tests pin the mirrored
behavior: same titles/severities/CWE/CVSS as c_security_headers, HSTS
only over https, and an INFO inconclusive finding when no response
arrives.
"""
import http.server
import socket
import ssl
import threading

import app2


def _serve(handler_cls, tls_ctx=None):
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if tls_ctx is not None:
        srv.socket = tls_ctx.wrap_socket(srv.socket, server_side=True)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, srv.server_address[1]


def _job():
    return {"log": [], "cancel": False}


class _BareHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


class _AlmostFullHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Strict-Transport-Security", "max-age=63072000")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        # Permissions-Policy deliberately missing.
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def _titles(res):
    return {f["title"]: f for f in res["findings"]}


def test_headers_branch_emits_mirrored_findings_http():
    srv, port = _serve(_BareHandler)
    try:
        res = app2.run_tool_scan({}, f"http://127.0.0.1:{port}/",
                                 "headers", "headers", _job())
    finally:
        srv.shutdown()
    assert res["ok"] is True
    by_title = _titles(res)
    # CSP MEDIUM mirrors c_security_headers; HSTS skipped on plain http.
    csp = by_title["Security header not set: content-security-policy"]
    assert csp["severity"] == "MEDIUM" and csp["cwe"] == "CWE-79"
    assert csp["confidence"] == "confirmed"
    assert "Security header not set: strict-transport-security" not in by_title
    for name in ("x-frame-options", "x-content-type-options",
                 "referrer-policy", "permissions-policy"):
        assert by_title[f"Security header not set: {name}"]["severity"] == "LOW"
    assert len(res["findings"]) == 5
    assert res["summary"] == {"MEDIUM": 1, "LOW": 4}
    assert res["overall_risk"] == "MEDIUM"


def test_headers_branch_single_missing_header():
    srv, port = _serve(_AlmostFullHandler)
    try:
        res = app2.run_tool_scan({}, f"http://127.0.0.1:{port}/",
                                 "headers", "headers", _job())
    finally:
        srv.shutdown()
    assert [f["title"] for f in res["findings"]] == [
        "Security header not set: permissions-policy"]
    assert res["overall_risk"] == "LOW"


def test_headers_branch_unreachable_is_inconclusive_not_clean():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    dead_port = s.getsockname()[1]
    s.close()
    res = app2.run_tool_scan({}, f"http://127.0.0.1:{dead_port}/",
                             "headers", "headers", _job())
    assert res["ok"] is False
    assert len(res["findings"]) == 1
    f0 = res["findings"][0]
    assert f0["severity"] == "INFO"
    assert "inconclusive" in f0["title"].lower()
    assert res["overall_risk"] == "INFO"


def test_headers_branch_hsts_finding_on_https():
    import datetime
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName(
                [x509.DNSName("localhost"),
                 x509.IPAddress(__import__("ipaddress").IPv4Address("127.0.0.1"))]),
                critical=False)
            .sign(key, hashes.SHA256()))
    import tempfile, os
    fd_c, cert_path = tempfile.mkstemp(suffix=".pem")
    fd_k, key_path = tempfile.mkstemp(suffix=".pem")
    with os.fdopen(fd_c, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with os.fdopen(fd_k, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    srv, port = _serve(_BareHandler, tls_ctx=ctx)
    try:
        res = app2.run_tool_scan({}, f"https://127.0.0.1:{port}/",
                                 "headers", "headers", _job())
    finally:
        srv.shutdown()
        os.unlink(cert_path)
        os.unlink(key_path)
    assert res["ok"] is True
    by_title = _titles(res)
    hsts = by_title["Security header not set: strict-transport-security"]
    assert hsts["severity"] == "MEDIUM" and hsts["cwe"] == "CWE-319"
    assert len(res["findings"]) == 6
