"""Kejujuran transport (audit ADE 2026-10-18): http_probe/header_audit/ssl
dulu direct-socket (kena intercept gateway + tebak skema http) — sekarang
lewat klien sadar-proxy / CONNECT. UDP tidak boleh probing IP sintetis."""
import socket
import ssl as _ssl
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import scanners


# ------------------------------------------------------------ _tcp_connect
def _listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    return srv, srv.getsockname()[1]


def test_tcp_connect_direct(monkeypatch):
    for v in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(v, raising=False)
    srv, port = _listener()
    def serve():
        c, _ = srv.accept()
        c.sendall(b"halo")
        c.close()
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    with scanners._tcp_connect("127.0.0.1", port, 3) as s:
        assert s.recv(10) == b"halo"


def test_tcp_connect_via_connect_proxy(monkeypatch):
    # proxy stub: terima CONNECT, balas 200, lalu teruskan byte ke listener echo
    target_srv, tport = _listener()
    seen = {}
    def echo():
        c, _ = target_srv.accept()
        data = c.recv(100)
        c.sendall(b"echo:" + data)
        c.close()
        target_srv.close()
    threading.Thread(target=echo, daemon=True).start()
    proxy_srv, pport = _listener()
    def proxy():
        c, _ = proxy_srv.accept()
        buf = b""
        while b"\r\n\r\n" not in buf:
            buf += c.recv(4096)
        seen["line"] = buf.split(b"\r\n", 1)[0]
        c.sendall(b"HTTP/1.1 200 OK\r\n\r\n")
        upstream = socket.create_connection(("127.0.0.1", tport), timeout=3)
        def pump(a, b):
            try:
                while True:
                    d = a.recv(4096)
                    if not d:
                        break
                    b.sendall(d)
            except OSError:
                pass
        threading.Thread(target=pump, args=(c, upstream), daemon=True).start()
        pump(upstream, c)
        proxy_srv.close()
    threading.Thread(target=proxy, daemon=True).start()
    monkeypatch.setenv("HTTPS_PROXY", f"http://127.0.0.1:{pport}")
    with scanners._tcp_connect("example.com", 443, 3) as s:
        s.sendall(b"ping")
        assert s.recv(100) == b"echo:ping"
    assert seen["line"] == b"CONNECT example.com:443 HTTP/1.1"


# ------------------------------------------------------------ http_probe
class _SpaHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/real-config":
            body = b"UNIQUE-REAL-PATH-CONTENT-1234567890"
            self.send_response(200)
        else:
            body = b"<html><body>SPA-SHELL-0123456789</body></html>"
            self.send_response(200)
        self.send_header("Server", "TestSrv/1.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def spa_server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _SpaHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def test_http_probe_catch_all_marked(spa_server):
    out = scanners.http_probe(spa_server, ["admin", "real-config", "backup"])
    by = {o["path"]: o for o in out}
    assert by["/real-config"]["catch_all"] is False
    assert by["/real-config"]["status"] == 200
    assert by["/admin"]["catch_all"] is True
    assert by["/backup"]["catch_all"] is True
    assert by["/admin"]["server"].startswith("BaseHTTP")


def test_header_audit_via_client(spa_server):
    res = scanners.header_audit(spa_server + "/real-config")
    assert res["ok"] is True and res["status"] == 200
    assert "Strict-Transport-Security" in res["missing"]
    assert 0 <= res["score"] < 100


# ------------------------------------------------------------ udp honesty
def test_udp_scan_inconclusive_on_synthetic(monkeypatch):
    monkeypatch.setattr(scanners, "doh_a", lambda name, timeout=6.0: None)
    def fake_gai(host, *a, **k):
        return [(socket.AF_INET, socket.SOCK_DGRAM, 17, "", ("198.18.51.104", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    res = scanners.udp_scan("example.invalid")
    assert res.get("inconclusive") is True
    assert res["open"] == [] and res["results"] == []


# ------------------------------------------------------------ ssl via tunnel
def _make_tls_server():
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.local")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1001)
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=1))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("test.local")]), False)
            .sign(key, hashes.SHA256()))
    import tempfile, os
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
    open(cp, "wb").write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, "wb").write(key.private_bytes(serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption()))
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    raw, port = _listener()
    def handle(c):
        try:
            c.settimeout(5)
            w = ctx.wrap_socket(c, server_side=True)
            try:
                w.recv(64)
            except Exception:
                pass
            w.close()
        except Exception:
            try:
                c.close()
            except Exception:
                pass
    def serve():
        raw.settimeout(20)
        for _ in range(10):
            try:
                c, _ = raw.accept()
            except OSError:
                break
            threading.Thread(target=handle, args=(c,), daemon=True).start()
    threading.Thread(target=serve, daemon=True).start()
    return port


def test_ssl_audit_local_tls(monkeypatch):
    for v in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        monkeypatch.delenv(v, raising=False)
    port = _make_tls_server()
    res = scanners.ssl_audit("127.0.0.1", port=port, timeout=4)
    assert res["ok"] is True
    assert res["verify_ok"] is False   # self-signed
    assert res["subject"].get("commonName") == "test.local"
    assert res["tls_version"] in ("TLSv1.2", "TLSv1.3")


def _dns_resp(txid=b"\x50\x47", rcode=0, ancount=1):
    import struct as _st
    flags = 0x8180 | rcode
    return _st.pack(">HHHHHH", int.from_bytes(txid, "big"), flags, 1, ancount, 0, 0) + b"\x07example\x03com\x00" + _st.pack(">HH", 1, 1)


def test_udp_dns_response_validation():
    probe = scanners._dns_query_packet()
    assert scanners._udp_response_valid("dns", _dns_resp(), probe) is True
    # bentuk respons 29B yang tadi menipu: header + question, RCODE 5, ANCOUNT 0
    assert scanners._udp_response_valid("dns", _dns_resp(rcode=5, ancount=0), probe) is False
    assert scanners._udp_response_valid("dns", _dns_resp(ancount=0), probe) is True  # NOERROR/NODATA + echo = server DNS asli
    assert scanners._udp_response_valid("dns", _dns_resp(txid=b"\x00\x00"), probe) is False


def test_tcp_connect_loopback_bypasses_proxy(monkeypatch):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")  # proxy mati
    srv, port = _listener()
    def serve():
        c, _ = srv.accept()
        c.sendall(b"langsung")
        c.close()
        srv.close()
    threading.Thread(target=serve, daemon=True).start()
    with scanners._tcp_connect("127.0.0.1", port, 3) as s:
        assert s.recv(20) == b"langsung"
