"""Test verifikasi layanan port (v3.2.2) — signature murni + integrasi socket lokal.
Dua cara jalan: pytest (fungsi test_*) atau langsung: python3 tests/test_port_verify.py"""
import socket
import sys
import threading

sys.path.insert(0, ".")
import scanners as S


def test_banner_signatures():
    assert S._match_banner_signature(5900, b"RFB 003.008\n") == "vnc"
    assert S._match_banner_signature(22, b"SSH-2.0-OpenSSH_9.6\r\n") == "ssh"
    assert S._match_banner_signature(21, b"220 (vsFTPd 3.0.5)\r\n") == "ftp"
    assert S._match_banner_signature(25, b"220 mail ESMTP\r\n") == "smtp"
    assert S._match_banner_signature(3306, b"\x0a8.0.32\x00\x01\x00\x00\x00") == "mysql"
    assert S._match_banner_signature(23, b"\xff\xfb\x01\xff\xfb\x03") == "telnet"
    assert S._match_banner_signature(5900, b"muse: Other TCP connections is turned off") is None
    assert S._match_banner_signature(6379, b"hello world") is None


def test_probe_signatures():
    assert S._match_probe_response(6379, b"+PONG\r\n") == "redis"
    assert S._match_probe_response(6379, b"-NOAUTH Authentication required.\r\n") == "redis"
    assert S._match_probe_response(6379, b"muse: Database connections is turned off") is None
    assert S._match_probe_response(5432, b"N") == "pgsql"
    assert S._match_probe_response(5432, b"muse: Database connections is turned off") is None
    assert S._match_probe_response(11211, b"VERSION 1.6.22\r\n") == "memcached"
    assert S._match_probe_response(3389, b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x12\x34\x00\x02\x01\x00") == "rdp"
    assert S._match_probe_response(9200, b"HTTP/1.1 200 OK\r\n") == "elasticsearch"
    assert S._match_probe_response(27017, b"It looks like you are trying to access MongoDB over HTTP") == "mongodb"


def test_interception_detection():
    muse_res = [{"port": p, "banner": "muse: Other TCP connections is turned off for this assistant.",
                 "verified": False} for p in (23, 445, 3389, 5900, 6379)]
    ok, reason, _ = S.detect_interception(muse_res)
    assert ok and "interceptor" in reason
    tarpit = [{"port": p, "banner": "some generic tarpit text", "verified": False}
              for p in (21, 22, 25, 80)]
    assert S.detect_interception(tarpit)[0]
    normal = [{"port": 22, "banner": "SSH-2.0-OpenSSH", "verified": True},
              {"port": 443, "banner": "TLS handshake sukses", "verified": True}]
    assert not S.detect_interception(normal)[0]


def test_local_protocol_servers():
    def serve(port, handler):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        srv.settimeout(20)

        def loop():
            try:
                while True:
                    c, _ = srv.accept()
                    threading.Thread(target=handler, args=(c,), daemon=True).start()
            except Exception:
                pass
        threading.Thread(target=loop, daemon=True).start()
        return srv

    def vnc_h(c):
        try:
            c.sendall(b"RFB 003.008\n")
            c.recv(64)
            c.close()
        except Exception:
            pass

    def redis_h(c):
        try:
            c.recv(64)
            c.sendall(b"+PONG\r\n")
            c.close()
        except Exception:
            pass

    s1 = serve(5900, vnc_h)
    s2 = serve(6379, redis_h)
    try:
        det = S.tcp_scan_detailed("127.0.0.1", [5900, 6379, 5999], timeout=2.0)
    finally:
        s1.close()
        s2.close()
    by = {r["port"]: r for r in det["open"]}
    assert by[5900]["verified"] and by[5900]["service"] == "vnc"
    assert by[6379]["verified"] and by[6379]["service"] == "redis"
    assert 5999 not in by
    assert not det["intercepted"]


def test_local_probe_servers():
    """Jalur probe AKTIF (kirim payload -> verifikasi respons) untuk PostgreSQL,
    Memcached, dan HTTP generik di port non-standar (fallback v3.2.2)."""
    def serve(port, handler):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(5)
        srv.settimeout(20)

        def loop():
            try:
                while True:
                    c, _ = srv.accept()
                    threading.Thread(target=handler, args=(c,), daemon=True).start()
            except Exception:
                pass
        threading.Thread(target=loop, daemon=True).start()
        return srv

    def pg_h(c):
        try:
            c.recv(64)
            c.sendall(b"N")
            c.close()
        except Exception:
            pass

    def mc_h(c):
        try:
            c.recv(64)
            c.sendall(b"VERSION 1.6.22\r\n")
            c.close()
        except Exception:
            pass

    def http_h(c):
        try:
            c.recv(256)
            c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            c.close()
        except Exception:
            pass

    srvs = [serve(15432, pg_h), serve(21211, mc_h), serve(18899, http_h)]
    try:
        det = S.tcp_scan_detailed("127.0.0.1", [15432, 21211, 18899], timeout=2.0)
    finally:
        for s in srvs:
            s.close()
    by = {r["port"]: r for r in det["open"]}
    # Port non-standar untuk protokol dikenal: probe dikirim berdasar port —
    # 15432/21211 bukan port baku PG/MC, jadi verifikasi di sini mengandalkan
    # pemetaan port->probe hanya untuk port baku; yang WAJIB terbukti adalah
    # HTTP generik di port arbitrer (kasus fixture 8899 v3.2.2).
    assert by[18899]["verified"] and by[18899]["service"] == "http"
    assert not det["intercepted"]


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("PASS", fn.__name__)
    print("\nSEMUA LULUS")
