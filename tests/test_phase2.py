"""Test Fase 2 (v3.17): active pack (UDP probe, cipher TLS, SYN graceful,
vhost enum), job gate, NVD parse, suppression store, fingerprint laporan.

Server uji semuanya lokal & nyata (UDP responder, TLS server, HTTP vhost)
— bukan mock: engine harus membuktikan perilakunya terhadap protokol asli.
"""
import json
import os
import socket
import ssl
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import jobgate
import nvd
import report_common
import scanners
import store


# --------------------------------------------------------------------- UDP --

def _udp_responder(ip, port, mode, stop):
    sk = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sk.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sk.bind((ip, port))
    sk.settimeout(0.3)
    while not stop.is_set():
        try:
            data, addr = sk.recvfrom(2048)
        except socket.timeout:
            continue
        except OSError:
            break
        # balas lewat socket connected: sandbox VM memblokir sendto UDP
        # tak-terhubung ke port ephemeral (EPERM) — server nyata membalas
        # dalam flow yang sama.
        try:
            sk.connect(addr)
        except OSError:
            continue
        if mode == "dns" and len(data) >= 12:
            resp = bytearray(data)
            resp[2] |= 0x80                      # QR=1
            sk.send(bytes(resp))
        elif mode == "snmp":
            sk.send(b"\x30\x26" + b"\x00" * 20)
    sk.close()


def test_udp_probes():
    stop = threading.Event()
    threads = []
    try:
        for port, mode in ((53, "dns"), (161, "snmp")):
            t = threading.Thread(target=_udp_responder,
                                 args=("127.0.0.1", port, mode, stop),
                                 daemon=True)
            t.start()
            threads.append(t)
    except OSError:
        stop.set()
        import pytest
        pytest.skip("tidak bisa bind UDP 53/161 di environment uji")
    try:
        time.sleep(0.2)
        res = scanners.udp_scan("127.0.0.1", ports=[53, 161, 59998],
                                timeout=1.2)
        by_port = {r["port"]: r for r in res["results"]}
        assert by_port[53]["state"] == "open"
        assert by_port[53]["service"] == "dns"
        assert by_port[161]["state"] == "open"
        assert by_port[161]["service"] == "snmp"
        # port mati di localhost: ICMP unreachable -> closed, atau diam ->
        # open|filtered; yang DILARANG adalah klaim 'open'
        assert by_port[59998]["state"] in ("closed", "open|filtered")
        assert res["ambiguous"] is False        # host lokal: tidak ambigu
    finally:
        stop.set()


# --------------------------------------------------------------------- TLS --

def _make_cert(tmp):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime as _dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(1000)
            .not_valid_before(_dt.datetime.now(_dt.timezone.utc))
            .not_valid_after(_dt.datetime.now(_dt.timezone.utc)
                             + _dt.timedelta(days=2))
            .sign(key, hashes.SHA256()))
    cp, kp = os.path.join(tmp, "c.pem"), os.path.join(tmp, "k.pem")
    with open(cp, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(kp, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    return cp, kp


def test_tls_cipher_audit(tmp_path):
    cp, kp = _make_cert(str(tmp_path))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256:AES128-SHA")
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(8)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                ss = ctx.wrap_socket(conn, server_side=True)
                ss.close()
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    try:
        res = scanners.tls_cipher_audit("127.0.0.1", port, timeout=2.0)
        assert res["protocols"]["tls1_2"] is True
        assert res["protocols"]["tls1_0"] is False
        assert res["deprecated"] == []
        assert res["weak"] == []
        assert any(c["protocol"] == "tls1_2" and "GCM" in c["cipher"]
                   for c in res["supported"])
    finally:
        stop.set()
        srv.close()


# --------------------------------------------------------------------- SYN --

def test_syn_graceful():
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(2)
    try:
        res = scanners.syn_scan("127.0.0.1", [port], timeout=1.0)
        assert isinstance(res["available"], bool)
        assert isinstance(res["open"], list)
        if res["available"]:
            assert port in res["open"]
        else:
            # environment memblokir raw (mis. EPERM sandbox): alasan wajib
            # dinyatakan — tidak boleh pura-pura semua filtered
            assert res["reason"]
    finally:
        srv.close()


# ------------------------------------------------------------------- VHOST --

def test_vhost_enum():
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            host = self.headers.get("Host", "")
            if host.startswith("admin."):
                body = b"ADMIN CONSOLE " + b"X" * 400
            else:
                body = b"PUBLIC SITE " + b"Y" * 400
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    httpd = HTTPServer(("127.0.0.1", 0), H)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        res = scanners.vhost_enum(f"http://127.0.0.1:{port}",
                                  candidates=["admin", "www", "dev"])
        interesting = {c["vhost"] for c in res["interesting"]}
        assert any(v.startswith("admin.") for v in interesting), res
        assert not any(v.startswith("www.") for v in interesting)
    finally:
        httpd.shutdown()


# --------------------------------------------------------------- JOB GATE --

def test_job_gate_priority_and_cancel():
    gate = jobgate.JobGate(global_limit=1, user_limit=5)
    assert gate.acquire(user="a") is True          # slot pertama
    granted = []

    def waiter(prio, tag, cancelled=None):
        ok = gate.acquire(priority=prio, user="b", cancelled=cancelled)
        granted.append((tag, ok))

    t_low = threading.Thread(target=waiter, args=(1, "low"))
    t_high = threading.Thread(target=waiter, args=(0, "high"))
    t_low.start()
    time.sleep(0.15)
    t_high.start()
    time.sleep(0.15)
    assert gate.snapshot()["waiting"] == 2
    gate.release("a")
    t_high.join(timeout=3)
    t_low.join(timeout=0.3)
    # prioritas high harus menang walau datang belakangan
    assert granted[0] == ("high", True)
    gate.release("b")
    t_low.join(timeout=3)
    assert granted[1] == ("low", True)
    gate.release("b")
    # jalur cancel: job yang dibatalkan saat menunggu tidak dapat slot
    assert gate.acquire(user="a") is True
    flag = {"c": False}
    t_c = threading.Thread(
        target=waiter, args=(1, "cx", lambda: flag["c"]))
    t_c.start()
    time.sleep(0.15)
    flag["c"] = True
    t_c.join(timeout=3)
    assert ("cx", False) in granted
    gate.release("a")


# -------------------------------------------------------------------- NVD --

def test_nvd_parse():
    data = {"vulnerabilities": [{"cve": {
        "id": "CVE-2099-1234",
        "published": "2099-01-01T00:00:00.000",
        "lastModified": "2099-01-02T00:00:00.000",
        "descriptions": [{"lang": "es", "value": "x"},
                         {"lang": "en", "value": "Example flaw"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-89"}]}],
        "references": [{"url": "https://example.com/advisory"}]}}]}
    rows = nvd.parse_nvd(data)
    assert len(rows) == 1
    r = rows[0]
    assert r["cve_id"] == "CVE-2099-1234"
    assert r["description"] == "Example flaw"
    assert r["cvss"] == 9.8 and r["severity"] == "CRITICAL"
    assert r["weaknesses"] == ["CWE-89"]


# ------------------------------------------------- store: CVE + suppression --

def test_store_cve_and_suppression(tmp_path):
    old = store.DB_PATH
    store.DB_PATH = str(tmp_path / "t.db")
    try:
        store.init_db()
        n = store.cve_upsert([{"cve_id": "CVE-2099-0001",
                               "description": "demo", "cvss": 7.5,
                               "severity": "HIGH"}])
        assert n == 1 and store.cve_stats()["count"] == 1
        assert store.cve_search("2099")[0]["cve_id"] == "CVE-2099-0001"
        sid = store.add_suppression("example.com", "Missing header", "admin")
        assert store.is_suppressed("example.com",
                                   "Missing header: X-Frame-Options")
        assert store.is_suppressed("sub.example.com",
                                   "Missing header: X-Frame-Options")
        assert not store.is_suppressed("other.com",
                                       "Missing header: X-Frame-Options")
        assert not store.is_suppressed("example.com", "Unrelated finding")
        store.delete_suppression(sid)
        assert not store.is_suppressed("example.com",
                                       "Missing header: X-Frame-Options")
    finally:
        store.DB_PATH = old


# ------------------------------------------------------------- fingerprint --

def test_report_fingerprint():
    scan = {"target": "http://x.test", "scan_type": "vulnscan",
            "profile": "active-deep", "started_at": 1.0,
            "findings": [{"title": "T", "severity": "HIGH",
                          "location": "/a"}]}
    h1 = report_common.data_fingerprint(scan)
    assert len(h1) == 64 and h1 == report_common.data_fingerprint(scan)
    scan2 = json.loads(json.dumps(scan))
    scan2["findings"][0]["title"] = "U"
    assert report_common.data_fingerprint(scan2) != h1

def test_nvd_sync_with_stub_fetcher():
    canned = {"vulnerabilities": [{"cve": {
        "id": "CVE-2099-7777", "published": "2099-05-05",
        "lastModified": "2099-05-06",
        "descriptions": [{"lang": "en", "value": "Stub flaw"}],
        "metrics": {}, "weaknesses": [], "references": []}}]}

    def stub(url, timeout=25, verify=True, headers=None):
        return 200, [], json.dumps(canned).encode()

    res = nvd.sync(keywords=["demo"], fetcher=stub)
    assert res["fetched"] == 1 and res["errors"] == []
    assert res["rows"][0]["cve_id"] == "CVE-2099-7777"

    def failing(url, timeout=25, verify=True, headers=None):
        return 0, [], b""

    res2 = nvd.sync(keywords=["demo"], fetcher=failing)
    assert res2["fetched"] == 0 and res2["errors"]   # gagal = dilaporkan
