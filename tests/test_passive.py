"""Test modul passive recon (v3.13) — fungsi murni + rantai audit."""
import io
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import passive
import store


def test_registrable_domain():
    assert passive._registrable("mail.example.co.id") == "example.co.id"
    assert passive._registrable("a.b.example.com") == "example.com"
    assert passive._registrable("example.com") == "example.com"
    assert passive._registrable("demo.testfire.net") == "testfire.net"
    assert passive._registrable("x.blogspot.co.uk") == "blogspot.co.uk"


def test_parse_crtsh():
    data = [{"name_value": "a.example.com\nb.example.com\n*.example.com",
             "issuer_name": "Let's Encrypt"},
            {"name_value": "a.example.com", "issuer_name": "DigiCert"}]
    r = passive._parse_crtsh(data)
    assert r["certificates"] == 2
    assert r["subdomains"] == ["*.example.com", "a.example.com", "b.example.com"]
    assert set(r["issuers"]) == {"Let's Encrypt", "DigiCert"}


def test_email_auth_findings():
    none = passive._email_auth_findings("example.com", [], [])
    titles = " ".join(f["title"] for f in none)
    assert "No SPF" in titles and "No DMARC" in titles
    assert all(f["origin"] == "passive" for f in none)
    weak = passive._email_auth_findings(
        "example.com", ['"v=spf1 +all"'], ['"v=DMARC1; p=none"'])
    sev = {f["title"][:12]: f["severity"] for f in weak}
    assert any(f["severity"] == "MEDIUM" for f in weak)      # SPF +all
    assert any("monitor-only" in f["title"] for f in weak)   # DMARC p=none
    ok = passive._email_auth_findings(
        "example.com", ['"v=spf1 include:_spf.google.com -all"'],
        ['"v=DMARC1; p=reject"'])
    assert ok == []


def test_fingerprint_and_exif():
    fp = passive._fingerprint(b"icon-bytes")
    assert fp["size"] == 10 and len(fp["sha256"]) == 64 and len(fp["md5"]) == 32
    from PIL import Image
    buf = io.BytesIO()
    im = Image.new("RGB", (8, 8), (10, 20, 30))
    ex = im.getexif()
    ex[271] = "CamTest"      # Make
    ex[272] = "ModelX"       # Model
    im.save(buf, "JPEG", exif=ex)
    got = passive._exif_of(buf.getvalue())
    assert got.get("Make") == "CamTest" and got.get("Model") == "ModelX"
    buf2 = io.BytesIO()
    Image.new("RGB", (4, 4)).save(buf2, "JPEG")
    assert passive._exif_of(buf2.getvalue()) == {}


def test_audit_hash_chain(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "t.db"))
    store.init_db()
    store.audit("alice", "login", "ip=1")
    store.audit("alice", "scan_start", "vulnscan x")
    ok, bad = store.verify_audit_chain()
    assert ok and bad is None
    import sqlite3
    conn = sqlite3.connect(str(tmp_path / "t.db"))
    conn.execute("UPDATE audit_log SET detail='tampered' WHERE id=1")
    conn.commit(); conn.close()
    ok, bad = store.verify_audit_chain()
    assert not ok and bad == 1


def test_dns_error_classification():
    assert passive._dns_error_kind("NoAnswer") == "nodata"
    assert passive._dns_error_kind("NXDOMAIN") == "nodata"
    assert passive._dns_error_kind("NoNameservers") == "failed"
    assert passive._dns_error_kind("Timeout") == "failed"


def test_audit_chain_under_concurrency(tmp_path, monkeypatch):
    import threading as _th
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "c.db"))
    store.init_db()
    def worker(n):
        for i in range(5):
            store.audit(f"user{n}", "login", f"batch {i}")
    threads = [_th.Thread(target=worker, args=(n,)) for n in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    ok, bad = store.verify_audit_chain()
    assert ok and bad is None
