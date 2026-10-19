"""Test adopsi stdlib v3.14: robotparser, sitemap XML, HTMLParser,
SimpleCookie, model dataclass, canary socketserver, selectors."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import passive
from model import Confidence, Finding, Origin, Severity, overall_risk


def test_robots_rules_parse():
    txt = ("User-agent: *\nDisallow: /admin/\nDisallow: /api/private\n"
           "Crawl-delay: 5\nSitemap: https://ex.com/sitemap.xml\n")
    r = passive._robots_rules(txt)
    assert r["sitemaps"] == ["https://ex.com/sitemap.xml"]
    assert r["crawl_delay"] == 5
    dis = [p for e in r["entries"] for p in e["disallow"]]
    assert "/admin/" in dis and "/api/private" in dis


def test_sitemap_xml_parse():
    xml = ('<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/'
           'schemas/sitemap/0.9"><url><loc>https://ex.com/a</loc></url>'
           '<url><loc>https://ex.com/b</loc></url></urlset>')
    r = passive._sitemap_urls(xml)
    assert r["count"] == 2 and r["sample"][0] == "https://ex.com/a"
    bad = passive._sitemap_urls("bukan xml <loc>https://ex.com/x</loc>")
    assert bad["count"] == 1          # fallback regex tetap jalan


def test_page_signals_htmlparser():
    html = ('<html><!-- TODO: remove debug password hint -->'
            '<img src="/a.jpg"><img src="b.png"><!-- short --></html>')
    sig = passive._PageSignals(html)
    assert sig.images == ["/a.jpg", "b.png"]
    assert any("TODO" in c for c in sig.comments)


def test_cookie_parse_precision():
    # 'httponly' sebagai VALUE tidak boleh dihitung sebagai flag (kasus yang
    # metode substring lama salah baca); SimpleCookie membedakan atribut.
    from http.cookies import SimpleCookie
    jar = SimpleCookie()
    jar.load("sess=httponly; Path=/")
    morsel = next(iter(jar.values()))
    present = {k.lower() for k in morsel.keys() if morsel[k]}
    assert "httponly" not in present and "path" in present
    jar2 = SimpleCookie()
    jar2.load("sess=abc; HttpOnly; Secure; SameSite=Lax")
    m2 = next(iter(jar2.values()))
    attrs = {k.lower() for k in m2.keys() if m2[k]}
    assert {"httponly", "secure", "samesite"} <= attrs


def test_model_roundtrip():
    f = Finding(severity=Severity.HIGH, title="X", origin=Origin.PASSIVE,
                confidence=Confidence.CANDIDATE, cvss=7.5)
    d = f.to_dict()
    assert d["severity"] == "HIGH" and d["origin"] == "passive"
    back = Finding.from_dict(d)
    assert back == f
    assert overall_risk([{"severity": "LOW"}, d]) == "HIGH"
    assert overall_risk([]) == "CLEAN"


def test_canary_records_hit():
    import http.client
    import canary
    srv, reg = canary.serve(port=0, host="127.0.0.1")
    try:
        port = srv.server_address[1]
        tok = reg.issue("unit-test")
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("GET", f"/{tok}?probe=1",
                     headers={"User-Agent": "canary-test"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        assert resp.status == 200
        hits = reg.hits(tok)
        assert len(hits) == 1 and hits[0]["ip"] == "127.0.0.1"
        assert reg.label_of(tok) == "unit-test"
        assert reg.hits("tidak-ada") == []
    finally:
        srv.shutdown()


def test_selectors_localhost():
    import scanners
    opens = scanners._connect_opens_selectors(
        "127.0.0.1", [59990, 59991], timeout=0.6)
    assert opens == set()             # tidak ada listener -> tidak ada open
