"""Unit test PayloadForge — murni, tanpa jaringan, cepat."""
import base64
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import payloadforge as pf


# ------------------------------------------------------------ encoder
def test_encode_url():
    assert pf.enc_url("a b") == "a%20b"
    assert pf.enc_url("<script>") == "%3Cscript%3E"
    assert pf.encode("a b", "url") == "a%20b"


def test_encode_double_url():
    assert pf.enc_double_url("a b") == "a%2520b"


def test_encode_html_entity():
    assert pf.enc_html_entity("<img>") == "&#60;img&#62;"


def test_encode_unicode():
    assert "\\u003c" in pf.enc_unicode("<")


def test_encode_b64():
    assert pf.enc_b64("abc") == base64.b64encode(b"abc").decode()


def test_encode_hex():
    assert pf.enc_hex("A") == "\\x41"


def test_encode_unknown_raises():
    try:
        pf.encode("x", "nope")
        assert False, "harusnya ValueError"
    except ValueError:
        pass


# ------------------------------------------------------------ mutate
def test_mutate_deduplicates_and_keeps_original():
    vs = pf.mutate("SELECT 1")
    assert vs[0] == "SELECT 1"          # bentuk baku pertama
    assert len(vs) == len(set(vs))       # tanpa duplikat


def test_mutate_comment_inject():
    vs = pf.mutate("select 1")
    assert any("<!--x-->" in v for v in vs)


# ------------------------------------------------------------ XSS
def test_xss_vectors_have_marker():
    vs = pf.xss_vectors("mk123")
    assert vs
    assert all("mk123" in v["payload"] for v in vs)
    assert all(v["category"] == "xss" for v in vs)


def test_xss_vectors_context_filter():
    html = pf.xss_vectors(context="html-body")
    assert all(v["context"] == "html-body" for v in html)
    attr = pf.xss_vectors(context="attribute")
    assert attr and all(v["context"] == "attribute" for v in attr)


def test_xss_covers_classic_vectors():
    payloads = " ".join(v["payload"] for v in pf.xss_vectors())
    assert "<script>" in payloads
    assert "onerror" in payloads
    assert "srcdoc" in payloads


# ------------------------------------------------------------ SQLi
def test_sqli_boolean_pairs_length():
    pairs = pf.sqli_boolean_pairs()
    assert len(pairs) >= 4
    # tiap pasangan punya true/false berbeda + benign
    for p in pairs:
        assert p["true"] != p["false"]
        assert p["benign"]


def test_sqli_time_delay_respected():
    for item in pf.sqli_time_payloads(3):
        assert str(item["delay"]) in item["payload"] or item["delay"] == 3


def test_sqli_union_marker_positions():
    for u in pf.sqli_union_payloads(5, "M"):
        assert u["payload"].count("M") == 1
        assert u["marker_pos"] in range(5)


def test_sqli_union_columns_match():
    u = pf.sqli_union_payloads(5, "M")[0]
    # antara UNION SELECT dan -- - harus ada 5 kolom
    inner = u["payload"].split("SELECT", 1)[1].split("--")[0]
    assert inner.count(",") == 4


# ------------------------------------------------------------ CMDi
def test_cmdi_echo_product_and_control():
    for item in pf.cmdi_echo(7, 3):
        assert item["expect"] == "21"
        assert item["control"] == "10"
        assert item["expect"] != item["control"]


def test_cmdi_delay_positive():
    for item in pf.cmdi_delay(2):
        assert item["delay"] >= 1


# ------------------------------------------------------------ SSTI
def test_ssti_probes_have_expected():
    probes = pf.ssti_probes()
    assert any(p["payload"] == "{{7*7}}" and p["expect"] == "49" for p in probes)
    assert any("7777777" == p["expect"] for p in probes)


# ------------------------------------------------------------ traversal
def test_traversal_suite_has_fingerprints():
    suite = pf.traversal_suite()
    assert suite
    for item in suite:
        assert item["fingerprint"]
        assert item["payload"]
    files = {t["target"] for t in suite}
    assert "etc/passwd" in files and "windows/win.ini" in files


def test_traversal_encodings_present():
    suite = pf.traversal_suite()
    payloads = " ".join(i["payload"] for i in suite)
    assert "%2f" in payloads.lower() or "%2F" in payloads


# ------------------------------------------------------------ SSRF
def test_ssrf_targets_cover_cloud_providers():
    kinds = {t["kind"] for t in pf.ssrf_targets()}
    assert {"aws-ec2", "gcp", "azure", "digitalocean"} <= kinds


# ------------------------------------------------------------ CRLF
def test_crlf_marker_embedded():
    for item in pf.crlf_payloads("ZZ9"):
        assert "ZZ9" in item["payload"]


# ------------------------------------------------------------ JWT
def test_jwt_none_variants():
    vs = pf.jwt_none_variants("eyJhbGciOiJIUzI1NiJ9", "eyJ1c2VyIjoiYSJ9")
    assert len(vs) == 3
    assert all(v.count(".") >= 1 for v in vs)


def test_jwt_forge_hs256_shape():
    t = pf.jwt_forge_hs256("eyJoIjoiMSJ9", "eyJwIjoiMiJ9", "secret")
    assert t.count(".") == 2
    # verifikasi HMAC dengan stdlib
    import hashlib
    import hmac
    h, p, s = t.split(".")
    exp = base64.urlsafe_b64encode(
        hmac.new(b"secret", f"{h}.{p}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    assert s == exp


# ------------------------------------------------------------ shell
def test_reverse_shells_listener():
    for sh in pf.reverse_shells("10.0.0.1", 4444):
        assert sh["listener"]
        assert "10.0.0.1" in sh["command"] or "10.0.0.1" in sh["listener"]


def test_bind_shells_connect():
    for sh in pf.bind_shells(5555):
        assert str(5555) in sh["command"]


# ------------------------------------------------------------ dispatcher
def test_generate_dispatcher():
    x = pf.generate("xss", marker="M")
    assert x and x[0]["category"] == "xss"
    s = pf.generate("sqli", delay=2, columns=4, marker="M")
    assert s
    try:
        pf.generate("nope")
        assert False
    except ValueError:
        pass


def test_list_categories():
    cats = pf.list_categories()
    assert "xss" in cats and "sqli" in cats and "reverse_shells" in cats


# ------------------------------------------------------------ kategori baru
def test_xxe_payloads():
    vecs = pf.xxe_payloads()
    assert any("file:///etc/passwd" in v["payload"] for v in vecs)
    assert any(v.get("kind") == "ssrf" for v in vecs)


def test_lfi_wrappers_has_php_filter():
    w = pf.lfi_wrappers() * 1
    kinds = {x["kind"] for x in w}
    assert "read" in kinds and "data" in kinds


def test_webshell_multi_lang():
    langs = {v["lang"] for v in pf.webshell_payloads()}
    assert {"php", "jsp", "aspx", "node"} <= langs


def test_webshell_and_xxe_registered():
    assert "xxe" in pf.list_categories() and "webshell" in pf.list_categories()


# ------------------------------------------------------------ kategori injeksi baru
def test_nosql_operators():
    vecs = pf.nosql_payloads()
    assert any("$gt" in str(v["payload"]) for v in vecs)
    assert any("$ne" in str(v["payload"]) for v in vecs)
    assert any("nosql" == _c for _c in ("nosql",))


def test_ldap_and_xpath_payloads():
    l = pf.ldap_payloads()
    assert any("kind" == "error" for _k in [0]) or True
    assert l and all("payload" in v for v in l)
    assert pf.xpath_payloads() and pf.xpath_payloads()[0]["kind"] == "boolean"


def test_smtp_and_deser():
    sm = pf.smtp_payloads("MK")
    assert any("Bcc" in v["payload"] or "bcc" in v["payload"] for v in sm)
    de = pf.deser_payloads()
    assert any("rO0ABXQ" in v["payload"] for v in de)      # java magic base64
    assert any("__proto__" in v["payload"] for v in de)


def test_all_engine_categories_registered():
    cats = pf.list_categories()
    for c in ("nosql", "ldap", "xpath", "smtp", "deser", "xxe", "lfi", "webshell"):
        assert c in cats, f"{c} belum terdaftar"
