"""Priority 1 (v1.2.0): XPath injection, exposed web secrets, hidden
parameters, reverse tabnabbing.

Unit tests for the pure logic (signatures, denylist/entropy, masking,
rel tokens, batch/bisect with a fake client) plus integration tests
that run the real check functions against the local fixture server.
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

PORT = 18097


# ------------------------------------------------------------------ units

def test_xpath_signatures_reject_bare_word():
    import vulnscan2 as v
    assert v._xpath_error_in("our docs explain xpath queries in detail", "") == []
    assert v._xpath_error_in("javax.xml.xpath.XPathExpressionException: boom", "")
    assert v._xpath_error_in("XPST0003 static error", "")
    # Signature yang sudah ada di baseline bukan temuan.
    both = "javax.xml.xpath.XPathExpressionException"
    assert v._xpath_error_in(both, both) == []
    assert "xpath" not in v.XPATH_ERRORS


def test_secret_denylist_and_entropy():
    import secretpatterns as sp
    assert sp.is_denied_secret("AKIAIOSFODNN7EXAMPLE")
    assert sp.is_denied_secret("sk_test_4eC39HqLyjWDarjtT1zdp7dc")
    assert sp.is_denied_secret("your-api-key-here")
    assert sp.is_denied_secret("${process.env.API_KEY}")
    assert sp.is_denied_secret("placeholder-value-123")
    assert not sp.is_denied_secret("kX9vR2mQ8zLp4wN7sT3yB6cF1hJ5dG0a")
    assert not sp.is_denied_secret("AKIA7F3K9Q2W8XZPLM4N")
    assert sp.shannon_entropy("aaaaaaaaaaaaaaaa") == 0.0
    assert sp.shannon_entropy("kX9vR2mQ8zLp4wN7sT3yB6cF1hJ5dG0a") >= 3.5


def test_mask_never_leaks_full_secret():
    import secretpatterns as sp
    raw = "AKIA7F3K9Q2W8XZPLM4N"
    masked = sp._mask(raw)
    assert masked == "AKIA***4N"
    assert raw not in masked


def test_rel_tokens_and_tabnab_rules():
    import vulnscan2 as v
    assert v._rel_tokens("NoOpener  noreferrer") == {"noopener", "noreferrer"}
    host = "target.test"
    ext = "https://other.example/page"
    assert v._tabnab_is_vulnerable("_blank", "", ext, host)
    assert v._tabnab_is_vulnerable("_BLANK", None, ext, host)
    assert not v._tabnab_is_vulnerable("_blank", "noopener", ext, host)
    assert not v._tabnab_is_vulnerable("_blank", "noreferrer", ext, host)
    assert not v._tabnab_is_vulnerable("_blank", "", "/local/page", host)
    assert not v._tabnab_is_vulnerable("_blank", "", "https://target.test/x", host)
    assert v._tabnab_is_vulnerable("_blank", "", "//other.example/x", host)
    assert not v._tabnab_is_vulnerable("_self", "", ext, host)
    assert not v._tabnab_is_vulnerable("_blank", "", "javascript:void(0)", host)


def test_tabnab_links_aggregation_parser():
    import vulnscan2 as v
    html = """
    <a href="https://ext.example/a" target="_blank">vuln</a>
    <a href="https://ext.example/b" target="_blank" rel="noopener">safe</a>
    <a href="https://ext.example/c" target="_blank" rel="noreferrer">safe</a>
    <a href="/item?id=1" target="_blank">same-host</a>
    <a href="https://ext.example/d">no target</a>
    """
    hits = v._tabnab_links_in(html, "target.test")
    assert hits == ["https://ext.example/a"], hits


class _FakeResp:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status

    def hdr(self, name):
        return ""


class _FakeSurf:
    def __init__(self, param_urls):
        self.param_urls = param_urls
        self.forms = []
        self.pages = []
        self.js_urls = []
        self.js_endpoints = []
        self.homepage = None


class _FakeCtx:
    def __init__(self, client, param_urls):
        self.client = client
        self.marker = "m4rk3r"
        self.log = []
        self._surf = _FakeSurf(param_urls)

    def L(self, msg):
        self.log.append(msg)

    def cancelled(self):
        return False

    def surface(self, full=True):
        return self._surf

    def is_missing(self, resp):
        return resp.status == 404


class _HiddenFakeClient:
    """Endpoint /x hanya berubah untuk debug & preview; /y tak stabil."""
    host = "fake.test"

    def get(self, url, **kw):
        from urllib.parse import urlparse, parse_qs
        p = urlparse(url)
        q = parse_qs(p.query)
        if p.path == "/y":
            import random
            return _FakeResp(f"<html>rotating {random.random()} banner "
                             f"with a fairly long stable-looking tail of text "
                             f"padding padding padding padding padding</html>")
        body = "<html><title>Lab</title>" + "stable catalogue text. " * 12
        if p.path == "/x" and "debug" in q:
            body += "<pre>DEBUG diagnostics block. " + "x" * 160 + "</pre>"
        if p.path == "/x" and "preview" in q:
            body += "<div>DRAFT PREVIEW block. " + "y" * 140 + "</div>"
        return _FakeResp(body)


def test_hidden_params_bisect_fake_client():
    import vulnscan2 as v
    ctx = _FakeCtx(_HiddenFakeClient(), ["/x?ref=1"])
    finds = []
    v.c_hidden_params(ctx, finds.append)
    assert len(finds) == 1, finds
    f = finds[0]
    assert f["location"] == "/x"
    assert set(x.strip() for x in f["param"].split(",")) == {"debug", "preview"}
    assert f["confidence"] == "probable" and f["severity"] == "LOW"


def test_hidden_params_unstable_endpoint_skipped_fake():
    import vulnscan2 as v
    ctx = _FakeCtx(_HiddenFakeClient(), ["/y?src=1", "/x?ref=1"])
    finds = []
    v.c_hidden_params(ctx, finds.append)
    locs = [f["location"] for f in finds]
    assert "/y" not in locs, finds


def test_hidden_wordlist_shape():
    import vulnscan2 as v
    assert 44 <= len(v.HIDDEN_PARAM_WORDLIST) <= 52
    assert len(set(v.HIDDEN_PARAM_WORDLIST)) == len(v.HIDDEN_PARAM_WORDLIST)
    assert "debug" in v.HIDDEN_PARAM_WORDLIST
    assert "preview" in v.HIDDEN_PARAM_WORDLIST
    assert not any(n.startswith("utm") for n in v.HIDDEN_PARAM_WORDLIST)


# ------------------------------------------------------------ integration

def _wait(port, tries=40):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return True
        except Exception:
            time.sleep(0.25)
    return False


class _Fixture:
    def __enter__(self):
        self.proc = subprocess.Popen(
            [sys.executable, "tests/fixture_vuln_server.py", str(PORT)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        assert _wait(PORT), "fixture priority1 tidak start"
        return self

    def __exit__(self, *a):
        self.proc.terminate()


def _ctx(param_urls=(), pages=(), js_urls=()):
    import vulnscan2
    import crawler as crawl_mod
    ctx = vulnscan2.Ctx(f"http://127.0.0.1:{PORT}", {"timeout": 5}, [])
    surf = crawl_mod.Surface()
    surf.homepage = ctx.client.get("/")
    surf.param_urls = list(param_urls)
    surf.pages = list(pages)
    surf.js_urls = list(js_urls)
    ctx._surf = surf
    ctx._surf_full = True
    return ctx


def test_tabnabbing_integration_aggregated_once():
    import vulnscan2
    with _Fixture():
        ctx = _ctx(pages=["/"])
        finds = []
        vulnscan2.c_tabnabbing(ctx, finds.append)
        assert len(finds) == 1, finds
        f = finds[0]
        assert f["title"].startswith("Reverse tabnabbing: 1 external")
        assert f["severity"] == "LOW" and f["confidence"] == "confirmed"
        assert f["cwe"] == "CWE-1022" and abs(f["cvss"] - 3.7) < 0.01
        assert "implicitly" in f["description"] and "WebView" in f["description"]
        assert "partner-example.org" in f["evidence"]


def test_exposed_secrets_integration_and_masking():
    import vulnscan2
    raw_keys = ["AKIA7F3K9Q2W8XZPLM4N", "sk_live_4eC39HqLyjWDarjtT1zdp7dc",
                "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
                "kX9vR2mQ8zLp4wN7sT3yB6cF1hJ5dG0a"]
    with _Fixture():
        ctx = _ctx(js_urls=["/static/secrets.js", "/static/clean.js"])
        finds = []
        vulnscan2.c_exposed_secrets(ctx, finds.append)
        sec = [f for f in finds if f["location"] == "/static/secrets.js"]
        titles = " | ".join(f["title"] for f in sec)
        assert "AWS Access Key ID exposed" in titles, titles
        assert "Stripe live secret key exposed" in titles, titles
        assert "GitHub token exposed" in titles, titles
        assert any(f["confidence"] == "candidate" for f in sec), sec
        assert all(f["confidence"] in ("probable", "candidate") for f in finds)
        clean = [f for f in finds if f["location"] == "/static/clean.js"]
        assert not clean, clean
        blob = repr(finds)
        for k in raw_keys:
            assert k not in blob, f"secret utuh bocor ke finding: {k}"
        assert "AKIA***4N" in blob


def test_hidden_params_integration():
    import vulnscan2
    with _Fixture():
        ctx = _ctx(param_urls=["/hidden?ref=home"])
        finds = []
        vulnscan2.c_hidden_params(ctx, finds.append)
        assert len(finds) == 1, finds
        assert set(x.strip() for x in finds[0]["param"].split(",")) == \
            {"debug", "preview"}
        ctx2 = _ctx(param_urls=["/safe/hidden?ref=home"])
        finds2 = []
        vulnscan2.c_hidden_params(ctx2, finds2.append)
        assert not finds2, finds2


def test_xpath_integration_error_boolean_safe():
    import vulnscan2
    with _Fixture():
        ctx = _ctx()
        targets = [("/xpath/search", "name", "GET", "/xpath/search?name=Ade"),
                   ("/xpath/blind", "name", "GET", "/xpath/blind?name=Ade"),
                   ("/safe/xpath/search", "name", "GET",
                    "/safe/xpath/search?name=Ade")]
        ctx.param_targets = lambda limit=30: targets
        finds = []
        vulnscan2.c_web_injection(ctx, finds.append)
        xp = [f for f in finds if f["title"].startswith("XPath Injection")]
        by_loc = {}
        for f in xp:
            by_loc.setdefault(f["location"], []).append(f)
        err = by_loc.get("/xpath/search") or []
        assert any(f["confidence"] == "probable" and "error indication" in f["title"]
                   for f in err), xp
        blind = by_loc.get("/xpath/blind") or []
        assert any(f["confidence"] == "confirmed" and "boolean-based" in f["title"]
                   for f in blind), xp
        assert "/safe/xpath/search" not in by_loc, xp
        assert all(f["cwe"] == "CWE-643" for f in xp)


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))
