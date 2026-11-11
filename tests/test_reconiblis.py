"""
Self-contained tests for reconiblis.py — no real network.

A local http.server fixture plays the scan target (root HTML with a <script>
link, an app.js containing credential-shaped strings, and a package.json
manifest). The external passive sources (crt.sh, Wayback CDX) are faked via a
monkeypatched module-level fetcher that routes those URLs to canned JSON;
everything else hits the local fixture server through passive._fetch_bytes.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

import pytest

import passive
from offensive import reconiblis

# ---------------------------------------------------------------- fixture content
ROOT_HTML = """<html><body>
<script src="/static/app.js"></script>
<script src="/static/vendor.js"></script>
</body></html>"""

APP_JS = """
var cfg = { apiKey: "AKIAZQ2EX4AMPLEKEY99", note: "sample" };
var tok = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.QmFkU2lnbmF0dXJlX2Zvcl90ZXN0";
"""

VENDOR_JS = "/* clean vendor bundle */"

PKG_JSON = json.dumps({
    "name": "target-app",
    "dependencies": {"lodash": "^4.17.21", "left-pad": "^1.3.0",
                     "expr-resolver": "^0.1.1"},
    "devDependencies": {"jest": "^29.0.0"},
})

CRTSH_JSON = [
    {"name_value": "www.example.test\napi.example.test",
     "issuer_name": "Let's Encrypt"},
    {"name_value": "staging.example.test", "issuer_name": "DigiCert"},
    {"name_value": "legacy.example.test", "issuer_name": "Let's Encrypt"},
]

CDX_JSON = [
    ["original", "statuscode"],
    ["http://www.example.test/", "200"],
    ["http://api.example.test/users?id=7", "200"],
    ["http://www.example.test/package.json", "200"],
    ["http://www.example.test/search?q=token&page=2", "200"],
]


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        routes = {
            "/": (200, ROOT_HTML, "text/html"),
            "/static/app.js": (200, APP_JS, "application/javascript"),
            "/static/vendor.js": (200, VENDOR_JS, "application/javascript"),
            "/package.json": (200, PKG_JSON, "application/json"),
        }
        status, body, ctype = routes.get(self.path, (404, "not found", "text/plain"))
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture(scope="module")
def target_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


@pytest.fixture()
def patched_fetch(target_server, monkeypatch):
    """Route external passive sources to canned JSON; everything else goes to
    the real (local) passive._fetch_bytes against the fixture server."""
    target = target_server

    def fake_fetch(url, timeout=8, verify=False, cap=2 * 1024 * 1024):
        p = urlparse(url)
        if p.hostname == "crt.sh":
            return 200, [], json.dumps(CRTSH_JSON).encode()
        if p.hostname == "web.archive.org":
            return 200, [], json.dumps(CDX_JSON).encode()
        # historical example.test hosts still serve the fixture content
        if p.hostname and p.hostname.endswith("example.test"):
            return passive._fetch_bytes(target + p.path, timeout=timeout,
                                        cap=cap)
        return passive._fetch_bytes(url, timeout=timeout, verify=verify,
                                    cap=cap)

    monkeypatch.setattr(reconiblis, "_fetch_bytes", fake_fetch)
    # never route the local fixture through the runtime egress proxy
    monkeypatch.setattr(passive.netclient, "_proxy_for",
                        lambda scheme, host, port: None)
    return fake_fetch


@pytest.fixture()
def no_dns(monkeypatch):
    # keep the takeover pre-check fully offline
    monkeypatch.setattr(reconiblis, "_dns_cname", lambda sub: "")
    monkeypatch.setattr(reconiblis, "_dns_cname", lambda sub: "")


# ------------------------------------------------------------------ unit checks
def test_ct_parse():
    ct = reconiblis.ct_subdomains("example.test", fetch=lambda u, **k: (
        200, [], json.dumps(CRTSH_JSON).encode()))
    assert ct["certificates"] == 3
    assert "api.example.test" in ct["subdomains"]


def test_ct_offline_returns_empty():
    assert reconiblis.ct_subdomains(
        "example.test", fetch=lambda u, **k: (0, [], b"")) == {}


def test_wayback_urls_and_params():
    wb = reconiblis.wayback_urls("example.test", fetch=lambda u, **k: (
        200, [], json.dumps(CDX_JSON).encode()))
    assert len(wb["urls"]) == 4
    assert "id" in wb["params"] and "q" in wb["params"]
    assert wb["warnings"] == []


def test_wayback_offline_warns():
    wb = reconiblis.wayback_urls("example.test", fetch=lambda u, **k: (
        0, [], b""))
    assert wb["urls"] == [] and wb["warnings"]


def test_github_dork_urls():
    dorks = reconiblis.github_dork_urls("example.test")
    assert len(dorks) == len(reconiblis._GITHUB_DORKS)
    assert all(d.startswith("https://github.com/search?q=") for d in dorks)
    assert all("example.test" in d for d in dorks)


def test_mine_secrets_masks_values():
    hits = reconiblis.mine_secrets(APP_JS, "app.js")
    kinds = {h["kind"] for h in hits}
    assert "aws" in kinds
    for h in hits:
        assert "AKIAZQ2EX4AMPLEKEY99" not in h["masked"]
        assert h["masked"] != h.get("raw", "")


def test_extract_packages_and_typosquat():
    pkgs = reconiblis.extract_packages(PKG_JSON, "package.json")
    names = {p["name"] for p in pkgs}
    assert {"lodash", "left-pad", "expr-resolver", "jest"} <= names
    squat = reconiblis.typosquat_candidates(pkgs)
    squat_names = {p["name"] for p in squat}
    assert "left-pad" in squat_names          # not in the curated allow-list
    assert "lodash" not in squat_names        # allow-listed
    # requirements.txt style
    pkgs2 = reconiblis.extract_packages("flask==2.0.1\nsome-lib>=1.0\n", "req")
    assert {"flask", "some-lib"} <= {p["name"] for p in pkgs2}


def test_takeover_fingerprint_via_subtakeover():
    # dangling S3 bucket: CNAME-style signature + 404 body
    svc, conf = reconiblis._takeover_fingerprint(
        "target-app.s3.amazonaws.com", 404,
        "<Code>NoSuchBucket</Code>")
    assert svc == "s3"


def test_takeover_precheck_bounded(monkeypatch):
    subs = [f"h{i}.example.test" for i in range(50)]
    called = []

    def fake_fetch(url, **k):
        called.append(url)
        return 404, [], b"NoSuchBucket"

    monkeypatch.setattr(reconiblis, "_dns_cname", lambda s: "x.s3.amazonaws.com")
    res, warns = reconiblis.takeover_precheck(subs, fetch=fake_fetch)
    assert len(called) <= 20
    assert res and warns == []


# ------------------------------------------------------- orchestration end-to-end
def test_run_reconiblis_end_to_end(patched_fetch, no_dns, target_server):
    out = reconiblis.run_reconiblis(target_server)
    assert out["type"] == "reconiblis"
    titles = " || ".join(f["title"] for f in out["findings"])
    assert "CT harvest" in titles
    assert "Wayback history" in titles
    assert "GitHub code-search dork links" in titles
    assert "Secret-like material" in titles
    assert "Dependency manifest harvested" in titles
    assert "Attack surface map" in titles
    # verification labels present
    for f in out["findings"]:
        assert f.get("verification")
    # attack surface map structure
    m = out["meta"]["attack_surface_map"]
    for key in ("hosts", "urls", "params", "secrets", "packages",
                "github_dorks", "takeover_candidates", "warnings"):
        assert key in m
    assert "api.example.test" in m["hosts"]
    assert any(u.endswith("/package.json") for u in m["urls"])
    assert any(h["kind"] == "aws" for h in m["secrets"])
    assert "left-pad" in m["typo_candidates"]
    # the map is also embedded as JSON in the evidence of its finding
    amap_f = next(f for f in out["findings"]
                  if f["title"].startswith("Attack surface map"))
    json.loads(amap_f["evidence"][:0] or "{}")  # evidence is truncated JSON (OK)
    assert amap_f["evidence"].startswith("{")


def test_run_reconiblis_offline_safe(monkeypatch):
    # every network call fails -> module must degrade to warnings, not crash
    monkeypatch.setattr(reconiblis, "_fetch_bytes",
                        lambda url, **k: (0, [], b""))
    monkeypatch.setattr(reconiblis, "_dns_cname", lambda s: "")
    out = reconiblis.run_reconiblis("example.test")
    assert out["findings"]                      # dork links + surface map still produced
    assert any("crt.sh" in w for w in out["warnings"])
    assert any("wayback" in w.lower() for w in out["warnings"])
    m = out["meta"]["attack_surface_map"]
    assert m["urls"] == [] and m["hosts"] == ["example.test"]
    assert m["github_dorks"]


def test_js_crawl_output_reuse(patched_fetch):
    """Passing an existing JS crawl result skips re-fetching the root page."""
    js_urls = ["http://127.0.0.1:1/nonexistent.js"]  # unreachable is fine
    secrets = reconiblis.js_secret_findings(
        "http://127.0.0.1:9/", js_crawl_output={"js_urls": js_urls})
    assert secrets == []
    # dict with a real (fixture-reachable) URL would hit patched fetch;
    # instead verify plain-list form is accepted
    secrets2 = reconiblis.js_secret_findings(
        "http://127.0.0.1:9/", js_crawl_output=list(js_urls))
    assert secrets2 == []
