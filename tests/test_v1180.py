"""v1.18.0 — Fase 2 program OSIRIS (service dashboard, globe view).

Design §4, host batch A only (nominatim.openstreetmap.org +
router.project-osrm.org), no CSP change, no AI, no other phase item:
  1. Search places via Nominatim through the fetch daemon, submit-based
     (no autocomplete, per OSMF policy), min 3 chars, max 5 results,
     1 req/s throttle, 24 h query cache; raw coordinates are parsed
     locally by the UI and never sent to a host; "lokasiku" is a
     one-shot browser geolocation (K14), never stored or sent.
  2. Directions via the OSRM demo server through the fetch daemon,
     DRIVE/WALK/BIKE + add stop, 1 req/s throttle, 24 h route cache,
     no stop reorder, no persistence; a straight line is never a route.
Plus ADE's direct order (2026-10-24 19:51 WIB), folded into this
release: DRAW + Drawing Tools removed (see test_v1170.py).
Amended v1.19.0: version lock follows the current release.

Python fetch tests are hermetic: globe_feeds._fetch is monkeypatched,
so no external network is used. Live Nominatim/OSRM proof is a
deployment-time check, not part of this suite.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "templates", "app.html"), encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()

# Amended v1.21.0 (F5): img-src + nowcoast.noaa.gov, frame-src +
# www.youtube-nocookie.com (approved §7/§14.2 diff); the CSP_1150
# name is historical.
CSP_1150 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'")
OSINT_MD5_1160 = "65ec21c31b4aad76aa304fcb411388ae"


def _run_node(js):
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(js)
        path = f.name
    try:
        r = subprocess.run(["node", path], capture_output=True, text=True, timeout=120)
    finally:
        os.unlink(path)
    assert r.returncode == 0, f"node harness failed:\n{r.stdout}\n{r.stderr}"
    return r.stdout


def _coord_fn():
    a = HTML.index("function glParseCoordInput")
    b = HTML.index("\n}\n", a) + 3
    return HTML[a:b]


COORD_BODY = r"""
function eqj(a, b) { if (JSON.stringify(a) !== JSON.stringify(b)) throw new Error("eqj failed: " + JSON.stringify(a) + " vs " + JSON.stringify(b)); }
function ok(v, msg) { if (!v) throw new Error("expected truthy: " + msg); }
eqj(glParseCoordInput("35.6586, 139.7454"), {la: 35.6586, lo: 139.7454});
eqj(glParseCoordInput("51.5074 -0.1278"), {la: 51.5074, lo: -0.1278});
eqj(glParseCoordInput("0, 0"), {la: 0, lo: 0});
eqj(glParseCoordInput("-13.8212, 165.7345"), {la: -13.8212, lo: 165.7345});
eqj(glParseCoordInput("35, 139"), {la: 35, lo: 139});
ok(glParseCoordInput("Eiffel Tower") === null, "place name is not coords");
ok(glParseCoordInput("") === null, "empty");
ok(glParseCoordInput("35.6586") === null, "single number");
ok(glParseCoordInput("91, 0") === null, "lat out of range");
ok(glParseCoordInput("0, 181") === null, "lon out of range");
ok(glParseCoordInput("35.6586, 139.7454, extra") === null, "trailing junk");
ok(glParseCoordInput("abc, def") === null, "non-numeric");
console.log("COORD ALL PASS");
"""


def test_coord_parser_vectors():
    out = _run_node(_coord_fn() + "\n" + COORD_BODY)
    assert "COORD ALL PASS" in out


def test_all_script_blocks_parse():
    js = "const fs=require('fs');const html=fs.readFileSync(%s,'utf8');" % json.dumps(
        os.path.join(ROOT, "templates", "app.html"))
    js += ("const re=/<script>([\\s\\S]*?)<\\/script>/g;let m,n=0;"
           "while((m=re.exec(html))){new Function(m[1]);n++;}"
           "if(n<3) throw new Error('expected >=3 script blocks, got '+n);"
           "console.log('SCRIPTS OK '+n);")
    out = _run_node(js)
    assert "SCRIPTS OK" in out


def _extra_obj(name):
    line = [ln for ln in HTML.split("\n") if ln.startswith("const " + name)][0]
    start = line.index("{")
    depth = 0
    for i, ch in enumerate(line[start:], start):
        if ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return json.loads(line[start:i + 1])
    raise AssertionError(name + " object not parsed")


def test_i18n_extra12_parity():
    obj = _extra_obj("I18N_EXTRA12")
    langs = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh", "ar", "hi"]
    assert sorted(obj.keys()) == sorted(langs)
    keysets = [set(obj[lang].keys()) for lang in langs]
    assert all(ks == keysets[0] for ks in keysets)
    assert len(keysets[0]) == 32, sorted(keysets[0])
    for key in ("Search places", "Directions", "Get route", "Pick on globe",
                "estimate (no live traffic)", "STALE", "Fly to"):
        assert all(obj[lang][key] for lang in langs), key


def test_version_points_are_1200():
    assert '"version": "1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert "Platform v1.25.0 ->" in APP2
    for mod in ("report.py", "docx_report.py"):
        body = open(os.path.join(ROOT, mod), encoding="utf-8").read()
        assert 'VERSION = "1.25.0"' in body, mod
    gf_src = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()
    assert "VANTHEX v1.25.0 — OSINT Globe feed engine" in gf_src
    assert "VANTHEX/1.25.0 (OSINT globe;" in gf_src
    assert '<span class="gl-ver">VANTHEX 1.25.0</span>' in HTML


def test_osint_engine_untouched():
    body = open(os.path.join(ROOT, "osint.py"), "rb").read()
    assert hashlib.md5(body).hexdigest() == OSINT_MD5_1160


def test_csp_unchanged():
    m = re.search(r'send_header\("Content-Security-Policy",\s*(.*?)\)', APP2, re.S)
    assert m, "CSP header block not found"
    served = "".join(re.findall(r'"([^"]*)"', m.group(1)))
    assert served == CSP_1150, served


def test_globe_routes():
    found = sorted(set(re.findall(r"/api/osint/globe/[a-z_]+", APP2)))
    # v1.20.0 adds markets to the v1.19.0 route set.
    # v1.21.0 adds cloudmeta, iss_telemetry, windgrid (Phase 5).
    # v1.23.0 adds recon, fingerprint (TOOLS panel).
    assert found == ["/api/osint/globe/cam", "/api/osint/globe/cloudmeta",
                     "/api/osint/globe/entities",
                     "/api/osint/globe/fingerprint",
                     "/api/osint/globe/github", "/api/osint/globe/iss_telemetry",
                     "/api/osint/globe/launches",
                     "/api/osint/globe/layer", "/api/osint/globe/markets",
                     "/api/osint/globe/news",
                     "/api/osint/globe/recon",
                     "/api/osint/globe/route",
                     "/api/osint/globe/search",
                     "/api/osint/globe/status",
                     "/api/osint/globe/windgrid"], found


def test_search_route_markers_present():
    for marker in (
        '/* v1.18.0 search-route-start */', '/* v1.18.0 search-route-end */',
        'function glParseCoordInput', 'function glSearchToggle',
        'function glRouteToggle', 'function glSearchRouteOverlay',
        'function glRoutePickSet', 'function glSearchFlyTo',
        'function glRouteGo', 'function glRouteOpenWith',
        'data-gt="places"', 'data-gt="route"',
        # v1.15.2 guard: the OSINT-search tab button must not return;
        # the globe place-search rail button is 'places', not 'search'.
        '<div class="gl-search" id="gl-search"',
        '<div class="gl-route" id="gl-route"',
        '/api/osint/globe/search?q=', '/api/osint/globe/route?profile=',
        'navigator.geolocation',
    ):
        assert marker in HTML, marker


def test_hosts_batch_markets():
    # v1.20.0 amends: Fase 4 (MARKETS) hosts join batches A+B;
    # the CoinGecko keyed fallback stays INACTIVE (K15) — its API
    # host must never appear as a fetch target.
    gf_src = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()
    assert "nominatim.openstreetmap.org" in gf_src
    assert "router.project-osrm.org" in gf_src
    for good in ("api.github.com", "ll.thespacedevs.com",
                 "feeds.bbci.co.uk", "www.aljazeera.com", "rss.dw.com",
                 "feeds.npr.org", "www.france24.com",
                 "fred.stlouisfed.org", "api.coinbase.com", "stooq.com"):
        assert good in gf_src, good
    assert "api.coingecko.com" not in gf_src
    assert "api.coingecko.com" not in APP2


def test_no_ai_strings_in_new_code():
    a = HTML.index("/* v1.18.0 search-route-start */")
    b = HTML.index("/* v1.18.0 search-route-end */")
    region = HTML[a:b]
    for bad in ("OpenAI", "assistant", "overview", "All sides"):
        assert bad.lower() not in region.lower(), bad


# ------------------------------------------------------- hermetic fetch tests
class _FakeFetch:
    def __init__(self, status, body):
        self.status = status
        self.body = body
        self.calls = []

    def __call__(self, host, path, timeout=30.0):
        self.calls.append((host, path, timeout))
        return self.status, self.body


def _clear_caches():
    gf._sr_search.clear()
    gf._sr_route.clear()
    gf._sr_throttle.clear()


def test_search_validation_never_fetches(monkeypatch):
    _clear_caches()
    fake = _FakeFetch(200, b"[]")
    monkeypatch.setattr(gf, "_fetch", fake)
    assert gf.search_places("ab")["ok"] is False
    assert gf.search_places("  ")["ok"] is False
    assert gf.search_places("x" * 501)["ok"] is False
    assert fake.calls == []


def test_search_path_parse_and_cache(monkeypatch):
    _clear_caches()
    body = json.dumps([
        {"display_name": "Eiffel Tower, Paris", "lat": "48.8584", "lon": "2.2945"},
        {"display_name": "No lon", "lat": "48.0"},
        {"display_name": "Out of range", "lat": "91.0", "lon": "0.0"},
        {"display_name": "Bad num", "lat": "x", "lon": "y"},
    ]).encode("utf-8")
    fake = _FakeFetch(200, body)
    monkeypatch.setattr(gf, "_fetch", fake)
    r1 = gf.search_places("Eiffel Tower")
    assert r1["ok"] is True
    assert r1["cached"] is False
    assert r1["results"] == [{"display_name": "Eiffel Tower, Paris",
                              "lat": 48.8584, "lon": 2.2945}]
    assert len(fake.calls) == 1
    host, path, _t = fake.calls[0]
    assert host == "nominatim.openstreetmap.org"
    assert "format=jsonv2" in path and "limit=5" in path
    assert "Eiffel%20Tower" in path
    r2 = gf.search_places("Eiffel Tower")
    assert r2["cached"] is True and r2["results"] == r1["results"]
    assert len(fake.calls) == 1  # second call served from cache


def test_search_offline_paths(monkeypatch):
    _clear_caches()

    def boom(host, path, timeout=30.0):
        raise IOError("conn refused")
    monkeypatch.setattr(gf, "_fetch", boom)
    r = gf.search_places("Somewhere Town")
    assert r["ok"] is False and "offline" in r["reason"]
    monkeypatch.setattr(gf, "_fetch", _FakeFetch(500, b""))
    r = gf.search_places("Elsewhere City")
    assert r["ok"] is False and "HTTP 500" in r["reason"]
    monkeypatch.setattr(gf, "_fetch", _FakeFetch(200, b"{not json"))
    r = gf.search_places("Third Place Here")
    assert r["ok"] is False and "unreadable" in r["reason"]


def test_route_validation(monkeypatch):
    _clear_caches()
    fake = _FakeFetch(200, b"{}")
    monkeypatch.setattr(gf, "_fetch", fake)
    assert gf.get_route("bogus", [(0, 0), (1, 1)])["ok"] is False
    assert gf.get_route("driving", [(0, 0)])["ok"] is False
    assert gf.get_route("driving", [(0, 0)] * 11)["ok"] is False
    assert gf.get_route("driving", [(91, 0), (0, 0)])["ok"] is False
    assert gf.get_route("driving", [("x", 0), (0, 0)])["ok"] is False
    assert fake.calls == []


def test_route_path_parse_rounding_and_cache(monkeypatch):
    _clear_caches()
    body = json.dumps({
        "code": "Ok",
        "routes": [{"distance": 12345.6, "duration": 1500.0,
                    "geometry": {"type": "LineString",
                                 "coordinates": [[2.2945, 48.8584],
                                                 [2.30, 48.86]]}}],
    }).encode("utf-8")
    fake = _FakeFetch(200, body)
    monkeypatch.setattr(gf, "_fetch", fake)
    # 7-decimal input must be rounded to 1e-5 in the request + cache key.
    r1 = gf.get_route("driving", [(48.8584151, 2.2945019), (48.86, 2.30)])
    assert r1["ok"] is True and r1["cached"] is False
    assert r1["distance_m"] == 12345.6 and r1["duration_s"] == 1500.0
    assert r1["geometry"]["type"] == "LineString"
    assert r1["waypoints"] == [[48.85842, 2.2945], [48.86, 2.3]]
    host, path, _t = fake.calls[0]
    assert host == "router.project-osrm.org"
    assert path.startswith("/route/v1/driving/")
    assert "geometries=geojson" in path
    assert "2.2945,48.85842" in path  # OSRM order is lon,lat
    r2 = gf.get_route("driving", [(48.8584151, 2.2945019), (48.86, 2.30)])
    assert r2["cached"] is True
    assert len(fake.calls) == 1


def test_route_no_route_and_offline(monkeypatch):
    _clear_caches()
    monkeypatch.setattr(gf, "_fetch", _FakeFetch(
        200, json.dumps({"code": "NoRoute"}).encode("utf-8")))
    r = gf.get_route("foot", [(0, 0), (1, 1)])
    assert r["ok"] is False and r["reason"] == "no route"
    monkeypatch.setattr(gf, "_fetch", _FakeFetch(200, b"{}"))
    r = gf.get_route("foot", [(0, 0), (2, 2)])
    assert r["ok"] is False and r["reason"] == "no route"
    monkeypatch.setattr(gf, "_fetch", _FakeFetch(503, b""))
    r = gf.get_route("foot", [(0, 0), (3, 3)])
    assert r["ok"] is False and "HTTP 503" in r["reason"]


def test_throttle_enforced_per_host(monkeypatch):
    _clear_caches()
    slept = []
    monkeypatch.setattr(time, "sleep", lambda s: slept.append(s))
    gf._sr_throttle["nominatim.openstreetmap.org"] = time.time()
    gf._sr_throttle_wait("nominatim.openstreetmap.org")
    assert len(slept) == 1
    assert 0 < slept[0] <= 1.0
