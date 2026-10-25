"""v1.25.0 — 3D Buildings + Terrain (service dashboard, design §16.7).

Scope (ONLY these two items, per §16.8): CARTO-style 3D building
extrusions (zoom 14.5+, globe-3D mode only) and Terrarium DEM terrain
(zoom 10+, exaggeration 1, globe projection only — Mercator disables
it). NO other items, NO AI/OI, NO DRAW, NO REMOTE, NO new routes.

CSP DIFF (the ONLY one, per §16.9): img-src += s3.amazonaws.com.
Raster-dem tiles are loaded by MapLibre as images, so no connect-src
entry and no custom tile protocol are needed (unlike OSIRIS's
osiris-dem:// protocol + fetch loader, VANTHEX uses the direct tile
URL). No live fetch from this VM to S3 is performed by any test.

GATES HONESTLY RECORDED (build verification, 2026-10-25):
- Buildings exist ONLY where the CARTO style carries them: the SAT
  style (Esri raster only) has no 'carto' source, so buildings are
  unavailable in SAT mode (toggle hint CARTO BASEMAP REQUIRED) and
  the 2D Mercator mode keeps the layer hidden so it stays flat
  (hint GLOBE VIEW REQUIRED). Regions without CARTO building data
  render without buildings — never invented ones.
- Terrain offline is a FIRST-ERROR latch by design (spec: "tile DEM
  tak terjangkau"): any terrain-source tile error turns terrain off
  and shows the TERRAIN OFFLINE chip; re-toggling retries. A single
  edge-tile failure therefore also latches — the retry is the toggle.
- Visual proof (extruded skyline, displaced relief, CARTO tiles at
  zoom 14.5+) cannot come from this VM: the audit environment has no
  WebGL and the MapLibre path falls back to canvas. Served-HTML
  markers, the node-harness gate matrix, and the live header/CSP are
  verified; active MapLibre rendering awaits ADE's browser.
- The v1.24.0 "NOT EVALUATED / Not built." DISPLAY placeholders are
  gone: the rows are real toggles now (the old note strings are
  asserted absent).

All tests below are hermetic (no live hosts); the live-server class
only checks the served header, CSP, and served-HTML markers.
"""

import hashlib
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

HTML = open(os.path.join(ROOT, "templates", "app.html"),
             encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
FEEDS = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()

CSP_1250 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com "
            "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com "
            "https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com "
            "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
            "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
            "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; frame-ancestors 'none'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'")

CSP_1240 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com "
            "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com; "
            "connect-src 'self' https://api.rainviewer.com "
            "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
            "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
            "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; frame-ancestors 'none'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'")


# ------------------------------------------------------------ version
def test_version_pins():
    assert '"version": "1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert "VANTHEX 1.25.0" in HTML
    assert "VANTHEX/1.25.0" in FEEDS


def _extract_csps(src):
    out = []
    for m in re.finditer(
            r'self\.send_header\("Content-Security-Policy",\s*(.*?)\)',
            src, re.S):
        parts = re.findall(r'"([^"]*)"', m.group(1))
        out.append("".join(parts))
    return out


def _directives(csp):
    out = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        name, _, rest = part.partition(" ")
        out[name] = rest.split()
    return out


def test_csp_byte_identical_and_single_diff():
    csps = _extract_csps(APP2)
    assert csps, "no CSP send_header found"
    assert len(csps) >= 2, "streaming CSP copy missing"
    assert all(c == CSP_1250 for c in csps)
    # The ONLY diff vs v1.24.0 is img-src += s3.amazonaws.com.
    old, new = _directives(CSP_1240), _directives(CSP_1250)
    assert set(old) == set(new), "directive set changed"
    for name in old:
        if name == "img-src":
            assert new[name] == old[name] + ["https://s3.amazonaws.com"]
        else:
            assert new[name] == old[name], name
    assert "terrarium" not in CSP_1250
    assert "gibs.earthdata.nasa.gov" not in CSP_1250


def test_osint_byte_identical():
    h = hashlib.md5(open(os.path.join(ROOT, "osint.py"), "rb").read())
    assert h.hexdigest() == "65ec21c31b4aad76aa304fcb411388ae"


# ------------------------------------------------------------ terrain config
def test_terrain_source_config():
    assert "const GL_TERRAIN_SRC = 'vx-terrain-dem'" in HTML
    assert ("const GL_TERRAIN_TILES = "
            "['https://s3.amazonaws.com/elevation-tiles-prod/terrarium/{z}/{x}/{y}.png']") in HTML
    assert "const GL_TERRAIN_MIN_ZOOM = 10" in HTML
    assert "encoding: 'terrarium'" in HTML
    assert "tileSize: 256, maxzoom: 10" in HTML
    assert "map.setTerrain({ source: GL_TERRAIN_SRC, exaggeration: 1 })" in HTML
    # No custom tile protocol: direct tile URL only (design §16.7).
    assert "addProtocol" not in HTML
    assert "osiris-dem" not in HTML


def test_buildings_layer_config():
    assert "const GL_BUILDINGS_LAYER = 'vx-3d-buildings'" in HTML
    assert "const GL_BUILDINGS_MIN_ZOOM = 14.5" in HTML
    assert "id: GL_BUILDINGS_LAYER, source: 'carto', 'source-layer': 'building'" in HTML
    assert "type: 'fill-extrusion', minzoom: GL_BUILDINGS_MIN_ZOOM" in HTML
    assert "['get', 'render_height']" in HTML
    assert "['get', 'render_min_height']" in HTML
    # OSIRIS opacity ramp 14.5 -> 0, 15 -> 0.7.
    assert "'fill-extrusion-opacity': ['interpolate', ['linear'], ['zoom']" in HTML


# ------------------------------------------------------------ pure gate matrix (node)
def _pure_block():
    a = HTML.find("/* v1.22.0 F6 pure-start */")
    b = HTML.find("/* v1.22.0 F6 pure-end */")
    assert a >= 0 and b > a, "F6 pure block not found"
    return HTML[a:b]


def test_relief_gate_matrix_node():
    driver = _pure_block() + r"""
const assert = require('assert');
const S = (o) => Object.assign({buildings: false, terrain: false,
  terrainOffline: false, mode: '3d', sat: false, zoom: 3,
  mapOn: true, cartoSource: true}, o);
// buildings: 3D + zoom gate + hints
let r = glReliefState(S({buildings: true, zoom: 15}));
assert.strictEqual(r.buildingsVisible, true); assert.strictEqual(r.buildingsHint, '');
r = glReliefState(S({buildings: true, zoom: 14}));
assert.strictEqual(r.buildingsVisible, false); assert.strictEqual(r.buildingsHint, 'ZOOM IN TO 14.5+');
r = glReliefState(S({buildings: true, zoom: 16, mode: '2d'}));
assert.strictEqual(r.buildingsVisible, false); assert.strictEqual(r.buildingsHint, 'GLOBE VIEW REQUIRED');
r = glReliefState(S({buildings: true, zoom: 16, sat: true}));
assert.strictEqual(r.buildingsVisible, false); assert.strictEqual(r.buildingsHint, 'CARTO BASEMAP REQUIRED');
r = glReliefState(S({buildings: true, zoom: 16, mapOn: false}));
assert.strictEqual(r.buildingsVisible, false); assert.strictEqual(r.buildingsHint, 'MAPLIBRE REQUIRED');
r = glReliefState(S({buildings: false, zoom: 16}));
assert.strictEqual(r.buildingsVisible, false); assert.strictEqual(r.buildingsHint, '');
// terrain: globe projection (3d AND sat) + zoom gate + offline latch
r = glReliefState(S({terrain: true, zoom: 10}));
assert.strictEqual(r.terrainActive, true); assert.strictEqual(r.terrainHint, '');
r = glReliefState(S({terrain: true, zoom: 12, sat: true}));
assert.strictEqual(r.terrainActive, true); assert.strictEqual(r.terrainHint, '');
r = glReliefState(S({terrain: true, zoom: 9}));
assert.strictEqual(r.terrainActive, false); assert.strictEqual(r.terrainHint, 'ZOOM IN TO 10+');
r = glReliefState(S({terrain: true, zoom: 12, mode: '2d'}));
assert.strictEqual(r.terrainActive, false); assert.strictEqual(r.terrainHint, 'GLOBE VIEW REQUIRED');
r = glReliefState(S({terrain: true, zoom: 12, terrainOffline: true}));
assert.strictEqual(r.terrainActive, false); assert.strictEqual(r.terrainOffline, true); assert.strictEqual(r.terrainHint, '');
r = glReliefState(S({terrain: true, zoom: 9, terrainOffline: true}));
assert.strictEqual(r.terrainHint, 'ZOOM IN TO 10+');
r = glReliefState(S({terrain: true, zoom: 12, mapOn: false}));
assert.strictEqual(r.terrainActive, false); assert.strictEqual(r.terrainHint, 'MAPLIBRE REQUIRED');
// boundary values are inclusive
r = glReliefState(S({buildings: true, zoom: 14.5}));
assert.strictEqual(r.buildingsVisible, true);
r = glReliefState(S({terrain: true, zoom: 10}));
assert.strictEqual(r.terrainActive, true);
console.log('RELIEF-MATRIX-OK');
"""
    path = os.path.join(ROOT, "tests", "_v1250_driver.js")
    with open(path, "w", encoding="utf-8") as f:
        f.write(driver)
    try:
        r = subprocess.run(["node", path], capture_output=True, text=True)
    finally:
        os.remove(path)
    assert r.returncode == 0, "node relief matrix failed: " + r.stdout + r.stderr
    assert "RELIEF-MATRIX-OK" in r.stdout


# ------------------------------------------------------------ wiring
def test_display_toggles_and_wiring():
    assert 'data-ctl="buildings"' in HTML
    assert 'data-ctl="terrain"' in HTML
    assert "glMapSyncRelief" in HTML
    # Wired from every path that can change zoom/mode/style.
    assert "glMapSyncRelief();" in HTML
    seg = HTML[HTML.find("function glMapApplyMode"):HTML.find("function glCardHtml")]
    assert "glMapSyncRelief();" in seg
    seg2 = HTML[HTML.find("function glMapEnsureDataLayers"):HTML.find("function glMapSyncRecon")]
    assert "glMapSyncRelief();" in seg2
    # Old NOT EVALUATED placeholders are gone.
    assert "Needs slippy zoom ~14.5" not in HTML
    assert "Needs zoom 10+ terrain tiles" not in HTML
    assert "Not built." not in HTML
    # Buildings pitch reveal on enable (OSIRIS pattern, globe-3D only).
    assert "map.easeTo({ pitch: 50, duration: 1200 })" in HTML
    # Terrain error branch: latch + null + panel refresh, before the
    # generic tile branch (so DEM failures never mark basemap offline).
    err = HTML[HTML.find("map.on('error'"):HTML.find("map.on('click'")]
    assert "sid === GL_TERRAIN_SRC" in err
    assert "terrainOffline = true" in err
    assert "map.setTerrain(null)" in err
    assert err.find("GL_TERRAIN_SRC") < err.find("sid === 'carto'")
    assert 'id="gl-terrain-chip"' in HTML
    # State init: default OFF, never server-persisted.
    assert "buildings: false, terrain: false, terrainOffline: false" in HTML


def _hosts(text):
    return set(re.findall(r"https://([A-Za-z0-9.\-]+)", text))


def test_host_batch_only_s3():
    allowed = {
        "server.arcgisonline.com", "tilecache.rainviewer.com",
        "api.rainviewer.com", "nowcoast.noaa.gov",
        "basemaps.cartocdn.com", "tiles.basemaps.cartocdn.com",
        "tiles-a.basemaps.cartocdn.com", "tiles-b.basemaps.cartocdn.com",
        "tiles-c.basemaps.cartocdn.com", "tiles-d.basemaps.cartocdn.com",
        "www.youtube-nocookie.com", "www.submarinecablemap.com",
        # v1.25.0 browser-direct tile host (§16.9).
        "s3.amazonaws.com",
        # Pre-existing non-fetched strings (never a fetch/tile/script
        # src by the app): a click-only SOURCE link, input
        # placeholders for user-typed targets/webhooks.
        "www.youtube.com", "webhook.site",
        "target.example.com", "target.company.co.id",
        "app1.company.com", "app2.company.com",
    }
    assert _hosts(HTML) <= allowed, _hosts(HTML) - allowed
    assert "s3.amazonaws.com" in _hosts(HTML)


def test_scope_guard_no_new_routes_no_ai_draw_remote():
    gts = sorted(set(v for v in
                     re.findall(r'data-gt="([^"]+)"', HTML)
                     if "+" not in v and "'" not in v))
    assert gts == ["arcgis", "copylink", "labels", "markets", "places",
                   "reset", "route", "space", "studio", "tools"]
    assert "drawMode" not in HTML
    assert "gemini" not in HTML.lower()
    assert "ai/overview" not in HTML
    assert "INSIDE THIS SHAPE" not in HTML
    assert "maraude" not in HTML.lower()


# ------------------------------------------------------------ I18N
def test_extra18():
    m = re.search(r"const I18N_EXTRA18 = (\{.*?\});\nfor", HTML, re.S)
    assert m, "EXTRA18 block missing"
    obj = json.loads(m.group(1))
    assert set(obj.keys()) == {"id", "es", "fr", "de", "pt", "ru", "ja",
                               "ko", "zh", "ar", "hi"}
    keysets = [set(d.keys()) for d in obj.values()]
    assert all(ks == keysets[0] for ks in keysets)
    assert len(keysets[0]) == 8
    for k in ["3D BUILDINGS", "3D TERRAIN", "ZOOM IN TO 14.5+",
              "ZOOM IN TO 10+", "GLOBE VIEW REQUIRED",
              "CARTO BASEMAP REQUIRED", "MAPLIBRE REQUIRED",
              "TERRAIN OFFLINE"]:
        assert k in keysets[0], k
    assert ("Object.assign(I18N[_lang] || {}, I18N_EXTRA18[_lang])"
            in HTML)


# ------------------------------------------------------------ live
class TestLiveServer:
    PORT = None
    PROC = None
    COOKIE = None

    @classmethod
    def _free_port(cls):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        p = s.getsockname()[1]
        s.close()
        return p

    @classmethod
    def setup_class(cls):
        import store as _store
        _store.init_db()
        try:
            _store.create_user("v1250test", "v1250testpw", "admin")
        except Exception:
            pass
        cls.PORT = cls._free_port()
        env = dict(os.environ)
        env["PTK_ADMIN_PW"] = "unused-in-this-test"
        cls.PROC = subprocess.Popen(
            [sys.executable, os.path.join(ROOT, "app2.py"),
             str(cls.PORT)],
            cwd=ROOT, env=env, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(
                        "http://127.0.0.1:%d/login" % cls.PORT,
                        timeout=5) as r:
                    assert r.status == 200
                    break
            except Exception:
                if cls.PROC.poll() is not None:
                    raise AssertionError("test server exited early")
                time.sleep(1)
        else:
            raise AssertionError("test server did not come up")
        req = urllib.request.Request(
            "http://127.0.0.1:%d/api/login" % cls.PORT,
            data=json.dumps({"username": "v1250test",
                             "password": "v1250testpw"}).encode(),
            headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            assert r.status == 200
            cls.COOKIE = r.headers.get("Set-Cookie", "").split(";")[0]

    @classmethod
    def teardown_class(cls):
        if cls.PROC is not None:
            cls.PROC.terminate()
            try:
                cls.PROC.wait(timeout=10)
            except Exception:
                cls.PROC.kill()

    def _get(self, path, authed=True):
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.PORT, path))
        if authed and self.COOKIE:
            req.add_header("Cookie", self.COOKIE)
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def test_live_header_csp_and_markers(self):
        st, headers, _body = self._get("/login", authed=False)
        assert st == 200
        assert headers.get("Server", "").startswith("VANTHEX/1.25.0")
        assert headers.get("Content-Security-Policy") == CSP_1250
        st, _h, body = self._get("/classic")
        assert st == 200
        html = body.decode("utf-8", "replace")
        for marker in ['data-ctl="buildings"', 'data-ctl="terrain"',
                       "vx-terrain-dem", "vx-3d-buildings",
                       "glMapSyncRelief", "glReliefState",
                       "elevation-tiles-prod/terrarium",
                       "VANTHEX 1.25.0"]:
            assert marker in html, marker
