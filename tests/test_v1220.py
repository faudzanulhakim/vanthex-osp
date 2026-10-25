"""v1.22.0 — Fase 6 program OSIRIS (service dashboard, globe view).

Design §8 (rebuild mesin globe WebGL MapLibre) + §9 (batch host) +
§10 (diff CSP) + §13 (gerbang verifikasi), with the §16.10
correction: the terrain diff does NOT apply at F6 (it lands at
v1.25.0) — no terrain, no buildings work in this phase. No AI,
no DRAW, no v1.23.0+ item (TOOLS panel, ARCGIS, REMOTE, §16 gap
items are out of scope here).

What changes: ONLY the renderer. All data plumbing (globe_feeds.py,
daemon, routes, panels, HUD, ticker, alerts, search, route,
markets, space, I18N, ?layers=) is untouched; the old canvas
renderer stays verbatim as glDrawLegacy and is the fallback when
MapLibre is unavailable (script missing, WebGL missing,
constructor throws, worker failure).

Hermetic: no network. The node harness extracts the F6 pure block
verbatim from templates/app.html (same pattern as the v1.21.0
windgrid-pure harness).

BLOCKED GATE (honest, reported to the parent): the MapLibre dist
files themselves (webui/vendor/maplibre/5.24.0/maplibre-gl.js +
.css) cannot be obtained from this VM without contacting a host
outside the §9 batch (unpkg / jsdelivr / npm registry); the
OSIRIS-clone vendor files are Turbopack chunks (256 minified
internal exports, no public Map/Marker/Popup API) and are NOT a
usable library. TestVendorAcquisitionGate fails until the dist
lands; everything else in this file must be green. Deploy is
blocked until the gate passes — no partial v1.22.0 ships.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "templates", "app.html"), encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
MASTER = os.path.abspath(os.path.join(ROOT, "..", "..", "..", "..",
                                     "pentest-toolkit-upgraded"))
MASTER_HTML = ""
if os.path.exists(os.path.join(MASTER, "templates", "app.html")):
    MASTER_HTML = open(os.path.join(MASTER, "templates", "app.html"),
                       encoding="utf-8").read()

CSP_1220 = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
            "https://server.arcgisonline.com https://tilecache.rainviewer.com "
            "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
            "connect-src 'self' https://api.rainviewer.com "
            "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
            "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
            "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
            "frame-src https://www.youtube-nocookie.com; "
            "worker-src 'self' blob:; "
            "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'")

V1220_SUBS = {
    "rain", "clouds", "wind", "wind_particles",
    "flights_all", "flights_commercial", "flights_private", "flights_jets",
    "flights_military", "maritime_static", "maritime_lines", "transit_live",
    "sats_all", "sats_comms", "sats_military", "sats_gnss", "sats_eo",
    "sats_stations", "launches", "cctv", "quakes", "fires", "severe",
    "events_other", "incidents", "gdelt_events", "nuclear", "botnet_c2",
    "malware_urls", "daynight", "entities",
}


def _extract_csp(src):
    m = re.search(r'self\.send_header\("Content-Security-Policy",\s*(.*?)\)',
                  src, re.S)
    assert m, "CSP send_header not found"
    parts = re.findall(r'"([^"]*)"', m.group(1))
    return "".join(parts)


def _hosts(text):
    return set(re.findall(r"https://([A-Za-z0-9.\-]+)", text))


def _adapter_block():
    a = HTML.find("/* v1.22.0 F6 (design")
    b = HTML.find("function glDrawLegacy() {")
    assert a >= 0 and b > a, "F6 adapter block not found"
    return HTML[a:b]


def _pure_block():
    a = HTML.find("/* v1.22.0 F6 pure-start */")
    b = HTML.find("/* v1.22.0 F6 pure-end */")
    assert a >= 0 and b > a, "F6 pure block not found"
    return HTML[a:b]


def test_server_version():
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.21.0"' not in APP2


def test_api_version():
    assert '"version": "1.25.0"' in APP2


def test_csp_verbatim():
    assert _extract_csp(APP2) == CSP_1220


def test_csp_terrain_s3_no_gibs():
    csp = _extract_csp(APP2)
    assert "s3.amazonaws.com" in csp
    assert "terrarium" not in csp
    assert "gibs.earthdata.nasa.gov" not in csp


def test_csp_hosts_within_batch():
    allowed = {
        "server.arcgisonline.com", "tilecache.rainviewer.com",
        "nowcoast.noaa.gov", "tiles.basemaps.cartocdn.com",
        "api.rainviewer.com", "basemaps.cartocdn.com",
        "tiles-a.basemaps.cartocdn.com", "tiles-b.basemaps.cartocdn.com",
        "tiles-c.basemaps.cartocdn.com", "tiles-d.basemaps.cartocdn.com",
        "www.youtube-nocookie.com",
        "s3.amazonaws.com",
    }
    assert _hosts(_extract_csp(APP2)) <= allowed


def test_osint_byte_identical():
    p = os.path.join(ROOT, "osint.py")
    h = hashlib.md5(open(p, "rb").read()).hexdigest()
    assert h == "65ec21c31b4aad76aa304fcb411388ae"


def test_vendor_route_present():
    assert 'path.startswith("/vendor/")' in APP2
    assert "def vendor_file(rel):" in APP2
    assert '"maplibre-gl.js", "maplibre-gl.css", "LICENSE.txt"' in APP2


def test_vendor_file_logic():
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "vendor", "maplibre", "5.24.0"))
        p = os.path.join(td, "vendor", "maplibre", "5.24.0", "maplibre-gl.js")
        with open(p, "wb") as f:
            f.write(b"// fake lib")
        # patch WEBUI_DIR by re-exec with the tmp dir
        m = re.search(r"def vendor_file\(rel\):(.*?)\n\n\ndef ",
                      APP2, re.S)
        src = "def vendor_file(rel):" + m.group(1) + "\n"
        g = {"os": os, "_WEBUI_CTYPES": {".js": "text/javascript",
                                         ".css": "text/css"},
             "WEBUI_DIR": td,
             "_VENDOR_FILES": {"maplibre-gl.js", "maplibre-gl.css",
                                "LICENSE.txt"}}
        exec(compile(src, "vendor_file", "exec"), g)
        fn2 = g["vendor_file"]
        data, ctype = fn2("vendor/maplibre/5.24.0/maplibre-gl.js")
        assert data == b"// fake lib" and ctype == "text/javascript"
        assert fn2("vendor/maplibre/5.24.0/../../secrets.key") is None
        assert fn2("vendor/maplibre/5.24.0/evil.js") is None
        assert fn2("vendor/maplibre/5.24.0/maplibre-gl.js/extra") is None
        assert fn2("vendor/maplibre/5.24.0/maplibre-gl.css") is None  # missing
        assert fn2("assets/index-ac460ghg.js") is None
        assert fn2("vendor/maplibre//maplibre-gl.js") is None


def test_stage_html():
    assert '<div id="gl-map" style="display:none"></div>' in HTML
    assert '<canvas id="gl-wind" style="display:none"></canvas>' in HTML
    assert '#gl-map{ display:block; width:100%; height:560px;' in HTML
    assert '#gl-wind{ position:absolute; inset:0; z-index:2; pointer-events:none; }' in HTML


def test_vendor_tags():
    assert '<link rel="stylesheet" href="/vendor/maplibre/5.24.0/maplibre-gl.css">' in HTML
    assert '<script src="/vendor/maplibre/5.24.0/maplibre-gl.js"></script>' in HTML
    assert "const GL_ML_VERSION = '5.24.0';" in HTML
    assert "const GL_CARTO_STYLE = 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json';" in HTML


def test_render_branch():
    assert HTML.count("function glDrawLegacy() {") == 1
    assert HTML.count("function glDraw() {") == 1
    assert "if (_gl && _gl.mapOn && _gl.map) { glMapRender(); return; }" in HTML
    assert "glMapFallback();" in HTML
    assert "function glMapInit()" in HTML
    assert "function glMapApplyMode()" in HTML
    assert "function glMapRender()" in HTML
    assert "function glMapClick(e)" in HTML
    assert "function glMapFlyTo(la, lo)" in HTML
    assert "function glMapSyncAll()" in HTML
    assert "function glMapEnsureDataLayers()" in HTML


def test_maplibre_api_surface():
    for call in ("setProjection({ type: spec.projection })",
                 "queryRenderedFeatures(", "map.project(", "map.unproject(",
                 "map.easeTo({ center: [lo, la]",
                 "map.setStyle(spec.style === 'sat' ? glMapSatStyle() : GL_CARTO_STYLE)",
                 "attributionControl: false"):
        assert call in HTML, "missing MapLibre call: " + call


def test_modes():
    assert "if (view === 'sat') return { projection: 'globe', style: 'sat' };" in HTML
    assert "if (view === '2d') return { projection: 'mercator', style: 'carto' };" in HTML
    assert "return { projection: 'globe', style: 'carto' };" in HTML


def test_old_renderer_intact():
    for fn in ("function glBindCanvas(canvas) {", "function glGeom() {",
               "function glProject(lat, lon, g) {",
               "function glSubsolar() {", "function glDrawTiles(ctx, g, kind) {",
               "function glDrawNowcoast(ctx, g) {", "function glDrawWind(ctx, g, bud) {",
               "function glDrawGridParts(ctx, g) {", "function glGridPartsStep() {",
               "function glDrawParts(ctx, g) {", "function glNcTileUrl(z, tx, ty, time) {",
               "function glCloudMetaLoad() {", "function glWindGridLoad(cycle, fhour) {",
               "function glLayersParseLayersParam(raw, SUBS) {"):
        assert fn in HTML, "legacy function missing: " + fn
    assert "/* v1.21.0 windgrid-pure-start */" in HTML
    assert "/* v1.21.0 windgrid-pure-end */" in HTML
    assert "global_longwave_imagery_mosaic" in HTML
    assert "fO9e9jnhYK8" in HTML  # Sen video id, unchanged


def test_subs_unchanged():
    m = re.search(r"const GL_SUBS = \{(.*?)\n\};", HTML, re.S)
    assert m, "GL_SUBS not found"
    ids = set(re.findall(r"(\w+): \{ g:", m.group(1)))
    assert ids == V1220_SUBS, "GL_SUBS drift: %s" % (ids ^ V1220_SUBS,)


def test_no_scope_creep_in_adapter():
    ad = _adapter_block()
    # v1.25.0: terrarium/setTerrain/s3 are IN the adapter by design (§16.7).
    assert "gibs.earthdata" not in ad
    assert "gemini" not in ad.lower()
    assert "ai/overview" not in ad
    assert "drawMode" not in ad
    assert "INSIDE THIS SHAPE" not in ad


def test_html_hosts_within_batch_or_master():
    allowed = {
        "server.arcgisonline.com", "tilecache.rainviewer.com",
        "api.rainviewer.com", "nowcoast.noaa.gov",
        "basemaps.cartocdn.com", "tiles.basemaps.cartocdn.com",
        "tiles-a.basemaps.cartocdn.com", "tiles-b.basemaps.cartocdn.com",
        "tiles-c.basemaps.cartocdn.com", "tiles-d.basemaps.cartocdn.com",
        "www.youtube-nocookie.com",
        "s3.amazonaws.com",
        # v1.25.0 click-only exception: the submarine-cables fallback
        # is a user-activated <a href> (never fetched by the app: no
        # fetch/tile/script/img/connect-src, no CSP entry). The gate
        # stays strict for every other host.
        "www.submarinecablemap.com",
    }
    if MASTER_HTML:
        allowed |= _hosts(MASTER_HTML)
    extra = _hosts(HTML) - allowed
    assert not extra, "new hosts in HTML: %s" % (extra,)


class TestVendorAcquisitionGate:
    """BLOCKED GATE: fails until the real MapLibre dist is vendored.
    See the module docstring. These are the ONLY tests allowed to
    fail pre-acquisition."""

    def test_dist_js_present(self):
        p = os.path.join(ROOT, "webui", "vendor", "maplibre", "5.24.0",
                         "maplibre-gl.js")
        assert os.path.exists(p), "maplibre-gl.js not vendored yet"
        data = open(p, "rb").read()
        assert len(data) > 100000, "dist suspiciously small"
        assert b"maplibregl" in data

    def test_dist_css_present(self):
        p = os.path.join(ROOT, "webui", "vendor", "maplibre", "5.24.0",
                         "maplibre-gl.css")
        assert os.path.exists(p), "maplibre-gl.css not vendored yet"
        data = open(p, "rb").read()
        assert len(data) > 1000, "css suspiciously small"
        assert b".maplibregl-map" in data


def _node_harness():
    pure = _pure_block()
    # ?layers= parse + serialize (pure, v1.18.0)
    a = HTML.find("function glLayersParseLayersParam")
    b = HTML.find("function glLayersSerializeLayers")
    assert a >= 0 and b > a
    c = HTML.find("\n}\n", b)
    assert c > b
    layers = HTML[a:c + 3]
    driver = pure + "\n" + layers + r"""
const assert = require('assert');
const approx = (a, b, e) => { assert(Math.abs(a - b) < e, a + ' != ' + b); };
// visc
approx(glMapVisc(0, 0, 0, 0), 1, 1e-9);
approx(glMapVisc(0, 180, 0, 0), -1, 1e-9);
approx(glMapVisc(0, 90, 0, 0), 0, 1e-9);
// mode spec
assert.deepStrictEqual(glMapModeSpec('3d'), { projection: 'globe', style: 'carto' });
assert.deepStrictEqual(glMapModeSpec('2d'), { projection: 'mercator', style: 'carto' });
assert.deepStrictEqual(glMapModeSpec('sat'), { projection: 'globe', style: 'sat' });
assert.deepStrictEqual(glMapModeSpec('bogus'), { projection: 'globe', style: 'carto' });
// nice scale
assert.deepStrictEqual(glMapNiceScale(10), { label: '1000 km', px: 100 });
assert.deepStrictEqual(glMapNiceScale(100), { label: '5000 km', px: 50 });
// night polygon: ray casting in lon/lat space
function inside(pt, poly) {
  const ring = poly.geometry.coordinates[0];
  let ins = false;
  for (let i = 0, j = ring.length - 1; i < ring.length; j = i++) {
    const xi = ring[i][0], yi = ring[i][1], xj = ring[j][0], yj = ring[j][1];
    if (((yi > pt[1]) !== (yj > pt[1])) && (pt[0] < (xj - xi) * (pt[1] - yi) / (yj - yi) + xi)) ins = !ins;
  }
  return ins;
}
let np = glMapNightPolygon({ lat: 20, lon: 0 });
let ring = np.geometry.coordinates[0];
assert(ring.length > 90, 'ring too short');
assert(ring[0][0] === ring[ring.length - 1][0] && ring[0][1] === ring[ring.length - 1][1], 'ring not closed');
ring.forEach(p => { assert(p[0] >= -180 && p[0] <= 180 && p[1] >= -90 && p[1] <= 90, 'vertex out of range'); });
assert(inside([179, -20], np), 'antipode must be in night');
assert(!inside([0, 20], np), 'subsolar point must not be in night');
assert(inside([0, -89], np), 'south pole must be in night (sun north)');
assert(!inside([0, 90], np), 'north pole must not be in night (sun north)');
let np0 = glMapNightPolygon({ lat: 0, lon: 0 });
assert(inside([170, 0], np0), 'midnight meridian must be in night');
assert(!inside([0, 0], np0), 'noon meridian must not be in night');
// points FC: dedup + visibility + quake props + budgets
const S = {
  mode: '3d', clon: 0, clat: 0,
  on: new Set(['flights_all', 'flights_commercial', 'sats_all', 'sats_comms', 'quakes']),
  data: {
    flights_all: { points: [{ la: 0, lo: 0, hex: 'A' }, { la: 0, lo: 10, hex: 'B' }, { la: 0, lo: 20, hex: 'C' }] },
    flights_commercial: { points: [{ la: 0, lo: 0, hex: 'A' }] },
    sats_all: { points: [{ la: 0, lo: 95, norad: 1 }, { la: 0, lo: 80, norad: 2 }, { la: 0, lo: 170, norad: 3 }] },
    sats_comms: { points: [{ la: 0, lo: 80, norad: 2 }] },
    quakes: { points: [{ la: 10, lo: 10, mag: 5.5 }, { la: 10, lo: 20, mag: 3.0 }] },
  },
};
let fc = glMapPointsFC(S, 'flights_all', false);
assert.deepStrictEqual(fc.fc.features.map(f => f.properties.hex), ['B', 'C']);
let fs = glMapPointsFC(S, 'sats_all', false);
assert.strictEqual(fs.fc.features.length, 1, 'sats ring: only the dim one survives');
assert.strictEqual(fs.fc.features[0].properties.dim, 1);
assert.strictEqual(fs.fc.features[0].properties.norad, 1);
let fq = glMapPointsFC(S, 'quakes', false);
assert.strictEqual(fq.fc.features[0].properties.lbl, 'M5.5');
approx(fq.fc.features[0].properties.r, 4.485, 1e-9);
assert.strictEqual(fq.fc.features[0].properties.c, '#EF4444');
assert.strictEqual(fq.fc.features[1].properties.lbl, '');
// lines FC: antimeridian split
let lf = glMapLinesFC([[0, 179, 0, -179], [10, 10, 10, 20]]);
assert.strictEqual(lf.features.length, 3);
assert.deepStrictEqual(lf.features[0].geometry.coordinates, [[179, 0], [180, 0]]);
assert.deepStrictEqual(lf.features[1].geometry.coordinates, [[-180, 0], [-179, 0]]);
// route FC: 6000 -> sampled, endpoints kept
let coords = [];
for (let i = 0; i < 6000; i++) coords.push([i * 0.01, 0]);
let rf = glMapRouteFC(coords);
assert(rf.features[0].geometry.coordinates.length <= 5001);
assert.deepStrictEqual(rf.features[0].geometry.coordinates[0], [0, 0]);
assert.deepStrictEqual(rf.features[0].geometry.coordinates[rf.features[0].geometry.coordinates.length - 1], [59.99, 0]);
// wind FC: dir 0 (FROM north) blows TO south
let wf = glMapWindFC([{ la: 0, lo: 0, dir: 0, spd: 10 }]);
approx(wf.tips.features[0].geometry.coordinates[1], -1.264, 1e-3);
approx(wf.tips.features[0].geometry.coordinates[0], 0, 1e-9);
assert.strictEqual(wf.tips.features[0].properties.spd, 10);
// tri FC: closed polygon
let tf = glMapTriFC([{ la: 0, lo: 0 }]);
assert.strictEqual(tf.features.length, 1);
assert.strictEqual(tf.features[0].geometry.coordinates[0].length, 4);
assert.deepStrictEqual(tf.features[0].geometry.coordinates[0][0], tf.features[0].geometry.coordinates[0][3]);
// tile templates
assert.deepStrictEqual(glMapRainTiles('https://h', '/p'), ['https://h/p/512/{z}/{x}/{y}/2/1_1.png']);
let ct = glMapCloudTiles('2026-10-25T00:00:00Z')[0];
assert(ct.includes('BBOX={bbox-epsg-3857}'), 'cloud template must use bbox-epsg-3857');
assert(ct.includes('global_longwave_imagery_mosaic'));
assert(ct.includes('TIME=2026-10-25T00:00:00Z'));
// ?layers=: leaf + group expansion + unknown ignored + dedup
const SUBS = { quakes: { g: 'hazards' }, flights_commercial: { g: 'flights' }, flights_private: { g: 'flights' } };
assert.deepStrictEqual(glLayersParseLayersParam('quakes,bogus', SUBS), ['quakes']);
assert.deepStrictEqual(glLayersParseLayersParam('flights', SUBS), ['flights_commercial', 'flights_private']);
assert.deepStrictEqual(glLayersParseLayersParam('quakes,quakes', SUBS), ['quakes']);
assert.deepStrictEqual(glLayersParseLayersParam('', SUBS), []);
assert.strictEqual(glLayersSerializeLayers(new Set(['a', 'b'])), 'a,b');
console.log('F6 HARNESS OK');
"""
    with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
        f.write(driver)
        path = f.name
    try:
        r = subprocess.run(["node", path], capture_output=True, text=True,
                           timeout=60)
    finally:
        os.unlink(path)
    assert r.returncode == 0, "node harness failed: " + r.stdout + r.stderr
    assert "F6 HARNESS OK" in r.stdout


def test_node_harness():
    _node_harness()
