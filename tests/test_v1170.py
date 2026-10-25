"""v1.17.0 — Fase 1 program OSIRIS (service dashboard, globe view),
as amended by v1.18.0 (ADE order 2026-10-24 19:51 WIB): items 2 and 3
below were REMOVED in v1.18.0. Amended v1.19.0: version lock follows
the current release; nothing else in this file changes meaning.
What remains of Fase 1 in the tree:
  1. ?layers= URL state (sub-layer ids + group expansion, unknown
     tokens ignored, URL wins for the session without overwriting
     stored settings — layer state is in-memory only).
  2. (REMOVED v1.18.0) DRAW button on Live Alerts cards.
  3. (REMOVED v1.18.0) Drawing Tools (AREA / BOX / RADIUS / PATH +
     "what is inside", pure math shared verbatim with the artifact
     harness).

The pure JS block now holds only the ?layers= helpers, extracted
under node exactly like before; the ?layers= vectors below must match
the artifact harness vectors one for one.
"""

import hashlib
import json
import os
import re
import subprocess
import tempfile

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


def _pure_block():
    a = HTML.index("/* v1.18.0 layers-pure-start */")
    b = HTML.index("/* v1.18.0 layers-pure-end */")
    return HTML[a:b]


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


HARNESS_HEAD = """
const SUBS = {quakes:{g:"hazards"},flights_all:{g:"flights"},flights_commercial:{g:"flights"},
  rain:{g:"weather"},wind:{g:"weather"},daynight:{g:"display"},entities:{g:null}};
function eq(a, b) { if (a !== b) throw new Error("eq failed: " + JSON.stringify(a) + " !== " + JSON.stringify(b)); }
function near(a, b, tol) { if (Math.abs(a - b) > tol) throw new Error("near failed: " + a + " vs " + b + " tol " + tol); }
function ok(v, msg) { if (!v) throw new Error("expected truthy: " + msg); }
function arrEq(a, b) { eq(JSON.stringify(a), JSON.stringify(b)); }
"""

HARNESS_BODY = r"""
// --- ?layers= parsing (the only vectors left from Fase 1) ---
arrEq(glLayersParseLayersParam("flights,quakes,unknown", SUBS),
      ["flights_all", "flights_commercial", "quakes"]);
arrEq(glLayersParseLayersParam("weather", SUBS), ["rain", "wind"]);
arrEq(glLayersParseLayersParam("", SUBS), []);
arrEq(glLayersParseLayersParam("quakes,quakes", SUBS), ["quakes"]);
arrEq(glLayersParseLayersParam("entities", SUBS), ["entities"]);
eq(glLayersSerializeLayers(["a", "b"]), "a,b");
arrEq(glLayersParseLayersParam(glLayersSerializeLayers(
  glLayersParseLayersParam("flights,quakes", SUBS)), SUBS),
  ["flights_all", "flights_commercial", "quakes"]);
console.log("HARNESS ALL PASS");
"""


def _harness_output():
    return _run_node(_pure_block() + "\n" + HARNESS_HEAD + HARNESS_BODY)


def test_pure_block_parses_and_vectors_pass():
    out = _harness_output()
    assert "HARNESS ALL PASS" in out


def test_all_script_blocks_parse():
    js = "const fs=require('fs');const html=fs.readFileSync(%s,'utf8');" % json.dumps(
        os.path.join(ROOT, "templates", "app.html"))
    js += ("const re=/<script>([\\s\\S]*?)<\\/script>/g;let m,n=0;"
           "while((m=re.exec(html))){new Function(m[1]);n++;}"
           "if(n<3) throw new Error('expected >=3 script blocks, got '+n);"
           "console.log('SCRIPTS OK '+n);")
    out = _run_node(js)
    assert "SCRIPTS OK" in out


def test_i18n_extra11_parity():
    # v1.18.0: EXTRA11 shrank to the one surviving key (the ?layers=
    # copy-link label); every DRAW/drawing key was removed with the
    # feature. Parity across languages must still hold exactly.
    line = [ln for ln in HTML.split("\n") if ln.startswith("const I18N_EXTRA11")][0]
    start = line.index("{")
    depth = 0
    for i, ch in enumerate(line[start:], start):
        if ch == "{": depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                obj = json.loads(line[start:i + 1])
                break
    langs = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh", "ar", "hi"]
    assert sorted(obj.keys()) == sorted(langs)
    keysets = [set(obj[lang].keys()) for lang in langs]
    assert all(ks == keysets[0] for ks in keysets)
    assert keysets[0] == {"LINK COPIED"}, keysets[0]
    assert all(obj[lang]["LINK COPIED"] for lang in langs)


def test_version_points_are_1200():
    # Amended v1.20.0, amended v1.21.0: the version lock follows the release.
    assert '"version": "1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert "Platform v1.25.0 ->" in APP2
    for mod in ("report.py", "docx_report.py"):
        body = open(os.path.join(ROOT, mod), encoding="utf-8").read()
        assert 'VERSION = "1.25.0"' in body, mod
    gf = open(os.path.join(ROOT, "globe_feeds.py"), encoding="utf-8").read()
    assert "VANTHEX v1.25.0 — OSINT Globe feed engine" in gf
    assert "VANTHEX/1.25.0 (OSINT globe;" in gf
    assert '<span class="gl-ver">VANTHEX 1.25.0</span>' in HTML


def test_osint_engine_untouched():
    body = open(os.path.join(ROOT, "osint.py"), "rb").read()
    assert hashlib.md5(body).hexdigest() == OSINT_MD5_1160


def test_csp_unchanged():
    # Same extraction shape as test_v1150._csp, then join the string
    # literals the policy is built from (implicit concatenation).
    m = re.search(r'send_header\("Content-Security-Policy",\s*(.*?)\)', APP2, re.S)
    assert m, "CSP header block not found"
    served = "".join(re.findall(r'"([^"]*)"', m.group(1)))
    assert served == CSP_1150, served


def test_globe_routes_current_set():
    # v1.20.0 adds markets to the v1.19.0 route set.
    # v1.21.0 adds cloudmeta, iss_telemetry, windgrid (Phase 5).
    # v1.23.0 adds recon, fingerprint (TOOLS panel).
    found = sorted(set(re.findall(r"/api/osint/globe/[a-z_]+", APP2)))
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


def test_phase1_draw_removed_layers_kept():
    # DRAW + Drawing Tools must be fully gone (ADE order 19:51 WIB);
    # the ?layers= machinery and its copy-link button must survive.
    for marker in (
        '<div class="gl-draw" id="gl-draw"',
        'data-gt="draw-area"', 'data-gt="draw-box"', 'data-gt="draw-radius"',
        'data-gt="draw-path"', 'data-gt="draw-clear"',
        'data-adraw=', 'glDrawOverlay(ctx, g);',
        'if (_gl.draw && _gl.draw.tool) glDrawCanvasClick(e);',
        'function glDrawTool', 'function glDrawCancel', 'function glDrawRenderPanel',
        'function glDrawCanvasClick', 'function glAlertHasDraw',
        'function glShapeInsideScan', 'function glShapeHavKm',
        'glDrawRenderPanel();',
    ):
        assert marker not in HTML, marker
    for marker in (
        'data-gt="copylink"',
        'glLayersParseLayersParam(qs.get(\'layers\'), GL_SUBS)',
        'function glCopyLink', 'function glLayersParseLayersParam',
        'function glLayersSerializeLayers',
    ):
        assert marker in HTML, marker


def test_no_ai_strings_in_new_code():
    a = HTML.index("/* v1.18.0 search-route-start */")
    b = HTML.index("/* v1.18.0 search-route-end */")
    region = HTML[a:b]
    for bad in ("OpenAI", "assistant", "overview", "All sides"):
        assert bad.lower() not in region.lower(), bad


def test_alerts_breaking_not_regressed():
    assert "/* v1.16.0 alerts-pure-start */" in HTML
    assert "function glAlertIsBreaking" in HTML
    assert "mag >= 6.0" in HTML
    assert "/* v1.16.0 Live Alerts end */" in HTML
