"""v1.2.1 parity suite — service dashboard 1:1 with the artifact.

Covers the six items ADE ordered 2026-10-25 20:20 WIB, all in
templates/app.html (service globe dashboard) only:

  1. CARD RAIL (artifact 16:18) — 7 rail features as floating
     cards, one at a time.
  2. POLES (artifact 16:11) — close-button styles, STUDIO rhythm,
     WEI chip, SEARCH results height, SURVEILLANCE label.
  3. SAT-GLOBE (artifact 16:30) — SAT renders as a globe in every
     service render path (quad-mesh warp + limb mask + terminator).
  4. LIVE-REFRESH (artifact 16:58) — 30 s tick, static TTL-None
     never re-fetched, markets at init + tick, wind grid on tick.
  5. GLASS UI (artifact 17:57) — frosted glass, 28px stage,
     pill controls, spring entry, reduced-motion respect.
  6. DEEP ZOOM SAT (artifact 18:08/18:21) — MapLibre SAT maxZoom
     19 + Esri maxzoom 19; fallback regional mosaic to z19,
     SAT zoom clamp 65536x, sub-100 km scale bar to 0.01 km.

Plus release invariants: version stays 1.2.1, osint.py byte-
identical (MD5 65ec21c31b4aad76aa304fcb411388ae), no new hosts,
no DRAW re-added, no app2.py change, all inline <script> blocks
parse under node, and node-evaluated pure functions (mosaic
planner, mosaic mapping, disc projection roundtrip, scale labels,
zoom caps) behave numerically.

Hermetic: reads files from this tree only; node is used to eval
extracted pure functions (no DOM, no service, no network).
"""
import hashlib
import json
import os
import re
import subprocess
import sys

import pytest

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = os.path.join(TREE, "templates", "app.html")
APP2 = os.path.join(TREE, "app2.py")
OSINT = os.path.join(TREE, "osint.py")
MASTER_APP2 = "/home/hatch/workspace/pentest-toolkit-upgraded/app2.py"

OSINT_MD5 = "65ec21c31b4aad76aa304fcb411388ae"


def read_html():
    with open(HTML, encoding="utf-8") as fh:
        return fh.read()


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def extract_fn(src, name):
    """Extract a top-level `function name(...) {...}` by brace counting."""
    m = re.search(r"(?m)^function %s\(" % re.escape(name), src)
    assert m, "function %s not found" % name
    i = src.index("{", m.end())
    depth = 0
    for j in range(i, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[m.start(): j + 1]
    raise AssertionError("unbalanced braces in %s" % name)


def node_eval(prelude, expr):
    """Run `expr` (JS expression) with `prelude` JS in node; return JSON."""
    script = prelude + "\nconsole.log(JSON.stringify(" + expr + "));\n"
    r = subprocess.run(
        ["node", "-e", script], capture_output=True, text=True, timeout=60
    )
    assert r.returncode == 0, "node failed: %s" % r.stderr[:500]
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def html():
    return read_html()


@pytest.fixture(scope="module")
def pure():
    """Node prelude with the pure globe helpers extracted from app.html."""
    src = read_html()
    fns = ["glSatMosaicPlan", "glSatMosaicXY", "glSatMercY", "glSatMercLat",
           "glScaleLabelKm", "glMapNiceScale", "glProject", "glUnproject",
           "glSetZoom", "glSetMode"]
    out = ["const _D2R = Math.PI / 180;"]
    m = re.search(r"const GL_SAT_MERC_LAT = [^;]+;", src)
    assert m, "GL_SAT_MERC_LAT const not found"
    out.append(m.group(0))
    for fn in fns:
        out.append(extract_fn(src, fn))
    # glSetMode touches the DOM; stub the pieces it reads/writes.
    out.append(
        "var _gl = { mode: '3d', sat: false, zoom: 1, clon: 0, clat: 0,"
        "  mapOn: false, map: null, on: new Set(), auto: false,"
        "  geom: { w: 800, h: 560, cx: 400, cy: 280, R: 257.6 } };"
        "var document = { getElementById: () => ({ classList: { toggle: () => {} },"
        "  style: {}, textContent: '' }) };"
        "function glSaveView() {} function glMapApplyMode() {} function glSaveUrl() {}"
        "function glStudioHtml() { return ''; } function glStudioBind() {}"
        "function glReliefState() { return {}; } function glRenderPanel() {}"
        "function glDraw() {} function glFetchStatus() {} function glAlertsRender() {}"
    )
    return "\n".join(out)


# ---------------------------------------------------------------- invariants
def test_version_stays_1_2_1(html):
    assert "1.2.1" in html
    assert "VANTHEX/1.2.1" in open(APP2, encoding="utf-8").read()
    # No 1.26.0 / 1.27.0 / 1.28.0 version string anywhere near the badge.
    assert "VANTHEX/1.26" not in open(APP2, encoding="utf-8").read()


def test_osint_byte_identical():
    assert md5(OSINT) == OSINT_MD5


def test_app2_untouched_vs_master():
    # Parity touches templates/app.html + this suite only.
    if not os.path.exists(MASTER_APP2):
        pytest.skip("master tree not present")
    assert md5(APP2) == md5(MASTER_APP2)


def test_no_new_hosts(html):
    for host in ("aisstream", "wsdot", "511on", "toronto.ca"):
        assert host not in html.lower()
    # Esri literal appears exactly twice: the tile URL list + the
    # legacy radar-style tile URL builder (glSatEsriUrl reuses the list).
    assert html.count("server.arcgisonline.com") == 2


def test_no_draw_readded(html):
    assert 'data-gt="draw"' not in html
    assert "Drawing Tools" not in html


def test_inline_scripts_parse():
    src = read_html()
    blocks = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", src, re.S)
    assert len(blocks) >= 2
    for i, b in enumerate(blocks):
        p = "/tmp/v121parity-script-%d.js" % i
        with open(p, "w", encoding="utf-8") as fh:
            fh.write(b)
        r = subprocess.run(["node", "--check", p], capture_output=True, text=True)
        assert r.returncode == 0, "script block %d parse error: %s" % (i, r.stderr[:400])


# ---------------------------------------------------------------- item 1: cards
def test_card_rail(html):
    for box in ("gl-search", "gl-route", "gl-recon", "gl-arcgis",
                "gl-markets", "gl-space", "gl-studio"):
        assert "glCardCloseOthers('%s')" % box in html
    assert "GL_CARD_BOXES" in html
    card = html[html.index("vanthex-globe-parity-121"):]
    assert "position:absolute" in card.replace(" ", "") or "position: absolute" in card
    assert "right:70px" in card.replace(" ", "")
    assert "border-radius:22px" in card.replace(" ", "")
    assert "backdrop-filter" in card and "24px" in card and "180%" in card
    assert "glCardIn" in card
    assert "prefers-reduced-motion" in card


# ---------------------------------------------------------------- item 2: poles
def test_poles(html):
    s = html.replace(" ", "")
    # Rail small labels: tracking 0em, hidden at small widths
    # (service media query at 820px covers the artifact's <=480px).
    assert "letter-spacing:0em" in s
    assert ".gl-railbuttonsmall,.gl-toolsbuttonsmall{display:none;}" in s
    assert "max-height:340px" in s  # SEARCH results area
    assert "padding:3px10px" in s  # WEI chip unified vertical padding
    assert "border:1pxsolid#22384D" in s  # MARKETS + SPACE close bordered
    assert "font-size:14px" in s and "padding:2px4px" in s  # card/help close
    assert ".gl-st-head{display:flex" in s and "gap:8px" in s  # STUDIO head
    assert ".gl-st-row{display:flex" in s and "padding:4px0" in s  # STUDIO rows


# ---------------------------------------------------------------- item 3: SAT-globe
def test_sat_is_globe_not_flat(html):
    assert "_gl.mode = '3d'; _gl.sat = true" in html
    assert "mode === '2d' && _gl.sat" not in html
    assert "glDrawSatGlobe(ctx, g)" in html
    assert "function glSatMosaicPlan" in html
    assert "function glSatWarpQuads" in html
    assert "function glSatLimbMask" in html
    assert "function glDrawSatGlobe" in html
    # Terminator floor 0.45 -> night overlay alpha 0.55.
    assert "rgba(2,6,18,0.55)" in html or "rgba(2,6,18,' + a" in html
    # Dot substrate still present after the SAT branch (never blank).
    i = html.index("glDrawSatGlobe(ctx, g)")
    assert "dot substrate" in html[i: i + 4000]
    # Note text reworded from flat to globe.
    assert "drawn on the globe" in html
    assert "drawn in 2D" not in html


def test_mosaic_planner(pure):
    g = node_eval(pure, "glSatMosaicPlan(1, 0, 0, 800, 560, false)")
    assert g["z"] == 3 and g["lon0"] == -180 and g["lon1"] == 180
    d = node_eval(pure, "glSatMosaicPlan(2, 0, 0, 800, 560, false)")
    assert d["z"] == 4  # desktop zoom > 1.5: z3 -> z4
    m = node_eval(pure, "glSatMosaicPlan(1, 0, 0, 400, 300, true)")
    assert m["z"] == 3  # mobile stays z3
    r = node_eval(pure, "glSatMosaicPlan(10, 106.8, -6.2, 800, 560, false)")
    assert r["z"] == 6  # round(3 + log2(10)) = 6
    assert r["lon0"] < 106.8 < r["lon1"] and r["lat0"] < -6.2 < r["lat1"]
    z = node_eval(pure, "glSatMosaicPlan(65536, 106.8, -6.2, 800, 560, false)")
    assert z["z"] == 19  # deep zoom: regional mosaic to z19
    # Tile-count cap: 256 at most for every probed zoom.
    tiles = node_eval(
        pure,
        "(function(){ let bad = 0; [5,8,16,64,256,4096,65536].forEach(z => {"
        " const p = glSatMosaicPlan(z, -74, 40.7, 800, 560, false);"
        " const n = Math.pow(2, p.z);"
        " const tx = Math.ceil((p.lon1 - p.lon0) / 360 * n);"
        " const ty = Math.ceil((glSatMercY(p.lat1) - glSatMercY(p.lat0)) / (2 * Math.PI) * n);"
        " if (tx * ty > 256) bad++; }); return bad; })()")
    assert tiles == 0


def test_mosaic_mapping(pure):
    mos = ("{lon0: -180, lon1: 180, lat0: -85.05112878, lat1: 85.05112878,"
           " w: 2048, h: 2048}")
    corners = node_eval(
        pure,
        "[glSatMosaicXY(-180, 85.05112878, %s), glSatMosaicXY(179, -85.05112878, %s),"
        " glSatMosaicXY(0, 0, %s)]" % (mos, mos, mos))
    assert abs(corners[0][0]) < 1e-6 and abs(corners[0][1]) < 1e-6
    # lon 179 (near the eastern seam) maps near the right edge.
    assert abs(corners[1][0] - 2048 * 359 / 360) < 1 and abs(corners[1][1] - 2048) < 1e-6
    assert abs(corners[2][0] - 1024) < 1e-6 and abs(corners[2][1] - 1024) < 1e-6
    # Antimeridian seam: lon 180 wraps to lon -180 on a world plan.
    seam = node_eval(
        pure,
        "[glSatMosaicXY(180, 0, %s), glSatMosaicXY(-180, 0, %s)]" % (mos, mos))
    assert abs(seam[0][0] - seam[1][0]) < 1e-6


def test_disc_projection_roundtrip(pure):
    """glProject/glUnproject roundtrip over the front hemisphere
    (mirrors the artifact's 2,309-point warp verification)."""
    out = node_eval(
        pure,
        "(function(){ const g = { w: 800, h: 560, cx: 400, cy: 280, R: 257.6 };"
        " let max = 0, n = 0;"
        " for (let la = -80; la <= 80; la += 2) for (let lo = -180; lo < 180; lo += 2) {"
        "   _gl.clon = 0; _gl.clat = 0;"
        "   const p = glProject(la, lo, g);"
        "   if (p[2] <= 0.05) continue;"
        "   const back = glUnproject(p[0], p[1], g); if (!back) continue;"
        "   max = Math.max(max, Math.abs(back[0] - la), Math.abs(back[1] - lo)); n++; }"
        " return { n, max }; })()")
    assert out["n"] > 2000
    assert out["max"] < 1e-6


# ---------------------------------------------------------------- item 4: live-refresh
def test_live_refresh(html):
    i = html.index("function glTick()")
    tick = html[i: i + 6000]
    assert "m.ttl_s == null" in tick  # static families skipped
    assert "glMarketsFetch()" in tick
    assert "windGridAt" in tick and "glWindGridLoad" in tick
    j = html.index("function globeInit()")
    init = html[j: j + 4000]
    assert "glMarketsFetch()" in init


# ---------------------------------------------------------------- item 5: glass
def test_glass(html):
    card = html[html.index("vanthex-globe-parity-121"):]
    s = card.replace(" ", "")
    assert "border-radius:28px" in s  # stage
    assert "blur(18px)" in s  # HUD + rails
    assert "blur(var(--gl-blur,24px))" in s  # cards / panels
    assert "saturate(180%)" in s
    assert "inset" in s and "rgba(255,255,255" in s  # specular highlight
    assert "border-radius:999px" in s  # pills
    assert "@keyframesglCardIn" in s
    assert "prefers-reduced-motion" in s


# ---------------------------------------------------------------- item 6: deep zoom
def test_deep_zoom_maplibre(html):
    assert "maxZoom: view === 'sat' ? 19 : 18" in html
    assert "map.setMaxZoom(view === 'sat' ? 19 : 18)" in html
    assert "maxzoom: 19" in html
    assert "const f = _gl.sat ? 1.25 : 1.12" in html  # wheel step
    assert "glSetZoom(_gl.zoom * (_gl.sat ? f * f : f))" in html  # buttons


def test_zoom_caps(pure):
    sat = node_eval(pure, "(function(){ _gl.sat = true; glSetZoom(100000); return _gl.zoom; })()")
    assert sat == 65536
    flat = node_eval(pure, "(function(){ _gl.sat = false; glSetZoom(100); return _gl.zoom; })()")
    assert flat == 2.5
    mode = node_eval(pure, "(function(){ glSetMode('sat'); return [_gl.mode, _gl.sat]; })()")
    assert mode == ["3d", True]


def test_scale_bar(pure):
    assert node_eval(pure, "glScaleLabelKm(5000)") == "5000 km"
    assert node_eval(pure, "glScaleLabelKm(1)") == "1 km"
    assert node_eval(pure, "glScaleLabelKm(0.5)") == "500 m"
    assert node_eval(pure, "glScaleLabelKm(0.01)") == "10 m"
    # Deep zoom: kmPerPx tiny -> metre label, bar 40..150 px.
    deep = node_eval(pure, "glMapNiceScale(0.0004)")
    assert deep["label"].endswith(" m") and 40 <= deep["px"] <= 150
    # Source: the extended nice list is present in both paths.
    src = read_html()
    assert "0.5, 0.2, 0.1, 0.05, 0.02, 0.01" in src
