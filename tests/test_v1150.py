"""v1.15.0 — globe view modes: SATELLITE basemap + DISPLAY mode
switch + 2D hardening (service renderer only; artifact parity is a
separate step).

Design: goals/pentest-toolkit/files/
vanthex-osint-globe-viewmodes-design.md (K1–K8 approved as
recommended). What this release is, mechanically:

  * mode 2D already existed (v1.13.0 weather substrate) — v1.15.0
    adds the Esri World Imagery basemap on top of it (view value
    'sat' = projection '2d' + a basemap flag), moves the mode switch
    into the DISPLAY panel as a segmented control mirrored by the
    canvas modebar, and hardens 2D (pinch, zoom-to-cursor, soft pan
    clamp, dateline guard, terminator strip over imagery, honest
    basemap chip);
  * the ONLY server change outside the renderer is the CSP
    amendment written verbatim in design §5 (Esri + RainViewer
    hosts; nothing wider) and the usual version strings.

These tests are hermetic source locks: they read app2.py /
templates/app.html and assert the exact contracted shapes. The
behavioral JS logic (mode mapping, anchor invariance, tile z/URL
construction, chip state machine, strip alpha, guard neutrality)
is exercised separately by the node harness kept with the build
evidence (hidden_files/v1150-fase0/js_harness.js, 32 assertions).
"""
import os
import re
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()
HTML = open(os.path.join(ROOT, "templates", "app.html"),
            encoding="utf-8").read()

NEW_KEYS = [
    "SATELLITE", "SATELLITE BASEMAP", "BASEMAP LIVE", "BASEMAP OFFLINE",
    "VIEW MODE",
    "View mode — rendering only; layers and data do not change.",
    "Imagery: Esri, Maxar, Earthstar Geographics — drawn in 2D; "
    "the dot substrate returns if tiles fail.",
]
LANGS = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh", "ar",
         "hi"]


def _func(name, src=HTML):
    i = src.find("function %s(" % name)
    assert i >= 0, name
    j = src.find("{", i)
    depth = 0
    k = j
    while True:
        if src[k] == "{":
            depth += 1
        elif src[k] == "}":
            depth -= 1
            if depth == 0:
                break
        k += 1
    return src[i:k + 1]


# ------------------------------------------------------------------ CSP

def test_csp_matches_approved_amendment_exactly():
    # design §5 diff, verbatim — and nothing wider.
    assert ('"default-src \'self\'; script-src \'self\' '
            '\'unsafe-inline\'; "') in APP2
    assert ('"style-src \'self\' \'unsafe-inline\'; '
            'img-src \'self\' data: "') in APP2
    assert ('"https://server.arcgisonline.com '
            'https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "') in APP2
    assert ('"connect-src \'self\' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "'
            ) in APP2
    # v1.21.0 (F5) adds the frame-src pin for the Sen embed.
    assert ('"frame-src https://www.youtube-nocookie.com; "'
            ) in APP2
    # v1.22.0 (F6, design §10): MapLibre worker blob.
    assert ('"worker-src \'self\' blob:; "'
            ) in APP2
    assert ('"frame-ancestors \'none\'; object-src \'none\'; '
            'base-uri \'self\'; "') in APP2
    assert '"form-action \'self\'"' in APP2
    # the pre-amendment bare img-src must be gone
    assert "img-src 'self' data:; " not in APP2
    # no other external host sneaks into the policy
    hosts = set(re.findall(r"https://([a-z0-9.-]+)", _csp(APP2)))
    # v1.21.0 (F5): NowCOAST img-src + youtube-nocookie frame-src.
    # v1.22.0 (F6, design §8/§10): CARTO style/tile/glyph/sprite hosts.
    assert hosts == {"server.arcgisonline.com",
                     "tilecache.rainviewer.com",
                     "api.rainviewer.com",
                     "nowcoast.noaa.gov",
                     "www.youtube-nocookie.com",
                     "basemaps.cartocdn.com",
                     "tiles.basemaps.cartocdn.com",
                     "tiles-a.basemaps.cartocdn.com",
                     "tiles-b.basemaps.cartocdn.com",
                     "tiles-c.basemaps.cartocdn.com",
                     "tiles-d.basemaps.cartocdn.com",
                     "s3.amazonaws.com"}


def _csp(src):
    m = re.search(r'send_header\("Content-Security-Policy",\s*'
                  r'(.*?)\)', src, re.S)
    assert m, "CSP header not found"
    return m.group(1)


# -------------------------------------------------------------- versions

def test_version_points_are_1170():
    # Rewritten for v1.18.0 (was _1170), amended v1.19.0, amended
    # v1.20.0, amended v1.21.0, amended v1.22.0, amended v1.23.0, amended v1.25.0: the version lock
    # follows the release; nothing else in this file changes.
    assert '"version": "1.25.0"' in APP2
    assert 'server_version = "VANTHEX/1.25.0"' in APP2
    assert "Platform v1.25.0 ->" in APP2
    for mod in ("report.py", "docx_report.py"):
        body = open(os.path.join(ROOT, mod), encoding="utf-8").read()
        assert 'VERSION = "1.25.0"' in body, mod
    gf = open(os.path.join(ROOT, "globe_feeds.py"),
              encoding="utf-8").read()
    assert "VANTHEX v1.25.0 — OSINT Globe feed engine" in gf
    assert "VANTHEX/1.25.0 (OSINT globe;" in gf
    assert '<span class="gl-ver">VANTHEX 1.25.0</span>' in HTML


# ------------------------------------------------------- mode state (K1)

def test_setmode_maps_sat_to_2d_plus_flag():
    body = _func("glSetMode")
    assert "if (m === 'sat') { _gl.mode = '2d'; _gl.sat = true; }" \
        in body
    assert "else if (m === '2d') { _gl.mode = '2d'; _gl.sat = false; }" \
        in body
    assert "else { _gl.mode = '3d'; _gl.sat = false; }" in body
    # both controls highlight from the same derived view value
    assert "const view = _gl.sat ? 'sat' : _gl.mode;" in body
    assert "getElementById('gl-msat')" in body
    # attribution strip follows the flag
    assert "at.style.display = _gl.sat ? '' : 'none';" in body


def test_modebar_and_stage_markup():
    assert '<button id="gl-msat" type="button">SAT</button>' in HTML
    assert ('<div class="gl-attr" id="gl-attr" style="display:none">'
            'Imagery: Esri, Maxar, Earthstar Geographics</div>') in HTML
    # globeInit wires the third button and honours ?view=
    assert "getElementById('gl-msat').onclick" in HTML
    assert "const vw = qs.get('view');" in HTML
    save = _func("glSaveUrl")
    assert "p.set('view', _gl.sat ? 'sat' : _gl.mode);" in save


def test_display_panel_segmented_control():
    assert 'data-view="3d"' in HTML and 'data-view="2d"' in HTML
    assert 'data-view="sat"' in HTML
    assert "tr('VIEW MODE')" in HTML
    assert "tr('SATELLITE')" in HTML
    # basemap status row + chip, fed by renderer state only
    assert 'id="gl-bm-chip"' in HTML
    assert "tr('SATELLITE BASEMAP')" in HTML
    assert "tr('BASEMAP LIVE')" in HTML
    assert "tr('BASEMAP OFFLINE')" in HTML
    # segmented buttons call the one shared setter
    assert "b.onclick = () => glSetMode(b.getAttribute('data-view'));" \
        in HTML


# ------------------------------------------------------- imagery (K2/K3)

def test_esri_tile_source_shape():
    body = _func("glDrawTiles")
    # ArcGIS REST order {z}/{y}/{x} — y before x, unlike RainViewer.
    assert ("https://server.arcgisonline.com/ArcGIS/rest/services/"
            "World_Imagery/MapServer/tile/${z}/${ty}/${tx}") in body
    # Fase 0 consequence: CORS-clean loads only, and only for Esri.
    assert "img.crossOrigin = 'anonymous';" in body
    assert body.count("crossOrigin") == 1
    # 256 px tiles: divisor 256 (RainViewer keeps 384); esri z <= 4.
    assert "(kind === 'esri' ? 256 : 384)" in body
    assert "Math.min(kind === 'esri' ? 4 : 6, z)" in body
    # RainViewer URL forms are untouched.
    assert "/512/${z}/${tx}/${ty}/0/0_0.png" in body
    assert "/512/${z}/${tx}/${ty}/2/1_1.png" in body
    # returns the drawn count so callers can be honest about fallback
    assert "return drawn;" in body


def test_basemap_state_machine_locks():
    body = _func("glBmState")
    # LIVE needs a completed/drawn tile; OFFLINE needs every request
    # settled with zero completions; anything else is LOADING.
    assert "nDrawn > 0 || _gl.bmOk > 0 ? 'live'" in body
    assert "_gl.bmErr > 0 && _gl.bmPending === 0 ? 'offline'" in body
    tiles = _func("glDrawTiles")
    assert "_gl.bmPending++" in tiles
    assert "_gl.bmOk++" in tiles and "_gl.bmErr++" in tiles


def test_sat_draw_order_and_dot_fallback():
    # v1.22.0 (F6): the legacy canvas renderer is now glDrawLegacy;
    # the draw order itself is unchanged.
    draw = _func("glDrawLegacy")
    i_esri = draw.find("glDrawTiles(ctx, g, 'esri')")
    i_strip = draw.find("glDrawNightStrip(ctx, g)")
    i_dots = draw.find("glLandPoints()")
    assert 0 < i_esri < i_strip < i_dots
    # dots only when no imagery base was established
    assert "if (!satBase) {" in draw
    assert "let satBase = false;" in draw


def test_night_strip_shape():
    body = _func("glDrawNightStrip")
    assert "Math.min(0.45, -cz * 0.45)" in body  # alpha cap 0.45
    assert "Math.floor(Date.now() / 60000)" in body  # per-minute cache
    assert "glSubsolar()" in body


# ---------------------------------------------------- 2D hardening (K4)

def test_zoom_range_unchanged_and_anchor_present():
    body = _func("glSetZoom")
    assert "Math.min(2.5, Math.max(0.8, nz))" in body
    anchor = _func("glZoomAnchor")
    assert "glUnproject(px, py, glGeom())" in anchor
    assert "glClampPan(g1)" in anchor


def test_pan_clamp_soft_bounds():
    body = _func("glClampPan")
    assert "Math.max(-W / 2, Math.min(W / 2" in body
    assert "Math.max(-H / 2, Math.min(H / 2" in body


def test_pinch_and_wheel_anchor_wiring():
    bind = _func("glBindCanvas")
    assert "const ptrs = new Map();" in bind
    assert "pinch = { d: Math.hypot" in bind
    assert "glZoomAnchor(pinch.zoom * d / pinch.d, mx, my);" in bind
    assert "glZoomAt(e.deltaY < 0 ? 1.12 : 1 / 1.12" in bind
    assert "pointercancel" in bind
    # drag in 2D passes through the clamp
    assert "glClampPan(glGeom());" in bind


def test_dateline_guard_present():
    body = _func("glDrawLines")
    assert ("Math.abs(x - prevX) > (g.w * _gl.zoom) / 2") in body


# ------------------------------------------------------------------ i18n

def test_i18n_extra9_parity():
    m = re.search(r"const I18N_EXTRA9 = (\{.*?\});\n", HTML, re.S)
    assert m, "I18N_EXTRA9 block missing"
    import json
    d = json.loads(m.group(1))
    assert sorted(d.keys()) == sorted(LANGS)
    for lang in LANGS:
        assert sorted(d[lang].keys()) == sorted(NEW_KEYS), lang
        for k in NEW_KEYS:
            assert d[lang][k].strip(), (lang, k)


# ------------------------------------------------------------- js syntax

@pytest.mark.skipif(not shutil.which("node"),
                    reason="node unavailable")
def test_inline_scripts_parse():
    scripts = re.findall(r"<script>(.*?)</script>", HTML, re.S)
    assert scripts
    path = "/tmp/v1150_app_check.js"
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n;\n".join(scripts))
    r = subprocess.run(["node", "--check", path],
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[:400]
