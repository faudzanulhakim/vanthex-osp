"""v1.16.0 — Live Alerts panel (service dashboard, globe view).

The panel reads only globe layers that already exist (quakes, severe,
incidents, gdelt_events). No new endpoint, no new feed, no new host,
no generated summaries, no helper agent, no key prompt. Titles stay
verbatim from the feeds; GDELT rows show event code + Goldstein +
mentions as recorded, never rewritten as headlines.
"""

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "templates", "app.html"),
             encoding="utf-8").read()
APP2 = open(os.path.join(ROOT, "app2.py"), encoding="utf-8").read()

LANGS = ["id", "es", "fr", "de", "pt", "ru", "ja", "ko", "zh", "ar", "hi"]
NEW_KEYS = [
    "LIVE ALERTS", "ALL", "QUAKE", "WARN", "FEEDS", "BREAKING",
    "SOURCES LIVE", "UPDATED", "Search alerts…", "No alerts yet",
    "No alerts match your filter",
    "Click an item to locate it on the globe", "of", "OFFLINE",
]

# CSP as amended for the satellite basemap (v1.15.0); v1.16.0 must not
# touch it — the panel needs no new host.
# Amended v1.21.0 (F5): img-src + nowcoast.noaa.gov, frame-src +
# www.youtube-nocookie.com (approved §7/§14.2 diff).
# Amended v1.22.0 (F6): img-src + tiles.basemaps.cartocdn.com, connect-src +
# 6 CARTO hosts, worker-src blob: (approved §8/§10 diff).
CSP_EXPECTED = (
    "default-src 'self'; script-src 'self' 'unsafe-inline'; "
    "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
    "https://server.arcgisonline.com https://tilecache.rainviewer.com https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com https://s3.amazonaws.com; "
    "connect-src 'self' https://api.rainviewer.com https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
    "frame-src https://www.youtube-nocookie.com; "
    "worker-src 'self' blob:; "
    "frame-ancestors 'none'; object-src 'none'; base-uri 'self'; "
    "form-action 'self'"
)

FORBIDDEN_RE = re.compile(r"(?<![A-Za-z])AI(?![A-Za-z])")


def _view_osint():
    return HTML[HTML.index("function viewOsint()"):
                HTML.index("function viewMobile")]


def _alerts_js():
    # anchor on the JS block header line, not the CSS comment above it
    a = HTML.index("v1.16.0 Live Alerts panel (globe view, service dashboard).")
    b = HTML.index("/* v1.16.0 Live Alerts end */") + len(
        "/* v1.16.0 Live Alerts end */")
    return HTML[a:b]


def _pure_js():
    a = HTML.index("/* v1.16.0 alerts-pure-start */")
    b = HTML.index("/* v1.16.0 alerts-pure-end */") + len(
        "/* v1.16.0 alerts-pure-end */")
    return HTML[a:b]


def _extra10():
    m = re.search(r"const I18N_EXTRA10 = (\{.*?\});\nfor", HTML, re.S)
    assert m, "I18N_EXTRA10 block missing"
    return json.loads(m.group(1))


# ------------------------------------------------------------ placement

def test_panel_container_in_osint_view():
    view = _view_osint()
    assert 'id="gl-alerts"' in view
    assert 'id="gl-alerts-head"' in view
    assert 'id="gl-alerts-body"' in view
    # full-width row under the stage, above the readout — never inside
    # the canvas stage, the rail, or the click card.
    assert view.index('id="gl-alerts"') > view.index('class="gl-stage"')
    assert view.index('id="gl-alerts"') < view.index('id="gl-readout"')
    assert ".gl-alerts{" in HTML
    assert ".gl-alerts .al-item{" in HTML


def test_panel_controls_present():
    js = _alerts_js()
    for fn in ("function glAlertsBuild", "function glAlertsApplyFilter",
               "function glAlertsRender", "function glAlertsRefresh",
               "function glAlertsFlyTo", "function glAlertsCard",
               "function glAlertsBind", "function glAlertsState"):
        assert fn in js, fn
    assert "['ALL', 'QUAKE', 'WARN', 'FEEDS', 'NEWS', 'BREAKING']" in js
    assert 'data-afilter' in js and 'data-aitem' in js
    assert 'data-acollapse' in js and 'id="gl-aquery"' in js
    assert "GL_ALERT_CAP = 200" in js


def test_panel_hooks_wired():
    # status refresh demands the four source layers and re-renders;
    # every layer landing re-renders; globe init paints the panel.
    st = HTML[HTML.index("async function glFetchStatus()"):
              HTML.index("async function glFetchLayer(id)")]
    assert "glAlertsRefresh(); glAlertsRender();" in st
    ly = HTML[HTML.index("async function glFetchLayer(id)"):
              HTML.index("function glToggleLayer(id)")]
    assert "glAlertsRender();" in ly
    gi = HTML[HTML.index("function globeInit()"):
              HTML.index("function glRenderRail()")]
    assert "glAlertsRender();" in gi


def test_panel_uses_no_new_endpoint_or_host():
    # v1.19.0 amends the v1.16.0 closed world: the panel now also
    # reads the NEWS + launches routes (design §5 items 8/11) — and
    # nothing else. No raw fetch(), no direct host, no other route.
    js = _alerts_js()
    assert "fetch(" not in js
    eps = set(re.findall(r"glApi\('([^']+)'", js))
    allowed = ("/api/osint/globe/layer/", "/api/osint/globe/entities",
               "/api/osint/globe/news", "/api/osint/globe/launches")
    assert eps, "no glApi calls found in panel"
    for ep in eps:
        assert any(ep.startswith(a) for a in allowed), ep


# ------------------------------------------------------- no-forbidden-terms

def test_alerts_block_has_no_forbidden_terms():
    js = _alerts_js()
    low = js.lower()
    for term in ("openai", "assistant", "overview"):
        assert term not in low, term
    # v1.23.0 §16.2: the static perspective filter documents itself as
    # NOT AI in two comments ("NO AI", "not an AI feature"). Those two
    # documented negations are stripped before the gate; any other
    # standalone AI token still fails.
    scrubbed = js.replace("NO AI", "").replace("not an AI feature", "")
    assert not FORBIDDEN_RE.search(scrubbed), "standalone AI token in panel code"


def test_i18n_extra10_parity_and_no_forbidden_terms():
    extra = _extra10()
    assert sorted(extra) == sorted(LANGS)
    for lang in LANGS:
        assert sorted(extra[lang]) == sorted(NEW_KEYS), lang
        for key in NEW_KEYS:
            val = extra[lang][key]
            assert isinstance(val, str) and val.strip(), (lang, key)
            assert not FORBIDDEN_RE.search(val), (lang, key, val)
            assert "assistant" not in val.lower()
            assert "overview" not in val.lower()


# ------------------------------------------------------------ globe intact

def test_globe_surface_intact():
    view = _view_osint()
    for marker in ("gl-canvas", "gl-rail", "gl-tools", "gl-modebar",
                   "gl-readout", "gl-ticker", "gl-src", "gl-card",
                   "gl-ver", "VANTHEX 1.25.0"):
        assert marker in view, marker
    for fn in ("function globeInit", "function glSetMode",
               "function glFetchLayer", "function glDraw",
               "function glClampPan", "function glProject",
               "function glTicker", "function glHud"):
        assert fn in HTML, fn
    assert 'data-gt="reset"' in view
    assert 'data-gt="labels"' in view


def test_csp_and_osint_engine_untouched():
    # the header value is split across source lines, so join its
    # literals before comparing — this gates the served value itself
    m = re.search(r'send_header\("Content-Security-Policy",\s*((?:"[^"]*"\s*)+)\)',
                  APP2)
    assert m, "CSP send_header call missing"
    served = "".join(re.findall(r'"([^"]*)"', m.group(1)))
    assert served == CSP_EXPECTED, served
    path = os.path.join(ROOT, "osint.py")
    digest = hashlib.md5(open(path, "rb").read()).hexdigest()
    assert digest == "65ec21c31b4aad76aa304fcb411388ae", digest


def test_inline_scripts_parse():
    node = shutil.which("node")
    assert node, "node required for the parse gate"
    blocks = re.findall(r"<script>(.*?)</script>", HTML, re.S)
    assert len(blocks) >= 3
    for i, block in enumerate(blocks):
        with tempfile.NamedTemporaryFile("w", suffix=".js",
                                         delete=False) as fh:
            fh.write(block)
            tmp = fh.name
        try:
            proc = subprocess.run([node, "--check", tmp],
                                  capture_output=True, text=True)
            assert proc.returncode == 0, (i, proc.stderr[-500:])
        finally:
            os.unlink(tmp)


# ------------------------------------------------------- pure rules (node)

NODE_HARNESS = r"""
const assert = require('assert');
const NOW = Date.parse('2026-10-24T10:00:00Z');
const H = 3600000;
Date.now = () => NOW;
const data = {
  quakes: { points: [
    { la: -6.1, lo: 106.8, lb: 'M5.1', ex: '10km ENE of Jakarta', mag: 5.1, t: NOW - 2 * H },
    { la: 35.7, lo: 139.7, lb: 'M6.0', ex: 'off Tokyo', mag: 6.0, t: NOW - 30 * 60000 },
    { la: 0.5, lo: 120.0, lb: 'M7.2', ex: 'Sulawesi Sea', mag: 7.2, t: NOW - 5 * 60000 },
    { la: 1.0, lo: 121.0, lb: 'M4.0', ex: 'no-time quake', mag: 4.0 },
  ]},
  severe: { points: [
    { la: 34.0, lo: -118.2, lb: 'Wildfire in California', ex: 'Wildfires', t: new Date(NOW - 30 * 60000).toISOString() },
    { la: 40.0, lo: 20.0, lb: 'Old storm', ex: 'Severe Storms', t: new Date(NOW - 61 * 60000).toISOString() },
    { la: 41.0, lo: 21.0, lb: 'Dateless flood', ex: 'Floods' },
    { la: 42.0, lo: 22.0, lb: 'Future event', ex: 'Floods', t: new Date(NOW + H).toISOString() },
    { la: 43.0, lo: 23.0, lb: 'Bad date', ex: 'Floods', t: 'not-a-date' },
  ]},
  incidents: { points: [
    { la: 55.7, lo: 37.6, lb: 'Moscow', ex: '14 · Goldstein 3.0 · Mentions 12' },
    { la: 48.8, lo: 2.3, lb: 'Paris', ex: '20 · Goldstein -4.0 · Mentions 5' },
  ]},
  gdelt_events: { items: [
    { lb: '0101', ex: '0101 · Goldstein 2.5 · Mentions 3' },
    { lb: '0203', ex: '0203 · Goldstein -1.0 · Mentions 9' },
  ]},
};
const meta = {
  quakes: { state: 'live', updated_at: Math.floor(NOW / 1000) - 90, ttl_s: 120 },
  severe: { state: 'live', updated_at: Math.floor(NOW / 1000) - 300, ttl_s: 1800 },
  incidents: { state: 'live', updated_at: Math.floor(NOW / 1000) - 600, ttl_s: 1800 },
  gdelt_events: { state: 'offline', updated_at: null, ttl_s: 1800 },
};
const built = glAlertsBuild(data, meta);
assert.strictEqual(built.items.length, 13);
assert.deepStrictEqual(built.counts, { ALL: 13, QUAKE: 4, WARN: 5, FEEDS: 4, BREAKING: 3 });
assert.deepStrictEqual(built.items.map(r => r.title), [
  'M5.1 — 10km ENE of Jakarta', 'M6.0 — off Tokyo', 'M7.2 — Sulawesi Sea', 'M4.0 — no-time quake',
  'Wildfire in California', 'Old storm', 'Future event', 'Dateless flood', 'Bad date',
  'Moscow', 'Paris', '0101', '0203',
]);
// timed rows first inside each category, feed order preserved, no-time rows last
assert.strictEqual(built.items[3].tms, null);
assert.strictEqual(built.items[7].tms, null);
assert.strictEqual(built.items[8].tms, null);
// GDELT list rows carry no coordinates: detail card only, never fly-to
assert.strictEqual(built.items[11].la, null);
assert.strictEqual(built.items[11].lo, null);
// sources: incidents live keeps the GDELT family live even though the
// events list is offline, so nothing is reported offline here
assert.strictEqual(built.sourcesLive, 3);
assert.strictEqual(built.sourcesTotal, 3);
assert.deepStrictEqual(built.offline, []);
assert.strictEqual(built.updatedAt, Math.floor(NOW / 1000) - 90);
// breaking boundary: M=6.0 exactly counts, 5.9 does not, missing mag does not
assert.strictEqual(glAlertIsBreaking({ cat: 'QUAKE', mag: 6.0 }, NOW), true);
assert.strictEqual(glAlertIsBreaking({ cat: 'QUAKE', mag: 5.9 }, NOW), false);
assert.strictEqual(glAlertIsBreaking({ cat: 'QUAKE', mag: null }, NOW), false);
// severe boundary: exactly 1h counts, 1h+1ms does not, future and
// dateless never count
assert.strictEqual(glAlertIsBreaking({ cat: 'WARN', tms: NOW - H }, NOW), true);
assert.strictEqual(glAlertIsBreaking({ cat: 'WARN', tms: NOW - H - 1 }, NOW), false);
assert.strictEqual(glAlertIsBreaking({ cat: 'WARN', tms: NOW + 1000 }, NOW), false);
assert.strictEqual(glAlertIsBreaking({ cat: 'WARN', tms: null }, NOW), false);
assert.strictEqual(glAlertIsBreaking({ cat: 'FEEDS', tms: NOW }, NOW), false);
// breaking filter keeps group order QUAKE then WARN
assert.deepStrictEqual(
  glAlertsApplyFilter(built, 'BREAKING', '', NOW).list.map(r => r.title),
  ['M6.0 — off Tokyo', 'M7.2 — Sulawesi Sea', 'Wildfire in California']);
// category filters are exact subsets
assert.strictEqual(glAlertsApplyFilter(built, 'QUAKE', '', NOW).total, 4);
assert.strictEqual(glAlertsApplyFilter(built, 'WARN', '', NOW).total, 5);
assert.strictEqual(glAlertsApplyFilter(built, 'FEEDS', '', NOW).total, 4);
assert.strictEqual(glAlertsApplyFilter(built, 'ALL', '', NOW).total, 13);
// plain substring search over title + detail, case-insensitive
assert.deepStrictEqual(
  glAlertsApplyFilter(built, 'ALL', 'jakarta', NOW).list.map(r => r.title),
  ['M5.1 — 10km ENE of Jakarta']);
assert.strictEqual(glAlertsApplyFilter(built, 'ALL', 'GOLDSTEIN', NOW).total, 4);
assert.strictEqual(glAlertsApplyFilter(built, 'ALL', 'zzz-no-match', NOW).total, 0);
// sources-live edge cases
assert.deepStrictEqual(glAlertsSourcesLive({}), { live: 0, total: 3, offline: [] });
assert.deepStrictEqual(glAlertsSourcesLive({
  quakes: { state: 'offline' }, severe: { state: 'stale' },
  incidents: { state: 'offline' }, gdelt_events: { state: 'offline' },
}), { live: 0, total: 3, offline: ['USGS', 'GDELT'] });
// list cap mirrors LIST_CAP: 200 shown, total kept
const many = { quakes: { points: [] }, severe: { points: [] }, incidents: { points: [] }, gdelt_events: { items: [] } };
for (let i = 0; i < 250; i++) many.quakes.points.push({ la: 0, lo: i, lb: 'M1.0', ex: 'q' + i, mag: 1.0, t: NOW - i * 1000 });
const capped = glAlertsApplyFilter(glAlertsBuild(many, meta), 'ALL', '', NOW);
assert.strictEqual(capped.list.length, 200);
assert.strictEqual(capped.total, 250);
// time parsing + relative age
assert.strictEqual(glAlertTimeMs({ t: 123 }), 123);
assert.strictEqual(glAlertTimeMs({ t: '2026-10-24T10:00:00Z' }), NOW);
assert.strictEqual(glAlertTimeMs({ t: 'junk' }), null);
assert.strictEqual(glAlertTimeMs({}), null);
assert.strictEqual(glAlertsAgo(1000, 1030), 'just now');
assert.strictEqual(glAlertsAgo(1000, 1120), '2m ago');
assert.strictEqual(glAlertsAgo(1000, 4600), '1h ago');
assert.strictEqual(glAlertsAgo(1000, 90000), '1d ago');
assert.strictEqual(glAlertsAgo(null, 90000), '');
console.log('v1160 node harness OK');
"""


def test_pure_rules_under_node():
    node = shutil.which("node")
    assert node, "node required for the pure-rules harness"
    with tempfile.NamedTemporaryFile("w", suffix=".js",
                                     delete=False) as fh:
        fh.write(_pure_js() + "\n" + NODE_HARNESS)
        tmp = fh.name
    try:
        proc = subprocess.run([node, tmp], capture_output=True, text=True)
        assert proc.returncode == 0, proc.stdout[-2000:] + proc.stderr[-2000:]
        assert "v1160 node harness OK" in proc.stdout
    finally:
        os.unlink(tmp)
