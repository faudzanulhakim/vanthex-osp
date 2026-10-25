"""v1.15.2 — OSINT Search view becomes globe-only (service dashboard).

What v1.15.2 changes, mechanically (templates/app.html only, plus
version strings):
- viewOsint() renders the globe panel and nothing else: the search
  form panel (intro, QUERY input, DETECTED TYPE row, BREACH toggle,
  Run button, progress div), the GLOBE/GRAPH tabs, the view's own
  reswrap, and the toolbar SEARCH/GRAPH buttons are gone.
- runOsint (the OSINT-search submit handler) is removed; the tab
  onclick wiring and the ?stage=graph init path are gone with it.
- The globe block itself is untouched and still wired by globeInit().

What v1.15.2 deliberately does NOT change (guarded here):
- Shared OSINT result renderers (renderOsintGraph / MetaBlocks /
  NoGraph) stay: Scan Detail / history views render STORED osint
  scans through them, and globeOnResult still re-points the globe
  ENTITIES layer at a stored scan.
- Other views (dashboard, New Scan, history, detail) are untouched;
  the nav entry 'OSINT Search' still maps to viewOsint.
- i18n tables are untouched (unused keys left in place, no churn);
  osint.py, CSP, login, and the engine/API are untouched (covered
  by the version/CSP gates in test_v1150.py and test_globe_feeds.py).

Note: the orphaned #osint-query CSS rule in the v1.11.0 style block
is inert (no such element exists anymore) and is intentionally left
in place — removing style rules is churn with zero user effect.
Likewise globeShowStage keeps null-guarded reads of the removed tab
buttons, so a stored ?stage=graph link degrades to the globe view.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTML = open(os.path.join(ROOT, "templates", "app.html"), encoding="utf-8").read()


def _view_osint():
    start = HTML.find("function viewOsint() {")
    assert start != -1, "viewOsint missing"
    end = HTML.find("async function viewMobile() {", start)
    assert end != -1 and end > start, "viewMobile anchor missing"
    return HTML[start:end]


def test_osint_view_has_no_search_markers():
    body = _view_osint()
    for marker in (
        "osint-query",
        "osint-run",
        "osint-progress",
        "osint-breach",
        "osintBreachSecret",
        "gl-tab-globe",
        "gl-tab-graph",
        "runOsint",
        "Run OSINT Search",
        "reswrap",
        'data-gt="search"',
        'data-gt="graph"',
        "DETECTED TYPE",
    ):
        assert marker not in body, f"search/graph marker still in viewOsint: {marker}"


def test_osint_view_keeps_globe():
    body = _view_osint()
    for marker in (
        "globe-panel",
        "gl-canvas",
        "gl-rail",
        "gl-gpanel",
        "gl-card",
        "gl-attr",
        "gl-m3d",
        "gl-m2d",
        "gl-msat",
        "gl-readout",
        "gl-ticker",
        "gl-zin",
        "gl-zout",
        "gl-zreset",
        "globeInit();",
        "OSINT GLOBE",
        # version marker follows the release (was 1.16.0, then 1.18.0,
        # then 1.19.0, then 1.20.0, then 1.21.0, then 1.23.0, now 1.25.0)
        "VANTHEX 1.25.0",
    ):
        assert marker in body, f"globe marker missing from viewOsint: {marker}"
    # toolbar keeps only the globe controls
    assert 'data-gt="reset"' in body
    assert 'data-gt="labels"' in body


def test_no_orphan_handler_refs():
    # Wiring that would throw on a removed element must be gone.
    for ref in (
        "getElementById('osint-run')",
        "getElementById('osint-breach')",
        "getElementById('osint-query')",
        "getElementById('gl-tab-graph').onclick",
        "getElementById('gl-tab-globe').onclick",
        "async function runOsint",
        ".onclick = runOsint",
        "stage === 'graph' ? 'graph' : 'globe'",
    ):
        assert ref not in HTML, f"orphan handler ref remains: {ref}"
    # globeInit always lands on the globe stage now
    assert "globeShowStage('globe', true);" in HTML


def test_shared_osint_renderers_intact():
    # Stored osint scans in Scan Detail / history still render.
    for fn in (
        "function renderOsintGraph",
        "function renderOsintMetaBlocks",
        "function renderOsintNoGraph",
        "function globeOnResult",
        "function globeShowStage",
    ):
        assert fn in HTML, f"shared renderer removed: {fn}"


def test_other_views_and_nav_intact():
    for fn in (
        "function viewDash",
        "function viewScan",
        "function viewHist",
        "function viewScanDetail",
        "function globeInit",
        "function glSetMode",
        "function glFetchLayer",
    ):
        assert fn in HTML, f"other view/function removed: {fn}"
    assert "osint: ['nav-osint', viewOsint]" in HTML
