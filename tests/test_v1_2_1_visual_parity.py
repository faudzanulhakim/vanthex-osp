"""v1.2.1 VISUAL parity pass (ADE order 2026-10-25 22:45 WIB): the classic
dashboard must LOOK like the artifact Command Deck, not merely contain the
same sections. This suite asserts the restyle in templates/app.html ONLY.

What changed (visual only, data sources identical):
- Topbar: visible search pill opening the existing Command Palette, theme
  toggle button, Log Out button (same POST /api/logout as the sidebar).
- Welcome hero: big bold title, subtitle, local clock as big time + date
  line ("SUN, OCT 25 · LOCAL TIME" style), Reset layout kept.
- Health: still the collapsible <details class="pt-health" open> panel with
  all rows (old total-parity test still passes), summary rendered uppercase
  via CSS, plus a vitals waveform (ptVitalsSvg, same poll data as Live
  Operations) refreshed by the same 30 s poll.
- KPI: three cards with big display numerals and mini sparkline charts:
  scans from the existing trend series; findings series bucketed by day
  from the findings list already loaded for the Cross-Check Matrix
  (cap 1000, same as the matrix). No invented data.
- Posture: SVG ring gauge + methodology text + Per-asset breakdown button
  (scrolls to the Insights Posture Trend). Spectrum rows show BIG
  percentages + counts.
- Posture + Spectrum sit side by side via CSS grid auto-placement on
  #dashDeck (grid-column rules only). DOM order is UNCHANGED, so
  drag-reorder (ptDeckApply/ptDeckBind) and the old order test keep
  working, and no saved-order path can hide a section (ptDeckApply only
  appends in saved order; it never removes or hides).

Deliberately UNCHANGED:
- app2.py, osint.py byte-identical (MD5 asserted below); no endpoint,
  no new host, no new key, no AI, no DRAW. Version stays 1.2.1.
- Deck section order and all old markers (see test_v1_2_1_total_parity.py).
- The default_classic MD5 pin was updated to the post-pass value with a
  dated comment (the pin's job is to catch unexpected changes; this
  change is the task itself, and this suite asserts the new content).

All tests below are hermetic (source text only, no live hosts, no DB,
no credentials). Live verification is a separate post-deploy step.
"""

import hashlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _html():
    return _read("templates/app.html")


def _dash():
    html = _html()
    start = html.index("async function viewDash() {")
    end = html.index("\nfunction renderTargetTrend() {", start)
    assert start < end
    return html[start:end]


def test_topbar_search_pill_opens_palette():
    html = _html()
    assert 'id="ptSearchPill"' in html
    assert 'onclick="ptPaletteOpen()"' in html
    assert "Search targets, scans, findings" in html
    assert "Ctrl K" in html
    assert 'id="ptPalette"' in html
    assert "function ptPaletteOpen" in html


def test_topbar_theme_and_logout_buttons():
    html = _html()
    assert 'id="ptThemeBtn"' in html
    assert 'onclick="toggleTheme()"' in html
    assert 'id="ptLogoutBtn"' in html
    assert "function ptLogout" in html
    assert "fetch('/api/logout', { method: 'POST' })" in html


def test_welcome_hero_markers():
    dash = _dash()
    assert "pt-hero-title" in dash
    assert "Welcome back, " in dash
    assert 'id="ptWelcomeName"' in dash
    assert 'id="ptClock"' in dash
    assert 'id="ptClockDate"' in dash
    assert "LOCAL TIME" in dash
    assert "Reset layout" in dash
    # Clock timer renders time-only + a date line (artifact format).
    html = _html()
    assert "toLocaleTimeString('en-GB')" in html
    assert "toLocaleDateString('en-US'" in html


def test_health_waveform_from_vitals():
    dash = _dash()
    assert '<details class="pt-health" open>' in dash
    assert "System &amp; Engine Health" in dash
    assert 'id="ptVitalsHealth"' in dash
    assert "LIVE TRACE" in dash
    html = _html()
    assert "function ptVitalsSvg" in html
    # The 30 s poll refreshes BOTH the Live Operations waveform and the
    # Health waveform; it never drops a section.
    assert "document.getElementById('ptVitalsHealth')" in html


def test_posture_gauge_and_methodology():
    dash = _dash()
    assert "pt-gauge" in dash
    assert "stroke-dasharray" in dash
    assert "stroke-dashoffset" in dash
    assert "OUT OF 100" in dash
    assert "Methodology" in dash
    assert "Per-asset breakdown" in dash
    assert "Unique Targets" in dash
    assert "Security Posture" in dash


def test_spectrum_big_percent_and_counts():
    dash = _dash()
    assert "pt-spec-row" in dash
    assert "pt-spec-pct" in dash
    assert "pt-spec-count" in dash
    assert "toFixed(1)" in dash
    assert "Severity Spectrum" in dash


def test_kpi_sparkline_cards():
    dash = _dash()
    assert "pt-kpi-card" in dash
    assert "pt-kpi-n" in dash
    assert "pt-spark" in dash
    assert "Total Scans" in dash
    assert "Critical Findings" in dash
    assert "Total Findings" in dash
    # Sparklines derive from existing data only: trend scans + findings
    # bucketed by day from the matrix's findings list.
    assert "scansSeries" in dash
    assert "bucket(" in dash


def test_twelve_deck_sections_in_order_and_grid_pairing():
    dash = _dash()
    found = re.findall(r'data-deck="([^"]+)"', dash)
    assert found == ["welcome", "health", "posture", "kpi", "quick",
                     "severity", "liveops", "trend", "topvuln", "brand",
                     "recent", "insights"], f"deck sections/order wrong: {found}"
    html = _html()
    # Posture + Spectrum pair side by side via grid placement only;
    # DOM order is untouched (see found list above).
    assert "#dashDeck{display:grid" in html
    assert '[data-deck="posture"]{grid-column:1}' in html
    assert '[data-deck="severity"]{grid-column:2}' in html


def test_deck_apply_only_reorders_never_hides():
    html = _html()
    start = html.index("function ptDeckApply() {")
    end = html.index("function ptDeckBind()", start)
    body = html[start:end]
    assert "appendChild" in body
    assert ".remove(" not in body
    assert "display" not in body
    assert "hidden" not in body
    assert "pt-deck-order" in body
    assert "function ptDeckReset" in html


def test_version_still_1_2_1_everywhere():
    html = _html()
    assert "VANTHEX V1.2.1, " in html
    assert "admin · V1.2.1" in html
    assert '<span class="gl-ver">VANTHEX 1.2.1</span>' in html
    assert "V1.5.0" not in html
    assert "VANTHEX V1.2.2" not in html
    assert "VANTHEX V1.3.0" not in html


def test_merged_shortcuts_and_alert_card_only_intact():
    html = _html()
    assert 'pt-help-key">Ctrl+K<' in html
    assert 'pt-help-key">n<' in html
    assert "glAlertsCard(r)" in html
    assert "if (r.la != null && r.lo != null) glAlertsFlyTo(r);" not in html
    assert "function glAlertsFlyTo" in html  # still used by rocket nav


def test_untouched_files_byte_identical():
    def md5(rel):
        with open(os.path.join(ROOT, rel), "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    assert md5("osint.py") == "65ec21c31b4aad76aa304fcb411388ae"
    assert md5("app2.py") == "a9804483d2c3ec6779d0199be4e775b3"
