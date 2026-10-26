"""v1.2.1 TOTAL parity port into the classic dashboard (templates/app.html).

Parent audit 2026-10-25 22:16 WIB under ADE's order that everything be
1:1 with the artifact. This suite asserts the ported surface in the
classic template ONLY. It does not touch app2.py, osint.py, CSP, the
database, webui, or the artifact.

Ported items:
1. System & Engine Health panel at the TOP of the dashboard
   (collapsible, per ADE's 2026-10-17 rule): engine version, status,
   job queue, uptime, memory, CPU, CVE cache, canary loopback,
   audit chain — all from existing endpoints (stats/engine/metrics).
2. Engine Reference in Settings: profiles + check counts + live
   libraries + verification layers.
3. Shell extras: Command Palette (Ctrl/Cmd+K and "/"), Notifications
   bell (Recent Activity dropdown), accent picker
   (Crimson/Cyan/Violet/Amber, persisted as pt-accent), dashboard
   cell drag-reorder + Reset layout (persisted as pt-deck-order).
4. Command Deck composition, in order: Welcome strip + Local clock,
   Health, Security Posture, KPI (Total Scans, Critical Findings,
   Total Findings), Quick Actions, Severity Spectrum WITH
   percentages, Live Operations terminal + vitals waveform, Scan
   Trend with 7D/14D toggle, Top Vulnerabilities, brand cell,
   Recent Scans, Insights (Posture Trend, Cross-Check Matrix,
   Findings by Severity/Confidence, Coverage OWASP, Top Targets by
   Risk, SLA & MTTR).
5. Dashboard version display: sidebar footer "VANTHEX V1.2.1, admin"
   + topbar session chip; the globe badge is unchanged.
6. Service Session panel in Settings: idle 4 hours, NOT 30 minutes.
7. Merged shortcuts: artifact dashboard set + classic globe set,
   listed in the "?" help overlay and in the globe help.
8. Alert click (ADE decision 2026-10-25 22:18 WIB, via widget):
   CARD ONLY, NO FLY-TO, like the artifact.

Foldings of classic-only cells (data kept, not deleted):
- Findings Distribution donut counts -> Severity Spectrum rows.
- Unique Targets own card -> Security Posture sub-stat.
- Severity stat cards -> Spectrum + KPI Critical Findings.
- Posture Score card -> Security Posture hero.
- Latest Findings feed -> Top Vulnerabilities (top 6, same rows).
- Latest Scans table -> Recent Scans (same table, retitled).
- Risk Score Trend per Asset -> Posture Trend (same chart, retitled).

Honest substitution (reported, not hidden): there is NO activity
endpoint and NO activity.log file in this service (the logs dir
holds only service.log and supervisor.out), so Live Operations is
fed from the audit trail (/api/audit), labelled as such. Creating
an activity endpoint was out of scope.

Deliberately UNCHANGED:
- app2.py byte-identical (MD5 asserted below); no endpoint created.
- osint.py byte-identical (MD5 asserted below).
- glAlertsFlyTo kept: still used by glRocketGo (launch navigation,
  NOT an alert click). Generic map point clicks (glMapClick /
  glCardHtml) untouched. Pins were already card-only, untouched.
- The old i18n key "Click an item to locate it on the globe" stays
  in the I18N_EXTRA10 dictionary (11 locales) as a stale key; the
  alerts footer now uses the new key, which falls back to English
  via tr() in locales without it. Deleting dictionary keys was
  avoided on purpose.
- Version stays 1.2.1; no new hosts, keys, or features.

All tests below are hermetic (source text only, no live hosts,
no DB, no credentials). Live verification is a separate
post-deploy step, not part of this suite.
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
    """The viewDash function body (dashboard composition under test)."""
    html = _html()
    start = html.index("async function viewDash() {")
    end = html.index("\nfunction renderTargetTrend() {", start)
    assert start < end
    return html[start:end]


def test_health_panel_top_collapsible_with_all_rows():
    dash = _dash()
    assert '<details class="pt-health" open>' in dash
    assert "System &amp; Engine Health" in dash
    assert "All Systems Operational" in dash
    for row in ("Engine version", "Job queue", "Uptime", "Memory", "CPU",
                "CVE cache", "Canary loopback", "Audit chain"):
        assert row in dash, f"health row missing: {row}"
    # Health renders before the posture hero (it sits at the top).
    assert dash.index("System &amp; Engine Health") < dash.index("Security Posture")


def test_engine_reference_in_settings():
    html = _html()
    assert "Engine Reference" in html
    assert 'id="ptEngineRef"' in html
    assert "<th>Profile</th><th>Checks</th>" in html
    assert "Libraries (live)" in html
    assert "Verification layers" in html
    assert "await $('/api/engine')" in html


def test_shell_extras_palette_bell_accent_deck():
    html = _html()
    # Command Palette
    assert 'id="ptPalette"' in html
    assert 'id="ptPaletteInput"' in html
    assert "function ptPaletteOpen" in html
    # Notifications bell
    assert 'id="ptBell"' in html
    assert 'id="ptBellDrop"' in html
    assert "Recent Activity" in html
    # Accent picker: four colours, persisted as pt-accent
    assert 'id="ptAccent"' in html
    for colour in ("crimson", "cyan", "violet", "amber"):
        assert f'data-accent="{colour}"' in html
    assert "pt-accent" in html
    # Deck drag-reorder + Reset layout
    assert "pt-deck-order" in html
    assert "Reset layout" in html
    assert "pt-deck-handle" in html
    assert "function ptDeckApply" in html
    assert "function ptDeckBind" in html
    assert "function ptDeckReset" in html


def test_command_deck_order():
    dash = _dash()
    markers = [
        "Welcome back, ",
        "System &amp; Engine Health",
        "Security Posture",
        "Total Scans",
        "Critical Findings",
        "Total Findings",
        "Quick Actions",
        "Severity Spectrum",
        "Live Operations",
        "Scan Trend",
        "Top Vulnerabilities",
        "<h3>VANTHEX</h3>",
        "Recent Scans",
        "<h3>Insights</h3>",
        "Posture Trend",
        "Cross-Check Matrix",
        "Findings by Severity",
        "Findings by Confidence",
        "Coverage OWASP",
        "Top Targets by Risk",
        "Remediation SLA",
    ]
    positions = [dash.index(m) for m in markers]
    assert positions == sorted(positions), "Command Deck order broken"


def test_severity_spectrum_has_percentages_and_trend_toggle():
    dash = _dash()
    assert "pt-spec-row" in dash
    assert "toFixed(1)" in dash  # percentage to 1 decimal
    assert 'data-td="7"' in dash
    assert 'data-td="14"' in dash
    assert "function ptTrendDays" in _html()
    assert "ptVitals" in dash
    assert "Recent activity (audit trail)" in dash
    assert "await $('/api/audit')" in dash


def test_version_display_sidebar_footer_and_session_chip():
    html = _html()
    assert 'id="sideVer"' in html
    # Scan-parity 2026-10-25: footer now matches the artifact format
    # "VANTHEX V1.2.1 · admin · admin" (was "VANTHEX V1.2.1, admin").
    assert 'VANTHEX V1.2.1 · ' in html
    assert 'id="footUname"' in html
    assert 'id="footRole"' in html
    assert 'id="sessChip"' in html
    assert "admin · V1.2.1" in html
    # Globe badge unchanged.
    assert '<span class="gl-ver">VANTHEX 1.2.1</span>' in html


def test_service_session_four_hours_not_thirty_minutes():
    html = _html()
    i = html.index("Service Session")
    window = html[i:i + 900]
    assert "4 hours without activity" in window
    assert "30 minute" not in window


def test_merged_shortcut_set():
    html = _html()
    # Dashboard set, in the "?" help overlay.
    for key in ("Ctrl+K", "g d", "g s", "g f", "g a"):
        assert f'pt-help-key">{key}<' in html, f"help overlay missing {key}"
    assert 'pt-help-key">n<' in html
    # Dashboard set, in the globe help (merged rows).
    for row in ("row('Ctrl+K', 'Command Palette')",
                "row('g d', 'Dashboard')",
                "row('g s', 'Scan History')",
                "row('g f', 'Findings')",
                "row('g a', 'Assets')",
                "row('n', 'New scan')"):
        assert row in html, f"globe help missing {row}"
    # Globe bindings still live (Esc = close, ? = help, in both sets).
    assert "glEscClose" in html
    assert "glHelpToggle" in html
    assert "ptCloseAll" in html
    assert "window._ptG" in html


def test_alert_click_card_only_no_flyto():
    html = _html()
    # The alert-row click no longer flies anywhere.
    assert "if (r.la != null && r.lo != null) glAlertsFlyTo(r);" not in html
    # The ticker quake click no longer flies either.
    assert "if (it.kind === 'quake') glAlertsFlyTo" not in html
    assert "glAlertsCard({ cat: 'QUAKE'" in html
    # The alerts footer says card, not locate.
    assert "let foot = esc(tr('Click an item to view its card'));" in html
    assert "let foot = esc(tr('Click an item to locate it on the globe'));" not in html
    # Pins were already card-only and stay so.
    assert "pin click shows the alert card only" in html
    # fly-to itself survives for launch navigation; generic point
    # clicks are untouched.
    assert "function glAlertsFlyTo" in html
    assert "function glRocketGo" in html
    assert "glCardHtml" in html


def test_untouched_files_byte_identical():
    def md5(rel):
        with open(os.path.join(ROOT, rel), "rb") as f:
            return hashlib.md5(f.read()).hexdigest()
    assert md5("osint.py") == "65ec21c31b4aad76aa304fcb411388ae"
    assert md5("app2.py") == "a9804483d2c3ec6779d0199be4e775b3"
