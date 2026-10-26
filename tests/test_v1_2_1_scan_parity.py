"""VANTHEX 1.2.1 scan-parity tests (2026-10-25): artifact-latest state ported
into the classic dashboard (templates/app.html) — scanning flows + appearance.
Hermetic source-text tests: no live hosts, no DB, no credentials.
"""
import hashlib
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding='utf-8') as f:
        return f.read()


def _html():
    return _read('templates/app.html')


def _slice(html, start_marker, end_marker):
    a = html.index(start_marker)
    b = html.index(end_marker, a)
    return html[a:b]


def _md5(rel):
    with open(os.path.join(ROOT, rel), 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()


# --- 1. Posture labels (exact artifact strings) ---

def test_posture_labels_exact_artifact_strings():
    html = _html()
    m = re.search(r"const pLabel = ([^\n]+)", html)
    assert m, 'pLabel line missing from viewDash'
    line = m.group(1)
    assert "'Severe risk'" in line and "'Elevated risk'" in line and "'Low risk'" in line
    assert ">= 70" in line and ">= 40" in line


# --- 2. Sidebar footer ---

def test_sidebar_footer_format():
    html = _html()
    assert 'VANTHEX V1.2.1 · <span id="footUname">admin</span> · <span id="footRole">admin</span>' in html
    assert "getElementById('footRole')" in html


# --- 3. Date format ---

def test_date_format_artifact_style():
    html = _html()
    assert "toLocaleString('en-GB')" not in html
    assert "toLocaleString(undefined, {month: 'short'" in html
    assert "toLocaleTimeString('en-GB')" in html  # hero clock untouched


# --- 4. Logout confirm ---

def test_logout_confirm():
    html = _html()
    m = re.search(r"async function ptLogout\(\) \{(.*?)\n\}", html, re.S)
    assert m, 'ptLogout missing'
    assert 'confirmDialog' in m.group(1)
    assert "nav-logout').onclick = () => ptLogout();" in html


# --- 5. Settings language selector (+ topbar wiring fix) ---

def test_settings_language_selector():
    html = _html()
    assert 'id="langsel2"' in html
    assert 'id="langsel" onchange="setLang(this.value)"' in html
    assert 'id="langsel2" onchange="setLang(this.value)"' in html
    m = re.search(r"function setLang\(l\) \{(.*?)\n\}", html, re.S)
    assert m and "getElementById('langsel2')" in m.group(1)


# --- 6. Mobile exports ---

def test_mobile_history_exports():
    html = _html()
    sec = _slice(html, 'async function loadMobileHist()', 'async function delScanMobile')
    assert 'export?fmt=json' in sec and 'export?fmt=csv' in sec


def test_mobile_result_csv():
    html = _html()
    m = re.search(r"function renderMobileResult\(j\) \{(.*?)\n\}", html, re.S)
    assert m, 'renderMobileResult missing'
    assert 'export?fmt=csv' in m.group(1)


# --- 7. Mobile cancel / stop ---

def test_mobile_cancel_stop():
    html = _html()
    assert 'function ptMobileCancel()' in html
    assert 'window._mobAbort' in html and 'window._mobJobId' in html
    assert "textContent = 'Stop analysis'" in html
    sec = _slice(html, 'async function runMobileAnalyze()', 'function prefillScan')
    assert "j.status === 'cancelled'" in sec
    assert 'Upload cancelled' in sec


# --- 8. Finding cards ---

def test_finding_card_origin():
    html = _html()
    assert 'function findingCardHtml' in html
    assert 'function ptOriginBadge' in html
    assert 'ORIGIN: PASSIVE' in html and 'ORIGIN: ACTIVE' in html
    assert 'Origin: ${ptOriginText(f)}' in html


def test_finding_card_tier_owner():
    html = _html()
    assert 'function ptTierBadges' in html
    assert r"/^\[T([0-3]) · owner=(app|library|unknown)\] /" in html
    assert 'T0 · STRING' in html and 'T1 · CONFIG' in html
    assert 'T2 · CODE' in html and 'T3 · DATAFLOW' in html
    assert 'OWNER: ' in html
    assert '.slice(m[0].length)' in html  # prefix stripped from evidence


def test_finding_card_triage_and_evidence():
    html = _html()
    assert 'Save triage' in html
    assert 'function ptTriageDirty' in html and 'function ptTriageSave' in html
    assert 'Triage saved.' in html
    assert 'Overdue since' in html
    assert 'Evidence: </span>' in html
    assert 'data-search=' in html


# --- 9. Vulnerability Findings view -> cards ---

def test_findings_view_cards():
    html = _html()
    sec = _slice(html, 'async function viewFindings()', 'const SLA_DAYS')
    assert 'fCardsWrap' in sec
    assert 'Loading findings…' in sec
    assert 'No matching findings' in sec
    assert '>Search</button>' in sec
    assert '_ptFindPreset' in sec
    assert 'showTarget: true' in sec
    assert '<th>Severity</th>' not in sec  # table gone


# --- 10. Scan Detail header + Rescan ---

def test_scan_detail_header_rescan():
    html = _html()
    sec = _slice(html, 'async function viewScanDetail(id)', 'async function loadDiff')
    assert 'font-size:22px' in sec
    assert 'risk score' in sec
    assert '↻ Rescan' in sec
    assert 'function rescanFromDetail' in html
    assert "}, 'Detail — ' + esc(d.scan.target));" in sec
    assert '}, `Detail — ${esc(d.scan.target)}`);' in sec


# --- 11. History rows + filters + exports ---

def test_history_rows_filters_exports():
    html = _html()
    sec = _slice(html, 'async function viewHist()', 'async function viewScanDetail')
    assert 'id="htype"' in sec and 'id="hprof"' in sec
    assert 'passive-recon' in sec and 'osint-deep' in sec and 'apk-static' in sec
    assert 'export?fmt=csv' in sec
    assert 'No matching scans' in sec
    assert '<th>Target</th>' not in sec  # table gone


# --- 12. Assets rows + sparkline + Delete + dirty Save ---

def test_assets_rows_sparkline_delete_save():
    html = _html()
    sec = _slice(html, 'async function viewAssets()', 'async function deleteAsset')
    assert 'asset-row' in sec
    assert 'viewBox="0 0 120 30"' in sec
    assert 'function ptAssetDirty' in html
    assert 'suppressions removed' in html
    assert 'No assets yet' in sec
    assert "showToast('Saved.'" in html


# --- 13. Schedules rows + button states + wording ---

def test_schedules_rows_button_states():
    html = _html()
    sec = _slice(html, 'async function viewSchedules()', 'async function createSchedule')
    assert 'id="schCreateBtn"' in sec
    assert 'function ptSchBtn' in html
    assert 'Saved Schedules' in sec
    assert 'Create Schedule' in sec
    assert 'every ${s.interval_h} h' in sec
    assert 'Previously saved scans will not be deleted' in html


# --- 14. Audit rows + Empty ---

def test_audit_rows_empty():
    html = _html()
    sec = _slice(html, 'async function viewAudit()', 'async function viewUsers')
    assert 'Loading audit log…' in sec
    assert '<div class="empty">Empty</div>' in sec
    assert '<th>Time</th>' not in sec  # table gone


# --- 15. New Scan wizard ---

def test_wizard_structure():
    html = _html()
    sec = _slice(html, 'function viewScan()', 'async function runScan()')
    for i in range(1, 6):
        assert f'id="ptPill{i}"' in sec
        assert f'id="ptStep{i}"' in sec
    assert 'function ptGoStep' in html
    assert 'function ptNextStep' in html
    assert 'function ptBuildReview' in html
    assert 'function ptScanErr' in html
    assert 'id="scanFormErr"' in sec
    assert 'id="ptNoAuthNote"' in sec
    assert 'Review & Launch' in sec
    assert 'This tool has no profile selection' in sec
    assert 'No advanced options for this tool.' in sec
    # artifact tool order in the grid
    order = ['data-t="vulnscan"', 'data-t="passive"', 'data-t="ports"',
             'data-t="subdomains"', 'data-t="dirs"', 'data-t="ssl"',
             'data-t="headers"', 'data-t="udp"', 'data-t="vhost"',
             'data-t="hybrid"', 'data-t="syn"']
    idx = [sec.index(t) for t in order]
    assert idx == sorted(idx), 'tool grid order is not artifact order'


def test_wizard_submit_guards_and_helpers():
    html = _html()
    assert "ptScanErr('Enter a target first.')" in html
    assert "ptScanErr('Extra headers are not valid JSON.')" in html
    assert "ptScanErr('Tick the authorization statement first…')" in html
    assert "STYPE === 'ports' || STYPE === 'udp' || STYPE === 'syn'" in html
    assert 'ptLongNote' in html
    assert 'ptQuickScan' in html and '_ptScanTool' in html
    assert '— QUEUED' in html and '— RUNNING' in html
    assert 'STOPPED' in html and 'FAILED' in html


# --- 16. Dashboard interactions ---

def test_dashboard_interactions():
    html = _html()
    assert 'Offensive Security &amp; Vulnerability Intelligence' in html
    assert 'Comprehensive security assessment for a stronger tomorrow.' in html
    assert 'Engine v1.2.1 · VANTHEX V1.2.1' in html
    assert '.pt-gauge-n{font-size:52px' in html
    assert '.pt-spec-pct{font-size:22px' in html
    assert '.pt-kpi-n{font-size:26px' in html
    assert 'title="View scan history" onclick="show(\'hist\')"' in html
    assert "_ptFindPreset={severity:'CRITICAL'};show('findings')" in html
    assert 'pt-spec-row" style="cursor:pointer"' in html
    for label in ['Web Application Testing', 'Mobile Application Testing',
                  'Passive Reconnaissance', 'OSINT Search', 'View Findings',
                  'Manage Assets', 'View Scan History', 'Generate Report']:
        assert label in html
    assert 'View All' in html
    assert 'function ptRecentExpand' in html
    assert 'Risk Score per Scan' in html
    assert 'pt-recent-${s.id}' in html


# --- Prior markers intact ---

def test_prior_markers_intact():
    html = _html()
    for deck in ['welcome', 'health', 'posture', 'kpi', 'quick', 'severity',
                 'liveops', 'trend', 'topvuln', 'brand', 'recent', 'insights']:
        assert f'data-deck="{deck}"' in html
    assert 'pt-spec-row' in html and 'pt-kpi-card' in html
    assert 'Recent activity (audit trail)' in html
    assert 'after 4 hours' in html
    assert 'glCardCloseOthers' in html
    assert 'ptDeckReset' in html
    assert 'VANTHEX V1.2.1' in html


# --- Untouched files pinned ---

def test_untouched_files_pinned():
    assert _md5('app2.py') == 'a9804483d2c3ec6779d0199be4e775b3'
    assert _md5('osint.py') == '65ec21c31b4aad76aa304fcb411388ae'
