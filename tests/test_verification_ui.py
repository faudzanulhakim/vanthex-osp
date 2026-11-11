"""Verification is operator-facing only: removed from DOCX/HTML reports,
exposed to the web UI via the findings table."""
import os
import sys
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import docx_report
import report as _report
import store


def _finding_with_verification():
    return {
        "severity": "LOW", "title": "Old finding",
        "description": "d", "evidence": "", "cwe": "CWE-200",
        "owasp": "", "cvss": 0, "remediation": "",
        "confidence": "probable", "location": "http://t",
        "param": "", "origin": "passive",
        "verification": "signature",
        "verification_note": "matched a content signature",
    }


# ---- DOCX report ---------------------------------------------------------

def test_docx_has_no_verification_but_keeps_manual_validation(tmp_path):
    f = _finding_with_verification()
    f["manual_check"] = {"title": "Check it", "commands": ["curl -s http://t"],
                         "vulnerable_if": "x", "safe_if": "y"}
    out = str(tmp_path / "r.docx")
    docx_report.generate_docx({"target": "http://t", "meta": {"scan_id": "s1"}},
                              [f], out)
    with zipfile.ZipFile(out) as z:
        blob = z.read("word/document.xml").decode("utf-8")
    assert "Verification:" not in blob
    assert "Verification note" not in blob
    assert "Manual validation" in blob
    # candidate impact potential stays
    assert "Old finding" in blob


def test_docx_no_verification_summary_row(tmp_path):
    out = str(tmp_path / "r2.docx")
    docx_report.generate_docx({"target": "http://t", "meta": {"scan_id": "s1"}},
                              [_finding_with_verification()], out)
    with zipfile.ZipFile(out) as z:
        blob = z.read("word/document.xml").decode("utf-8")
    assert "verification status" not in blob.lower()


# ---- HTML report ---------------------------------------------------------

def test_html_has_no_verification_but_keeps_manual_validation():
    f = _finding_with_verification()
    f["manual_check"] = {"title": "Check it", "commands": ["curl -s http://t"],
                         "vulnerable_if": "x", "safe_if": "y"}
    html = _report.render_report({"target": "http://t",
                                  "meta": {"scan_id": "s1"}}, [f])
    assert "Verification:" not in html
    assert "Verification note" not in html
    assert "Manual validation" in html
    assert "Old finding" in html


# ---- store round-trip ----------------------------------------------------

def test_store_round_trip_verification(monkeypatch, tmp_path):
    monkeypatch.setattr(store, "DB_PATH", str(tmp_path / "t.db"))
    store.init_db()
    f = _finding_with_verification()
    scan_id = store.save_scan("http://t", "web", "standard",
                              {"findings": [f], "summary": {}})
    rows = store.list_findings_global()
    assert len(rows) == 1
    assert rows[0]["verification"] == "signature"
    rows2 = store.get_findings(scan_id)
    assert rows2[0]["verification"] == "signature"
    # scan-detail API path (app2.py) uses the same get_findings rows
    keys = rows2[0].keys()
    assert "verification" in keys


# ---- web bundle ----------------------------------------------------------

def test_bundle_shows_verification_badge_on_finding_cards():
    p = os.path.join(ROOT, "web", "assets", "index-zx0p0xvc.js")
    s = open(p, encoding="utf-8").read()
    # normalizer carries the field through
    assert "verification:_(t.verification)" in s
    # card renders a Verification badge right after the confidence badge
    assert 'r(fs,{conf:e.confidence}),e.verification?r(Z,{text:"Verification: "' in s
