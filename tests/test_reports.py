"""Test generator laporan v3.4.1 — struktur standar industri/HackerOne harus ada
di HTML & DOCX, dan DOCX harus OOXML valid (semua part XML ter-parse)."""
import io
import json
import os
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from defusedxml import ElementTree as DET

import report as html_report
from docx_report import generate_docx

SCAN = {"id": "abc123def456", "target": "https://app.contoh.co.id/login",
        "profile": "enterprise-full", "started_at": 1792000000,
        "overall_risk": "CRITICAL",
        "summary": {"CRITICAL": 1, "HIGH": 1, "LOW": 1},
        "result": json.dumps({"risk_score": 88, "checks_run": 41, "checks_total": 41,
                              "duration_s": 42, "warnings": [],
                              "tech_profile": [
                                  {"name": "nginx", "category": "Web Server",
                                   "version": "1.24", "evidence": "Server: nginx/1.24"},
                                  {"name": "Stripe", "category": "Payment",
                                   "version": "", "evidence": "js.stripe.com/v3"}]})}
FINDINGS = [
    {"severity": "CRITICAL", "title": "SQL Injection (error-based): /item param 'id'",
     "description": "Payload injeksi memicu pesan error database.",
     "evidence": "payload='1\\'' -> error: You have an error in your SQL syntax",
     "cwe": "CWE-89", "owasp": "A03:2021 Injection", "cvss": 9.8,
     "remediation": "Gunakan parameterized queries.", "confidence": "confirmed",
     "status": "open", "location": "/item", "param": "id"},
    {"severity": "HIGH", "title": "IDOR/BOLA indication: /api/orders",
     "description": "Objek dapat diakses lintas konteks.",
     "evidence": "id 1001 vs 1002 sama-sama 200", "cwe": "CWE-639",
     "owasp": "A01:2021 Broken Access Control", "cvss": 8.1,
     "remediation": "Periksa otorisasi per objek.", "confidence": "probable",
     "status": "open", "location": "/api/orders", "param": "id",
     "assignee": "Tim Backend", "due_date": "2026-11-01"},
    {"severity": "LOW", "title": "Header keamanan tidak ada: X-Frame-Options",
     "description": "Header clickjacking protection absen.", "evidence": "tidak ada header",
     "cwe": "CWE-1021", "owasp": "A05:2021", "cvss": 3.1,
     "remediation": "Set X-Frame-Options: DENY.", "confidence": "confirmed",
     "status": "fixed", "location": "/", "param": ""},
]

MUST_HAVE = ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  # vektor SQLi
             "Proof of Concept", "Appendix C",
             "Steps to Reproduce", "Supporting Material", "Risk Matrix",
             "TLP:AMBER"]


EMOJI_FORBIDDEN = ["🛡", "✅", "🟡", "🔎", "⚠", "🧬", "🔧", "🎯", "📍", "🚀"]


def test_html_report_structure():
    out = html_report.render_report(dict(SCAN), [dict(f) for f in FINDINGS])
    for marker in MUST_HAVE:
        assert marker in out, f"HTML kehilangan: {marker}"
    assert "F-001" in out and "Tim Backend" in out and "2026-11-01" in out
    assert "Technology &amp; Integration Profile" in out and "Stripe" in out and "nginx" in out
    # v3.5.1: format formal — sampul resmi, daftar isi, tanpa emoji dekoratif
    assert "Penetration Test Report" in out and "Contents" in out
    assert "Document Control" in out and "Version History" in out
    for e in EMOJI_FORBIDDEN:
        assert e not in out, f"HTML mengandung emoji non-formal: {e}"


def test_docx_report_structure_and_validity(tmp_path):
    path = str(tmp_path / "laporan.docx")
    generate_docx(dict(SCAN), [dict(f) for f in FINDINGS], path)
    z = zipfile.ZipFile(path)
    names = set(z.namelist())
    assert {"word/header1.xml", "word/footer1.xml", "word/document.xml"} <= names
    doc = ""
    for name in names:  # semua part XML harus ter-parse (OOXML valid)
        if name.endswith(".xml") or name.endswith(".rels"):
            DET.fromstring(z.read(name))
        if name == "word/document.xml":
            doc = z.read(name).decode()
    for marker in MUST_HAVE + ["headerReference", "TOC", "CVSS Vector",
                               "Technology &amp; Integration Profile", "Stripe"]:
        assert marker in doc, f"DOCX kehilangan: {marker}"
    for marker in ("PENETRATION TEST REPORT", "Document Control", "Version History",
                   "Contents", "4.1 F-001", "Consolas"):
        assert marker in doc, f"DOCX kehilangan penanda formal: {marker}"
    for e in EMOJI_FORBIDDEN:
        assert e not in doc, f"DOCX mengandung emoji non-formal: {e}"
    ftr = z.read("word/footer1.xml").decode()
    assert "PAGE" in ftr and "NUMPAGES" in ftr
