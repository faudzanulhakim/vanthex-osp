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


# ---------------------------------------------------------------------------
# v1.9.2 — laporan mengikuti bahasa UI: KERANGKA terlokalisasi (12 bahasa),
# judul/deskripsi/bukti temuan (data engine) TIDAK pernah diterjemahkan.
# ---------------------------------------------------------------------------
import re

import report_common as RC
import report_i18n as RI


def _docx_all_text(path):
    z = zipfile.ZipFile(path)
    for part in z.namelist():  # OOXML valid di semua bahasa
        if part.endswith((".xml", ".rels")):
            DET.fromstring(z.read(part))
    import html as _H
    txt = ""
    for name in ("word/document.xml", "word/header1.xml", "word/footer1.xml"):
        txt += re.sub(r"<[^>]+>", " ", z.read(name).decode()) + " "
    return _H.unescape(txt)


def test_docx_report_follows_ui_language_id(tmp_path):
    path = str(tmp_path / "laporan_id.docx")
    generate_docx(dict(SCAN), [dict(f) for f in FINDINGS], path, lang="id")
    doc = _docx_all_text(path)
    # Kerangka Bahasa Indonesia
    for marker in ("LAPORAN UJI PENETRASI", "Kendali Dokumen",
                   "1. Ringkasan Eksekutif", "KRITIS", "Matriks Risiko",
                   RI.T["id"]["h_steps"], RI.T["id"]["h_poc"],
                   "14 Oktober 2026" if False else "Oktober 2026"):
        assert marker in doc, f"DOCX id kehilangan: {marker}"
    # Kerangka Inggris tidak boleh bocor
    assert "1. Executive Summary" not in doc
    assert "Document Control" not in doc
    # Data temuan tetap verbatim (tidak diterjemahkan)
    assert "SQL Injection (error-based): /item param 'id'" in doc
    assert "Payload injeksi memicu pesan error database." in doc
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in doc
    assert "TLP:AMBER" in doc


def test_docx_report_follows_ui_language_de(tmp_path):
    path = str(tmp_path / "bericht_de.docx")
    generate_docx(dict(SCAN), [dict(f) for f in FINDINGS], path, lang="de")
    doc = _docx_all_text(path)
    for marker in ("PENETRATIONSTEST-BERICHT", "Dokumentenkontrolle",
                   "1. Zusammenfassung für die Leitungsebene", "KRITISCH",
                   "Risikomatrix", "Oktober 2026"):
        assert marker in doc, f"DOCX de kehilangan: {marker}"
    assert "1. Executive Summary" not in doc
    assert "Payload injeksi memicu pesan error database." in doc


def test_docx_report_invalid_lang_defaults_english(tmp_path):
    path = str(tmp_path / "fallback.docx")
    generate_docx(dict(SCAN), [dict(f) for f in FINDINGS], path, lang="xx-YY")
    doc = _docx_all_text(path)
    assert "PENETRATION TEST REPORT" in doc
    assert "1. Executive Summary" in doc
    assert "Document Control" in doc


def test_html_report_follows_ui_language():
    out = html_report.render_report(dict(SCAN), [dict(f) for f in FINDINGS],
                                    lang="id")
    assert '<html lang="id">' in out
    for marker in ("Laporan Uji Penetrasi", "Kendali Dokumen",
                   "Ringkasan Eksekutif", "Matriks Risiko"):
        assert marker in out, f"HTML id kehilangan: {marker}"
    assert "Payload injeksi memicu pesan error database." in out
    out_en = html_report.render_report(dict(SCAN), [dict(f) for f in FINDINGS])
    assert '<html lang="en">' in out_en
    assert "Penetration Test Report" in out_en


def test_report_common_localized_framework():
    f = dict(FINDINGS[0])
    steps_id = RC.steps_for(f, "https://x", lang="id")
    assert steps_id[0].startswith("Buka aplikasi target")
    assert RC.steps_for(f, "https://x")[0].startswith(
        "Open the target application")
    assert RC.impact_for(f, lang="id").startswith("Penyerang dapat membaca")
    assert RC.impact_for(f).startswith("An attacker can read")
    refs_de = RC.refs_for(f, lang="de")
    assert any(r.startswith("Kategorie:") for r in refs_de)
    assert RI.norm_lang("pt-BR") == "pt" and RI.norm_lang("junk") == "en"


def test_actions_report_lang_plumbing(monkeypatch):
    import actions

    seen = {}

    def fake_call_service(port, method, path, payload=None, binary=False,
                          timeout=None):
        seen["path"] = path
        return {"down": False, "status": 200, "base64": "QUJD",
                "text": "<html>ok</html>", "error": ""}

    monkeypatch.setattr(actions, "call_service", fake_call_service)
    r = actions._a_get_report_docx({"scanId": "abc123", "lang": "id"}, 5000)
    assert r["base64"] == "QUJD"
    assert "fmt=docx&lang=id" in seen["path"]
    actions._a_get_report_docx({"scanId": "abc123", "lang": "xx"}, 5000)
    assert "lang=" not in seen["path"]
    actions._a_get_report_docx({"scanId": "abc123"}, 5000)
    assert "lang=" not in seen["path"]
    r = actions._a_get_report_html({"scanId": "abc123", "lang": "de"}, 5000)
    assert r["html"] == "<html>ok</html>"
    assert seen["path"].endswith("?lang=de")
