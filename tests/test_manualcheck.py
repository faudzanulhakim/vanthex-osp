"""Per-finding manual validation commands (manualcheck.py) — hermetic tests."""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from offensive import manualcheck
import report as _report
import vulnscan2
import exploitkit


def _mc(finding):
    mc = manualcheck.build_manual_check(finding)
    assert mc, "build_manual_check returned empty dict"
    assert mc["commands"] and 1 <= len(mc["commands"]) <= 4
    assert mc["vulnerable_if"] and mc["safe_if"]
    assert all(isinstance(c, str) and c for c in mc["commands"])
    return mc


def _assert_param(mc, param, url_fragment=""):
    blob = " ".join(mc["commands"]) + mc["title"]
    if param:
        assert param in blob, f"param {param!r} missing from commands"
    if url_fragment:
        assert url_fragment in blob


def test_cmdi():
    f = vulnscan2.F("HIGH", "OS Command Injection", "d", cwe="CWE-78",
                    location="http://t/ping", param="host")
    mc = _mc(f)
    assert "curl" in " ".join(mc["commands"])
    assert "host" in " ".join(mc["commands"]) and "ping" in " ".join(mc["commands"])
    assert "%24%28id%29" in " ".join(mc["commands"])  # encoded $(id)


def test_sqli():
    f = vulnscan2.F("HIGH", "SQL Injection", "d", cwe="CWE-89",
                    location="http://t/item", param="id")
    mc = _mc(f)
    blob = " ".join(mc["commands"])
    assert "id=" in blob and "%27" in blob  # encoded apostrophe
    assert "id" in mc["title"]


def test_xss():
    f = vulnscan2.F("MEDIUM", "Reflected XSS", "d", cwe="CWE-79",
                    location="http://t/s", param="q")
    mc = _mc(f)
    blob = " ".join(mc["commands"])
    assert "q=" in blob and "%3Csvg" in blob
    assert "q" in mc["title"]


def test_xss_dom():
    f = vulnscan2.F("MEDIUM", "DOM-based XSS via location.hash", "d",
                    cwe="CWE-79", location="http://t/#", param="name")
    mc = _mc(f)
    assert "devtools" in mc["title"].lower() or "devtools" in \
        " ".join(mc["commands"]).lower() or "innerHTML" in " ".join(mc["commands"])


def test_ssrf():
    f = vulnscan2.F("HIGH", "Server-Side Request Forgery (SSRF)", "d",
                    cwe="CWE-918", location="http://t/fetch", param="url")
    mc = _mc(f)
    blob = " ".join(mc["commands"])
    assert "169.254.169.254" in blob and "url=" in blob


def test_traversal():
    f = vulnscan2.F("HIGH", "Path Traversal", "d", cwe="CWE-22",
                    location="http://t/download", param="file")
    mc = _mc(f)
    blob = " ".join(mc["commands"])
    assert "%2Fetc%2Fpasswd" in blob and "file=" in blob


def test_ldap_nosql():
    f = vulnscan2.F("HIGH", "NoSQL Injection", "d", cwe="CWE-943",
                    location="http://t/u", param="user")
    mc = _mc(f)
    assert mc["commands"]
    f2 = vulnscan2.F("HIGH", "LDAP Injection", "d", cwe="CWE-90",
                     location="http://t/ldap", param="uid")
    mc2 = _mc(f2)
    assert "uid=" in " ".join(mc2["commands"])


def test_open_redirect():
    f = vulnscan2.F("MEDIUM", "Open Redirect", "d", cwe="CWE-601",
                    location="http://t/go", param="next")
    mc = _mc(f)
    blob = " ".join(mc["commands"]) + mc["vulnerable_if"]
    assert "next=https%3A%2F%2F" in blob and "Location" in blob


def test_takeover():
    f = vulnscan2.F("HIGH", "Subdomain Takeover", "d", cwe="CWE-350",
                    location="", param="", evidence="blog.victim.example.com")
    mc = _mc(f)
    assert "dig" in " ".join(mc["commands"])


def test_header_missing():
    f = vulnscan2.F("LOW", "Missing security header: Content-Security-Policy",
                    "d", cwe="CWE-693", location="http://t/",
                    remed="Set Content-Security-Policy: default-src 'self'.")
    mc = _mc(f)
    blob = " ".join(mc["commands"])
    assert "curl -sI" in blob and "Content-Security-Policy" in blob


def test_version_disclosure():
    f = vulnscan2.F("INFO", "Server version disclosure", "d", cwe="CWE-200",
                    location="http://t/")
    mc = _mc(f)
    assert "curl -sI" in " ".join(mc["commands"])


def test_generic_fallback():
    f = vulnscan2.F("MEDIUM", "Unusual Error Page Behavior", "d",
                    location="http://t/x", param="p",
                    evidence="anomalous response difference")
    mc = _mc(f)
    blob = " ".join(mc["commands"])
    assert "baseline.html" in blob and "diff" in blob and "p=" in blob


def test_generic_no_location():
    f = vulnscan2.F("LOW", "Odd Finding", "d")
    mc = manualcheck.build_manual_check(f)
    assert mc and mc["commands"] and mc["vulnerable_if"] and mc["safe_if"]


def test_f_attaches_manual_check():
    f = vulnscan2.F("HIGH", "SQL Injection", "d", cwe="CWE-89",
                    location="http://t/item", param="id")
    assert isinstance(f.get("manual_check"), dict)
    assert f["manual_check"]["commands"]
    f2 = vulnscan2.F("LOW", "Something", "d")
    assert isinstance(f2.get("manual_check"), dict)


def test_exploitkit_F_attaches():
    f = exploitkit._F("HIGH", "SQL Injection", "d", cwe="CWE-89",
                      location="http://t/item", param="id")
    assert isinstance(f.get("manual_check"), dict)
    assert f["manual_check"]["commands"]


def test_build_never_raises():
    assert manualcheck.build_manual_check(None) == {}
    assert manualcheck.build_manual_check("nope") == {}
    assert manualcheck.build_manual_check({"title": "x", "location": "http://t"})


# ---- report rendering ---------------------------------------------------

def _findings_for_report():
    f = vulnscan2.F("HIGH", "SQL Injection", "desc", cwe="CWE-89",
                    location="http://t/item", param="id",
                    evidence="db error shown")
    return [f]


def test_report_html_contains_manual_validation():
    findings = _findings_for_report()
    html = _report.render_report({"target": "http://t",
                                  "meta": {"scan_id": "s1"}},
                                 findings)
    assert "Manual validation" in html
    import html as _H
    first_cmd = _H.escape(findings[0]["manual_check"]["commands"][0])
    assert first_cmd in html
    assert "Vulnerable if:" in html and "Safe if:" in html


def test_report_html_graceful_without_manual_check():
    findings = [{"severity": "LOW", "title": "Old finding",
                 "description": "d", "evidence": "", "cwe": "CWE-200",
                 "owasp": "", "cvss": 0, "remediation": "",
                 "confidence": "probable", "location": "http://t",
                 "param": "", "origin": "passive",
                 "verification": "signature"}]
    html = _report.render_report({"target": "http://t",
                                  "meta": {"scan_id": "s1"}},
                                 findings)
    assert "Manual validation" not in html
    assert "Old finding" in html


def test_docx_contains_manual_validation(tmp_path):
    import docx_report
    findings = _findings_for_report()
    out = str(tmp_path / "r.docx")
    docx_report.generate_docx({"target": "http://t",
                               "meta": {"scan_id": "s1"}}, findings, out)
    import zipfile
    with zipfile.ZipFile(out) as z:
        blob = z.read("word/document.xml").decode("utf-8")
    assert "Manual validation" in blob
    assert "Vulnerable if:" in blob and "Safe if:" in blob
    # commands rendered in monospace runs
    assert 'w:ascii="Consolas"' in blob


def test_docx_graceful_without_manual_check(tmp_path):
    import docx_report
    findings = [{"severity": "LOW", "title": "Old finding",
                 "description": "d", "evidence": "", "cwe": "CWE-200",
                 "owasp": "", "cvss": 0, "remediation": "",
                 "confidence": "probable", "location": "http://t",
                 "param": "", "origin": "passive",
                 "verification": "signature"}]
    out = str(tmp_path / "r2.docx")
    docx_report.generate_docx({"target": "http://t",
                               "meta": {"scan_id": "s1"}}, findings, out)
    import zipfile
    with zipfile.ZipFile(out) as z:
        blob = z.read("word/document.xml").decode("utf-8")
    assert "Manual validation" not in blob
    assert "Old finding" in blob
