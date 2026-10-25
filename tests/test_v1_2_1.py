"""v1.2.1 — relabel ONLY: service version line 1.25.0 -> 1.2.1.

Decision (ADE, 2026-10-25 20:09 WIB): the GitHub release line was last
pushed at v1.1.1, so 1.2.1 is the next release on ADE's GitHub line.
This relabel REPLACES the service version line 1.25.0. The number
1.2.1 reads lower than 1.25.0; that is a consequence ADE accepted
with the order. It is NOT a downgrade of features: no behaviour,
feature, CSP, database content, or engine code changes here.

Scope (user-visible version strings ONLY):
- app2.py API "version" field, Server header, startup print
- templates/app.html globe badge (gl-ver)
- report.py / docx_report.py VERSION (report footers)
- globe_feeds.py User-Agent (product version identity)
- DOCKER.md / INSTALL.md "**Version ...**" headers (they state the
  running version; they were stale at 1.9.0, now 1.2.1)
- README.md has NO version header (verified) — nothing to change
- templates/login.html has NO version string (verified) — nothing

Deliberately UNCHANGED (history, not user-visible version):
- code comments mentioning v1.25.0 (CSP gate note, §16.7 notes)
- globe_feeds.py module docstring / dated comments
- AUDIT.md / UPGRADE_NOTES.md / all older suites (history)
- DOCKER.md tag EXAMPLES (1.9.0 examples, not version statements)
- osint.py byte-identical; CSP byte-identical (F6 + img-src s3 only)

All tests below are hermetic (source text only, no live hosts,
no DB, no credentials). Live header/CSP/badge verification is a
separate post-deploy step, not part of this suite.
"""

import hashlib
import os
import py_compile
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


APP2 = _read("app2.py")
HTML = _read(os.path.join("templates", "app.html"))
LOGIN = _read(os.path.join("templates", "login.html"))
REPORT = _read("report.py")
DOCX = _read("docx_report.py")
FEEDS = _read("globe_feeds.py")
DOCKER = _read("DOCKER.md")
INSTALL = _read("INSTALL.md")
OSINT_MD5 = hashlib.md5(
    open(os.path.join(ROOT, "osint.py"), "rb").read()).hexdigest()

# CSP value UNCHANGED from v1.25.0 (F6 + img-src s3.amazonaws.com only).
CSP_CURRENT = ("default-src 'self'; script-src 'self' 'unsafe-inline'; "
               "style-src 'self' 'unsafe-inline'; img-src 'self' data: "
               "https://server.arcgisonline.com https://tilecache.rainviewer.com "
               "https://nowcoast.noaa.gov https://tiles.basemaps.cartocdn.com "
               "https://s3.amazonaws.com; "
               "connect-src 'self' https://api.rainviewer.com "
               "https://basemaps.cartocdn.com https://tiles.basemaps.cartocdn.com "
               "https://tiles-a.basemaps.cartocdn.com https://tiles-b.basemaps.cartocdn.com "
               "https://tiles-c.basemaps.cartocdn.com https://tiles-d.basemaps.cartocdn.com; "
               "frame-src https://www.youtube-nocookie.com; "
               "worker-src 'self' blob:; frame-ancestors 'none'; "
               "object-src 'none'; base-uri 'self'; form-action 'self'")


def test_version_pins_1_2_1():
    assert '"version": "1.2.1"' in APP2
    assert 'server_version = "VANTHEX/1.2.1"' in APP2
    assert "VANTHEX Offensive Security Platform v1.2.1" in APP2
    assert '<span class="gl-ver">VANTHEX 1.2.1</span>' in HTML
    assert 'VERSION = "1.2.1"' in REPORT
    assert 'VERSION = "1.2.1"' in DOCX
    assert "VANTHEX/1.2.1 (OSINT globe;" in FEEDS


def test_no_stale_user_visible_version():
    # The user-visible lines themselves must not still say 1.25.0.
    # (Comments/history elsewhere may still mention 1.25.0 legitimately.)
    for line in APP2.split("\n"):
        if '"version":' in line or "server_version" in line \
                or "Offensive Security Platform v1" in line:
            assert "1.25.0" not in line, line.strip()[:120]
    for line in HTML.split("\n"):
        if "gl-ver" in line:
            assert "1.25.0" not in line, line.strip()[:120]
    for src in (REPORT, DOCX):
        for line in src.split("\n"):
            if line.startswith("VERSION ="):
                assert "1.25.0" not in line, line.strip()[:120]
    for line in FEEDS.split("\n"):
        if "User-Agent" in line:
            assert "1.25.0" not in line, line.strip()[:120]


def test_csp_unchanged():
    out = []
    for m in re.finditer(
            r'self\.send_header\("Content-Security-Policy",\s*(.*?)\)',
            APP2, re.S):
        parts = re.findall(r'"([^"]*)"', m.group(1))
        out.append("".join(parts))
    assert len(out) == 2, out
    assert out[0] == CSP_CURRENT
    assert out[1] == CSP_CURRENT


def test_osint_byte_identical():
    assert OSINT_MD5 == "65ec21c31b4aad76aa304fcb411388ae"


def test_docs_version_headers():
    assert "**Version 1.2.1**" in DOCKER
    assert "**Version 1.2.1**" in INSTALL
    assert "**Version 1.9.0**" not in DOCKER
    assert "**Version 1.9.0**" not in INSTALL


def test_login_has_no_version_badge():
    # Verified finding: login.html carries no version string, so the
    # relabel correctly leaves it untouched.
    assert not re.search(r"VANTHEX 1\.\d", LOGIN)
    assert "1.2.1" not in LOGIN


def test_edited_python_parses():
    for rel in ("app2.py", "report.py", "docx_report.py", "globe_feeds.py"):
        py_compile.compile(os.path.join(ROOT, rel), doraise=True)
