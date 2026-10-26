"""v1.2.1 TOTAL parity port — RETIRED 2026-10-26 (artifact-UI port).

This suite previously asserted the total-parity port inside the
classic dashboard (templates/app.html): Health panel on top, Engine
Reference, shell extras (palette/bell/accent/deck), Command Deck
order, Severity Spectrum percentages, version display, 4-hour Service
Session, merged shortcuts, alert-click card-only, and app2.py/osint.py
MD5 pins.

ADE's 2026-10-26 09:50 WIB order removed classic entirely
(templates/app.html DELETED, /classic 404s); the dashboard now IS the
artifact UI bundle served at /. Those template assertions no longer
have a subject and are RETIRED here — not faked. The app2.py MD5 pin
is also dropped: app2.py legitimately changed in this port (new
/artifact-assets/ route, / flip, /classic removal). K13 note: the
classic-only cells (Findings Distribution, Unique Targets card) are
accepted as absent in the artifact UI per ADE's decision — their old
foldings in this suite are retired with everything else.

What survives as still-true invariants is kept below. Dashboard
parity is now verified against the real bundle at integration
(design §7), owned by the coordinator — not by this file.
"""
import hashlib
import os

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP2 = os.path.join(TREE, "app2.py")
OSINT = os.path.join(TREE, "osint.py")

OSINT_MD5 = "65ec21c31b4aad76aa304fcb411388ae"


def md5(path):
    h = hashlib.md5()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def test_classic_template_retired():
    assert not os.path.exists(
        os.path.join(TREE, "templates", "app.html"))
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    assert 'path == "/classic"' not in src
    assert 'load_template("app.html")' not in src


def test_version_stays_1_2_1():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read()
    assert 'server_version = "VANTHEX/1.2.1"' in src


def test_osint_byte_identical():
    assert md5(OSINT) == OSINT_MD5
