"""v1.2.1 VISUAL parity pass — RETIRED 2026-10-26 (artifact-UI port).

This suite previously asserted the visual restyle inside the classic
dashboard (templates/app.html): topbar search pill, theme/logout
buttons, welcome hero, health waveform, posture gauge, spectrum big
percentages, KPI sparklines, deck order/grid pairing, deck-apply
never hiding, version strings, merged shortcuts + alert card-only,
posture label words, dashboard title-block removal, and app2.py/
osint.py MD5 pins.

ADE's 2026-10-26 09:50 WIB order removed classic entirely
(templates/app.html DELETED, /classic 404s); appearance now comes
from the artifact UI bundle served at /, not from restyling classic.
Those template assertions no longer have a subject and are RETIRED
here — not faked. The app2.py MD5 pin is also dropped: app2.py
legitimately changed in this port (new /artifact-assets/ route,
/ flip, /classic removal).

What survives as still-true invariants is kept below. Visual parity
is now verified against the real bundle at integration (design §7
side-by-side screenshot checklist), owned by the coordinator — not
by this file.
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
