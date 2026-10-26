"""v1.2.1 parity suite — RETIRED 2026-10-26 (artifact-UI port).

This suite previously asserted the classic dashboard
(templates/app.html): CARD RAIL, POLES, SAT-GLOBE, LIVE-REFRESH,
GLASS UI, DEEP ZOOM SAT, plus node-evaluated pure globe helpers
extracted from that template. ADE's 2026-10-26 09:50 WIB order removed
classic entirely (templates/app.html DELETED, /classic 404s); the
artifact UI is now served as a bundle at / instead of a restyled
classic. Those template assertions therefore no longer have a subject
and are RETIRED here — not faked, not re-pointed at the placeholder
bundle index (which is not artifact content).

What survives as still-true invariants is kept below: version stays
1.2.1, osint.py byte-identical, no forbidden hosts in the service
source. The live parity bar is now the side-by-side screenshot
checklist against the real bundle at integration (design §7), owned
by the coordinator — not by this file.
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
    assert "VANTHEX/1.26" not in src


def test_osint_byte_identical():
    assert md5(OSINT) == OSINT_MD5


def test_no_forbidden_hosts_in_service_source():
    with open(APP2, encoding="utf-8") as fh:
        src = fh.read().lower()
    for host in ("aisstream", "wsdot", "511on", "toronto.ca"):
        assert host not in src
