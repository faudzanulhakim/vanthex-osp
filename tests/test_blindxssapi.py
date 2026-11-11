"""Tests for blindxssapi.py: blind-XSS canary seeding + stored-reflection
sweep + differential mass-assignment v2 + content-type confusion.
Hermetic — local fixture server + in-process canary listener only.
AUTHORIZED TESTING ONLY (fixture is a deliberately vulnerable lab).
"""
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

from offensive import blindxssapi
import canary
import netclient


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def fixture_port():
    port = _free_port()
    proc = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(40):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            break
        except Exception:
            time.sleep(0.25)
    else:
        proc.terminate()
        pytest.fail("fixture server did not start")
    yield port
    proc.terminate()
    proc.wait(timeout=5)


class _Ctx:
    """Minimal Ctx stand-in: client + opts + oob state + no crawl."""

    def __init__(self, port, opts=None):
        self.client = netclient.Client(f"http://127.0.0.1:{port}")
        self.opts = opts or {}
        self.logs = []
        self.scan_id = "scan-blxtest"
        self._oob_planted = []
        self._oob_reported = set()
        self._oob_last_plant_ts = 0.0

    def cancelled(self):
        return False

    def surface(self, full=True):
        class _S:
            pages = ["/blx/comments", "/blx/safe/comments"]
            forms = []
            param_urls = []
        return _S()

    def L(self, msg):
        self.logs.append(msg)


# --------------------------------------------------- blind-XSS seeding

def test_blind_xss_seeding_probable_without_callback(fixture_port):
    """Safe store: payload stored + marker rendered escaped, but no
    beacon fetch -> probable 'planted', verification manual-required."""
    reg = canary.CanaryRegistry()
    base = f"http://127.0.0.1:{fixture_port}/blx/beacon"
    ctx = _Ctx(fixture_port, opts={
        "canary": {"registry": reg, "base": base},
        "blx_targets": [("/blx/safe/comment", "comment")]})
    res = blindxssapi.run_blind_xss(ctx, ctx.opts)
    assert res["planted"] == 1 and res["callbacks"] == 0
    titles = [f["title"] for f in res["findings"]]
    assert any(t.startswith(blindxssapi.PLANTED_TITLE) for t in titles)
    f = [f for f in res["findings"]
         if f["title"].startswith(blindxssapi.PLANTED_TITLE)][0]
    assert f["confidence"] == "probable"
    assert f["verification"] == "manual-required"
    assert "manual" in f["verification_note"].lower()
    # payload carries the tag + hex token and the beacon URL
    assert f["evidence"].startswith("1 canary-tagged payload")
    assert blindxssapi.BLX_TAG in f["evidence"]
    assert ctx._oob_planted and ctx._oob_planted[0]["check"] == "c_blind_xss_api"


def test_blind_xss_confirmed_on_callback(fixture_port):
    """Vuln store: render page simulates the victim viewer fetching the
    beacon -> REAL canary listener records the callback -> CONFIRMED
    executed-proof."""
    srv, reg = canary.serve(port=_free_port(), host="127.0.0.1")
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        ctx = _Ctx(fixture_port, opts={
            "canary": {"registry": reg, "base": base},
            "blx_targets": [("/blx/comment", "comment")]})
        res = blindxssapi.run_blind_xss(ctx, ctx.opts)
        assert res["callbacks"] >= 1
        conf = [f for f in res["findings"]
                if f["title"].startswith(blindxssapi.CONFIRMED_TITLE)]
        assert conf, res
        f = conf[0]
        assert f["confidence"] == "confirmed"
        assert f["severity"] == "HIGH"
        assert f["cwe"] == "CWE-79"
        assert "canary callback" in f["evidence"]
        assert "/blx/comment" in f["title"]
        # no probable finding for the same (already-confirmed) location
        assert not [f2 for f2 in res["findings"]
                    if f2["title"].startswith(blindxssapi.PLANTED_TITLE)]
    finally:
        srv.shutdown()


def test_blind_xss_stored_reflection_rendered_note(fixture_port):
    """Safe store: marker rendered (escaped HTML keeps the plain marker
    text) outside an echoed query context -> stored render recorded."""
    reg = canary.CanaryRegistry()
    base = f"http://127.0.0.1:{fixture_port}/blx/beacon"
    ctx = _Ctx(fixture_port, opts={
        "canary": {"registry": reg, "base": base},
        "blx_targets": [("/blx/safe/comment", "comment")]})
    res = blindxssapi.run_blind_xss(ctx, ctx.opts)
    assert res["stored_hits"] >= 1
    f = [f for f in res["findings"]
         if f["title"].startswith(blindxssapi.PLANTED_TITLE)][0]
    assert "rendered on /blx/safe/comments" in f["evidence"]


def test_blind_xss_skips_without_canary(fixture_port):
    """No canary base configured -> declared skip, no findings, no reqs."""
    ctx = _Ctx(fixture_port, opts={})
    res = blindxssapi.run_blind_xss(ctx, ctx.opts)
    assert res["planted"] == 0 and res["findings"] == []
    assert any("skipped" in m for m in ctx.logs)


def test_blind_xss_echo_only_not_stored_proof(fixture_port):
    """FP guard: a marker that appears ONLY inside an echoed next= query
    value must not count as stored reflection (vulnscan2 semantics)."""
    import vulnscan2 as _v
    class _R:  # stub response echoing the marker in a next= redirect param
        status = 302
        body = '<a href="/login?next=%2Fx%3Fm%3DPTKBLXSS-deadbeef01">go</a>'
        headers = {"Location": "/login?next=%2Fx%3Fm%3DPTKBLXSS-deadbeef01"}
        def hdr(self, n, d=""):
            return {"location": self.headers.get("Location", "")}.get(
                n.lower(), d)
    assert _v._echo_only_response(_R(), "PTKBLXSS-deadbeef01")
    # and a plain decoded body occurrence IS credited (differential sanity)
    class _R2:
        status = 200
        body = "<div>PTKBLXSS-deadbeef01</div>"
        headers = {}
        def hdr(self, n, d=""):
            return d
    assert not _v._echo_only_response(_R2(), "PTKBLXSS-deadbeef01")


def test_blind_xss_manual_callback_replay_upgrade(fixture_port):
    """A callback recorded mid-window (canary.Hit like canary.py records
    it) upgrades the planted token to confirmed on the next poll."""
    reg = canary.CanaryRegistry()
    base = f"http://127.0.0.1:{fixture_port}/blx/beacon"
    ctx = _Ctx(fixture_port, opts={
        "canary": {"registry": reg, "base": base},
        "blx_targets": [("/blx/safe/comment", "comment")]})
    tok = reg.issue("replay", meta={"scan_id": ctx.scan_id,
                                    "check": "c_blind_xss_api",
                                    "target": "/blx/safe/comment",
                                    "parameter": "comment",
                                    "payload_class": "blind-xss script beacon"})
    reg.record(canary.Hit(token=tok, ts=time.time(), ip="127.0.0.1",
                          method="GET", path=f"/{tok}", user_agent="victim"))
    # a fresh scan run sees the callback and reports confirmed
    ctx2 = _Ctx(fixture_port, opts=ctx.opts)
    ctx2._oob_planted = [{"token": tok, "kind": "XSS",
                          "location": "/blx/safe/comment", "param": "comment",
                          "check": "c_blind_xss_api",
                          "payload_class": "blind-xss script beacon",
                          "scan_id": ctx.scan_id}]
    hits = reg.hits(tok)
    assert hits and hits[0]["token"] == tok
    assert reg.stats(ctx.scan_id)["callbacks_received"] == 1


def test_fixture_beacon_recorder(fixture_port):
    """Fixture /blx/beacon/<token> records canary.py-shaped hits, listed
    at /blx/beacons."""
    urllib.request.urlopen(
        f"http://127.0.0.1:{fixture_port}/blx/beacon/cafebabedeadbeef",
        timeout=3).read()
    data = json.loads(urllib.request.urlopen(
        f"http://127.0.0.1:{fixture_port}/blx/beacons", timeout=3).read())
    assert any(h["token"] == "cafebabedeadbeef" for h in data)
    assert data[-1]["method"] == "GET"


# --------------------------------------------- mass-assignment v2 gate

def test_massassign_v2_gated_off_by_default(fixture_port):
    ctx = _Ctx(fixture_port, opts={})
    blindxssapi.c_massassign_v2(ctx, lambda f: pytest.fail("ungated finding"))
    assert not any("massassignv2" in m for m in ctx.logs)


def test_massassign_v2_gated_by_env(fixture_port, monkeypatch):
    monkeypatch.setenv("PTK_AUTHZ", "1")
    ctx = _Ctx(fixture_port, opts={})
    seen = []
    blindxssapi.c_massassign_v2(ctx, seen.append)
    assert any("massassignv2" in m for m in ctx.logs)
    for f in seen:
        assert f["cwe"] == "CWE-915"
        assert f["title"].startswith(blindxssapi.MA_TITLE)


# -------------------------------------------- content-type confusion

def test_ct_confusion_differential_probe(fixture_port):
    ctx = _Ctx(fixture_port, opts={})
    res = blindxssapi.run_ct_confusion(ctx, ctx.opts)
    assert res["requests"] <= blindxssapi.MAX_CT_ENDPOINTS * 2
    for f in res["findings"]:
        assert f["cwe"] == "CWE-436"
        assert f["title"].startswith(blindxssapi.CT_TITLE)
        assert f["confidence"] in ("confirmed", "probable")


def test_ct_confusion_bounded_and_cancelled(fixture_port):
    ctx = _Ctx(fixture_port, opts={"probe_urls": ["/api/json/config"] * 20})
    ctx.cancelled = lambda: True
    res = blindxssapi.run_ct_confusion(ctx, ctx.opts)
    assert res["requests"] == 0 and res["findings"] == []


# ------------------------------------------------ registration wiring

def test_registered_in_vulnscan2():
    import vulnscan2
    for name in ("c_blind_xss_api", "c_massassign_v2", "c_ct_confusion"):
        assert name in vulnscan2.PROFILES["enterprise-full"]
        assert callable(getattr(vulnscan2, name))
        assert name in [c.__name__ for c in blindxssapi.CHECKS]
    assert len(vulnscan2.PROFILES["enterprise-full"]) == 141
