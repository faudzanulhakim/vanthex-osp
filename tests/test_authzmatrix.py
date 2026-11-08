"""Tests for authzmatrix.py (v1.2.2): authorization matrix + BOLA +
SPA endpoint mining. Hermetic — runs the local fixture server only.
AUTHORIZED TESTING ONLY (fixture is a deliberately vulnerable lab).
"""
import json
import os
import socket
import subprocess
import sys
import time
import types
import urllib.request

import pytest

import authzmatrix
import netclient

PORT = 18099


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
    """Minimal Ctx stand-in: client + crawl-backed surface."""

    def __init__(self, port, opts=None):
        self.client = netclient.Client(f"http://127.0.0.1:{port}")
        self.opts = opts or {}
        self.logs = []
        self._surf = None

    def surface(self, full=True):
        if self._surf is None:
            import crawler
            self._surf = crawler.crawl(self.client, max_pages=3)
        return self._surf

    def cancelled(self):
        return False

    def L(self, msg):
        self.logs.append(msg)


SESS = {"low": {"X-Test-User": "user1"}, "high": {"X-Test-User": "admin"}}


def test_idor_confirmed_with_two_sessions(fixture_port):
    ctx = _Ctx(fixture_port, opts={
        "authz_matrix": True, "sessions": SESS,
        "object_urls": ["/api/user/1002/profile"]})
    res = authzmatrix.run_authz_matrix(ctx, ctx.opts)
    idor = [f for f in res["findings"]
            if f["title"] == authzmatrix.IDOR_TITLE]
    assert idor, f"expected IDOR finding, got {res}"
    f = idor[0]
    assert f["confidence"] == "confirmed"
    assert f["severity"] == "HIGH"
    assert f["cvss"] == 8.2
    assert f["cwe"] == "CWE-639"
    assert f["location"] == "/api/user/1002/profile"
    assert "anon" in f["evidence"] or "low" in f["evidence"]


def test_safe_route_negative(fixture_port):
    ctx = _Ctx(fixture_port, opts={
        "authz_matrix": True, "sessions": SESS,
        "object_urls": ["/safe/acct/profile/1001"]})
    res = authzmatrix.run_authz_matrix(ctx, ctx.opts)
    assert not [f for f in res["findings"]
                if f["title"] == authzmatrix.IDOR_TITLE]


def test_mass_assignment_probable_on_reflect_only_route(fixture_port):
    ctx = _Ctx(fixture_port, opts={
        "authz_matrix": True, "sessions": SESS,
        "probe_urls": ["/api/user/profile/update"]})
    res = authzmatrix.run_authz_matrix(ctx, ctx.opts)
    esc = [f for f in res["findings"]
           if f["title"] == authzmatrix.PRIVESC_TITLE]
    assert esc, f"expected priv-esc finding, got {res}"
    f = esc[0]
    assert f["confidence"] == "probable"
    assert f["cwe"] == "CWE-915"
    # reflect-only must NOT be reported as confirmed critical
    assert not (f["severity"] == "CRITICAL" and
                f["confidence"] == "confirmed")


def test_mass_assignment_not_fired_on_rejecting_route(fixture_port):
    ctx = _Ctx(fixture_port, opts={
        "authz_matrix": True, "sessions": SESS,
        "probe_urls": ["/api/key/check"]})
    res = authzmatrix.run_authz_matrix(ctx, ctx.opts)
    assert not [f for f in res["findings"]
                if f["title"] == authzmatrix.PRIVESC_TITLE]


def test_spa_miner_extracts_hidden_config(fixture_port):
    ctx = _Ctx(fixture_port)
    surf = types.SimpleNamespace(js_urls=["/app.js"], js_endpoints=[],
                                 pages=[], homepage=None)
    ctx.surface = lambda full=True: surf
    endpoints = authzmatrix.mine_spa_endpoints(ctx, "/")
    assert "/api/hidden/config" in endpoints
    assert "/api/user/me" in endpoints
    # merged into the surface for other checks
    assert "/api/hidden/config" in surf.js_endpoints


def test_c_spa_mine_emits_one_summary_finding(fixture_port):
    ctx = _Ctx(fixture_port)
    surf = types.SimpleNamespace(js_urls=["/app.js"], js_endpoints=[],
                                 pages=[], homepage=None)
    ctx.surface = lambda full=True: surf
    got = []
    authzmatrix.c_spa_mine(ctx, got.append)
    assert len(got) == 1
    f = got[0]
    assert f["severity"] == "INFO"
    assert f["title"].startswith("SPA Surface Expanded: ")
    assert "/api/hidden/config" in f["evidence"]


def test_gate_off_noop(fixture_port, monkeypatch):
    monkeypatch.delenv("PTK_AUTHZ", raising=False)
    ctx = _Ctx(fixture_port, opts={})
    got = []
    authzmatrix.c_authz_matrix(ctx, got.append)
    assert got == []


def test_gate_on_runs(monkeypatch, fixture_port):
    monkeypatch.setenv("PTK_AUTHZ", "1")
    ctx = _Ctx(fixture_port, opts={
        "sessions": SESS, "object_urls": ["/api/user/1002/profile"]})
    got = []
    authzmatrix.c_authz_matrix(ctx, got.append)
    assert any(f["title"] == authzmatrix.IDOR_TITLE for f in got)


def test_caps_respected(fixture_port):
    ctx = _Ctx(fixture_port, opts={
        "authz_matrix": True, "sessions": SESS,
        "object_urls": [f"/api/user/{n}/profile" for n in range(2, 42)]})
    res = authzmatrix.run_authz_matrix(ctx, ctx.opts)
    assert res["objects_tested"] == authzmatrix.MAX_OBJECTS
    assert res["requests"] <= 2 * authzmatrix.MAX_OBJECTS


def test_check_registration():
    assert authzmatrix.CHECKS == [authzmatrix.c_authz_matrix]
