"""tests/test_protocolattacks.py — hermetic tests for protocolattacks.py
(protocol-level attack checks, bounded differential probes).

Fixture routes live under /proto/* in tests/fixture_vuln_server.py:
- /proto/smuggle        simple smuggling emulator (explicit desync report);
- /proto/h2             h2 Content-Length inconsistency emulator;
- /proto/race, /proto/race/redeem (+ /safe) race-condition emulator;
- /proto/cache (+ /safe) cache-poisoning emulator (poison served on hit);
- /proto/xfh            X-Forwarded-Host reflection into a canonical link.
"""
import json
import os
import sys
import threading
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fixture_vuln_server as FX  # noqa: E402
from offensive import protocolattacks  # noqa: E402
import vulnscan2 as v  # noqa: E402

_PORT = 18777
BASE = f"http://127.0.0.1:{_PORT}"


@pytest.fixture(scope="module")
def server():
    srv = ThreadingHTTPServer(("127.0.0.1", _PORT), FX.H)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield srv
    srv.shutdown()


def _reset_state():
    FX.PROTO_CACHE.clear()
    FX.STATE["proto_race"] = 0
    FX.STATE["proto_race_safe"] = 0
    FX.STATE.pop("proto_race_safe_done", None)


@pytest.fixture(autouse=True)
def clean_state():
    _reset_state()
    yield
    _reset_state()


def make_ctx(opts):
    return v.Ctx(BASE, dict(opts), [])


def run(opts, check=None):
    ctx, found = make_ctx(opts), []
    if check is None:
        for c in protocolattacks.CHECKS:
            c(ctx, found.append)
    else:
        check(ctx, found.append)
    return found


def by_title(found, needle):
    return [f for f in found if needle.lower() in f["title"].lower()]


# ---------------------------------------------------------------- registry

def test_checks_registered_and_profile_count():
    names = {"c_proto_smuggling", "c_proto_h2", "c_proto_race",
             "c_proto_cache_poisoning", "c_proto_host_header"}
    for n in names:
        assert hasattr(v, n), n
    for n in names:
        assert n in v.PROFILES["enterprise-full"], n


# ---------------------------------------------------------------- gating

def test_gated_checks_noop_without_env(server, monkeypatch):
    monkeypatch.delenv("PTK_PROTO", raising=False)
    opts = {"proto_race_endpoint": "/proto/race/redeem",
            "proto_h2_endpoint": "/proto/h2"}
    h2 = run(opts, protocolattacks.c_proto_h2)
    race = run(opts, protocolattacks.c_proto_race)
    assert h2 == [] and race == []


def test_gated_checks_run_with_env(server, monkeypatch):
    monkeypatch.setenv("PTK_PROTO", "1")
    found = run({"proto_h2_endpoint": "/proto/h2"},
                protocolattacks.c_proto_h2)
    assert len(found) == 1
    assert found[0]["confidence"] == "confirmed"
    assert "PROTO-H2-CL-CONFLICT" in found[0]["evidence"]
    assert found[0]["verification"] == "differential-response"


# ---------------------------------------------------------------- smuggling

def test_smuggling_confirmed_on_emulator(server):
    found = run({"proto_endpoints": ["/proto/smuggle"]},
                protocolattacks.c_proto_smuggling)
    smug = by_title(found, "Request Smuggling")
    assert smug, found
    f = smug[0]
    assert f["confidence"] == "confirmed"
    assert f["cwe"] == "CWE-444"
    assert "PROTO-DESYNC" in f["evidence"]
    assert f["verification"] == "differential-response"
    assert "flood" in f["verification_note"].lower() or \
        "once" in f["verification_note"].lower()


def test_smuggling_clean_server_no_finding(server):
    # /proto/smuggle-clean honours Content-Length exactly and keeps the
    # connection alive: canonical probes must NOT produce a finding
    # (fp-guard differential — clean baseline, no desync).
    found = run({"proto_endpoints": ["/proto/smuggle-clean"]},
                protocolattacks.c_proto_smuggling)
    assert by_title(found, "Request Smuggling") == []


def test_smuggling_unreachable_endpoint_skipped(server):
    found = run({"proto_endpoints": ["/definitely-not-there"]},
                protocolattacks.c_proto_smuggling)
    assert found == []


# ---------------------------------------------------------------- race

def test_race_confirmed_on_vulnerable_route(server, monkeypatch):
    monkeypatch.setenv("PTK_PROTO", "1")
    found = run({"proto_race_endpoint": "/proto/race/redeem",
                 "proto_race_counter": "/proto/race"},
                protocolattacks.c_proto_race)
    rc = by_title(found, "Race Condition")
    assert rc, found
    f = rc[0]
    assert f["confidence"] == "confirmed"
    assert f["verification"] == "differential-count"
    assert "delta" in f["evidence"]
    assert FX.STATE["proto_race"] >= 2


def test_race_negative_on_safe_route(server, monkeypatch):
    monkeypatch.setenv("PTK_PROTO", "1")
    found = run({"proto_race_endpoint": "/proto/race/safe/redeem",
                 "proto_race_counter": "/proto/race?which=safe"},
                protocolattacks.c_proto_race)
    assert by_title(found, "Race Condition") == []
    assert FX.STATE["proto_race_safe"] == 1  # idempotent: one wave, one apply


# ------------------------------------------------------- cache poisoning

def test_cache_poisoning_confirmed_via_cache_hit(server):
    found = run({"proto_cache_endpoints": ["/proto/cache"]},
                protocolattacks.c_proto_cache_poisoning)
    cp = by_title(found, "Web Cache Poisoning")
    assert cp, found
    f = cp[0]
    assert f["confidence"] == "confirmed"
    assert f["verification"] == "cache-served-poison"
    assert "x-cache: hit" in f["evidence"].lower()
    assert FX.PROTO_CACHE  # emulator cache was poisoned


def test_cache_poisoning_negative_on_safe_route(server):
    found = run({"proto_cache_endpoints": ["/proto/cache/safe"]},
                protocolattacks.c_proto_cache_poisoning)
    assert by_title(found, "Web Cache Poisoning") == []
    assert by_title(found, "Reflection") == []
    assert not FX.PROTO_CACHE


# ------------------------------------------------------- host-header

def test_host_header_reflection_probable(server):
    found = run({"proto_host_endpoints": ["/proto/xfh"]},
                protocolattacks.c_proto_host_header)
    hh = by_title(found, "Host-Header")
    assert hh, found
    f = hh[0]
    # reflection proven but no cache hit on this route -> weak signal label
    assert f["confidence"] in ("probable", "candidate")
    assert f["verification"] == "header-reflection"
    assert f["verification_note"]
    assert "cache" in f["evidence"].lower()


def test_host_header_confirmed_when_cache_serves_poison(server):
    found = run({"proto_host_endpoints": ["/proto/cache"]},
                protocolattacks.c_proto_host_header)
    hh = by_title(found, "Host-Header")
    assert hh, found
    conf = [f for f in hh if f["confidence"] == "confirmed"]
    assert conf, hh
    assert conf[0]["verification"] == "cache-served-poison"


# ------------------------------------------------------- honesty / limits

def test_finding_shape_has_verification_fields(server):
    found = run({"proto_endpoints": ["/proto/smuggle"]},
                protocolattacks.c_proto_smuggling)
    for f in found:
        assert f["origin"] == "protocolattacks"
        assert f["verification"]
        assert f["verification_note"]
        assert f["confidence"] in ("confirmed", "probable", "candidate")
        assert f["title"] and f["description"]


def test_bounded_probe_counts(server):
    """No flooding: the smuggling check must send a bounded number of
    requests per endpoint (baseline + probes + follow-ups)."""
    seen = {"n": 0}
    real = protocolattacks._raw_request

    def counting(host, port, raw, timeout=protocolattacks._RAW_TIMEOUT):
        seen["n"] += 1
        return real(host, port, raw, timeout=timeout)

    orig = protocolattacks._raw_request
    protocolattacks._raw_request = counting
    try:
        run({"proto_endpoints": ["/proto/smuggle", "/", "/proto/x1",
                                 "/proto/x2", "/proto/x3", "/proto/x4",
                                 "/proto/x5"]},
            protocolattacks.c_proto_smuggling)
    finally:
        protocolattacks._raw_request = orig
    # max 4 endpoints x ~8 bounded requests each
    assert seen["n"] <= 4 * 10, seen["n"]
