"""v1.2.1 globe /actions timeout (2026-10-26, surgical fix).

Diagnosed 2026-10-26: on a cold cache, slow globe families exceed the
/actions default timeout (FETCH_TIMEOUT_S = 12.0 s) — sats refresh
(CelesTrak download + thousands of SGP4 propagations) and fires
(FIRMS fetch) take ~13-26 s — so the artifact/docker client gets
error/serviceDown and shows 0, even though the server-side refresh
still completes and a warm retry succeeds in ~0.2 s. Flights already
uses background refresh for exactly this reason; every other family
still refreshes synchronously, so the fix is a larger budget for globe
reads, not a refresh-semantics change.

This file is hermetic: call_service is stubbed (no live service, no
DB, no creds). It pins: GLOBE_TIMEOUT_MS = 120000, the 12 s default
unchanged for non-globe calls, every getGlobe* handler passing the
globe budget, cam keeping binary 30 s, and fingerprint having no
/actions handler (direct NDJSON route only).
"""

import os
import sys

import pytest

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, TREE)

import actions  # noqa: E402

GLOBE_HANDLERS_120S = [
    "getGlobeStatus", "getGlobeLayer", "getGlobeEntities",
    "getGlobeSearch", "getGlobeRoute", "getGlobeGithub",
    "getGlobeLaunches", "getGlobeNews", "getGlobeMarkets",
    "getGlobeCloudmeta", "getGlobeWindgrid", "getGlobeIssTelemetry",
    "getGlobeRecon", "getGlobeTicker",
]

HANDLER_ARGS = {
    "getGlobeLayer": {"layerId": "quakes"},
}


def _stub_service(monkeypatch):
    """Replace call_service with a recorder returning a usable payload."""
    calls = []

    def fake(port, method, path, body=None, binary=False, timeout_ms=None):
        calls.append({"port": port, "method": method, "path": path,
                      "binary": binary, "timeout_ms": timeout_ms})
        return {"down": False, "status": 200,
                "json": {"rows": [], "ok": True}, "text": "",
                "base64": "", "contentType": "application/json"}

    monkeypatch.setattr(actions, "call_service", fake)
    return calls


def test_globe_timeout_constants():
    assert actions.GLOBE_TIMEOUT_MS == 120000
    # The default for every non-globe call is unchanged.
    assert actions.FETCH_TIMEOUT_S == 12.0


def test_all_globe_handlers_pass_120s(monkeypatch):
    calls = _stub_service(monkeypatch)
    globe_in_map = [k for k in actions._ACTIONS
                    if k.startswith("getGlobe") and k != "getGlobeCam"]
    assert sorted(globe_in_map) == sorted(GLOBE_HANDLERS_120S)
    for name in GLOBE_HANDLERS_120S:
        before = len(calls)
        out = actions._ACTIONS[name](HANDLER_ARGS.get(name, {}), 5000)
        assert len(calls) == before + 1, name
        assert calls[-1]["timeout_ms"] == 120000, name
        assert out.get("serviceDown") is False, name


def test_globe_cam_keeps_binary_30s(monkeypatch):
    calls = _stub_service(monkeypatch)
    out = actions._ACTIONS["getGlobeCam"]({}, 5000)
    assert len(calls) == 1
    assert calls[0]["binary"] is True
    # Cam passes no timeout_ms, so call_service keeps its binary
    # default (30 s) — the globe budget must not leak into it.
    assert calls[0]["timeout_ms"] is None
    assert out.get("serviceDown") is False


def test_fingerprint_has_no_actions_handler():
    assert "getGlobeFingerprint" not in actions._ACTIONS


class _FakeResp:
    status_code = 200
    headers = {}
    content = b'{"ok": true}'
    text = '{"ok": true}'

    def json(self):
        return {"ok": True}


def test_call_service_default_and_globe_budget(monkeypatch):
    seen = []

    def fake_request(method, url, headers=None, allow_redirects=False,
                     timeout=None, **kwargs):
        seen.append(timeout)
        return _FakeResp()

    monkeypatch.setattr(actions, "_ensure_session", lambda port: True)
    actions._session_cookie = "test-cookie"
    monkeypatch.setattr(actions.requests, "request", fake_request)
    actions.call_service(5000, "GET", "/api/me")
    assert seen[-1] == 12.0
    actions.call_service(5000, "GET", "/api/osint/globe/status",
                         timeout_ms=120000)
    assert seen[-1] == 120.0
