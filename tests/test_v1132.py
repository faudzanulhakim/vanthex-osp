"""v1.13.2 — EONET family survives episodic egress stalls.

Measured diagnosis behind the fix: the EONET events feed is a single
all-or-nothing fetch on the joint-shortest timeout of the family set
(30 s). During the observed stall window even the tiny Kp feed took
~17 s and two consecutive EONET attempts died at the cap, recorded
verbatim as 'OSError: timed out', while multi-call families
(flights/sats sweeps) tolerate individual stalled calls. The fetch
daemon itself is threaded and measured NOT to queue ops (EONET op
1.2 s idle, <=4.5 s under a full concurrent flights+sats cycle), so
the cure lives in the family fetcher: retry the events fetch on
transport errors with escalating timeouts/backoff, re-raise the
last genuine error verbatim, and keep parsing outside the retry.

Hermetic tests: gf._fetch is stubbed at the module seam (the same
seam the family fetcher resolves at call time). No external network.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

FAST_PLAN = ((5.0, 0.0), (6.0, 0.0), (7.0, 0.0))


def _ev(cat_id, cat_title, title, lon, lat):
    return {"title": title,
            "categories": [{"id": cat_id, "title": cat_title}],
            "geometry": [{"type": "Point", "coordinates": [lon, lat],
                          "date": "2026-10-23T00:00:00Z"}]}


SAMPLE = json.dumps({"events": [
    _ev("wildfires", "Wildfires", "Fire A", 100.0, -2.0),
    _ev("wildfires", "Wildfires", "Fire B", 101.0, -3.0),
    _ev("severeStorms", "Severe Storms", "Storm A", 90.0, 10.0),
    _ev("seaLakeIce", "Sea and Lake Ice", "Ice A", 0.0, 80.0),
]}).encode()


class _Flaky:
    """_fetch stub: raises for the first `fails` calls, then serves."""

    def __init__(self, fails, raw=SAMPLE):
        self.fails = fails
        self.raw = raw
        self.calls = []

    def __call__(self, host, path, timeout=30.0):
        self.calls.append((host, path, timeout))
        if len(self.calls) <= self.fails:
            raise IOError("timed out")
        return 200, self.raw


def _patch(monkeypatch, stub):
    monkeypatch.setattr(gf, "_fetch", stub)
    monkeypatch.setattr(gf, "_EONET_FETCH_PLAN", FAST_PLAN)


# ------------------------------------------------------------- plan shape
def test_eonet_plan_shape():
    plan = gf._EONET_FETCH_PLAN
    assert len(plan) == 3
    timeouts = [t for t, _b in plan]
    backoffs = [b for _t, b in plan]
    assert timeouts[0] >= 45.0
    assert timeouts == sorted(timeouts)      # never shrinks
    assert backoffs[0] == 0.0
    assert backoffs == sorted(backoffs)      # spreads across a stall


# ----------------------------------------------------------------- retry
def test_eonet_recovers_after_transient_timeouts(monkeypatch):
    stub = _Flaky(fails=2)
    _patch(monkeypatch, stub)
    raw = gf._fetch_eonet_events()
    assert raw == SAMPLE
    # every attempt hit the exact declared feed, with escalating
    # timeout budgets from the plan
    assert [c[0] for c in stub.calls] == ["eonet.gsfc.nasa.gov"] * 3
    assert all(c[1] == "/api/v3/events?status=open&days=30"
               for c in stub.calls)
    assert [c[2] for c in stub.calls] == [5.0, 6.0, 7.0]


def test_eonet_reraises_last_genuine_error(monkeypatch):
    stub = _Flaky(fails=99)
    _patch(monkeypatch, stub)
    with pytest.raises(IOError) as ei:
        gf._fetch_eonet_events()
    # error fidelity: the recorded failure stays the transport's own
    # words, not a wrapper's paraphrase
    assert str(ei.value) == "timed out"
    assert len(stub.calls) == len(FAST_PLAN)


def test_eonet_first_try_success_no_retry(monkeypatch):
    stub = _Flaky(fails=0)
    _patch(monkeypatch, stub)
    assert gf._fetch_eonet_events() == SAMPLE
    assert len(stub.calls) == 1


# ---------------------------------------------------------------- family
def test_eonet_family_partitions_after_retry(monkeypatch):
    stub = _Flaky(fails=1)
    _patch(monkeypatch, stub)
    monkeypatch.setattr(gf, "_feed_keys", lambda: {"firms": "",
                                                   "abusech": ""})
    out = gf._fetch_eonet_family()
    assert out["fires"]["total"] == 2
    assert out["severe"]["total"] == 1
    assert out["events_other"]["total"] == 1
    assert sum(e["total"] for e in out.values()) == 4
    assert all(e["ok"] for e in out.values())


def test_eonet_parse_error_not_retried(monkeypatch):
    stub = _Flaky(fails=0, raw=b"<not json>")
    _patch(monkeypatch, stub)
    monkeypatch.setattr(gf, "_feed_keys", lambda: {"firms": "",
                                                   "abusech": ""})
    with pytest.raises(Exception):
        gf._fetch_eonet_family()
    # one fetch only: a garbage body is not a transport failure and
    # must fail fast, exactly as before v1.13.2
    assert len(stub.calls) == 1
