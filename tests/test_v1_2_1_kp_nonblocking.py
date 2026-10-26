"""v1.2.1 Kp-nonblocking fix (2026-10-26).

Bug: get_kp() early-returned only when Kp was ok AND fresher than
900 s. On persistent SWPC failure ok stayed False, so EVERY status()
call attempted a full _fetch (30 s timeout, up to ~90 s via the
daemon helper path). The client header renders statusAgg || "OFFLINE"
until the first status response arrives, so every browser refresh
showed OFFLINE for that long.

Fix: a due Kp refresh runs in a daemon thread. The triggering call
waits at most _KP_SYNC_GRACE_S (2 s) so an already-fast answer still
lands synchronously (the existing synchronous success path, pinned
by test_status_reports_kp_and_layers); calls while a refresh is in
flight, and calls within _KP_FAIL_TTL_S (300 s) after a failure,
return immediately. A failed fetch clears the stored value and marks
ok False, so no stale number is ever presented as current.

This file is hermetic: the SWPC fetch is stubbed (no network, no
live service, no DB). It pins: (1) status() is fast when the Kp
fetch hangs; (2) aggregate is PARTIAL, not OFFLINE, when layers have
data and Kp fails; (3) the Kp success path is unchanged (value
returned, 900 s TTL honored); (4) a failed Kp is not retried on
every status call within the negative TTL; (5) no stale Kp value is
presented as current on failure.
"""

import os
import threading
import time

import pytest

import globe_feeds as gf

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "globe")


def _swpc_raw():
    with open(os.path.join(FIX, "swpc_kp.json"), "rb") as f:
        return f.read()


def _wait_kp_idle(timeout=10.0):
    """True once no Kp refresh thread is running (backstop only:
    every test below releases its stub and waits before returning)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not gf._kp_refresh_in_flight:
            return True
        time.sleep(0.05)
    return not gf._kp_refresh_in_flight


@pytest.fixture(autouse=True)
def _isolated_kp():
    orig_fetch = gf._fetch
    gf._cache.clear()
    gf._kp.update(value=None, time_tag="", fetched_at=0.0, ok=False,
                  error="")
    gf._kp_refresh_in_flight = False
    gf._kp_last_failed_at = 0.0
    yield
    # Let any spawned refresh finish while the stub is still
    # installed, so no thread can ever touch the real _fetch later.
    _wait_kp_idle(timeout=10.0)
    gf._fetch = orig_fetch
    gf._cache.clear()
    gf._kp.update(value=None, time_tag="", fetched_at=0.0, ok=False,
                  error="")
    gf._kp_refresh_in_flight = False
    gf._kp_last_failed_at = 0.0


def test_status_fast_when_kp_hangs():
    """(1) A hung SWPC fetch must not hold status() hostage: the
    triggering call costs at most the sync grace, and later calls
    while the refresh is in flight cost ~nothing."""
    started = threading.Event()
    release = threading.Event()

    def hanging(host, path, timeout=30.0, headers=None):
        assert host == "services.swpc.noaa.gov"
        started.set()
        release.wait(30)  # bounded; the test releases it below
        raise IOError("simulated SWPC hang")

    gf._fetch = hanging
    t0 = time.time()
    st = gf.status()
    dt = time.time() - t0
    assert dt < 5.0, f"status() blocked {dt:.2f}s on a hung Kp fetch"
    assert st["kp"]["value"] is None and st["kp"]["ok"] is False
    assert started.is_set()

    t0 = time.time()
    st2 = gf.status()
    dt2 = time.time() - t0
    assert dt2 < 5.0, f"in-flight status() blocked {dt2:.2f}s"
    assert st2["kp"]["value"] is None and st2["kp"]["ok"] is False

    release.set()
    assert _wait_kp_idle()
    assert gf._kp["ok"] is False and gf._kp["error"]


def test_aggregate_partial_not_offline_when_kp_fails():
    """(2) Layers with data (the local static families status()
    always includes) + failed Kp => PARTIAL, never OFFLINE."""

    def failing(host, path, timeout=30.0, headers=None):
        raise IOError("SWPC down")

    gf._fetch = failing
    st = gf.status()
    assert _wait_kp_idle()
    assert st["aggregate"] == "PARTIAL"
    assert st["kp"]["value"] is None and st["kp"]["ok"] is False
    assert any(m["state"] in ("live", "static", "computed")
               for m in st["layers"].values())
    st2 = gf.status()
    assert st2["aggregate"] == "PARTIAL"


def test_kp_success_path_unchanged():
    """(3) A fast SWPC answer still lands in the same status() call,
    and the 900 s TTL is honored (no refetch on immediate retry)."""
    raw = _swpc_raw()
    calls = {"n": 0}

    def ok_fetch(host, path, timeout=30.0, headers=None):
        assert host == "services.swpc.noaa.gov"
        calls["n"] += 1
        return 200, raw

    gf._fetch = ok_fetch
    st = gf.status()
    assert _wait_kp_idle()
    assert calls["n"] == 1
    assert st["kp"]["ok"] is True and st["kp"]["value"] is not None
    value, _tag = gf.parse_swpc_kp(raw)
    assert st["kp"]["value"] == value

    st2 = gf.status()
    assert st2["kp"]["value"] == value
    assert calls["n"] == 1, "fresh Kp must not be refetched"


def test_failed_kp_not_retried_within_negative_ttl():
    """(4) After a failure, status() calls inside the 300 s negative
    TTL must not start another fetch; after the window, a fresh
    attempt is made again."""
    calls = {"n": 0}

    def failing(host, path, timeout=30.0, headers=None):
        calls["n"] += 1
        raise IOError("SWPC down")

    gf._fetch = failing
    gf.status()
    assert _wait_kp_idle()
    assert calls["n"] == 1
    gf.status()
    gf.status()
    gf.status()
    assert calls["n"] == 1, "failed Kp retried inside the negative TTL"

    gf._kp_last_failed_at = time.time() - (gf._KP_FAIL_TTL_S + 1)
    gf.status()
    assert _wait_kp_idle()
    assert calls["n"] == 2, "no fresh attempt after the negative TTL"


def test_no_stale_kp_value_after_failure():
    """(5) An expired previous success (value 5.0, fetched 1000 s
    ago) + a failing refresh must never surface the stale number:
    not on the triggering call, not after the failure lands, and
    not in stored state either."""
    gf._kp.update(value=5.0, time_tag="stale-tag",
                  fetched_at=time.time() - 1000, ok=True, error="")

    def failing(host, path, timeout=30.0, headers=None):
        raise IOError("SWPC down")

    gf._fetch = failing
    st = gf.status()
    assert st["kp"]["value"] is None, "stale Kp value presented"
    assert st["kp"]["ok"] is False
    assert _wait_kp_idle()
    st2 = gf.status()
    assert st2["kp"]["value"] is None and st2["kp"]["ok"] is False
    assert gf._kp["value"] is None
