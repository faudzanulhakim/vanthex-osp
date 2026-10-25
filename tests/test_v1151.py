"""v1.15.1 — background refresh for the flights family (service only).

Problem (verified 2026-10-24): get_layer() refreshed a stale family
synchronously in the requesting thread, so a flights layer read
blocked for the whole sweep (~135-220 s, outlier 302 s). The
artifact's getGlobeLayer action is capped by a 120 s worker limit
(undocumented, proven empirically), so a sweep-triggering fetch via
the artifact was always killed and the row stayed stuck at 0.

What v1.15.1 changes, mechanically (globe_feeds.py only):
  * get_layer() for a member of the flights family, on stale cache,
    spawns a daemon thread that holds the family lock and runs
    _refresh_family(), and returns the last snapshot immediately
    (STALE with previous data, OFFLINE with none) — it never blocks
    on a sweep;
  * every other family still refreshes synchronously in the
    requesting thread, exactly as before;
  * the family lock still guarantees a single flights sweep at a
    time; a restart mid-sweep behaves as before (the daemon thread
    dies with the process; the next GET starts a fresh sweep).

These tests stub _FAMILY_FETCH (never the network) and control the
module-level _cache directly; they restore both afterwards so they
are order-independent.
"""

import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))))

import globe_feeds as gf  # noqa: E402

FLIGHT_MEMBERS = ["flights_all", "flights_commercial", "flights_private",
                  "flights_jets", "flights_military"]


def _stale_entry(total=100):
    return {"points": [{"la": 1.0, "lo": 2.0, "lb": "X", "ex": "old"}],
            "items": [], "total": total, "drawn": total,
            "fetched_at": time.time() - 10000, "ok": True,
            "note": "old snapshot", "error": ""}


def _fresh_entry(total):
    return {"points": [{"la": 1.0, "lo": 2.0, "lb": "X", "ex": "new"}],
            "items": [], "total": total, "drawn": total,
            "fetched_at": time.time(), "ok": True,
            "note": "fresh sweep", "error": ""}


@pytest.fixture()
def _saved_cache(monkeypatch):
    """Snapshot + restore the cache keys these tests touch."""
    saved = {sid: gf._cache.get(sid) for sid in
             FLIGHT_MEMBERS + ["quakes"]}
    yield
    for sid, entry in saved.items():
        if entry is None:
            gf._cache.pop(sid, None)
        else:
            gf._cache[sid] = entry


def _wait_until(pred, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.05)
    return pred()


def _wait_until_lock_free(fam, timeout=15.0):
    """A worker releases the family lock only after _save_snapshot,
    which runs after the cache update — so cache-fresh alone does
    not prove the lock is free. Probe it without side effects: a
    successful non-blocking acquire (immediately released) means
    no worker holds it. This keeps tests isolated: a test must not
    return while its worker still holds the lock, or the next test's
    get_layer would find the lock held and spawn no worker of its
    own."""
    def free():
        lock = gf._family_lock(fam)
        if lock.acquire(blocking=False):
            lock.release()
            return True
        return False
    return _wait_until(free, timeout=timeout)


def test_flights_stale_returns_immediately_not_blocking(
        monkeypatch, _saved_cache):
    # (a) get_layer on stale flights cache returns in <5 s with the
    # old snapshot (STALE), while the sweep is still running in the
    # background.
    started = threading.Event()
    release = threading.Event()
    calls = []

    def slow_fetch():
        calls.append(time.time())
        started.set()
        release.wait(timeout=10)
        return {"flights_all": _fresh_entry(111),
                "flights_commercial": _fresh_entry(222),
                "flights_private": _fresh_entry(333),
                "flights_jets": _fresh_entry(444),
                "flights_military": _fresh_entry(555)}

    monkeypatch.setitem(gf._FAMILY_FETCH, "flights", slow_fetch)
    for sid in FLIGHT_MEMBERS:
        gf._cache[sid] = _stale_entry(total=100)
    t0 = time.time()
    out = gf.get_layer("flights_commercial")
    elapsed = time.time() - t0
    assert elapsed < 5, f"blocked {elapsed:.1f}s on a sweep"
    assert out["state"] == "stale"
    assert out["count_total"] == 100  # last snapshot, not the sweep
    assert started.wait(timeout=5), "background sweep never started"
    release.set()
    assert _wait_until(lambda: len(calls) == 1 and
                       gf._cache.get("flights_commercial", {}).get(
                           "fetched_at", 0) > t0)
    out2 = gf.get_layer("flights_commercial")
    assert out2["state"] == "live"
    assert out2["count_total"] == 222
    assert _wait_until_lock_free("flights")


def test_flights_no_data_returns_offline_immediately(
        monkeypatch, _saved_cache):
    # OFFLINE (not a hang) when there is no previous snapshot at all.
    release = threading.Event()

    def slow_fetch():
        release.wait(timeout=10)
        return {"flights_all": _fresh_entry(1),
                "flights_commercial": _fresh_entry(2),
                "flights_private": _fresh_entry(3),
                "flights_jets": _fresh_entry(4),
                "flights_military": _fresh_entry(5)}

    monkeypatch.setitem(gf._FAMILY_FETCH, "flights", slow_fetch)
    for sid in FLIGHT_MEMBERS:
        gf._cache.pop(sid, None)
    t0 = time.time()
    out = gf.get_layer("flights_all")
    assert time.time() - t0 < 5
    assert out["state"] == "offline"
    assert out["count_total"] == 0
    release.set()
    assert _wait_until(lambda: gf._cache.get(
        "flights_all", {}).get("fetched_at", 0) > t0)
    assert gf.get_layer("flights_all")["state"] == "live"
    assert _wait_until_lock_free("flights")


def test_flights_concurrent_reads_all_return_at_once_single_sweep(
        monkeypatch, _saved_cache):
    # (c) many concurrent reads during one sweep: all return at once,
    # and exactly one sweep runs (single-flight preserved).
    release = threading.Event()
    calls = []

    def slow_fetch():
        calls.append(1)
        release.wait(timeout=10)
        return {sid: _fresh_entry(i + 1)
                for i, sid in enumerate(FLIGHT_MEMBERS)}

    monkeypatch.setitem(gf._FAMILY_FETCH, "flights", slow_fetch)
    for sid in FLIGHT_MEMBERS:
        gf._cache[sid] = _stale_entry(total=50)
    results = {}
    errors = []

    def read(sid):
        try:
            t0 = time.time()
            out = gf.get_layer(sid)
            results[sid] = (time.time() - t0, out["state"])
        except Exception as e:  # noqa: BLE001
            errors.append(e)

    threads = [threading.Thread(target=read, args=(sid,))
               for sid in FLIGHT_MEMBERS]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert not errors, errors
    assert len(results) == len(FLIGHT_MEMBERS)
    for sid, (elapsed, state) in results.items():
        assert elapsed < 5, f"{sid} blocked {elapsed:.1f}s"
        assert state == "stale", (sid, state)
    release.set()
    assert _wait_until(lambda: len(calls) == 1)
    assert _wait_until_lock_free("flights")
    # The lock is released after the sweep: a second stale cycle can
    # start a fresh sweep (no deadlock, no leaked lock). The second
    # sweep gets its own blocking stub — reusing the first cycle's
    # already-set release event would let it finish instantly and
    # the immediate get_layer could legitimately return live.
    release2 = threading.Event()
    calls2 = []

    def slow_fetch2():
        calls2.append(1)
        release2.wait(timeout=10)
        return {sid: _fresh_entry(i + 1)
                for i, sid in enumerate(FLIGHT_MEMBERS)}

    monkeypatch.setitem(gf._FAMILY_FETCH, "flights", slow_fetch2)
    for sid in FLIGHT_MEMBERS:
        gf._cache[sid] = _stale_entry(total=50)
    out = gf.get_layer("flights_all")
    assert out["state"] == "stale"
    release2.set()
    assert _wait_until(lambda: len(calls2) == 1)
    assert _wait_until_lock_free("flights")


def test_non_flights_family_still_refreshes_synchronously(
        monkeypatch, _saved_cache):
    # (d) a fast family (quakes) still refreshes in the requesting
    # thread: the returned payload is already the fresh stub data.
    done = threading.Event()

    def quake_fetch():
        time.sleep(0.2)
        done.set()
        return {"quakes": _fresh_entry(42)}

    monkeypatch.setitem(gf._FAMILY_FETCH, "quakes", quake_fetch)
    gf._cache["quakes"] = _stale_entry(total=7)
    out = gf.get_layer("quakes")
    assert done.is_set(), "sync family must finish before return"
    assert out["state"] == "live"
    assert out["count_total"] == 42


def test_flights_background_failure_keeps_last_snapshot(
        monkeypatch, _saved_cache):
    # (e) a failing background sweep keeps the last good snapshot
    # (STALE) with the error stamped — never a crash, never blanked.
    monkeypatch.setitem(gf._FAMILY_FETCH, "flights",
                        lambda: (_ for _ in ()).throw(
                            IOError("simulated sweep failure")))
    for sid in FLIGHT_MEMBERS:
        gf._cache[sid] = _stale_entry(total=77)
    t0 = time.time()
    out = gf.get_layer("flights_jets")
    assert time.time() - t0 < 5
    assert out["state"] == "stale"
    assert out["count_total"] == 77
    # _refresh_family retries once after 2 s, then stamps the error.
    assert _wait_until(lambda: "simulated sweep failure" in
                       (gf._cache.get("flights_jets", {}).get(
                           "error") or ""), timeout=15)
    after = gf.get_layer("flights_jets")
    assert after["count_total"] == 77  # snapshot preserved
    assert "simulated sweep failure" in after["error"]
    assert _wait_until_lock_free("flights")
