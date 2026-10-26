"""v1.2.1 globe warmer (2026-10-26).

The docker container has no fetch daemon and ships no
globe_feed_cache.json, so its registry starts EMPTY on every Recreated
deploy and status() reads OFFLINE until a browser opens a layer. The
warmer (globe_warmer.py) fixes that server-side: two daemon threads
started with the service process sweep the warm set through the same
reads a browser would make, so a deploy goes live with zero browser
traffic and a refresh never reads OFFLINE once warmed.

This file is hermetic: globe_feeds.get_layer / get_news / get_markets
are stubbed (no live service, no network, no DB, no creds). It pins:
import starts nothing; start spawns exactly two daemon threads (fast +
sats) and is idempotent; the full warm set is called (11 fast layers +
news + markets on the fast thread, 6 sats layers on the sats thread);
every excluded id is never called; one failing layer does not kill a
sweep; stop is prompt even with long polls and restart works; and a
slow sats call cannot starve the fast thread (separate threads, not
one shared loop).
"""

import threading
import time

import pytest

import globe_feeds
import globe_warmer

EXCLUDED = (
    "wind_particles",
    "flights_all", "flights_commercial", "flights_private",
    "flights_jets", "flights_military",
    "rain", "clouds", "daynight",
    "maritime_static", "maritime_lines", "nuclear", "transit_live",
)


@pytest.fixture(autouse=True)
def _stop_warmer():
    globe_warmer.stop_warmer()
    yield
    globe_warmer.stop_warmer()


def _warmer_threads():
    return [t for t in threading.enumerate()
            if t.name.startswith("globe-warmer-")]


def _install_stubs(monkeypatch, calls, fail_on=(), slow_sats_s=0.0):
    def fake_get_layer(name):
        calls.append((threading.current_thread().name, "layer", name))
        if slow_sats_s and name == "sats_all":
            time.sleep(slow_sats_s)
        if name in fail_on:
            raise RuntimeError("stub boom")
        return {"layer": name}

    def fake_get_news():
        calls.append((threading.current_thread().name, "news", None))

    def fake_get_markets():
        calls.append((threading.current_thread().name, "markets", None))

    monkeypatch.setattr(globe_feeds, "get_layer", fake_get_layer)
    monkeypatch.setattr(globe_feeds, "get_news", fake_get_news)
    monkeypatch.setattr(globe_feeds, "get_markets", fake_get_markets)


def test_import_starts_nothing():
    assert _warmer_threads() == []
    assert globe_warmer.running() is False


def test_start_spawns_two_daemon_threads(monkeypatch):
    calls = []
    _install_stubs(monkeypatch, calls)
    assert globe_warmer.start_warmer(fast_poll_s=0.05,
                                     sats_poll_s=0.05) is True
    assert globe_warmer.running() is True
    threads = _warmer_threads()
    assert sorted(t.name for t in threads) == [
        "globe-warmer-fast", "globe-warmer-sats"]
    assert all(t.daemon for t in threads)


def test_start_is_idempotent(monkeypatch):
    calls = []
    _install_stubs(monkeypatch, calls)
    assert globe_warmer.start_warmer(fast_poll_s=0.05,
                                     sats_poll_s=0.05) is True
    assert globe_warmer.start_warmer(fast_poll_s=0.05,
                                     sats_poll_s=0.05) is False
    assert len(_warmer_threads()) == 2


def test_warm_set_called_on_right_threads(monkeypatch):
    calls = []
    _install_stubs(monkeypatch, calls)
    globe_warmer.start_warmer(fast_poll_s=0.05, sats_poll_s=0.05)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        seen_layers = {name for _t, kind, name in calls
                       if kind == "layer"}
        seen_kinds = {kind for _t, kind, _n in calls}
        if (set(globe_warmer.WARM_LAYERS_FAST) <= seen_layers
                and set(globe_warmer.WARM_LAYERS_SATS) <= seen_layers
                and "news" in seen_kinds and "markets" in seen_kinds):
            break
        time.sleep(0.02)
    seen_layers = {name for _t, kind, name in calls if kind == "layer"}
    assert set(globe_warmer.WARM_LAYERS_FAST) <= seen_layers
    assert set(globe_warmer.WARM_LAYERS_SATS) <= seen_layers
    fast_thread_calls = {name for t, kind, name in calls
                         if t == "globe-warmer-fast" and kind == "layer"}
    sats_thread_calls = {name for t, kind, name in calls
                         if t == "globe-warmer-sats" and kind == "layer"}
    assert set(globe_warmer.WARM_LAYERS_FAST) <= fast_thread_calls
    assert set(globe_warmer.WARM_LAYERS_SATS) <= sats_thread_calls
    assert "news" in {kind for t, kind, _n in calls
                      if t == "globe-warmer-fast"}
    assert "markets" in {kind for t, kind, _n in calls
                         if t == "globe-warmer-fast"}


def test_excluded_ids_never_called(monkeypatch):
    calls = []
    _install_stubs(monkeypatch, calls)
    globe_warmer.start_warmer(fast_poll_s=0.05, sats_poll_s=0.05)
    time.sleep(0.3)
    seen_layers = {name for _t, kind, name in calls if kind == "layer"}
    for sid in EXCLUDED:
        assert sid not in seen_layers, sid


def test_one_failing_layer_does_not_kill_sweep(monkeypatch):
    calls = []
    _install_stubs(monkeypatch, calls, fail_on={"cctv"})
    globe_warmer.start_warmer(fast_poll_s=0.05, sats_poll_s=0.05)
    time.sleep(0.3)
    seen_layers = {name for _t, kind, name in calls if kind == "layer"}
    assert "cctv" in seen_layers  # attempted, then skipped past
    assert "quakes" in seen_layers
    assert "launches" in seen_layers
    assert globe_warmer.running() is True
    assert len(_warmer_threads()) == 2


def test_stop_is_prompt_and_restartable(monkeypatch):
    calls = []
    _install_stubs(monkeypatch, calls)
    assert globe_warmer.start_warmer(fast_poll_s=60.0,
                                     sats_poll_s=60.0) is True
    started = time.monotonic()
    assert globe_warmer.stop_warmer(timeout=5.0) is True
    assert time.monotonic() - started < 5.0
    assert globe_warmer.running() is False
    assert _warmer_threads() == []
    assert globe_warmer.stop_warmer() is False
    assert globe_warmer.start_warmer(fast_poll_s=0.05,
                                     sats_poll_s=0.05) is True
    assert globe_warmer.running() is True


def test_slow_sats_does_not_starve_fast_thread(monkeypatch):
    # sats_all sleeps 2 s per call (cold-download shape). With one
    # shared loop, quakes could only be called once in a 1.2 s window;
    # with separate threads the fast loop sweeps many times over.
    calls = []
    _install_stubs(monkeypatch, calls, slow_sats_s=2.0)
    globe_warmer.start_warmer(fast_poll_s=0.05, sats_poll_s=0.05)
    time.sleep(1.2)
    quakes_calls = [c for c in calls
                    if c[1] == "layer" and c[2] == "quakes"]
    sats_calls = [c for c in calls
                  if c[1] == "layer" and c[2] == "sats_all"]
    assert len(quakes_calls) >= 3
    assert len(sats_calls) == 1
