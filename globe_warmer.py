"""Background globe warmer (v1.2.1, 2026-10-26).

Why this exists: the docker container has no fetch daemon and ships no
``globe_feed_cache.json``, so its in-memory layer registry starts EMPTY
on every Recreated deploy. ``globe_feeds.status()`` never triggers a feed
fetch (except Kp, own TTL 900 s) — it only reports the cache — so a cold
container reads OFFLINE until a browser actually opens a layer, and a
page refresh shows OFFLINE again until demand warms it. The client alone
cannot fix that: the service itself must warm its own cache.

What this does: two daemon threads, started with the service process
(``app2.main()``), sweep a fixed warm set through the SAME reads a
browser would make — ``globe_feeds.get_layer`` for layers, plus the
TTL-gated ``globe_feeds.get_news`` / ``get_markets`` getters. No second
cache, no new fetch paths, no new hosts, no new keys, no CSP change,
no database change, no daemon change, no version bump (label stays
1.2.1). Demand-driven reads are untouched: a browser still gets exactly
what ``get_layer`` has always returned.

Threads (a slow family must never starve fast families, and no warmer
work may ever block a request):

* ``globe-warmer-fast`` — the 11 non-sats warm layers (in order, fast
  families first so visible data lands in seconds) plus news + markets,
  re-polled every ``FAST_POLL_S`` (30 s). Each ``get_layer`` call is
  TTL-gated inside ``globe_feeds``: fresh entries return immediately,
  so a poll is cheap once warm.
* ``globe-warmer-sats`` — the 6 sats layers (one family: the first
  call, ``sats_all``, triggers the family fetch and populates all six),
  re-polled every ``SATS_POLL_S`` (60 s, the sats TTL). The cold sats
  refresh (CelesTrak download + ~7,680 SGP4 propagations, >120 s, past
  even the 120 s action budget) runs ONLY here, never on a request
  path, and never overlapped: ``get_layer`` takes the per-family lock
  non-blocking, so while the warmer holds it, a concurrent request
  skips the refresh and returns the last snapshot immediately — and
  while a request holds it, the warmer skips that family this sweep
  and retries on the next poll. No thread ever waits on the other.

Sats cadence, honestly: TLE groups are cached 2 h (``SAT_TLE_TTL``), so
a warm refresh is just propagation (~0.2 s) and sats reads LIVE most
of the time (live while age <= 1.5 x 60 s TTL, polled every 60 s).
During a TLE download window — the first cold sweep, and every ~2 h
re-download — the previous positions stay served and read
STALE-but-present, never OFFLINE, never 0. A failed refresh likewise
keeps the last good snapshot as STALE (``globe_feeds`` failure path).

Status expectations: at process start the registry is cold; within
seconds of the first fast family landing, feed families read
live/stale and the STATUS pill leaves OFFLINE for good under normal
egress. Steady state is PARTIAL, not LIVE: LIVE requires every
sublayer live/static/computed plus Kp ok, and rain/clouds report
browser-state while transit_live reports noteval, which veto all_live
in ``status()`` — PARTIAL is the healthy state, OFFLINE is the failure
state. A total egress outage degrades warmed families to STALE (old
data still served), not OFFLINE; only a cold container that never
fetched anything reads OFFLINE.

Warm set (explicit; everything else is deliberately excluded):

* Fast: quakes, fires, severe, events_other, cctv, wind, incidents,
  gdelt_events, botnet_c2, malware_urls, launches, plus news, markets.
* Sats: sats_all, sats_comms, sats_military, sats_gnss, sats_eo,
  sats_stations.
* Excluded: wind_particles (computed from daemon-decoded GFS grid
  state; docker has no daemon, so it stays OFFLINE by architecture —
  never faked); flights (already background-refreshed since v1.15.1);
  rain/clouds (browser tile overlays, not server families); daynight
  (client-computed); transit_live (NOT EVALUATED by design);
  maritime_static/maritime_lines/nuclear (static files, already OK
  via ``_local_entry`` on every status read, no fetch needed).

Lifecycle: ``start_warmer()`` is idempotent (a second call while the
threads are alive is a no-op returning False) and is called from
``app2.main()`` only — importing this module starts nothing, so tests
and any non-server import stay inert. ``stop_warmer()`` exists for
tests and clean shutdown; both threads are daemon threads, so process
exit never hangs even if stop is never called. A warmer failure never
kills the service: per-item failures are logged and skipped, and a
failed ``start_warmer()`` in ``app2.main()`` is caught so the server
still serves (demand-driven, as before).
"""

import threading

import globe_feeds

# Fast families first: visible data lands in seconds, sats follows in
# its own thread. Order within a thread is the sweep order; sibling
# sublayers of one family return cached immediately once the family
# fetch lands, so listing every member is cheap and explicit.
WARM_LAYERS_FAST = (
    "quakes",        # family quakes, TTL 120 s
    "fires",         # family eonet (fires/severe/events_other), 1800 s
    "severe",
    "events_other",
    "cctv",          # TTL 3600 s
    "wind",          # Open-Meteo, TTL 21600 s
    "incidents",     # family gdelt (incidents/gdelt_events), 1800 s
    "gdelt_events",
    "botnet_c2",     # family abusech (botnet_c2/malware_urls), 3600 s
    "malware_urls",
    "launches",      # TTL 3600 s
)

WARM_LAYERS_SATS = (
    "sats_all",      # family sats (all six members), TTL 60 s
    "sats_comms",
    "sats_military",
    "sats_gnss",
    "sats_eo",
    "sats_stations",
)

FAST_POLL_S = 30.0
SATS_POLL_S = 60.0

_lock = threading.Lock()
_stop = threading.Event()
_threads = []


def _sweep_layer(sid):
    try:
        globe_feeds.get_layer(sid)
    except Exception as e:  # noqa: BLE001 — one layer never kills a sweep
        print(f"[globe] warmer {sid} failed: {e!r}", flush=True)


def _sweep_fast(stop):
    for sid in WARM_LAYERS_FAST:
        if stop.is_set():
            return
        _sweep_layer(sid)
    if stop.is_set():
        return
    try:
        globe_feeds.get_news()
    except Exception as e:  # noqa: BLE001 — see _sweep_layer
        print(f"[globe] warmer news failed: {e!r}", flush=True)
    if stop.is_set():
        return
    try:
        globe_feeds.get_markets()
    except Exception as e:  # noqa: BLE001 — see _sweep_layer
        print(f"[globe] warmer markets failed: {e!r}", flush=True)


def _sweep_sats(stop):
    for sid in WARM_LAYERS_SATS:
        if stop.is_set():
            return
        _sweep_layer(sid)


def _loop(stop, sweep, poll_s):
    while not stop.is_set():
        try:
            sweep(stop)
        except Exception as e:  # noqa: BLE001 — the loop never dies
            print(f"[globe] warmer sweep failed: {e!r}", flush=True)
        stop.wait(poll_s)


def start_warmer(fast_poll_s=FAST_POLL_S, sats_poll_s=SATS_POLL_S):
    """Start the fast + sats warmer threads. Idempotent: returns True
    when this call started them, False when they were already alive.
    Poll intervals are parameters only so hermetic tests can run fast
    sweeps; production callers use the defaults."""
    with _lock:
        if any(t.is_alive() for t in _threads):
            return False
        _stop.clear()
        _threads.clear()
        fast = threading.Thread(
            target=_loop, args=(_stop, _sweep_fast, fast_poll_s),
            daemon=True, name="globe-warmer-fast")
        sats = threading.Thread(
            target=_loop, args=(_stop, _sweep_sats, sats_poll_s),
            daemon=True, name="globe-warmer-sats")
        _threads.extend([fast, sats])
        fast.start()
        sats.start()
        print("[globe] warmer started "
              "(fast: 11 layers + news + markets; sats: 6 layers)",
              flush=True)
        return True


def stop_warmer(timeout=5.0):
    """Stop the warmer threads. Returns True when threads were stopped,
    False when none were running. The stop event wakes a sleeping poll
    immediately, so this returns promptly even with long poll
    intervals; a thread stuck inside a single slow fetch is joined only
    up to ``timeout`` (daemon threads die with the process anyway)."""
    with _lock:
        threads = list(_threads)
    if not threads:
        return False
    _stop.set()
    for t in threads:
        t.join(timeout=timeout)
    with _lock:
        _threads.clear()
    return True


def running():
    """True while at least one warmer thread is alive."""
    with _lock:
        return any(t.is_alive() for t in _threads)
