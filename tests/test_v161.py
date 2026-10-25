"""VANTHEX v1.6.1 — OSINT stop + speed hotfix, hermetic tests.

Contract points covered:
  * an operator cancel raised mid-sweep stops the engine within
    seconds, keeps the partial findings, and the coverage statement
    records status 'cancelled' with the platforms actually checked;
  * the parallel platform sweep (12 workers) produces findings and
    a graph IDENTICAL to a sequential (1 worker) sweep on the same
    fixture — speed must not change results;
  * exceeding the soft time budget marks the rest not evaluated
    with a 'time budget' reason instead of silently truncating;
  * a cancel during the name (person) flow also returns partial
    results fast, with later pivots gated off.
"""
import sys
import threading
import time

sys.path.insert(0, __file__.rsplit("/tests/", 1)[0])
import osint  # noqa: E402
import scanners  # noqa: E402


class _DohNone:
    """Neutralize DNS-over-HTTPS (hermetic: no network at all)."""

    def __enter__(self):
        self._orig = scanners.doh_query
        scanners.doh_query = lambda *a, **k: None
        return self

    def __exit__(self, *exc):
        scanners.doh_query = self._orig


def _plats(n):
    return [(f"Plat{i:02d}", f"https://p{i:02d}.test/u/{{h}}",
             "profile:{h}") for i in range(n)]


def _fetch_handle(sleep=0.0, counter=None, flip_after=None,
                  state=None):
    """Fake fetch: the target handle exists (probable) everywhere,
    junk handles are absent (control gate passes)."""

    def fetch(url, timeout=8, verify=False, cap=0, headers=None,
              _hops=0):
        if counter is not None:
            with counter["lock"]:
                counter["n"] += 1
                if flip_after and counter["n"] >= flip_after \
                        and state is not None:
                    state["on"] = True
        if ".test/u/" in url:
            if sleep:
                time.sleep(sleep)
            handle = url.rsplit("/", 1)[-1]
            if handle.startswith("ptk") and handle.endswith("zz9"):
                return 404, [], b"no such user"
            return 200, [], f"profile:{handle}".encode()
        if "api.github.com" in url or "gitlab.com" in url:
            return 404, [], b""
        if "duckduckgo.com" in url or "bing.com" in url:
            return 200, [], b"<html><body>no results</body></html>"
        return 0, [], b""

    return fetch


def test_cancel_mid_sweep_stops_fast_with_partial_results():
    counter = {"n": 0, "lock": threading.Lock()}
    state = {"on": False, "flip_ts": None}

    def cancelled():
        if state["on"] and state["flip_ts"] is None:
            state["flip_ts"] = time.time()
        return state["on"]

    fetch = _fetch_handle(sleep=0.05, counter=counter, flip_after=12,
                          state=state)
    t0 = time.time()
    with _DohNone():
        res = osint.run_osint_recon(
            "fixtureuser", _fetch=fetch, _platforms=_plats(30),
            cancelled=cancelled)
    elapsed = time.time() - t0
    cov = res["meta"]["coverage"]
    assert cov["status"] == "cancelled"
    # Partial honesty: some platforms probed, the rest skipped —
    # never the full set, never zero.
    assert 0 < cov["platforms_checked"] < 30
    skipped = res["meta"]["username"]["skipped"]
    assert skipped, "unprobed platforms must be reported as skipped"
    assert cov["platforms_checked"] + len(skipped) == 30
    # Findings gathered before the stop are kept, not discarded.
    assert any("found on" in f["title"] for f in res["findings"])
    # Stop latency: engine exits within seconds of the flag.
    assert state["flip_ts"] is not None
    assert time.time() - state["flip_ts"] < 15
    assert elapsed < 15


def test_parallel_sweep_identical_to_sequential(monkeypatch):
    plats = _plats(12)
    out = {}
    for workers in ("1", "12"):
        monkeypatch.setenv("PTK_OSINT_PROBE_WORKERS", workers)
        with _DohNone():
            out[workers] = osint.run_osint_recon(
                "fixtureuser", _fetch=_fetch_handle(),
                _platforms=plats)
    seq, par = out["1"], out["12"]
    assert seq["findings"] == par["findings"]
    assert seq["meta"]["graph"] == par["meta"]["graph"]
    assert seq["meta"]["graph_stats"] == par["meta"]["graph_stats"]
    assert seq["meta"]["username"]["probable"] \
        == par["meta"]["username"]["probable"]
    assert seq["meta"]["username"]["candidate"] \
        == par["meta"]["username"]["candidate"]
    assert par["meta"]["coverage"]["status"] == "complete"
    assert par["meta"]["coverage"]["platforms_checked"] == 12


def test_time_budget_marks_rest_not_evaluated():
    fetch = _fetch_handle(sleep=0.2)
    t0 = time.time()
    with _DohNone():
        res = osint.run_osint_recon(
            "fixtureuser", opts={"time_budget_s": 0.05},
            _fetch=fetch, _platforms=_plats(30))
    elapsed = time.time() - t0
    cov = res["meta"]["coverage"]
    assert cov["status"] == "time_budget_exceeded"
    assert cov["time_budget_s"] == 0.05
    assert any("time budget" in m
               for m in cov["modules_not_evaluated"])
    assert res["meta"]["username"]["skipped"], \
        "platforms past the budget must be reported as skipped"
    assert cov["platforms_checked"] < 30
    assert elapsed < 15


def test_cancel_during_name_flow_returns_partial():
    state = {"on": False}
    t0 = time.time()

    def cancelled():
        return time.time() - t0 > 1.0 or state["on"]

    fetch = _fetch_handle(sleep=0.1)
    with _DohNone():
        res = osint.run_osint_recon(
            "Fixture Person", _fetch=fetch, _platforms=_plats(8),
            cancelled=cancelled)
    elapsed = time.time() - t0
    cov = res["meta"]["coverage"]
    assert cov["status"] == "cancelled"
    assert res["meta"]["detected_type"] == "name"
    assert "identity" in res["meta"], \
        "the person pivot's partial identity data must be kept"
    # Later pivots are gated off once the stop fires.
    assert "institution" not in res["meta"]
    assert elapsed < 15
