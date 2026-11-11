"""Reliability v1.8.0 — regression for three ADE complaints (night of 2026-10-17):
1) a 2067s scan with no results because the target was written schemeless -> the old
   parser guessed http:// for an app that only lives on https;
2) rescans gave different results (coverage became a timeout lottery);
3) the framework was not detected (consequence of #1: no page ever loaded).
"""
import os
import subprocess
import sys
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.chdir(ROOT)

import netclient
import vulnscan2

PORT = 18091


def _wait(port, tries=40):
    for _ in range(tries):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2)
            return True
        except Exception:
            time.sleep(0.25)
    return False


def _boot():
    p = subprocess.Popen(
        [sys.executable, "tests/fixture_vuln_server.py", str(PORT)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert _wait(PORT), "reliability fixture did not start"
    return p


def test_schemeless_target_resolves_and_detects():
    p = _boot()
    try:
        t0 = time.time()
        # written exactly as a user would type it: schemeless
        r = vulnscan2.run_vulnscan(f"127.0.0.1:{PORT}", "active-standard",
                                   log=[])
        dur = time.time() - t0
        assert r["effective_target"].startswith("http://"), r["effective_target"]
        names = [t["name"] for t in r["tech_profile"]]
        assert names, "empty fingerprint on a proven-alive target"
        assert dur < 600, f"fixture scan took too long: {dur:.0f}s"
    finally:
        p.terminate()


def test_unreachable_target_aborts_fast():
    t0 = time.time()
    r = vulnscan2.run_vulnscan("127.0.0.1:9", "active-standard", log=[])
    dur = time.time() - t0
    assert dur < 30, f"preflight abort too slow: {dur:.1f}s"
    titles = [f["title"] for f in r["findings"]]
    assert titles == ["Target unreachable — scan aborted early"], titles
    assert all(d["status"] == "skipped" for d in r["checks_detail"])
    assert any("inconclusive" in w.lower() for w in r["warnings"])


def test_get_cache_serves_second_identical_request():
    p = _boot()
    try:
        c = netclient.Client(f"http://127.0.0.1:{PORT}", timeout=4)
        a = c.get("/")
        b = c.get("/")
        assert a.status == b.status == 200
        assert a.body == b.body
        assert c.stats.get("cache_hits", 0) >= 1
    finally:
        p.terminate()


def test_determinism_two_runs_identical():
    p = _boot()
    try:
        r1 = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT}",
                                    "active-standard", log=[])
        r2 = vulnscan2.run_vulnscan(f"http://127.0.0.1:{PORT}",
                                    "active-standard", log=[])
        t1 = sorted(f["title"] for f in r1["findings"])
        t2 = sorted(f["title"] for f in r2["findings"])
        assert t1 == t2, (
            "two identical scans gave different results:\n"
            f"only in run1: {sorted(set(t1) - set(t2))}\n"
            f"only in run2: {sorted(set(t2) - set(t1))}")
        n1 = sorted(t["name"] for t in r1["tech_profile"])
        n2 = sorted(t["name"] for t in r2["tech_profile"])
        assert n1 == n2, f"tech profile differs: {n1} vs {n2}"
    finally:
        p.terminate()


def test_header_variant_taints_cache():
    """A URL once requested with a special header must never again be served
    from the cache — the cache-poisoning verification reads the probe
    response from the network, not the pre-poisoning snapshot."""
    p = _boot()
    try:
        c = netclient.Client(f"http://127.0.0.1:{PORT}", timeout=4)
        c.get("/")
        assert c.stats.get("cache_hits", 0) == 0
        c.get("/", headers={"X-Forwarded-Host": "evil-taint.example"})
        hits_after_header = c.stats.get("cache_hits", 0)
        r = c.get("/")
        assert r.status == 200
        # the third GET MUST hit the network: cache_hits must not increase
        assert c.stats.get("cache_hits", 0) == hits_after_header
    finally:
        p.terminate()
