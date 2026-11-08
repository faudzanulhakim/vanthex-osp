"""
test_offensive_v6.py — Fleet & Pivot Pack v1.8.0.
Jalankan: .venv/bin/python tests/test_offensive_v6.py  (driver manual).
PORT=18212 (fixture), 18213 (listener beacon).
"""
import json
import os
import sys
import threading
import time
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = 18212
BASE = f"http://127.0.0.1:{PORT}/"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from http.server import ThreadingHTTPServer  # noqa: E402
from fixture_vuln_server import H  # noqa: E402
import vulnscan2 as v  # noqa: E402
import pivot  # noqa: E402
import cloudrecon  # noqa: E402
import fuzzkit  # noqa: E402
import selftune  # noqa: E402
import fleet  # noqa: E402
import reportgen  # noqa: E402
import beacon  # noqa: E402
import phishclone  # noqa: E402
import sentinel  # noqa: E402


def make_ctx():
    return v.Ctx(BASE, {}, [])


def test_pivot_check():
    ctx, found = make_ctx(), []
    pivot.c_pivot_internal_map(ctx, found.append)
    assert found, "pivot check kosong"
    f = found[0]
    assert f["severity"] == "CRITICAL" and f["confidence"] == "confirmed"
    assert "/internal/netmap" == f["location"]
    g = pivot.build_graph([{"source": "/internal/netmap",
                            "hosts": [("10.0.5.10", "db")],
                            "ports": ["10.0.5.10:5432/x"], "creds": ["k"]}])


def test_pivot_safe_control():
    # kontrol: /safe 403 → tanpa sasaran tidak ada temuan palsu
    ctx = make_ctx()
    r = ctx.client.get("/safe/internal/netmap")
    assert r.status in (401, 403), r.status


def test_cloud_check():
    ctx, found = make_ctx(), []
    cloudrecon.c_cloud_container_recon(ctx, found.append)
    titles = [f["title"] for f in found]
    assert any("IMDSv1" in t for t in titles), titles
    assert any("Docker" in t for t in titles), titles
    assert any("Kubernetes" in t for t in titles), titles
    assert all(f["confidence"] == "confirmed" for f in found)


def test_grammar_fuzz_check():
    ctx, found = make_ctx(), []
    fuzzkit.c_grammar_fuzz(ctx, found.append)
    assert found, "fuzz check kosong"
    assert found[0]["confidence"] == "confirmed"
    assert "5" in str(found[0]["evidence"])  # 5xx terbukti


def test_selftune():
    probe = selftune.probe_target(make_ctx().client, BASE)
    assert "latency_s" in probe and "waf" in probe
    opts, notes = selftune.recommend(probe)
    assert "selftune" in opts and notes
    slow = selftune.recommend({"latency_s": 3.0, "waf": True, "tech": "spa"})
    assert slow[0]["timeout"] >= 20 and slow[0]["evasion"] is True


def test_fleet():
    out = fleet.scan_fleet([BASE.rstrip("/")], profile="passive-quick",
                           max_parallel=1)
    assert out["totals"]["targets"] == 1
    assert out["ranking"], "ranking kosong"
    assert "risk_score" in out["ranking"][0]


def test_reportgen():
    f = {"severity": "CRITICAL", "title": "Uji Temuan", "location": "/x",
         "confidence": "confirmed", "cvss": 9.8, "description": "desc"}
    path = os.path.join("/tmp", "vanthex_v18_report.docx")
    reportgen.build_campaign_report(
        path, {"target": BASE}, [{"phase": "recon", "t": "0s", "desc": "d"}],
        [{"name": "chain-a", "steps": [{"action": "probe", "approved": True}],
          "outcome": "ok"}], [f], recs=["perbaiki"])
    assert os.path.getsize(path) > 2000


def test_beacon_sim():
    sim = beacon.BeaconSim(BASE.rstrip("/"), beacon_id="testbx",
                           interval_s=0.05, jitter=0.1, max_beacons=3)
    recap = sim.run()
    assert recap["beacons"] == 3
    assert recap["success"] >= 2
    assert recap["gaps_s"]


def test_phishclone_watermark():
    out = phishclone.clone(BASE.rstrip("/") + "/", "/tmp/vanthex_phish")
    html = open(out["path"], encoding="utf-8").read()
    assert "AUTHORIZED-TESTING-ONLY" in html
    assert "AUTHORIZED PHISHING SIMULATION" in html
    assert "x-vanthex-engagement" in html


def test_sentinel_diff():
    baseline = {"/": "aaa", "/about": "bbb"}
    current = {"/": "aaa", "/about": "ccc", "/admin/backdoor": "ddd"}
    d = sentinel.diff_snapshots(baseline, current)
    assert d["added"] == ["/admin/backdoor"]
    assert d["changed"] == ["/about"]
    assert d["verdict"] == "surface-changed"


def test_registry_v18():
    assert len(v.PROFILES["enterprise-full"]) == 118
    for c in ("c_pivot_internal_map", "c_cloud_container_recon",
              "c_grammar_fuzz"):
        assert callable(getattr(v, c, None)), c


def _autostart():
    srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    import atexit
    atexit.register(srv.shutdown)
    time.sleep(0.3)
    return srv


_autostart()

if __name__ == "__main__":
    ok = fail = 0
    tests = [n for n in sorted(globals()) if n.startswith("test_")]
    for name in tests:
        try:
            globals()[name]()
            ok += 1
            print(f"PASS {name}")
        except Exception:
            fail += 1
            print(f"FAIL {name}")
            traceback.print_exc(limit=4)
    srv = None  # server dihentikan otomatis via atexit
    print(f"== v6: {ok} passed, {fail} failed ==")
    sys.exit(1 if fail else 0)
