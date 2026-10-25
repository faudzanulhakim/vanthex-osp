"""v1.12.0 — globe_feeds parser + failure-semantics tests.

Hermetic: every test drives the pure parsers from fixtures recorded in
the Fase-0 smoke window (tests/fixtures/globe/) or patches the single
_fetch() seam. No network. OpenSky + GDELT live capture FAILED in the
Fase-0 window (egress proxy dropped OpenSky; GDELT returned 404 on the
documented endpoint forms), so their fixtures are SYNTHETIC files built
to the documented public schemas and named as such.
"""
import json
import os
import time

import pytest

import globe_feeds as gf

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "globe")


def _raw(name):
    with open(os.path.join(FIX, name), "rb") as f:
        return f.read()


@pytest.fixture(autouse=True)
def _isolated_state(tmp_path, monkeypatch):
    monkeypatch.setattr(gf, "CACHE_PATH", str(tmp_path / "cache.json"))
    gf._cache.clear()
    gf._kp.update(value=None, time_tag="", fetched_at=0.0, ok=False,
                  error="")
    gf._tle.update(text="", fetched_at=0.0, ok=False, error="",
                   bad_lines=0)
    gf._sat_memo.update(points=None, at=0.0, total=0)
    yield
    gf._cache.clear()


# ------------------------------------------------------------- parsers

def test_parse_usgs_fixture():
    pts, total, _note = gf.parse_usgs(_raw("usgs_quakes.json"))
    assert total == 12
    assert len(pts) == 12
    for p in pts:
        assert -90 <= p["la"] <= 90 and -180 <= p["lo"] <= 180
        assert p["lb"].startswith("M") and p["lb"][1].isdigit()
    # geometry-less features are skipped, never invented
    d = json.loads(_raw("usgs_quakes.json"))
    d["features"].append({"type": "Feature", "geometry": None,
                          "properties": {"mag": 9.9, "place": "Nowhere"}})
    pts2, total2, _ = gf.parse_usgs(json.dumps(d).encode())
    assert len(pts2) == 12 and total2 == 12


def test_parse_opensky_airborne_and_sampling():
    pts, total, _ = gf.parse_opensky(_raw("opensky_states_SYNTHETIC.json"))
    # 4 vectors: 2 airborne with coords, 1 on ground, 1 without coords
    assert total == 2 and len(pts) == 2
    assert all(p["lb"] for p in pts)
    # cap + declared sampling: 7000 airborne -> 6000 drawn, note says so
    states = []
    for i in range(7000):
        states.append([f"{i:06x}", f"T{i} ", "X", 0, 0, 10.0, 50.0,
                       9000.0, False, 200.0, 90.0, 0.0, None, 9100.0,
                       None, False, 0])
    raw = json.dumps({"time": 0, "states": states}).encode()
    pts2, total2, note2 = gf.parse_opensky(raw)
    assert total2 == 7000 and len(pts2) == 6000
    assert "SAMPLED" in note2.upper()


def test_tle_parse_and_iss_propagation():
    text = _raw("celestrak_stations.tle").decode()
    objs, bad = gf.parse_tle(text)
    assert len(objs) >= 8 and bad == 0
    import datetime as _dt
    when = _dt.datetime(2026, 10, 21, 1, 8, 59,
                        tzinfo=_dt.timezone.utc).timestamp()
    pts, total, _note = gf.propagate_tle(text, when=when)
    assert total >= 8 and len(pts) == total
    # physical plausibility (no independent ephemeris was available
    # offline — the check is band/determinism, stated honestly)
    iss = [p for p in pts if "ISS" in p["lb"] or "ZARYA" in p["lb"]]
    assert iss, "ISS (ZARYA) must be in the stations fixture"
    alt = int(iss[0]["ex"].split(" km")[0].split("alt ")[1])
    assert 300 <= alt <= 600
    assert abs(iss[0]["la"]) <= 51.7  # ISS inclination bound
    pts2, _, _ = gf.propagate_tle(text, when=when)
    assert pts == pts2  # deterministic


def test_parse_eonet_skips_geometryless():
    pts, total, _ = gf.parse_eonet(_raw("eonet_events.json"))
    assert total >= 5 and len(pts) == total
    d = json.loads(_raw("eonet_events.json"))
    d["events"].append({"id": "X1", "title": "No geometry",
                        "categories": [{"id": "wildfires"}],
                        "geometry": []})
    pts2, total2, _ = gf.parse_eonet(json.dumps(d).encode())
    assert len(pts2) == total and total2 == total


def test_parse_swpc_kp():
    value, tag = gf.parse_swpc_kp(_raw("swpc_kp.json"))
    assert 0.0 <= value <= 9.0 and tag


def test_parse_cctv_indexes():
    tfl_pts, tfl_total, _ = gf.parse_tfl(_raw("tfl_jamcams.json"))
    assert tfl_total == 3 and len(tfl_pts) == 3
    assert all("s3-eu-west-1.amazonaws.com" in (p.get("img") or "")
               for p in tfl_pts)
    cal_pts, cal_total, _ = gf.parse_caltrans(_raw("caltrans_d3.json"))
    assert cal_total >= 1 and len(cal_pts) == cal_total
    assert all(-90 <= p["la"] <= 90 for p in cal_pts)


def test_parse_gdelt_news_geocoded_label():
    pts, total, note = gf.parse_gdelt(_raw("gdelt_geo_SYNTHETIC.json"))
    assert total == 2 and len(pts) == 2  # geometry-less feature skipped
    assert "NEWS-GEOCODED" in note or all(
        "NEWS-GEOCODED" in p["ex"] for p in pts)


def _big_caltrans(n=300):
    """A Caltrans-shaped body larger than the 256 KB wire cap, built by
    replicating one real recorded record (hermetic, no big fixture)."""
    d = json.loads(_raw("caltrans_d3.json"))
    rec = d["data"][0]
    body = json.dumps({"data": [rec] * n}).encode()
    assert len(body) > 262144
    return body


def test_fetch_large_reassembles_ranges(monkeypatch):
    full = _big_caltrans()

    def ranged(host, path, start, end, timeout=30.0):
        part = full[start:end + 1]
        return (206 if part else 200), part
    monkeypatch.setattr(gf, "_fetch_range", ranged)
    buf = gf._fetch_large("cwwp2.dot.ca.gov", "/x.json")
    assert buf == full
    pts, total, _ = gf.parse_caltrans(buf)
    assert total == 300 and len(pts) == 300  # full index, not a prefix


def test_fetch_large_range_ignored_degrades(monkeypatch):
    full = _big_caltrans()
    # server ignores Range: always 200 with the (wire-capped) prefix
    monkeypatch.setattr(
        gf, "_fetch_range",
        lambda h, p, s, e, timeout=30.0: (200, full[:262144]))
    buf = gf._fetch_large("cwwp2.dot.ca.gov", "/x.json")
    assert buf == full[:262144]  # partial body surfaces as-is
    with pytest.raises(Exception):
        gf.parse_caltrans(buf)  # and the parser honestly fails on it


# ------------------------------------------------- failure semantics

def test_layer_offline_when_never_ok(monkeypatch):
    def boom(host, path, timeout=30.0):
        raise IOError("simulated transport failure")
    monkeypatch.setattr(gf, "_fetch", boom)
    out = gf.get_layer("quakes")
    assert out["status"] == "offline"
    assert out["points"] == [] and out["count_drawn"] == 0


def test_layer_stale_keeps_last_good(monkeypatch):
    good = _raw("usgs_quakes.json")
    monkeypatch.setattr(gf, "_fetch",
                        lambda h, p, timeout=30.0: (200, good))
    out = gf.get_layer("quakes")
    assert out["status"] == "live" and out["count_drawn"] == 12
    # age the snapshot far beyond 1.5x TTL, then break the feed
    gf._cache["quakes"]["fetched_at"] = gf._now() - 10 * 120
    def boom(host, path, timeout=30.0):
        raise IOError("feed down")
    monkeypatch.setattr(gf, "_fetch", boom)
    out2 = gf.get_layer("quakes")
    assert out2["status"] == "stale"
    assert out2["count_drawn"] == 12  # last good kept, labeled stale
    assert out2["error"]


def test_flights_quota_bounded_by_ttl(monkeypatch):
    """v1.13 contract (replaces the v1.12 OpenSky-credit test): the
    flights family is ONE adsb.lol sweep per TTL (300 s) no matter
    how often the layer is demanded, and the four category buckets
    partition ALL exactly. The family fetcher is the patch seam.
    v1.15.1 background form: a stale demand now spawns a worker
    thread instead of blocking, so the fake clock must not advance
    until that worker has finished and released the family lock —
    otherwise the test measures thread scheduling (a worker still
    inside the slow ~1 MB snapshot write while the clock jumps a
    whole day) instead of the TTL contract. With the drain, the
    cadence is exactly one sweep per 6 steps (240/day)."""
    clock = {"t": 1_800_000_000.0}
    monkeypatch.setattr(gf, "_now", lambda: clock["t"])
    calls = {"n": 0}

    def drain():
        deadline = time.time() + 10
        while time.time() < deadline:
            lock = gf._family_lock("flights")
            if lock.acquire(blocking=False):
                lock.release()
                return True
            time.sleep(0.01)
        return False
    recs = [
        {"hex": "abc001", "flight": "BAW123 ", "t": "A320",
         "lat": 51.5, "lon": -0.1, "dbFlags": 0},
        {"hex": "abc002", "flight": "", "t": "GLF5",
         "lat": 51.6, "lon": -0.2, "dbFlags": 0},
        {"hex": "abc003", "flight": "RRR99", "t": "A400",
         "lat": 51.7, "lon": -0.3, "dbFlags": 1},
        {"hex": "abc004", "flight": "N12345", "t": "C172",
         "lat": 51.8, "lon": -0.4, "dbFlags": 0},
    ]

    def fake_family():
        calls["n"] += 1
        pts = gf.parse_adsb_records(recs, set())
        return gf._flights_entries(pts, "synthetic", "test")
    monkeypatch.setattr(gf, "_fetch_flights_family", fake_family)
    for step in range(24 * 60):  # 24 h in 60 s steps, demand each time
        clock["t"] = 1_800_000_000.0 + step * 60
        gf.get_layer("flights")
        assert drain(), f"flights worker still holding lock at step {step}"
    assert calls["n"] <= 288  # TTL 300 s -> at most 288 sweeps/day
    assert calls["n"] >= 200  # and it does refresh (not stuck)
    out = gf.get_layer("flights")
    assert out["count_total"] == 4
    parts = sum(gf.get_layer(s)["count_total"] for s in
                ("flights_commercial", "flights_private",
                 "flights_jets", "flights_military"))
    assert parts == 4  # buckets are an exact partition of ALL


def test_maritime_is_static_and_local():
    out = gf.get_layer("maritime")
    assert out["count_drawn"] == 50  # 40 ports + 10 chokepoints
    assert "STATIC" in out["note"]
    assert all(p["la"] and p["lo"] for p in out["points"])


def test_status_reports_kp_and_layers(monkeypatch):
    kp = _raw("swpc_kp.json")
    def fake(host, path, timeout=30.0):
        assert host == "services.swpc.noaa.gov"
        return 200, kp
    monkeypatch.setattr(gf, "_fetch", fake)
    st = gf.status()
    assert st["kp"]["value"] is not None
    for name in ("flights", "satellites", "quakes", "events", "cctv",
                 "incidents", "maritime"):
        assert name in st["layers"]


# ------------------------------------------------------------- entities

def test_entities_country_level_only():
    result = {"meta": {
        "graph": {
            "nodes": [
                {"id": "ip:1.2.3.4", "type": "ip", "label": "1.2.3.4"},
                {"id": "domain:example.com", "type": "domain",
                 "label": "example.com"},
                {"id": "person:x", "type": "person", "label": "X"},
                {"id": "ip:9.9.9.9", "type": "ip", "label": "9.9.9.9"},
            ],
            "edges": [
                {"source": "domain:example.com", "target": "ip:1.2.3.4",
                 "relation": "RESOLVES_TO"},
            ],
        },
        "sections": {"infra": {"rdap": [
            {"ip": "1.2.3.4", "country": "NL"},
            {"ip": "9.9.9.9", "country": ""},
        ]}},
    }}
    pts, located, total = gf.entities_from_result(result)
    assert total == 4 and located == 2 and len(pts) == 2
    assert all("NOT A SUBJECT LOCATION" in p["ex"] for p in pts)
    labels = {p["lb"] for p in pts}
    assert labels == {"1.2.3.4", "example.com"}
    out = gf.get_entities(result, scan_id="abc")
    assert out["located"] == 2 and out["total"] == 4
